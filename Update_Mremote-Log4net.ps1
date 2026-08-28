<#
.SYNOPSIS
    Replaces the vulnerable log4net.dll embedded in mRemoteNG with a patched
    Apache.log4net build, applying the required binding redirect.

.DESCRIPTION
    Automates the manual log4net remediation runbook for mRemoteNG:
      1. Detects the currently embedded version and its hash (pre-change evidence).
      2. Uses the patched log4net.dll placed next to this script (net4xx build).
      3. Backs up the current DLL with a timestamp.
      4. Replaces the DLL and unblocks it (Mark of the Web), if applicable.
      5. Updates (or inserts) the bindingRedirect in mRemoteNG.exe.config.
      6. Verifies the new assembly loads correctly (without opening the UI).
      7. Prints a short summary of what changed.

    Meant to be run one server at a time, manually, with human review of the
    result before closing the scanner finding.

.PARAMETER AppPath
    mRemoteNG install path. Default: "C:\Program Files (x86)\mRemoteNG"

.PARAMETER SourceDllPath
    Path to the already-patched log4net.dll (net4xx build). Defaults to
    "log4net.dll" in the same folder as this script, so you only need to drop
    the file next to it before running — no path to type each time.

.PARAMETER WhatIf
    Simulation mode: runs all checks but does not modify the DLL or the
    .config file. Use this first to review before applying for real.

.PARAMETER Rollback
    Restores the original DLL from the most recent backup and reverts the
    bindingRedirect that was added. Use if something went wrong.

.EXAMPLE
    .\Update-MRemoteNGLog4net.ps1 -WhatIf
    Simulates the replacement using log4net.dll from the script's own folder.

.EXAMPLE
    .\Update-MRemoteNGLog4net.ps1
    Runs the real replacement.

.EXAMPLE
    .\Update-MRemoteNGLog4net.ps1 -Rollback
    Reverts to the original DLL from backup.

.NOTES
    Requires mRemoteNG to be closed before running (the script checks and aborts if it's open).
    Requires PowerShell running elevated in most cases, since the app lives under Program Files.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$AppPath = "C:\Program Files (x86)\mRemoteNG",
    [string]$SourceDllPath = (Join-Path $PSScriptRoot "log4net.dll"),
    [switch]$Rollback
)

$ErrorActionPreference = "Stop"
$LogDir    = Join-Path $AppPath "log4net_remediation"
$BackupDir = Join-Path $LogDir "backup"
$LogFile   = Join-Path $LogDir ("log4net_remediation_{0}.log" -f (Get-Date -Format "yyyyMMdd_HHmmss"))

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

function Assert-AppClosed {
    $proc = Get-Process -Name "mRemoteNG" -ErrorAction SilentlyContinue
    if ($proc) {
        throw "mRemoteNG is still running (PID $($proc.Id)). Close it before continuing."
    }
}

function Get-CurrentLog4netInfo {
    $dllPath = Join-Path $AppPath "log4net.dll"
    if (-not (Test-Path $dllPath)) {
        throw "log4net.dll not found under $AppPath. Is the install path correct?"
    }
    $versionInfo = (Get-Item $dllPath).VersionInfo
    $hash = (Get-FileHash $dllPath -Algorithm SHA256).Hash
    [PSCustomObject]@{
        Path           = $dllPath
        FileVersion    = $versionInfo.FileVersion
        ProductVersion = $versionInfo.ProductVersion
        SHA256         = $hash
    }
}

# ── Rollback mode ────────────────────────────────────────────────────────
if ($Rollback) {
    Write-Log "ROLLBACK mode."
    if (-not (Test-Path $BackupDir)) {
        throw "No backup folder found ($BackupDir). Nothing to roll back."
    }
    $lastBackup = Get-ChildItem $BackupDir -Filter "log4net_*.dll" |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $lastBackup) {
        throw "No log4net.dll backup found in $BackupDir."
    }
    Assert-AppClosed
    $dllPath = Join-Path $AppPath "log4net.dll"
    if ($PSCmdlet.ShouldProcess($dllPath, "Restore from $($lastBackup.Name)")) {
        Copy-Item $lastBackup.FullName $dllPath -Force
        Write-Log "Restored log4net.dll from $($lastBackup.Name)."
    }

    $configPath = Join-Path $AppPath "mRemoteNG.exe.config"
    $configBackup = Join-Path $BackupDir "mRemoteNG.exe.config.bak"
    if (Test-Path $configBackup) {
        if ($PSCmdlet.ShouldProcess($configPath, "Restore original configuration")) {
            Copy-Item $configBackup $configPath -Force
            Write-Log "Restored mRemoteNG.exe.config from backup."
        }
    } else {
        Write-Log "No .config backup found; check the bindingRedirect manually." "WARN"
    }
    Write-Log "Rollback complete."
    return
}

# ── Main flow ────────────────────────────────────────────────────────────
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null

Write-Log "=== Starting mRemoteNG log4net remediation ==="
Write-Log "AppPath: $AppPath"

Assert-AppClosed

if (-not (Test-Path $SourceDllPath)) {
    throw "Patched log4net.dll not found at $SourceDllPath. Place it next to this script, or pass -SourceDllPath explicitly."
}

$before = Get-CurrentLog4netInfo
$configPath = Join-Path $AppPath "mRemoteNG.exe.config"
if (-not (Test-Path $configPath)) {
    throw "mRemoteNG.exe.config not found under $AppPath."
}

$newDll = Get-Item $SourceDllPath
$newVersion = $newDll.VersionInfo.FileVersion

if ($before.FileVersion -eq $newVersion) {
    Write-Log "Installed version already matches the source DLL ($newVersion). Nothing to do." "WARN"
    return
}

# Backups
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupDllPath = Join-Path $BackupDir "log4net_$($before.FileVersion)_$timestamp.dll"
$backupConfigPath = Join-Path $BackupDir "mRemoteNG.exe.config.bak"

if ($PSCmdlet.ShouldProcess($before.Path, "Backup to $backupDllPath")) {
    Copy-Item $before.Path $backupDllPath -Force
}
if (-not (Test-Path $backupConfigPath)) {
    if ($PSCmdlet.ShouldProcess($configPath, "Backup configuration")) {
        Copy-Item $configPath $backupConfigPath -Force
    }
}

# Replace the DLL
if ($PSCmdlet.ShouldProcess($before.Path, "Replace with log4net $newVersion")) {
    Copy-Item $newDll.FullName $before.Path -Force
    try {
        Unblock-File -Path $before.Path -ErrorAction Stop
    } catch {
        # No Mark of the Web to remove — fine if the DLL came from a local copy, not a download.
    }
}

# Update the bindingRedirect (real XML manipulation, not regex; idempotent)
if ($PSCmdlet.ShouldProcess($configPath, "Update log4net bindingRedirect")) {
    [xml]$xml = Get-Content $configPath
    $ns = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
    $ns.AddNamespace("asm", "urn:schemas-microsoft-com:asm.v1")

    $runtime = $xml.configuration.runtime
    if (-not $runtime) {
        $runtime = $xml.CreateElement("runtime")
        $xml.configuration.AppendChild($runtime) | Out-Null
    }

    $assemblyBinding = $runtime.SelectSingleNode("asm:assemblyBinding", $ns)
    if (-not $assemblyBinding) {
        $assemblyBinding = $xml.CreateElement("assemblyBinding", "urn:schemas-microsoft-com:asm.v1")
        $runtime.AppendChild($assemblyBinding) | Out-Null
    }

    # Remove any log4net entry from a previous run of this script
    $existing = $assemblyBinding.SelectNodes("asm:dependentAssembly[asm:assemblyIdentity/@name='log4net']", $ns)
    foreach ($node in $existing) { $assemblyBinding.RemoveChild($node) | Out-Null }

    $dependentAssembly = $xml.CreateElement("dependentAssembly", "urn:schemas-microsoft-com:asm.v1")

    $assemblyIdentity = $xml.CreateElement("assemblyIdentity", "urn:schemas-microsoft-com:asm.v1")
    $assemblyIdentity.SetAttribute("name", "log4net")
    $assemblyIdentity.SetAttribute("publicKeyToken", "669e0ddf0bb1aa2a")
    $assemblyIdentity.SetAttribute("culture", "neutral")
    $dependentAssembly.AppendChild($assemblyIdentity) | Out-Null

    $bindingRedirect = $xml.CreateElement("bindingRedirect", "urn:schemas-microsoft-com:asm.v1")
    $bindingRedirect.SetAttribute("oldVersion", "0.0.0.0-$($before.FileVersion)")
    $bindingRedirect.SetAttribute("newVersion", $newVersion)
    $dependentAssembly.AppendChild($bindingRedirect) | Out-Null

    $assemblyBinding.AppendChild($dependentAssembly) | Out-Null
    $xml.Save($configPath)
}

# Verify the assembly loads correctly, without opening the UI
try {
    $verifyJob = Start-Job -ScriptBlock {
        param($dllPath)
        Add-Type -Path $dllPath
        [AppDomain]::CurrentDomain.GetAssemblies() |
            Where-Object { $_.GetName().Name -eq "log4net" } |
            Select-Object -First 1 -ExpandProperty FullName
    } -ArgumentList $before.Path
    $verifyResult = $verifyJob | Wait-Job -Timeout 30 | Receive-Job
    Remove-Job $verifyJob -Force
    if (-not $verifyResult) {
        Write-Log "Could not confirm the assembly loaded (timeout or no output). Verify manually by opening the app." "WARN"
    }
} catch {
    Write-Log "Automatic load check failed: $_. Not necessarily an error — confirm by opening the app manually." "WARN"
}

$after = Get-CurrentLog4netInfo
Write-Log "log4net updated: $($before.FileVersion) -> $($after.FileVersion)"
Write-Log "Log file: $LogFile"

Write-Host ""
Write-Host "Done. Open mRemoteNG manually to confirm RDP/SSH/logging still work before closing the finding." -ForegroundColor Green
Write-Host "If anything breaks, run: .\$($MyInvocation.MyCommand.Name) -Rollback" -ForegroundColor Yellow
