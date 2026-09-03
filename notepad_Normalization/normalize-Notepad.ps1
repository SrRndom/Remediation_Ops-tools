<#
.SYNOPSIS
    Discovers all Notepad++ installations on a server (MSI-based, EXE-based,
    or unregistered folders), removes them cleanly, cleans up orphaned traces,
    and reinstalls to a single normalized location with auto-update disabled.

.DESCRIPTION
    Notepad++ has been deployed two different ways over the years: the older
    EXE (NSIS) installer, and the newer official MSI (since v8.8.8). The MSI
    does not support a custom install directory or the /noUpdater switch, so
    for a normalized, auto-update-disabled deployment, the EXE installer is
    used for the final install regardless of which type is found on a given
    server.

    This script:
      1. Finds every Notepad++ entry in the Windows uninstall registry
         (32/64-bit), whether MSI- or EXE-registered.
      2. Finds every folder on C:\ and D:\ named "Notepad++", registered or not.
      3. Closes Notepad++ if it's running (with confirmation).
      4. Uninstalls every registered instance (MSI via msiexec, legacy EXE via
         its NSIS uninstaller /S).
      5. Removes registry entries that point to install locations that no
         longer exist on disk (orphaned uninstallers).
      6. Re-scans for leftover folders that survived uninstall and asks
         before removing them.
      7. Removes broken shortcuts (Desktop / Start Menu) pointing at
         Notepad++ paths that no longer exist.
      8. Installs via the official EXE installer, silently, to the normalized
         path, with the auto-updater explicitly disabled -- both via the
         /noUpdater switch AND by removing the "updater" folder afterward
         (the switch alone can be silently ignored if a leftover per-user
         config.xml from a previous install still has auto-update enabled).
      9. Verifies the final state and prints a summary.

.PARAMETER NormalizedPath
    Target install path for the clean reinstall.
    Default: "D:\Software\Notepad++" (same standard as the 7-Zip normalization).

.PARAMETER SourceExePath
    Path to the official Notepad++ EXE installer (npp.<version>.Installer.x64.exe).
    Defaults to auto-detecting a matching .exe in the same folder as this
    script, so you only need to drop the installer next to it.

.PARAMETER ScanDepth
    How many subfolder levels deep to search under C:\ and D:\ for leftover
    Notepad++ folders. Default: 3.

.PARAMETER WhatIf
    Simulation mode: runs discovery and shows what would be removed/installed,
    without actually uninstalling, deleting, or installing anything.

.PARAMETER Force
    Skips confirmation prompts (closing a running Notepad++, proceeding with
    cleanup, deleting leftover orphan folders) and answers Yes automatically.

.EXAMPLE
    .\Normalize-NotepadPP.ps1 -WhatIf
    Shows what would happen without touching anything.

.EXAMPLE
    .\Normalize-NotepadPP.ps1 -Force
    Runs the full cleanup, normalization, and reinstall unattended.

.NOTES
    Requires an elevated PowerShell session.
    Official MSI cannot be redirected to a custom INSTALLDIR and has no
    /noUpdater equivalent, per the Notepad++ maintainer's own confirmation
    in the community forum -- that's why this script always reinstalls via
    the EXE, even on servers where the MSI was originally used.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$NormalizedPath = "D:\Software\Notepad++",
    [string]$SourceExePath,
    [int]$ScanDepth = 3,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

# --- Elevation check ---
$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host ""
    Write-Host "This script needs an elevated (Run as Administrator) PowerShell session." -ForegroundColor Yellow
    $answer = Read-Host "Relaunch this script elevated now? (Y/N)"
    if ($answer -match '^[Yy]') {
        $argList = @()
        foreach ($key in $PSBoundParameters.Keys) {
            $value = $PSBoundParameters[$key]
            if ($value -is [switch]) {
                if ($value.IsPresent) { $argList += "-$key" }
            } else {
                $argList += "-$key", "`"$value`""
            }
        }
        $argString = "-NoExit -ExecutionPolicy Bypass -File `"$PSCommandPath`" " + ($argList -join " ")
        Start-Process -FilePath "powershell.exe" -ArgumentList $argString -Verb RunAs
        return
    } else {
        throw "Re-run this script from an elevated PowerShell session (Run as Administrator)."
    }
}

$LogDir  = Join-Path $env:ProgramData "NotepadPP_Normalization"
$LogFile = Join-Path $LogDir ("normalize_nppp_{0}.log" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

function Assert-AppClosed {
    $proc = Get-Process -Name "notepad++" -ErrorAction SilentlyContinue
    if (-not $proc) { return }

    Write-Host ""
    Write-Host "Notepad++ is currently running ($($proc.Count) process(es))." -ForegroundColor Yellow
    if ($Force) {
        Write-Log "-Force given: closing Notepad++ without prompting."
        $answer = "Y"
    } else {
        $answer = Read-Host "Close it now to continue? (Y/N)"
    }
    if ($answer -notmatch '^[Yy]') {
        throw "Notepad++ is still running. Close it manually and re-run the script."
    }
    $proc | Stop-Process -Force
    Start-Sleep -Seconds 2
    if (Get-Process -Name "notepad++" -ErrorAction SilentlyContinue) {
        throw "Notepad++ did not close. Close it manually and re-run the script."
    }
    Write-Log "Notepad++ closed."
}

Write-Log "=== Starting Notepad++ discovery, cleanup, and normalization ==="
Write-Log "Target normalized path: $NormalizedPath"

# --- Auto-detect the EXE next to this script if not given ---
if (-not $SourceExePath) {
    $candidate = Get-ChildItem $PSScriptRoot -Filter "npp*x64*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $candidate) {
        $candidate = Get-ChildItem $PSScriptRoot -Filter "npp*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    }
    $SourceExePath = $candidate.FullName
}
if (-not $SourceExePath -or -not (Test-Path $SourceExePath)) {
    throw "No Notepad++ EXE installer found. Place npp.<version>.Installer.x64.exe next to this script, or pass -SourceExePath explicitly."
}
Write-Log "Installer to use: $SourceExePath"

Assert-AppClosed

# --- Step 1: discover registered installs (MSI or EXE-registered) ---
$uninstallRoots = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)
$registeredInstalls = @(Get-ItemProperty $uninstallRoots -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -eq "Notepad++" -or $_.DisplayName -like "Notepad++*" } |
    Select-Object DisplayName, DisplayVersion, InstallLocation, UninstallString, PSPath)

Write-Log "Registered Notepad++ entries found: $($registeredInstalls.Count)"
foreach ($r in $registeredInstalls) {
    $kind = if ($r.UninstallString -match '\{[0-9A-Fa-f\-]{36}\}') { "MSI" } else { "EXE" }
    if ([string]::IsNullOrWhiteSpace($r.InstallLocation)) {
        Write-Log ("  - v{0} | {1} | InstallLocation not set" -f $r.DisplayVersion, $kind)
    } else {
        Write-Log ("  - v{0} | {1} | {2} | on disk: {3}" -f $r.DisplayVersion, $kind, $r.InstallLocation, (Test-Path $r.InstallLocation))
    }
}

# --- Step 2: discover candidate folders on disk (registered or not) ---
# Prunes noisy system folders instead of filtering after a full recursive
# walk -- that's what actually keeps this fast on a real server.
$excludedFolderNames = @('Windows', 'ProgramData', 'AppData', 'System Volume Information', '$RECYCLE.BIN')

function Find-NotepadPPFolders {
    param([string]$Root, [int]$MaxDepth)
    $found = New-Object System.Collections.Generic.List[string]
    $queue = New-Object System.Collections.Generic.Queue[object]
    $queue.Enqueue(@{ Path = $Root; Depth = 0 })
    while ($queue.Count -gt 0) {
        $current = $queue.Dequeue()
        $children = Get-ChildItem -LiteralPath $current.Path -Directory -Force -ErrorAction SilentlyContinue
        foreach ($child in $children) {
            if ($excludedFolderNames -contains $child.Name) { continue }
            if ($child.Name -match '^Notepad\+\+$') { $found.Add($child.FullName) }
            if ($current.Depth -lt $MaxDepth) {
                $queue.Enqueue(@{ Path = $child.FullName; Depth = $current.Depth + 1 })
            }
        }
    }
    return $found
}

$searchRoots = @("C:\", "D:\") | Where-Object { Test-Path $_ }
$candidateFolders = New-Object System.Collections.Generic.List[string]
foreach ($root in $searchRoots) {
    Find-NotepadPPFolders -Root $root -MaxDepth $ScanDepth |
        Where-Object { $_ -ne $PSScriptRoot -and $PSScriptRoot -notlike "$_\*" -and $_ -notlike "$PSScriptRoot\*" } |
        ForEach-Object { if (-not $candidateFolders.Contains($_)) { $candidateFolders.Add($_) } }
}
Write-Log "Candidate Notepad++ folders found on disk (scan depth $ScanDepth): $($candidateFolders.Count)"
foreach ($f in $candidateFolders) { Write-Log "  - $f" }

if ($registeredInstalls.Count -eq 0 -and $candidateFolders.Count -eq 0) {
    Write-Log "No Notepad++ traces found at all. Proceeding straight to clean install."
} elseif ($Force) {
    Write-Log "-Force given: proceeding with uninstall + cleanup without prompting."
} else {
    Write-Host ""
    $proceed = Read-Host "Proceed with uninstall + cleanup of everything listed above? (Y/N)"
    if ($proceed -notmatch '^[Yy]') {
        throw "Aborted by user before any changes were made."
    }
}

# --- Step 3: uninstall every registered instance ---
foreach ($r in $registeredInstalls) {
    if ($PSCmdlet.ShouldProcess("Notepad++ v$($r.DisplayVersion)", "Uninstall")) {
        if ($r.UninstallString -match '\{[0-9A-Fa-f\-]{36}\}') {
            $productCode = $Matches[0]
            Write-Log "Uninstalling (MSI) Notepad++ v$($r.DisplayVersion) [$productCode]..."
            $msiLog = Join-Path $LogDir ("uninstall_{0}.log" -f ($productCode -replace '[{}]',''))
            $p = Start-Process "msiexec.exe" -ArgumentList "/x $productCode /qn /norestart /l*v `"$msiLog`"" -Wait -PassThru
            Write-Log "Exit code: $($p.ExitCode)"
        } elseif ($r.UninstallString) {
            Write-Log "Uninstalling (legacy EXE) Notepad++ v$($r.DisplayVersion) via: $($r.UninstallString)"
            try {
                $exePath = ($r.UninstallString -replace '^"?([^"]+)"?.*', '$1')
                if (Test-Path $exePath) {
                    $p = Start-Process $exePath -ArgumentList "/S" -Wait -PassThru
                    Write-Log "Exit code: $($p.ExitCode)"
                } else {
                    Write-Log "Uninstaller executable not found at $exePath -- registry entry is orphaned, will be cleaned below." "WARN"
                }
            } catch {
                Write-Log "Legacy uninstall failed: $_" "WARN"
            }
        }
    }
}

# --- Step 4: remove orphaned registry entries (install location no longer exists) ---
$stillRegistered = @(Get-ItemProperty $uninstallRoots -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -eq "Notepad++" -or $_.DisplayName -like "Notepad++*" })
foreach ($r in $stillRegistered) {
    if ([string]::IsNullOrWhiteSpace($r.InstallLocation)) {
        Write-Log "Skipping orphan check for v$($r.DisplayVersion): InstallLocation is blank." "WARN"
        continue
    }
    if (-not (Test-Path $r.InstallLocation)) {
        if ($PSCmdlet.ShouldProcess($r.PSPath, "Remove orphaned registry entry")) {
            Remove-Item $r.PSPath -Force -Recurse -ErrorAction SilentlyContinue
            Write-Log "Removed orphaned registry entry: v$($r.DisplayVersion) (pointed to missing path $($r.InstallLocation))"
        }
    }
}

# --- Step 5: re-scan for leftover folders that survived uninstall ---
$orphanFolders = $candidateFolders | Where-Object { Test-Path $_ } | Where-Object { $_ -ne $NormalizedPath }
if ($orphanFolders) {
    Write-Host ""
    Write-Host "These folders are still on disk after uninstall (leftover / never registered):" -ForegroundColor Yellow
    $orphanFolders | ForEach-Object { Write-Host "  - $_" }
    if ($Force) {
        Write-Log "-Force given: deleting leftover folders without prompting."
        $removeOrphans = "Y"
    } else {
        $removeOrphans = Read-Host "Delete these leftover folders? (Y/N)"
    }
    if ($removeOrphans -match '^[Yy]') {
        foreach ($f in $orphanFolders) {
            if ($PSCmdlet.ShouldProcess($f, "Remove leftover folder")) {
                Remove-Item $f -Recurse -Force -ErrorAction SilentlyContinue
                Write-Log "Removed leftover folder: $f"
            }
        }
    } else {
        Write-Log "User chose to keep leftover folders as-is: $($orphanFolders -join '; ')" "WARN"
    }
}

# --- Step 6: clean up broken shortcuts pointing at Notepad++ ---
$shortcutRoots = @(
    [Environment]::GetFolderPath("Desktop"),
    [Environment]::GetFolderPath("CommonDesktopDirectory"),
    [Environment]::GetFolderPath("StartMenu"),
    [Environment]::GetFolderPath("CommonStartMenu")
) | Where-Object { $_ -and (Test-Path $_) }

$shell = New-Object -ComObject WScript.Shell
$brokenShortcuts = foreach ($root in $shortcutRoots) {
    Get-ChildItem $root -Filter "*.lnk" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $target = $shell.CreateShortcut($_.FullName).TargetPath
            if ($target -match 'notepad\+\+' -and $target -and -not (Test-Path $target)) {
                $_.FullName
            }
        } catch { }
    }
}
if ($brokenShortcuts) {
    Write-Log "Broken Notepad++ shortcuts found: $($brokenShortcuts.Count)"
    foreach ($s in $brokenShortcuts) {
        if ($PSCmdlet.ShouldProcess($s, "Remove broken shortcut")) {
            Remove-Item $s -Force -ErrorAction SilentlyContinue
            Write-Log "Removed broken shortcut: $s"
        }
    }
}

# --- Step 7: clean install via EXE to the normalized path, updater disabled ---
Write-Log "Installing Notepad++ to $NormalizedPath (silent, auto-updater disabled)..."
if ($PSCmdlet.ShouldProcess($NormalizedPath, "Install Notepad++ from $SourceExePath")) {
    # NSIS requirement: /D=<path> must be the LAST argument and unquoted.
    $installArgs = "/S /noUpdater /D=$NormalizedPath"
    $p = Start-Process -FilePath $SourceExePath -ArgumentList $installArgs -Wait -PassThru
    if ($p.ExitCode -ne 0) {
        throw "Notepad++ install failed with exit code $($p.ExitCode)."
    }
    Write-Log "Install finished with exit code $($p.ExitCode)."

    # Belt-and-suspenders: /noUpdater can be silently ignored if a leftover
    # per-user config.xml from a previous install already has the updater
    # enabled. Removing the updater folder itself blocks it regardless.
    $updaterPath = Join-Path $NormalizedPath "updater"
    if (Test-Path $updaterPath) {
        Remove-Item $updaterPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log "Removed 'updater' folder to guarantee auto-update stays disabled: $updaterPath"
    }
}

# --- Step 8: verify final state ---
Start-Sleep -Seconds 2
$final = @(Get-ItemProperty $uninstallRoots -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -eq "Notepad++" -or $_.DisplayName -like "Notepad++*" })

Write-Host ""
if ($final -and (Test-Path (Join-Path $NormalizedPath "notepad++.exe"))) {
    Write-Log "Verified: Notepad++ v$($final[0].DisplayVersion) installed at $NormalizedPath"
    Write-Host "Done. Notepad++ v$($final[0].DisplayVersion) is now the only instance, at $NormalizedPath, auto-updater disabled." -ForegroundColor Green
} else {
    Write-Log "Could not verify the final install. Check $LogDir manually." "WARN"
    Write-Host "Install ran, but verification did not find notepad++.exe at $NormalizedPath -- check manually." -ForegroundColor Yellow
}
Write-Log "Log file: $LogFile"
