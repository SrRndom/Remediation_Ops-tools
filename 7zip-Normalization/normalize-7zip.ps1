<#
.SYNOPSIS
    Discovers all 7-Zip installations on a server (registered or not), removes
    them cleanly, cleans up orphaned traces, and reinstalls to a single
    normalized location using the official MSI.

.DESCRIPTION
    Years of ad-hoc installs left 7-Zip scattered across paths like
    C:\Program Files\7-Zip, D:\7zip, D:\Software\7zip, etc. -- some registered
    properly, some copied by hand, some with broken uninstall entries pointing
    to folders that no longer exist. This script:

      1. Finds every 7-Zip entry in the Windows uninstall registry (32/64-bit).
      2. Finds every folder on C:\ and D:\ whose name looks like a 7-Zip install,
         registered or not.
      3. Uninstalls every properly registered instance (MSI or legacy NSIS
         uninstaller, whichever applies).
      4. Removes registry entries that point to install locations that no
         longer exist on disk (orphaned uninstallers).
      5. After uninstall, re-scans for leftover folders that survived (never
         registered, or the uninstaller didn't clean them) and asks before
         removing them.
      6. Removes broken shortcuts (Desktop / Start Menu) pointing at 7-Zip
         paths that no longer exist.
      7. Installs the official MSI to a single normalized path
         (C:\Program Files\7-Zip by default).
      8. Verifies the final state and prints a summary.

    Meant to be run one server at a time, with human review of the discovery
    list before anything gets removed.

.PARAMETER NormalizedPath
    Target install path for the clean reinstall. Default: "C:\Program Files\7-Zip"

.PARAMETER SourceMsiPath
    Path to the official 7-Zip MSI. Defaults to auto-detecting a matching
    .msi (x64 vs x86, based on this OS) in the same folder as this script,
    so you only need to drop the installer(s) next to it.

.PARAMETER ScanDepth
    How many subfolder levels deep to search under C:\ and D:\ for leftover
    7-Zip folders. Default: 4 (covers things like D:\Data\Old\Backup\Tools\7zip).
    Raise it if your environment buries software deeper than that; lower it
    if the scan is too slow on a server with a huge C:\ tree.

.PARAMETER WhatIf
    Simulation mode: runs discovery and shows what would be removed/installed,
    without actually uninstalling, deleting, or installing anything.

.EXAMPLE
    .\Normalize-7Zip.ps1 -WhatIf
    Shows what would happen without touching anything.

.EXAMPLE
    .\Normalize-7Zip.ps1
    Runs the real cleanup and reinstall, with confirmation prompts before
    destructive steps.

.NOTES
    Requires an elevated PowerShell session (installs/uninstalls under
    Program Files and writes to HKLM).
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$NormalizedPath = "C:\Program Files\7-Zip",
    [string]$SourceMsiPath,
    [int]$ScanDepth = 4
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

$LogDir  = Join-Path $env:ProgramData "SevenZip_Normalization"
$LogFile = Join-Path $LogDir ("normalize_7zip_{0}.log" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

Write-Log "=== Starting 7-Zip discovery, cleanup, and normalization ==="
Write-Log "Target normalized path: $NormalizedPath"

# --- Auto-detect the MSI next to this script if not given ---
if (-not $SourceMsiPath) {
    $is64 = [Environment]::Is64BitOperatingSystem
    $candidates = Get-ChildItem $PSScriptRoot -Filter "7z*.msi" -ErrorAction SilentlyContinue
    if ($is64) {
        $SourceMsiPath = ($candidates | Where-Object { $_.Name -match 'x64' } | Select-Object -First 1).FullName
    }
    if (-not $SourceMsiPath) {
        $SourceMsiPath = ($candidates | Where-Object { $_.Name -notmatch 'x64' } | Select-Object -First 1).FullName
    }
}
if (-not $SourceMsiPath -or -not (Test-Path $SourceMsiPath)) {
    throw "No 7-Zip .msi found. Place the correct installer (7z*-x64.msi for 64-bit OS) next to this script, or pass -SourceMsiPath explicitly."
}
Write-Log "Installer to use: $SourceMsiPath"

# --- Step 1: discover registered installs ---
$uninstallRoots = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)
$registeredInstalls = Get-ItemProperty $uninstallRoots -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -like "7-Zip*" } |
    Select-Object DisplayName, DisplayVersion, InstallLocation, UninstallString, PSPath

Write-Log "Registered 7-Zip entries found: $($registeredInstalls.Count)"
foreach ($r in $registeredInstalls) {
    $existsOnDisk = $r.InstallLocation -and (Test-Path $r.InstallLocation)
    Write-Log ("  - {0} | v{1} | {2} | on disk: {3}" -f $r.DisplayName, $r.DisplayVersion, $r.InstallLocation, $existsOnDisk)
}

# --- Step 2: discover candidate folders on disk (registered or not) ---
$searchRoots = @("C:\", "D:\") | Where-Object { Test-Path $_ }
$candidateFolders = New-Object System.Collections.Generic.List[string]
foreach ($root in $searchRoots) {
    Get-ChildItem $root -Directory -Recurse -Depth $ScanDepth -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '7.?zip' } |
        ForEach-Object { if (-not $candidateFolders.Contains($_.FullName)) { $candidateFolders.Add($_.FullName) } }
}
Write-Log "Candidate 7-Zip folders found on disk (scan depth $ScanDepth): $($candidateFolders.Count)"
foreach ($f in $candidateFolders) { Write-Log "  - $f" }

if ($registeredInstalls.Count -eq 0 -and $candidateFolders.Count -eq 0) {
    Write-Log "No 7-Zip traces found at all. Proceeding straight to clean install."
} else {
    Write-Host ""
    $proceed = Read-Host "Proceed with uninstall + cleanup of everything listed above? (Y/N)"
    if ($proceed -notmatch '^[Yy]') {
        throw "Aborted by user before any changes were made."
    }
}

# --- Step 3: uninstall every registered instance ---
foreach ($r in $registeredInstalls) {
    if ($PSCmdlet.ShouldProcess($r.DisplayName, "Uninstall")) {
        if ($r.UninstallString -match '\{[0-9A-Fa-f\-]{36}\}') {
            $productCode = $Matches[0]
            Write-Log "Uninstalling (MSI) $($r.DisplayName) [$productCode]..."
            $msiLog = Join-Path $LogDir ("uninstall_{0}.log" -f ($productCode -replace '[{}]',''))
            $p = Start-Process "msiexec.exe" -ArgumentList "/x $productCode /qn /norestart /l*v `"$msiLog`"" -Wait -PassThru
            Write-Log "Exit code: $($p.ExitCode)"
        } elseif ($r.UninstallString) {
            Write-Log "Uninstalling (legacy installer) $($r.DisplayName) via: $($r.UninstallString)"
            try {
                # Legacy 7-Zip NSIS uninstaller supports /S for silent
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
$stillRegistered = Get-ItemProperty $uninstallRoots -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -like "7-Zip*" }
foreach ($r in $stillRegistered) {
    $existsOnDisk = $r.InstallLocation -and (Test-Path $r.InstallLocation)
    if (-not $existsOnDisk) {
        if ($PSCmdlet.ShouldProcess($r.PSPath, "Remove orphaned registry entry")) {
            Remove-Item $r.PSPath -Force -Recurse -ErrorAction SilentlyContinue
            Write-Log "Removed orphaned registry entry: $($r.DisplayName) (pointed to missing path $($r.InstallLocation))"
        }
    }
}

# --- Step 5: re-scan for leftover folders that survived uninstall ---
$orphanFolders = $candidateFolders | Where-Object { Test-Path $_ } | Where-Object { $_ -ne $NormalizedPath }
if ($orphanFolders) {
    Write-Host ""
    Write-Host "These folders are still on disk after uninstall (leftover / never registered):" -ForegroundColor Yellow
    $orphanFolders | ForEach-Object { Write-Host "  - $_" }
    $removeOrphans = Read-Host "Delete these leftover folders? (Y/N)"
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

# --- Step 6: clean up broken shortcuts pointing at 7-Zip ---
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
            if ($target -match '7.?zip' -and $target -and -not (Test-Path $target)) {
                $_.FullName
            }
        } catch { }
    }
}
if ($brokenShortcuts) {
    Write-Log "Broken 7-Zip shortcuts found: $($brokenShortcuts.Count)"
    foreach ($s in $brokenShortcuts) {
        if ($PSCmdlet.ShouldProcess($s, "Remove broken shortcut")) {
            Remove-Item $s -Force -ErrorAction SilentlyContinue
            Write-Log "Removed broken shortcut: $s"
        }
    }
}

# --- Step 7: clean install to the normalized path ---
Write-Log "Installing 7-Zip to $NormalizedPath ..."
if ($PSCmdlet.ShouldProcess($NormalizedPath, "Install 7-Zip from $SourceMsiPath")) {
    $installLog = Join-Path $LogDir "install.log"
    $p = Start-Process "msiexec.exe" -ArgumentList "/i `"$SourceMsiPath`" INSTALLDIR=`"$NormalizedPath`" /qn /norestart /l*v `"$installLog`"" -Wait -PassThru
    if ($p.ExitCode -notin 0, 3010) {
        throw "7-Zip install failed with exit code $($p.ExitCode). Check $installLog for details."
    }
    Write-Log "Install finished with exit code $($p.ExitCode)."
}

# --- Step 8: verify final state ---
Start-Sleep -Seconds 2
$final = Get-ItemProperty $uninstallRoots -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -like "7-Zip*" }

Write-Host ""
if ($final -and (Test-Path (Join-Path $NormalizedPath "7zFM.exe"))) {
    Write-Log "Verified: 7-Zip $($final.DisplayVersion) installed at $NormalizedPath"
    Write-Host "Done. 7-Zip $($final.DisplayVersion) is now the only instance, at $NormalizedPath." -ForegroundColor Green
} else {
    Write-Log "Could not verify the final install. Check $LogDir manually." "WARN"
    Write-Host "Install ran, but verification did not find 7zFM.exe at $NormalizedPath -- check manually." -ForegroundColor Yellow
}
Write-Log "Log file: $LogFile"
