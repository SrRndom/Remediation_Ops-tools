<#
.SYNOPSIS
    Removes leftover ".vscode" folders from user profiles on servers where
    VS Code is no longer installed.

.DESCRIPTION
    The ".vscode" folder in a user profile (C:\Users\<user>\.vscode) holds
    installed extensions and editor state. On a server where VS Code was
    removed (or never kept), those folders are dead weight and often carry
    bundled third-party code that vulnerability scanners keep flagging.

    This script:
      1. Refuses to run if VS Code is still installed system-wide or is
         currently running (that means the assumption "VS Code is gone" is
         wrong, and deleting extensions would break someone's environment).
      2. Lists every profile under the users root that has a ".vscode" folder,
         with its size.
      3. Skips any profile that has a per-user VS Code install, and any
         ".vscode" that is a symlink/junction (never followed or deleted).
      4. Asks for confirmation (unless -Force), then deletes the folders.
         Deep node_modules trees can exceed the Windows path-length limit, so
         if a normal delete fails, it retries with a robocopy-based method.
      5. Prints a summary of what was removed and what failed.

    Only the profile-level ".vscode" is touched. Project-level ".vscode"
    folders, "%APPDATA%\Code" user settings, and other variants such as
    ".vscode-server" or ".vscode-insiders" are NOT covered.

.PARAMETER UsersRoot
    Folder that contains the user profiles. Default: "C:\Users"

.PARAMETER WhatIf
    Simulation mode: lists what would be deleted without deleting anything.

.PARAMETER Force
    Skips the confirmation prompt and deletes without asking. The safety
    checks (VS Code installed or running, per-user installs, symlinks) still
    apply and are not bypassed by -Force.

.EXAMPLE
    .\Remove-VSCodeProfileLeftovers.ps1 -WhatIf
    Shows what would be removed without touching anything.

.EXAMPLE
    .\Remove-VSCodeProfileLeftovers.ps1 -Force
    Removes the leftovers without prompting.

.NOTES
    Requires an elevated PowerShell session (needs rights over other users'
    profile folders). Deletion is permanent: there is no backup or rollback.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$UsersRoot = "C:\Users",
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

$LogDir  = Join-Path $env:ProgramData "VSCode_Cleanup"
$LogFile = Join-Path $LogDir ("vscode_cleanup_{0}.log" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

function Remove-DeepFolder {
    param([string]$Path)
    try {
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
    } catch {
        Write-Log "Standard delete hit an error ($($_.Exception.Message)). Retrying with the robocopy method." "WARN"
    }
    if (Test-Path -LiteralPath $Path) {
        # Mirroring an empty folder over the target empties it even when paths
        # exceed the Windows path-length limit, then the empty shell is removed.
        $empty = Join-Path $env:TEMP ("empty_" + [guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $empty -Force | Out-Null
        & robocopy.exe $empty $Path /MIR /NJH /NJS /NFL /NDL /NP /R:0 /W:0 | Out-Null
        Remove-Item -LiteralPath $empty -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
    }
    return (-not (Test-Path -LiteralPath $Path))
}

Write-Log "=== Starting VS Code profile leftovers cleanup ==="
Write-Log "Users root: $UsersRoot"

if (-not (Test-Path $UsersRoot)) {
    throw "Users root not found: $UsersRoot"
}

# --- Safety check 1: VS Code installed system-wide? ---
$uninstallRoots = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)
$installed = @(Get-ItemProperty $uninstallRoots -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -like "Microsoft Visual Studio Code*" })
if ($installed.Count -gt 0) {
    throw "VS Code is installed on this server ($($installed[0].DisplayName) v$($installed[0].DisplayVersion)). Aborting: deleting extensions would affect whoever uses it."
}

# --- Safety check 2: VS Code running? ---
$running = Get-Process -Name "Code" -ErrorAction SilentlyContinue
if ($running) {
    throw "A 'Code' process is running (PID $($running[0].Id)), so VS Code exists somewhere on this server. Aborting."
}

# --- Discover profiles with a .vscode folder ---
$excludedProfiles = @("Public", "Default", "Default User", "All Users")
$targets = New-Object System.Collections.Generic.List[object]

Get-ChildItem -LiteralPath $UsersRoot -Directory -Force -ErrorAction SilentlyContinue |
    Where-Object { $excludedProfiles -notcontains $_.Name } |
    ForEach-Object {
        $profilePath = $_.FullName
        $vscodePath  = Join-Path $profilePath ".vscode"
        if (-not (Test-Path -LiteralPath $vscodePath)) { return }

        $item = Get-Item -LiteralPath $vscodePath -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            Write-Log "Skipping $vscodePath : it is a symlink/junction, not followed or deleted." "WARN"
            return
        }

        $perUserInstall = Join-Path $profilePath "AppData\Local\Programs\Microsoft VS Code\Code.exe"
        if (Test-Path -LiteralPath $perUserInstall) {
            Write-Log "Skipping $vscodePath : this profile has a per-user VS Code install." "WARN"
            return
        }

        $bytes = (Get-ChildItem -LiteralPath $vscodePath -Recurse -Force -File -ErrorAction SilentlyContinue |
            Measure-Object -Property Length -Sum).Sum
        if (-not $bytes) { $bytes = 0 }
        $targets.Add([PSCustomObject]@{ Path = $vscodePath; Bytes = [int64]$bytes })
    }

if ($targets.Count -eq 0) {
    Write-Log "No .vscode folders found under $UsersRoot. Nothing to do."
    Write-Log "Log file: $LogFile"
    return
}

$totalBytes = ($targets | Measure-Object -Property Bytes -Sum).Sum
Write-Log "Found $($targets.Count) .vscode folder(s), $('{0:N1}' -f ($totalBytes / 1MB)) MB in total:"
foreach ($t in $targets) {
    Write-Log ("  - {0} ({1:N1} MB)" -f $t.Path, ($t.Bytes / 1MB))
}

# --- Confirmation ---
if ($Force) {
    Write-Log "-Force given: deleting without prompting."
} else {
    Write-Host ""
    Write-Host "Deletion is permanent, there is no backup." -ForegroundColor Yellow
    $proceed = Read-Host "Delete the folders listed above? (Y/N)"
    if ($proceed -notmatch '^[Yy]') {
        throw "Aborted by user before any changes were made."
    }
}

# --- Delete ---
$removed = 0
$failed  = New-Object System.Collections.Generic.List[string]
foreach ($t in $targets) {
    if ($PSCmdlet.ShouldProcess($t.Path, "Delete .vscode folder")) {
        if (Remove-DeepFolder -Path $t.Path) {
            $removed++
            Write-Log "Removed: $($t.Path)"
        } else {
            $failed.Add($t.Path)
            Write-Log "Could not remove: $($t.Path)" "ERROR"
        }
    }
}

# --- Summary ---
Write-Host ""
Write-Log ("Done. Removed {0} of {1} folder(s). Failed: {2}." -f $removed, $targets.Count, $failed.Count)
if ($failed.Count -gt 0) {
    Write-Host "Folders that could not be removed (check permissions or open file handles):" -ForegroundColor Yellow
    $failed | ForEach-Object { Write-Host "  - $_" }
}
Write-Log "Log file: $LogFile"
