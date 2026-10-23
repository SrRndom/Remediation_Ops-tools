<#
.SYNOPSIS
    Read-only inventory of every Java runtime (JDK/JRE) found on a server,
    with version, vendor, size, classification, and evidence of real usage.

.DESCRIPTION
    Vulnerability scanners report Java in many places (JDK, JRE, JAR files)
    without saying which ones matter. This script does NOT delete, uninstall
    or change anything. It builds an inventory so the decision can be made by
    a person, one item at a time.

    For every Java home found (any folder that contains bin\java.exe) it
    reports:
      - Version, vendor, JDK vs JRE and architecture, read from the "release"
        file or the file properties of java.exe. The binary is never executed.
      - Size on disk and creation date.
      - Classification (heuristic): Registered install, Standalone
        (unregistered), or Bundled runtime that belongs to another application.
      - Evidence of use: running processes, services (including Apache
        Procrun wrappers), scheduled tasks, JAVA_HOME / JRE_HOME / JDK_HOME,
        presence in the machine PATH, JavaSoft registry keys, and the
        installer's uninstall entry.

    Evidence is summarized in an EvidenceLevel column:
      1-Running now
      2-Configured (service/task/env var)
      3-Registered only (PATH/JavaSoft/installer)
      4-No evidence found

    IMPORTANT: "No evidence found" is NOT proof that a Java is unused. This is
    a snapshot. Something that runs once a month, or is started by a script or
    config file this script does not read, will show no evidence. Treat level 4
    as "candidate to investigate", never as "safe to delete".

    Output goes to CSV files (one per section) in the output folder, with a
    ComputerName column so files from many servers can be merged and compared.

    Not covered (by design or limitation):
      - Per-user environment variables and config files (setenv.bat, .ini,
        wrapper configs) that point to a Java path.
      - Service wrappers other than Apache Procrun.
      - The inside of JAR files (a library can be shaded inside another JAR).
        Use -IncludeJars to list JAR files by name only.
      - Java homes deeper than -ScanDepth.

.PARAMETER Drives
    Comma-separated drive letters to scan, for example "C,D". Default: all
    fixed local drives.

.PARAMETER ScanDepth
    How many folder levels deep to look for Java homes. Default: 8. Lower it
    (for example to 5) if the scan is too slow on a server with a huge tree.

.PARAMETER OutputDir
    Folder for the CSV files. Default: C:\ProgramData\Java_Inventory when
    elevated, or Java_Inventory inside your own profile when not elevated.
    When elevated, the folder's permissions are restricted to SYSTEM and
    local Administrators (inheritance removed), because the CSVs can contain
    process command lines.

.PARAMETER IncludeJars
    Also lists JAR files found outside Java homes, by name, in a separate CSV.

.PARAMETER JarHighlight
    Regex used to flag JAR file names of interest in the JAR list.
    Default: "log4j". Only used with -IncludeJars.

.EXAMPLE
    .\Get-JavaInventory.ps1
    Scans all fixed drives and writes the CSV files.

.EXAMPLE
    .\Get-JavaInventory.ps1 -Drives "C,D" -ScanDepth 6 -IncludeJars
    Scans only C and D, a bit shallower, and also lists JAR files.

.NOTES
    Works best from an elevated PowerShell session: without admin rights it
    cannot read other users' profiles or the command line of other users'
    processes, so results may be incomplete.

    Sensitive data: the RunningCmdHint column holds part of the command line
    of a running Java process. Values that look like secrets (passwords,
    tokens, keys, credentials in URLs, long random-looking strings) are masked
    with ***, but this masking is best effort and cannot catch every format.
    Review the CSV before sharing it, and keep it in the restricted folder.
#>

[CmdletBinding()]
param(
    [string]$Drives,
    [int]$ScanDepth = 8,
    [string]$OutputDir = (Join-Path $env:ProgramData "Java_Inventory"),
    [switch]$IncludeJars,
    [string]$JarHighlight = "log4j"
)

$ErrorActionPreference = "Continue"

# --- Elevation check (read-only script, so declining is allowed) ---
$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host ""
    Write-Host "Not running elevated. Without admin rights the scan cannot read other users' profiles" -ForegroundColor Yellow
    Write-Host "or the command line of other users' processes, so results may be incomplete." -ForegroundColor Yellow
    $answer = Read-Host "Relaunch elevated now? (Y/N - N continues with limited visibility)"
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
    }
}

# Without admin rights the output folder's permissions cannot be restricted, and
# ProgramData is readable by other users, so default to the user's own profile.
if (-not $isAdmin -and -not $PSBoundParameters.ContainsKey("OutputDir")) {
    $OutputDir = Join-Path $env:USERPROFILE "Java_Inventory"
    Write-Host "Not elevated: output folder switched to $OutputDir so other users cannot read it." -ForegroundColor Yellow
}

$hostName  = $env:COMPUTERNAME
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$startTime = Get-Date

function Write-Info {
    param([string]$Message)
    Write-Host ("[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $Message)
}

# Returns a path in a normalized form: trimmed, with exactly one trailing backslash.
function Get-DirKey {
    param([string]$Path)
    if (-not $Path) { return "" }
    return ($Path.Trim().TrimEnd('\') + '\')
}

function Test-UnderPrefix {
    param([string]$Path, [string]$Prefix)
    if (-not $Path -or -not $Prefix) { return $false }
    return $Path.StartsWith($Prefix, [StringComparison]::OrdinalIgnoreCase)
}

function Test-TextHasPath {
    param([string]$Text, [string]$Prefix)
    if (-not $Text -or -not $Prefix) { return $false }
    return ($Text.IndexOf($Prefix, [StringComparison]::OrdinalIgnoreCase) -ge 0)
}

# Best-effort masking of values that look like secrets in a command line.
# It cannot catch every format, so the output folder is also locked down.
function Hide-Secrets {
    param([string]$Text)
    if (-not $Text) { return $Text }
    $t = $Text
    # name=value or name:value where the name suggests a secret (-Dpassword=..., token=..., api_key: ...)
    $t = [regex]::Replace($t, '(?i)([\w.\-]*(?:pass(?:word|wd)?|pwd|secret|token|api[-_]?key|credential|auth)[\w.\-]*)\s*([=:])\s*("[^"]*"|''[^'']*''|\S+)', '$1$2***')
    # flag followed by a separate value (--password hunter2, -token abc)
    $t = [regex]::Replace($t, '(?i)(\s-{1,2}[\w.\-]*(?:pass(?:word|wd)?|pwd|secret|token|api[-_]?key|credential)[\w.\-]*)\s+("[^"]*"|''[^'']*''|[^\s-]\S*)', '$1 ***')
    # credentials inside URLs (scheme://user:pass@host)
    $t = [regex]::Replace($t, '(?i)(://)[^/\s:@]+:[^/\s@]+@', '$1***@')
    # long random-looking strings (keys, tokens, hashes)
    $t = [regex]::Replace($t, '(?<![\\\w.\-])[A-Za-z0-9+/_\-]{32,}={0,2}', '***')
    return $t
}

# Restricts a folder to SYSTEM and local Administrators, removing inherited access.
# Uses well-known SIDs so it works on any Windows language.
function Set-RestrictedAcl {
    param([string]$Path)
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($r in @($acl.Access)) { [void]$acl.RemoveAccessRule($r) }
    $inherit = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
    $prop    = [System.Security.AccessControl.PropagationFlags]::None
    $allow   = [System.Security.AccessControl.AccessControlType]::Allow
    foreach ($sidText in @("S-1-5-18", "S-1-5-32-544")) {
        $sid  = New-Object System.Security.Principal.SecurityIdentifier($sidText)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, "FullControl", $inherit, $prop, $allow)
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Read-ReleaseFile {
    param([string]$HomePath)
    $result = @{}
    $file = Join-Path $HomePath "release"
    if (Test-Path -LiteralPath $file) {
        Get-Content -LiteralPath $file -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_ -match '^\s*([A-Z_0-9]+)\s*=\s*"?([^"]*)"?\s*$') {
                $result[$Matches[1]] = $Matches[2]
            }
        }
    }
    return $result
}

# --- Discovery: walk the tree, pruning noisy folders, testing each folder for bin\java.exe ---
$excludedNames = @('$RECYCLE.BIN', 'System Volume Information', 'WinSxS', 'node_modules', '.git',
                   'Cache', 'Code Cache', 'GPUCache', 'CachedData', 'Package Cache')

function Find-JavaItems {
    param([string]$Root, [int]$MaxDepth, [bool]$CollectJars)

    $homes = New-Object System.Collections.Generic.List[string]
    $jars  = New-Object System.Collections.Generic.List[object]
    $windowsDir = Join-Path $Root "Windows"
    $queue = New-Object System.Collections.Generic.Queue[object]
    $queue.Enqueue(@{ Path = $Root; Depth = 0 })

    while ($queue.Count -gt 0) {
        $current = $queue.Dequeue()
        $dir = $current.Path

        if (Test-Path -LiteralPath (Join-Path $dir "bin\java.exe")) {
            $homes.Add($dir)
            continue
        }

        if ($CollectJars) {
            Get-ChildItem -LiteralPath $dir -File -Filter "*.jar" -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -ieq ".jar" } |
                ForEach-Object { $jars.Add($_) }
        }

        if ($current.Depth -ge $MaxDepth) { continue }

        $children = Get-ChildItem -LiteralPath $dir -Directory -Force -ErrorAction SilentlyContinue
        foreach ($child in $children) {
            if ($excludedNames -contains $child.Name) { continue }
            if ($child.FullName -ieq $windowsDir) { continue }
            if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
            $queue.Enqueue(@{ Path = $child.FullName; Depth = $current.Depth + 1 })
        }
    }

    return [PSCustomObject]@{ Homes = $homes; Jars = $jars }
}

# --- Resolve drives ---
$driveRoots = @()
if ($Drives) {
    foreach ($d in ($Drives -split ',')) {
        $letter = $d.Trim().TrimEnd(':', '\')
        if ($letter) { $driveRoots += ($letter + ":\") }
    }
} else {
    $driveRoots = @(Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue |
        ForEach-Object { $_.DeviceID + "\" })
}
$driveRoots = @($driveRoots | Where-Object { Test-Path -LiteralPath $_ })
if ($driveRoots.Count -eq 0) {
    throw "No drives to scan. Check the -Drives value."
}

Write-Info "=== Java inventory on $hostName ==="
Write-Info "Drives: $($driveRoots -join ', ') | Scan depth: $ScanDepth | Jars: $($IncludeJars.IsPresent)"

# --- Collect evidence sources once ---
Write-Info "Collecting running processes, services, scheduled tasks and registry references..."

$procs = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
    Select-Object ProcessId, Name, ExecutablePath, CommandLine)

$services = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
    Select-Object Name, State, PathName)

$taskActions = New-Object System.Collections.Generic.List[object]
try {
    foreach ($t in (Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        foreach ($a in $t.Actions) {
            if ($a.PSObject.Properties.Name -contains 'Execute') {
                $taskActions.Add([PSCustomObject]@{
                    TaskName  = $t.TaskName
                    TaskPath  = $t.TaskPath
                    State     = [string]$t.State
                    Execute   = [string]$a.Execute
                    Arguments = [string]$a.Arguments
                })
            }
        }
    }
} catch {
    Write-Info "Could not read scheduled tasks: $($_.Exception.Message)"
}

$envJavaVars = @{}
foreach ($name in @("JAVA_HOME", "JRE_HOME", "JDK_HOME")) {
    $v = [Environment]::GetEnvironmentVariable($name, "Machine")
    if ($v) { $envJavaVars[$name] = Get-DirKey $v }
}

$machinePathRaw = [Environment]::GetEnvironmentVariable("Path", "Machine")
$machinePath = [Environment]::ExpandEnvironmentVariables($machinePathRaw)
$pathEntries = @($machinePath -split ';' | Where-Object { $_ } | ForEach-Object { Get-DirKey $_ })

$javaSoft = New-Object System.Collections.Generic.List[object]
foreach ($rootKey in @("HKLM:\SOFTWARE\JavaSoft", "HKLM:\SOFTWARE\WOW6432Node\JavaSoft")) {
    if (Test-Path $rootKey) {
        Get-ChildItem $rootKey -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
            if ($p -and $p.JavaHome) {
                $javaSoft.Add([PSCustomObject]@{
                    Key      = ($_.Name -replace '^HKEY_LOCAL_MACHINE\\', '')
                    JavaHome = Get-DirKey $p.JavaHome
                })
            }
        }
    }
}

$procrun = New-Object System.Collections.Generic.List[object]
foreach ($rk in @("HKLM:\SOFTWARE\Apache Software Foundation\Procrun 2.0",
                  "HKLM:\SOFTWARE\WOW6432Node\Apache Software Foundation\Procrun 2.0")) {
    if (Test-Path $rk) {
        Get-ChildItem $rk -ErrorAction SilentlyContinue | ForEach-Object {
            $svcName = $_.PSChildName
            $pp = Get-ItemProperty -LiteralPath ("{0}\Parameters\Java" -f $_.PSPath) -ErrorAction SilentlyContinue
            if ($pp -and $pp.Jvm) {
                $procrun.Add([PSCustomObject]@{ Service = $svcName; Jvm = [string]$pp.Jvm })
            }
        }
    }
}

$uninstallRoots = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)
$registered = @(Get-ItemProperty $uninstallRoots -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -and $_.DisplayName -match '\b(Java|JDK|JRE|OpenJDK|Temurin|Adoptium|Zulu|Corretto|Semeru|Liberica|IcedTea)\b' } |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallLocation, InstallDate, UninstallString)

function Get-UsageEvidence {
    param([string]$Prefix)

    $running = @($procs | Where-Object { Test-UnderPrefix $_.ExecutablePath $Prefix })
    $viaCmd  = @($procs | Where-Object {
        -not (Test-UnderPrefix $_.ExecutablePath $Prefix) -and (Test-TextHasPath $_.CommandLine $Prefix)
    })
    $runningAll = @($running) + @($viaCmd)
    $runningText = ($runningAll | Select-Object -First 3 | ForEach-Object { "{0}({1})" -f $_.Name, $_.ProcessId }) -join "; "
    $cmdHint = ""
    if ($runningAll.Count -gt 0 -and $runningAll[0].CommandLine) {
        # Mask first, truncate after: cutting first could leave half a secret unmasked.
        $cmdHint = Hide-Secrets ([string]$runningAll[0].CommandLine)
        if ($cmdHint.Length -gt 160) { $cmdHint = $cmdHint.Substring(0, 160) }
    }

    $svcList = @()
    foreach ($s in @($services | Where-Object { Test-TextHasPath $_.PathName $Prefix })) {
        $svcList += ("{0}[{1}]" -f $s.Name, $s.State)
    }
    foreach ($pr in @($procrun | Where-Object { Test-TextHasPath $_.Jvm $Prefix })) {
        $svcList += ("{0}(procrun)" -f $pr.Service)
    }
    $svcText = $svcList -join "; "

    $taskList = @($taskActions | Where-Object {
        (Test-TextHasPath $_.Execute $Prefix) -or (Test-TextHasPath $_.Arguments $Prefix)
    } | ForEach-Object { "{0}{1}" -f $_.TaskPath, $_.TaskName })
    $taskText = $taskList -join "; "

    $envList = @()
    foreach ($k in $envJavaVars.Keys) {
        if ($envJavaVars[$k] -ieq $Prefix) { $envList += $k }
    }
    $envText = $envList -join "; "

    $binKey = Get-DirKey (Join-Path $Prefix "bin")
    $onPath = (@($pathEntries | Where-Object { $_ -ieq $binKey }).Count -gt 0)

    $jsText = (@($javaSoft | Where-Object { $_.JavaHome -ieq $Prefix } | ForEach-Object { $_.Key }) -join "; ")

    $instText = (@($registered | Where-Object {
        $_.InstallLocation -and ((Get-DirKey $_.InstallLocation) -ieq $Prefix)
    } | ForEach-Object { $_.DisplayName }) -join "; ")

    $level = "4-No evidence found"
    if ($runningAll.Count -gt 0) {
        $level = "1-Running now"
    } elseif ($svcText -or $taskText -or $envText) {
        $level = "2-Configured (service/task/env var)"
    } elseif ($onPath -or $jsText -or $instText) {
        $level = "3-Registered only (PATH/JavaSoft/installer)"
    }

    return [PSCustomObject]@{
        Level     = $level
        Running   = $runningText
        CmdHint   = $cmdHint
        Services  = $svcText
        Tasks     = $taskText
        EnvVars   = $envText
        OnPath    = $onPath
        JavaSoft  = $jsText
        Installer = $instText
    }
}

function Get-JavaHomeInfo {
    param([string]$HomePath)

    $rel = Read-ReleaseFile -HomePath $HomePath
    $javaExe = Join-Path $HomePath "bin\java.exe"
    $vi = $null
    if (Test-Path -LiteralPath $javaExe) { $vi = (Get-Item -LiteralPath $javaExe).VersionInfo }

    $notes = @()
    $version = $rel["JAVA_VERSION"]
    if (-not $version -and $vi) {
        $version = $vi.FileVersion
        $notes += "No release file: version from java.exe file info"
    }
    $vendor = $rel["IMPLEMENTOR"]
    if (-not $vendor -and $vi) { $vendor = $vi.CompanyName }

    $arch = $rel["OS_ARCH"]
    if (-not $arch -and $HomePath -match 'Program Files \(x86\)') { $arch = "x86 (by path)" }

    $type = "JRE"
    if (Test-Path -LiteralPath (Join-Path $HomePath "bin\javac.exe")) { $type = "JDK" }

    $bytes = (Get-ChildItem -LiteralPath $HomePath -Recurse -Force -File -ErrorAction SilentlyContinue |
        Measure-Object -Property Length -Sum).Sum
    if (-not $bytes) { $bytes = 0 }

    $created = ""
    try { $created = (Get-Item -LiteralPath $HomePath).CreationTime.ToString("yyyy-MM-dd") } catch { }

    return [PSCustomObject]@{
        Type           = $type
        Version        = $version
        RuntimeVersion = $rel["JAVA_RUNTIME_VERSION"]
        Vendor         = $vendor
        Arch           = $arch
        SizeMB         = [math]::Round($bytes / 1MB, 1)
        Created        = $created
        NestedJre      = (Test-Path -LiteralPath (Join-Path $HomePath "jre\bin\java.exe"))
        Notes          = ($notes -join "; ")
    }
}

# Heuristic classification: registered install, standalone (unregistered), or bundled with an app.
function Get-Classification {
    param([string]$HomePath, [string]$InstallerText)

    $leaf = Split-Path $HomePath -Leaf
    $parentPath = Split-Path $HomePath -Parent
    $parentLeaf = ""
    if ($parentPath) { $parentLeaf = Split-Path $parentPath -Leaf }

    $standaloneParents = @('Java', 'Eclipse Adoptium', 'Eclipse Foundation', 'AdoptOpenJDK',
                           'Amazon Corretto', 'Zulu', 'Microsoft', 'BellSoft', 'Semeru', 'RedHat', 'Oracle')

    if ($InstallerText) {
        return [PSCustomObject]@{ Class = "Registered install"; Owner = "" }
    }
    if ($leaf -match '^(jdk|jre|openjdk|temurin|zulu|corretto|semeru|liberica|java)[-_.]?\d' -or
        $standaloneParents -contains $parentLeaf) {
        return [PSCustomObject]@{ Class = "Standalone (unregistered)"; Owner = "" }
    }
    return [PSCustomObject]@{ Class = "Bundled runtime"; Owner = $parentPath }
}

# --- Scan ---
$allHomes = New-Object System.Collections.Generic.List[string]
$allJars  = New-Object System.Collections.Generic.List[object]

foreach ($root in $driveRoots) {
    Write-Info "Scanning $root ..."
    $found = Find-JavaItems -Root $root -MaxDepth $ScanDepth -CollectJars $IncludeJars.IsPresent
    foreach ($h in $found.Homes) { $allHomes.Add($h) }
    foreach ($j in $found.Jars)  { $allJars.Add($j) }
    Write-Info ("  {0}: {1} Java home(s)" -f $root, $found.Homes.Count)
}

# --- Build rows ---
$rows = New-Object System.Collections.Generic.List[object]
$counter = 0
foreach ($h in $allHomes) {
    $counter++
    Write-Info ("Inspecting {0}/{1}: {2}" -f $counter, $allHomes.Count, $h)
    $prefix = Get-DirKey $h
    $info = Get-JavaHomeInfo -HomePath $h
    $ev = Get-UsageEvidence -Prefix $prefix
    $cls = Get-Classification -HomePath $h -InstallerText $ev.Installer

    $rows.Add([PSCustomObject]@{
        ComputerName   = $hostName
        HomePath       = $h
        Type           = $info.Type
        Version        = $info.Version
        RuntimeVersion = $info.RuntimeVersion
        Vendor         = $info.Vendor
        Arch           = $info.Arch
        SizeMB         = $info.SizeMB
        Created        = $info.Created
        Classification = $cls.Class
        OwnerApp       = $cls.Owner
        EvidenceLevel  = $ev.Level
        RunningNow     = $ev.Running
        RunningCmdHint = $ev.CmdHint
        Services       = $ev.Services
        ScheduledTasks = $ev.Tasks
        EnvVars        = $ev.EnvVars
        OnMachinePath  = $ev.OnPath
        JavaSoftKeys   = $ev.JavaSoft
        InstallerEntry = $ev.Installer
        NestedJre      = $info.NestedJre
        Notes          = $info.Notes
    })
}

# System launcher stubs (they only dispatch to the registered Java, so size/usage rules differ).
$stubExes = New-Object System.Collections.Generic.List[string]
foreach ($p in @((Join-Path $env:windir "System32\java.exe"), (Join-Path $env:windir "SysWOW64\java.exe"))) {
    if (Test-Path -LiteralPath $p) { $stubExes.Add($p) }
}
$oracleShimRoot = Join-Path $env:ProgramData "Oracle\Java"
if (Test-Path -LiteralPath $oracleShimRoot) {
    Get-ChildItem -LiteralPath $oracleShimRoot -Recurse -Filter "java.exe" -ErrorAction SilentlyContinue |
        ForEach-Object { $stubExes.Add($_.FullName) }
}
foreach ($exe in $stubExes) {
    $vi = (Get-Item -LiteralPath $exe).VersionInfo
    $runningStub = @($procs | Where-Object { $_.ExecutablePath -ieq $exe })
    $level = "3-Registered only (PATH/JavaSoft/installer)"
    if ($runningStub.Count -gt 0) { $level = "1-Running now" }
    $rows.Add([PSCustomObject]@{
        ComputerName   = $hostName
        HomePath       = (Split-Path $exe -Parent)
        Type           = "launcher"
        Version        = $vi.FileVersion
        RuntimeVersion = ""
        Vendor         = $vi.CompanyName
        Arch           = ""
        SizeMB         = [math]::Round((Get-Item -LiteralPath $exe).Length / 1MB, 1)
        Created        = (Get-Item -LiteralPath $exe).CreationTime.ToString("yyyy-MM-dd")
        Classification = "System launcher/stub"
        OwnerApp       = ""
        EvidenceLevel  = $level
        RunningNow     = (($runningStub | Select-Object -First 3 | ForEach-Object { "{0}({1})" -f $_.Name, $_.ProcessId }) -join "; ")
        RunningCmdHint = ""
        Services       = ""
        ScheduledTasks = ""
        EnvVars        = ""
        OnMachinePath  = ""
        JavaSoftKeys   = ""
        InstallerEntry = ""
        NestedJre      = $false
        Notes          = "File: $exe. Stub that dispatches to the registered Java; not evaluated for usage like a full runtime."
    })
}

# Scheduled tasks that call java through PATH (cannot be attributed to a single home).
$viaPath = @($taskActions | Where-Object { $_.Execute.Trim('"') -match '^javaw?(\.exe)?$' } |
    Select-Object @{n='ComputerName';e={$hostName}}, TaskPath, TaskName, State, Execute, Arguments)

# Registered Java products, for manual cross-checking.
$registeredRows = @($registered | Select-Object @{n='ComputerName';e={$hostName}},
    DisplayName, DisplayVersion, Publisher, InstallLocation, InstallDate, UninstallString)

# JAR list (names only).
$jarRows = @()
if ($IncludeJars.IsPresent) {
    $jarRows = @($allJars | ForEach-Object {
        $ver = ""
        if ($_.Name -match '-(\d+(?:\.\d+)+)') { $ver = $Matches[1] }
        $hl = ""
        if ($JarHighlight -and $_.Name -match $JarHighlight) { $hl = "MATCH" }
        [PSCustomObject]@{
            ComputerName    = $hostName
            Directory       = $_.DirectoryName
            Name            = $_.Name
            SizeKB          = [math]::Round($_.Length / 1KB, 0)
            VersionFromName = $ver
            Highlight       = $hl
        }
    })
}

# --- Export ---
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
if ($isAdmin) {
    try {
        Set-RestrictedAcl -Path $OutputDir
        Write-Info "Output folder restricted to SYSTEM and Administrators: $OutputDir"
    } catch {
        Write-Info "WARNING: could not restrict permissions on $OutputDir ($($_.Exception.Message)). Treat the CSVs as sensitive and move them somewhere private."
    }
}
$rowsSorted = @($rows | Sort-Object EvidenceLevel, HomePath)

function Export-IfAny {
    param([object[]]$Data, [string]$Label)
    if ($Data.Count -gt 0) {
        $file = Join-Path $OutputDir ("{0}_{1}_{2}.csv" -f $hostName, $Label, $timestamp)
        $Data | Export-Csv -LiteralPath $file -NoTypeInformation -Encoding UTF8
        Write-Info ("Wrote {0} row(s): {1}" -f $Data.Count, $file)
    }
}

Export-IfAny -Data $rowsSorted     -Label "JavaHomes"
Export-IfAny -Data $registeredRows -Label "RegisteredJavaProducts"
Export-IfAny -Data $viaPath        -Label "TasksCallingJavaViaPath"
Export-IfAny -Data $jarRows        -Label "Jars"

# --- Summary ---
Write-Host ""
Write-Info "=== Summary for $hostName ==="
if ($rowsSorted.Count -eq 0) {
    Write-Info "No Java homes or launchers found."
} else {
    foreach ($g in ($rowsSorted | Group-Object EvidenceLevel | Sort-Object Name)) {
        $mb = ($g.Group | Measure-Object -Property SizeMB -Sum).Sum
        Write-Info ("  {0}: {1} item(s), {2:N0} MB" -f $g.Name, $g.Count, $mb)
    }
    Write-Host ""
    $rowsSorted | Select-Object HomePath, Type, Version, SizeMB, Classification, EvidenceLevel |
        Format-Table -AutoSize -Wrap
}
if ($IncludeJars.IsPresent) {
    $highlightCount = @($jarRows | Where-Object { $_.Highlight -eq "MATCH" }).Count
    Write-Info ("JAR files outside Java homes: {0} (highlight '{1}': {2})" -f $jarRows.Count, $JarHighlight, $highlightCount)
}
Write-Info ("Elapsed: {0:N1} minute(s)" -f ((Get-Date) - $startTime).TotalMinutes)
Write-Host ""
Write-Host "Reminder: 'No evidence found' means a candidate to investigate, not proof the Java is unused." -ForegroundColor Yellow
