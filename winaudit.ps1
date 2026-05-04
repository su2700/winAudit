<#
.SYNOPSIS
  Stable Windows audit script for Windows Server 2022+ (PowerShell)

.DESCRIPTION
  - Uses CIM/WMI instead of deprecated WMIC
  - Timeout protection for slow commands
  - Exports scheduled tasks
  - Transcript logging
  - Full environment dump (Get-ChildItem Env:)
  - PowerShell command history check (Get-History + history file read)
  - Hotfix/update info and pending reboot indicators

.USAGE
  .\winaudit.ps1
  .\winaudit.ps1 -OutLog "C:\Temp\audit.log" -SchtasksFile "C:\Temp\schtasks.txt" -TimeoutSeconds 20
#>

param(
    [string]$OutLog = ".\audit_output.txt",
    [string]$SchtasksFile = ".\schtasks.txt",
    [string]$ExportJson = $null,
    [int]$TimeoutSeconds = 20,
    [int]$RegContextBefore = 60,
    [int]$RegContextAfter = 60,
    [switch]$RegSafeMode
)

# ---------------------------
# Structured Data Initialization
# ---------------------------
$Script:AuditData = [ordered]@{
    Metadata = [ordered]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        User = $env:USERNAME
        ComputerName = $env:COMPUTERNAME
    }
    Results = [System.Collections.Generic.List[object]]::new()
}

function Add-AuditResult {
    param([string]$Category, [object]$Data)
    $Script:AuditData.Results.Add([ordered]@{
        Category = $Category
        Data = $Data
    })
}

# ---------------------------
# Transcript / Logging
# ---------------------------
try {
    if (Get-Command Start-Transcript -ErrorAction SilentlyContinue) {
        try { Stop-Transcript -ErrorAction SilentlyContinue } catch { }
        Start-Transcript -Path $OutLog -Force | Out-Null
    } else {
        Write-Output "Start-Transcript not available; continuing without it."
    }
} catch {
    Write-Warning ("Could not start transcript: {0}" -f $_)
}

# ---------------------------
# Global State for ADHD-friendly Summary
# ---------------------------
$Script:AlertCount = 0
$Script:WarningCount = 0
$Script:SummaryList = [System.Collections.Generic.List[string]]::new()
$Script:CurrentStep = 0
$Script:TotalSteps = 15 # Estimated total headers

# ---------------------------
# Helper functions
# ---------------------------
function Write-AuditAlert {
    param([string]$Message)
    $Script:AlertCount++
    $Script:SummaryList.Add("🚨 ALERT: $Message")
    Write-Host "  🚨 [ALERT] $Message" -ForegroundColor Red
    Write-Output "[ALERT] $Message"
}

function Write-AuditWarning {
    param([string]$Message)
    $Script:WarningCount++
    $Script:SummaryList.Add("⚠️ WARNING: $Message")
    Write-Host "  ⚠️ [WARNING] $Message" -ForegroundColor Yellow
    Write-Output "[WARNING] $Message"
}

function Write-AuditInfo {
    param([string]$Message)
    Write-Host "  🔍 [INFO] $Message" -ForegroundColor Cyan
    Write-Output "[INFO] $Message"
}

function Write-AuditSuccess {
    param([string]$Message)
    Write-Host "  ✅ [SUCCESS] $Message" -ForegroundColor Green
    Write-Output "[SUCCESS] $Message"
}

function Header {
    param([string]$title)
    $Script:CurrentStep++
    $sep = "═" * 80
    Write-Host ""
    Write-Host $sep -ForegroundColor Cyan
    Write-Host ("  Step $($Script:CurrentStep)/$($Script:TotalSteps): {0}" -f $title.ToUpper()) -ForegroundColor White -BackgroundColor DarkCyan
    Write-Host $sep -ForegroundColor Cyan

    # For transcript/log
    Write-Output ""
    Write-Output ("=" * 80)
    Write-Output ("== Step $Script:CurrentStep: {0}" -f $title)
    Write-Output ("=" * 80)
}

function RunCommand {
    param([Parameter(Mandatory=$true)][string]$Cmd,[object[]]$Args=@())
    try { & $Cmd @Args 2>&1 } catch { Write-Output ("Command {0} failed: {1}" -f $Cmd, $_) }
}

function RunCommandWithTimeout {
    param([Parameter(Mandatory=$true)][string]$Cmd,[object[]]$Args=@(),[int]$Timeout=20)
    try {
        $job = Start-Job -ScriptBlock { param($c,$a) & $c @a 2>&1 } -ArgumentList $Cmd,$Args
        if (Wait-Job $job -Timeout $Timeout) {
            $out = Receive-Job $job -ErrorAction SilentlyContinue
            Remove-Job $job -Force -ErrorAction SilentlyContinue
            return $out
        } else {
            Write-Warning ("Command timed out after {0}s: {1} {2}" -f $Timeout,$Cmd,($Args -join ' '))
            Stop-Job $job -Force -ErrorAction SilentlyContinue
            Remove-Job $job -Force -ErrorAction SilentlyContinue
            return @("<<TIMED OUT>>")
        }
    } catch {
        Write-Output ("RunCommandWithTimeout error: {0}" -f $_)
    }
}

# ---------------------------
# Registry helper utilities
# ---------------------------
function Normalize-RegistryValueToString {
    param([object]$Value)
    if ($Value -is [byte[]]) {
        return ($Value | ForEach-Object { $_.ToString('X2') }) -join ''
    } elseif ($Value -is [System.Array]) {
        return ($Value -join '|')
    } else {
        return [string]$Value
    }
}

function Get-Snippet {
    param([string]$Text,[int]$Index,[int]$LengthBefore=60,[int]$LengthAfter=60)
    $start = [math]::Max(0, $Index - $LengthBefore)
    $len = [math]::Min($LengthBefore + $LengthAfter + 0, [math]::Max(0, $Text.Length - $start))
    if ($len -le 0) { return "" }
    return $Text.Substring($start, [math]::Min($len, $Text.Length - $start))
}


# ---------------------------
# REPORT
# ---------------------------

Header "WHOAMI"
$whoami = RunCommand "whoami.exe"
$whoami | Write-Output
Add-AuditResult -Category "WhoAmI" -Data $whoami

Header "USERNAME (environment)"
Write-Output $env:USERNAME

Header "PRIVILEGES"
$privs = RunCommand "whoami.exe" @("/priv")
$privs | Write-Output
Add-AuditResult -Category "Privileges" -Data $privs

Header "SYSTEM INFO"
$sysinfo = RunCommand "systeminfo.exe"
$sysinfo | Write-Output
Add-AuditResult -Category "System Info" -Data $sysinfo

Header "OS INFO (Caption, CSDVersion, OSArchitecture, Version)"
try {
    $osInfo = Get-CimInstance Win32_OperatingSystem | Select-Object Caption, CSDVersion, OSArchitecture, Version
    $osInfo | Format-List | Out-String | Write-Output
    Add-AuditResult -Category "OS Info" -Data $osInfo
} catch {
    Write-Output ("OS Info failed: {0}" -f $_)
}

Header "ENVIRONMENT (Get-ChildItem Env:)"
try {
    $envVars = Get-ChildItem Env: | Sort-Object Name
    $envVars | Format-Table -AutoSize | Out-String | Write-Output
    Add-AuditResult -Category "Environment Variables" -Data $envVars
    
    Write-Output "`n-- PATH entries (first 40) --"
    $paths = ($env:Path -split ';')[0..([math]::Min(39,($env:Path -split ';').Count-1))]
    $paths | ForEach-Object { Write-Output $_ }
    
    Write-Output "`n-- PSModulePath entries --"
    ($env:PSModulePath -split ';') | ForEach-Object { Write-Output $_ }
    
    Write-Output "`n-- PowerShell version table --"
    $PSVersionTable | Format-List | Out-String | Write-Output
    Add-AuditResult -Category "PowerShell Version" -Data $PSVersionTable
} catch {
    Write-Output ("Environment section failed: {0}" -f $_)
}

Header "POWERSHELL HISTORY"
try {
    Write-Output "`n-- Current session history (Get-History) --"
    $hist = Get-History | Select-Object Id, CommandLine
    $hist | Format-Table -AutoSize | Out-String | Write-Output
    Add-AuditResult -Category "Session History" -Data $hist

    Write-Output "`n-- Persistent PSReadLine history file (if available) --"
    # Try multiple possible history file locations
    $historyPaths = @(
        "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
        (Get-PSReadLineOption).HistorySavePath
    )
    
    $historyFile = $null
    foreach ($hp in $historyPaths) {
        if ($hp -and (Test-Path $hp -ErrorAction SilentlyContinue)) {
            $historyFile = $hp
            break
        }
    }
    
    if ($historyFile) {
        $lines = Get-Content $historyFile -ErrorAction SilentlyContinue
        Write-Output ("History file: {0}" -f $historyFile)
        Write-Output ("Total lines: {0}" -f $lines.Count)
        Write-Output "`nLast 30 commands:"
        $last30 = $lines | Select-Object -Last 30
        $last30 | ForEach-Object { Write-Output $_ }
        Add-AuditResult -Category "Persistent History" -Data @{ File = $historyFile; Last30 = $last30 }
    } else {
        Write-Output "No PSReadLine history file found at any known location."
    }
} catch {
    Write-Output ("History check failed: {0}" -f $_)
}

Header "SERVICES (Name, StartName, State)"
try {
    $svc = Get-CimInstance Win32_Service | Select-Object Name, StartName, State
    $svc | Format-Table -AutoSize | Out-String | Write-Output
    Write-Output ("`n(Total services enumerated: {0})" -f ($svc | Measure-Object).Count)
    Add-AuditResult -Category "Services" -Data $svc
} catch { Write-Output ("Service enumeration failed: {0}" -f $_) }

Header "NET START (running services)"
$netStart = RunCommandWithTimeout "net.exe" @("start") $TimeoutSeconds
$netStart | Write-Output
Add-AuditResult -Category "Running Services" -Data $netStart

Header "ADMIN CHECK (local administrators group)"
$admins = RunCommandWithTimeout "net.exe" @("localgroup","administrators") $TimeoutSeconds
$admins | Write-Output
Add-AuditResult -Category "Local Administrators" -Data $admins

Header "LOCAL USERS"
$localUsers = RunCommandWithTimeout "net.exe" @("user") $TimeoutSeconds
$localUsers | Write-Output
Add-AuditResult -Category "Local Users" -Data $localUsers

Header "LOCAL GROUPS"
$localGroups = RunCommandWithTimeout "net.exe" @("localgroup") $TimeoutSeconds
$localGroups | Write-Output
Add-AuditResult -Category "Local Groups" -Data $localGroups

Header "NETWORK"
$netstat = RunCommandWithTimeout "netstat.exe" @("-anoy") $TimeoutSeconds
$netstat | Write-Output
Add-AuditResult -Category "Network - Netstat" -Data $netstat

$route = RunCommandWithTimeout "route.exe"   @("print")  $TimeoutSeconds
$route | Write-Output
Add-AuditResult -Category "Network - Route" -Data $route

$arp = RunCommandWithTimeout "arp.exe"     @("-A")     $TimeoutSeconds
$arp | Write-Output
Add-AuditResult -Category "Network - ARP" -Data $arp

$ipconfig = RunCommandWithTimeout "ipconfig.exe" @("/all")  $TimeoutSeconds
$ipconfig | Write-Output
Add-AuditResult -Category "Network - Ipconfig" -Data $ipconfig

Header "USER DETAILS (Win32_UserAccount)"
try {
    $userDetails = Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True" |
        Select-Object Name, FullName, Disabled, Lockout, PasswordChangeable, PasswordRequired
    $userDetails | Format-Table -AutoSize | Out-String | Write-Output
    Add-AuditResult -Category "User Details" -Data $userDetails
} catch { Write-Output ("User enumeration failed: {0}" -f $_) }

Header "SCHEDULED TASKS (exported)"
try {
    $scht = RunCommandWithTimeout "schtasks.exe" @("/query","/fo","LIST","/v") $TimeoutSeconds
    if ($scht -is [array] -and $scht -contains "<<TIMED OUT>>") {
        Write-Warning "Scheduled task query timed out; not exported."
    } else {
        $scht | Out-File -FilePath $SchtasksFile -Encoding utf8
        Write-Output ("Scheduled tasks exported to: {0}" -f $SchtasksFile)
        Add-AuditResult -Category "Scheduled Tasks" -Data @{ ExportPath = $SchtasksFile }
    }
} catch {
    Write-Output ("Scheduled task query failed: {0}" -f $_)
}

Header "UPDATE / PATCH STATUS"
try {
    Write-Output "`n-- Installed hotfixes (QuickFixEngineering) --"
    $hotfixes = Get-CimInstance Win32_QuickFixEngineering | Sort-Object InstalledOn -Descending |
        Select-Object -First 40 HotFixID, Description, InstalledOn
    $hotfixes | Format-Table -AutoSize | Out-String | Write-Output
    Add-AuditResult -Category "Hotfixes" -Data $hotfixes

    Write-Output "`n-- Windows Update service (wuauserv) status --"
    $wuauserv = Get-Service -Name wuauserv -ErrorAction SilentlyContinue |
        Select-Object Name, Status, StartType, DisplayName
    $wuauserv | Format-List | Out-String | Write-Output
    Add-AuditResult -Category "Windows Update Service" -Data $wuauserv

    Write-Output "`n-- Pending reboot indicators --"
    $pending = @{
        CBS = (Test-Path "C:\Windows\WinSxS\pending.xml")
        Registry = $false
    }
    $regKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
        "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations"
    )
    foreach ($k in $regKeys) { if (Test-Path $k) { $pending.Registry = $true } }
    Write-Output ("CBS pending.xml exists: {0}" -f $pending.CBS)
    Write-Output ("Registry indicates reboot required: {0}" -f $pending.Registry)
    Add-AuditResult -Category "Pending Reboot" -Data $pending
} catch { Write-Output ("Update section failed: {0}" -f $_) }

Header "INSTALLATION RIGHTS (AlwaysInstallElevated)"
try {
    $hkcu = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue
    $hklm = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue
    $elevated = @{
        HKCU = if ($hkcu) { $hkcu.AlwaysInstallElevated } else { $null }
        HKLM = if ($hklm) { $hklm.AlwaysInstallElevated } else { $null }
    }
    Write-Output ("HKCU AlwaysInstallElevated: {0}" -f $elevated.HKCU)
    Write-Output ("HKLM AlwaysInstallElevated: {0}" -f $elevated.HKLM)
    Add-AuditResult -Category "AlwaysInstallElevated" -Data $elevated
} catch { Write-Output ("Registry query failed: {0}" -f $_) }

# ---------------------------
# Wrap-up
# ---------------------------
# ---------------------------
# CHECK FILES (selected sensitive/common files)
# ---------------------------
Header "CHECK FILES (selected sensitive/common files)"

$checkPaths = @(
    "C:/Users/Administrator/NTUser.dat",
    "C:/Documents and Settings/Administrator/NTUser.dat",
    "C:/apache/logs/access.log",
    "C:/apache/logs/error.log",
    "C:/apache/php/php.ini",
    "C:/boot.ini",
    "C:/inetpub/wwwroot/global.asa",
    "C:/MySQL/data/hostname.err",
    "C:/MySQL/data/mysql.err",
    "C:/MySQL/data/mysql.log",
    "C:/MySQL/my.cnf",
    "C:/MySQL/my.ini",
    "C:/php4/php.ini",
    "C:/php5/php.ini",
    "C:/php/php.ini",
    "C:/Program Files/Apache Group/Apache2/conf/httpd.conf",
    "C:/Program Files/Apache Group/Apache/conf/httpd.conf",
    "C:/Program Files/Apache Group/Apache/logs/access.log",
    "C:/Program Files/Apache Group/Apache/logs/error.log",
    "C:/Program Files/FileZilla Server/FileZilla Server.xml",
    "C:/Program Files/MySQL/data/hostname.err",
    "C:/Program Files/MySQL/data/mysql-bin.log",
    "C:/Program Files/MySQL/data/mysql.err",
    "C:/Program Files/MySQL/data/mysql.log",
    "C:/Program Files/MySQL/my.ini",
    "C:/Program Files/MySQL/my.cnf",
    "C:/Program Files/MySQL/MySQL Server 5.0/data/hostname.err",
    "C:/Program Files/MySQL/MySQL Server 5.0/data/mysql-bin.log",
    "C:/Program Files/MySQL/MySQL Server 5.0/data/mysql.err",
    "C:/Program Files/MySQL/MySQL Server 5.0/data/mysql.log",
    "C:/Program Files/MySQL/MySQL Server 5.0/my.cnf",
    "C:/Program Files/MySQL/MySQL Server 5.0/my.ini",
    "C:/Program Files (x86)/Apache Group/Apache2/conf/httpd.conf",
    "C:/Program Files (x86)/Apache Group/Apache/conf/httpd.conf",
    "C:/Program Files (x86)/Apache Group/Apache/conf/access.log",
    "C:/Program Files (x86)/Apache Group/Apache/conf/error.log",
    "C:/Program Files (x86)/FileZilla Server/FileZilla Server.xml",
    "C:/Program Files (x86)/xampp/apache/conf/httpd.conf",
    "C:/WINDOWS/php.ini",
    "C:/WINDOWS/Repair/SAM",
    "C:/Windows/repair/system",
    "C:/Windows/repair/software",
    "C:/Windows/repair/security",
    "C:/WINDOWS/System32/drivers/etc/hosts",
    "C:/Windows/win.ini",
    "C:/WINNT/php.ini",
    "C:/WINNT/win.ini",
    "C:/xampp/apache/bin/php.ini",
    "C:/xampp/apache/logs/access.log",
    "C:/xampp/apache/logs/error.log",
    "C:/Windows/Panther/Unattend/Unattended.xml",
    "C:/Windows/Panther/Unattended.xml",
    "C:/Windows/debug/NetSetup.log",
    "C:/Windows/system32/config/AppEvent.Evt",
    "C:/Windows/system32/config/SecEvent.Evt",
    "C:/Windows/system32/config/default.sav",
    "C:/Windows/system32/config/security.sav",
    "C:/Windows/system32/config/software.sav",
    "C:/Windows/system32/config/system.sav",
    "C:/Windows/system32/config/regback/default",
    "C:/Windows/system32/config/regback/sam",
    "C:/Windows/system32/config/regback/security",
    "C:/Windows/system32/config/regback/system",
    "C:/Windows/system32/config/regback/software",
    "C:/Program Files/MySQL/MySQL Server 5.1/my.ini",
    "C:/Windows/System32/inetsrv/config/schema/ASPNET_schema.xml",
    "C:/Windows/System32/inetsrv/config/applicationHost.config",
    "C:/inetpub/logs/LogFiles/W3SVC1/u_ex[YYMMDD].log"
)

foreach ($p in $checkPaths) {
    $orig = $p
    # Normalize slashes to backslashes for Windows PowerShell
    $pNorm = $p -replace '/', '\\'
    # Treat the placeholder [YYMMDD] as a wildcard
    $pNorm = $pNorm -replace '\[YYMMDD\]', '*'

    # If the path contains wildcards, allow Get-ChildItem to expand them
    try {
        $matches = Get-ChildItem -Path $pNorm -ErrorAction SilentlyContinue -Force
    } catch {
        $matches = @()
    }

    if (-not $matches -or $matches.Count -eq 0) {
        Write-Output ("NOT FOUND: {0}" -f $orig)
    } else {
        # safety limits for content output
        $MaxLines = 200
        $MaxBytes = 100 * 1024  # 100 KiB
        $sensitivePatterns = @(
            '\\Windows\\system32\\config\\SAM$',
            '\\Windows\\system32\\config\\SYSTEM$',
            '\\Windows\\system32\\config\\security$',
            '\\Windows\\system32\\config\\software$',
            '\\Windows\\system32\\config\\system$',
            '\\Windows\\Repair\\SAM$'
        )

        foreach ($m in $matches) {
            if ($m -is [System.IO.FileInfo]) {
                $full = $m.FullName
                Write-Output ("FOUND: {0} (File) Size={1} LastWrite={2}" -f $full,$m.Length,$m.LastWriteTime)
                Add-AuditResult -Category "Checked Files" -Data @{ Path = $full; Size = $m.Length; LastWrite = $m.LastWriteTime }

                # mark if file matches known sensitive hive patterns (we will still print contents)
                $isSensitive = $false
                foreach ($pat in $sensitivePatterns) { if ($full -match $pat) { $isSensitive = $true; break } }
                if ($isSensitive) {
                    Write-AuditWarning "Sensitive file pattern matched; printing contents anyway: {0}"
                }

                try {
                    if ($m.Length -le $MaxBytes) {
                        Write-Output ("`n--- BEGIN FILE: {0} ---" -f $full)
                        # small file: print entire content
                        Get-Content -Path $full -ErrorAction SilentlyContinue -Raw | ForEach-Object { Write-Output $_ }
                        Write-Output ("--- END FILE: {0} ---`n" -f $full)
                    } else {
                        Write-Output ("`n--- BEGIN FILE (truncated): {0} (first {1} lines) ---" -f $full,$MaxLines)
                        Get-Content -Path $full -ErrorAction SilentlyContinue -TotalCount $MaxLines | ForEach-Object { Write-Output $_ }
                        Write-Output ("--- OUTPUT TRUNCATED (size {0} bytes > {1} bytes) ---" -f $m.Length,$MaxBytes)
                        Write-Output ("--- END FILE: {0} ---`n" -f $full)
                    }
                } catch {
                    Write-Output ("Could not read file content: {0}" -f $_)
                }

            } elseif ($m -is [System.IO.DirectoryInfo]) {
                Write-Output ("FOUND: {0} (Directory)" -f $m.FullName)
                Add-AuditResult -Category "Checked Files" -Data @{ Path = $m.FullName; Type = "Directory" }
            } else {
                Write-Output ("FOUND (other): {0}" -f $m.FullName)
            }
        }
    }
}

# ---------------------------
# CREDENTIALS SECRETS SCAN
# ---------------------------
Header "CREDENTIALS AND SECRETS (Plaintext creds, keys, weak ACLs)"

Write-Output "`n=== 1. PLAINTEXT CREDENTIALS IN CONFIG FILES ==="
$credConfigFiles = @(
    "C:\*.env",
    "C:\*.config",
    "C:\web.config",
    "C:\appsettings.json",
    "C:\connections.xml",
    "C:\Program Files\*\*.config",
    "C:\Program Files\*\*.ini",
    "C:\ProgramData\*\*.xml"
)

foreach ($pattern in $credConfigFiles) {
    try {
        # Using -Recurse with a shallow depth for Program Files/ProgramData to avoid massive scans but find nested configs
        $searchOptions = @{ Path = $pattern; ErrorAction = 'SilentlyContinue'; Force = $true; File = $true }
        if ($pattern -match "Program Files|ProgramData") { $searchOptions.Depth = 2; $searchOptions.Recurse = $true }
        
        $files = Get-ChildItem @searchOptions 2>$null
        foreach ($f in $files) {
            $content = Get-Content -Path $f.FullName -ErrorAction SilentlyContinue -Raw
            if ($content) {
                if ($content -match '(?i)password\s*=|(?i)apikey|(?i)secret\s*=|(?i)token\s*=') {
                    Write-AuditAlert "FOUND potential credentials in: $($f.FullName)"
                    Add-AuditResult -Category "Potential Credentials" -Data @{ Path = $f.FullName; Type = "Config File" }
                }
            }
        }
    } catch { }
}

Write-Output "`n=== 2. DATABASE CONNECTION STRINGS ==="
$dbPaths = @(
    "C:\MySQL\my.ini",
    "C:\MySQL\my.cnf",
    "C:\Program Files\MySQL\*.ini",
    "C:\*.xml",
    "C:\inetpub\wwwroot\web.config",
    "C:\*.json"
)

foreach ($dbPath in $dbPaths) {
    try {
        $searchOptions = @{ Path = $dbPath; ErrorAction = 'SilentlyContinue'; Force = $true; File = $true }
        if ($dbPath -match "Program Files|inetpub") { $searchOptions.Depth = 2; $searchOptions.Recurse = $true }

        $files = Get-ChildItem @searchOptions 2>$null
        foreach ($f in $files) {
            $content = Get-Content -Path $f.FullName -ErrorAction SilentlyContinue -Raw
            if ($content -match '(?i)server\s*=|(?i)host\s*=') {
                if ($content -match '(?i)user|(?i)password|(?i)pwd') {
                    Write-AuditAlert "FOUND database connection string in: $($f.FullName)"
                    Add-AuditResult -Category "Database Connection Strings" -Data @{ Path = $f.FullName }
                }
            }
        }
    } catch { }
}

Write-Output "`n=== 3. PRIVATE KEYS AND CERTIFICATES ==="
$keyExtensions = @(".pem", ".key", ".ppk", ".pfx", ".p12", ".keystore")
$keyLocations = @(
    "C:\Users\*\.ssh\*",
    "C:\ProgramData\*\*",
    "C:\Program Files\*\certs\*",
    "C:\inetpub\*\*.pfx",
    "C:\Windows\System32\*\*.pfx"
)

foreach ($loc in $keyLocations) {
    try {
        $searchOptions = @{ Path = $loc; ErrorAction = 'SilentlyContinue'; Force = $true; File = $true }
        if ($loc -match "ProgramData|Program Files|inetpub") { $searchOptions.Depth = 2; $searchOptions.Recurse = $true }

        $files = Get-ChildItem @searchOptions 2>$null
        foreach ($f in $files) {
            if ($keyExtensions -contains $f.Extension) {
                Write-AuditAlert "FOUND PRIVATE KEY: $($f.FullName) (Size: $($f.Length) bytes)"
                Add-AuditResult -Category "Private Keys" -Data @{ Path = $f.FullName; Size = $f.Length }
            }
        }
    } catch { }
}

Write-Output "`n=== 4. GROUP POLICY PREFERENCES CPASSWORD ==="
$gppPaths = @(
    "C:\Windows\SYSVOL\*\Policies\*\Machine\Preferences\*\*.xml",
    "\\*\SYSVOL\*\Policies\*\Machine\Preferences\*\*.xml"
)

foreach ($gppPath in $gppPaths) {
    try {
        $xmlFiles = Get-ChildItem -Path $gppPath -ErrorAction SilentlyContinue -Force -File 2>$null
        foreach ($xml in $xmlFiles) {
            $content = Get-Content -Path $xml.FullName -ErrorAction SilentlyContinue -Raw
            if ($content -match 'cpassword') {
                Write-AuditAlert "FOUND cpassword in GPP XML: $($xml.FullName)"
                Add-AuditResult -Category "GPP cpassword" -Data @{ Path = $xml.FullName }
            }
        }
    } catch { }
}

Write-Output "`n=== 5. WINDOWS CREDENTIAL MANAGER SAVED CREDENTIALS ==="
try {
    $creds = cmdkey /list 2>$null | Select-String "Target"
    if ($creds) {
        Write-AuditWarning "Stored credentials found in Credential Manager:"
        $creds | ForEach-Object { 
            Write-Output ("  {0}" -f $_)
            Add-AuditResult -Category "Credential Manager" -Data @{ Target = $_.ToString().Trim() }
        }
    } else {
        Write-Output "No stored credentials in Credential Manager."
    }
} catch {
    Write-Output "Could not enumerate Credential Manager (may require elevation)."
}

Write-Output "`n=== 6. RDP FILES SAVED PASSWORDS ==="
$rdpPaths = @(
    "C:\Users\*\Documents\*.rdp",
    "C:\Users\*\AppData\Local\Microsoft\Terminal Server Client\*",
    "C:\Users\*\Desktop\*.rdp"
)

foreach ($rdpPath in $rdpPaths) {
    try {
        $searchOptions = @{ Path = $rdpPath; ErrorAction = 'SilentlyContinue'; Force = $true; File = $true }
        if ($rdpPath -match "AppData") { $searchOptions.Depth = 2; $searchOptions.Recurse = $true }

        $rdpFiles = Get-ChildItem @searchOptions 2>$null
        foreach ($rdp in $rdpFiles) {
            Write-AuditAlert "FOUND RDP file (may contain saved credentials): $($rdp.FullName)"
            Add-AuditResult -Category "RDP Files" -Data @{ Path = $rdp.FullName }
        }
    } catch { }
}

Write-Output "`n=== 7. SERVICE ACCOUNT CREDENTIALS ==="
try {
    $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.StartName -and $_.StartName -notmatch "NT AUTHORITY" -and $_.StartName -ne "LocalSystem" }
    if ($services) {
        Write-AuditWarning "Services running under non-system accounts:"
        foreach ($svc in $services) { 
            Write-Output ("  {0}: {1}" -f $svc.Name, $svc.StartName) 
            Add-AuditResult -Category "Service Accounts" -Data @{ Service = $svc.Name; Account = $svc.StartName }
        }
    }
} catch {
    Write-Output "Could not enumerate service accounts."
}

Write-Output "`n=== 8. WEAK FILE ACLs WORLD-WRITABLE PATHS ==="
$sensitiveWritablePaths = @(
    "C:\Program Files",
    "C:\Program Files (x86)",
    "C:\Windows\Tasks",
    "C:\Windows\System32\drivers\etc"
)

foreach ($path in $sensitiveWritablePaths) {
    try {
        if (Test-Path $path) {
            $acl = Get-Acl -Path $path -ErrorAction SilentlyContinue
            $hasWeakAcl = $false
            foreach ($access in $acl.Access) {
                if ($access.IdentityReference -match "Everyone|Users" -and $access.FileSystemRights -match "Write|Modify|FullControl") {
                    $hasWeakAcl = $true
                    break
                }
            }
            if ($hasWeakAcl) {
                Write-AuditAlert "WEAK ACL FOUND on $path"
                Add-AuditResult -Category "Weak ACLs" -Data @{ Path = $path; Reason = "World-writable" }
            }
        }
    } catch { }
}

Write-Output "`n=== 9. UNQUOTED SERVICE PATHS ==="
try {
    $unrequotedServices = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.PathName -notmatch '^\s*"' -and $_.PathName -match '\s' }
    if ($unrequotedServices) {
        Write-AuditAlert "Services with unquoted paths (potential DLL injection/path hijacking):"
        foreach ($svc in $unrequotedServices) { 
            Write-Output ("  {0}: {1}" -f $svc.Name, $svc.PathName) 
            Add-AuditResult -Category "Unquoted Service Paths" -Data @{ Service = $svc.Name; Path = $svc.PathName }
        }
    }
} catch {
    Write-Output "Could not enumerate unquoted service paths."
}

Write-Output "`n=== 10. VERSION CONTROL BACKUP ARTIFACTS ==="
$vcsArtifacts = @(".git", ".svn", ".zip", ".tar", ".gz")
$vcsSearchPaths = @(
    "C:\",
    "C:\inetpub\*",
    "C:\Users\*\Documents",
    "C:\Program Files\*"
)

foreach ($searchPath in $vcsSearchPaths) {
    try {
        $items = Get-ChildItem -Path $searchPath -ErrorAction SilentlyContinue -Force 2>$null
        foreach ($item in $items) {
            if ($vcsArtifacts -contains $item.Extension -or $item.Name -match "backup|old") {
                Write-AuditInfo "Version control/backup artifact: $($item.FullName)"
                Add-AuditResult -Category "VCS Artifacts" -Data @{ Path = $item.FullName }
            }
        }
    } catch { }
}

## ---------------------------
## REGISTRY KEYS & VALUES CHECK (refactored)
## ---------------------------
Header "REGISTRY KEYS & VALUES"

# Paths to inspect (can be expanded)
$regPaths = @(
    'HKLM:\SOFTWARE',
    'HKCU:\SOFTWARE',
    'HKLM:\SYSTEM\CurrentControlSet\Services',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
)

# value/data patterns that often indicate credentials or secrets
$regValuePatterns = @('password','pwd','pass','secret','apikey','token','connectionstring','cpassword','pw',':pw')

function Search-RegistryPath {
    param(
        [string]$Path,
        [string[]]$Patterns,
        [int]$ContextBefore = $script:RegContextBefore,
        [int]$ContextAfter = $script:RegContextAfter,
        [switch]$SafeMode
    )

    Write-Output ("Scanning registry path: {0}" -f $Path)
    $keys = Get-ChildItem -Path $Path -ErrorAction SilentlyContinue -Force
    foreach ($k in $keys) {
        # gather value names
        $vals = @()
        try {
            if ($k.PSProvider.Name -eq "Registry") {
                $vals = $k.GetValueNames()
            } else {
                $vals = Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name -ErrorAction SilentlyContinue | Where-Object { $_ -notmatch '^(PSPath|PSParentPath|PSChildName|PSDrive|PSProvider)$' }
            }
        } catch { }

        foreach ($vn in $vals) {
            try {
                $vraw = (Get-ItemProperty -Path $k.PSPath -Name $vn -ErrorAction SilentlyContinue).$vn
            } catch { $vraw = $null }

            if ($vraw -ne $null) {
                $vstr = Normalize-RegistryValueToString -Value $vraw

                foreach ($pat in $Patterns) {
                    $match = $null
                    try { $match = [regex]::Match($vstr, $pat, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase) } catch { $match = $null }

                    if ($match -and $match.Success) {
                        if ($SafeMode) {
                            Write-Output ("FOUND REG VALUE match: Key={0} ValueName={1} Pattern={2} (safe mode: snippet suppressed)" -f $k.PSPath, $vn, $pat)
                            Add-AuditResult -Category "Registry Match" -Data @{ Key = $k.PSPath; ValueName = $vn; Pattern = $pat; Snippet = "[SUPPRESSED]" }
                        } else {
                            $snippet = Get-Snippet -Text $vstr -Index $match.Index -LengthBefore $ContextBefore -LengthAfter $ContextAfter
                            $escaped = [regex]::Escape($match.Value)
                            $snippetMarked = $snippet -replace $escaped, "<<<$($match.Value)>>>", 1
                            Write-Output ("FOUND REG VALUE match: Key={0} ValueName={1} Pattern={2} Snippet={3}" -f $k.PSPath, $vn, $pat, $snippetMarked)
                            Add-AuditResult -Category "Registry Match" -Data @{ Key = $k.PSPath; ValueName = $vn; Pattern = $pat; Snippet = $snippetMarked }
                        }
                    } elseif ($vn -match $pat) {
                        Write-Output ("FOUND REG VALUE NAME match: Key={0} ValueName={1} Pattern={2}" -f $k.PSPath, $vn, $pat)
                        Add-AuditResult -Category "Registry Match" -Data @{ Key = $k.PSPath; ValueName = $vn; Pattern = $pat; MatchType = "ValueName" }
                    }
                }
            }
        }

        # check ACLs
        try {
            $acl = Get-Acl -Path $k.PSPath -ErrorAction SilentlyContinue
            if ($acl) {
                foreach ($ace in $acl.Access) {
                    if ($ace.IdentityReference -match 'Everyone|Users|Authenticated Users') {
                        if ($ace.RegistryRights -match 'SetValue|CreateSubKey|FullControl') {
                            Write-AuditAlert "WEAK REG ACL: {0} -> {1} : {2}" -f $k.PSPath, $ace.IdentityReference, $ace.RegistryRights
                            Add-AuditResult -Category "Weak Registry ACL" -Data @{ Key = $k.PSPath; Identity = $ace.IdentityReference; Rights = $ace.RegistryRights }
                        }
                    }
                }
            }
        } catch { }
    }
}

foreach ($r in $regPaths) {
    try { Search-RegistryPath -Path $r -Patterns $regValuePatterns -ContextBefore $RegContextBefore -ContextAfter $RegContextAfter -SafeMode:$RegSafeMode } catch { Write-Output ("Could not enumerate registry path: {0}" -f $r) }
}

# ---------------------------
# Export Structured Data
# ---------------------------
if ($ExportJson) {
    try {
        $json = $Script:AuditData | ConvertTo-Json -Depth 10
        $json | Out-File -FilePath $ExportJson -Encoding utf8 -Force
        Write-AuditInfo "Structured audit data exported to: $ExportJson"
    } catch {
        Write-Warning "Failed to export JSON: $_"
    }
}

# ---------------------------
# Wrap-up & Summary (ADHD-friendly)
# ---------------------------
Header "QUICK GLANCE SUMMARY"

if ($Script:SummaryList.Count -gt 0) {
    Write-Host "Found $($Script:AlertCount) alerts and $($Script:WarningCount) warnings:`n" -ForegroundColor Cyan
    foreach ($item in $Script:SummaryList) {
        if ($item -match "🚨") { Write-Host "  $item" -ForegroundColor Red }
        elseif ($item -match "⚠️") { Write-Host "  $item" -ForegroundColor Yellow }
        else { Write-Host "  $item" }
    }
} else {
    Write-AuditSuccess "Clean run! No obvious security alerts or warnings found."
}

try {
    if (Get-Command Stop-Transcript -ErrorAction SilentlyContinue) { Stop-Transcript | Out-Null }
} catch { Write-Warning ("Could not stop transcript cleanly: {0}" -f $_) }

Write-Output ""
Write-AuditSuccess "Audit complete."
Write-Host ("  📂 Primary log: {0}" -f $OutLog) -ForegroundColor Gray
Write-Host ("  📝 Scheduled tasks: {0}" -f $SchtasksFile) -ForegroundColor Gray
if ($ExportJson) { Write-Host ("  📊 JSON export: {0}" -f $ExportJson) -ForegroundColor Gray }
