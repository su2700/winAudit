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
    [int]$TimeoutSeconds = 20
)

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
# Helper functions
# ---------------------------
function Header {
    param([string]$title)
    $sep = "=" * 80
    Write-Output ""
    Write-Output $sep
    Write-Output ("== {0}" -f $title)
    Write-Output $sep
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
# REPORT
# ---------------------------

Header "WHOAMI"
RunCommand "whoami.exe"

Header "USERNAME (environment)"
Write-Output $env:USERNAME

Header "PRIVILEGES"
RunCommand "whoami.exe" @("/priv")

Header "SYSTEM INFO"
RunCommand "systeminfo.exe"

Header "OS INFO (Caption, CSDVersion, OSArchitecture, Version)"
Get-CimInstance Win32_OperatingSystem | Select-Object Caption, CSDVersion, OSArchitecture, Version | Format-List

Header "ENVIRONMENT (Get-ChildItem Env:)"
try {
    Get-ChildItem Env: | Sort-Object Name | Format-Table -AutoSize
    Write-Output "`n-- PATH entries (first 40) --"
    ($env:Path -split ';')[0..([math]::Min(39,($env:Path -split ';').Count-1))] | ForEach-Object { Write-Output $_ }
    Write-Output "`n-- PSModulePath entries --"
    ($env:PSModulePath -split ';') | ForEach-Object { Write-Output $_ }
    Write-Output "`n-- PowerShell version table --"
    $PSVersionTable | Format-List
} catch {
    Write-Output ("Environment section failed: {0}" -f $_)
}

Header "POWERSHELL HISTORY"
try {
    Write-Output "`n-- Current session history (Get-History) --"
    Get-History | Select-Object Id, CommandLine | Format-Table -AutoSize

    Write-Output "`n-- Persistent PSReadLine history file (if available) --"
    $historyPath = (Get-PSReadLineOption).HistorySavePath
    if (Test-Path $historyPath) {
        $lines = Get-Content $historyPath -ErrorAction SilentlyContinue
        Write-Output ("History file: {0}" -f $historyPath)
        Write-Output ("Total lines: {0}" -f $lines.Count)
        Write-Output "`nLast 30 commands:"
        $lines | Select-Object -Last 30 | ForEach-Object { Write-Output $_ }
    } else {
        Write-Output "No PSReadLine history file found."
    }
} catch {
    Write-Output ("History check failed: {0}" -f $_)
}

Header "SERVICES (Name, StartName, State)"
try {
    $svc = Get-CimInstance Win32_Service | Select-Object Name, StartName, State
    $svc | Format-Table -AutoSize
    Write-Output ("`n(Total services enumerated: {0})" -f ($svc | Measure-Object).Count)
} catch { Write-Output ("Service enumeration failed: {0}" -f $_) }

Header "NET START (running services)"
RunCommandWithTimeout "net.exe" @("start") $TimeoutSeconds

Header "ADMIN CHECK (local administrators group)"
RunCommandWithTimeout "net.exe" @("localgroup","administrators") $TimeoutSeconds

Header "LOCAL USERS"
RunCommandWithTimeout "net.exe" @("user") $TimeoutSeconds

Header "LOCAL GROUPS"
RunCommandWithTimeout "net.exe" @("localgroup") $TimeoutSeconds

Header "NETWORK"
RunCommandWithTimeout "netstat.exe" @("-anoy") $TimeoutSeconds
RunCommandWithTimeout "route.exe"   @("print")  $TimeoutSeconds
RunCommandWithTimeout "arp.exe"     @("-A")     $TimeoutSeconds
RunCommandWithTimeout "ipconfig.exe" @("/all")  $TimeoutSeconds

Header "USER DETAILS (Win32_UserAccount)"
try {
    Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True" |
        Select-Object Name, FullName, Disabled, Lockout, PasswordChangeable, PasswordRequired |
        Format-Table -AutoSize
} catch { Write-Output ("User enumeration failed: {0}" -f $_) }

Header "FIREWALL RULES"
RunCommandWithTimeout "netsh.exe" @("advfirewall","firewall","show","rule","name=all") $TimeoutSeconds

Header "SCHEDULED TASKS (exported)"
try {
    $scht = RunCommandWithTimeout "schtasks.exe" @("/query","/fo","LIST","/v") $TimeoutSeconds
    if ($scht -is [array] -and $scht -contains "<<TIMED OUT>>") {
        Write-Warning "Scheduled task query timed out; not exported."
    } else {
        $scht | Out-File -FilePath $SchtasksFile -Encoding utf8
        Write-Output ("Scheduled tasks exported to: {0}" -f $SchtasksFile)
    }
} catch {
    Write-Output ("Scheduled task query failed: {0}" -f $_)
}

Header "UPDATE / PATCH STATUS"
try {
    Write-Output "`n-- Installed hotfixes (QuickFixEngineering) --"
    Get-CimInstance Win32_QuickFixEngineering | Sort-Object InstalledOn -Descending |
        Select-Object -First 40 HotFixID, Description, InstalledOn | Format-Table -AutoSize

    Write-Output "`n-- Windows Update service (wuauserv) status --"
    Get-Service -Name wuauserv -ErrorAction SilentlyContinue |
        Select-Object Name, Status, StartType, DisplayName | Format-List

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
} catch { Write-Output ("Update section failed: {0}" -f $_) }

Header "INSTALLATION RIGHTS (AlwaysInstallElevated)"
try {
    $hkcu = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue
    $hklm = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue
    Write-Output ("HKCU AlwaysInstallElevated: {0}" -f $($hkcu.AlwaysInstallElevated))
    Write-Output ("HKLM AlwaysInstallElevated: {0}" -f $($hklm.AlwaysInstallElevated))
} catch { Write-Output ("Registry query failed: {0}" -f $_) }

# ---------------------------
# Wrap-up
# ---------------------------
try {
    if (Get-Command Stop-Transcript -ErrorAction SilentlyContinue) { Stop-Transcript | Out-Null }
} catch { Write-Warning ("Could not stop transcript cleanly: {0}" -f $_) }

Write-Output ""
Write-Output ("Audit complete. Primary log: {0}" -f $OutLog)
Write-Output ("Scheduled tasks file: {0}" -f $SchtasksFile)
