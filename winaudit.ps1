<#
.SYNOPSIS
  Stable Windows audit script for Windows Server 2022+ (PowerShell)

.DESCRIPTION
  - Uses modern CIM/WMI (Get-CimInstance, Get-Service) instead of deprecated WMIC
  - Adds timeout protection for slow commands (Start-Job + Wait-Job)
  - Exports scheduled tasks to a file
  - Logs to transcript file when possible
  - Native PowerShell registry queries
  - ENV section uses Get-ChildItem Env: to list environment variables
  - UPDATE section checks hotfixes, Windows Update service, pending reboot indicators

.USAGE
  .\winaudit.ps1
  .\winaudit.ps1 -OutLog "C:\Temp\audit.log" -SchtasksFile "C:\Temp\schtasks.txt" -TimeoutSeconds 20

.NOTES
  - Run as Administrator for full results
  - Compatible with Windows PowerShell 5.1 / PowerShell 7+
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
    param(
        [Parameter(Mandatory=$true)][string]$Cmd,
        [object[]]$Args = @()
    )
    try { & $Cmd @Args 2>&1 } catch { Write-Output ("Command {0} failed: {1}" -f $Cmd, $_) }
}

function RunCommandWithTimeout {
    param(
        [Parameter(Mandatory=$true)][string]$Cmd,
        [object[]]$Args = @(),
        [int]$Timeout = 20
    )
    try {
        $job = Start-Job -ScriptBlock { param($c,$a) & $c @a 2>&1 } -ArgumentList $Cmd,$Args
        if (Wait-Job $job -Timeout $Timeout) {
            $out = Receive-Job $job -ErrorAction SilentlyContinue
            Remove-Job $job -Force -ErrorAction SilentlyContinue
            return $out
        } else {
            Write-Warning ("Command timed out after {0}s: {1} {2}" -f $Timeout, $Cmd, ($Args -join ' '))
            Stop-Job $job -Force -ErrorAction SilentlyContinue
            Remove-Job $job -Force -ErrorAction SilentlyContinue
            return @("<<TIMED OUT>>")
        }
    } catch {
        Write-Output ("RunCommandWithTimeout error: {0}" -f $_)
    }
}

function RunBlockWithTimeout {
    param(
        [Parameter(Mandatory=$true)][scriptblock]$Script,
        [int]$Timeout = 20
    )
    try {
        $job = Start-Job -ScriptBlock $Script
        if (Wait-Job $job -Timeout $Timeout) {
            $out = Receive-Job $job -ErrorAction SilentlyContinue
            Remove-Job $job -Force -ErrorAction SilentlyContinue
            return $out
        } else {
            Write-Warning ("Script block timed out after {0}s" -f $Timeout)
            Stop-Job $job -Force -ErrorAction SilentlyContinue
            Remove-Job $job -Force -ErrorAction SilentlyContinue
            return @("<<TIMED OUT>>")
        }
    } catch {
        Write-Output ("RunBlockWithTimeout error: {0}" -f $_)
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
RunBlockWithTimeout -Timeout $TimeoutSeconds -Script {
    Get-CimInstance Win32_OperatingSystem |
        Select-Object Caption, CSDVersion, OSArchitecture, Version |
        Format-List
}

Header "ENVIRONMENT"
try {
    Write-Output "`n-- Full environment variables (Get-ChildItem Env:) --"
    # Full environment dump (may be large)
    Get-ChildItem Env: | Sort-Object Name | Format-Table -AutoSize

    Write-Output "`n-- PATH entries (first 40) --"
    $pathEntries = ($env:Path -split ';') -ne ''
    $pathEntries[0..([math]::Min(39,$pathEntries.Count-1))] | ForEach-Object { Write-Output $_ }

    Write-Output "`n-- PSModulePath entries --"
    $psmod = $env:PSModulePath -split ';'
    $psmod | ForEach-Object { Write-Output $_ }

    Write-Output "`n-- PowerShell version table --"
    $PSVersionTable | Format-List

    Write-Output "`n-- Selected common env vars --"
    $vars = @("USERNAME","USERDOMAIN","USERPROFILE","ALLUSERSPROFILE","ProgramFiles","ProgramFiles(x86)","TEMP","TMP","COMSPEC","WINDIR")
    foreach ($v in $vars) {
        $val = (Get-Item -Path env:$v -ErrorAction SilentlyContinue).Value
        Write-Output ("{0} = {1}" -f $v, $val)
    }

    Write-Output "`n-- Installed PowerShell modules (available) --"
    Get-Module -ListAvailable | Select-Object Name, Version | Sort-Object Name | Format-Table -AutoSize

    Write-Output "`n-- Installed applications (first 60 from Uninstall keys) --"
    $uninst = @()
    $keys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    foreach ($k in $keys) {
        try {
            Get-ChildItem -Path $k -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    $p = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                    if ($p.DisplayName) {
                        $uninst += [PSCustomObject]@{
                            DisplayName = $p.DisplayName
                            DisplayVersion = $p.DisplayVersion
                            Publisher = $p.Publisher
                            InstallDate = $p.InstallDate
                        }
                    }
                } catch {}
            }
        } catch {}
    }
    $uninst | Sort-Object DisplayName | Select-Object -First 60 | Format-Table -AutoSize
} catch {
    Write-Output ("Environment section failed: {0}" -f $_)
}

Header "SERVICES (Name, StartName, State)"
try {
    $svc = RunBlockWithTimeout -Timeout $TimeoutSeconds -Script {
        Get-CimInstance Win32_Service | Select-Object Name, StartName, State
    }
    if ($svc -is [array] -and $svc -contains "<<TIMED OUT>>") {
        Write-Warning "Service enumeration timed out; using Get-Service fallback."
        Get-Service | Select-Object Name, Status, ServiceType, StartType | Format-Table -AutoSize
    } else {
        $svc | Format-Table -AutoSize
        $svcCount = ($svc | Measure-Object).Count
        Write-Output ("`n(Total services enumerated: {0})" -f $svcCount)
    }
} catch {
    Write-Output ("Service enumeration failed: {0}" -f $_)
}

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
    Write-Output "`nLocal user accounts (CIM query)"
    $users = RunBlockWithTimeout -Timeout $TimeoutSeconds -Script {
        Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True" |
            Select-Object Name, FullName, Disabled, Lockout, PasswordChangeable, PasswordRequired
    }
    if ($users -is [array] -and $users -contains "<<TIMED OUT>>") {
        Write-Warning "User account enumeration timed out."
    } else {
        $users | Format-Table -AutoSize
    }
} catch {
    Write-Output ("User enumeration failed: {0}" -f $_)
}

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
    $hotfixes = RunBlockWithTimeout -Timeout $TimeoutSeconds -Script {
        Get-CimInstance Win32_QuickFixEngineering | Select-Object HotFixID, Description, InstalledOn
    }
    if ($hotfixes -is [array] -and $hotfixes -contains "<<TIMED OUT>>") {
        Write-Warning "Hotfix enumeration timed out."
    } else {
        $hotfixes | Sort-Object InstalledOn -Descending | Select-Object -First 40 | Format-Table -AutoSize
    }

    Write-Output "`n-- Windows Update service (wuauserv) status --"
    try {
        Get-Service -Name wuauserv -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType, DisplayName | Format-List
    } catch {
        Write-Output "Could not query wuauserv: $_"
    }

    Write-Output "`n-- Pending reboot indicators --"
    $pending = @{
        CBS = $false
        Registry = $false
    }
    $pending.CBS = Test-Path "C:\Windows\WinSxS\pending.xml"
    try {
        $regKeys = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
            "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations"
        )
        foreach ($k in $regKeys) {
            if (Test-Path $k) { $pending.Registry = $true }
        }
    } catch {}
    Write-Output ("CBS pending.xml exists: {0}" -f $pending.CBS)
    Write-Output ("Registry indicates reboot required: {0}" -f $pending.Registry)

    Write-Output "`n-- Windows Update client last results (if available) --"
    try {
        $wu = New-Object -ComObject "Microsoft.Update.Session" -ErrorAction SilentlyContinue
        if ($wu) {
            $searcher = $wu.CreateUpdateSearcher()
            $historyCount = $searcher.GetTotalHistoryCount()
            Write-Output ("Update history entries: {0}" -f $historyCount)
            if ($historyCount -gt 0) {
                $hist = $searcher.QueryHistory(0, [math]::Min(20, $historyCount))
                $hist | Select-Object Date, Title, ResultCode | Format-Table -AutoSize
            }
        } else {
            Write-Output "Windows Update COM object not available in this session."
        }
    } catch {
        Write-Output ("Windows Update client query failed: {0}" -f $_)
    }
} catch {
    Write-Output ("Update section failed: {0}" -f $_)
}

Header "INSTALLATION RIGHTS (AlwaysInstallElevated)"
try {
    $hkcu = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue
    $hklm = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue

    Write-Output ("HKCU AlwaysInstallElevated: {0}" -f $($hkcu.AlwaysInstallElevated))
    Write-Output ("HKLM AlwaysInstallElevated: {0}" -f $($hklm.AlwaysInstallElevated))
} catch {
    Write-Output ("Registry query failed: {0}" -f $_)
}

# ---------------------------
# Wrap-up
# ---------------------------
try {
    if (Get-Command Stop-Transcript -ErrorAction SilentlyContinue) {
        Stop-Transcript | Out-Null
    }
} catch {
    Write-Warning ("Could not stop transcript cleanly: {0}" -f $_)
}

Write-Output ""
Write-Output ("Audit complete. Primary log: {0}" -f $OutLog)
Write-Output ("Scheduled tasks file: {0}" -f $SchtasksFile)
