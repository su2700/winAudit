$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile('/home/noah/Documents/winAudit/winaudit.ps1',[ref]$null,[ref]$errors)
if ($errors) {
    Write-Output 'PARSE_ERRORS'
    $errors | ForEach-Object { Write-Output $_ }
    exit 2
} else {
    Write-Output 'PARSE_OK'
    exit 0
}
