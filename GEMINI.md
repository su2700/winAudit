# winAudit Project Overview

A collection of PowerShell scripts for comprehensive Windows system auditing and security assessment, specifically optimized for Windows Server 2022+.

## Project Structure

- `winaudit.ps1`: The main audit engine. It performs system information gathering, service/network analysis, secret discovery, and vulnerability checks.
- `parse_check.ps1`: A utility script used to validate the syntax of `winaudit.ps1` using the PowerShell parser.

## Features

- **System Reconnaissance:** Gathers OS info, environment variables, user accounts, and local group memberships.
- **Service & Network Analysis:** Enumerates services, active network connections (netstat), routing tables, and ARP cache.
- **Security & Vulnerability Checks:**
  - Identifies unquoted service paths.
  - Detects weak file and registry ACLs (world-writable paths).
  - Checks for `AlwaysInstallElevated` registry settings.
  - Scans for pending reboot indicators (CBS, registry).
- **Secret Discovery:**
  - Searches for plaintext credentials in config files (`.env`, `.config`, `.xml`, `.json`, etc.).
  - Extracts potential database connection strings.
  - Locates private keys and certificates (`.pem`, `.key`, `.pfx`).
  - Identifies Group Policy Preferences (GPP) `cpassword` occurrences.
  - Checks for saved RDP credentials and Credential Manager entries.
- **Audit Logs:** Uses PowerShell transcripts and dedicated output files for scheduled tasks.

## Usage

### Running the Audit
Execute the main script from an elevated PowerShell prompt for best results:

```powershell
.\winaudit.ps1
```

**Optional Parameters:**
- `-OutLog`: Path to the primary audit log (default: `.\audit_output.txt`).
- `-SchtasksFile`: Path to export scheduled tasks (default: `.\schtasks.txt`).
- `-TimeoutSeconds`: Timeout for slow-running commands (default: `20`).
- `-RegSafeMode`: If set, suppresses snippets of registry values in the output to avoid leaking sensitive data in the log itself.

### Validating Script Integrity
Run the parse check to ensure there are no syntax errors:

```powershell
.\parse_check.ps1
```

## Development Conventions

- **Modern Tooling:** Uses CIM (`Get-CimInstance`) and WMI instead of the deprecated `WMIC`.
- **Robustness:** Implements `RunCommandWithTimeout` using background jobs to prevent the audit from hanging on slow system calls.
- **Logging:** Employs `Start-Transcript` to capture all output for forensic review.
- **Formatting:** Uses `Header` helper functions and PowerShell's built-in formatting (`Format-Table`, `Format-List`) to maintain a clean, readable audit trail.
