# winAudit

A robust, modern PowerShell-based auditing and security assessment tool specifically designed for Windows Server 2022+ environments. 

## Overview

`winAudit` is a comprehensive script for performing system reconnaissance, identifying common misconfigurations, and discovering sensitive data stored in plaintext. It prioritizes stability and modern Windows management interfaces (CIM/WMI) over deprecated tools like `WMIC`.

## Key Features

- **System Reconnaissance:** Full OS, user account, group membership, and environment variable enumeration.
- **Network Analysis:** Real-time port monitoring (`netstat`), ARP cache, and routing table analysis.
- **Service Security:** Identification of unquoted service paths and service accounts running with non-standard privileges.
- **Secret & Credential Discovery:**
  - Scans for plaintext passwords in configuration files with recursive depth-limited searching.
  - Locates database connection strings and private keys (`.pem`, `.key`, `.pfx`).
  - Detects Group Policy Preferences (GPP) `cpassword` vulnerabilities.
- **Vulnerability Assessment:** Finds world-writable paths and insecure `AlwaysInstallElevated` settings.
- **Structured Output:** Optionally exports all gathered data to a structured JSON file for SIEM or automation integration.
- **Robust Execution:** Built-in timeout protection for slow-running system commands to prevent hanging.

## Usage

### Prerequisites
- PowerShell 5.1 or PowerShell Core (pwsh).
- Administrative privileges are highly recommended for a complete audit.

### Quick Start
Run the audit via the batch launcher to automatically bypass execution policy and export structured data:
```cmd
.\winaudit.bat
```

Alternatively, run the PowerShell script directly:
```powershell
.\winaudit.ps1
```

### Advanced Usage
Customize output locations, export structured data, and adjust command timeouts:
```powershell
.\winaudit.ps1 -OutLog "C:\Temp\audit.log" -ExportJson ".\audit_results.json" -SchtasksFile "C:\Temp\tasks.txt" -TimeoutSeconds 30
```

### Parameters
| Parameter | Description | Default |
| :--- | :--- | :--- |
| `-OutLog` | Path to the primary audit log. | `.\audit_output.txt` |
| `-ExportJson` | Path to export structured audit results (JSON format). | `None` |
| `-SchtasksFile` | Path for exported scheduled tasks. | `.\schtasks.txt` |
| `-TimeoutSeconds` | Max wait time for individual commands. | `20` |
| `-RegSafeMode` | Suppresses sensitive registry data snippets in logs. | `Off` |

## Project Structure

- `winaudit.ps1`: The primary auditing engine.
- `parse_check.ps1`: A utility for validating the syntax of the audit scripts.

## Safety & Compliance

This tool is designed for authorized security assessments and internal audits. Always ensure you have explicit permission before running this script on production systems.
