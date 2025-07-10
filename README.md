# ProcRiskAudit.ps1

> Scan SQL Server stored procedures for risky patterns like dynamic SQL, registry access, command execution, and known injection vectors  
> ⚠️ You may need to adjust your PowerShell execution policy to run this script — see [Script Execution Policy](#script-execution-policy)

---

## Overview

**ProcRiskAudit** is a lightweight PowerShell script designed to help teams audit stored procedures in legacy or modern SQL Server databases. It identifies risky keywords, assesses their severity, and provides line-by-line insights — perfect for DBAs, modernization architects, and security reviewers.

---

## Features

- Fast scan across all stored procedures in a target database
- Flags constructs such as `EXEC`, `xp_cmdshell`, `sp_executesql`, and others
- Line-by-line detection with line number and code snippet
- Severity tagging (`Low`, `Medium`, `High`, `Critical`)
- In-script explanation of why each keyword may be risky
- CSV output for easy auditing and report sharing

---

## Example Output

| ProcedureName | LineNumber | LineText                          | KeywordFound | Severity | RiskReason |
|---------------|------------|-----------------------------------|--------------|----------|------------|
| AuditTrail    | 42         | EXEC xp_cmdshell 'dir C:\'        | xp_cmdshell  | Critical | Executes OS-level commands; high privilege abuse risk |

---

## Usage

### Prerequisites

- Windows PowerShell  
- SQL Server access (with Integrated Security recommended)

### Running the Script

```powershell
.\ProcRiskAudit.ps1 -Server "YourSQLServer" -Database "YourDatabase"

The script will generate a CSV file in the current folder:

ProcRiskAudit_YourDatabase_YYYYMMDD_HHMM.csv
Script Execution Policy
By default, PowerShell may block script execution — especially on systems with strict security settings.

If you see this error:

UnauthorizedAccess / PSSecurityException
Run PowerShell as Administrator and enter:

```powershell
Set-ExecutionPolicy RemoteSigned

Or use this one-time bypass:

```powershell
powershell -ExecutionPolicy Bypass -File .\ProcRiskAudit.ps1

Learn more: PowerShell Execution Policies

Customization
You can modify the $KeywordProfiles array inside the script to:

Add or remove keywords
Adjust severity levels
Refine explanations or add new patterns

License
MIT License — open for use and modification.

Author
Created by Joost Stolk to support real-world system audits, legacy modernization, and secure database practices. Feedback and contributions welcome.
