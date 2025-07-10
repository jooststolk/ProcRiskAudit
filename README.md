# ProcRiskAudit
Scan of all stored procedures in a specified database for risky keywords
You may need to adjust your PowerShell execution policy to run this script — see “Script Execution Policy” below.

#  ProcRiskAudit.ps1

## Overview
**ProcRiskAudit** is a lightweight PowerShell script that scans SQL Server stored procedures for risky patterns — including dynamic SQL execution, registry access, OS-level commands, and known SQL injection vectors. It helps modernization teams, DBAs, and security-focused developers audit legacy databases with ease.

## Features
-  Fast scan of all stored procedures in a specified database
-  Flags risky keywords like `EXEC`, `xp_cmdshell`, `sp_executesql`, etc.
-  Line-by-line detection with line number and source snippet
-  Severity tagging (`Low`, `Medium`, `High`, `Critical`)
-  In-script explanations for each risky pattern
-  Outputs a CSV report with all findings

## Example Output

| ProcedureName | LineNumber | LineText                          | KeywordFound | Severity | RiskReason |
|---------------|------------|-----------------------------------|--------------|----------|------------|
| `AuditTrail`  | 42         | `EXEC xp_cmdshell 'dir C:\'`     | `xp_cmdshell`| Critical | Executes OS-level commands; high privilege abuse risk |

## Usage

### Prerequisites
- Windows PowerShell
- Access to SQL Server with Integrated Security

### Run the Script

```powershell
.\ProcRiskAudit.ps1 -Server "YourSQLServer" -Database "YourDatabase"

### Script Execution Policy
By default, PowerShell may block scripts from running — especially on systems with strict execution policies.

If you encounter an error like:

At line:1 char:1
+ .\ProcRiskAudit.ps1 ...
+ ~~~~~~~~~~~~~~~~~~~~
UnauthorizedAccess / PSSecurityException
You can fix this by temporarily allowing script execution:

Run PowerShell as Administrator, and then:

powershell
Set-ExecutionPolicy RemoteSigned
Alternatively, to bypass just for this script:

powershell
powershell -ExecutionPolicy Bypass -File .\ProcRiskAudit.ps1
⚠️ Use caution when changing execution policy. It's best to restore your original setting afterward.
