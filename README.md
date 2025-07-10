# ProcRiskAudit
Scan of all stored procedures in a specified database for risky keywords
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

