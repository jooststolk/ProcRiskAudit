param (
    [string]$Server = "localhost",
    [string]$Database = "YourDatabase"
)

# Define risky keywords with severity and reason
$KeywordProfiles = @(
    @{ Keyword = "EXEC";          Severity = "Medium";   Reason = "Can execute dynamic SQL; risk of injection if input is not sanitized" },
    @{ Keyword = "EXECUTE";       Severity = "Medium";   Reason = "Allows arbitrary command execution" },
    @{ Keyword = "sp_executesql"; Severity = "High";     Reason = "Dynamic SQL support with parameters; risky if concatenated" },
    @{ Keyword = "xp_cmdshell";   Severity = "Critical"; Reason = "Executes OS-level commands; high privilege abuse risk" },
    @{ Keyword = "sp_OACreate";   Severity = "High";     Reason = "Creates COM objects; may access file system or registry" },
    @{ Keyword = "sp_OAMethod";   Severity = "High";     Reason = "Runs COM methods; used in persistence techniques" },
    @{ Keyword = "xp_regread";    Severity = "High";     Reason = "Reads registry; useful for reconnaissance" },
    @{ Keyword = "xp_regwrite";   Severity = "Critical"; Reason = "Modifies registry; can change system behavior" },
    @{ Keyword = "xp_dirtree";    Severity = "Medium";   Reason = "Maps directories; potential file system probing" },
    @{ Keyword = "xp_fileexist";  Severity = "Medium";   Reason = "Checks file presence; used in system probing" },
    @{ Keyword = "UNION SELECT";  Severity = "High";     Reason = "SQL injection vector for merging malicious queries" },
    @{ Keyword = "CHAR";          Severity = "Low";      Reason = "Used to obfuscate injected payloads" },
    @{ Keyword = "CAST";          Severity = "Low";      Reason = "Type casting that may aid obfuscation" },
    @{ Keyword = "CONVERT";       Severity = "Low";      Reason = "Similar to CAST; used in query manipulation" }
)

# Connection setup
$ConnectionString = "Server=$Server;Database=$Database;Integrated Security=True"
$Connection = New-Object System.Data.SqlClient.SqlConnection
$Connection.ConnectionString = $ConnectionString
$Connection.Open()

$Command = $Connection.CreateCommand()
$Command.CommandText = @"
SELECT OBJECT_NAME(object_id) AS ProcedureName, definition
FROM sys.sql_modules
"@
$Reader = $Command.ExecuteReader()

$Results = @()

while ($Reader.Read()) {
    $procName = $Reader["ProcedureName"]
    $definition = $Reader["definition"]
    $lines = $definition -split "`r`n|`n"

    for ($i = 0; $i -lt $lines.Length; $i++) {
        $lineText = $lines[$i].Trim()

        # Skip parameter declarations
        if ($lineText -match '^ *@\w+ +(VARCHAR|NVARCHAR|INT|DECIMAL|CHAR|BIT|DATETIME|FLOAT|TEXT)\b') {
            continue
        }

        foreach ($profile in $KeywordProfiles) {
            $keyword = $profile.Keyword
            if ($lineText -match $keyword) {
                $Results += [PSCustomObject]@{
                    ProcedureName = $procName
                    LineNumber    = $i + 1
                    LineText      = $lineText
                    KeywordFound  = $keyword
                    Severity      = $profile.Severity
                    RiskReason    = $profile.Reason
                }
            }
        }
    }
}

$Connection.Close()

# Output results
$Timestamp = Get-Date -Format "yyyyMMdd_HHmm"
$OutputPath = ".\ProcRiskAudit_$($Database)_$Timestamp.csv"
$Results | Export-Csv -Path $OutputPath -NoTypeInformation

Write-Output "✅ Scan complete. Results saved to: $OutputPath"
