<#
SQL Server Azure readiness assessor - standalone ISE edition.

How to use in PowerShell ISE:
1. Paste this whole file into ISE, or open it in ISE.
2. Edit the CONFIG block below if you want to avoid prompts.
3. Press F5.

This script is read-only. It uses built-in .NET SqlClient only. It does not use
DMA, dbatools, the SqlServer module, Azure modules, or Azure APIs. It writes one
JSON report and never exports table data, full object definitions, job command
text, credentials, or connection strings.

Rule source references reviewed 2026-07-01:
- https://learn.microsoft.com/en-us/data-migration/sql-server/database/assessment-rules
- https://learn.microsoft.com/en-us/data-migration/sql-server/managed-instance/assessment-rules
- https://learn.microsoft.com/en-us/azure/azure-sql/database/features-comparison
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

###############################################################################
# CONFIG - edit these values, or leave SqlInstance blank to be prompted.
###############################################################################
$SqlInstance = ''
$DatabaseName = ''
$OutputPath = ''
$UseIntegratedSecurity = $true
$SqlUsername = ''
$SqlPassword = $null
$PromptForSqlPassword = $true
$EncryptConnection = $true
$TrustServerCertificate = $true
$ConnectionTimeoutSeconds = 15
$CommandTimeoutSeconds = 120
$IncludeObjectPatternScan = $true
$MaxObjectPatternRows = 250
###############################################################################

$script:AssessmentVersion = '2026.07.01-ise-standalone'
$script:SkipSqlAzureReadinessAutoRun = ($env:SQL_AZURE_READINESS_TEST_MODE -eq '1')

try {
    Add-Type -AssemblyName System.Data -ErrorAction Stop
}
catch {
    # Windows PowerShell can usually load these types lazily. Connection
    # creation below will fail clearly if SqlClient is unavailable.
}

function Test-IsBlank {
    param([object]$Value)
    if ($null -eq $Value) { return $true }
    return [string]::IsNullOrWhiteSpace($Value.ToString())
}

function Get-TextValue {
    param([object]$Value, [string]$Default = '')
    if ($null -eq $Value) { return $Default }
    $text = $Value.ToString().Trim()
    if ($text -eq '') { return $Default }
    return $text
}

function Get-ObjectValue {
    param(
        [object]$InputObject,
        [Parameter(Mandatory = $true)][string]$PropertyName,
        [object]$Default = $null
    )

    if ($null -eq $InputObject) { return $Default }
    $property = $InputObject.PSObject.Properties[$PropertyName]
    if ($null -eq $property -or $null -eq $property.Value) { return $Default }
    return $property.Value
}

function Get-ObjectText {
    param(
        [object]$InputObject,
        [Parameter(Mandatory = $true)][string]$PropertyName,
        [string]$Default = ''
    )

    return Get-TextValue -Value (Get-ObjectValue -InputObject $InputObject -PropertyName $PropertyName -Default $Default) -Default $Default
}

function Get-ObjectInt {
    param(
        [object]$InputObject,
        [Parameter(Mandatory = $true)][string]$PropertyName,
        [int]$Default = 0
    )

    $value = Get-ObjectValue -InputObject $InputObject -PropertyName $PropertyName -Default $Default
    if ($null -eq $value -or [string]::IsNullOrWhiteSpace($value.ToString())) { return $Default }
    $result = 0
    if ([int]::TryParse($value.ToString(), [ref]$result)) { return $result }
    return $Default
}

function Get-ObjectDecimal {
    param(
        [object]$InputObject,
        [Parameter(Mandatory = $true)][string]$PropertyName,
        [decimal]$Default = 0
    )

    $value = Get-ObjectValue -InputObject $InputObject -PropertyName $PropertyName -Default $Default
    if ($null -eq $value -or [string]::IsNullOrWhiteSpace($value.ToString())) { return $Default }
    [decimal]$result = 0
    if ([decimal]::TryParse($value.ToString(), [ref]$result)) { return $result }
    return $Default
}

function ConvertFrom-SecureStringToPlainText {
    param([Parameter(Mandatory = $true)][securestring]$SecureString)

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        if ($bstr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }
}

function Quote-SqlLiteral {
    param([object]$Value)
    if ($null -eq $Value) { return 'NULL' }
    return "N'$($Value.ToString().Replace("'", "''"))'"
}

function Add-ListItem {
    param(
        [Parameter(Mandatory = $true)]$List,
        [object]$Value
    )

    if ($null -eq $Value) { return }
    $text = $Value.ToString().Trim()
    if ($text -eq '') { return }
    if (-not $List.Contains($text)) { [void]$List.Add($text) }
}

function Add-RuleHit {
    param(
        [Parameter(Mandatory = $true)]$List,
        [Parameter(Mandatory = $true)][string]$Target,
        [Parameter(Mandatory = $true)][string]$Severity,
        [Parameter(Mandatory = $true)][string]$RuleId,
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $true)][string]$Remediation,
        [string]$Evidence = ''
    )

    $exists = $false
    foreach ($item in @($List)) {
        if ($item.target -eq $Target -and $item.ruleId -eq $RuleId -and $item.message -eq $Message) {
            $exists = $true
            break
        }
    }

    if (-not $exists) {
        [void]$List.Add([pscustomobject][ordered]@{
            target      = $Target
            severity    = $Severity
            ruleId      = $RuleId
            message     = $Message
            remediation = $Remediation
            evidence    = $Evidence
        })
    }
}

function Join-UniqueText {
    param([object[]]$Values, [string]$Default = 'None')
    $items = @($Values | Where-Object { -not (Test-IsBlank $_) } | ForEach-Object { $_.ToString().Trim() } | Select-Object -Unique)
    if (@($items).Count -eq 0) { return $Default }
    return ($items -join '; ')
}

function New-ReadinessConnectionString {
    param(
        [Parameter(Mandatory = $true)][string]$Instance,
        [Parameter(Mandatory = $true)][bool]$IntegratedSecurity,
        [string]$Username = '',
        [securestring]$Password,
        [bool]$Encrypt = $true,
        [bool]$TrustCertificate = $true,
        [int]$ConnectTimeout = 15
    )

    $builder = New-Object System.Data.SqlClient.SqlConnectionStringBuilder
    $builder['Data Source'] = $Instance
    $builder['Initial Catalog'] = 'master'
    $builder['Application Name'] = 'SQL Azure Readiness Standalone ISE'
    $builder['Connect Timeout'] = $ConnectTimeout
    $builder['Encrypt'] = $Encrypt
    $builder['TrustServerCertificate'] = $TrustCertificate

    if ($IntegratedSecurity) {
        $builder['Integrated Security'] = $true
    }
    else {
        if (Test-IsBlank $Username) { throw 'SqlUsername is required when UseIntegratedSecurity is false.' }
        if ($null -eq $Password) { throw 'SqlPassword is required when UseIntegratedSecurity is false.' }
        $builder['User ID'] = $Username
        $builder['Password'] = ConvertFrom-SecureStringToPlainText -SecureString $Password
    }

    return $builder.ConnectionString
}

function Invoke-ReadinessSqlQuery {
    param(
        [Parameter(Mandatory = $true)][string]$ConnectionString,
        [Parameter(Mandatory = $true)][string]$Query,
        [string]$Database = 'master',
        [int]$TimeoutSeconds = 120
    )

    $builder = New-Object System.Data.SqlClient.SqlConnectionStringBuilder $ConnectionString
    $builder['Initial Catalog'] = $Database

    $connection = New-Object System.Data.SqlClient.SqlConnection $builder.ConnectionString
    $command = $connection.CreateCommand()
    $command.CommandText = $Query
    $command.CommandTimeout = $TimeoutSeconds
    $table = New-Object System.Data.DataTable
    $adapter = New-Object System.Data.SqlClient.SqlDataAdapter $command

    try {
        $connection.Open()
        [void]$adapter.Fill($table)
    }
    finally {
        $adapter.Dispose()
        $command.Dispose()
        $connection.Dispose()
    }

    $rows = @()
    foreach ($dataRow in $table.Rows) {
        $values = [ordered]@{}
        foreach ($column in $table.Columns) {
            if ($dataRow.IsNull($column)) {
                $values[$column.ColumnName] = $null
            }
            else {
                $values[$column.ColumnName] = $dataRow[$column]
            }
        }
        $rows += [pscustomobject]$values
    }

    return @($rows)
}

function Invoke-OptionalReadinessSqlQuery {
    param(
        [Parameter(Mandatory = $true)][string]$ConnectionString,
        [Parameter(Mandatory = $true)][string]$Query,
        [string]$Database = 'master',
        [string]$CollectorName = 'collector',
        [int]$TimeoutSeconds = 120
    )

    try {
        $rows = Invoke-ReadinessSqlQuery -ConnectionString $ConnectionString -Query $Query -Database $Database -TimeoutSeconds $TimeoutSeconds
        return [pscustomobject]@{ Rows = @($rows); Error = '' }
    }
    catch {
        return [pscustomobject]@{ Rows = @(); Error = "$CollectorName failed: $($_.Exception.Message)" }
    }
}

function Add-CollectionError {
    param(
        [Parameter(Mandatory = $true)]$Errors,
        [Parameter(Mandatory = $true)][string]$CollectorName,
        [string]$Database = '',
        [string]$Message = ''
    )

    if (Test-IsBlank $Message) { return }
    [void]$Errors.Add([pscustomobject][ordered]@{
        collectorName = $CollectorName
        databaseName  = $Database
        message       = $Message
    })
}

function Get-DefaultOutputPath {
    param([string]$Instance)

    $safeInstance = ($Instance -replace '[^A-Za-z0-9_.-]', '_')
    if (Test-IsBlank $safeInstance) { $safeInstance = 'sqlserver' }
    $fileName = "sql-azure-readiness-$safeInstance-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"

    $base = ''
    $scriptRootVariable = Get-Variable -Name PSScriptRoot -Scope Script -ErrorAction SilentlyContinue
    $iseVariable = Get-Variable -Name psISE -Scope Global -ErrorAction SilentlyContinue

    if ($null -ne $scriptRootVariable -and -not (Test-IsBlank $scriptRootVariable.Value)) {
        $base = $scriptRootVariable.Value
    }
    elseif ($null -ne $iseVariable -and $null -ne $iseVariable.Value -and $iseVariable.Value.CurrentFile -and -not (Test-IsBlank $iseVariable.Value.CurrentFile.FullPath)) {
        $base = Split-Path -Parent $iseVariable.Value.CurrentFile.FullPath
    }
    else {
        $base = (Get-Location).Path
    }

    return Join-Path $base $fileName
}

function Get-ServerReadinessEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$ConnectionString,
        [Parameter(Mandatory = $true)][string]$Instance,
        [Parameter(Mandatory = $true)]$Errors,
        [int]$TimeoutSeconds = 120
    )

    $serverProperties = Invoke-ReadinessSqlQuery -ConnectionString $ConnectionString -Database 'master' -TimeoutSeconds $TimeoutSeconds -Query @"
SELECT
    CONVERT(nvarchar(128), SERVERPROPERTY('MachineName')) AS machine_name,
    CONVERT(nvarchar(128), SERVERPROPERTY('ServerName')) AS server_name,
    CONVERT(nvarchar(128), SERVERPROPERTY('InstanceName')) AS instance_name,
    CONVERT(nvarchar(128), SERVERPROPERTY('Edition')) AS edition,
    CONVERT(nvarchar(128), SERVERPROPERTY('ProductVersion')) AS product_version,
    CONVERT(nvarchar(128), SERVERPROPERTY('ProductMajorVersion')) AS product_major_version,
    CONVERT(nvarchar(128), SERVERPROPERTY('ProductLevel')) AS product_level,
    CONVERT(nvarchar(128), SERVERPROPERTY('ProductUpdateLevel')) AS product_update_level,
    CONVERT(int, SERVERPROPERTY('EngineEdition')) AS engine_edition,
    CONVERT(nvarchar(128), SERVERPROPERTY('Collation')) AS server_collation,
    CONVERT(int, SERVERPROPERTY('IsClustered')) AS is_clustered,
    CONVERT(int, SERVERPROPERTY('IsHadrEnabled')) AS is_hadr_enabled;
"@

    $base = @($serverProperties)[0]

    $permissionResult = Invoke-OptionalReadinessSqlQuery -ConnectionString $ConnectionString -Database 'master' -CollectorName 'permissions' -TimeoutSeconds $TimeoutSeconds -Query @"
SELECT
    ISNULL(HAS_PERMS_BY_NAME(NULL, 'SERVER', 'VIEW SERVER STATE'), 0) AS has_view_server_state,
    ISNULL(HAS_PERMS_BY_NAME(NULL, 'SERVER', 'VIEW ANY DEFINITION'), 0) AS has_view_any_definition,
    ISNULL(IS_SRVROLEMEMBER('sysadmin'), 0) AS is_sysadmin;
"@
    Add-CollectionError -Errors $Errors -CollectorName 'permissions' -Message $permissionResult.Error
    $permissions = if (@($permissionResult.Rows).Count -gt 0) { @($permissionResult.Rows)[0] } else { $null }

    $osResult = Invoke-OptionalReadinessSqlQuery -ConnectionString $ConnectionString -Database 'master' -CollectorName 'dm_os_sys_info' -TimeoutSeconds $TimeoutSeconds -Query @"
SELECT
    cpu_count,
    scheduler_count,
    CONVERT(decimal(18,2), physical_memory_kb / 1024.0) AS physical_memory_mb,
    sqlserver_start_time
FROM sys.dm_os_sys_info;
"@
    Add-CollectionError -Errors $Errors -CollectorName 'dm_os_sys_info' -Message $osResult.Error
    $os = if (@($osResult.Rows).Count -gt 0) { @($osResult.Rows)[0] } else { $null }

    $configResult = Invoke-OptionalReadinessSqlQuery -ConnectionString $ConnectionString -Database 'master' -CollectorName 'server_configurations' -TimeoutSeconds $TimeoutSeconds -Query @"
SELECT name, value_in_use
FROM sys.configurations
WHERE name IN (
    N'max server memory (MB)',
    N'xp_cmdshell',
    N'clr enabled',
    N'external scripts enabled',
    N'polybase enabled'
);
"@
    Add-CollectionError -Errors $Errors -CollectorName 'server_configurations' -Message $configResult.Error
    $configs = @{}
    foreach ($row in @($configResult.Rows)) {
        $configs[(Get-ObjectText $row 'name').ToLowerInvariant()] = Get-ObjectInt $row 'value_in_use'
    }

    $tempdbResult = Invoke-OptionalReadinessSqlQuery -ConnectionString $ConnectionString -Database 'master' -CollectorName 'tempdb_files' -TimeoutSeconds $TimeoutSeconds -Query @"
SELECT
    CONVERT(decimal(18,2), SUM(size) * 8.0 / 1024.0) AS tempdb_total_size_mb,
    SUM(CASE WHEN type_desc = N'ROWS' THEN 1 ELSE 0 END) AS tempdb_data_file_count,
    SUM(CASE WHEN type_desc = N'LOG' THEN 1 ELSE 0 END) AS tempdb_log_file_count
FROM sys.master_files
WHERE database_id = 2;
"@
    Add-CollectionError -Errors $Errors -CollectorName 'tempdb_files' -Message $tempdbResult.Error
    $tempdb = if (@($tempdbResult.Rows).Count -gt 0) { @($tempdbResult.Rows)[0] } else { $null }

    $linkedServerResult = Invoke-OptionalReadinessSqlQuery -ConnectionString $ConnectionString -Database 'master' -CollectorName 'linked_servers' -TimeoutSeconds $TimeoutSeconds -Query @"
SELECT
    COUNT(*) AS linked_server_count,
    SUM(CASE
        WHEN provider IS NULL THEN 0
        WHEN UPPER(provider) IN (N'SQLNCLI', N'SQLNCLI10', N'SQLNCLI11', N'SQLOLEDB', N'MSOLEDBSQL', N'SQL SERVER') THEN 0
        ELSE 1
    END) AS non_sql_linked_server_count
FROM sys.servers
WHERE is_linked = 1;
"@
    Add-CollectionError -Errors $Errors -CollectorName 'linked_servers' -Message $linkedServerResult.Error
    $linkedServers = if (@($linkedServerResult.Rows).Count -gt 0) { @($linkedServerResult.Rows)[0] } else { $null }

    $agentResult = Invoke-OptionalReadinessSqlQuery -ConnectionString $ConnectionString -Database 'msdb' -CollectorName 'sql_agent_jobs' -TimeoutSeconds $TimeoutSeconds -Query @"
SELECT
    (SELECT COUNT(*) FROM dbo.sysjobs) AS sql_agent_job_count,
    COUNT(*) AS sql_agent_jobstep_count,
    SUM(CASE WHEN subsystem IN (N'CmdExec', N'PowerShell') THEN 1 ELSE 0 END) AS sql_agent_command_step_count,
    SUM(CASE WHEN subsystem <> N'TSQL' THEN 1 ELSE 0 END) AS sql_agent_non_tsql_step_count
FROM dbo.sysjobsteps;
"@
    Add-CollectionError -Errors $Errors -CollectorName 'sql_agent_jobs' -Message $agentResult.Error
    $agent = if (@($agentResult.Rows).Count -gt 0) { @($agentResult.Rows)[0] } else { $null }

    $mailResult = Invoke-OptionalReadinessSqlQuery -ConnectionString $ConnectionString -Database 'msdb' -CollectorName 'database_mail_profiles' -TimeoutSeconds $TimeoutSeconds -Query "SELECT COUNT(*) AS item_count FROM dbo.sysmail_profile;"
    $credentialResult = Invoke-OptionalReadinessSqlQuery -ConnectionString $ConnectionString -Database 'master' -CollectorName 'server_credentials' -TimeoutSeconds $TimeoutSeconds -Query "SELECT COUNT(*) AS item_count FROM sys.credentials;"
    $endpointResult = Invoke-OptionalReadinessSqlQuery -ConnectionString $ConnectionString -Database 'master' -CollectorName 'server_endpoints' -TimeoutSeconds $TimeoutSeconds -Query "SELECT COUNT(*) AS item_count FROM sys.endpoints WHERE type_desc <> N'SERVICE_BROKER';"
    $triggerResult = Invoke-OptionalReadinessSqlQuery -ConnectionString $ConnectionString -Database 'master' -CollectorName 'server_triggers' -TimeoutSeconds $TimeoutSeconds -Query "SELECT COUNT(*) AS item_count FROM sys.server_triggers WHERE is_disabled = 0;"
    $agResult = Invoke-OptionalReadinessSqlQuery -ConnectionString $ConnectionString -Database 'master' -CollectorName 'availability_groups' -TimeoutSeconds $TimeoutSeconds -Query "SELECT COUNT(*) AS item_count FROM sys.availability_groups;"
    $rgResult = Invoke-OptionalReadinessSqlQuery -ConnectionString $ConnectionString -Database 'master' -CollectorName 'resource_governor' -TimeoutSeconds $TimeoutSeconds -Query "SELECT COUNT(*) AS item_count FROM sys.resource_governor_resource_pools WHERE pool_id > 2;"
    $windowsLoginResult = Invoke-OptionalReadinessSqlQuery -ConnectionString $ConnectionString -Database 'master' -CollectorName 'windows_server_principals' -TimeoutSeconds $TimeoutSeconds -Query "SELECT COUNT(*) AS item_count FROM sys.server_principals WHERE type IN (N'U', N'G') AND name NOT LIKE N'NT SERVICE\%' AND name NOT LIKE N'NT AUTHORITY\%';"
    $traceFlagResult = Invoke-OptionalReadinessSqlQuery -ConnectionString $ConnectionString -Database 'master' -CollectorName 'trace_flags' -TimeoutSeconds $TimeoutSeconds -Query "DBCC TRACESTATUS(-1) WITH NO_INFOMSGS;"

    foreach ($pair in @(
        @{ Name = 'database_mail_profiles'; Result = $mailResult },
        @{ Name = 'server_credentials'; Result = $credentialResult },
        @{ Name = 'server_endpoints'; Result = $endpointResult },
        @{ Name = 'server_triggers'; Result = $triggerResult },
        @{ Name = 'availability_groups'; Result = $agResult },
        @{ Name = 'resource_governor'; Result = $rgResult },
        @{ Name = 'windows_server_principals'; Result = $windowsLoginResult },
        @{ Name = 'trace_flags'; Result = $traceFlagResult }
    )) {
        Add-CollectionError -Errors $Errors -CollectorName $pair.Name -Message $pair.Result.Error
    }

    return [pscustomobject][ordered]@{
        sqlInstance                  = $Instance
        machineName                  = Get-ObjectText $base 'machine_name'
        serverName                   = Get-ObjectText $base 'server_name'
        instanceName                 = Get-ObjectText $base 'instance_name'
        edition                      = Get-ObjectText $base 'edition'
        productVersion               = Get-ObjectText $base 'product_version'
        productMajorVersion          = Get-ObjectInt $base 'product_major_version'
        productLevel                 = Get-ObjectText $base 'product_level'
        productUpdateLevel           = Get-ObjectText $base 'product_update_level'
        engineEdition                = Get-ObjectInt $base 'engine_edition'
        serverCollation              = Get-ObjectText $base 'server_collation'
        isClustered                  = Get-ObjectInt $base 'is_clustered'
        isHadrEnabled                = Get-ObjectInt $base 'is_hadr_enabled'
        cpuCount                     = Get-ObjectInt $os 'cpu_count'
        schedulerCount               = Get-ObjectInt $os 'scheduler_count'
        physicalMemoryMb             = Get-ObjectDecimal $os 'physical_memory_mb'
        sqlServerStartTime           = Get-ObjectText $os 'sqlserver_start_time'
        maxServerMemoryMb            = if ($configs.ContainsKey('max server memory (mb)')) { $configs['max server memory (mb)'] } else { 0 }
        tempdbTotalSizeMb            = Get-ObjectDecimal $tempdb 'tempdb_total_size_mb'
        tempdbDataFileCount          = Get-ObjectInt $tempdb 'tempdb_data_file_count'
        tempdbLogFileCount           = Get-ObjectInt $tempdb 'tempdb_log_file_count'
        linkedServerCount            = Get-ObjectInt $linkedServers 'linked_server_count'
        nonSqlLinkedServerCount      = Get-ObjectInt $linkedServers 'non_sql_linked_server_count'
        sqlAgentJobCount             = Get-ObjectInt $agent 'sql_agent_job_count'
        sqlAgentJobStepCount         = Get-ObjectInt $agent 'sql_agent_jobstep_count'
        sqlAgentCommandStepCount     = Get-ObjectInt $agent 'sql_agent_command_step_count'
        sqlAgentNonTsqlStepCount     = Get-ObjectInt $agent 'sql_agent_non_tsql_step_count'
        databaseMailProfileCount     = Get-ObjectInt (@($mailResult.Rows)[0]) 'item_count'
        credentialCount              = Get-ObjectInt (@($credentialResult.Rows)[0]) 'item_count'
        endpointCount                = Get-ObjectInt (@($endpointResult.Rows)[0]) 'item_count'
        serverTriggerCount           = Get-ObjectInt (@($triggerResult.Rows)[0]) 'item_count'
        availabilityGroupCount       = Get-ObjectInt (@($agResult.Rows)[0]) 'item_count'
        resourceGovernorPoolCount    = Get-ObjectInt (@($rgResult.Rows)[0]) 'item_count'
        windowsServerPrincipalCount  = Get-ObjectInt (@($windowsLoginResult.Rows)[0]) 'item_count'
        traceFlagCount               = @($traceFlagResult.Rows).Count
        xpCmdShellEnabled            = if ($configs.ContainsKey('xp_cmdshell')) { $configs['xp_cmdshell'] } else { 0 }
        clrEnabled                   = if ($configs.ContainsKey('clr enabled')) { $configs['clr enabled'] } else { 0 }
        externalScriptsEnabled       = if ($configs.ContainsKey('external scripts enabled')) { $configs['external scripts enabled'] } else { 0 }
        polybaseEnabled              = if ($configs.ContainsKey('polybase enabled')) { $configs['polybase enabled'] } else { 0 }
        hasViewServerState           = Get-ObjectInt $permissions 'has_view_server_state'
        hasViewAnyDefinition         = Get-ObjectInt $permissions 'has_view_any_definition'
        isSysadmin                   = Get-ObjectInt $permissions 'is_sysadmin'
    }
}

function Get-DatabaseListEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$ConnectionString,
        [string]$OnlyDatabase = '',
        [int]$TimeoutSeconds = 120
    )

    $databaseFilter = if (Test-IsBlank $OnlyDatabase) { 'NULL' } else { Quote-SqlLiteral $OnlyDatabase }
    $query = @"
DECLARE @DatabaseName sysname = $databaseFilter;

SELECT
    CONVERT(nvarchar(128), d.name) AS database_name,
    CONVERT(nvarchar(60), d.state_desc) AS state_desc,
    d.compatibility_level,
    CONVERT(nvarchar(60), d.recovery_model_desc) AS recovery_model_desc,
    CONVERT(nvarchar(128), d.collation_name) AS collation_name,
    CONVERT(decimal(18,2), SUM(mf.size) * 8.0 / 1024.0 / 1024.0) AS total_size_gb,
    CONVERT(decimal(18,2), SUM(CASE WHEN mf.type_desc = N'ROWS' THEN mf.size ELSE 0 END) * 8.0 / 1024.0 / 1024.0) AS data_size_gb,
    CONVERT(decimal(18,2), SUM(CASE WHEN mf.type_desc = N'LOG' THEN mf.size ELSE 0 END) * 8.0 / 1024.0 / 1024.0) AS log_size_gb,
    SUM(CASE WHEN mf.type_desc = N'ROWS' THEN 1 ELSE 0 END) AS data_file_count,
    SUM(CASE WHEN mf.type_desc = N'LOG' THEN 1 ELSE 0 END) AS log_file_count,
    CONVERT(int, d.is_broker_enabled) AS service_broker_enabled,
    CONVERT(int, d.is_cdc_enabled) AS cdc_enabled,
    CONVERT(int, d.is_encrypted) AS tde_enabled
FROM sys.databases d
LEFT JOIN sys.master_files mf ON d.database_id = mf.database_id
WHERE d.database_id > 4
  AND d.source_database_id IS NULL
  AND (@DatabaseName IS NULL OR d.name = @DatabaseName)
GROUP BY
    d.name,
    d.state_desc,
    d.compatibility_level,
    d.recovery_model_desc,
    d.collation_name,
    d.is_broker_enabled,
    d.is_cdc_enabled,
    d.is_encrypted
ORDER BY d.name;
"@

    return Invoke-ReadinessSqlQuery -ConnectionString $ConnectionString -Database 'master' -TimeoutSeconds $TimeoutSeconds -Query $query
}

function Get-DatabaseFeatureEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$ConnectionString,
        [Parameter(Mandatory = $true)][string]$Database,
        [Parameter(Mandatory = $true)]$Errors,
        [bool]$ScanObjects = $true,
        [int]$MaxObjectRows = 250,
        [int]$TimeoutSeconds = 120
    )

    $featureQuery = @"
DECLARE @filegroup_count int = 0,
        @filestream_filegroup_count int = 0,
        @memory_optimized_table_count int = 0,
        @filetable_count int = 0,
        @external_table_count int = 0,
        @fulltext_catalog_count int = 0,
        @partition_scheme_count int = 0,
        @user_assembly_count int = 0,
        @synonym_count int = 0,
        @cross_database_reference_count int = 0,
        @change_tracking_enabled int = 0,
        @query_store_state nvarchar(60) = N'Unavailable',
        @windows_database_principal_count int = 0,
        @database_scoped_credential_count int = 0;

SELECT @filegroup_count = COUNT(*) FROM sys.filegroups;
SELECT @filestream_filegroup_count = COUNT(*) FROM sys.filegroups WHERE type = N'FD';

IF COL_LENGTH(N'sys.tables', N'is_memory_optimized') IS NOT NULL
    EXEC sys.sp_executesql N'SELECT @value = COUNT(*) FROM sys.tables WHERE is_memory_optimized = 1', N'@value int OUTPUT', @value = @memory_optimized_table_count OUTPUT;

IF COL_LENGTH(N'sys.tables', N'is_filetable') IS NOT NULL
    EXEC sys.sp_executesql N'SELECT @value = COUNT(*) FROM sys.tables WHERE is_filetable = 1', N'@value int OUTPUT', @value = @filetable_count OUTPUT;

IF OBJECT_ID(N'sys.external_tables') IS NOT NULL
    EXEC sys.sp_executesql N'SELECT @value = COUNT(*) FROM sys.external_tables', N'@value int OUTPUT', @value = @external_table_count OUTPUT;

IF OBJECT_ID(N'sys.fulltext_catalogs') IS NOT NULL
    EXEC sys.sp_executesql N'SELECT @value = COUNT(*) FROM sys.fulltext_catalogs', N'@value int OUTPUT', @value = @fulltext_catalog_count OUTPUT;

SELECT @partition_scheme_count = COUNT(*) FROM sys.partition_schemes;
SELECT @user_assembly_count = COUNT(*) FROM sys.assemblies WHERE is_user_defined = 1;
SELECT @synonym_count = COUNT(*) FROM sys.synonyms;
SELECT @cross_database_reference_count = COUNT(DISTINCT referenced_database_name)
FROM sys.sql_expression_dependencies
WHERE referenced_database_name IS NOT NULL
  AND referenced_database_name <> DB_NAME();

IF EXISTS (SELECT 1 FROM sys.change_tracking_databases WHERE database_id = DB_ID())
    SET @change_tracking_enabled = 1;

IF OBJECT_ID(N'sys.database_query_store_options') IS NOT NULL
    EXEC sys.sp_executesql N'SELECT @value = CONVERT(nvarchar(60), actual_state_desc) FROM sys.database_query_store_options', N'@value nvarchar(60) OUTPUT', @value = @query_store_state OUTPUT;

SELECT @windows_database_principal_count = COUNT(*)
FROM sys.database_principals
WHERE type IN (N'U', N'G')
  AND name NOT LIKE N'NT AUTHORITY\%'
  AND name NOT LIKE N'NT SERVICE\%';

IF OBJECT_ID(N'sys.database_scoped_credentials') IS NOT NULL
    EXEC sys.sp_executesql N'SELECT @value = COUNT(*) FROM sys.database_scoped_credentials', N'@value int OUTPUT', @value = @database_scoped_credential_count OUTPUT;

SELECT
    @filegroup_count AS filegroup_count,
    @filestream_filegroup_count AS filestream_filegroup_count,
    @memory_optimized_table_count AS memory_optimized_table_count,
    @filetable_count AS filetable_count,
    @external_table_count AS external_table_count,
    @fulltext_catalog_count AS fulltext_catalog_count,
    @partition_scheme_count AS partition_scheme_count,
    @user_assembly_count AS user_assembly_count,
    @synonym_count AS synonym_count,
    @cross_database_reference_count AS cross_database_reference_count,
    @change_tracking_enabled AS change_tracking_enabled,
    @query_store_state AS query_store_state,
    @windows_database_principal_count AS windows_database_principal_count,
    @database_scoped_credential_count AS database_scoped_credential_count;
"@

    $featureResult = Invoke-OptionalReadinessSqlQuery -ConnectionString $ConnectionString -Database $Database -CollectorName "database_features:$Database" -TimeoutSeconds $TimeoutSeconds -Query $featureQuery
    Add-CollectionError -Errors $Errors -CollectorName 'database_features' -Database $Database -Message $featureResult.Error
    $feature = if (@($featureResult.Rows).Count -gt 0) { @($featureResult.Rows)[0] } else { $null }

    $databaseLiteral = Quote-SqlLiteral $Database
    $agentQuery = @"
DECLARE @DatabaseName sysname = $databaseLiteral;

SELECT
    COUNT(*) AS sql_agent_jobstep_count,
    SUM(CASE WHEN subsystem IN (N'CmdExec', N'PowerShell') THEN 1 ELSE 0 END) AS sql_agent_command_step_count,
    SUM(CASE WHEN subsystem <> N'TSQL' THEN 1 ELSE 0 END) AS sql_agent_non_tsql_step_count
FROM dbo.sysjobsteps
WHERE database_name = @DatabaseName
   OR command LIKE N'%' + @DatabaseName + N'%';
"@

    $agentResult = Invoke-OptionalReadinessSqlQuery -ConnectionString $ConnectionString -Database 'msdb' -CollectorName "sql_agent_jobsteps:$Database" -TimeoutSeconds $TimeoutSeconds -Query $agentQuery
    Add-CollectionError -Errors $Errors -CollectorName 'sql_agent_jobsteps' -Database $Database -Message $agentResult.Error
    $agent = if (@($agentResult.Rows).Count -gt 0) { @($agentResult.Rows)[0] } else { $null }

    $objectHits = @()
    if ($ScanObjects) {
        $topN = [Math]::Max(1, [Math]::Min(1000, $MaxObjectRows))
        $objectQuery = @"
SELECT TOP ($topN)
    feature_name,
    schema_name,
    object_name,
    object_type
FROM (
    SELECT N'xp_cmdshell' AS feature_name, SCHEMA_NAME(o.schema_id) AS schema_name, o.name AS object_name, o.type_desc AS object_type
    FROM sys.sql_modules m INNER JOIN sys.objects o ON m.object_id = o.object_id
    WHERE UPPER(m.definition) LIKE N'%XP_CMDSHELL%'
    UNION ALL
    SELECT N'openrowset', SCHEMA_NAME(o.schema_id), o.name, o.type_desc
    FROM sys.sql_modules m INNER JOIN sys.objects o ON m.object_id = o.object_id
    WHERE UPPER(m.definition) LIKE N'%OPENROWSET%'
    UNION ALL
    SELECT N'opendatasource', SCHEMA_NAME(o.schema_id), o.name, o.type_desc
    FROM sys.sql_modules m INNER JOIN sys.objects o ON m.object_id = o.object_id
    WHERE UPPER(m.definition) LIKE N'%OPENDATASOURCE%'
    UNION ALL
    SELECT N'openquery', SCHEMA_NAME(o.schema_id), o.name, o.type_desc
    FROM sys.sql_modules m INNER JOIN sys.objects o ON m.object_id = o.object_id
    WHERE UPPER(m.definition) LIKE N'%OPENQUERY%'
    UNION ALL
    SELECT N'bulk_operation', SCHEMA_NAME(o.schema_id), o.name, o.type_desc
    FROM sys.sql_modules m INNER JOIN sys.objects o ON m.object_id = o.object_id
    WHERE UPPER(m.definition) LIKE N'%BULK INSERT%' OR UPPER(m.definition) LIKE N'%OPENROWSET%BULK%'
    UNION ALL
    SELECT N'distributed_transaction', SCHEMA_NAME(o.schema_id), o.name, o.type_desc
    FROM sys.sql_modules m INNER JOIN sys.objects o ON m.object_id = o.object_id
    WHERE UPPER(m.definition) LIKE N'%BEGIN DISTRIBUTED TRANSACTION%' OR UPPER(m.definition) LIKE N'%MSDTC%'
    UNION ALL
    SELECT N'legacy_outer_join', SCHEMA_NAME(o.schema_id), o.name, o.type_desc
    FROM sys.sql_modules m INNER JOIN sys.objects o ON m.object_id = o.object_id
    WHERE m.definition LIKE N'%*=%' OR m.definition LIKE N'%=*%'
    UNION ALL
    SELECT N'legacy_raiserror', SCHEMA_NAME(o.schema_id), o.name, o.type_desc
    FROM sys.sql_modules m INNER JOIN sys.objects o ON m.object_id = o.object_id
    WHERE UPPER(m.definition) LIKE N'%RAISERROR %' AND UPPER(m.definition) NOT LIKE N'%RAISERROR(%'
    UNION ALL
    SELECT N'removed_system_procedure', SCHEMA_NAME(o.schema_id), o.name, o.type_desc
    FROM sys.sql_modules m INNER JOIN sys.objects o ON m.object_id = o.object_id
    WHERE UPPER(m.definition) LIKE N'%SP_DBOPTION%'
       OR UPPER(m.definition) LIKE N'%SP_ADDSERVER%'
       OR UPPER(m.definition) LIKE N'%SP_DROPALIAS%'
       OR UPPER(m.definition) LIKE N'%SP_ACTIVEDIRECTORY_OBJ%'
       OR UPPER(m.definition) LIKE N'%SP_ACTIVEDIRECTORY_SCP%'
       OR UPPER(m.definition) LIKE N'%SP_ACTIVEDIRECTORY_START%'
) AS hits
ORDER BY feature_name, schema_name, object_name;
"@

        $objectResult = Invoke-OptionalReadinessSqlQuery -ConnectionString $ConnectionString -Database $Database -CollectorName "object_pattern_scan:$Database" -TimeoutSeconds $TimeoutSeconds -Query $objectQuery
        Add-CollectionError -Errors $Errors -CollectorName 'object_pattern_scan' -Database $Database -Message $objectResult.Error
        $objectHits = @($objectResult.Rows)
    }

    return [pscustomobject][ordered]@{
        filegroupCount                  = Get-ObjectInt $feature 'filegroup_count'
        filestreamFilegroupCount        = Get-ObjectInt $feature 'filestream_filegroup_count'
        memoryOptimizedTableCount       = Get-ObjectInt $feature 'memory_optimized_table_count'
        filetableCount                  = Get-ObjectInt $feature 'filetable_count'
        externalTableCount              = Get-ObjectInt $feature 'external_table_count'
        fulltextCatalogCount            = Get-ObjectInt $feature 'fulltext_catalog_count'
        partitionSchemeCount            = Get-ObjectInt $feature 'partition_scheme_count'
        userAssemblyCount               = Get-ObjectInt $feature 'user_assembly_count'
        synonymCount                    = Get-ObjectInt $feature 'synonym_count'
        crossDatabaseReferenceCount     = Get-ObjectInt $feature 'cross_database_reference_count'
        changeTrackingEnabled           = Get-ObjectInt $feature 'change_tracking_enabled'
        queryStoreState                 = Get-ObjectText $feature 'query_store_state' 'Unavailable'
        windowsDatabasePrincipalCount   = Get-ObjectInt $feature 'windows_database_principal_count'
        databaseScopedCredentialCount   = Get-ObjectInt $feature 'database_scoped_credential_count'
        sqlAgentJobStepCount            = Get-ObjectInt $agent 'sql_agent_jobstep_count'
        sqlAgentCommandStepCount        = Get-ObjectInt $agent 'sql_agent_command_step_count'
        sqlAgentNonTsqlStepCount        = Get-ObjectInt $agent 'sql_agent_non_tsql_step_count'
        objectPatternHits               = @($objectHits)
    }
}

function Get-ObjectPatternSummary {
    param([object[]]$Hits)

    $summaries = @()
    foreach ($group in @($Hits | Group-Object feature_name)) {
        $samples = @($group.Group | Select-Object -First 5 | ForEach-Object {
            $schema = Get-ObjectText $_ 'schema_name'
            $name = Get-ObjectText $_ 'object_name'
            if ($schema -eq '') { $name } else { "$schema.$name" }
        })
        $summaries += [pscustomobject][ordered]@{
            featureName = $group.Name
            count       = @($group.Group).Count
            samples     = @($samples)
        }
    }

    return @($summaries)
}

function Test-PatternHit {
    param([object[]]$Summaries, [string]$FeatureName)
    return (@($Summaries | Where-Object { $_.featureName -eq $FeatureName }).Count -gt 0)
}

function New-DatabaseReadinessAssessment {
    param(
        [Parameter(Mandatory = $true)][object]$Server,
        [Parameter(Mandatory = $true)][object]$Database,
        [Parameter(Mandatory = $true)][object]$Feature,
        [int]$AssessedDatabaseCount = 1,
        [decimal]$AssessedDatabaseSizeGb = 0
    )

    $blockers = New-Object 'System.Collections.Generic.List[object]'
    $warnings = New-Object 'System.Collections.Generic.List[object]'
    $remediations = New-Object 'System.Collections.Generic.List[string]'
    $evidence = New-Object 'System.Collections.Generic.List[string]'
    $confidenceNotes = New-Object 'System.Collections.Generic.List[string]'

    $dbName = Get-ObjectText $Database 'database_name'
    if ($dbName -eq '') { $dbName = Get-ObjectText $Database 'databaseName' }
    $state = Get-ObjectText $Database 'state_desc'
    if ($state -eq '') { $state = Get-ObjectText $Database 'state' }
    $compatibility = Get-ObjectInt $Database 'compatibility_level'
    if ($compatibility -eq 0) { $compatibility = Get-ObjectInt $Database 'compatibilityLevel' }
    $sizeGb = Get-ObjectDecimal $Database 'total_size_gb'
    if ($sizeGb -eq 0) { $sizeGb = Get-ObjectDecimal $Database 'totalSizeGb' }
    $logFileCount = Get-ObjectInt $Database 'log_file_count'
    if ($logFileCount -eq 0) { $logFileCount = Get-ObjectInt $Database 'logFileCount' }
    $serviceBroker = Get-ObjectInt $Database 'service_broker_enabled'
    if ($serviceBroker -eq 0) { $serviceBroker = Get-ObjectInt $Database 'serviceBrokerEnabled' }
    $cdc = Get-ObjectInt $Database 'cdc_enabled'
    if ($cdc -eq 0) { $cdc = Get-ObjectInt $Database 'cdcEnabled' }
    $tde = Get-ObjectInt $Database 'tde_enabled'
    if ($tde -eq 0) { $tde = Get-ObjectInt $Database 'tdeEnabled' }

    $objectSummary = Get-ObjectPatternSummary -Hits @($Feature.objectPatternHits)

    Add-ListItem -List $evidence -Value "sizeGb=$([Math]::Round($sizeGb, 2))"
    Add-ListItem -List $evidence -Value "compatibilityLevel=$compatibility"
    Add-ListItem -List $evidence -Value "logFileCount=$logFileCount"
    Add-ListItem -List $evidence -Value "queryStoreState=$(Get-ObjectText $Feature 'queryStoreState' 'Unavailable')"

    if ($state -ne 'ONLINE') {
        Add-RuleHit -List $blockers -Target 'AzureSqlDatabase' -Severity 'Issue' -RuleId 'DATABASE_NOT_ONLINE' -Message "Database is not online ($state)." -Remediation 'Bring the database online or assess a restored online copy.'
        Add-RuleHit -List $blockers -Target 'AzureSqlManagedInstance' -Severity 'Issue' -RuleId 'DATABASE_NOT_ONLINE' -Message "Database is not online ($state)." -Remediation 'Bring the database online or assess a restored online copy.'
        Add-ListItem -List $remediations -Value 'Bring the database online or assess a restored online copy.'
    }

    if ($compatibility -gt 0 -and ($compatibility -lt 100 -or $compatibility -gt 160)) {
        Add-RuleHit -List $blockers -Target 'AzureSqlDatabase' -Severity 'Issue' -RuleId 'COMPATIBILITY_LEVEL' -Message "Compatibility level $compatibility is outside the Azure SQL Database 100-160 assessment range." -Remediation 'Move to a supported compatibility level and regression test.'
        Add-RuleHit -List $blockers -Target 'AzureSqlManagedInstance' -Severity 'Issue' -RuleId 'COMPATIBILITY_LEVEL' -Message "Compatibility level $compatibility is outside the Azure SQL Managed Instance 100-160 assessment range." -Remediation 'Move to a supported compatibility level and regression test.'
        Add-ListItem -List $remediations -Value 'Move to a supported compatibility level and regression test.'
    }

    if ($sizeGb -gt 100000) {
        Add-RuleHit -List $blockers -Target 'AzureSqlDatabase' -Severity 'Issue' -RuleId 'AZURE_SQL_DB_SIZE' -Message 'Database size exceeds the conservative Azure SQL Database assessment size envelope.' -Remediation 'Archive, shard, compress, or select SQL Server on Azure VM.'
    }

    if ($sizeGb -gt 32768) {
        Add-RuleHit -List $blockers -Target 'AzureSqlManagedInstance' -Severity 'Issue' -RuleId 'MI_DATABASE_SIZE' -Message 'Database size exceeds the Azure SQL Managed Instance 32 TB database assessment rule.' -Remediation 'Archive, shard, split the database, or select SQL Server on Azure VM.'
        Add-ListItem -List $remediations -Value 'Archive, shard, split the database, or select SQL Server on Azure VM.'
    }

    if ($AssessedDatabaseCount -gt 500) {
        Add-RuleHit -List $warnings -Target 'AzureSqlManagedInstance' -Severity 'Warning' -RuleId 'MI_DATABASE_COUNT' -Message 'The assessed instance has more than 500 user databases.' -Remediation 'Split databases across multiple managed instances or use SQL Server on Azure VM if they must remain together.'
    }

    if ($AssessedDatabaseSizeGb -gt 32768) {
        Add-RuleHit -List $warnings -Target 'AzureSqlManagedInstance' -Severity 'Warning' -RuleId 'MI_INSTANCE_SIZE' -Message 'Total assessed database size exceeds 32 TB.' -Remediation 'Split databases across multiple managed instances or use SQL Server on Azure VM if they must remain together.'
    }

    if ($logFileCount -gt 1) {
        Add-RuleHit -List $blockers -Target 'AzureSqlDatabase' -Severity 'Warning' -RuleId 'MULTIPLE_LOG_FILES' -Message 'Multiple database log files detected.' -Remediation 'Reduce the database to one log file before PaaS migration, or use SQL Server on Azure VM.'
        Add-RuleHit -List $blockers -Target 'AzureSqlManagedInstance' -Severity 'Issue' -RuleId 'MI_MULTIPLE_LOG_FILES' -Message 'Multiple database log files detected.' -Remediation 'Reduce the database to one log file before MI migration, or use SQL Server on Azure VM.'
        Add-ListItem -List $remediations -Value 'Reduce the database to one log file before MI migration, or use SQL Server on Azure VM.'
    }

    if ((Get-ObjectInt $Feature 'filestreamFilegroupCount') -gt 0) {
        Add-RuleHit -List $blockers -Target 'AzureSqlDatabase' -Severity 'Issue' -RuleId 'FILESTREAM' -Message 'FILESTREAM filegroups detected.' -Remediation 'Move binary content to application or Azure Blob storage, or use SQL Server on Azure VM.'
        Add-RuleHit -List $blockers -Target 'AzureSqlManagedInstance' -Severity 'Issue' -RuleId 'FILESTREAM' -Message 'FILESTREAM filegroups detected.' -Remediation 'Move binary content to application or Azure Blob storage, or use SQL Server on Azure VM.'
        Add-ListItem -List $remediations -Value 'Move FILESTREAM data outside SQL Server or use SQL Server on Azure VM.'
    }

    if ((Get-ObjectInt $Feature 'filetableCount') -gt 0) {
        Add-RuleHit -List $blockers -Target 'AzureSqlDatabase' -Severity 'Issue' -RuleId 'FILETABLE' -Message 'FileTable objects detected.' -Remediation 'Replace FileTable with application-managed document storage, or use SQL Server on Azure VM.'
        Add-RuleHit -List $blockers -Target 'AzureSqlManagedInstance' -Severity 'Issue' -RuleId 'FILETABLE' -Message 'FileTable objects detected.' -Remediation 'Replace FileTable with application-managed document storage, or use SQL Server on Azure VM.'
    }

    if ((Get-ObjectInt $Feature 'sqlAgentJobStepCount') -gt 0 -or (Get-ObjectInt $Server 'sqlAgentJobStepCount') -gt 0) {
        Add-RuleHit -List $blockers -Target 'AzureSqlDatabase' -Severity 'Warning' -RuleId 'SQL_AGENT_JOBS' -Message 'SQL Server Agent jobs or job steps detected.' -Remediation 'Move scheduling to Elastic Jobs, Azure Automation, Functions, Logic Apps, or validate MI SQL Agent support.'
        Add-ListItem -List $remediations -Value 'Move SQL Agent scheduling to a target-compatible scheduler, or validate MI SQL Agent support.'
    }

    if ((Get-ObjectInt $Feature 'sqlAgentCommandStepCount') -gt 0 -or (Get-ObjectInt $Server 'sqlAgentCommandStepCount') -gt 0) {
        Add-RuleHit -List $blockers -Target 'AzureSqlManagedInstance' -Severity 'Warning' -RuleId 'SQL_AGENT_COMMAND_STEPS' -Message 'SQL Agent CmdExec or PowerShell job steps detected.' -Remediation 'Rewrite OS command steps to Azure Automation, Functions, Logic Apps, or use SQL Server on Azure VM.'
        Add-RuleHit -List $blockers -Target 'AzureSqlDatabase' -Severity 'Warning' -RuleId 'SQL_AGENT_COMMAND_STEPS' -Message 'SQL Agent command-shell style job steps detected.' -Remediation 'Rewrite OS command steps outside the database platform.'
        Add-ListItem -List $remediations -Value 'Rewrite SQL Agent command-shell style steps outside SQL Server.'
    }
    elseif ((Get-ObjectInt $Feature 'sqlAgentNonTsqlStepCount') -gt 0 -or (Get-ObjectInt $Server 'sqlAgentNonTsqlStepCount') -gt 0) {
        Add-RuleHit -List $blockers -Target 'AzureSqlManagedInstance' -Severity 'Warning' -RuleId 'SQL_AGENT_UNSUPPORTED_SUBSYSTEMS' -Message 'Non-T-SQL SQL Agent job steps detected.' -Remediation 'Review job subsystems and rewrite unsupported MI steps before migration.'
    }

    if ((Get-ObjectInt $Feature 'crossDatabaseReferenceCount') -gt 0) {
        Add-RuleHit -List $blockers -Target 'AzureSqlDatabase' -Severity 'Warning' -RuleId 'CROSS_DATABASE_REFERENCES' -Message 'Cross-database references detected.' -Remediation 'Refactor references, use elastic query patterns, or co-locate databases on MI/VM.'
        Add-RuleHit -List $warnings -Target 'AzureSqlManagedInstance' -Severity 'Warning' -RuleId 'CROSS_DATABASE_REFERENCES' -Message 'Cross-database references require dependency and colocation validation.' -Remediation 'Co-locate dependent databases or refactor data access boundaries.'
    }

    if ((Get-ObjectInt $Server 'linkedServerCount') -gt 0) {
        Add-RuleHit -List $blockers -Target 'AzureSqlDatabase' -Severity 'Warning' -RuleId 'LINKED_SERVERS' -Message 'Linked servers detected.' -Remediation 'Replace linked servers with application integration, ETL/data movement, or target-supported patterns.'
        if ((Get-ObjectInt $Server 'nonSqlLinkedServerCount') -gt 0) {
            Add-RuleHit -List $blockers -Target 'AzureSqlManagedInstance' -Severity 'Issue' -RuleId 'MI_NON_SQL_LINKED_SERVER' -Message 'Linked server with non-SQL provider detected.' -Remediation 'Remove the non-SQL linked server dependency, route through SQL Server VM, or select SQL Server on Azure VM.'
        }
        else {
            Add-RuleHit -List $warnings -Target 'AzureSqlManagedInstance' -Severity 'Warning' -RuleId 'MI_SQL_LINKED_SERVER' -Message 'Linked servers need provider and network validation on MI.' -Remediation 'Validate provider, authentication, and network support on MI.'
        }
    }

    if ($serviceBroker -gt 0) {
        Add-RuleHit -List $blockers -Target 'AzureSqlDatabase' -Severity 'Issue' -RuleId 'SERVICE_BROKER' -Message 'Service Broker is enabled.' -Remediation 'Use Azure SQL Managed Instance where broker semantics are required, or redesign messaging.'
        Add-RuleHit -List $warnings -Target 'AzureSqlManagedInstance' -Severity 'Warning' -RuleId 'SERVICE_BROKER_MI_VALIDATE' -Message 'Service Broker usage needs MI behavior validation.' -Remediation 'Validate broker routes, activation, and dependent databases on MI.'
    }

    if ((Get-ObjectInt $Server 'databaseMailProfileCount') -gt 0) {
        Add-RuleHit -List $blockers -Target 'AzureSqlDatabase' -Severity 'Warning' -RuleId 'DATABASE_MAIL' -Message 'Database Mail profiles detected.' -Remediation 'Move notifications outside Azure SQL Database or configure MI Database Mail.'
        Add-RuleHit -List $warnings -Target 'AzureSqlManagedInstance' -Severity 'Warning' -RuleId 'DATABASE_MAIL_MI' -Message 'Database Mail requires MI-specific configuration.' -Remediation 'Configure and test Database Mail profile on MI.'
    }

    if ((Get-ObjectInt $Server 'credentialCount') -gt 0) {
        Add-RuleHit -List $blockers -Target 'AzureSqlDatabase' -Severity 'Warning' -RuleId 'SERVER_CREDENTIALS' -Message 'Server-scoped credentials detected.' -Remediation 'Convert to database-scoped credentials or managed identity patterns where possible.'
        Add-RuleHit -List $warnings -Target 'AzureSqlManagedInstance' -Severity 'Warning' -RuleId 'SERVER_CREDENTIALS_MI' -Message 'Server credentials require target validation.' -Remediation 'Validate credential type and external access requirements.'
    }

    if ((Get-ObjectInt $Server 'serverTriggerCount') -gt 0) {
        Add-RuleHit -List $blockers -Target 'AzureSqlDatabase' -Severity 'Warning' -RuleId 'SERVER_TRIGGERS' -Message 'Server-scoped triggers detected.' -Remediation 'Move to database-level logic where possible or select MI/VM after validation.'
        Add-RuleHit -List $warnings -Target 'AzureSqlManagedInstance' -Severity 'Warning' -RuleId 'SERVER_TRIGGERS_MI' -Message 'Server trigger behavior requires MI validation.' -Remediation 'Validate trigger scope and behavior on MI.'
    }

    if ((Get-ObjectInt $Server 'windowsServerPrincipalCount') -gt 0 -or (Get-ObjectInt $Feature 'windowsDatabasePrincipalCount') -gt 0) {
        Add-RuleHit -List $warnings -Target 'AzureSqlDatabase' -Severity 'Warning' -RuleId 'WINDOWS_AUTH_PRINCIPALS' -Message 'Windows logins or users detected.' -Remediation 'Map Windows identities to Microsoft Entra identities or SQL authentication before migration.'
        Add-RuleHit -List $warnings -Target 'AzureSqlManagedInstance' -Severity 'Warning' -RuleId 'WINDOWS_AUTH_PRINCIPALS_MI' -Message 'Windows logins or users need identity migration planning.' -Remediation 'Plan Microsoft Entra identity mapping and authentication changes.'
    }

    if ((Get-ObjectInt $Server 'traceFlagCount') -gt 0) {
        Add-RuleHit -List $warnings -Target 'AzureSqlDatabase' -Severity 'Warning' -RuleId 'TRACE_FLAGS' -Message 'Server trace flags detected.' -Remediation 'Remove trace flag dependency or validate target behavior.'
        Add-RuleHit -List $warnings -Target 'AzureSqlManagedInstance' -Severity 'Warning' -RuleId 'TRACE_FLAGS_MI' -Message 'Most trace flags are not a clean MI dependency.' -Remediation 'Review trace flags and validate MI support.'
    }

    if ((Get-ObjectInt $Server 'xpCmdShellEnabled') -gt 0 -or (Test-PatternHit -Summaries $objectSummary -FeatureName 'xp_cmdshell')) {
        Add-RuleHit -List $blockers -Target 'AzureSqlDatabase' -Severity 'Issue' -RuleId 'XP_CMDSHELL' -Message 'xp_cmdshell is enabled or referenced.' -Remediation 'Remove OS shell execution from SQL Server or use SQL Server on Azure VM with explicit controls.'
        Add-RuleHit -List $blockers -Target 'AzureSqlManagedInstance' -Severity 'Issue' -RuleId 'XP_CMDSHELL' -Message 'xp_cmdshell is enabled or referenced.' -Remediation 'Remove OS shell execution from SQL Server or use SQL Server on Azure VM with explicit controls.'
        Add-ListItem -List $remediations -Value 'Remove xp_cmdshell usage or select SQL Server on Azure VM.'
    }

    if ((Get-ObjectInt $Server 'resourceGovernorPoolCount') -gt 0) {
        Add-RuleHit -List $blockers -Target 'AzureSqlDatabase' -Severity 'Issue' -RuleId 'RESOURCE_GOVERNOR' -Message 'Resource Governor user pools detected.' -Remediation 'Remove Resource Governor dependency or select SQL Server on Azure VM.'
        Add-RuleHit -List $blockers -Target 'AzureSqlManagedInstance' -Severity 'Issue' -RuleId 'RESOURCE_GOVERNOR' -Message 'Resource Governor user pools detected.' -Remediation 'Remove Resource Governor dependency or select SQL Server on Azure VM.'
    }

    if ((Get-ObjectInt $Feature 'userAssemblyCount') -gt 0) {
        Add-RuleHit -List $blockers -Target 'AzureSqlDatabase' -Severity 'Warning' -RuleId 'CLR_ASSEMBLIES' -Message 'User CLR assemblies detected.' -Remediation 'Move CLR logic to application/Azure Functions or validate MI support.'
        Add-RuleHit -List $warnings -Target 'AzureSqlManagedInstance' -Severity 'Warning' -RuleId 'CLR_ASSEMBLIES_MI' -Message 'CLR assemblies require MI compatibility validation.' -Remediation 'Validate assemblies, permission sets, and dependencies on MI.'
    }

    if ((Get-ObjectInt $Server 'externalScriptsEnabled') -gt 0) {
        Add-RuleHit -List $blockers -Target 'AzureSqlDatabase' -Severity 'Issue' -RuleId 'EXTERNAL_SCRIPTS' -Message 'External scripts are enabled.' -Remediation 'Move R/Python execution to application, Azure ML, Functions, or SQL Server on Azure VM.'
        Add-RuleHit -List $blockers -Target 'AzureSqlManagedInstance' -Severity 'Warning' -RuleId 'EXTERNAL_SCRIPTS_MI' -Message 'External script runtime dependency detected.' -Remediation 'Move runtime execution outside SQL Server or validate an IaaS target.'
    }

    if ((Get-ObjectInt $Server 'polybaseEnabled') -gt 0 -or (Get-ObjectInt $Feature 'externalTableCount') -gt 0) {
        Add-RuleHit -List $blockers -Target 'AzureSqlDatabase' -Severity 'Warning' -RuleId 'EXTERNAL_DATA' -Message 'PolyBase or external tables detected.' -Remediation 'Validate Azure SQL external data support or redesign to Azure-native data integration.'
        Add-RuleHit -List $warnings -Target 'AzureSqlManagedInstance' -Severity 'Warning' -RuleId 'EXTERNAL_DATA_MI' -Message 'External data access requires MI validation.' -Remediation 'Validate external table, data source, and credential behavior on MI.'
    }

    if ((Test-PatternHit -Summaries $objectSummary -FeatureName 'bulk_operation') -or (Test-PatternHit -Summaries $objectSummary -FeatureName 'openrowset')) {
        Add-RuleHit -List $blockers -Target 'AzureSqlDatabase' -Severity 'Warning' -RuleId 'OPENROWSET_OR_BULK' -Message 'OPENROWSET or bulk operation references detected.' -Remediation 'Move file access to Azure Blob-supported paths or redesign ingestion.'
        Add-RuleHit -List $warnings -Target 'AzureSqlManagedInstance' -Severity 'Warning' -RuleId 'OPENROWSET_OR_BULK_MI' -Message 'OPENROWSET or bulk operation references need source/provider review for MI.' -Remediation 'Validate provider and Azure Blob based access, or use SQL Server on Azure VM.'
    }

    if ((Test-PatternHit -Summaries $objectSummary -FeatureName 'opendatasource') -or (Test-PatternHit -Summaries $objectSummary -FeatureName 'openquery')) {
        Add-RuleHit -List $blockers -Target 'AzureSqlDatabase' -Severity 'Warning' -RuleId 'AD_HOC_PROVIDER_ACCESS' -Message 'Ad hoc external provider access references detected.' -Remediation 'Replace with supported integration patterns or validate MI/VM target.'
        Add-RuleHit -List $warnings -Target 'AzureSqlManagedInstance' -Severity 'Warning' -RuleId 'AD_HOC_PROVIDER_ACCESS_MI' -Message 'External provider access needs MI provider validation.' -Remediation 'Validate providers and remote targets.'
    }

    if (Test-PatternHit -Summaries $objectSummary -FeatureName 'distributed_transaction') {
        Add-RuleHit -List $blockers -Target 'AzureSqlDatabase' -Severity 'Warning' -RuleId 'DISTRIBUTED_TRANSACTION' -Message 'Distributed transaction references detected.' -Remediation 'Remove distributed transaction dependency or validate participant support on MI/VM.'
        Add-RuleHit -List $warnings -Target 'AzureSqlManagedInstance' -Severity 'Warning' -RuleId 'DISTRIBUTED_TRANSACTION_MI' -Message 'Distributed transactions need participant validation for MI.' -Remediation 'Validate whether all participants are supported SQL targets.'
    }

    foreach ($legacyFeature in @('legacy_outer_join', 'legacy_raiserror', 'removed_system_procedure')) {
        if (Test-PatternHit -Summaries $objectSummary -FeatureName $legacyFeature) {
            Add-RuleHit -List $warnings -Target 'AzureSqlDatabase' -Severity 'Warning' -RuleId $legacyFeature.ToUpperInvariant() -Message "$legacyFeature pattern detected in module definitions." -Remediation 'Modernize the T-SQL pattern and regression test before migration.'
            Add-RuleHit -List $warnings -Target 'AzureSqlManagedInstance' -Severity 'Warning' -RuleId $legacyFeature.ToUpperInvariant() -Message "$legacyFeature pattern detected in module definitions." -Remediation 'Modernize the T-SQL pattern and regression test before migration.'
        }
    }

    if ((Get-ObjectText $Feature 'queryStoreState' 'Unavailable') -eq 'Unavailable') {
        Add-ListItem -List $confidenceNotes -Value 'Query Store evidence unavailable; sizing confidence is low.'
    }
    if ((Get-ObjectInt $Server 'hasViewServerState') -eq 0 -and (Get-ObjectInt $Server 'isSysadmin') -eq 0) {
        Add-ListItem -List $confidenceNotes -Value 'VIEW SERVER STATE unavailable; workload, IO, and memory evidence is limited.'
    }
    if ((Get-ObjectInt $Server 'hasViewAnyDefinition') -eq 0 -and (Get-ObjectInt $Server 'isSysadmin') -eq 0) {
        Add-ListItem -List $confidenceNotes -Value 'VIEW ANY DEFINITION unavailable; object pattern scan may be incomplete.'
    }
    if (@($objectSummary).Count -gt 0) {
        Add-ListItem -List $evidence -Value "objectPatternHits=$(@($objectSummary).Count)"
    }
    if ($cdc -gt 0) {
        Add-RuleHit -List $warnings -Target 'AzureSqlDatabase' -Severity 'Warning' -RuleId 'CDC' -Message 'CDC is enabled.' -Remediation 'Validate target CDC support and downstream consumers.'
        Add-RuleHit -List $warnings -Target 'AzureSqlManagedInstance' -Severity 'Warning' -RuleId 'CDC_MI' -Message 'CDC is enabled.' -Remediation 'Validate target CDC support and downstream consumers.'
    }
    if ($tde -gt 0) {
        Add-RuleHit -List $warnings -Target 'AzureSqlDatabase' -Severity 'Warning' -RuleId 'TDE' -Message 'TDE is enabled.' -Remediation 'Plan key/certificate handling and target encryption model.'
        Add-RuleHit -List $warnings -Target 'AzureSqlManagedInstance' -Severity 'Warning' -RuleId 'TDE_MI' -Message 'TDE is enabled.' -Remediation 'Plan key/certificate handling and target encryption model.'
    }

    foreach ($hit in @($blockers + $warnings)) {
        Add-ListItem -List $remediations -Value $hit.remediation
    }

    $azureSqlBlockers = @($blockers | Where-Object { $_.target -eq 'AzureSqlDatabase' })
    $miBlockers = @($blockers | Where-Object { $_.target -eq 'AzureSqlManagedInstance' })
    $azureSqlWarnings = @($warnings | Where-Object { $_.target -eq 'AzureSqlDatabase' })
    $miWarnings = @($warnings | Where-Object { $_.target -eq 'AzureSqlManagedInstance' })

    $azureReadiness = if (@($azureSqlBlockers).Count -eq 0 -and @($azureSqlWarnings).Count -eq 0) {
        'Ready'
    }
    elseif (@($azureSqlBlockers).Count -eq 0) {
        'ReadyWithWarnings'
    }
    else {
        'Blocked'
    }

    $miReadiness = if (@($miBlockers).Count -eq 0 -and @($miWarnings).Count -eq 0) {
        'Ready'
    }
    elseif (@($miBlockers).Count -eq 0) {
        'ReadyWithWarnings'
    }
    else {
        'Blocked'
    }

    $target = 'AzureSqlDatabase'
    if (@($azureSqlBlockers).Count -gt 0) {
        if (@($miBlockers).Count -eq 0) {
            $target = 'AzureSqlManagedInstance'
        }
        else {
            $target = 'SqlServerOnAzureVm'
        }
    }

    $confidence = 'Medium'
    if (@($confidenceNotes).Count -gt 0) { $confidence = 'Low' }
    if ($azureReadiness -eq 'Ready' -and $miReadiness -eq 'Ready' -and @($confidenceNotes).Count -eq 0) { $confidence = 'High' }

    $serviceTier = 'General Purpose'
    if ($target -eq 'AzureSqlDatabase' -and $sizeGb -gt 4000) {
        $serviceTier = 'Hyperscale'
    }
    elseif ((Get-ObjectInt $Feature 'memoryOptimizedTableCount') -gt 0) {
        $serviceTier = 'Business Critical'
    }
    elseif ($target -eq 'SqlServerOnAzureVm') {
        $serviceTier = 'SQL Server on Azure VM; select VM family after workload baseline.'
    }

    return [pscustomobject][ordered]@{
        databaseName                = $dbName
        recommendedTarget           = $target
        azureSqlDatabaseReadiness   = $azureReadiness
        managedInstanceReadiness    = $miReadiness
        sqlVmFallback               = [pscustomobject][ordered]@{
            recommended = ($target -eq 'SqlServerOnAzureVm')
            reason      = if ($target -eq 'SqlServerOnAzureVm') { 'Azure SQL Database and Managed Instance have unresolved blockers for this evidence set.' } else { 'Use only if remediation is not accepted or OS/instance-level control must be preserved.' }
        }
        serviceTierHint             = $serviceTier
        sizingEvidence              = [pscustomobject][ordered]@{
            currentSizeGb       = [Math]::Round($sizeGb, 2)
            storageWithHeadroom = [Math]::Max(32, [Math]::Ceiling($sizeGb * 1.3))
            sourceCpuCount      = Get-ObjectInt $Server 'cpuCount'
            sourceMemoryMb      = Get-ObjectDecimal $Server 'physicalMemoryMb'
            confidence          = $confidence
            confidenceNotes     = @($confidenceNotes)
        }
        blockers                    = @($blockers)
        warnings                    = @($warnings)
        remediation                 = @($remediations | Select-Object -Unique)
        evidenceSummary             = Join-UniqueText -Values @($evidence) -Default 'No notable feature evidence.'
        objectPatternSummary        = @($objectSummary)
    }
}

function ConvertTo-JsonDepthSafe {
    param([Parameter(Mandatory = $true)]$Value)
    return $Value | ConvertTo-Json -Depth 12
}

function Invoke-SqlAzureReadinessAssessmentMain {
    $collectionErrors = New-Object 'System.Collections.Generic.List[object]'
    $instance = Get-TextValue $SqlInstance
    if (Test-IsBlank $instance) {
        $instance = Read-Host 'SQL Server instance name'
    }
    if (Test-IsBlank $instance) { throw 'SQL Server instance name is required.' }

    $securePassword = $null
    if (-not $UseIntegratedSecurity) {
        if (Test-IsBlank $SqlUsername) {
            $SqlUsername = Read-Host 'SQL username'
        }
        if ($PromptForSqlPassword -or $null -eq $SqlPassword) {
            $securePassword = Read-Host 'SQL password' -AsSecureString
        }
        else {
            $securePassword = $SqlPassword
        }
    }

    $resolvedOutputPath = Get-TextValue $OutputPath
    if (Test-IsBlank $resolvedOutputPath) {
        $resolvedOutputPath = Get-DefaultOutputPath -Instance $instance
    }
    $outputDirectory = Split-Path -Parent $resolvedOutputPath
    if (-not (Test-Path -LiteralPath $outputDirectory)) {
        [void](New-Item -ItemType Directory -Path $outputDirectory -Force)
    }

    Write-Host "Connecting to $instance..."
    $connectionString = New-ReadinessConnectionString `
        -Instance $instance `
        -IntegratedSecurity $UseIntegratedSecurity `
        -Username $SqlUsername `
        -Password $securePassword `
        -Encrypt $EncryptConnection `
        -TrustCertificate $TrustServerCertificate `
        -ConnectTimeout $ConnectionTimeoutSeconds

    Write-Host 'Collecting server metadata...'
    $server = Get-ServerReadinessEvidence `
        -ConnectionString $connectionString `
        -Instance $instance `
        -Errors $collectionErrors `
        -TimeoutSeconds $CommandTimeoutSeconds

    Write-Host 'Collecting database list...'
    $databaseRows = @(Get-DatabaseListEvidence `
        -ConnectionString $connectionString `
        -OnlyDatabase $DatabaseName `
        -TimeoutSeconds $CommandTimeoutSeconds)

    if (-not (Test-IsBlank $DatabaseName) -and @($databaseRows).Count -eq 0) {
        throw "Database not found or not accessible: $DatabaseName"
    }

    $totalSizeGb = 0
    foreach ($row in @($databaseRows)) {
        $totalSizeGb += Get-ObjectDecimal $row 'total_size_gb'
    }

    $databaseAssessments = @()
    foreach ($db in @($databaseRows)) {
        $dbName = Get-ObjectText $db 'database_name'
        Write-Host "Assessing $dbName..."

        if ((Get-ObjectText $db 'state_desc') -eq 'ONLINE') {
            $feature = Get-DatabaseFeatureEvidence `
                -ConnectionString $connectionString `
                -Database $dbName `
                -Errors $collectionErrors `
                -ScanObjects $IncludeObjectPatternScan `
                -MaxObjectRows $MaxObjectPatternRows `
                -TimeoutSeconds $CommandTimeoutSeconds
        }
        else {
            Add-CollectionError -Errors $collectionErrors -CollectorName 'database_features' -Database $dbName -Message "Skipped in-database collectors because database state is $(Get-ObjectText $db 'state_desc')."
            $feature = [pscustomobject][ordered]@{
                filegroupCount                = 0
                filestreamFilegroupCount      = 0
                memoryOptimizedTableCount     = 0
                filetableCount                = 0
                externalTableCount            = 0
                fulltextCatalogCount          = 0
                partitionSchemeCount          = 0
                userAssemblyCount             = 0
                synonymCount                  = 0
                crossDatabaseReferenceCount   = 0
                changeTrackingEnabled         = 0
                queryStoreState               = 'Unavailable'
                windowsDatabasePrincipalCount = 0
                databaseScopedCredentialCount = 0
                sqlAgentJobStepCount          = 0
                sqlAgentCommandStepCount      = 0
                sqlAgentNonTsqlStepCount      = 0
                objectPatternHits             = @()
            }
        }

        $databaseAssessments += New-DatabaseReadinessAssessment `
            -Server $server `
            -Database $db `
            -Feature $feature `
            -AssessedDatabaseCount @($databaseRows).Count `
            -AssessedDatabaseSizeGb $totalSizeGb
    }

    $dbReady = @($databaseAssessments | Where-Object { $_.recommendedTarget -eq 'AzureSqlDatabase' }).Count
    $miReady = @($databaseAssessments | Where-Object { $_.recommendedTarget -eq 'AzureSqlManagedInstance' }).Count
    $vmFallback = @($databaseAssessments | Where-Object { $_.recommendedTarget -eq 'SqlServerOnAzureVm' }).Count
    $collectionStatus = if (@($collectionErrors).Count -gt 0) { 'CompletedWithWarnings' } else { 'Completed' }

    $report = [pscustomobject][ordered]@{
        scriptVersion    = $script:AssessmentVersion
        generatedAtUtc   = (Get-Date).ToUniversalTime().ToString('s') + 'Z'
        sqlInstance      = $instance
        collectionStatus = $collectionStatus
        permissions      = [pscustomobject][ordered]@{
            hasViewServerState   = [bool]((Get-ObjectInt $server 'hasViewServerState') -gt 0 -or (Get-ObjectInt $server 'isSysadmin') -gt 0)
            hasViewAnyDefinition = [bool]((Get-ObjectInt $server 'hasViewAnyDefinition') -gt 0 -or (Get-ObjectInt $server 'isSysadmin') -gt 0)
            isSysadmin           = [bool]((Get-ObjectInt $server 'isSysadmin') -gt 0)
        }
        instanceSummary  = [pscustomobject][ordered]@{
            serverName                  = $server.serverName
            edition                     = $server.edition
            productVersion              = $server.productVersion
            productLevel                = $server.productLevel
            productUpdateLevel          = $server.productUpdateLevel
            cpuCount                    = $server.cpuCount
            physicalMemoryMb            = $server.physicalMemoryMb
            assessedDatabaseCount       = @($databaseRows).Count
            assessedDatabaseSizeGb      = [Math]::Round($totalSizeGb, 2)
            azureSqlDatabaseCandidates  = $dbReady
            managedInstanceCandidates   = $miReady
            sqlServerOnAzureVmFallbacks = $vmFallback
        }
        databases        = @($databaseAssessments)
        collectionErrors = @($collectionErrors)
        ruleSources      = @(
            [pscustomobject][ordered]@{ name = 'Azure SQL Database assessment rules'; url = 'https://learn.microsoft.com/en-us/data-migration/sql-server/database/assessment-rules'; reviewedDate = '2026-07-01' },
            [pscustomobject][ordered]@{ name = 'Azure SQL Managed Instance assessment rules'; url = 'https://learn.microsoft.com/en-us/data-migration/sql-server/managed-instance/assessment-rules'; reviewedDate = '2026-07-01' },
            [pscustomobject][ordered]@{ name = 'Azure SQL Database and Managed Instance feature comparison'; url = 'https://learn.microsoft.com/en-us/azure/azure-sql/database/features-comparison'; reviewedDate = '2026-07-01' }
        )
    }

    $json = ConvertTo-JsonDepthSafe -Value $report
    Set-Content -LiteralPath $resolvedOutputPath -Value $json -Encoding UTF8

    Write-Host ''
    Write-Host 'SQL Server Azure readiness assessment complete.'
    Write-Host "Output: $resolvedOutputPath"
    Write-Host "Azure SQL Database candidates: $dbReady"
    Write-Host "Azure SQL Managed Instance candidates: $miReady"
    Write-Host "SQL Server on Azure VM fallbacks: $vmFallback"
    if (@($collectionErrors).Count -gt 0) {
        Write-Warning "Completed with $(@($collectionErrors).Count) collection warning(s). Review collectionErrors in the JSON."
    }
}

if (-not $script:SkipSqlAzureReadinessAutoRun) {
    Invoke-SqlAzureReadinessAssessmentMain
}
Invoke-SqlAzureReadinessStandalone.ps1
