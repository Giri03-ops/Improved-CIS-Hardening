# =============================================================================
# CIS IIS Hardening Orchestrator — main.ps1
# Runs CIS controls 1.2–4.7 (IIS) and 7.2–7.12 (SCHANNEL) in sequence.
#
# Usage:
#   .\main.ps1                          # Live run (applies changes + creates backups)
#   .\main.ps1 -WhatIf                  # Audit only — no changes, no backups
#   .\main.ps1 -WhatIf -SkipCIS '2.3','7.12'   # Skip specific controls
#
# Restore IIS after a live run:
#   & "$env:SystemRoot\System32\inetsrv\appcmd.exe" restore backup "CIS_<timestamp>"
# =============================================================================
param(
    [switch]$WhatIf,
    [string[]]$SkipCIS = @()
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# 1. Admin check (manual — not #Requires, so the message reaches the log)
# ---------------------------------------------------------------------------
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'ERROR: This script must be run as Administrator.' -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------------
# 2. Timestamp (set once, reused everywhere)
# ---------------------------------------------------------------------------
$ts = Get-Date -Format 'yyyyMMdd_HHmmss'

# ---------------------------------------------------------------------------
# 3. Directory setup
# ---------------------------------------------------------------------------
$scriptRoot   = $PSScriptRoot
$scriptsDir   = Join-Path $scriptRoot 'Scripts'
$backupDir    = Join-Path $scriptRoot "Backups\$ts"
$reportDir    = Join-Path $scriptRoot "Reports\$ts"
$logFile      = Join-Path $reportDir  'CIS_Run.log'
$reportFile   = Join-Path $reportDir  'CIS_Report.html'
$IISXmlExport = Join-Path $backupDir  'IIS_Config_Export.xml'
$SCHANNELReg  = Join-Path $backupDir  'SCHANNEL_Registry.reg'

New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
New-Item -Path $reportDir -ItemType Directory -Force | Out-Null

# ---------------------------------------------------------------------------
# 4. Write-Log — writes to console and appends to log file
# ---------------------------------------------------------------------------
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )
    $line = "[$(Get-Date -Format 'HH:mm:ss')] [$Level] $Message"
    switch ($Level) {
        'Warning' { Write-Host $line -ForegroundColor Yellow }
        'Error'   { Write-Host $line -ForegroundColor Red   }
        default   { Write-Host $line }
    }
    Add-Content -Path $logFile -Value $line -Encoding UTF8
}

Write-Log "CIS IIS Hardening orchestrator started. WhatIf=$WhatIf  SkipCIS=[$($SkipCIS -join ',')]"
Write-Log "Timestamp : $ts"
Write-Log "Reports   : $reportDir"
Write-Log "Backups   : $backupDir"

# ---------------------------------------------------------------------------
# 5. IIS detection
# ---------------------------------------------------------------------------
$iisService   = Get-Service W3SVC -ErrorAction SilentlyContinue
$IISInstalled = $null -ne $iisService

if ($IISInstalled) {
    Write-Log 'IIS (W3SVC) service detected.'
} else {
    Write-Log 'IIS (W3SVC) not found. IIS-specific controls (1.2–4.7) will be skipped.' -Level Warning
}

# ---------------------------------------------------------------------------
# 6. WebAdministration module import (only if IIS present)
# ---------------------------------------------------------------------------
if ($IISInstalled) {
    try {
        Import-Module WebAdministration -ErrorAction Stop
        Write-Log 'WebAdministration module imported successfully.'
    } catch {
        Write-Log "Failed to import WebAdministration module: $_ — IIS controls will be skipped." -Level Error
        $IISInstalled = $false
    }
}

# ---------------------------------------------------------------------------
# 7. Backup phase (skipped in WhatIf mode)
# ---------------------------------------------------------------------------
if (-not $WhatIf) {
    Write-Log 'Starting backup phase...'

    $appcmd = "$env:SystemRoot\System32\inetsrv\appcmd.exe"

    if ($IISInstalled -and (Test-Path $appcmd)) {
        # IIS named backup (restores with: appcmd restore backup "CIS_<ts>")
        $iisBackupName = "CIS_$ts"
        try {
            & $appcmd add backup $iisBackupName 2>&1 | ForEach-Object { Write-Log "  [appcmd] $_" }
            Write-Log "IIS named backup created: $iisBackupName  (restore with: appcmd restore backup `"$iisBackupName`")"
        } catch {
            Write-Log "IIS named backup failed: $_ — continuing." -Level Warning
        }

        # Human-readable config snapshot
        try {
            & $appcmd list config 'MACHINE/WEBROOT/APPHOST' 2>&1 | Out-File -FilePath $IISXmlExport -Encoding UTF8
            Write-Log "IIS config snapshot: $IISXmlExport"
        } catch {
            Write-Log "IIS config export failed: $_ — continuing." -Level Warning
        }
    }

    # SCHANNEL registry backup
    try {
        & reg @('export', 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL', $SCHANNELReg, '/y') 2>&1 |
            ForEach-Object { Write-Log "  [reg] $_" }
        Write-Log "SCHANNEL registry backup: $SCHANNELReg"
    } catch {
        Write-Log "SCHANNEL registry backup failed: $_ — continuing." -Level Warning
    }

    Write-Log 'Backup phase complete.'
} else {
    Write-Log 'WhatIf mode: backup phase skipped.'
}

# ---------------------------------------------------------------------------
# 8. CIS manifest — ordered map of all controls
# ---------------------------------------------------------------------------
$manifest = [ordered]@{
    '1.2'  = @{ File='CIS_1.2.ps1';  Function='Invoke-CIS1_2';  RequiresIIS=$true;  Level='L1'; Description='Ensure host headers are configured on all sites' }
    '1.6'  = @{ File='CIS_1.6.ps1';  Function='Invoke-CIS1_6';  RequiresIIS=$true;  Level='L1'; Description="Ensure 'application pool identity' is configured for anonymous user identity" }
    '2.3'  = @{ File='CIS_2.3.ps1';  Function='Invoke-CIS2_3';  RequiresIIS=$true;  Level='L1'; Description="Ensure 'forms authentication' require SSL is configured" }
    '2.4'  = @{ File='CIS_2.4.ps1';  Function='Invoke-CIS2_4';  RequiresIIS=$true;  Level='L2'; Description='Ensure Forms Authentication uses cookies (cookieless=UseCookies)' }
    '3.7'  = @{ File='CIS_3.7.ps1';  Function='Invoke-CIS3_7';  RequiresIIS=$true;  Level='L1'; Description='Ensure cookies are set with HttpOnly flag (httpOnlyCookies=True)' }
    '3.10' = @{ File='CIS_3.10.ps1'; Function='Invoke-CIS3_10'; RequiresIIS=$true;  Level='L1'; Description='Ensure global .NET trust level is configured to Medium' }
    '4.4'  = @{ File='CIS_4.4.ps1';  Function='Invoke-CIS4_4';  RequiresIIS=$true;  Level='L2'; Description='Ensure non-ASCII characters in URLs are blocked (allowHighBitCharacters=False)' }
    '4.7'  = @{ File='CIS_4.7.ps1';  Function='Invoke-CIS4_7';  RequiresIIS=$true;  Level='L1'; Description='Ensure unlisted file extensions are not allowed (allowUnlisted=False)' }
    '7.2'  = @{ File='CIS_7.2.ps1';  Function='Invoke-CIS7_2';  RequiresIIS=$false; Level='L1'; Description='Ensure SSL 2.0 is disabled (Server + Client)' }
    '7.3'  = @{ File='CIS_7.3.ps1';  Function='Invoke-CIS7_3';  RequiresIIS=$false; Level='L1'; Description='Ensure SSL 3.0 is disabled (Server + Client)' }
    '7.4'  = @{ File='CIS_7.4.ps1';  Function='Invoke-CIS7_4';  RequiresIIS=$false; Level='L1'; Description='Ensure TLS 1.0 is disabled (Server + Client)' }
    '7.5'  = @{ File='CIS_7.5.ps1';  Function='Invoke-CIS7_5';  RequiresIIS=$false; Level='L1'; Description='Ensure TLS 1.1 is disabled (Server + Client)' }
    '7.6'  = @{ File='CIS_7.6.ps1';  Function='Invoke-CIS7_6';  RequiresIIS=$false; Level='L1'; Description='Ensure TLS 1.2 is enabled (Server + Client)' }
    '7.7'  = @{ File='CIS_7.7.ps1';  Function='Invoke-CIS7_7';  RequiresIIS=$false; Level='L1'; Description='Ensure NULL cipher suite is disabled' }
    '7.8'  = @{ File='CIS_7.8.ps1';  Function='Invoke-CIS7_8';  RequiresIIS=$false; Level='L1'; Description='Ensure DES 56/56 cipher is disabled' }
    '7.9'  = @{ File='CIS_7.9.ps1';  Function='Invoke-CIS7_9';  RequiresIIS=$false; Level='L1'; Description='Ensure RC4 cipher suites are disabled' }
    '7.10' = @{ File='CIS_7.10.ps1'; Function='Invoke-CIS7_10'; RequiresIIS=$false; Level='L1'; Description='Ensure AES 128/128 cipher suite is disabled' }
    '7.11' = @{ File='CIS_7.11.ps1'; Function='Invoke-CIS7_11'; RequiresIIS=$false; Level='L1'; Description='Ensure AES 256/256 cipher suite is enabled' }
    '7.12' = @{ File='CIS_7.12.ps1'; Function='Invoke-CIS7_12'; RequiresIIS=$false; Level='L2'; Description='Ensure TLS cipher suite ordering is configured' }
}

# ---------------------------------------------------------------------------
# 9. Normalize and validate -SkipCIS input, then orchestration loop
# ---------------------------------------------------------------------------
$normalizedSkipCIS = @(
    $SkipCIS |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { $_.Trim() } |
        Select-Object -Unique
)

$invalidSkipCIS = @($normalizedSkipCIS | Where-Object { $manifest.Keys -notcontains $_ })
if ($invalidSkipCIS.Count -gt 0) {
    Write-Log "Ignoring invalid -SkipCIS references: $($invalidSkipCIS -join ', ')" -Level Warning
}

$effectiveSkipCIS = @($normalizedSkipCIS | Where-Object { $manifest.Keys -contains $_ })

$Results = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($ref in $manifest.Keys) {
    $entry = $manifest[$ref]
    Write-Log "--- CIS $ref : $($entry.Description) ---"

    # Skip if user requested
    if ($effectiveSkipCIS -contains $ref) {
        Write-Log "CIS $ref: Skipped (user-requested via -SkipCIS)." -Level Warning
        $Results.Add([PSCustomObject]@{
            CISRef      = $ref
            Description = $entry.Description
            Level       = $entry.Level
            Before      = 'N/A'
            After       = 'N/A'
            Status      = 'Skipped'
            Messages    = @("Skipped by user request (-SkipCIS '$ref').")
        })
        continue
    }

    # Skip IIS controls when IIS is not installed
    if ($entry.RequiresIIS -and -not $IISInstalled) {
        Write-Log "CIS $ref: Skipped (IIS not installed)." -Level Warning
        $Results.Add([PSCustomObject]@{
            CISRef      = $ref
            Description = $entry.Description
            Level       = $entry.Level
            Before      = 'N/A'
            After       = 'N/A'
            Status      = 'Skipped'
            Messages    = @('Skipped: IIS (W3SVC) not installed on this system.')
        })
        continue
    }

    $scriptPath = Join-Path $scriptsDir $entry.File

    # Fail fast if script file is missing
    if (-not (Test-Path $scriptPath)) {
        Write-Log "CIS $ref: Script file not found: $scriptPath" -Level Error
        $Results.Add([PSCustomObject]@{
            CISRef      = $ref
            Description = $entry.Description
            Level       = $entry.Level
            Before      = 'N/A'
            After       = 'N/A'
            Status      = 'Fail'
            Messages    = @("Script file not found: $scriptPath")
        })
        continue
    }

    try {
        # Dot-source to load the function into this scope
        . $scriptPath

        # Invoke the function
        $funcName = $entry.Function
        $result   = if ($WhatIf) { & $funcName -WhatIf } else { & $funcName }

        foreach ($msg in $result.Messages) {
            Write-Log "  [CIS $ref] $msg"
        }
        Write-Log "CIS $ref Status: $($result.Status)"
        $Results.Add($result)

    } catch {
        $errMsg = "Exception running CIS $ref ($($entry.Function)): $_"
        Write-Log $errMsg -Level Error
        $Results.Add([PSCustomObject]@{
            CISRef      = $ref
            Description = $entry.Description
            Level       = $entry.Level
            Before      = 'N/A'
            After       = 'N/A'
            Status      = 'Fail'
            Messages    = @($errMsg)
        })
    }
}

# ---------------------------------------------------------------------------
# 10. Summary counts
# ---------------------------------------------------------------------------
$passCount    = @($Results | Where-Object { $_.Status -eq 'Pass'    }).Count
$failCount    = @($Results | Where-Object { $_.Status -eq 'Fail'    }).Count
$skippedCount = @($Results | Where-Object { $_.Status -in 'Skipped','WhatIf' }).Count
$totalCount   = $Results.Count

Write-Log "=== SUMMARY: Total=$totalCount  Pass=$passCount  Fail=$failCount  Skipped/WhatIf=$skippedCount ==="

# ---------------------------------------------------------------------------
# 11. HTML report helpers
# ---------------------------------------------------------------------------
function Get-StatusColor {
    param([string]$Status)
    switch ($Status) {
        'Pass'    { '#d4edda' }
        'Fail'    { '#f8d7da' }
        'Skipped' { '#fff3cd' }
        'WhatIf'  { '#cce5ff' }
        default   { '#f8f9fa' }
    }
}

function New-HtmlTableRow {
    param([PSCustomObject]$Result)
    $color  = Get-StatusColor $Result.Status
    $notes  = ($Result.Messages | ForEach-Object { [System.Net.WebUtility]::HtmlEncode($_) }) -join '<br/>'
    $before = [System.Net.WebUtility]::HtmlEncode($Result.Before)
    $after  = [System.Net.WebUtility]::HtmlEncode($Result.After)
    @"
    <tr style="background-color:$color">
      <td>$([System.Net.WebUtility]::HtmlEncode($Result.CISRef))</td>
      <td>$([System.Net.WebUtility]::HtmlEncode($Result.Level))</td>
      <td>$([System.Net.WebUtility]::HtmlEncode($Result.Description))</td>
      <td style="font-family:monospace;font-size:0.85em;word-break:break-all">$before</td>
      <td style="font-family:monospace;font-size:0.85em;word-break:break-all">$after</td>
      <td><strong>$([System.Net.WebUtility]::HtmlEncode($Result.Status))</strong></td>
      <td style="font-size:0.82em">$notes</td>
    </tr>
"@
}

function New-CISHtmlReport {
    param(
        [System.Collections.Generic.List[PSCustomObject]]$Results,
        [switch]$WhatIf,
        [string]$ServerName = $env:COMPUTERNAME,
        [string]$RunDate    = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),
        [int]$Total,
        [int]$Passed,
        [int]$Failed,
        [int]$Skipped
    )
    $modeLabel = if ($WhatIf) { 'WhatIf (Audit Only — no changes made)' } else { 'Live (Changes Applied)' }
    $rows      = ($Results | ForEach-Object { New-HtmlTableRow $_ }) -join "`n"

    @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CIS IIS Hardening Report</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    body   { font-family: Arial, sans-serif; margin: 2em; color: #333; background: #fafafa; }
    h1     { color: #2c3e50; margin-bottom: 0.2em; }
    .meta  { color: #555; margin-bottom: 1.5em; font-size: 0.95em; }
    .summary { display: flex; gap: 1em; margin-bottom: 2em; flex-wrap: wrap; }
    .card  { padding: 1em 2em; border-radius: 8px; text-align: center; min-width: 110px; box-shadow: 0 1px 3px rgba(0,0,0,.12); }
    .card-total   { background: #e9ecef; }
    .card-pass    { background: #d4edda; }
    .card-fail    { background: #f8d7da; }
    .card-skipped { background: #fff3cd; }
    .card h2 { margin: 0; font-size: 2.2em; }
    .card p  { margin: 0.2em 0 0; font-size: 0.85em; color: #555; }
    table  { width: 100%; border-collapse: collapse; font-size: 0.88em; background: #fff; }
    th     { background: #2c3e50; color: #fff; padding: 0.65em 0.5em; text-align: left; white-space: nowrap; }
    td     { padding: 0.45em 0.5em; border-bottom: 1px solid #dee2e6; vertical-align: top; }
    .reboot-warn {
      background: #fff3cd; border-left: 4px solid #ffc107;
      padding: 0.9em 1.2em; margin-top: 2em; border-radius: 4px;
    }
    footer { margin-top: 1.5em; color: #aaa; font-size: 0.78em; }
  </style>
</head>
<body>
  <h1>CIS IIS Hardening Report</h1>
  <div class="meta">
    <strong>Server:</strong> $([System.Net.WebUtility]::HtmlEncode($ServerName)) &nbsp;|&nbsp;
    <strong>Run Date:</strong> $([System.Net.WebUtility]::HtmlEncode($RunDate)) &nbsp;|&nbsp;
    <strong>Mode:</strong> $([System.Net.WebUtility]::HtmlEncode($modeLabel))
  </div>
  <div class="summary">
    <div class="card card-total">  <h2>$Total</h2>   <p>Total</p></div>
    <div class="card card-pass">   <h2>$Passed</h2>  <p>Passed</p></div>
    <div class="card card-fail">   <h2>$Failed</h2>  <p>Failed</p></div>
    <div class="card card-skipped"><h2>$Skipped</h2> <p>Skipped / WhatIf</p></div>
  </div>
  <table>
    <thead>
      <tr>
        <th>CIS Ref</th>
        <th>Level</th>
        <th>Description</th>
        <th>Before</th>
        <th>After</th>
        <th>Status</th>
        <th>Notes</th>
      </tr>
    </thead>
    <tbody>
$rows
    </tbody>
  </table>
  <div class="reboot-warn">
    <strong>&#9888; Reboot Required:</strong>
    SCHANNEL changes (7.2&ndash;7.12) require a full system reboot to take effect.
  </div>
  <footer>
    Generated by CIS IIS Hardening Orchestrator &mdash; $([System.Net.WebUtility]::HtmlEncode($RunDate))
  </footer>
</body>
</html>
"@
}

$htmlContent = New-CISHtmlReport `
    -Results  $Results `
    -WhatIf:$WhatIf `
    -Total    $totalCount `
    -Passed   $passCount `
    -Failed   $failCount `
    -Skipped  $skippedCount

$htmlContent | Out-File -FilePath $reportFile -Encoding UTF8
Write-Log "HTML report written: $reportFile"

# ---------------------------------------------------------------------------
# 12. Final summary output
# ---------------------------------------------------------------------------
Write-Log ''
Write-Log '========================================='
Write-Log '  CIS HARDENING RUN COMPLETE'
Write-Log '========================================='
Write-Log "  Report : $reportFile"
Write-Log "  Log    : $logFile"
if (-not $WhatIf) {
    Write-Log "  Backup : $backupDir"
    if ($IISInstalled) {
        Write-Log "  IIS named backup: %SystemRoot%\System32\inetsrv\backup\CIS_$ts"
        Write-Log "  To restore IIS  : & appcmd restore backup `"CIS_$ts`""
    }
}
Write-Log "  Pass=$passCount  Fail=$failCount  Skipped/WhatIf=$skippedCount  Total=$totalCount"
Write-Log ''
Write-Log '*** REMINDER: SCHANNEL changes (7.2-7.12) require a system reboot to take effect. ***' -Level Warning
