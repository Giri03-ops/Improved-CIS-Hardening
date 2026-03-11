# =============================================================================
# CIS IIS Hardening — rollback.ps1
# Restores IIS configuration and SCHANNEL registry from a backup created by
# main.ps1. Backups are only created during a live run (not -WhatIf).
#
# Usage:
#   .\rollback.ps1 -ListBackups              # Show all available backups
#   .\rollback.ps1                           # Restore from the most recent backup
#   .\rollback.ps1 -Timestamp 20260306_120000  # Restore a specific backup
#   .\rollback.ps1 -WhatIf                   # Show what would be restored (no changes)
#   .\rollback.ps1 -Force                    # Skip confirmation prompt
# =============================================================================
param(
    [string]$Timestamp   = '',
    [switch]$ListBackups,
    [switch]$WhatIf,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Admin check
# ---------------------------------------------------------------------------
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'ERROR: rollback.ps1 must be run as Administrator.' -ForegroundColor Red
    exit 1
}

$scriptRoot  = $PSScriptRoot
$backupsRoot = Join-Path $scriptRoot 'Backups'
$appcmd      = "$env:SystemRoot\System32\inetsrv\appcmd.exe"

# ---------------------------------------------------------------------------
# Helper: coloured output
# ---------------------------------------------------------------------------
function Write-Info    { param([string]$m) Write-Host "[INFO]  $m" -ForegroundColor Cyan    }
function Write-OK      { param([string]$m) Write-Host "[ OK ]  $m" -ForegroundColor Green   }
function Write-Warn    { param([string]$m) Write-Host "[WARN]  $m" -ForegroundColor Yellow  }
function Write-Err     { param([string]$m) Write-Host "[ERR ]  $m" -ForegroundColor Red     }
function Write-Step    { param([string]$m) Write-Host "`n==> $m" -ForegroundColor White     }

# ---------------------------------------------------------------------------
# Discover available backups
# ---------------------------------------------------------------------------
if (-not (Test-Path $backupsRoot)) {
    Write-Err "Backups folder not found: $backupsRoot"
    Write-Err 'No backups available. Run main.ps1 (without -WhatIf) to create one.'
    exit 1
}

$backupFolders = @(
    Get-ChildItem -Path $backupsRoot -Directory |
    Where-Object { $_.Name -match '^\d{8}_\d{6}$' } |
    Sort-Object Name -Descending   # newest first (yyyyMMdd_HHmmss sorts correctly)
)

# ---------------------------------------------------------------------------
# -ListBackups: display all available backups and exit
# ---------------------------------------------------------------------------
if ($ListBackups) {
    if ($backupFolders.Count -eq 0) {
        Write-Warn 'No backups found in Backups\ folder.'
        exit 0
    }

    Write-Host "`nAvailable backups ($($backupFolders.Count) found):`n"
    foreach ($folder in $backupFolders) {
        $ts       = $folder.Name
        $regFile  = Join-Path $folder.FullName 'SCHANNEL_Registry.reg'
        $xmlFile  = Join-Path $folder.FullName 'IIS_Config_Export.xml'
        $iisNamed = Join-Path "$env:SystemRoot\System32\inetsrv\backup" "CIS_$ts"

        $parts = @()
        if (Test-Path $regFile)  { $parts += 'SCHANNEL.reg' }
        if (Test-Path $xmlFile)  { $parts += 'IIS snapshot' }
        if (Test-Path $iisNamed) { $parts += 'IIS named backup' }

        $label = if ($folder -eq $backupFolders[0]) { ' <-- most recent' } else { '' }
        Write-Host ("  {0}{1}" -f $ts, $label) -ForegroundColor White
        Write-Host ("        Contains: {0}" -f ($parts -join ', ')) -ForegroundColor Gray
    }
    Write-Host ''
    Write-Host 'To restore: .\rollback.ps1 -Timestamp <timestamp>' -ForegroundColor Cyan
    exit 0
}

# ---------------------------------------------------------------------------
# Resolve timestamp to use
# ---------------------------------------------------------------------------
if ($Timestamp -eq '') {
    if ($backupFolders.Count -eq 0) {
        Write-Err 'No backups found. Run main.ps1 (without -WhatIf) first.'
        exit 1
    }
    $Timestamp = $backupFolders[0].Name
    Write-Info "No -Timestamp specified - using most recent: $Timestamp"
}

$backupDir = Join-Path $backupsRoot $Timestamp

if (-not (Test-Path $backupDir)) {
    Write-Err "Backup folder not found: $backupDir"
    Write-Err "Run '.\rollback.ps1 -ListBackups' to see available backups."
    exit 1
}

# ---------------------------------------------------------------------------
# Inventory what this backup contains
# ---------------------------------------------------------------------------
$regFile    = Join-Path $backupDir 'SCHANNEL_Registry.reg'
$iisNamed   = Join-Path "$env:SystemRoot\System32\inetsrv\backup" "CIS_$Timestamp"
$hasReg     = Test-Path $regFile
$hasIIS     = (Test-Path $appcmd) -and (Test-Path $iisNamed)
$iisService = Get-Service W3SVC -ErrorAction SilentlyContinue
$iisRunning = $null -ne $iisService

# ---------------------------------------------------------------------------
# Show restore plan
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '======================================================' -ForegroundColor White
Write-Host '  CIS IIS Hardening — Rollback Plan' -ForegroundColor White
Write-Host '======================================================' -ForegroundColor White
Write-Host "  Timestamp : $Timestamp"
Write-Host "  Backup dir: $backupDir"
Write-Host ''

if ($hasIIS) {
    Write-Host "  [1] IIS config    : WILL restore named backup 'CIS_$Timestamp'" -ForegroundColor Green
    Write-Host "       appcmd restore backup `"CIS_$Timestamp`""
} else {
    if (-not $iisRunning) {
        Write-Host '  [1] IIS config    : SKIP — IIS (W3SVC) not installed' -ForegroundColor Yellow
    } elseif (-not (Test-Path $iisNamed)) {
        Write-Host "  [1] IIS config    : SKIP - IIS named backup 'CIS_$Timestamp' not found in inetsrv\backup\" -ForegroundColor Yellow
        Write-Host "        (This backup was likely created when IIS was not installed, or was a -WhatIf run)"
    } else {
        Write-Host "  [1] IIS config    : SKIP - appcmd.exe not found" -ForegroundColor Yellow
    }
}

if ($hasReg) {
    Write-Host "  [2] SCHANNEL reg  : WILL import $regFile" -ForegroundColor Green
    Write-Host '        reg import "..."'
} else {
    Write-Host "  [2] SCHANNEL reg  : SKIP - SCHANNEL_Registry.reg not found in backup folder" -ForegroundColor Yellow
}

Write-Host ''
Write-Host '  NOTE: SCHANNEL changes require a reboot to take effect.' -ForegroundColor Yellow
Write-Host '======================================================' -ForegroundColor White
Write-Host ''

if (-not $hasIIS -and -not $hasReg) {
    Write-Err "Nothing to restore - backup contains neither an IIS named backup nor a SCHANNEL .reg file."
    exit 1
}

# ---------------------------------------------------------------------------
# WhatIf exit point
# ---------------------------------------------------------------------------
if ($WhatIf) {
    Write-Warn 'WhatIf mode: no changes made.'
    exit 0
}

# ---------------------------------------------------------------------------
# Confirmation prompt (unless -Force)
# ---------------------------------------------------------------------------
if (-not $Force) {
    Write-Host 'This will overwrite the current IIS configuration and/or SCHANNEL registry.' -ForegroundColor Yellow
    $answer = Read-Host 'Type YES to continue, anything else to abort'
    if ($answer -ne 'YES') {
        Write-Warn 'Rollback aborted by user.'
        exit 0
    }
}

$anyError = $false

# ---------------------------------------------------------------------------
# Step 1: Restore IIS named backup
# ---------------------------------------------------------------------------
if ($hasIIS) {
    Write-Step "Restoring IIS configuration from named backup 'CIS_$Timestamp'..."
    try {
        $output = & $appcmd restore backup "CIS_$Timestamp" 2>&1
        $output | ForEach-Object { Write-Info "  [appcmd] $_" }
        Write-OK "IIS configuration restored successfully."
    } catch {
        Write-Err "IIS restore failed: $_"
        $anyError = $true
    }
} else {
    Write-Warn 'IIS restore step skipped (see plan above).'
}

# ---------------------------------------------------------------------------
# Step 2: Restore SCHANNEL registry
# ---------------------------------------------------------------------------
if ($hasReg) {
    Write-Step "Restoring SCHANNEL registry from $regFile ..."
    try {
        $output = & reg @('import', $regFile) 2>&1
        $output | ForEach-Object { Write-Info "  [reg] $_" }
        Write-OK 'SCHANNEL registry restored successfully.'
    } catch {
        Write-Err "SCHANNEL registry restore failed: $_"
        $anyError = $true
    }
} else {
    Write-Warn 'SCHANNEL restore step skipped (see plan above).'
}

# ---------------------------------------------------------------------------
# Final output
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '======================================================' -ForegroundColor White
if ($anyError) {
    Write-Host '  Rollback completed WITH ERRORS (see above).' -ForegroundColor Red
} else {
    Write-Host '  Rollback completed successfully.' -ForegroundColor Green
}
Write-Host '======================================================' -ForegroundColor White
Write-Host ''
Write-Host "*** A system REBOOT is required for SCHANNEL changes to take effect. ***" -ForegroundColor Yellow
Write-Host ''
