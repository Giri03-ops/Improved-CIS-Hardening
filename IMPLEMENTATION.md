# CIS IIS Hardening — Implementation Documentation

## Overview

18 original PowerShell scripts were refactored and a new orchestrator (`main.ps1`) was created.
The originals in the root folder are **untouched**. All refactored scripts live in `Scripts\`.

---

## Repository Layout

```
CIS Hardening\
├── main.ps1                       NEW — orchestrator entry point
├── IMPLEMENTATION.md              this file
├── Scripts\
│   ├── CIS_1.2.ps1
│   ├── CIS_1.6.ps1
│   ├── CIS_2.3.ps1
│   ├── CIS_2.4.ps1
│   ├── CIS_3.7.ps1
│   ├── CIS_3.10.ps1
│   ├── CIS_4.4.ps1
│   ├── CIS_4.7.ps1
│   ├── CIS_7.2.ps1  …  CIS_7.12.ps1
├── Backups\{timestamp}\           CREATED AT RUNTIME
│   ├── IIS_Config_Export.xml
│   └── SCHANNEL_Registry.reg
└── Reports\{timestamp}\           CREATED AT RUNTIME
    ├── CIS_Report.html
    └── CIS_Run.log
```

> The IIS named backup is also stored at:
> `%SystemRoot%\System32\inetsrv\backup\CIS_{timestamp}\`
> Restore with: `& appcmd restore backup "CIS_{timestamp}"`

---

## How to Run

```powershell
# Audit only — no changes, no backups, all results show 'WhatIf'
.\main.ps1 -WhatIf

# Skip specific controls
.\main.ps1 -WhatIf -SkipCIS @('2.3', '7.12')

# Live run — applies changes, creates backups, generates report
.\main.ps1
```

Must be run from an **elevated PowerShell** on **Windows Server**.

---

## Universal Script Contract

Every script in `Scripts\` follows the same contract:

- Contains **exactly one** exported function named `Invoke-CIS{X}_{Y}` (e.g. `Invoke-CIS1_2`)
- Accepts `[switch]$WhatIf`
- Uses `$messages.Add(...)` — no `Write-Host`
- Returns a single `[PSCustomObject]`:

```powershell
[PSCustomObject]@{
    CISRef      = '1.2'
    Description = 'Human-readable description'
    Level       = 'L1'           # or 'L2'
    Before      = 'State before change'
    After       = 'State after change, or "N/A (WhatIf)"'
    Status      = 'Pass'         # Pass | Fail | Skipped | WhatIf
    Messages    = $messages.ToArray()
}
```

**Status semantics:**

| Status  | Meaning |
|---------|---------|
| `Pass`  | Already compliant, or change applied and verified |
| `Fail`  | Change failed or post-check mismatch |
| `Skipped` | Not applicable (no sites, no HTTPS binding, IIS absent) |
| `WhatIf` | Dry-run — state read and reported, nothing written |

---

## Critical Bugs Fixed

| # | Bug | Original Location | Fix Applied |
|---|-----|-------------------|-------------|
| 1 | `exit 0` on early-compliance path kills the entire orchestrator process | `CIS_7.12.ps1` line 61 | Replaced with `return [PSCustomObject]@{ ... Status='Pass' ... }` |
| 2 | `$ForceRequireSslEvenWithoutIisHttps = $true` forces `requireSSL` even when no HTTPS binding exists, silently breaking Forms Auth | `CIS_2.3.ps1` line 4 | Removed. Sites without an IIS HTTPS binding now receive `Status='Skipped'` with an explanatory message |
| 3 | `function Get-ProtoState` defined locally in five scripts — collides at dot-source time when all scripts are loaded into one session | `CIS_7.2–7.6.ps1` | Removed helper function; 2-line read logic inlined directly in Before and After loops |
| 4 | `function Get-EnabledValue` defined locally | `CIS_7.9.ps1` | Removed; inlined |
| 5 | `function Get-MultiString` defined locally | `CIS_7.12.ps1` | Removed; inlined |
| 6 | Redundant `appcmd.exe` text-parsing block (lines 9–55) did the same site/binding discovery as the `Get-WebConfiguration` block below it | `CIS_1.2.ps1` | Removed appcmd block entirely; `Get-Website` and `Get-WebBinding` used throughout |
| 7 | Bare `return` statements at script scope became no-ops once logic was moved inside a function | `CIS_1.2.ps1` | Each `return` is now `return [PSCustomObject]@{ ... }` inside the function body |
| 8 | No backup taken before any changes | All scripts | Centralized backup phase in `main.ps1` runs once before the orchestration loop |

---

## Per-Script Change Log

### CIS_1.2.ps1 — HIGH CHANGE
**Original:** `1.2_AuditSetting_Script.ps1`

Changes:
- **Removed** entire `appcmd.exe` text-parsing block (original lines 9–55). It parsed site names from `appcmd list sites` output with regex. The IIS PS module block below it already did the same work more reliably.
- **Replaced** with `Get-Website` + `Get-WebBinding` for site and binding discovery.
- **Wrapped** remaining `Get-WebConfiguration` / `Set-WebConfigurationProperty` logic in `function Invoke-CIS1_2`.
- **Fixed** bare `return` statements (were at script scope; now `return [PSCustomObject]@{...}` inside the function).
- **WhatIf:** reads and reports binding state, skips `Set-WebConfigurationProperty`.
- **Before state:** all current bindings joined as `protocol bindingInformation; ...`
- **After state:** all bindings after update.
- **Skipped** conditions: no sites, no HTTP/HTTPS sites, multiple HTTP/HTTPS sites (unsafe to auto-select), host header cannot be auto-detected, no bare `*:80:` binding found.

---

### CIS_1.6.ps1 — WRAP ONLY
**Original:** `1.6 (L1) Ensure 'application pool identity'...copy.ps1`

Changes:
- Wrapped all logic in `function Invoke-CIS1_6`.
- Replaced `Write-Host` calls with `$messages.Add(...)`.
- `$anonLocations` captured as `Before` state.
- Post-check reads `passAnonymousToken` back for each pool and builds `After` state.
- Returns `Status='Skipped'` when no Anonymous Auth entries found, or when no app pools resolve.

---

### CIS_2.3.ps1 — CRITICAL FIX + WRAP
**Original:** `2.3 (L1) Ensure 'forms authentication' require SSL copy.ps1`

Changes:
- **Removed** `$ForceRequireSslEvenWithoutIisHttps = $true` (line 4 of original). This flag would force `requireSSL=True` even when the site has no HTTPS binding in IIS, which breaks Forms Auth on sites where HTTPS is terminated at an upstream load balancer.
- **New behaviour:** if a site has no HTTPS binding, `requireSSL` is left unchanged and the site receives a `Skipped(noHTTPS)` entry in the After column with an explanatory message.
- Wrapped in `function Invoke-CIS2_3`.
- `Before` state: per-site `requireSSL` values joined with `;`.
- `After` state: per-site results (compliant / updated / skipped).
- Returns `Status='Skipped'` when Forms Auth is not configured on any site.

---

### CIS_2.4.ps1 — WRAP ONLY
**Original:** `2.4 (L2) Ensure Forms Authentication uses cookies copy.ps1`

Changes:
- Wrapped in `function Invoke-CIS2_4`.
- Replaced `Write-Host` with `$messages.Add(...)`.
- Per-site `cookieless` values captured as `Before`; post-check values as `After`.
- Returns `Status='Skipped'` when Forms Auth not configured on any site.

---

### CIS_3.7.ps1 — WRAP ONLY
**Original:** `3.7 (L1) Ensure cookies are set with HttpOnly...copy.ps1`

Changes:
- Wrapped in `function Invoke-CIS3_7`.
- `Before`: `httpOnlyCookies=<value>` read via `Get-WebConfigurationProperty`.
- `After`: value re-read after `Set-WebConfigurationProperty`.
- Short-circuits with `Status='Pass'` when already `True`.

---

### CIS_3.10.ps1 — WRAP ONLY
**Original:** `3.10 (L1) Global .NET trust level copy.ps1`

Changes:
- Wrapped in `function Invoke-CIS3_10`.
- `Before`: current trust level string. `After`: post-set value.
- Short-circuits with `Status='Pass'` when already `Medium`.

---

### CIS_4.4.ps1 — WRAP ONLY
**Original:** `4.4 (L2) Block non-ASCII characters in URLs copy.ps1`

Changes:
- Wrapped in `function Invoke-CIS4_4`.
- `Before`: `allowHighBitCharacters=<value>`. `After`: value after set.
- Short-circuits when already `False`.

---

### CIS_4.7.ps1 — WRAP ONLY
**Original:** `4.7 (L1) Ensure Unlisted File Extensions are not allowed copy.ps1`

Changes:
- Wrapped in `function Invoke-CIS4_7`.
- `Before`: `allowUnlisted=<value>`. `After`: value after set.
- Short-circuits when already `False`.

---

### CIS_7.2.ps1 — WRAP + COLLISION FIX
**Original:** `7.2 (L1) Ensure SSLv2 is Disabled copy.ps1`

Changes:
- **Removed** `function Get-ProtoState` definition.
- Inlined the 2-line registry read (`Get-ItemProperty Enabled` + `Get-ItemProperty DisabledByDefault`) directly inside both the Before loop and the After/verify loop.
- Wrapped in `function Invoke-CIS7_2`.
- Target values: `Enabled=0, DisabledByDefault=1` for both Server and Client sub-keys.
- `Before`: `"Server: Enabled=X DisabledByDefault=Y; Client: Enabled=X DisabledByDefault=Y"` (shows `not set` if key absent).
- `After`: same format after write.
- Adds reboot-required note to `Messages`.

---

### CIS_7.3.ps1 — WRAP + COLLISION FIX
**Original:** `7.3 (L1) Ensure SSLv3 is Disabled copy.ps1`

Same changes as CIS_7.2.ps1 — protocol name changed to `SSL 3.0`.

---

### CIS_7.4.ps1 — WRAP + COLLISION FIX
**Original:** `7.4 (L1) Disable TLS 1.0 (Server + Client) copy.ps1`

Same changes as CIS_7.2.ps1 — protocol name changed to `TLS 1.0`.

---

### CIS_7.5.ps1 — WRAP + COLLISION FIX
**Original:** `7.5 (L1) Ensure TLS 1.1 is Disabled (Automated) copy 2.ps1`

Same changes as CIS_7.2.ps1 — protocol name changed to `TLS 1.1`.

---

### CIS_7.6.ps1 — WRAP + COLLISION FIX
**Original:** `7.6 (L1) Ensure TLS 1.2 is Enabled (Server + Client) copy.ps1`

Same structural changes as CIS_7.2–7.5.ps1.
**Difference:** target values are `Enabled=1, DisabledByDefault=0` (enable, not disable).

---

### CIS_7.7.ps1 — WRAP ONLY
**Original:** `7.7 (L1) Ensure NULL Cipher Suites is Disabled (Automated) copy.ps1`

Changes:
- Wrapped in `function Invoke-CIS7_7`. Single registry key (`SCHANNEL\Ciphers\NULL`).
- `Before`: `Enabled=<value or 'not set'>`. `After`: `Enabled=0`.
- Adds reboot-required note.

---

### CIS_7.8.ps1 — WRAP ONLY
**Original:** `7.8 (L1) Ensure DES Cipher Suites is Disabled copy.ps1`

Same pattern as CIS_7.7.ps1 — registry key changed to `SCHANNEL\Ciphers\DES 56/56`.

---

### CIS_7.9.ps1 — WRAP + COLLISION FIX
**Original:** `7.9 (L1) Ensure RC4 Cipher Suites is Disabled copy 2.ps1`

Changes:
- **Removed** `function Get-EnabledValue` definition.
- Inlined the read logic directly inside the Before and After loops.
- Wrapped in `function Invoke-CIS7_9`. Iterates 4 RC4 sub-keys: `RC4 40/128`, `RC4 56/128`, `RC4 64/128`, `RC4 128/128`.
- `Before`: all four as `"RC4 40/128=Enabled:X; RC4 56/128=Enabled:X; ..."`.
- `After`: same format after setting all to `Enabled=0`.

---

### CIS_7.10.ps1 — WRAP ONLY
**Original:** `7.10 (L1) Ensure AES 128 Cipher Suite is Disabled copy (1).ps1`

Same pattern as CIS_7.7.ps1 — registry key `SCHANNEL\Ciphers\AES 128/128`, target `Enabled=0`.

---

### CIS_7.11.ps1 — WRAP ONLY
**Original:** `7.11 (L1) Ensure AES 256 Cipher Suite is Enabled copy.ps1`

Same pattern as CIS_7.7.ps1 — registry key `SCHANNEL\Ciphers\AES 256/256`, target `Enabled=1`.

---

### CIS_7.12.ps1 — HIGH CHANGE
**Original:** `7.12 (L2) Ensure TLS Cipher Suite ordering is Configured.ps1`

Changes:
- **Removed** `function Get-MultiString` definition. Inlined the `Get-ItemProperty` read logic for `REG_MULTI_SZ` values in both the Before read and the After/verify read.
- **Removed** `$env:TEMP` backup lines (original lines 45–49). Backup is now handled centrally in `main.ps1`.
- **Fixed `exit 0`** (original line 61): when cipher order was already compliant, the script called `exit 0`. This terminated the entire `main.ps1` process. Replaced with `return [PSCustomObject]@{ ... Status='Pass' ... }`.
- Wrapped in `function Invoke-CIS7_12`.
- `Before`: current cipher list joined with `; `, or `"Not configured (OS default)"`.
- `After`: desired cipher list joined with `; `, or `"N/A (WhatIf)"`.
- Adds reboot-required note to `Messages`.

---

## main.ps1 — New File

Orchestrates all 19 controls in order. Structure:

| Step | What it does |
|------|-------------|
| 1 | Admin check via `[WindowsPrincipal]` — exits with message if not elevated |
| 2 | Sets `$ts = Get-Date -Format 'yyyyMMdd_HHmmss'` — used everywhere |
| 3 | Creates `Backups\{ts}\` and `Reports\{ts}\` via `New-Item -Force` |
| 4 | Defines `Write-Log` — writes timestamped lines to console and `CIS_Run.log` simultaneously |
| 5 | Detects IIS via `Get-Service W3SVC` |
| 6 | Imports `WebAdministration` module if IIS present; sets `$IISInstalled=$false` on failure |
| 7 | Backup phase (skipped in `-WhatIf`): creates IIS/SCHANNEL backups, validates artifacts, and aborts remediation if any backup is missing/empty or backup creation fails |
| 8 | Defines `$manifest` — ordered hashtable mapping each CIS ref to file, function, RequiresIIS flag |
| 9 | Orchestration loop: skip checks → dot-source script → call function → log messages → collect result. Each control wrapped in `try/catch` so one failure never stops the rest |
| 10 | Computes Pass/Fail/Skipped counts |
| 11 | Generates HTML report via `New-CISHtmlReport` (pure here-string, inline CSS, all data HTML-encoded) |
| 12 | Prints paths for report, log, and backups; prints SCHANNEL reboot warning |

### `-SkipCIS` parameter

```powershell
.\main.ps1 -SkipCIS @('2.3', '7.12')
```

Skipped controls appear in the HTML report with `Status='Skipped'` and the message
`"Skipped by user request (-SkipCIS '2.3')"`.

### IIS-absent behaviour

When `W3SVC` is not running (or `WebAdministration` fails to import), all controls with
`RequiresIIS=$true` (1.2, 1.6, 2.3, 2.4, 3.7, 3.10, 4.4, 4.7) are automatically skipped
with `Status='Skipped'` and the message `"Skipped: IIS (W3SVC) not installed on this system."`.
SCHANNEL controls (7.2–7.12) run regardless.

---

## HTML Report

- Header: server name, run date, WhatIf/Live label
- Summary cards: Total / Passed / Failed / Skipped+WhatIf
- Detail table: CIS Ref | Level | Description | Before | After | Status | Notes
- Row background colour: green (Pass) / red (Fail) / yellow (Skipped) / blue (WhatIf)
- Footer reboot warning for SCHANNEL controls
- All user-sourced data (Before, After, Messages) encoded via `[System.Net.WebUtility]::HtmlEncode()` — no XSS risk
- No external modules, no PSWriteHTML, no Excel — pure PowerShell here-string

---

## Restore Procedure (after a live run)

```powershell
# Restore IIS configuration
$ts = '20260306_120000'   # replace with actual timestamp from run
& "$env:SystemRoot\System32\inetsrv\appcmd.exe" restore backup "CIS_$ts"

# Restore SCHANNEL registry
reg import "C:\path\to\CIS Hardening\Backups\$ts\SCHANNEL_Registry.reg"
```

A **system reboot** is required after restoring SCHANNEL registry keys.
