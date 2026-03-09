# CIS IIS Hardening

PowerShell scripts to audit and remediate CIS Benchmark controls for IIS and Windows SCHANNEL.
Covers controls 1.2–4.7 (IIS hardening) and 7.2–7.12 (SCHANNEL/TLS registry hardening).

---

## Prerequisites

| Requirement | Details |
|-------------|---------|
| OS | Windows Server 2016 / 2019 / 2022 |
| Shell | PowerShell 5.1+ (elevated — run as Administrator) |
| IIS controls (1.x–4.x) | IIS role installed, `WebAdministration` module available |
| SCHANNEL controls (7.x) | No additional prerequisites — registry access only |
| Do NOT run on | Personal/development PCs — target is Windows Server only |

---

## File Layout

```
CIS Hardening\
├── main.ps1                  Orchestrator — runs all controls in sequence
├── rollback.ps1              Rollback — restores from a backup created by main.ps1
├── README.md                 This file
├── IMPLEMENTATION.md         Detailed per-script change log and design notes
│
├── Scripts\                  Refactored individual control scripts
│   ├── CIS_1.2.ps1           Ensure host headers are configured
│   ├── CIS_1.6.ps1           Ensure application pool identity for anonymous auth
│   ├── CIS_2.3.ps1           Ensure Forms Auth requires SSL
│   ├── CIS_2.4.ps1           Ensure Forms Auth uses cookies
│   ├── CIS_3.7.ps1           Ensure HttpOnly cookies
│   ├── CIS_3.10.ps1          Ensure .NET trust level is Medium
│   ├── CIS_4.4.ps1           Block non-ASCII characters in URLs
│   ├── CIS_4.7.ps1           Disallow unlisted file extensions
│   ├── CIS_7.2.ps1           Disable SSL 2.0
│   ├── CIS_7.3.ps1           Disable SSL 3.0
│   ├── CIS_7.4.ps1           Disable TLS 1.0
│   ├── CIS_7.5.ps1           Disable TLS 1.1
│   ├── CIS_7.6.ps1           Enable TLS 1.2
│   ├── CIS_7.7.ps1           Disable NULL cipher
│   ├── CIS_7.8.ps1           Disable DES 56/56 cipher
│   ├── CIS_7.9.ps1           Disable RC4 cipher suites
│   ├── CIS_7.10.ps1          Disable AES 128/128 cipher
│   ├── CIS_7.11.ps1          Enable AES 256/256 cipher
│   └── CIS_7.12.ps1          Configure TLS cipher suite ordering
│
├── Backups\{timestamp}\      Created at runtime by main.ps1 (live run only)
│   ├── IIS_Config_Export.xml Human-readable IIS config snapshot
│   └── SCHANNEL_Registry.reg SCHANNEL registry export for rollback
│
└── Reports\{timestamp}\      Created at runtime by main.ps1
    ├── CIS_Report.html       Colour-coded before/after results table
    └── CIS_Run.log           Full timestamped log of the run
```

> The IIS named backup is also stored at:
> `%SystemRoot%\System32\inetsrv\backup\CIS_{timestamp}\`

---

## Running the Hardening

Open an **elevated PowerShell** on the target Windows Server and `cd` to this folder.

### 1. Audit only — no changes, no backups

```powershell
.\main.ps1 -WhatIf
```

All controls run in read-only mode. The HTML report shows every control as `WhatIf`.
Use this first to understand the current state before making any changes.

### 2. Skip specific controls (works for both `-WhatIf` and live runs)

Skip a single control:

```powershell
.\main.ps1 -WhatIf -SkipCIS '7.12'
```

Skip multiple controls (either format works):

```powershell
.\main.ps1 -WhatIf -SkipCIS '2.3','7.12'
.\main.ps1 -WhatIf -SkipCIS @('2.3', '7.12')
```

Skipped controls appear in the report as `Skipped`.
Accepts any combination of CIS reference numbers (e.g. `'1.2'`, `'7.6'`).
You do **not** need to provide a range — pass only the control IDs you want to skip.
Invalid CIS references in `-SkipCIS` are ignored with a warning in the log.

### 3. Live run — applies changes and creates backups

```powershell
.\main.ps1
```

Live run while skipping selected controls:

```powershell
.\main.ps1 -SkipCIS '1.2','7.10'
```

- Creates `Backups\{timestamp}\` with IIS config snapshot and SCHANNEL `.reg` file
- Creates an IIS named backup via `appcmd`
- Applies all control remediations
- Writes `Reports\{timestamp}\CIS_Report.html` and `CIS_Run.log`

---

## Rolling Back

> Only possible after a live run. `-WhatIf` runs do not create backups.

### List available backups

```powershell
.\rollback.ps1 -ListBackups
```

Output shows each backup timestamp and what it contains (IIS named backup, SCHANNEL reg).

### Preview what a rollback would do (no changes)

```powershell
.\rollback.ps1 -WhatIf
.\rollback.ps1 -Timestamp 20260306_120000 -WhatIf
```

### Restore from the most recent backup

```powershell
.\rollback.ps1
```

Prompts for confirmation before making any changes. Type `YES` to proceed.

### Restore a specific backup

```powershell
.\rollback.ps1 -Timestamp 20260306_120000
```

### Restore without the confirmation prompt

```powershell
.\rollback.ps1 -Force
.\rollback.ps1 -Timestamp 20260306_120000 -Force
```

### What rollback.ps1 restores

| Component | How it restores |
|-----------|----------------|
| IIS configuration | `appcmd restore backup "CIS_{timestamp}"` — full IIS config rollback |
| SCHANNEL registry | `reg import SCHANNEL_Registry.reg` — restores all protocol/cipher key values |

> **A system reboot is required after rollback** for SCHANNEL changes to take effect.

### Manual restore (if rollback.ps1 is unavailable)

```powershell
# IIS
& "$env:SystemRoot\System32\inetsrv\appcmd.exe" restore backup "CIS_20260306_120000"

# SCHANNEL registry
reg import "C:\path\to\CIS Hardening\Backups\20260306_120000\SCHANNEL_Registry.reg"
```

---

## CIS Controls Covered

### IIS Controls (require IIS role)

| Control | Level | Description | What it changes |
|---------|-------|-------------|-----------------|
| 1.2 | L1 | Ensure host headers are configured | Sets `bindingInformation` on bare `*:80:` HTTP bindings |
| 1.6 | L1 | Ensure application pool identity for anonymous auth | Sets `passAnonymousToken=True` on app pools serving anonymous content |
| 2.3 | L1 | Ensure Forms Auth requires SSL | Sets `requireSSL=True` — only on sites with an HTTPS binding |
| 2.4 | L2 | Ensure Forms Auth uses cookies | Sets `cookieless=UseCookies` |
| 3.7 | L1 | Ensure HttpOnly cookies | Sets `httpOnlyCookies=True` in global `system.web/httpCookies` |
| 3.10 | L1 | Ensure .NET trust level is Medium | Sets `system.web/trust level=Medium` at MACHINE/WEBROOT |
| 4.4 | L2 | Block non-ASCII characters in URLs | Sets `allowHighBitCharacters=False` in request filtering |
| 4.7 | L1 | Disallow unlisted file extensions | Sets `allowUnlisted=False` in request filtering |

> Controls 1.2–4.7 are automatically skipped if the IIS role is not installed.

### SCHANNEL Controls (registry — no IIS required)

| Control | Level | Description | Registry path |
|---------|-------|-------------|---------------|
| 7.2 | L1 | Disable SSL 2.0 | `Protocols\SSL 2.0\{Server,Client}` → Enabled=0, DisabledByDefault=1 |
| 7.3 | L1 | Disable SSL 3.0 | `Protocols\SSL 3.0\{Server,Client}` → Enabled=0, DisabledByDefault=1 |
| 7.4 | L1 | Disable TLS 1.0 | `Protocols\TLS 1.0\{Server,Client}` → Enabled=0, DisabledByDefault=1 |
| 7.5 | L1 | Disable TLS 1.1 | `Protocols\TLS 1.1\{Server,Client}` → Enabled=0, DisabledByDefault=1 |
| 7.6 | L1 | Enable TLS 1.2 | `Protocols\TLS 1.2\{Server,Client}` → Enabled=1, DisabledByDefault=0 |
| 7.7 | L1 | Disable NULL cipher | `Ciphers\NULL` → Enabled=0 |
| 7.8 | L1 | Disable DES 56/56 | `Ciphers\DES 56/56` → Enabled=0 |
| 7.9 | L1 | Disable RC4 suites | `Ciphers\RC4 {40,56,64,128}/128` → Enabled=0 |
| 7.10 | L1 | Disable AES 128/128 | `Ciphers\AES 128/128` → Enabled=0 |
| 7.11 | L1 | Enable AES 256/256 | `Ciphers\AES 256/256` → Enabled=1 |
| 7.12 | L2 | Configure cipher suite ordering | `SOFTWARE\Policies\Microsoft\Cryptography\...\Functions` (REG_MULTI_SZ) |

All SCHANNEL paths are under:
`HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\`

> **All SCHANNEL changes (7.2–7.12) require a full system reboot to take effect.**

---

## HTML Report

After every run a colour-coded report is written to `Reports\{timestamp}\CIS_Report.html`.

| Colour | Status | Meaning |
|--------|--------|---------|
| Green | Pass | Already compliant, or change applied and verified |
| Red | Fail | Change failed or post-check did not match expected value |
| Yellow | Skipped | Not applicable (no sites, no HTTPS binding, IIS absent) |
| Blue | WhatIf | Dry-run — state was read but nothing was written |

Open the file in any browser — no server required.

---

## Important Notes

- **Always run `-WhatIf` first** on a new server to review the current state before applying changes.
- **Backup is automatic** during a live run — never skip it by modifying the script.
- **CIS 2.3 only applies when an HTTPS binding exists** on the IIS site. If HTTPS is terminated upstream (load balancer, WAF), this control is deliberately skipped to avoid breaking Forms Authentication.
- **CIS 1.2** requires a host header to be already present on an HTTPS or HTTP binding to auto-detect the FQDN. If the server has a bare `*:80:` binding with no other hostname configured, the control shows `Skipped` — set the host header manually first.
- **CIS 3.10** sets the global .NET trust level to `Medium`. If any application requires `Full` trust, test this control in a staging environment first.
- **CIS 4.7** blocks all file extensions not explicitly allowed. Verify your allowed-extension list in IIS Manager before running a live run in production.
- **SCHANNEL changes are server-wide** — they affect all TLS-using services on the machine, not just IIS (SQL Server, RDP, etc.). Test in a non-production environment first.
