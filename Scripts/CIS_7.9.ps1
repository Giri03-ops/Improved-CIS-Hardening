# CIS 7.9 (L1) Ensure RC4 cipher suites are disabled (RC4 40/128, 56/128, 64/128, 128/128)
# Refactored: inlined registry reads (no Get-EnabledValue helper to avoid dot-source collisions)

function Invoke-CIS7_9 {
    [CmdletBinding()]
    param([switch]$WhatIf)

    $messages  = [System.Collections.Generic.List[string]]::new()
    $cisRef    = '7.9'
    $desc      = 'Ensure RC4 cipher suites are disabled'
    $level     = 'L1'
    $base      = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers"
    $rc4Names  = @('RC4 40/128', 'RC4 56/128', 'RC4 64/128', 'RC4 128/128')

    # Before (inlined — no shared helper)
    $beforeParts = [System.Collections.Generic.List[string]]::new()
    foreach ($name in $rc4Names) {
        $p  = Join-Path $base $name
        $en = $null
        if (Test-Path $p) {
            try { $en = (Get-ItemProperty -Path $p -Name Enabled -ErrorAction Stop).Enabled } catch {}
        }
        $beforeParts.Add("$name=Enabled:$( if ($null -eq $en) { 'not set' } else { $en } )")
    }
    $beforeState = $beforeParts -join '; '
    $messages.Add("Before: $beforeState")

    if ($WhatIf) {
        $messages.Add('[WhatIf] Would set all RC4 cipher variants Enabled=0.')
        return [PSCustomObject]@{
            CISRef      = $cisRef
            Description = $desc
            Level       = $level
            Before      = $beforeState
            After       = 'N/A (WhatIf)'
            Status      = 'WhatIf'
            Messages    = $messages.ToArray()
        }
    }

    # Apply
    foreach ($name in $rc4Names) {
        $p = Join-Path $base $name
        if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
        New-ItemProperty -Path $p -Name 'Enabled' -Value 0 -PropertyType DWord -Force | Out-Null
        $messages.Add("Applied: $name Enabled=0")
    }

    # Verify (inlined)
    $allGood    = $true
    $afterParts = [System.Collections.Generic.List[string]]::new()
    foreach ($name in $rc4Names) {
        $p  = Join-Path $base $name
        $en = $null
        if (Test-Path $p) {
            try { $en = (Get-ItemProperty -Path $p -Name Enabled -ErrorAction Stop).Enabled } catch {}
        }
        $afterParts.Add("$name=Enabled:$en")
        if ($en -ne 0) { $allGood = $false }
    }
    $afterState = $afterParts -join '; '
    $messages.Add("After: $afterState")
    $messages.Add('NOTE: A reboot is required for SCHANNEL changes to take effect.')

    $status = if ($allGood) { 'Pass' } else { 'Fail' }
    return [PSCustomObject]@{
        CISRef      = $cisRef
        Description = $desc
        Level       = $level
        Before      = $beforeState
        After       = $afterState
        Status      = $status
        Messages    = $messages.ToArray()
    }
}
