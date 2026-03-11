# CIS 7.12 (L2) Ensure TLS cipher suite ordering is configured
# Refactored:
#   - FIXED: replaced `exit 0` with `return [PSCustomObject]@{...}` (exit would kill the orchestrator)
#   - Removed local $env:TEMP backup (centralized in main.ps1)
#   - Inlined Get-MultiString (no shared helper to avoid dot-source collisions)

function Invoke-CIS7_12 {
    [CmdletBinding()]
    param([switch]$WhatIf)

    $messages = [System.Collections.Generic.List[string]]::new()
    $cisRef   = '7.12'
    $desc     = 'Ensure TLS cipher suite ordering is configured'
    $level    = 'L2'
    $path     = 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002'
    $name     = 'Functions'

    $desired = @(
        'TLS_AES_256_GCM_SHA384',
        'TLS_AES_128_GCM_SHA256',
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
        'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
        'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256'
    )

    # Read current value (inlined - no Get-MultiString helper)
    $current = $null
    if (Test-Path $path) {
        try {
            $v = (Get-ItemProperty -Path $path -Name $name -ErrorAction Stop).$name
            $current = if ($v -is [string[]]) { $v } else { ($v -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' } }
        } catch {}
    }

    $beforeState = if ($null -eq $current) { 'Not configured (OS default)' } else { $current -join '; ' }
    $messages.Add("Before: cipher suite order - $beforeState")

    # Check compliance
    $alreadyCompliant = ($null -ne $current) -and (($current -join '|') -eq ($desired -join '|'))

    if ($alreadyCompliant) {
        $messages.Add('Already compliant. Cipher suite order matches desired configuration.')
        # FIXED: was `exit 0` which terminates the entire orchestrator process
        return [PSCustomObject]@{
            CISRef      = $cisRef
            Description = $desc
            Level       = $level
            Before      = $beforeState
            After       = $desired -join '; '
            Status      = 'Pass'
            Messages    = $messages.ToArray()
        }
    }

    if ($WhatIf) {
        $messages.Add("[WhatIf] Would write desired cipher suite order ($($desired.Count) suites).")
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

    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
    $desiredString = $desired -join ','
    New-ItemProperty -Path $path -Name $name -Value $desiredString -PropertyType String -Force | Out-Null
    $messages.Add("Applied: cipher suite order written ($($desired.Count) suites).")

    # Verify (inlined)
    $after = $null
    if (Test-Path $path) {
        try {
            $v = (Get-ItemProperty -Path $path -Name $name -ErrorAction Stop).$name
            $after = if ($v -is [string[]]) { $v } else { ($v -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' } }
        } catch {}
    }
    $afterState = if ($null -eq $after) { 'Not set (verify error)' } else { $after -join '; ' }
    $messages.Add("After: $afterState")
    $messages.Add('NOTE: A reboot (or policy refresh) is required for cipher suite ordering changes to take effect.')

    $status = if ($null -ne $after -and ($after -join '|') -eq ($desired -join '|')) { 'Pass' } else { 'Fail' }
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
