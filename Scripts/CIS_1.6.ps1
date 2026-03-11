# CIS 1.6 (L1) Ensure 'application pool identity' is configured for anonymous user identity
# Fixed: check passAnonymousToken on app pools (not anonymousAuthentication.userName)

function Invoke-CIS1_6 {
    [CmdletBinding()]
    param([switch]$WhatIf)

    $messages = [System.Collections.Generic.List[string]]::new()
    $cisRef   = '1.6'
    $desc     = "Ensure 'application pool identity' is configured for anonymous user identity"
    $level    = 'L1'

    $pools = Get-ChildItem IIS:\AppPools -ErrorAction SilentlyContinue
    if (-not $pools) {
        $messages.Add('No application pools found.')
        return [PSCustomObject]@{
            CISRef      = $cisRef
            Description = $desc
            Level       = $level
            Before      = 'No app pools'
            After       = 'N/A'
            Status      = 'Skipped'
            Messages    = $messages.ToArray()
        }
    }

    $beforeParts  = [System.Collections.Generic.List[string]]::new()
    $afterParts   = [System.Collections.Generic.List[string]]::new()
    $nonCompliant = [System.Collections.Generic.List[string]]::new()

    foreach ($pool in $pools) {
        $poolName = $pool.Name
        $raw = Get-ItemProperty -Path "IIS:\AppPools\$poolName" -Name passAnonymousToken -ErrorAction SilentlyContinue
        try {
            $val = [System.Convert]::ToBoolean($raw)
        } catch {
            $val = $false
        }
        $beforeParts.Add("$poolName=passAnonymousToken:$val")
        if (-not $val) {
            $nonCompliant.Add($poolName)
        }
    }

    $messages.Add("App pools checked: $($pools.Count)")

    # If all pools are already compliant, return Pass (before WhatIf check)
    if ($nonCompliant.Count -eq 0) {
        $messages.Add('All application pools already have passAnonymousToken=True.')
        return [PSCustomObject]@{
            CISRef      = $cisRef
            Description = $desc
            Level       = $level
            Before      = $beforeParts -join '; '
            After       = $beforeParts -join '; '
            Status      = 'Pass'
            Messages    = $messages.ToArray()
        }
    }

    if ($WhatIf) {
        $messages.Add("[WhatIf] Would set passAnonymousToken=True for: $($nonCompliant -join ', ')")
        return [PSCustomObject]@{
            CISRef      = $cisRef
            Description = $desc
            Level       = $level
            Before      = $beforeParts -join '; '
            After       = 'N/A (WhatIf)'
            Status      = 'WhatIf'
            Messages    = $messages.ToArray()
        }
    }

    # Remediate non-compliant pools
    $setFailures = [System.Collections.Generic.List[string]]::new()
    foreach ($poolName in $nonCompliant) {
        try {
            Set-ItemProperty -Path "IIS:\AppPools\$poolName" -Name passAnonymousToken -Value $true -ErrorAction Stop
            $messages.Add("Set passAnonymousToken=True for: $poolName")
        } catch {
            $setFailures.Add($poolName)
            $messages.Add("Failed setting passAnonymousToken for '$poolName'. Error: $($_.Exception.Message)")
        }
    }

    # Post-check: re-read all pools
    $allGood = $true
    foreach ($pool in $pools) {
        $poolName = $pool.Name
        $raw = Get-ItemProperty -Path "IIS:\AppPools\$poolName" -Name passAnonymousToken -ErrorAction SilentlyContinue
        try {
            $val = [System.Convert]::ToBoolean($raw)
        } catch {
            $val = $false
        }
        $afterParts.Add("$poolName=passAnonymousToken:$val")
        if (-not $val) {
            $allGood = $false
        }
    }

    if ($setFailures.Count -gt 0) { $allGood = $false }

    return [PSCustomObject]@{
        CISRef      = $cisRef
        Description = $desc
        Level       = $level
        Before      = $beforeParts -join '; '
        After       = $afterParts -join '; '
        Status      = if ($allGood) { 'Pass' } else { 'Fail' }
        Messages    = $messages.ToArray()
    }
}
