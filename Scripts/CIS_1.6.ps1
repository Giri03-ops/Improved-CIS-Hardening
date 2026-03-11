# CIS 1.6 (L1) Ensure 'application pool identity' is configured for anonymous user identity
# Refactored: wrapped in function, structured return, no Write-Host

function Invoke-CIS1_6 {
    [CmdletBinding()]
    param([switch]$WhatIf)

    $messages = [System.Collections.Generic.List[string]]::new()
    $cisRef   = '1.6'
    $desc     = "Ensure 'application pool identity' is configured for anonymous user identity"
    $level    = 'L1'

    $anonEntries = Get-WebConfiguration `
        -Filter 'system.webServer/security/authentication/anonymousAuthentication' `
        -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.enabled -eq $true }

    if (-not $anonEntries) {
        $messages.Add('No locations with Anonymous Authentication enabled.')
        return [PSCustomObject]@{
            CISRef      = $cisRef
            Description = $desc
            Level       = $level
            Before      = 'Anonymous Authentication: not enabled anywhere'
            After       = 'N/A'
            Status      = 'Skipped'
            Messages    = $messages.ToArray()
        }
    }

    $anonLocations = @(
        $anonEntries |
            Select-Object -ExpandProperty Location |
            ForEach-Object { if ($null -eq $_) { '' } else { $_.ToString().Trim() } } |
            Sort-Object -Unique
    )
    $displayLocations = @($anonLocations | ForEach-Object { if ([string]::IsNullOrWhiteSpace($_)) { '<server-root>' } else { $_ } })
    $beforeState   = 'Anonymous Auth enabled at: ' + ($displayLocations -join '; ')
    $messages.Add("Anonymous Authentication enabled at: $($displayLocations -join ', ')")

    # Resolve app pools for those sites
    $appPools = foreach ($loc in $anonLocations) {
        if ([string]::IsNullOrWhiteSpace($loc)) {
            # Server-level setting applies broadly; include all site application pools.
            Get-WebConfiguration `
                -Filter 'system.applicationHost/sites/site/application' `
                -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty applicationPool
            continue
        }

        $siteName = ($loc -split '/')[0]
        Get-WebConfiguration `
            -Filter "system.applicationHost/sites/site[@name='$siteName']/application" `
            -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty applicationPool
    }
    $appPools = @($appPools | Where-Object { $_ -and $_.Trim() -ne '' } | Sort-Object -Unique)

    if (-not $appPools) {
        $messages.Add('No application pools resolved from anonymous locations.')
        return [PSCustomObject]@{
            CISRef      = $cisRef
            Description = $desc
            Level       = $level
            Before      = $beforeState
            After       = 'N/A'
            Status      = 'Skipped'
            Messages    = $messages.ToArray()
        }
    }

    $messages.Add("Resolved app pools: $($appPools -join ', ')")

    if ($WhatIf) {
        $messages.Add("[WhatIf] Would set passAnonymousToken=True for: $($appPools -join ', ')")
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

    $setFailures = [System.Collections.Generic.List[string]]::new()
    foreach ($pool in $appPools) {
        try {
            Set-ItemProperty -Path "IIS:\AppPools\$pool" -Name passAnonymousToken -Value $true -ErrorAction Stop
            $messages.Add("Set passAnonymousToken=True for: $pool")
        } catch {
            $setFailures.Add($pool)
            $messages.Add("Failed setting passAnonymousToken=True for '$pool'. Error: $($_.Exception.Message)")
        }
    }

    # Post-check (coerce to bool to avoid provider-specific string/integer values)
    $allGood    = $true
    $afterParts = [System.Collections.Generic.List[string]]::new()
    foreach ($pool in $appPools) {
        $rawVal = (Get-ItemProperty -Path "IIS:\AppPools\$pool" -Name passAnonymousToken -ErrorAction SilentlyContinue).passAnonymousToken
        $isEnabled = $false
        if ($null -ne $rawVal) {
            try { $isEnabled = [System.Convert]::ToBoolean($rawVal) } catch { $isEnabled = $false }
        }
        $afterParts.Add("$pool=passAnonymousToken:$rawVal (bool:$isEnabled)")
        if (-not $isEnabled) { $allGood = $false }
    }

    if ($setFailures.Count -gt 0) { $allGood = $false }
    $status = if ($allGood) { 'Pass' } else { 'Fail' }
    return [PSCustomObject]@{
        CISRef      = $cisRef
        Description = $desc
        Level       = $level
        Before      = $beforeState
        After       = $afterParts -join '; '
        Status      = $status
        Messages    = $messages.ToArray()
    }
}
