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
    $messages.Add("Anonymous Authentication enabled at: $($displayLocations -join ', ')")

    # Resolve app pools for impacted locations.
    $appPools = foreach ($loc in $anonLocations) {
        if ([string]::IsNullOrWhiteSpace($loc)) {
            # Server-level setting applies broadly; include all site applications.
            Get-WebConfiguration `
                -PSPath 'MACHINE/WEBROOT/APPHOST' `
                -Filter 'system.applicationHost/sites/site/application' `
                -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty applicationPool
            continue
        }

        $siteName = ($loc -split '/')[0]
        if ([string]::IsNullOrWhiteSpace($siteName)) { continue }

        Get-WebConfiguration `
            -PSPath 'MACHINE/WEBROOT/APPHOST' `
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
            Before      = 'Anonymous Auth enabled at: ' + ($displayLocations -join '; ')
            After       = 'N/A'
            Status      = 'Skipped'
            Messages    = $messages.ToArray()
        }
    }

    $messages.Add("Resolved app pools: $($appPools -join ', ')")

    # Build per-pool current state first (so WhatIf can correctly identify compliant pools).
    $beforeParts  = [System.Collections.Generic.List[string]]::new()
    $targetPools  = [System.Collections.Generic.List[string]]::new()
    foreach ($pool in $appPools) {
        $rawVal = (Get-ItemProperty -Path "IIS:\AppPools\$pool" -Name passAnonymousToken -ErrorAction SilentlyContinue).passAnonymousToken
        $isEnabled = $false
        if ($null -ne $rawVal) {
            try { $isEnabled = [System.Convert]::ToBoolean($rawVal) } catch { $isEnabled = $false }
        }

        $beforeParts.Add("$pool=passAnonymousToken:$rawVal (bool:$isEnabled)")

        if (-not $isEnabled) {
            $targetPools.Add($pool)
        }
    }

    if ($targetPools.Count -eq 0) {
        $messages.Add('All resolved application pools already have passAnonymousToken=True.')
        return [PSCustomObject]@{
            CISRef      = $cisRef
            Description = $desc
            Level       = $level
            Before      = $beforeParts -join '; '
            After       = $beforeParts -join '; '
            Status      = if ($WhatIf) { 'WhatIf' } else { 'Pass' }
            Messages    = $messages.ToArray()
        }
    }

    if ($WhatIf) {
        $messages.Add("[WhatIf] Would set passAnonymousToken=True for: $($targetPools -join ', ')")
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

    $setFailures = [System.Collections.Generic.List[string]]::new()
    foreach ($pool in $targetPools) {
        try {
            Set-ItemProperty -Path "IIS:\AppPools\$pool" -Name passAnonymousToken -Value $true -ErrorAction Stop
            $messages.Add("Set passAnonymousToken=True for: $pool")
        } catch {
            $setFailures.Add($pool)
            $messages.Add("Failed setting passAnonymousToken=True for '$pool'. Error: $($_.Exception.Message)")
        }
    }

    # Post-check
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
        Before      = $beforeParts -join '; '
        After       = $afterParts -join '; '
        Status      = $status
        Messages    = $messages.ToArray()
    }
}
