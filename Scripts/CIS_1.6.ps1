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

    $anonLocations = @($anonEntries | Select-Object -ExpandProperty Location | Sort-Object -Unique)
    $beforeState   = 'Anonymous Auth enabled at: ' + ($anonLocations -join '; ')
    $messages.Add("Anonymous Authentication enabled at: $($anonLocations -join ', ')")

    # Resolve app pools for those sites
    $appPools = foreach ($loc in $anonLocations) {
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

    foreach ($pool in $appPools) {
        Set-ItemProperty -Path "IIS:\AppPools\$pool" -Name passAnonymousToken -Value $true -ErrorAction Stop
        $messages.Add("Set passAnonymousToken=True for: $pool")
    }

    # Post-check
    $allGood    = $true
    $afterParts = [System.Collections.Generic.List[string]]::new()
    foreach ($pool in $appPools) {
        $val = (Get-ItemProperty -Path "IIS:\AppPools\$pool" -Name passAnonymousToken -ErrorAction SilentlyContinue).passAnonymousToken
        $afterParts.Add("$pool=passAnonymousToken:$val")
        if ($val -ne $true) { $allGood = $false }
    }

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
