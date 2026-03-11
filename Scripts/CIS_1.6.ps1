# CIS 1.6 (L1) Ensure 'application pool identity' is configured for anonymous user identity
# Refactored: enforce anonymousAuthentication.userName='' (app pool identity)

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

    $beforeParts = [System.Collections.Generic.List[string]]::new()
    $afterParts  = [System.Collections.Generic.List[string]]::new()

    $nonCompliant = [System.Collections.Generic.List[string]]::new()
    foreach ($location in $anonLocations) {
        $userName = [string](Get-WebConfigurationProperty `
            -PSPath   'MACHINE/WEBROOT/APPHOST' `
            -Location $location `
            -Filter   'system.webServer/security/authentication/anonymousAuthentication' `
            -Name     'userName' `
            -ErrorAction SilentlyContinue).Value

        $locLabel = if ([string]::IsNullOrWhiteSpace($location)) { '<server-root>' } else { $location }
        $safeUser = if ($null -eq $userName) { '' } else { $userName }
        $beforeParts.Add("$locLabel=userName:'$safeUser'")

        if (-not [string]::IsNullOrWhiteSpace($safeUser)) {
            $nonCompliant.Add($location)
        }
    }

    if ($nonCompliant.Count -eq 0) {
        $messages.Add('All anonymous authentication entries already use application pool identity (userName blank).')
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
        $whatIfTargets = @($nonCompliant | ForEach-Object { if ([string]::IsNullOrWhiteSpace($_)) { '<server-root>' } else { $_ } })
        $messages.Add("[WhatIf] Would set anonymousAuthentication userName='' for: $($whatIfTargets -join ', ')")
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
    foreach ($location in $nonCompliant) {
        $locLabel = if ([string]::IsNullOrWhiteSpace($location)) { '<server-root>' } else { $location }
        try {
            Set-WebConfigurationProperty `
                -PSPath   'MACHINE/WEBROOT/APPHOST' `
                -Location $location `
                -Filter   'system.webServer/security/authentication/anonymousAuthentication' `
                -Name     'userName' `
                -Value    '' `
                -ErrorAction Stop

            Set-WebConfigurationProperty `
                -PSPath   'MACHINE/WEBROOT/APPHOST' `
                -Location $location `
                -Filter   'system.webServer/security/authentication/anonymousAuthentication' `
                -Name     'password' `
                -Value    '' `
                -ErrorAction SilentlyContinue

            $messages.Add("Set anonymousAuthentication userName='' for: $locLabel")
        } catch {
            $setFailures.Add($location)
            $messages.Add("Failed setting anonymousAuthentication identity for '$locLabel'. Error: $($_.Exception.Message)")
        }
    }

    $allGood = $true
    foreach ($location in $anonLocations) {
        $locLabel = if ([string]::IsNullOrWhiteSpace($location)) { '<server-root>' } else { $location }
        $postUser = [string](Get-WebConfigurationProperty `
            -PSPath   'MACHINE/WEBROOT/APPHOST' `
            -Location $location `
            -Filter   'system.webServer/security/authentication/anonymousAuthentication' `
            -Name     'userName' `
            -ErrorAction SilentlyContinue).Value

        $safePostUser = if ($null -eq $postUser) { '' } else { $postUser }
        $afterParts.Add("$locLabel=userName:'$safePostUser'")

        if (-not [string]::IsNullOrWhiteSpace($safePostUser)) {
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
