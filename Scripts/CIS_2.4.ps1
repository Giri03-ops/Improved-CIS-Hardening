# CIS 2.4 (L2) Ensure Forms Authentication uses cookies (cookieless=UseCookies)
# Refactored: wrapped in function, structured return, no Write-Host

function Invoke-CIS2_4 {
    [CmdletBinding()]
    param([switch]$WhatIf)

    function Resolve-CookielessValue {
        param([object]$Value)

        if ($null -eq $Value) { return 'UseDeviceProfile' }

        # Numeric enum from provider (0-3).
        if ($Value -is [int] -or $Value -is [long]) {
            switch ([int]$Value) {
                0 { return 'UseUri' }
                1 { return 'UseCookies' }
                2 { return 'AutoDetect' }
                3 { return 'UseDeviceProfile' }
                default { return [string]$Value }
            }
        }

        $stringVal = [string]$Value
        if ([string]::IsNullOrWhiteSpace($stringVal)) { return 'UseDeviceProfile' }

        # Some providers return enum as numeric string.
        $parsed = 0
        if ([int]::TryParse($stringVal, [ref]$parsed)) {
            switch ($parsed) {
                0 { return 'UseUri' }
                1 { return 'UseCookies' }
                2 { return 'AutoDetect' }
                3 { return 'UseDeviceProfile' }
            }
        }

        return $stringVal
    }

    $messages = [System.Collections.Generic.List[string]]::new()
    $cisRef   = '2.4'
    $desc     = 'Ensure Forms Authentication uses cookies (cookieless=UseCookies)'
    $level    = 'L2'

    $sites = Get-Website -ErrorAction SilentlyContinue
    if (-not $sites) {
        $messages.Add('No IIS sites found.')
        return [PSCustomObject]@{
            CISRef      = $cisRef
            Description = $desc
            Level       = $level
            Before      = 'No sites'
            After       = 'N/A'
            Status      = 'Skipped'
            Messages    = $messages.ToArray()
        }
    }

    $beforeParts   = [System.Collections.Generic.List[string]]::new()
    $afterParts    = [System.Collections.Generic.List[string]]::new()
    $anyFail       = $false
    $anyApplicable = $false

    foreach ($s in $sites) {
        $siteName = $s.Name
        $sitePsPath = "MACHINE/WEBROOT/APPHOST/$siteName"

        $cookielessProp = Get-WebConfigurationProperty `
            -PSPath   $sitePsPath `
            -Filter   'system.web/authentication/forms' `
            -Name     'cookieless' `
            -ErrorAction SilentlyContinue

        if ($null -eq $cookielessProp) {
            $messages.Add("[$siteName] Forms Auth not configured - skipping.")
            continue
        }

        $anyApplicable = $true
        $cookielessRaw = $cookielessProp.Value
        $cookieless    = Resolve-CookielessValue -Value $cookielessRaw

        if ($null -eq $cookielessRaw -or [string]::IsNullOrWhiteSpace([string]$cookielessRaw)) {
            $messages.Add("[$siteName] cookieless is inherited/default; effective value interpreted as $cookieless.")
        }

        $beforeParts.Add("$siteName=cookieless:$cookieless")
        $messages.Add("[$siteName] cookieless(raw='$cookielessRaw') normalized='$cookieless'")

        if ($cookieless -eq 'UseCookies') {
            $messages.Add("[$siteName] Already compliant.")
            $afterParts.Add("$siteName=cookieless:UseCookies")
            continue
        }

        if ($WhatIf) {
            $messages.Add("[WhatIf] [$siteName] Would set cookieless=UseCookies.")
            $afterParts.Add("$siteName=N/A(WhatIf)")
            continue
        }

        try {
            Set-WebConfigurationProperty `
                -PSPath   $sitePsPath `
                -Filter   'system.web/authentication/forms' `
                -Name     'cookieless' `
                -Value    'UseCookies' `
                -ErrorAction Stop
        } catch {
            $messages.Add("[$siteName] Failed to set cookieless=UseCookies. Error: $($_.Exception.Message)")
            $anyFail = $true
            $afterParts.Add("$siteName=SetFailed")
            continue
        }

        $postRaw = (Get-WebConfigurationProperty `
            -PSPath   $sitePsPath `
            -Filter   'system.web/authentication/forms' `
            -Name     'cookieless' `
            -ErrorAction SilentlyContinue).Value
        $postVal = Resolve-CookielessValue -Value $postRaw

        $messages.Add("[$siteName] Post-check: cookieless(raw='$postRaw') normalized='$postVal'")
        if ($postVal -ne 'UseCookies') { $anyFail = $true }
        $afterParts.Add("$siteName=cookieless:$postVal")
    }

    if (-not $anyApplicable) {
        return [PSCustomObject]@{
            CISRef      = $cisRef
            Description = $desc
            Level       = $level
            Before      = 'Forms Auth not configured on any site'
            After       = 'N/A'
            Status      = 'Skipped'
            Messages    = $messages.ToArray()
        }
    }

    $status = if ($WhatIf) { 'WhatIf' } elseif ($anyFail) { 'Fail' } else { 'Pass' }
    return [PSCustomObject]@{
        CISRef      = $cisRef
        Description = $desc
        Level       = $level
        Before      = $beforeParts -join '; '
        After       = if ($WhatIf) { 'N/A (WhatIf)' } else { $afterParts -join '; ' }
        Status      = $status
        Messages    = $messages.ToArray()
    }
}
