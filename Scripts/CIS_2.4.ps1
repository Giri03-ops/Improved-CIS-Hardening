# CIS 2.4 (L2) Ensure Forms Authentication uses cookies (cookieless=UseCookies)
# Fixed: PSPath format, value extraction, and WhatIf compliance detection

function Invoke-CIS2_4 {
    [CmdletBinding()]
    param([switch]$WhatIf)

    function Resolve-CookielessValue {
        param($Value)

        if ($null -eq $Value) { return 'UseDeviceProfile' }

        # Try .Value first (ConfigurationAttribute), then fall back to raw object
        $raw = $null
        if ($Value.PSObject.Properties.Match('Value').Count -gt 0) {
            $raw = [string]$Value.Value
        }
        if ([string]::IsNullOrWhiteSpace($raw)) {
            $raw = [string]$Value
        }
        if ([string]::IsNullOrWhiteSpace($raw)) { return 'UseDeviceProfile' }

        switch -Regex ($raw.Trim()) {
            '^0$' { 'UseUri'; break }
            '^1$' { 'UseCookies'; break }
            '^2$' { 'AutoDetect'; break }
            '^3$' { 'UseDeviceProfile'; break }
            default { $raw.Trim() }
        }
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

    $beforeParts    = [System.Collections.Generic.List[string]]::new()
    $afterParts     = [System.Collections.Generic.List[string]]::new()
    $anyFail        = $false
    $anyApplicable  = $false
    $anyNonCompliant = $false

    foreach ($s in $sites) {
        $siteName = $s.Name

        $formsSection = Get-WebConfiguration `
            -PSPath "MACHINE/WEBROOT/APPHOST/$siteName" `
            -Filter 'system.web/authentication/forms' `
            -ErrorAction SilentlyContinue

        if ($null -eq $formsSection) {
            $messages.Add("[$siteName] Forms Auth section not present for this site - skipping.")
            continue
        }

        $anyApplicable = $true

        $cookielessProp = Get-WebConfigurationProperty `
            -PSPath "MACHINE/WEBROOT/APPHOST/$siteName" `
            -Filter 'system.web/authentication/forms' `
            -Name   'cookieless' `
            -ErrorAction SilentlyContinue

        $currentCookieless = Resolve-CookielessValue -Value $cookielessProp
        $beforeParts.Add("$siteName=cookieless:$currentCookieless")
        $messages.Add("[$siteName] cookieless=$currentCookieless")

        if ($currentCookieless -eq 'UseCookies') {
            $messages.Add("[$siteName] Already compliant.")
            $afterParts.Add("$siteName=cookieless:UseCookies")
            continue
        }

        $anyNonCompliant = $true

        if ($WhatIf) {
            $messages.Add("[WhatIf] [$siteName] Would set cookieless=UseCookies.")
            $afterParts.Add("$siteName=N/A(WhatIf)")
            continue
        }

        try {
            Set-WebConfigurationProperty `
                -PSPath "MACHINE/WEBROOT/APPHOST/$siteName" `
                -Filter 'system.web/authentication/forms' `
                -Name   'cookieless' `
                -Value  'UseCookies' `
                -ErrorAction Stop
        } catch {
            $messages.Add("[$siteName] Failed to set cookieless=UseCookies. Error: $($_.Exception.Message)")
            $anyFail = $true
            $afterParts.Add("$siteName=SetFailed")
            continue
        }

        $postProp = Get-WebConfigurationProperty `
            -PSPath "MACHINE/WEBROOT/APPHOST/$siteName" `
            -Filter 'system.web/authentication/forms' `
            -Name   'cookieless' `
            -ErrorAction SilentlyContinue

        $postCookieless = Resolve-CookielessValue -Value $postProp
        $messages.Add("[$siteName] Post-check: cookieless=$postCookieless")

        if ($postCookieless -ne 'UseCookies') { $anyFail = $true }
        $afterParts.Add("$siteName=cookieless:$postCookieless")
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

    if ($WhatIf) {
        $status = if ($anyNonCompliant) { 'WhatIf' } else { 'Pass' }
    } else {
        $status = if ($anyFail) { 'Fail' } else { 'Pass' }
    }

    return [PSCustomObject]@{
        CISRef      = $cisRef
        Description = $desc
        Level       = $level
        Before      = $beforeParts -join '; '
        After       = if ($WhatIf -and $anyNonCompliant) { 'N/A (WhatIf)' } elseif ($WhatIf) { $beforeParts -join '; ' } else { $afterParts -join '; ' }
        Status      = $status
        Messages    = $messages.ToArray()
    }
}
