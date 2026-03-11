# CIS 2.3 (L1) Ensure 'forms authentication' require SSL is configured
# Refactored: removed $ForceRequireSslEvenWithoutIisHttps=$true (CRITICAL FIX)
# Sites without an IIS HTTPS binding are now Skipped instead of broken

function Invoke-CIS2_3 {
    [CmdletBinding()]
    param([switch]$WhatIf)

    $messages = [System.Collections.Generic.List[string]]::new()
    $cisRef   = '2.3'
    $desc     = "Ensure 'forms authentication' require SSL is configured"
    $level    = 'L1'

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
        $hasHttps = @(Get-WebBinding -Name $siteName -Protocol https -ErrorAction SilentlyContinue).Count -gt 0

        $requireSslProp = Get-WebConfigurationProperty `
            -pspath "MACHINE/WEBROOT/APPHOST/$siteName" `
            -filter 'system.web/authentication/forms' `
            -name   'requireSSL' `
            -ErrorAction SilentlyContinue

        if ($null -eq $requireSslProp) {
            $messages.Add("[$siteName] Forms Auth not configured - skipping.")
            continue
        }

        $anyApplicable = $true
        $requireSsl    = [bool]$requireSslProp.Value
        $beforeParts.Add("$siteName=requireSSL:$requireSsl")
        $messages.Add("[$siteName] requireSSL=$requireSsl ; httpsBinding=$hasHttps")

        # FIXED: never force requireSSL when no HTTPS binding exists - skip instead
        if (-not $hasHttps) {
            $messages.Add("[$siteName] No HTTPS binding on IIS - skipping to avoid breaking Forms Auth over HTTP.")
            $afterParts.Add("$siteName=Skipped(noHTTPS)")
            continue
        }

        if ($requireSsl) {
            $messages.Add("[$siteName] Already compliant.")
            $afterParts.Add("$siteName=requireSSL:True")
            continue
        }

        if ($WhatIf) {
            $messages.Add("[WhatIf] [$siteName] Would set requireSSL=True.")
            $afterParts.Add("$siteName=N/A(WhatIf)")
            continue
        }

        Set-WebConfigurationProperty `
            -pspath "MACHINE/WEBROOT/APPHOST/$siteName" `
            -filter 'system.web/authentication/forms' `
            -name   'requireSSL' `
            -value  $true

        # Post-check
        $postVal = [bool](Get-WebConfigurationProperty `
            -pspath "MACHINE/WEBROOT/APPHOST/$siteName" `
            -filter 'system.web/authentication/forms' `
            -name   'requireSSL' `
            -ErrorAction SilentlyContinue).Value
        $messages.Add("[$siteName] Post-check: requireSSL=$postVal")
        if (-not $postVal) { $anyFail = $true }
        $afterParts.Add("$siteName=requireSSL:$postVal")
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
