# CIS 3.7 (L1) Ensure cookies are set with HttpOnly flag (httpOnlyCookies=True)
# Refactored: wrapped in function, structured return, no Write-Host

function Invoke-CIS3_7 {
    [CmdletBinding()]
    param([switch]$WhatIf)

    $messages = [System.Collections.Generic.List[string]]::new()
    $cisRef   = '3.7'
    $desc     = 'Ensure cookies are set with HttpOnly flag (httpOnlyCookies=True)'
    $level    = 'L1'

    $before    = Get-WebConfigurationProperty `
        -pspath 'MACHINE/WEBROOT/APPHOST' `
        -filter 'system.web/httpCookies' `
        -name   'httpOnlyCookies' `
        -ErrorAction Stop
    $beforeVal = $before.Value
    $messages.Add("Before: httpOnlyCookies=$beforeVal")

    if ($beforeVal -eq $true) {
        $messages.Add('Already compliant.')
        return [PSCustomObject]@{
            CISRef      = $cisRef
            Description = $desc
            Level       = $level
            Before      = "httpOnlyCookies=$beforeVal"
            After       = 'httpOnlyCookies=True'
            Status      = 'Pass'
            Messages    = $messages.ToArray()
        }
    }

    if ($WhatIf) {
        $messages.Add('[WhatIf] Would set httpOnlyCookies=True.')
        return [PSCustomObject]@{
            CISRef      = $cisRef
            Description = $desc
            Level       = $level
            Before      = "httpOnlyCookies=$beforeVal"
            After       = 'N/A (WhatIf)'
            Status      = 'WhatIf'
            Messages    = $messages.ToArray()
        }
    }

    try {
        Set-WebConfigurationProperty `
            -pspath 'MACHINE/WEBROOT/APPHOST' `
            -filter 'system.web/httpCookies' `
            -name   'httpOnlyCookies' `
            -value  $true `
            -ErrorAction Stop
    } catch {
        $messages.Add("Failed to set httpOnlyCookies=True. Error: $($_.Exception.Message)")
        return [PSCustomObject]@{
            CISRef      = $cisRef
            Description = $desc
            Level       = $level
            Before      = "httpOnlyCookies=$beforeVal"
            After       = 'httpOnlyCookies=SetFailed'
            Status      = 'Fail'
            Messages    = $messages.ToArray()
        }
    }

    $afterVal = (Get-WebConfigurationProperty `
        -pspath 'MACHINE/WEBROOT/APPHOST' `
        -filter 'system.web/httpCookies' `
        -name   'httpOnlyCookies' `
        -ErrorAction Stop).Value
    $messages.Add("After: httpOnlyCookies=$afterVal")

    $status = if ($afterVal -eq $true) { 'Pass' } else { 'Fail' }
    return [PSCustomObject]@{
        CISRef      = $cisRef
        Description = $desc
        Level       = $level
        Before      = "httpOnlyCookies=$beforeVal"
        After       = "httpOnlyCookies=$afterVal"
        Status      = $status
        Messages    = $messages.ToArray()
    }
}
