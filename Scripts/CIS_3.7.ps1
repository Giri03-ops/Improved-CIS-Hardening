# CIS 3.7 (L1) Ensure cookies are set with HttpOnly flag (httpOnlyCookies=True)
# Fixed: robust boolean extraction handles string/ConfigurationAttribute/bool

function Invoke-CIS3_7 {
    [CmdletBinding()]
    param([switch]$WhatIf)

    function Resolve-BoolValue {
        param($Value)
        if ($null -eq $Value) { return $false }
        # Try .Value property first (ConfigurationAttribute objects)
        $raw = $Value
        if ($Value.PSObject.Properties.Match('Value').Count -gt 0) {
            $raw = $Value.Value
        }
        if ($null -eq $raw) { return $false }
        try {
            return [System.Convert]::ToBoolean($raw)
        } catch {
            return $false
        }
    }

    $messages = [System.Collections.Generic.List[string]]::new()
    $cisRef   = '3.7'
    $desc     = 'Ensure cookies are set with HttpOnly flag (httpOnlyCookies=True)'
    $level    = 'L1'

    $before    = Get-WebConfigurationProperty `
        -pspath 'MACHINE/WEBROOT/APPHOST' `
        -filter 'system.web/httpCookies' `
        -name   'httpOnlyCookies' `
        -ErrorAction Stop
    $beforeVal = Resolve-BoolValue -Value $before
    $messages.Add("Before: httpOnlyCookies=$beforeVal")

    if ($beforeVal) {
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

    $after    = Get-WebConfigurationProperty `
        -pspath 'MACHINE/WEBROOT/APPHOST' `
        -filter 'system.web/httpCookies' `
        -name   'httpOnlyCookies' `
        -ErrorAction Stop
    $afterVal = Resolve-BoolValue -Value $after
    $messages.Add("After: httpOnlyCookies=$afterVal")

    $status = if ($afterVal) { 'Pass' } else { 'Fail' }
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
