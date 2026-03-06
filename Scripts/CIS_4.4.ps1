# CIS 4.4 (L2) Ensure non-ASCII characters in URLs are blocked (allowHighBitCharacters=False)
# Refactored: wrapped in function, structured return, no Write-Host

function Invoke-CIS4_4 {
    [CmdletBinding()]
    param([switch]$WhatIf)

    $messages  = [System.Collections.Generic.List[string]]::new()
    $cisRef    = '4.4'
    $desc      = 'Ensure non-ASCII characters in URLs are blocked (allowHighBitCharacters=False)'
    $level     = 'L2'

    $before    = Get-WebConfigurationProperty `
        -pspath 'MACHINE/WEBROOT/APPHOST' `
        -filter 'system.webServer/security/requestFiltering' `
        -name   'allowHighBitCharacters' `
        -ErrorAction Stop
    $beforeVal = $before.Value
    $messages.Add("Before: allowHighBitCharacters=$beforeVal")

    if ($beforeVal -eq $false) {
        $messages.Add('Already compliant.')
        return [PSCustomObject]@{
            CISRef      = $cisRef
            Description = $desc
            Level       = $level
            Before      = "allowHighBitCharacters=$beforeVal"
            After       = 'allowHighBitCharacters=False'
            Status      = 'Pass'
            Messages    = $messages.ToArray()
        }
    }

    if ($WhatIf) {
        $messages.Add('[WhatIf] Would set allowHighBitCharacters=False.')
        return [PSCustomObject]@{
            CISRef      = $cisRef
            Description = $desc
            Level       = $level
            Before      = "allowHighBitCharacters=$beforeVal"
            After       = 'N/A (WhatIf)'
            Status      = 'WhatIf'
            Messages    = $messages.ToArray()
        }
    }

    Set-WebConfigurationProperty `
        -pspath 'MACHINE/WEBROOT/APPHOST' `
        -filter 'system.webServer/security/requestFiltering' `
        -name   'allowHighBitCharacters' `
        -value  $false `
        -ErrorAction Stop

    $afterVal = (Get-WebConfigurationProperty `
        -pspath 'MACHINE/WEBROOT/APPHOST' `
        -filter 'system.webServer/security/requestFiltering' `
        -name   'allowHighBitCharacters' `
        -ErrorAction Stop).Value
    $messages.Add("After: allowHighBitCharacters=$afterVal")

    $status = if ($afterVal -eq $false) { 'Pass' } else { 'Fail' }
    return [PSCustomObject]@{
        CISRef      = $cisRef
        Description = $desc
        Level       = $level
        Before      = "allowHighBitCharacters=$beforeVal"
        After       = "allowHighBitCharacters=$afterVal"
        Status      = $status
        Messages    = $messages.ToArray()
    }
}
