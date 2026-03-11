# CIS 4.7 (L1) Ensure unlisted file extensions are not allowed (allowUnlisted=False)
# Refactored: wrapped in function, structured return, no Write-Host

function Invoke-CIS4_7 {
    [CmdletBinding()]
    param([switch]$WhatIf)

    $messages  = [System.Collections.Generic.List[string]]::new()
    $cisRef    = '4.7'
    $desc      = 'Ensure unlisted file extensions are not allowed (allowUnlisted=False)'
    $level     = 'L1'

    $before    = Get-WebConfigurationProperty `
        -pspath 'MACHINE/WEBROOT/APPHOST' `
        -filter 'system.webServer/security/requestFiltering/fileExtensions' `
        -name   'allowUnlisted' `
        -ErrorAction Stop
    $beforeVal = $before.Value
    $messages.Add("Before: allowUnlisted=$beforeVal")

    if ($beforeVal -eq $false) {
        $messages.Add('Already compliant.')
        return [PSCustomObject]@{
            CISRef      = $cisRef
            Description = $desc
            Level       = $level
            Before      = "allowUnlisted=$beforeVal"
            After       = 'allowUnlisted=False'
            Status      = 'Pass'
            Messages    = $messages.ToArray()
        }
    }

    if ($WhatIf) {
        $messages.Add('[WhatIf] Would set allowUnlisted=False.')
        return [PSCustomObject]@{
            CISRef      = $cisRef
            Description = $desc
            Level       = $level
            Before      = "allowUnlisted=$beforeVal"
            After       = 'N/A (WhatIf)'
            Status      = 'WhatIf'
            Messages    = $messages.ToArray()
        }
    }

    try {
        Set-WebConfigurationProperty `
            -pspath 'MACHINE/WEBROOT/APPHOST' `
            -filter 'system.webServer/security/requestFiltering/fileExtensions' `
            -name   'allowUnlisted' `
            -value  $false `
            -ErrorAction Stop
    } catch {
        $messages.Add("Failed to set allowUnlisted=False. Error: $($_.Exception.Message)")
        return [PSCustomObject]@{
            CISRef      = $cisRef
            Description = $desc
            Level       = $level
            Before      = "allowUnlisted=$beforeVal"
            After       = 'allowUnlisted=SetFailed'
            Status      = 'Fail'
            Messages    = $messages.ToArray()
        }
    }

    $afterVal = (Get-WebConfigurationProperty `
        -pspath 'MACHINE/WEBROOT/APPHOST' `
        -filter 'system.webServer/security/requestFiltering/fileExtensions' `
        -name   'allowUnlisted' `
        -ErrorAction Stop).Value
    $messages.Add("After: allowUnlisted=$afterVal")

    $status = if ($afterVal -eq $false) { 'Pass' } else { 'Fail' }
    return [PSCustomObject]@{
        CISRef      = $cisRef
        Description = $desc
        Level       = $level
        Before      = "allowUnlisted=$beforeVal"
        After       = "allowUnlisted=$afterVal"
        Status      = $status
        Messages    = $messages.ToArray()
    }
}
