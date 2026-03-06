# CIS 3.10 (L1) Ensure global .NET trust level is configured to Medium
# Refactored: wrapped in function, structured return, no Write-Host

function Invoke-CIS3_10 {
    [CmdletBinding()]
    param([switch]$WhatIf)

    $messages    = [System.Collections.Generic.List[string]]::new()
    $cisRef      = '3.10'
    $desc        = 'Ensure global .NET trust level is configured to Medium or lower'
    $level       = 'L1'
    $targetLevel = 'Medium'

    $cur       = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT' -filter 'system.web/trust' -name 'level' -ErrorAction Stop
    $beforeVal = $cur.Value
    $messages.Add("Before: trustLevel=$beforeVal")

    if ($beforeVal -eq $targetLevel) {
        $messages.Add('Already compliant.')
        return [PSCustomObject]@{
            CISRef      = $cisRef
            Description = $desc
            Level       = $level
            Before      = "trustLevel=$beforeVal"
            After       = "trustLevel=$targetLevel"
            Status      = 'Pass'
            Messages    = $messages.ToArray()
        }
    }

    if ($WhatIf) {
        $messages.Add("[WhatIf] Would set trust level to '$targetLevel'.")
        return [PSCustomObject]@{
            CISRef      = $cisRef
            Description = $desc
            Level       = $level
            Before      = "trustLevel=$beforeVal"
            After       = 'N/A (WhatIf)'
            Status      = 'WhatIf'
            Messages    = $messages.ToArray()
        }
    }

    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT' -filter 'system.web/trust' -name 'level' -value $targetLevel -ErrorAction Stop

    $afterVal = (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT' -filter 'system.web/trust' -name 'level' -ErrorAction Stop).Value
    $messages.Add("After: trustLevel=$afterVal")

    $status = if ($afterVal -eq $targetLevel) { 'Pass' } else { 'Fail' }
    return [PSCustomObject]@{
        CISRef      = $cisRef
        Description = $desc
        Level       = $level
        Before      = "trustLevel=$beforeVal"
        After       = "trustLevel=$afterVal"
        Status      = $status
        Messages    = $messages.ToArray()
    }
}
