# CIS 7.7 (L1) Ensure NULL cipher suite is disabled
# Refactored: wrapped in function, inlined registry read, no Write-Host

function Invoke-CIS7_7 {
    [CmdletBinding()]
    param([switch]$WhatIf)

    $messages    = [System.Collections.Generic.List[string]]::new()
    $cisRef      = '7.7'
    $desc        = 'Ensure NULL cipher suite is disabled'
    $level       = 'L1'
    $path        = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL"
    $wantEnabled = 0

    # Before (inlined)
    $beforeEn = $null
    if (Test-Path $path) {
        try { $beforeEn = (Get-ItemProperty -Path $path -Name Enabled -ErrorAction Stop).Enabled } catch {}
    }
    $beforeState = "Enabled=$( if ($null -eq $beforeEn) { 'not set' } else { $beforeEn } )"
    $messages.Add("Before: NULL cipher $beforeState")

    $isCompliant = ($beforeEn -eq $wantEnabled)

    if ($WhatIf) {
        if ($isCompliant) {
            $messages.Add('Already compliant. No changes required.')
            return [PSCustomObject]@{
                CISRef      = $cisRef
                Description = $desc
                Level       = $level
                Before      = $beforeState
                After       = $beforeState
                Status      = 'Pass'
                Messages    = $messages.ToArray()
            }
        }

        $messages.Add('[WhatIf] Would set NULL cipher Enabled=0.')
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

    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
    New-ItemProperty -Path $path -Name 'Enabled' -Value $wantEnabled -PropertyType DWord -Force | Out-Null

    # Verify (inlined)
    $afterEn = $null
    try { $afterEn = (Get-ItemProperty -Path $path -Name Enabled -ErrorAction Stop).Enabled } catch {}
    $afterState = "Enabled=$afterEn"
    $messages.Add("After: NULL cipher $afterState")
    $messages.Add('NOTE: A reboot is required for SCHANNEL changes to take effect.')

    $status = if ($afterEn -eq $wantEnabled) { 'Pass' } else { 'Fail' }
    return [PSCustomObject]@{
        CISRef      = $cisRef
        Description = $desc
        Level       = $level
        Before      = $beforeState
        After       = $afterState
        Status      = $status
        Messages    = $messages.ToArray()
    }
}
