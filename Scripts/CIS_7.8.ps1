# CIS 7.8 (L1) Ensure DES 56/56 cipher is disabled
# Refactored: wrapped in function, inlined registry read, no Write-Host

function Invoke-CIS7_8 {
    [CmdletBinding()]
    param([switch]$WhatIf)

    $messages    = [System.Collections.Generic.List[string]]::new()
    $cisRef      = '7.8'
    $desc        = 'Ensure DES 56/56 cipher is disabled'
    $level       = 'L1'
    $path        = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56"
    $wantEnabled = 0

    # Before (inlined)
    $beforeEn = $null
    if (Test-Path $path) {
        try { $beforeEn = (Get-ItemProperty -Path $path -Name Enabled -ErrorAction Stop).Enabled } catch {}
    }
    $beforeState = "Enabled=$( if ($null -eq $beforeEn) { 'not set' } else { $beforeEn } )"
    $messages.Add("Before: DES 56/56 $beforeState")

    if ($WhatIf) {
        $messages.Add('[WhatIf] Would set DES 56/56 Enabled=0.')
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
    $messages.Add("After: DES 56/56 $afterState")
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
