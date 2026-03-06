# CIS 7.11 (L1) Ensure AES 256/256 cipher suite is enabled
# Refactored: wrapped in function, inlined registry read, no Write-Host

function Invoke-CIS7_11 {
    [CmdletBinding()]
    param([switch]$WhatIf)

    $messages    = [System.Collections.Generic.List[string]]::new()
    $cisRef      = '7.11'
    $desc        = 'Ensure AES 256/256 cipher suite is enabled'
    $level       = 'L1'
    $path        = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256"
    $wantEnabled = 1

    # Before (inlined)
    $beforeEn = $null
    if (Test-Path $path) {
        try { $beforeEn = (Get-ItemProperty -Path $path -Name Enabled -ErrorAction Stop).Enabled } catch {}
    }
    $beforeState = "Enabled=$( if ($null -eq $beforeEn) { 'not set' } else { $beforeEn } )"
    $messages.Add("Before: AES 256/256 $beforeState")

    if ($WhatIf) {
        $messages.Add('[WhatIf] Would set AES 256/256 Enabled=1.')
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
    $messages.Add("After: AES 256/256 $afterState")
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
