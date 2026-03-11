# CIS 7.6 (L1) Ensure TLS 1.2 is enabled (Server + Client)
# Refactored: inlined registry reads (no Get-ProtoState helper to avoid dot-source collisions)
# Note: target values are Enabled=1, DisabledByDefault=0 (opposite of disable scripts)

function Invoke-CIS7_6 {
    [CmdletBinding()]
    param([switch]$WhatIf)

    $messages    = [System.Collections.Generic.List[string]]::new()
    $cisRef      = '7.6'
    $desc        = 'Ensure TLS 1.2 is enabled (Server + Client)'
    $level       = 'L1'
    $proto       = 'TLS 1.2'
    $base        = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto"
    $targets     = @(
        @{ Name = 'Server'; Path = "$base\Server" },
        @{ Name = 'Client'; Path = "$base\Client" }
    )
    $wantEnabled = 1
    $wantDbd     = 0

    # Read before state (inlined - no shared helper)
    $beforeParts = [System.Collections.Generic.List[string]]::new()
    foreach ($t in $targets) {
        $en = $null; $dbd = $null
        if (Test-Path $t.Path) {
            try { $en  = (Get-ItemProperty -Path $t.Path -Name Enabled           -ErrorAction Stop).Enabled           } catch {}
            try { $dbd = (Get-ItemProperty -Path $t.Path -Name DisabledByDefault -ErrorAction Stop).DisabledByDefault } catch {}
        }
        $enStr  = if ($null -eq $en)  { 'not set' } else { "$en"  }
        $dbdStr = if ($null -eq $dbd) { 'not set' } else { "$dbd" }
        $beforeParts.Add("$($t.Name): Enabled=$enStr DisabledByDefault=$dbdStr")
    }
    $beforeState = $beforeParts -join '; '
    $messages.Add("Before: $beforeState")

    if ($WhatIf) {
        $messages.Add("[WhatIf] Would set $proto Server+Client: Enabled=$wantEnabled, DisabledByDefault=$wantDbd.")
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

    # Apply
    foreach ($t in $targets) {
        if (-not (Test-Path $t.Path)) { New-Item -Path $t.Path -Force | Out-Null }
        New-ItemProperty -Path $t.Path -Name 'Enabled'           -Value $wantEnabled -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path $t.Path -Name 'DisabledByDefault' -Value $wantDbd     -PropertyType DWord -Force | Out-Null
        $messages.Add("Applied: $($t.Name) at $($t.Path)")
    }

    # Verify (inlined)
    $allGood    = $true
    $afterParts = [System.Collections.Generic.List[string]]::new()
    foreach ($t in $targets) {
        $en = $null; $dbd = $null
        if (Test-Path $t.Path) {
            try { $en  = (Get-ItemProperty -Path $t.Path -Name Enabled           -ErrorAction Stop).Enabled           } catch {}
            try { $dbd = (Get-ItemProperty -Path $t.Path -Name DisabledByDefault -ErrorAction Stop).DisabledByDefault } catch {}
        }
        $afterParts.Add("$($t.Name): Enabled=$en DisabledByDefault=$dbd")
        if ($en -ne $wantEnabled -or $dbd -ne $wantDbd) { $allGood = $false }
    }
    $afterState = $afterParts -join '; '
    $messages.Add("After: $afterState")
    $messages.Add('NOTE: A reboot is required for SCHANNEL changes to take effect.')

    $status = if ($allGood) { 'Pass' } else { 'Fail' }
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
