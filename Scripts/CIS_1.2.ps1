# CIS 1.2 (L1) Ensure host headers are configured on all sites
# Refactored: removed appcmd block, uses IIS PS module only

function Invoke-CIS1_2 {
    [CmdletBinding()]
    param([switch]$WhatIf)

    $messages  = [System.Collections.Generic.List[string]]::new()
    $cisRef    = '1.2'
    $desc      = 'Ensure host headers are configured on all sites'
    $level     = 'L1'

    # Audit: capture all bindings as before-state
    $allBindings = Get-WebBinding -ErrorAction SilentlyContinue
    $beforeState = if ($allBindings) {
        ($allBindings | ForEach-Object { "$($_.protocol) $($_.bindingInformation)" }) -join '; '
    } else { 'No bindings found' }

    # Find sites with HTTP/HTTPS bindings using IIS PS module
    $sites = Get-Website -ErrorAction SilentlyContinue
    if (-not $sites) {
        $messages.Add('No IIS sites found.')
        return [PSCustomObject]@{
            CISRef      = $cisRef
            Description = $desc
            Level       = $level
            Before      = $beforeState
            After       = 'N/A'
            Status      = 'Skipped'
            Messages    = $messages.ToArray()
        }
    }

    $httpSites = @($sites | Where-Object {
        @(Get-WebBinding -Name $_.Name -ErrorAction SilentlyContinue |
            Where-Object { $_.protocol -in 'http','https' }).Count -gt 0
    })

    if ($httpSites.Count -eq 0) {
        $messages.Add('No HTTP/HTTPS sites found. CIS 1.2 not applicable (FTP-only server).')
        return [PSCustomObject]@{
            CISRef      = $cisRef
            Description = $desc
            Level       = $level
            Before      = $beforeState
            After       = 'N/A'
            Status      = 'Skipped'
            Messages    = $messages.ToArray()
        }
    }

    if ($httpSites.Count -ne 1) {
        $siteList = ($httpSites | ForEach-Object { $_.Name }) -join ', '
        $messages.Add("Multiple HTTP/HTTPS sites found ($siteList). Auto-selection is unsafe - set SiteName manually.")
        return [PSCustomObject]@{
            CISRef      = $cisRef
            Description = $desc
            Level       = $level
            Before      = $beforeState
            After       = 'N/A'
            Status      = 'Skipped'
            Messages    = $messages.ToArray()
        }
    }

    $SiteName = $httpSites[0].Name
    $messages.Add("Auto-selected site: $SiteName")

    # Best-effort host header discovery from existing bindings (HTTPS preferred, then HTTP)
    $siteBindings = Get-WebBinding -Name $SiteName -ErrorAction SilentlyContinue
    $HostHeader   = $null

    $httpsB = $siteBindings | Where-Object { $_.protocol -eq 'https' } | Select-Object -First 1
    if ($httpsB) {
        $parts = $httpsB.bindingInformation -split ':'
        if ($parts.Count -ge 3 -and $parts[2] -ne '') { $HostHeader = $parts[2] }
    }
    if (-not $HostHeader) {
        $httpB = $siteBindings | Where-Object { $_.protocol -eq 'http' } | Select-Object -First 1
        if ($httpB) {
            $parts = $httpB.bindingInformation -split ':'
            if ($parts.Count -ge 3 -and $parts[2] -ne '') { $HostHeader = $parts[2] }
        }
    }

    if (-not $HostHeader) {
        $messages.Add('Host header could not be auto-detected (site has empty *:80: binding). Set $HostHeader manually to the real FQDN.')
        return [PSCustomObject]@{
            CISRef      = $cisRef
            Description = $desc
            Level       = $level
            Before      = $beforeState
            After       = 'N/A'
            Status      = 'Skipped'
            Messages    = $messages.ToArray()
        }
    }

    $messages.Add("Auto-detected host header: $HostHeader")

    # Check for bare *:80: binding that needs a host header applied
    $filter = "system.applicationHost/sites/site[@name='$SiteName']/bindings/binding[@protocol='http' and @bindingInformation='*:80:']"
    $match  = Get-WebConfiguration -pspath 'MACHINE/WEBROOT/APPHOST' -filter $filter -ErrorAction SilentlyContinue

    if ($null -eq $match) {
        $messages.Add("No bare HTTP '*:80:' binding found for '$SiteName' - host header already set or binding not present.")
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

    if ($WhatIf) {
        $messages.Add("[WhatIf] Would update bindingInformation from '*:80:' to '*:80:$HostHeader' for site '$SiteName'.")
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

    try {
        Set-WebConfigurationProperty `
            -pspath 'MACHINE/WEBROOT/APPHOST' `
            -filter $filter `
            -name  'bindingInformation' `
            -value "*:80:$HostHeader" `
            -ErrorAction Stop
        $messages.Add("Updated host header for site '$SiteName' to '$HostHeader' on HTTP :80.")
    } catch {
        $messages.Add("Failed to update host header for site '$SiteName'. Error: $($_.Exception.Message)")
        return [PSCustomObject]@{
            CISRef      = $cisRef
            Description = $desc
            Level       = $level
            Before      = $beforeState
            After       = 'bindingInformation=SetFailed'
            Status      = 'Fail'
            Messages    = $messages.ToArray()
        }
    }

    $afterBindings = Get-WebBinding -ErrorAction SilentlyContinue
    $afterState    = if ($afterBindings) {
        ($afterBindings | ForEach-Object { "$($_.protocol) $($_.bindingInformation)" }) -join '; '
    } else { 'No bindings found' }

    return [PSCustomObject]@{
        CISRef      = $cisRef
        Description = $desc
        Level       = $level
        Before      = $beforeState
        After       = $afterState
        Status      = 'Pass'
        Messages    = $messages.ToArray()
    }
}
