function Test-APKISiteState {
    <#
    .SYNOPSIS
        Checks that an IIS site and its application pools are Started, starting them if not.
    .DESCRIPTION
        Application pools are started before the site. With -WhatIf nothing is started and a
        stopped object is reported as failed ("would start").
    .OUTPUTS
        Health check results: one 'AppPoolState' per pool (Target = pool name) and one
        'SiteState' (Target = site name).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$SiteName,

        # Seconds to wait for an object reported as 'Starting' to reach 'Started'.
        [ValidateRange(0, 300)]
        [int]$StartWaitSec = 10
    )

    $results = New-Object System.Collections.Generic.List[object]

    try {
        $state = Get-APKIHealthSiteState -SiteName $SiteName
    }
    catch {
        $results.Add((New-APKIHealthResult -Check 'SiteState' -Target $SiteName -Passed $false -Detail ('Could not read IIS state: {0}' -f $_.Exception.Message)))
        return $results.ToArray()
    }
    if ($null -eq $state) {
        $results.Add((New-APKIHealthResult -Check 'SiteState' -Target $SiteName -Passed $false -Detail 'IIS site not found.'))
        return $results.ToArray()
    }

    foreach ($pool in @($state.AppPools)) {
        $poolName = [string]$pool.Name
        $poolState = [string]$pool.State
        if ($poolState -eq 'Started') {
            $results.Add((New-APKIHealthResult -Check 'AppPoolState' -Target $poolName -Passed $true -Detail 'Started.'))
            continue
        }
        if ($poolState -eq 'Missing') {
            $results.Add((New-APKIHealthResult -Check 'AppPoolState' -Target $poolName -Passed $false -Detail "Application pool used by site '$SiteName' does not exist."))
            continue
        }
        if (-not $PSCmdlet.ShouldProcess("IIS application pool '$poolName'", 'Start')) {
            $results.Add((New-APKIHealthResult -Check 'AppPoolState' -Target $poolName -Passed $false -Detail "State $poolState; would start (WhatIf)."))
            continue
        }
        try {
            $newState = [string](Start-APKIHealthAppPool -Name $poolName -Confirm:$false)
            $waited = 0
            while ($newState -ne 'Started' -and $waited -lt $StartWaitSec) {
                Start-Sleep -Seconds 1
                $waited++
                $reread = Get-APKIHealthSiteState -SiteName $SiteName
                if ($reread) {
                    $match = @($reread.AppPools | Where-Object { $_.Name -eq $poolName }) | Select-Object -First 1
                    if ($match) {
                        $newState = [string]$match.State
                    }
                }
            }
            $ok = ($newState -eq 'Started')
            $results.Add((New-APKIHealthResult -Check 'AppPoolState' -Target $poolName -Passed $ok -Detail "Was $poolState; start attempted, now $newState."))
        }
        catch {
            $results.Add((New-APKIHealthResult -Check 'AppPoolState' -Target $poolName -Passed $false -Detail ("Was {0}; start failed: {1}" -f $poolState, $_.Exception.Message)))
        }
    }

    $siteState = [string]$state.State
    if ($siteState -eq 'Started') {
        $results.Add((New-APKIHealthResult -Check 'SiteState' -Target $SiteName -Passed $true -Detail 'Started.'))
    }
    elseif (-not $PSCmdlet.ShouldProcess("IIS site '$SiteName'", 'Start')) {
        $results.Add((New-APKIHealthResult -Check 'SiteState' -Target $SiteName -Passed $false -Detail "State $siteState; would start (WhatIf)."))
    }
    else {
        try {
            $newState = [string](Start-APKIHealthSite -SiteName $SiteName -Confirm:$false)
            $waited = 0
            while ($newState -ne 'Started' -and $waited -lt $StartWaitSec) {
                Start-Sleep -Seconds 1
                $waited++
                $reread = Get-APKIHealthSiteState -SiteName $SiteName
                if ($reread) {
                    $newState = [string]$reread.State
                }
            }
            $ok = ($newState -eq 'Started')
            $results.Add((New-APKIHealthResult -Check 'SiteState' -Target $SiteName -Passed $ok -Detail "Was $siteState; start attempted, now $newState."))
        }
        catch {
            $results.Add((New-APKIHealthResult -Check 'SiteState' -Target $SiteName -Passed $false -Detail ("Was {0}; start failed: {1}" -f $siteState, $_.Exception.Message)))
        }
    }

    $results.ToArray()
}
