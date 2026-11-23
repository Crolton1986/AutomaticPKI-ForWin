function Get-APKIHealthSiteState {
    <#
    .SYNOPSIS
        Reads the runtime state of an IIS site and the application pools its applications use (mock target).
    .DESCRIPTION
        Uses Microsoft.Web.Administration via Get-APKIServerManager (IIS layer). The ServerManager
        is not disposed here because its lifetime belongs to Get-APKIServerManager.
    .OUTPUTS
        $null if the site does not exist, else PSCustomObject:
        SiteName, State (ObjectState name or 'Unknown'), AppPools (@{ Name; State } ...,
        State 'Missing' if the pool is not defined).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$SiteName
    )

    $manager = Get-APKIServerManager
    $site = $manager.Sites[$SiteName]
    if ($null -eq $site) {
        return $null
    }

    # State reads go to the WAS runtime and throw (COMException) when W3SVC/WAS is not running.
    $siteState = 'Unknown'
    try {
        $siteState = [string]$site.State
    }
    catch {
        $siteState = 'Unknown'
    }

    $poolNames = New-Object System.Collections.Generic.List[string]
    foreach ($app in $site.Applications) {
        $name = [string]$app.ApplicationPoolName
        if (-not $name) {
            $name = [string]$site.ApplicationDefaults.ApplicationPoolName
        }
        if ($name -and -not $poolNames.Contains($name)) {
            $poolNames.Add($name)
        }
    }

    $pools = @(
        foreach ($poolName in $poolNames) {
            $pool = $manager.ApplicationPools[$poolName]
            $poolState = 'Missing'
            if ($null -ne $pool) {
                try {
                    $poolState = [string]$pool.State
                }
                catch {
                    $poolState = 'Unknown'
                }
            }
            [pscustomobject]@{
                Name  = $poolName
                State = $poolState
            }
        }
    )

    [pscustomobject]@{
        SiteName = $SiteName
        State    = $siteState
        AppPools = $pools
    }
}
