function Start-APKIHealthSite {
    <#
    .SYNOPSIS
        Starts an IIS site via Microsoft.Web.Administration (mock target).
    .OUTPUTS
        [string] ObjectState returned by Site.Start() ('Started', 'Starting', ...).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$SiteName
    )

    if (-not $PSCmdlet.ShouldProcess("IIS site '$SiteName'", 'Start')) {
        return
    }
    $manager = Get-APKIServerManager
    $site = $manager.Sites[$SiteName]
    if ($null -eq $site) {
        throw "IIS site '$SiteName' not found."
    }
    [string]$site.Start()
}
