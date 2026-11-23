function Start-APKIHealthAppPool {
    <#
    .SYNOPSIS
        Starts an IIS application pool via Microsoft.Web.Administration (mock target).
    .OUTPUTS
        [string] ObjectState returned by ApplicationPool.Start().
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    if (-not $PSCmdlet.ShouldProcess("IIS application pool '$Name'", 'Start')) {
        return
    }
    $manager = Get-APKIServerManager
    $pool = $manager.ApplicationPools[$Name]
    if ($null -eq $pool) {
        throw "IIS application pool '$Name' not found."
    }
    [string]$pool.Start()
}
