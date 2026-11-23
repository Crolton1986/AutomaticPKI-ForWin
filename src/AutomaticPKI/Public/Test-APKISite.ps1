function Test-APKISite {
    <#
    .SYNOPSIS
        Health-checks an order's site against its current certificate, without changing anything.
    .DESCRIPTION
        Runs Invoke-APKIHealthCheck for Order.CurrentThumbprint: site and application pool state,
        TLS handshake per managed https binding (served certificate must match), and the HTTP
        probe when Order.HttpProbe.Enabled. Read-only: a stopped site or pool is reported, not
        started.
    .PARAMETER Id
        Order Id.
    .PARAMETER TimeoutSec
        Per-connection timeout.
    .EXAMPLE
        Test-APKISite -Id contoso-web

        Returns Passed, Thumbprint and the individual check results.
    .EXAMPLE
        (Test-APKISite -Id contoso-web).Results | Where-Object { -not $_.Passed }

        Lists only the failing checks.
    .OUTPUTS
        PSCustomObject: Passed, Thumbprint, Results (Check, Target, Passed, Detail).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [string]$Id,

        [ValidateRange(1, 600)]
        [int]$TimeoutSec = 10
    )

    process {
        $order = Get-APKIOrderData -Id $Id
        if ($null -eq $order) {
            throw "Order '$Id' does not exist."
        }
        $thumbprint = ConvertTo-APKINormalizedThumbprint -Thumbprint ([string](Get-APKIOptionalProperty -InputObject $order -Name 'CurrentThumbprint' -Default ''))
        if (-not $thumbprint) {
            throw "Order '$Id' has no current certificate to test."
        }

        # Read-only: the site-state check would otherwise start stopped sites and pools.
        # Set-Variable (local scope) instead of an assignment the analyzer reads as unused.
        Set-Variable -Name 'WhatIfPreference' -Value $true -Scope Local
        Invoke-APKIHealthCheck -Order $order -Thumbprint $thumbprint -TimeoutSec $TimeoutSec
    }
}
