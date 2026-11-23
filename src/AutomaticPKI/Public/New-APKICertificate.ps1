function New-APKICertificate {
    <#
    .SYNOPSIS
        Runs one order now: requests (or collects) a certificate, binds it with health check and
        rollback, and saves the order.
    .DESCRIPTION
        Same logic as the scheduled renewal for a single order. An Active order whose certificate
        is not due yet is left alone unless -Force is given. A Pending order collects its pending
        request. Proposed and Disabled orders are refused; approve them with Approve-APKIOrder.
    .PARAMETER Id
        Order Id.
    .PARAMETER Force
        Request a new certificate even when the current one is not due for renewal.
    .EXAMPLE
        New-APKICertificate -Id contoso-web

        Issues and binds the first certificate for an approved order.
    .EXAMPLE
        New-APKICertificate -Id contoso-web -Force

        Replaces the current certificate now, for example after changing hostnames.
    .OUTPUTS
        PSCustomObject: OrderId, Outcome (Renewed|Pending|Failed|NotDue|Skipped), Status,
        Thumbprint, Message, Order.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [string]$Id,

        [switch]$Force
    )

    process {
        $order = Get-APKIOrderData -Id $Id
        if ($null -eq $order) {
            throw "Order '$Id' does not exist."
        }
        $status = [string]$order.Status
        if (@('Proposed', 'Disabled') -ccontains $status) {
            throw "Order '$Id' is $status. Approve it first with Approve-APKIOrder -Id $Id."
        }
        if ($PSCmdlet.ShouldProcess("order '$Id' (site '$($order.SiteName)')", 'Request and bind certificate')) {
            Invoke-APKIOrderRenewal -Order $order -Force:$Force
        }
    }
}
