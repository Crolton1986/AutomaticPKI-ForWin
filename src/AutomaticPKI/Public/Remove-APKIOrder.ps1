function Remove-APKIOrder {
    <#
    .SYNOPSIS
        Deletes a certificate order.
    .DESCRIPTION
        Removes orders\<Id>.json. Certificates and IIS bindings are left as they are; the site
        keeps serving its current certificate but is no longer renewed.
    .PARAMETER Id
        Order Id.
    .EXAMPLE
        Remove-APKIOrder -Id old-site

        Stops managing the certificate of the site 'old-site' (asks for confirmation with -Confirm).
    .EXAMPLE
        Get-APKIOrder -Status Proposed | Remove-APKIOrder -WhatIf

        Shows which proposed orders would be removed.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [string]$Id
    )

    process {
        $order = Get-APKIOrderData -Id $Id
        if ($null -eq $order) {
            Write-Error -Message "Order '$Id' does not exist." -Category ObjectNotFound -TargetObject $Id
            return
        }
        if ($PSCmdlet.ShouldProcess("order '$Id' (site '$($order.SiteName)')", 'Remove')) {
            Remove-APKIOrderData -Id $Id -Confirm:$false
        }
    }
}
