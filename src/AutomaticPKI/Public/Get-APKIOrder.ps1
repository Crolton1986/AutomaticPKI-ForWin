function Get-APKIOrder {
    <#
    .SYNOPSIS
        Lists certificate orders.
    .DESCRIPTION
        Reads orders from the order store (%ProgramData%\AutomaticPKI\orders). Invalid order files
        are logged (EventId 3004) and skipped.
    .PARAMETER Id
        Return only this order. Writes an error when it does not exist.
    .PARAMETER Status
        Return only orders with this status.
    .EXAMPLE
        Get-APKIOrder

        Lists every order.
    .EXAMPLE
        Get-APKIOrder -Status Proposed | Format-Table Id, SiteName, Hostnames, NameStatus

        Shows what discovery proposed and still needs approval.
    .OUTPUTS
        PSCustomObject order (docs/contracts.md).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Position = 0, ValueFromPipelineByPropertyName)]
        [string]$Id,

        [ValidateSet('Proposed', 'Approved', 'Pending', 'Active', 'Failed', 'Disabled')]
        [string]$Status
    )

    process {
        $orders = @()
        if ($Id) {
            $orders = @(Get-APKIOrderData -Id $Id)
            if ($orders.Count -eq 0) {
                Write-Error -Message "Order '$Id' does not exist." -Category ObjectNotFound -TargetObject $Id
                return
            }
        }
        else {
            $orders = @(Get-APKIOrderData)
        }

        foreach ($order in $orders) {
            if (-not $Status -or [string]$order.Status -ceq $Status) {
                $order
            }
        }
    }
}
