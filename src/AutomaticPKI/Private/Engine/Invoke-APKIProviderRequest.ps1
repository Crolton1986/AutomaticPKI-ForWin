function Invoke-APKIProviderRequest {
    <#
    .SYNOPSIS
        Calls Request-APKI<Order.Provider>Certificate for an order.
    .DESCRIPTION
        Unknown or missing provider: logs EventId 3004 and returns a Failed ProviderResult.
        Returns nothing when the provider skipped the request (-WhatIf).
    .OUTPUTS
        ProviderResult (docs/contracts.md).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$Order
    )

    $provider = [string](Get-APKIOptionalProperty -InputObject $Order -Name 'Provider' -Default '')
    switch -CaseSensitive ($provider) {
        'AdcsRpc' { return (Request-APKIAdcsRpcCertificate -Order $Order) }
        'AdcsCep' { return (Request-APKIAdcsCepCertificate -Order $Order) }
    }

    $orderId = [string](Get-APKIOptionalProperty -InputObject $Order -Name 'Id' -Default '')
    $message = "Unknown certificate provider '$provider'; expected 'AdcsRpc' or 'AdcsCep'."
    Write-APKILog -Message $message -Level Error -EventId 3004 -OrderId $orderId
    [pscustomobject]@{
        Status     = 'Failed'
        Thumbprint = $null
        RequestId  = $null
        Message    = $message
    }
}
