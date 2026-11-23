function Invoke-APKIProviderReceive {
    <#
    .SYNOPSIS
        Calls Receive-APKI<Order.Provider>Certificate for a pending request.
    .DESCRIPTION
        RequestId defaults to Order.PendingRequestId. Unknown or missing provider, or no request
        ID: logs EventId 3004 and returns a Failed ProviderResult. Returns nothing under -WhatIf.
    .OUTPUTS
        ProviderResult (docs/contracts.md).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$Order,

        [string]$RequestId
    )

    if (-not $RequestId) {
        $RequestId = [string](Get-APKIOptionalProperty -InputObject $Order -Name 'PendingRequestId' -Default '')
    }
    $orderId = [string](Get-APKIOptionalProperty -InputObject $Order -Name 'Id' -Default '')
    $provider = [string](Get-APKIOptionalProperty -InputObject $Order -Name 'Provider' -Default '')

    $message = 'No pending request ID to retrieve.'
    if ($RequestId) {
        switch -CaseSensitive ($provider) {
            'AdcsRpc' { return (Receive-APKIAdcsRpcCertificate -Order $Order -RequestId $RequestId) }
            'AdcsCep' { return (Receive-APKIAdcsCepCertificate -Order $Order -RequestId $RequestId) }
        }
        $message = "Unknown certificate provider '$provider'; expected 'AdcsRpc' or 'AdcsCep'."
    }

    Write-APKILog -Message $message -Level Error -EventId 3004 -OrderId $orderId
    [pscustomobject]@{
        Status     = 'Failed'
        Thumbprint = $null
        RequestId  = $null
        Message    = $message
    }
}
