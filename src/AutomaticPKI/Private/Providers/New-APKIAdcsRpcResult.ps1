function New-APKIAdcsRpcResult {
    <#
    .SYNOPSIS
        Builds a ProviderResult (docs/contracts.md) for the AdcsRpc provider. Pure function.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Pure function: returns an object, changes no state.')]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Issued', 'Pending', 'Denied', 'Failed')]
        [string]$Status,

        [AllowNull()]
        [string]$Thumbprint,

        [AllowNull()]
        [string]$RequestId,

        [AllowNull()]
        [string]$Message
    )

    $tp = $null
    if ($Thumbprint) { $tp = $Thumbprint }
    $rid = $null
    if ($RequestId) { $rid = $RequestId }

    [pscustomobject]@{
        Status     = $Status
        Thumbprint = $tp
        RequestId  = $rid
        Message    = $Message
    }
}
