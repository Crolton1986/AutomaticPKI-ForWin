function New-APKIAdcsCepResult {
    <#
    .SYNOPSIS
        Builds a ProviderResult (docs/contracts.md) for the AdcsCep provider. In-memory object only.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Creates an in-memory object only.')]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Issued', 'Pending', 'Denied', 'Failed')]
        [string]$Status,

        [string]$Thumbprint,

        [string]$RequestId,

        [string]$Message
    )

    $thumb = $null
    if ($Thumbprint) { $thumb = $Thumbprint.ToUpperInvariant() }
    $reqId = $null
    if ($RequestId) { $reqId = $RequestId }
    $msg = ''
    if ($Message) { $msg = $Message }

    [pscustomobject]@{
        Status     = $Status
        Thumbprint = $thumb
        RequestId  = $reqId
        Message    = $msg
    }
}
