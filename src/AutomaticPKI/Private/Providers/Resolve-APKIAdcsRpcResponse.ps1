function Resolve-APKIAdcsRpcResponse {
    <#
    .SYNOPSIS
        Turns parsed certreq -submit / -retrieve output into a ProviderResult, installing the
        certificate when it was issued. Logs with contract event IDs.
    .PARAMETER Retrieval
        Set for -retrieve. A request that is still pending is then logged without event 1002,
        which was already raised when the request was first submitted.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$Order,

        [Parameter(Mandatory)]
        [object]$Response,

        [Parameter(Mandatory)]
        [string]$CertificatePath,

        [AllowNull()]
        [string]$RequestId,

        [switch]$Retrieval
    )

    $orderId = $null
    if ($Order.PSObject.Properties['Id']) { $orderId = [string]$Order.Id }

    $rid = $Response.RequestId
    if (-not $rid) { $rid = $RequestId }
    $operation = 'submit'
    if ($Retrieval) { $operation = 'retrieve' }

    switch ($Response.Disposition) {
        'Issued' {
            return Complete-APKIAdcsRpcIssuance -Order $Order -CertificatePath $CertificatePath -RequestId $rid
        }
        'Pending' {
            if (-not $rid) {
                $msg = "CA reported the request as pending but certreq returned no RequestId: $($Response.Message)"
                Write-APKILog -Message $msg -Level Error -EventId 3000 -OrderId $orderId
                return New-APKIAdcsRpcResult -Status Failed -Message $msg
            }
            $msg = "Certificate request $rid is pending CA manager approval."
            if ($Retrieval) {
                Write-APKILog -Message $msg -Level Info -OrderId $orderId
            }
            else {
                Write-APKILog -Message $msg -Level Info -EventId 1002 -OrderId $orderId
            }
            return New-APKIAdcsRpcResult -Status Pending -RequestId $rid -Message $msg
        }
        'Denied' {
            $msg = "Certificate request $rid was denied by the CA: $($Response.Message)"
            Write-APKILog -Message $msg -Level Error -EventId 3001 -OrderId $orderId
            return New-APKIAdcsRpcResult -Status Denied -RequestId $rid -Message $msg
        }
        'Unavailable' {
            $msg = "CA unavailable during certreq -$operation ($($Response.ErrorCode)): $($Response.Message)"
            Write-APKILog -Message $msg -Level Error -EventId 3000 -OrderId $orderId
            return New-APKIAdcsRpcResult -Status Failed -RequestId $rid -Message $msg
        }
        'Error' {
            $msg = "certreq -$operation failed (exit $($Response.ExitCode)): $($Response.Message)"
            Write-APKILog -Message $msg -Level Error -EventId 3000 -OrderId $orderId
            return New-APKIAdcsRpcResult -Status Failed -RequestId $rid -Message $msg
        }
        default {
            $msg = "Unrecognised certreq -$operation output (exit $($Response.ExitCode)): $($Response.Message)"
            Write-APKILog -Message $msg -Level Error -EventId 3000 -OrderId $orderId
            return New-APKIAdcsRpcResult -Status Failed -RequestId $rid -Message $msg
        }
    }
}
