function Complete-APKIAdcsRpcIssuance {
    <#
    .SYNOPSIS
        Installs an issued certificate (certreq -accept -machine) and resolves its thumbprint.
    .DESCRIPTION
        -accept pairs the certificate with the private key that certreq -new left in the machine
        request store and puts it in Cert:\LocalMachine\My. The thumbprint is taken from the
        -accept output when present, else from the .cer file, else by serial number, and is
        always confirmed against the store (private key present).
        Called by Request-/Receive-APKIAdcsRpcCertificate after their ShouldProcess check.
    .OUTPUTS
        ProviderResult with Status Issued or Failed.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$Order,

        [Parameter(Mandatory)]
        [string]$CertificatePath,

        [AllowNull()]
        [string]$RequestId
    )

    $orderId = $null
    if ($Order.PSObject.Properties['Id']) { $orderId = [string]$Order.Id }

    if (-not (Test-Path -LiteralPath $CertificatePath)) {
        $msg = "CA reported request $RequestId as issued but certreq wrote no certificate file."
        Write-APKILog -Message $msg -Level Error -EventId 3000 -OrderId $orderId
        return New-APKIAdcsRpcResult -Status Failed -RequestId $RequestId -Message $msg
    }

    $accept = Invoke-APKICertreq -Arguments @('-accept', '-q', '-machine', $CertificatePath)
    $parsed = ConvertFrom-APKICertreqOutput -Output $accept.Output -ExitCode $accept.ExitCode
    if ($accept.ExitCode -ne 0) {
        $msg = "certreq -accept failed for request $RequestId (exit $($accept.ExitCode)): $($parsed.Message)"
        Write-APKILog -Message $msg -Level Error -EventId 3000 -OrderId $orderId
        return New-APKIAdcsRpcResult -Status Failed -RequestId $RequestId -Message $msg
    }

    $cert = $null
    if ($parsed.Thumbprint) {
        $cert = Find-APKIMachineCertificate -Thumbprint $parsed.Thumbprint
    }
    $fileInfo = $null
    if (-not $cert) {
        $fileInfo = Get-APKICertificateFileInfo -Path $CertificatePath
        if ($fileInfo -and $fileInfo.Thumbprint) {
            $cert = Find-APKIMachineCertificate -Thumbprint $fileInfo.Thumbprint
        }
    }
    if (-not $cert) {
        $serial = $parsed.SerialNumber
        if (-not $serial -and $fileInfo) { $serial = $fileInfo.SerialNumber }
        if ($serial) {
            $cert = Find-APKIMachineCertificate -SerialNumber $serial
        }
    }

    if (-not $cert) {
        $msg = "certreq -accept succeeded for request $RequestId but no certificate with a private key was found in Cert:\LocalMachine\My."
        Write-APKILog -Message $msg -Level Error -EventId 3000 -OrderId $orderId
        return New-APKIAdcsRpcResult -Status Failed -RequestId $RequestId -Message $msg
    }

    $thumb = ([string]$cert.Thumbprint).ToUpperInvariant()
    $msg = "Certificate issued for request $RequestId and installed in LocalMachine\My (thumbprint $thumb)."
    Write-APKILog -Message $msg -Level Info -OrderId $orderId
    New-APKIAdcsRpcResult -Status Issued -Thumbprint $thumb -RequestId $RequestId -Message $msg
}
