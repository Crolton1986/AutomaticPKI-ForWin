function Remove-APKIMachineCertificate {
    <#
    .SYNOPSIS
        Deletes a certificate and its private key from Cert:\LocalMachine\My (mock target).
    .DESCRIPTION
        Does nothing when the certificate is not in the store. Callers are responsible for
        checking that no IIS binding uses it.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory)]
        [string]$Thumbprint
    )

    $thumb = ConvertTo-APKINormalizedThumbprint -Thumbprint $Thumbprint
    if (-not $thumb) {
        throw "Invalid certificate thumbprint '$Thumbprint'."
    }
    $path = 'Cert:\LocalMachine\My\{0}' -f $thumb
    if (-not (Test-Path -LiteralPath $path)) {
        return
    }
    if ($PSCmdlet.ShouldProcess($path, 'Delete certificate and private key')) {
        Remove-Item -LiteralPath $path -DeleteKey -Force -ErrorAction Stop
    }
}
