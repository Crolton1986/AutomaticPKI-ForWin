function Find-APKIMachineCertificate {
    <#
    .SYNOPSIS
        Looks up a certificate with a private key in Cert:\LocalMachine\My by thumbprint or serial.
        Wraps the certificate store so tests can mock it.
    .OUTPUTS
        The first matching X509Certificate2, or nothing.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Thumbprint')]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Thumbprint')]
        [string]$Thumbprint,

        [Parameter(Mandatory, ParameterSetName = 'Serial')]
        [string]$SerialNumber
    )

    $certs = @(Get-ChildItem -Path 'Cert:\LocalMachine\My' -ErrorAction SilentlyContinue)
    if ($PSCmdlet.ParameterSetName -eq 'Thumbprint') {
        $want = ($Thumbprint -replace '\s', '').ToUpperInvariant()
        $match = @($certs | Where-Object { $_.Thumbprint -eq $want -and $_.HasPrivateKey })
    }
    else {
        $want = ($SerialNumber -replace '\s', '').ToUpperInvariant()
        $match = @($certs | Where-Object { $_.SerialNumber -eq $want -and $_.HasPrivateKey } |
                Sort-Object -Property NotBefore -Descending)
    }
    if ($match.Count -gt 0) { $match[0] }
}
