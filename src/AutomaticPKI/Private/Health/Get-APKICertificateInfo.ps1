function Get-APKICertificateInfo {
    <#
    .SYNOPSIS
        Flattens the parts of an X509Certificate2 that the precheck needs (mock target).
    .OUTPUTS
        PSCustomObject: Thumbprint, Subject, HasPrivateKey, NotBefore, NotAfter,
        DnsNames (string[] from SAN), HasEku (bool), Ekus (string[] OID values).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        # X509Certificate2. Typed [object] so tests can pass fakes to the mocked command.
        [Parameter(Mandatory)]
        [object]$Certificate
    )

    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    $dnsNames = @()
    $hasEku = $false
    $ekus = @()

    foreach ($ext in $cert.Extensions) {
        $oid = $ext.Oid.Value
        if ($oid -eq '2.5.29.17') {
            $dnsNames = @(ConvertFrom-APKISanExtension -RawData $ext.RawData)
        }
        elseif ($oid -eq '2.5.29.37') {
            $hasEku = $true
            $ekuExt = $ext
            if ($ekuExt -isnot [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
                $ekuExt = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($ext, $ext.Critical)
            }
            $ekus = @($ekuExt.EnhancedKeyUsages | ForEach-Object { $_.Value })
        }
    }

    [pscustomobject]@{
        Thumbprint    = $cert.Thumbprint
        Subject       = $cert.Subject
        HasPrivateKey = [bool]$cert.HasPrivateKey
        NotBefore     = $cert.NotBefore
        NotAfter      = $cert.NotAfter
        DnsNames      = $dnsNames
        HasEku        = $hasEku
        Ekus          = $ekus
    }
}
