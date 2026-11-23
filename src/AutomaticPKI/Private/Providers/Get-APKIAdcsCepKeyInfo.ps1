function Get-APKIAdcsCepKeyInfo {
    <#
    .SYNOPSIS
        Returns the public key algorithm and size of an issued certificate, in Order.Key terms.
    .DESCRIPTION
        Used after a CEP enrollment to warn when the template produced a different key than
        Order.Key asks for (Get-Certificate cannot set key parameters itself).
        Returns $null when the input is not an X509Certificate2 (e.g. a deserialized object
        under PowerShell 7 Windows compatibility) or the key type is unknown.
    .OUTPUTS
        PSCustomObject: Algorithm ('RSA', 'ECDSA_P256', 'ECDSA_P384', ...), Length (bits).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Certificate
    )

    if (-not ($Certificate -is [System.Security.Cryptography.X509Certificates.X509Certificate2])) {
        return $null
    }

    $oid = [string]$Certificate.PublicKey.Oid.Value
    switch ($oid) {
        '1.2.840.113549.1.1.1' {
            $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($Certificate)
            try {
                return [pscustomobject]@{ Algorithm = 'RSA'; Length = [int]$rsa.KeySize }
            }
            finally {
                if ($null -ne $rsa) { $rsa.Dispose() }
            }
        }
        '1.2.840.10045.2.1' {
            $ecdsa = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($Certificate)
            try {
                $size = [int]$ecdsa.KeySize
                return [pscustomobject]@{ Algorithm = "ECDSA_P$size"; Length = $size }
            }
            finally {
                if ($null -ne $ecdsa) { $ecdsa.Dispose() }
            }
        }
        default {
            return $null
        }
    }
}
