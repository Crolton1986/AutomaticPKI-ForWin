function Get-APKICertificateDnsName {
    <#
    .SYNOPSIS
        Returns the DNS names (SANs) of a certificate in Cert:\LocalMachine\<StoreName>.
    .DESCRIPTION
        Thin wrapper around the certificate provider so tests can Mock it. Uses the DnsNameList
        property the PKI type data adds to certificates (SAN dNSName entries, or the subject CN when
        the certificate has no SAN extension). Returns an empty array when the certificate is missing.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [string]$Thumbprint,

        [string]$StoreName = 'My'
    )

    $names = New-Object System.Collections.Generic.List[string]
    $path = 'Cert:\LocalMachine\{0}\{1}' -f $StoreName, $Thumbprint
    $cert = $null
    try {
        $cert = Get-Item -LiteralPath $path -ErrorAction Stop
    }
    catch {
        Write-APKILog -Message "Certificate $Thumbprint not found in LocalMachine\$StoreName." -Level Info
    }
    if (-not $cert) {
        return $names.ToArray()
    }

    if ($cert.PSObject.Properties['DnsNameList'] -and $cert.DnsNameList) {
        foreach ($entry in $cert.DnsNameList) {
            $value = $null
            if ($entry.PSObject.Properties['Punycode']) {
                $value = [string]$entry.Punycode
            }
            else {
                $value = [string]$entry
            }
            if ($value -and -not $names.Contains($value)) {
                $names.Add($value)
            }
        }
    }
    else {
        $cn = $cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::DnsName, $false)
        if ($cn) {
            $names.Add($cn)
        }
    }
    $names.ToArray()
}
