function Get-APKIHealthCertificate {
    <#
    .SYNOPSIS
        Returns a certificate from a LocalMachine store by thumbprint, or $null (mock target).
    #>
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    param(
        [Parameter(Mandatory)]
        [string]$Thumbprint,

        [ValidateSet('My', 'WebHosting')]
        [string]$StoreName = 'My'
    )

    $normalized = ConvertTo-APKINormalizedThumbprint -Thumbprint $Thumbprint
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store -ArgumentList $StoreName, ([System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
    try {
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
        $found = $store.Certificates.Find([System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $normalized, $false)
        if ($found.Count -gt 0) {
            return $found[0]
        }
        return $null
    }
    finally {
        $store.Close()
    }
}
