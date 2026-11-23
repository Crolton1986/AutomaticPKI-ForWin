function Get-APKICertificateFileInfo {
    <#
    .SYNOPSIS
        Reads thumbprint and serial number of a public certificate file (.cer, base64 or DER).
        Wrapped so tests can mock it.
    .OUTPUTS
        [pscustomobject] @{ Thumbprint; SerialNumber }, or nothing when the file is unreadable.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    try {
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $Path
        [pscustomobject]@{
            Thumbprint   = $cert.Thumbprint.ToUpperInvariant()
            SerialNumber = $cert.SerialNumber.ToUpperInvariant()
        }
    }
    catch {
        Write-Verbose "Get-APKICertificateFileInfo: cannot read '$Path': $($_.Exception.Message)"
    }
}
