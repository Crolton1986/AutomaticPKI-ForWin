function ConvertTo-APKICertificateHash {
    <#
    .SYNOPSIS
        Converts a hex thumbprint into the byte[] that Microsoft.Web.Administration expects.
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]
        [string]$Thumbprint
    )

    $hex = ConvertTo-APKIThumbprint -Hash $Thumbprint
    if ($hex.Length -eq 0 -or ($hex.Length % 2) -ne 0) {
        throw "Invalid certificate thumbprint '$Thumbprint'."
    }
    $bytes = New-Object byte[] ($hex.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16)
    }
    , $bytes
}
