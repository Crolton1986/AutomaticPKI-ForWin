function ConvertTo-APKIThumbprint {
    <#
    .SYNOPSIS
        Normalises a certificate hash to an upper-case hex thumbprint.
    .DESCRIPTION
        Accepts the byte[] CertificateHash of a Microsoft.Web.Administration binding (or any
        enumerable of bytes) or a thumbprint string (spaces, colons and invisible characters copied
        from the MMC are stripped). Returns '' for $null or an empty hash.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()]
        [object]$Hash
    )

    if ($null -eq $Hash) {
        return ''
    }
    if ($Hash -is [string]) {
        return ($Hash -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    }
    $sb = New-Object System.Text.StringBuilder
    foreach ($b in @($Hash)) {
        [void]$sb.Append(([byte]$b).ToString('X2'))
    }
    $sb.ToString()
}
