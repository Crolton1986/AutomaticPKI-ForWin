function ConvertTo-APKINormalizedThumbprint {
    <#
    .SYNOPSIS
        Upper-case hex thumbprint without spaces or invisible characters (MMC copy/paste adds U+200E).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Thumbprint
    )

    if (-not $Thumbprint) {
        return ''
    }
    ($Thumbprint -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
}
