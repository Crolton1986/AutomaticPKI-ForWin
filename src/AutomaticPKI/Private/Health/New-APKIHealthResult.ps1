function New-APKIHealthResult {
    <#
    .SYNOPSIS
        Builds a health check result in the shape fixed by docs/contracts.md.
    .NOTES
        New-* here only creates an in-memory object; nothing on the system changes.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Creates an in-memory object only.')]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$Check,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Target,

        [Parameter(Mandatory)]
        [bool]$Passed,

        [AllowEmptyString()]
        [string]$Detail = ''
    )

    [pscustomobject]@{
        Check  = $Check
        Target = $Target
        Passed = $Passed
        Detail = $Detail
    }
}
