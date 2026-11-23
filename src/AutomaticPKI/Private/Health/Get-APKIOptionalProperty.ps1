function Get-APKIOptionalProperty {
    <#
    .SYNOPSIS
        Reads a property that may be missing (JSON-loaded objects); safe under StrictMode 3.0.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name,

        [AllowNull()]
        [object]$Default = $null
    )

    if ($null -eq $InputObject) {
        return $Default
    }
    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) {
            return $InputObject[$Name]
        }
        return $Default
    }
    $prop = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $prop) {
        return $Default
    }
    $prop.Value
}
