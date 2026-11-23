function Set-APKIObjectProperty {
    <#
    .SYNOPSIS
        Sets a property on a PSCustomObject, adding it when missing (safe under StrictMode 3.0).
    .DESCRIPTION
        Uses PSNoteProperty so $null and empty arrays are stored as given.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Changes an in-memory object only.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name,

        [AllowNull()]
        [object]$Value
    )

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        $InputObject.PSObject.Properties.Add([System.Management.Automation.PSNoteProperty]::new($Name, $Value))
    }
    else {
        $property.Value = $Value
    }
}
