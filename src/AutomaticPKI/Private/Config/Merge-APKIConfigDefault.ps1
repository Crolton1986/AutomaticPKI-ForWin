function Merge-APKIConfigDefault {
    <#
    .SYNOPSIS
        Adds every key from Default that is missing on InputObject, recursing into nested objects.
    .DESCRIPTION
        Existing values (and unknown keys) are kept. A nested object that is null on InputObject
        is replaced by the default object. Modifies InputObject in place and returns it.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [object]$Default
    )

    foreach ($defaultProperty in @($Default.PSObject.Properties)) {
        $existing = $InputObject.PSObject.Properties[$defaultProperty.Name]
        $defaultIsObject = $defaultProperty.Value -is [System.Management.Automation.PSCustomObject]

        if ($null -eq $existing) {
            # PSNoteProperty instead of Add-Member so $null and empty-array defaults survive.
            $InputObject.PSObject.Properties.Add(
                [System.Management.Automation.PSNoteProperty]::new($defaultProperty.Name, $defaultProperty.Value))
        }
        elseif ($defaultIsObject -and $null -eq $existing.Value) {
            $existing.Value = $defaultProperty.Value
        }
        elseif ($defaultIsObject -and $existing.Value -is [System.Management.Automation.PSCustomObject]) {
            $null = Merge-APKIConfigDefault -InputObject $existing.Value -Default $defaultProperty.Value
        }
    }

    $InputObject
}
