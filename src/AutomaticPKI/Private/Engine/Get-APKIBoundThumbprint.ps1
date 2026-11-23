function Get-APKIBoundThumbprint {
    <#
    .SYNOPSIS
        Returns the thumbprints of every certificate bound to any IIS https binding.
    .DESCRIPTION
        Reads all sites through Get-APKIIisBinding. Throws when IIS cannot be read, so callers
        that delete certificates can refuse to delete when they cannot prove a cert is unused.
    .OUTPUTS
        [string] normalized (upper-case hex) thumbprints, unique.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $list = New-Object System.Collections.Generic.List[string]
    foreach ($binding in @(Get-APKIIisBinding)) {
        if ([string](Get-APKIOptionalProperty -InputObject $binding -Name 'Protocol' -Default '') -ne 'https') {
            continue
        }
        $thumb = ConvertTo-APKINormalizedThumbprint -Thumbprint ([string](Get-APKIOptionalProperty -InputObject $binding -Name 'Thumbprint' -Default ''))
        if ($thumb -and -not $list.Contains($thumb)) {
            $list.Add($thumb)
        }
    }
    $list.ToArray()
}
