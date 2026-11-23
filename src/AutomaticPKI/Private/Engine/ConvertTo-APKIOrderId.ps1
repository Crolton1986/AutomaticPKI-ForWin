function ConvertTo-APKIOrderId {
    <#
    .SYNOPSIS
        Builds the order Id slug for an IIS site name (the one shared slug rule, docs/contracts.md).
    .DESCRIPTION
        Lower-case; every run of characters other than a-z and 0-9 becomes one '-'; leading and
        trailing '-' removed; at most 120 characters (room for a '-<n>' de-duplication suffix).
        An empty result becomes 'site'; a Windows device name (con, nul, com1, ...) gets '-site'
        appended. The result always passes Assert-APKISafeName.
    .EXAMPLE
        ConvertTo-APKIOrderId -SiteName 'Default Web Site'   # default-web-site
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$SiteName
    )

    $id = ($SiteName.ToLowerInvariant() -replace '[^a-z0-9]+', '-').Trim('-')
    if ($id.Length -gt 120) {
        $id = $id.Substring(0, 120).TrimEnd('-')
    }
    if (-not $id) {
        $id = 'site'
    }
    if ($id -match '^(con|prn|aux|nul|com[0-9]|lpt[0-9])$') {
        $id = '{0}-site' -f $id
    }
    Assert-APKISafeName -Name $id -Kind 'order Id'
    $id
}
