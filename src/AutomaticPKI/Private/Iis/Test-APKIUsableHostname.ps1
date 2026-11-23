function Test-APKIUsableHostname {
    <#
    .SYNOPSIS
        True when a name can go into a certificate order as a SAN.
    .DESCRIPTION
        Rejects: empty, localhost (and *.localhost), single-label names (no dot), IP literals
        (IPv4, IPv6 and the short numeric forms .NET also parses), any wildcard, names with an
        all-numeric last label and anything that is not a syntactically valid DNS name.
        A trailing dot is ignored.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Name
    )

    if (-not $Name) {
        return $false
    }
    $n = $Name.Trim().TrimEnd('.').ToLowerInvariant()
    if (-not $n) {
        return $false
    }
    if ($n.Contains('*')) {
        return $false
    }
    $ip = $null
    if ([System.Net.IPAddress]::TryParse($n.Trim([char[]]@('[', ']')), [ref]$ip)) {
        return $false
    }
    if ($n -eq 'localhost' -or $n.EndsWith('.localhost')) {
        return $false
    }
    if (-not $n.Contains('.')) {
        return $false
    }
    $labels = $n.Split('.')
    if ($labels[$labels.Length - 1] -match '^[0-9]+$') {
        return $false
    }
    if ($n.Length -gt 253) {
        return $false
    }
    $label = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
    return [bool]($n -match ('^{0}(?:\.{0})+$' -f $label))
}
