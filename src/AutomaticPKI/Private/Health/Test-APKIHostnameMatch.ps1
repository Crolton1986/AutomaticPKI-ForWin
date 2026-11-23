function Test-APKIHostnameMatch {
    <#
    .SYNOPSIS
        True if a certificate DNS name (exact or wildcard) covers a hostname.
    .DESCRIPTION
        Case-insensitive, trailing dot ignored. A wildcard is honoured only as the complete
        left-most label ("*.contoso.com") and matches exactly one label: it covers
        "www.contoso.com" but not "contoso.com" or "a.b.contoso.com". Partial-label wildcards
        ("w*.contoso.com") and wildcards directly over a single-label suffix ("*.com") never match.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Pattern,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$HostName
    )

    $p = $Pattern.Trim().TrimEnd('.').ToLowerInvariant()
    $h = $HostName.Trim().TrimEnd('.').ToLowerInvariant()
    if (-not $p -or -not $h) {
        return $false
    }

    if ($p.StartsWith('*.')) {
        $suffix = $p.Substring(1)    # ".contoso.com"
        if ($suffix.Contains('*')) {
            return $false
        }
        if ($suffix.Substring(1).IndexOf('.') -lt 0) {
            return $false
        }
        if (-not $h.EndsWith($suffix)) {
            return $false
        }
        $label = $h.Substring(0, $h.Length - $suffix.Length)
        return ($label.Length -gt 0 -and $label.IndexOf('.') -lt 0 -and $label.IndexOf('*') -lt 0)
    }

    if ($p.Contains('*')) {
        return $false
    }
    $p -eq $h
}
