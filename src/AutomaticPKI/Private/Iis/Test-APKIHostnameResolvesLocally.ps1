function Test-APKIHostnameResolvesLocally {
    <#
    .SYNOPSIS
        True when the name resolves to at least one IP address of this host.
    .DESCRIPTION
        Names behind a load balancer or NAT legitimately resolve elsewhere, so callers only warn
        (EventId 2002) on $false.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    $resolved = @(Resolve-APKIDnsName -Name $Name)
    if ($resolved.Count -eq 0) {
        return $false
    }
    $local = New-Object System.Collections.Generic.List[string]
    foreach ($l in @(Get-APKILocalIPAddress)) {
        $parsed = $null
        if ([System.Net.IPAddress]::TryParse([string]$l, [ref]$parsed)) {
            $local.Add($parsed.ToString())
        }
    }
    foreach ($r in $resolved) {
        $parsed = $null
        if ([System.Net.IPAddress]::TryParse([string]$r, [ref]$parsed) -and $local.Contains($parsed.ToString())) {
            return $true
        }
    }
    return $false
}
