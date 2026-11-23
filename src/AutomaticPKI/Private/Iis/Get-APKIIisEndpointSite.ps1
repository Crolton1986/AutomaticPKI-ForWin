function Get-APKIIisEndpointSite {
    <#
    .SYNOPSIS
        Names of other sites holding a non-SNI https binding on the given IP:port.
    .DESCRIPTION
        Non-SNI https bindings on the same IP:port share one http.sys certificate entry, so changing
        or deleting it affects all of them.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [object]$ServerManager,

        [Parameter(Mandatory)]
        [string]$IPAddress,

        [Parameter(Mandatory)]
        [int]$Port,

        # Site to leave out of the result.
        [string]$ExcludeSite = ''
    )

    $names = New-Object System.Collections.Generic.List[string]
    foreach ($site in @($ServerManager.Sites)) {
        $name = [string]$site.Name
        if ($name -eq $ExcludeSite) {
            continue
        }
        foreach ($b in @($site.Bindings)) {
            if ([string]$b.Protocol -ne 'https') {
                continue
            }
            $flags = 0
            try {
                $flags = [int]$b.SslFlags
            }
            catch {
                $flags = 0
            }
            if (($flags -band 1) -ne 0) {
                continue
            }
            $parts = Split-APKIBindingInformation -BindingInformation ([string]$b.BindingInformation)
            if ($parts.IPAddress -eq $IPAddress -and $parts.Port -eq $Port -and -not $names.Contains($name)) {
                $names.Add($name)
            }
        }
    }
    , $names.ToArray()
}
