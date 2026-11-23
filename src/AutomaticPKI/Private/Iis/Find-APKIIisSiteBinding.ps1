function Find-APKIIisSiteBinding {
    <#
    .SYNOPSIS
        Locates the live site and binding object that match a contract Binding.
    .DESCRIPTION
        Match is on site name, protocol, IP, port and host header (host header case-insensitive).
        Returns [pscustomobject] Site (null when the site does not exist) and Binding (null when no
        matching binding exists).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$ServerManager,

        [Parameter(Mandatory)]
        [string]$SiteName,

        [string]$Protocol = 'https',

        [string]$IPAddress = '*',

        [Parameter(Mandatory)]
        [int]$Port,

        [AllowEmptyString()]
        [string]$HostHeader = ''
    )

    $foundSite = $null
    $foundBinding = $null
    foreach ($site in $ServerManager.Sites) {
        if ([string]$site.Name -ne $SiteName) {
            continue
        }
        $foundSite = $site
        foreach ($b in $site.Bindings) {
            if ([string]$b.Protocol -ne $Protocol) {
                continue
            }
            $parts = Split-APKIBindingInformation -BindingInformation ([string]$b.BindingInformation)
            if ($parts.IPAddress -eq $IPAddress -and $parts.Port -eq $Port -and $parts.HostHeader -eq $HostHeader) {
                $foundBinding = $b
                break
            }
        }
        break
    }

    [pscustomobject]@{
        Site    = $foundSite
        Binding = $foundBinding
    }
}
