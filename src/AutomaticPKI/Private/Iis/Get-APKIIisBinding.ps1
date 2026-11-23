function Get-APKIIisBinding {
    <#
    .SYNOPSIS
        Lists http/https bindings as contract Binding objects (docs/contracts.md).
    .DESCRIPTION
        Reads every site so SharedWith can be computed: for an https binding without the SNI flag,
        SharedWith lists the other sites that also have a non-SNI https binding on the same IP:port
        (they share one http.sys certificate). NameStatus comes from Get-APKIBindingNameStatus.
        Other protocols (ftp, net.tcp, ...) are ignored. Output also carries BindingInformation.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string]$SiteName,

        # Microsoft.Web.Administration.ServerManager (or a test fake). Default: Get-APKIServerManager.
        [object]$ServerManager
    )

    if (-not $ServerManager) {
        $ServerManager = Get-APKIServerManager
    }

    $all = New-Object System.Collections.Generic.List[object]
    foreach ($site in @($ServerManager.Sites)) {
        $name = [string]$site.Name
        foreach ($b in @($site.Bindings)) {
            $protocol = ([string]$b.Protocol).ToLowerInvariant()
            if ($protocol -ne 'http' -and $protocol -ne 'https') {
                continue
            }
            $all.Add((ConvertFrom-APKIIisBinding -SiteName $name -Binding $b))
        }
    }

    foreach ($raw in $all) {
        if ($SiteName -and $raw.SiteName -ne $SiteName) {
            continue
        }

        $shared = New-Object System.Collections.Generic.List[string]
        if ($raw.Protocol -eq 'https' -and ($raw.SslFlags -band 1) -eq 0) {
            foreach ($other in $all) {
                if ($other.SiteName -eq $raw.SiteName -or $other.Protocol -ne 'https') {
                    continue
                }
                if (($other.SslFlags -band 1) -ne 0) {
                    continue
                }
                if ($other.IPAddress -eq $raw.IPAddress -and $other.Port -eq $raw.Port -and -not $shared.Contains($other.SiteName)) {
                    $shared.Add($other.SiteName)
                }
            }
        }

        $nameStatus = Get-APKIBindingNameStatus -Binding $raw

        [pscustomobject]@{
            SiteName           = $raw.SiteName
            Protocol           = $raw.Protocol
            IPAddress          = $raw.IPAddress
            Port               = $raw.Port
            HostHeader         = $raw.HostHeader
            SslFlags           = $raw.SslFlags
            Thumbprint         = $raw.Thumbprint
            StoreName          = $raw.StoreName
            NameStatus         = $nameStatus.NameStatus
            SharedWith         = [string[]]$shared.ToArray()
            BindingInformation = $raw.BindingInformation
        }
    }
}
