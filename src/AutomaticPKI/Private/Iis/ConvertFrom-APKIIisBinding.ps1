function ConvertFrom-APKIIisBinding {
    <#
    .SYNOPSIS
        Reads a Microsoft.Web.Administration Binding into a plain object.
    .DESCRIPTION
        Output has the contract Binding fields except NameStatus/SharedWith (computed by
        Get-APKIIisBinding), plus BindingInformation. CertificateHash and CertificateStoreName come
        from http.sys (they are not stored in applicationHost.config); reading them can throw when
        the http.sys entry is broken, in which case Thumbprint is ''.
        SslFlags is the raw bit field: 1 = SNI, 2 = CentralCertStore, higher bits = Disable* options.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$SiteName,

        [Parameter(Mandatory)]
        [object]$Binding
    )

    $protocol = ([string]$Binding.Protocol).ToLowerInvariant()
    $info = [string]$Binding.BindingInformation
    $parts = Split-APKIBindingInformation -BindingInformation $info

    $flags = 0
    $thumb = ''
    $store = ''
    if ($protocol -eq 'https') {
        try {
            $flags = [int]$Binding.SslFlags
        }
        catch {
            $flags = 0
        }
        try {
            $thumb = ConvertTo-APKIThumbprint -Hash $Binding.CertificateHash
        }
        catch {
            Write-APKILog -Message "Could not read certificate of $SiteName $info : $($_.Exception.Message)" -Level Warning
            $thumb = ''
        }
        if ($thumb) {
            $store = [string]$Binding.CertificateStoreName
            if (-not $store -or $store -eq 'my') {
                $store = 'My'
            }
            elseif ($store -eq 'webhosting') {
                $store = 'WebHosting'
            }
        }
    }

    [pscustomobject]@{
        SiteName           = $SiteName
        Protocol           = $protocol
        IPAddress          = $parts.IPAddress
        Port               = $parts.Port
        HostHeader         = $parts.HostHeader
        SslFlags           = $flags
        Thumbprint         = $thumb
        StoreName          = $store
        BindingInformation = $info
    }
}
