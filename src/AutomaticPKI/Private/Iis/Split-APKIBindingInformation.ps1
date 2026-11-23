function Split-APKIBindingInformation {
    <#
    .SYNOPSIS
        Splits an IIS bindingInformation string ("IP:Port:Host") into its parts.
    .DESCRIPTION
        Handles "*:443:", ":443:" (blank IP = all), "10.0.0.5:443:www.contoso.com" and bracketed IPv6
        ("[2001:db8::1]:443:"). IPv6 brackets are removed from IPAddress; Join-APKIBindingInformation
        puts them back.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$BindingInformation
    )

    $last = $BindingInformation.LastIndexOf(':')
    if ($last -lt 1) {
        throw "Invalid binding information '$BindingInformation'."
    }
    $hostHeader = $BindingInformation.Substring($last + 1)
    $rest = $BindingInformation.Substring(0, $last)
    $portSep = $rest.LastIndexOf(':')
    if ($portSep -lt 0) {
        throw "Invalid binding information '$BindingInformation'."
    }
    $ip = $rest.Substring(0, $portSep)
    $portText = $rest.Substring($portSep + 1)
    $port = 0
    if (-not [int]::TryParse($portText, [ref]$port)) {
        throw "Invalid port in binding information '$BindingInformation'."
    }
    if ($ip -eq '') {
        $ip = '*'
    }
    if ($ip.StartsWith('[') -and $ip.EndsWith(']')) {
        $ip = $ip.Substring(1, $ip.Length - 2)
    }

    [pscustomobject]@{
        IPAddress  = $ip
        Port       = $port
        HostHeader = $hostHeader
    }
}
