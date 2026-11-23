function Join-APKIBindingInformation {
    <#
    .SYNOPSIS
        Builds an IIS bindingInformation string ("IP:Port:Host") from its parts.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowEmptyString()]
        [string]$IPAddress = '*',

        [Parameter(Mandatory)]
        [int]$Port,

        [AllowEmptyString()]
        [string]$HostHeader = ''
    )

    $ip = $IPAddress
    if (-not $ip) {
        $ip = '*'
    }
    if ($ip.Contains(':') -and -not $ip.StartsWith('[')) {
        $ip = '[' + $ip + ']'
    }
    if ($null -eq $HostHeader) {
        $HostHeader = ''
    }
    '{0}:{1}:{2}' -f $ip, $Port, $HostHeader
}
