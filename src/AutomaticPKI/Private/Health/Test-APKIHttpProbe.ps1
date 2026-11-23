function Test-APKIHttpProbe {
    <#
    .SYNOPSIS
        Sends one HTTPS GET and passes if the status code is below -ExpectStatusBelow.
    .DESCRIPTION
        Redirects are not followed; a 3xx counts as its own status. Certificate validation is
        not enforced (the thumbprint was verified by Test-APKITlsBinding).
    .OUTPUTS
        Health check result: Check 'HttpProbe', Target = URL (plus Host header when set).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$Url,

        [ValidateRange(100, 1000)]
        [int]$ExpectStatusBelow = 500,

        [string]$HostHeader,

        [ValidateRange(1, 600)]
        [int]$TimeoutSec = 15
    )

    $target = $Url
    $requestParams = @{
        Url        = $Url
        TimeoutSec = $TimeoutSec
    }
    if ($HostHeader) {
        $requestParams.HostHeader = $HostHeader
        $target = '{0} (Host: {1})' -f $Url, $HostHeader
    }

    try {
        $response = Invoke-APKIHttpRequest @requestParams
    }
    catch {
        return New-APKIHealthResult -Check 'HttpProbe' -Target $target -Passed $false -Detail ('Request failed: {0}' -f $_.Exception.Message)
    }

    $code = [int]$response.StatusCode
    $description = [string](Get-APKIOptionalProperty -InputObject $response -Name 'StatusDescription' -Default '')
    if ($code -lt $ExpectStatusBelow) {
        New-APKIHealthResult -Check 'HttpProbe' -Target $target -Passed $true -Detail ('HTTP {0} {1} (< {2}).' -f $code, $description, $ExpectStatusBelow)
    }
    else {
        New-APKIHealthResult -Check 'HttpProbe' -Target $target -Passed $false -Detail ('HTTP {0} {1} (expected < {2}).' -f $code, $description, $ExpectStatusBelow)
    }
}
