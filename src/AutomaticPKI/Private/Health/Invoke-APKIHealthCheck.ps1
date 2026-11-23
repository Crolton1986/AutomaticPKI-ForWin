function Invoke-APKIHealthCheck {
    <#
    .SYNOPSIS
        Runs the post-bind health checks for an order against an expected certificate.
    .DESCRIPTION
        1. Site and application pool state (Test-APKISiteState; starts stopped objects,
           honours -WhatIf through $WhatIfPreference).
        2. TLS per managed https binding (Test-APKITlsBinding):
             SNI (SslFlags bit 1): connect 127.0.0.1, SNI = binding host header.
             non-SNI: connect the binding IP (127.0.0.1 for '*'/0.0.0.0), SNI = host header or
             the order's first hostname.
        3. HTTP probe per binding if Order.HttpProbe.Enabled (Test-APKIHttpProbe):
             SNI: https://<hostheader>:<port><path>. Windows PowerShell's HttpWebRequest takes SNI
             from the URL host, so this probe relies on DNS for the hostname.
             non-SNI: https://<ip>:<port><path> with the Host header set.
    .OUTPUTS
        PSCustomObject: Passed (bool, all results passed), Thumbprint, Results (health results).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$Order,

        [Parameter(Mandatory)]
        [string]$Thumbprint,

        [ValidateRange(1, 600)]
        [int]$TimeoutSec = 10
    )

    $results = New-Object System.Collections.Generic.List[object]
    $siteName = [string](Get-APKIOptionalProperty -InputObject $Order -Name 'SiteName' -Default '')
    $orderId = [string](Get-APKIOptionalProperty -InputObject $Order -Name 'Id' -Default '')
    $hostnames = @(Get-APKIOptionalProperty -InputObject $Order -Name 'Hostnames' -Default @()) | Where-Object { $_ }
    $firstHostname = ''
    if (@($hostnames).Count -gt 0) {
        $firstHostname = [string]@($hostnames)[0]
    }

    # 1. Site state
    if ($siteName) {
        foreach ($r in @(Test-APKISiteState -SiteName $siteName)) {
            $results.Add($r)
        }
    }
    else {
        $results.Add((New-APKIHealthResult -Check 'SiteState' -Target $orderId -Passed $false -Detail 'Order has no SiteName.'))
    }

    # Probe settings
    $probe = Get-APKIOptionalProperty -InputObject $Order -Name 'HttpProbe'
    $probeEnabled = [bool](Get-APKIOptionalProperty -InputObject $probe -Name 'Enabled' -Default $false)
    $probePath = [string](Get-APKIOptionalProperty -InputObject $probe -Name 'Path' -Default '/')
    if (-not $probePath) {
        $probePath = '/'
    }
    if (-not $probePath.StartsWith('/')) {
        $probePath = '/' + $probePath
    }
    $probeBelow = [int](Get-APKIOptionalProperty -InputObject $probe -Name 'ExpectStatusBelow' -Default 500)
    if ($probeBelow -le 0) {
        $probeBelow = 500
    }

    # 2./3. Per https binding
    $bindings = @(Get-APKIOptionalProperty -InputObject $Order -Name 'Bindings' -Default @()) | Where-Object {
        $null -ne $_ -and [string](Get-APKIOptionalProperty -InputObject $_ -Name 'Protocol' -Default '') -eq 'https'
    }
    $seen = @{}
    $tlsCount = 0
    foreach ($binding in @($bindings)) {
        $port = [int](Get-APKIOptionalProperty -InputObject $binding -Name 'Port' -Default 443)
        $hostHeader = [string](Get-APKIOptionalProperty -InputObject $binding -Name 'HostHeader' -Default '')
        $sslFlags = [int](Get-APKIOptionalProperty -InputObject $binding -Name 'SslFlags' -Default 0)
        $bindingIp = ([string](Get-APKIOptionalProperty -InputObject $binding -Name 'IPAddress' -Default '')).Trim().Trim('[', ']')
        $isSni = (($sslFlags -band 1) -eq 1)

        if ($isSni) {
            $connectIp = '127.0.0.1'
            $sniHost = $hostHeader
        }
        else {
            $connectIp = $bindingIp
            if (-not $connectIp -or $connectIp -eq '*' -or $connectIp -eq '0.0.0.0' -or $connectIp -eq '::') {
                $connectIp = '127.0.0.1'
            }
            $sniHost = $hostHeader
            if (-not $sniHost) {
                $sniHost = $firstHostname
            }
            if (-not $sniHost) {
                $sniHost = $connectIp
            }
        }

        if (-not $sniHost) {
            $results.Add((New-APKIHealthResult -Check 'TlsHandshake' -Target ('{0}:{1}' -f $bindingIp, $port) -Passed $false -Detail 'SNI binding has no host header.'))
            continue
        }

        $key = '{0}|{1}|{2}' -f $sniHost.ToLowerInvariant(), $connectIp, $port
        if ($seen.ContainsKey($key)) {
            continue
        }
        $seen[$key] = $true
        $tlsCount++

        $results.Add((Test-APKITlsBinding -HostName $sniHost -Port $port -IPAddress $connectIp -ExpectedThumbprint $Thumbprint -TimeoutSec $TimeoutSec))

        if ($probeEnabled) {
            if ($isSni) {
                $url = 'https://{0}:{1}{2}' -f $sniHost, $port, $probePath
                $results.Add((Test-APKIHttpProbe -Url $url -ExpectStatusBelow $probeBelow -TimeoutSec $TimeoutSec))
            }
            else {
                $urlHost = $connectIp
                if ($urlHost.Contains(':')) {
                    $urlHost = '[{0}]' -f $urlHost
                }
                $url = 'https://{0}:{1}{2}' -f $urlHost, $port, $probePath
                $results.Add((Test-APKIHttpProbe -Url $url -HostHeader $sniHost -ExpectStatusBelow $probeBelow -TimeoutSec $TimeoutSec))
            }
        }
    }

    if ($tlsCount -eq 0) {
        $results.Add((New-APKIHealthResult -Check 'TlsHandshake' -Target $orderId -Passed $false -Detail 'Order has no managed https binding to check.'))
    }

    $all = $results.ToArray()
    $failed = @($all | Where-Object { -not $_.Passed })
    [pscustomobject]@{
        Passed     = ($failed.Count -eq 0)
        Thumbprint = $Thumbprint
        Results    = $all
    }
}
