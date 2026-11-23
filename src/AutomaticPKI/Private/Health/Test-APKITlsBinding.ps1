function Test-APKITlsBinding {
    <#
    .SYNOPSIS
        Checks that an HTTPS endpoint serves the expected certificate.
    .DESCRIPTION
        Connects to -IPAddress when given (non-SNI binding IP, or 127.0.0.1 to test this host
        while sending SNI = -HostName), otherwise to -HostName as resolved by DNS. Only the
        served thumbprint is compared; chain and names are covered by Test-APKICertificatePrecheck.
    .OUTPUTS
        Health check result: Check 'TlsHandshake', Target '<HostName>:<Port>'.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$HostName,

        [ValidateRange(1, 65535)]
        [int]$Port = 443,

        [string]$IPAddress,

        [Parameter(Mandatory)]
        [string]$ExpectedThumbprint,

        [ValidateRange(1, 600)]
        [int]$TimeoutSec = 10
    )

    $target = '{0}:{1}' -f $HostName, $Port
    $via = ''
    if ($IPAddress) {
        $via = " via $IPAddress"
    }
    $expected = ConvertTo-APKINormalizedThumbprint -Thumbprint $ExpectedThumbprint

    $handshakeParams = @{
        HostName   = $HostName
        Port       = $Port
        TimeoutSec = $TimeoutSec
    }
    if ($IPAddress) {
        $handshakeParams.IPAddress = $IPAddress
    }

    try {
        $served = Invoke-APKITlsHandshake @handshakeParams
    }
    catch {
        $kind = 'failed'
        $ex = $_.Exception
        while ($ex) {
            if ($ex -is [System.TimeoutException]) {
                $kind = 'timed out'
                break
            }
            $ex = $ex.InnerException
        }
        return New-APKIHealthResult -Check 'TlsHandshake' -Target $target -Passed $false -Detail ("TLS handshake{0} (SNI '{1}') {2}: {3}" -f $via, $HostName, $kind, $_.Exception.Message)
    }

    $actual = ''
    if ($null -ne $served) {
        $actual = ConvertTo-APKINormalizedThumbprint -Thumbprint ([string]$served.Thumbprint)
    }

    if ($actual -and $actual -eq $expected) {
        New-APKIHealthResult -Check 'TlsHandshake' -Target $target -Passed $true -Detail ("Served expected certificate {0}{1}." -f $actual, $via)
    }
    else {
        New-APKIHealthResult -Check 'TlsHandshake' -Target $target -Passed $false -Detail ("Served certificate {0}, expected {1}{2}." -f $actual, $expected, $via)
    }
}
