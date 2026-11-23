function Invoke-APKIHttpRequest {
    <#
    .SYNOPSIS
        Sends one GET with HttpWebRequest and returns the status code (mock target).
    .DESCRIPTION
        Redirects are not followed (a 301/302 is a valid answer). Certificate validation is not
        enforced: the served thumbprint is checked by Test-APKITlsBinding and the chain by
        Test-APKICertificatePrecheck. 4xx/5xx responses are returned, not thrown; transport
        failures (DNS, TCP, TLS, timeout) throw.

        Note for Windows PowerShell 5.1: HttpWebRequest takes the TLS SNI name from the URL host,
        not from -HostHeader. Use a URL with the real hostname for SNI-only bindings.
    .OUTPUTS
        PSCustomObject: StatusCode (int), StatusDescription (string).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$Url,

        [string]$HostHeader,

        [ValidateRange(1, 600)]
        [int]$TimeoutSec = 15
    )

    # powershell.exe may still default to SSL3/TLS1.0; add TLS 1.2 unless the process uses the OS default (0).
    $current = [System.Net.ServicePointManager]::SecurityProtocol
    if ([int]$current -ne 0 -and -not ($current -band [System.Net.SecurityProtocolType]::Tls12)) {
        [System.Net.ServicePointManager]::SecurityProtocol = $current -bor [System.Net.SecurityProtocolType]::Tls12
    }

    $timeoutMs = $TimeoutSec * 1000
    $request = [System.Net.HttpWebRequest][System.Net.WebRequest]::Create($Url)
    $request.Method = 'GET'
    $request.AllowAutoRedirect = $false
    $request.KeepAlive = $false
    $request.Timeout = $timeoutMs
    $request.ReadWriteTimeout = $timeoutMs
    $request.UserAgent = 'AutomaticPKI-HealthProbe'
    $request.ServerCertificateValidationCallback = Get-APKIAcceptAnyCertificateCallback
    if ($HostHeader) {
        $request.Host = $HostHeader
    }

    $response = $null
    try {
        $response = $request.GetResponse()
    }
    catch {
        $webEx = $_.Exception
        while ($webEx -and -not ($webEx -is [System.Net.WebException])) {
            $webEx = $webEx.InnerException
        }
        if ($webEx -and $webEx.Response) {
            $response = $webEx.Response
        }
        else {
            throw
        }
    }

    try {
        [pscustomobject]@{
            StatusCode        = [int]$response.StatusCode
            StatusDescription = [string]$response.StatusDescription
        }
    }
    finally {
        $response.Close()
    }
}
