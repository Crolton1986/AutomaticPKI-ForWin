function Invoke-APKICepHttpRequest {
    <#
    .SYNOPSIS
        Sends an unauthenticated GET to a CES/CEP URL and returns the HTTP status code.
    .DESCRIPTION
        Wrapper around Invoke-WebRequest so tests can mock it. An HTTP error status (401, 404,
        500, ...) is returned as an [int], not thrown. Errors without an HTTP response (DNS,
        TCP, TLS, timeout) are thrown.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [ValidateRange(1, 300)]
        [int]$TimeoutSec = 15
    )

    if ($PSVersionTable.PSEdition -ne 'Core') {
        # Windows PowerShell 5.1 on older .NET Framework may not offer TLS 1.2 by default.
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
    }

    try {
        $response = Invoke-WebRequest -Uri $Uri -Method Get -UseBasicParsing -TimeoutSec $TimeoutSec -ErrorAction Stop
        return [int]$response.StatusCode
    }
    catch {
        # 5.1: WebException.Response (HttpWebResponse). 7.x: HttpResponseException.Response (HttpResponseMessage).
        $exception = $_.Exception
        $depth = 0
        while ($null -ne $exception -and $depth -lt 5) {
            if ($exception.PSObject.Properties['Response']) {
                $httpResponse = $exception.Response
                if ($null -ne $httpResponse -and $httpResponse.PSObject.Properties['StatusCode']) {
                    return [int]$httpResponse.StatusCode
                }
            }
            $exception = $exception.InnerException
            $depth++
        }
        throw
    }
}
