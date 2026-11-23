function Invoke-APKITlsHandshake {
    <#
    .SYNOPSIS
        Opens a TCP connection, performs a TLS client handshake and returns the served certificate (mock target).
    .DESCRIPTION
        Connects to -IPAddress when given (e.g. 127.0.0.1 or a non-SNI binding's IP), otherwise to
        the first address -HostName resolves to (IPv4 preferred). The TLS ClientHello always carries
        SNI = -HostName: SslStream.AuthenticateAsClient(targetHost, ...) sends targetHost as the
        server name. AuthenticateAsClient is synchronous and honours the socket timeouts.
        Server certificate validation is disabled on purpose; see Get-APKIAcceptAnyCertificateCallback.
    .OUTPUTS
        X509Certificate2 served by the endpoint. Throws on connect/handshake failure or timeout.
    #>
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    param(
        [Parameter(Mandatory)]
        [string]$HostName,

        [ValidateRange(1, 65535)]
        [int]$Port = 443,

        [string]$IPAddress,

        [ValidateRange(1, 600)]
        [int]$TimeoutSec = 10,

        # Explicit protocols: under Windows PowerShell 5.1 the "system default" (SslProtocols.None)
        # behaviour depends on the AppContext/registry switches of powershell.exe. TLS 1.2 is
        # available on every supported IIS 10 host. Add Tls13 only where SChannel supports it
        # (Server 2022+); requesting it elsewhere makes the handshake fail.
        [System.Security.Authentication.SslProtocols]$SslProtocols = [System.Security.Authentication.SslProtocols]::Tls12
    )

    $timeoutMs = $TimeoutSec * 1000

    if ($IPAddress) {
        $address = [System.Net.IPAddress]::Parse($IPAddress.Trim().Trim('[', ']'))
    }
    else {
        $candidates = @([System.Net.Dns]::GetHostAddresses($HostName))
        $address = $candidates | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } | Select-Object -First 1
        if (-not $address) {
            $address = $candidates | Select-Object -First 1
        }
        if (-not $address) {
            throw "Host name '$HostName' did not resolve to any address."
        }
    }

    $tcp = [System.Net.Sockets.TcpClient]::new($address.AddressFamily)
    $ssl = $null
    try {
        $tcp.ReceiveTimeout = $timeoutMs
        $tcp.SendTimeout = $timeoutMs

        $async = $tcp.BeginConnect($address, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($timeoutMs)) {
            throw (New-Object System.TimeoutException -ArgumentList "TCP connect to ${address}:$Port timed out after $TimeoutSec s.")
        }
        $tcp.EndConnect($async)

        $callback = Get-APKIAcceptAnyCertificateCallback
        $ssl = [System.Net.Security.SslStream]::new($tcp.GetStream(), $false, $callback)
        $ssl.ReadTimeout = $timeoutMs
        $ssl.WriteTimeout = $timeoutMs

        $noClientCerts = [System.Security.Cryptography.X509Certificates.X509CertificateCollection]::new()
        try {
            $ssl.AuthenticateAsClient($HostName, $noClientCerts, $SslProtocols, $false)
        }
        catch {
            $inner = $_.Exception
            while ($inner.InnerException) {
                if ($inner -is [System.IO.IOException] -and $inner.InnerException -is [System.Net.Sockets.SocketException] -and
                    $inner.InnerException.SocketErrorCode -eq [System.Net.Sockets.SocketError]::TimedOut) {
                    throw (New-Object System.TimeoutException -ArgumentList "TLS handshake with ${address}:$Port (SNI '$HostName') timed out after $TimeoutSec s.")
                }
                $inner = $inner.InnerException
            }
            throw
        }

        $remote = $ssl.RemoteCertificate
        if ($null -eq $remote) {
            throw "Server ${address}:$Port (SNI '$HostName') presented no certificate."
        }
        [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($remote)
    }
    finally {
        if ($ssl) {
            $ssl.Dispose()
        }
        $tcp.Close()
    }
}
