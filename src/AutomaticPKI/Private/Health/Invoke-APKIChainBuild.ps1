function Invoke-APKIChainBuild {
    <#
    .SYNOPSIS
        Builds the certificate chain in the machine context (mock target).
    .DESCRIPTION
        X509Chain with RevocationFlag ExcludeRoot (roots are self-signed and carry no CDP) and the
        requested RevocationMode. Returns the chain status flag names rather than the chain, so
        callers and tests never handle X509Chain objects.
    .OUTPUTS
        PSCustomObject: Built (bool, X509Chain.Build result), Status (string[] of
        X509ChainStatusFlags names, empty when clean), StatusInformation (string[]).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        # X509Certificate2. Typed [object] so tests can pass fakes to the mocked command.
        [Parameter(Mandatory)]
        [object]$Certificate,

        [ValidateSet('Online', 'Offline', 'NoCheck')]
        [string]$RevocationMode = 'Online',

        [ValidateRange(1, 300)]
        [int]$UrlRetrievalTimeoutSec = 15
    )

    # $true = machine context: IIS (LocalSystem) trusts LocalMachine roots, not the caller's.
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain -ArgumentList $true
    try {
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]$RevocationMode
        $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot
        $chain.ChainPolicy.UrlRetrievalTimeout = New-TimeSpan -Seconds $UrlRetrievalTimeoutSec

        $built = $chain.Build([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

        $status = New-Object System.Collections.Generic.List[string]
        $info = New-Object System.Collections.Generic.List[string]
        foreach ($s in $chain.ChainStatus) {
            foreach ($name in ($s.Status.ToString() -split ',\s*')) {
                if ($name -and $name -ne 'NoError' -and -not $status.Contains($name)) {
                    $status.Add($name)
                }
            }
            if ($s.StatusInformation) {
                $info.Add($s.StatusInformation.Trim())
            }
        }

        [pscustomobject]@{
            Built             = [bool]$built
            Status            = $status.ToArray()
            StatusInformation = $info.ToArray()
        }
    }
    finally {
        # X509Chain is IDisposable from .NET Framework 4.6; Reset() frees the native context before that.
        if ($chain -is [System.IDisposable]) {
            $chain.Dispose()
        }
        else {
            $chain.Reset()
        }
    }
}
