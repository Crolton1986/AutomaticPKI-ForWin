function Test-APKICertificatePrecheck {
    <#
    .SYNOPSIS
        Verifies a certificate is fit to bind before it touches IIS.
    .DESCRIPTION
        Returns one health check result per sub-check (Target = thumbprint):
          PrivateKey        private key present
          ValidityPeriod    now within NotBefore..NotAfter
          ServerAuthEku     EKU contains 1.3.6.1.5.5.7.3.1, or the certificate has no EKU extension
          SanCoverage       every hostname covered by a SAN dNSName (wildcards: one label only)
          ChainTrust        chain builds to a trusted root (machine context)
          RevocationStatus  revocation status obtainable and not revoked
        -RevocationPolicy:
          Strict  (default) RevocationStatusUnknown / OfflineRevocation fail the check.
          Lenient           those pass with a warning in Detail; Revoked still fails.
          Skip              no revocation lookup (RevocationMode NoCheck); check passes with a note.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        # X509Certificate2 (anything Get-APKICertificateInfo accepts).
        [Parameter(Mandatory)]
        [object]$Certificate,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$Hostnames,

        [ValidateSet('Strict', 'Lenient', 'Skip')]
        [string]$RevocationPolicy = 'Strict',

        [ValidateRange(1, 300)]
        [int]$UrlRetrievalTimeoutSec = 15
    )

    $serverAuthOid = '1.3.6.1.5.5.7.3.1'
    $revocationSoftFlags = @('RevocationStatusUnknown', 'OfflineRevocation')
    $results = New-Object System.Collections.Generic.List[object]

    $info = Get-APKICertificateInfo -Certificate $Certificate
    $target = [string]$info.Thumbprint

    # PrivateKey
    if ($info.HasPrivateKey) {
        $results.Add((New-APKIHealthResult -Check 'PrivateKey' -Target $target -Passed $true -Detail 'Private key present.'))
    }
    else {
        $results.Add((New-APKIHealthResult -Check 'PrivateKey' -Target $target -Passed $false -Detail 'Certificate has no associated private key.'))
    }

    # ValidityPeriod
    $now = Get-Date
    $notBefore = [datetime]$info.NotBefore
    $notAfter = [datetime]$info.NotAfter
    if ($now -lt $notBefore) {
        $results.Add((New-APKIHealthResult -Check 'ValidityPeriod' -Target $target -Passed $false -Detail ('Not yet valid; NotBefore {0:u}.' -f $notBefore)))
    }
    elseif ($now -gt $notAfter) {
        $results.Add((New-APKIHealthResult -Check 'ValidityPeriod' -Target $target -Passed $false -Detail ('Expired; NotAfter {0:u}.' -f $notAfter)))
    }
    else {
        $results.Add((New-APKIHealthResult -Check 'ValidityPeriod' -Target $target -Passed $true -Detail ('Valid {0:u} to {1:u}.' -f $notBefore, $notAfter)))
    }

    # ServerAuthEku
    $ekus = @($info.Ekus | Where-Object { $_ })
    if (-not $info.HasEku) {
        $results.Add((New-APKIHealthResult -Check 'ServerAuthEku' -Target $target -Passed $true -Detail 'No EKU extension; all usages allowed.'))
    }
    elseif ($ekus -contains $serverAuthOid) {
        $results.Add((New-APKIHealthResult -Check 'ServerAuthEku' -Target $target -Passed $true -Detail 'EKU contains Server Authentication.'))
    }
    else {
        $results.Add((New-APKIHealthResult -Check 'ServerAuthEku' -Target $target -Passed $false -Detail ('EKU lacks Server Authentication ({0}); has: {1}.' -f $serverAuthOid, ($ekus -join ', '))))
    }

    # SanCoverage
    $dnsNames = @($info.DnsNames | Where-Object { $_ })
    $missing = New-Object System.Collections.Generic.List[string]
    foreach ($h in $Hostnames) {
        if (-not $h) {
            continue
        }
        $covered = $false
        foreach ($n in $dnsNames) {
            if (Test-APKIHostnameMatch -Pattern $n -HostName $h) {
                $covered = $true
                break
            }
        }
        if (-not $covered) {
            $missing.Add($h)
        }
    }
    if ($missing.Count -eq 0) {
        $results.Add((New-APKIHealthResult -Check 'SanCoverage' -Target $target -Passed $true -Detail ('SAN covers: {0}.' -f ($Hostnames -join ', '))))
    }
    else {
        $results.Add((New-APKIHealthResult -Check 'SanCoverage' -Target $target -Passed $false -Detail ('SAN does not cover: {0}. SAN has: {1}.' -f ($missing -join ', '), ($dnsNames -join ', '))))
    }

    # ChainTrust + RevocationStatus
    $mode = 'Online'
    if ($RevocationPolicy -eq 'Skip') {
        $mode = 'NoCheck'
    }
    $chain = $null
    $chainError = $null
    try {
        $chain = Invoke-APKIChainBuild -Certificate $Certificate -RevocationMode $mode -UrlRetrievalTimeoutSec $UrlRetrievalTimeoutSec
    }
    catch {
        $chainError = $_.Exception.Message
    }

    if ($null -eq $chain) {
        $results.Add((New-APKIHealthResult -Check 'ChainTrust' -Target $target -Passed $false -Detail "Chain build failed: $chainError"))
        $results.Add((New-APKIHealthResult -Check 'RevocationStatus' -Target $target -Passed $false -Detail 'Not evaluated; chain build failed.'))
        return $results.ToArray()
    }

    $statusNames = @($chain.Status | Where-Object { $_ })
    $infoText = (@($chain.StatusInformation | Where-Object { $_ }) -join ' ')
    $trustErrors = @($statusNames | Where-Object { $revocationSoftFlags -notcontains $_ -and $_ -ne 'Revoked' })
    if ($trustErrors.Count -eq 0) {
        $results.Add((New-APKIHealthResult -Check 'ChainTrust' -Target $target -Passed $true -Detail 'Chain builds to a trusted root.'))
    }
    else {
        $results.Add((New-APKIHealthResult -Check 'ChainTrust' -Target $target -Passed $false -Detail ('Chain errors: {0}. {1}' -f ($trustErrors -join ', '), $infoText).Trim()))
    }

    $softErrors = @($statusNames | Where-Object { $revocationSoftFlags -contains $_ })
    if ($statusNames -contains 'Revoked') {
        $results.Add((New-APKIHealthResult -Check 'RevocationStatus' -Target $target -Passed $false -Detail 'Certificate or an issuing CA is revoked.'))
    }
    elseif ($RevocationPolicy -eq 'Skip') {
        $results.Add((New-APKIHealthResult -Check 'RevocationStatus' -Target $target -Passed $true -Detail 'Revocation check skipped by policy.'))
    }
    elseif ($softErrors.Count -gt 0) {
        $detail = 'Revocation status not obtainable ({0}); check CDP/OCSP reachability.' -f ($softErrors -join ', ')
        if ($RevocationPolicy -eq 'Lenient') {
            $results.Add((New-APKIHealthResult -Check 'RevocationStatus' -Target $target -Passed $true -Detail "WARNING: $detail Accepted by Lenient policy."))
        }
        else {
            $results.Add((New-APKIHealthResult -Check 'RevocationStatus' -Target $target -Passed $false -Detail $detail))
        }
    }
    else {
        $results.Add((New-APKIHealthResult -Check 'RevocationStatus' -Target $target -Passed $true -Detail 'Revocation status obtained; not revoked.'))
    }

    $results.ToArray()
}
