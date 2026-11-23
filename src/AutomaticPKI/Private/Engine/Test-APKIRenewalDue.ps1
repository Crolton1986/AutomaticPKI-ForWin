function Test-APKIRenewalDue {
    <#
    .SYNOPSIS
        Decides whether an order's current certificate must be renewed.
    .DESCRIPTION
        Due when:
          - the order has no CurrentThumbprint;
          - the certificate (with private key) is not in Cert:\LocalMachine\My;
          - a hostname in Order.Hostnames is not covered by the certificate's SAN dNSNames;
          - now is past the renewal point: the earlier of NotAfter - RenewalDaysBefore (order
            value overrides the global one) and NotAfter - one third of the lifetime.
    .OUTPUTS
        PSCustomObject: Due (bool), Reason (string), NotAfter (datetime or $null),
        RenewAfter (datetime or $null).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$Order,

        # Global configuration (Get-APKIConfig when omitted).
        [object]$Config,

        [datetime]$Now = (Get-Date)
    )

    $due = $true
    $reason = ''
    $notAfter = $null
    $renewAfter = $null

    $thumbprint = ConvertTo-APKINormalizedThumbprint -Thumbprint ([string](Get-APKIOptionalProperty -InputObject $Order -Name 'CurrentThumbprint' -Default ''))
    $certificate = $null
    if ($thumbprint) {
        $certificate = Find-APKIMachineCertificate -Thumbprint $thumbprint
    }

    if (-not $thumbprint) {
        $reason = 'The order has no current certificate.'
    }
    elseif ($null -eq $certificate) {
        $reason = "Current certificate $thumbprint (with private key) is not in Cert:\LocalMachine\My."
    }
    else {
        $info = Get-APKICertificateInfo -Certificate $certificate
        $notAfter = [datetime]$info.NotAfter
        $notBefore = [datetime]$info.NotBefore
        $dnsNames = @(@($info.DnsNames) | Where-Object { $_ } | ForEach-Object { [string]$_ })

        $uncovered = New-Object System.Collections.Generic.List[string]
        foreach ($hostname in @(@(Get-APKIOptionalProperty -InputObject $Order -Name 'Hostnames' -Default @()) | Where-Object { $_ })) {
            $name = ([string]$hostname).Trim().TrimEnd('.')
            $covered = $false
            foreach ($dnsName in $dnsNames) {
                if ([string]::Equals($dnsName.Trim().TrimEnd('.'), $name, [System.StringComparison]::OrdinalIgnoreCase) -or
                    (Test-APKIHostnameMatch -Pattern $dnsName -HostName $name)) {
                    $covered = $true
                    break
                }
            }
            if (-not $covered) {
                $uncovered.Add($name)
            }
        }

        if ($uncovered.Count -gt 0) {
            $reason = 'Hostnames not covered by the current certificate: {0}.' -f ($uncovered -join ', ')
        }
        else {
            if ($null -eq $Config) {
                $Config = Get-APKIConfig
            }
            $days = [int](Get-APKIOptionalProperty -InputObject $Config -Name 'RenewalDaysBefore' -Default 30)
            $orderDays = Get-APKIOptionalProperty -InputObject $Order -Name 'RenewalDaysBefore' -Default $null
            if ($null -ne $orderDays -and [string]$orderDays -ne '') {
                $days = [int]$orderDays
            }

            $byDays = $notAfter.AddDays(-$days)
            $lifetime = $notAfter - $notBefore
            $byLifetime = $notAfter.AddTicks(-1 * [long]($lifetime.Ticks / 3))
            $renewAfter = $byDays
            if ($byLifetime -lt $renewAfter) {
                $renewAfter = $byLifetime
            }

            $expires = $notAfter.ToString('yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture)
            $window = $renewAfter.ToString('yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture)
            if ($Now -ge $renewAfter) {
                $reason = "Certificate $thumbprint expires $expires; renewal window opened $window."
            }
            else {
                $due = $false
                $reason = "Certificate $thumbprint expires $expires; renewal due from $window."
            }
        }
    }

    [pscustomobject]@{
        Due        = $due
        Reason     = $reason
        NotAfter   = $notAfter
        RenewAfter = $renewAfter
    }
}
