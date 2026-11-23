function Get-APKIBindingNameStatus {
    <#
    .SYNOPSIS
        Works out which hostnames a binding serves and whether it needs a name from an operator.
    .DESCRIPTION
        Name sources, first one that yields a usable name wins:
          1. HostHeader of the binding
          2. SANs of the certificate currently bound (Get-APKICertificateDnsName, mockable)
          3. OverrideName (hostnames from an existing order / operator input)
        Names failing Test-APKIUsableHostname (localhost, single label, IP literal, wildcard) are dropped.
        NameStatus is 'Usable' when at least one name remains, otherwise 'NeedsName'.
    .OUTPUTS
        [pscustomobject] NameStatus, Names (string[]), Source (HostHeader|CertificateSan|Override|None)
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        # A contract Binding (needs HostHeader; Thumbprint/StoreName optional).
        [Parameter(Mandatory)]
        [object]$Binding,

        [string[]]$OverrideName = @()
    )

    $names = New-Object System.Collections.Generic.List[string]
    $source = 'None'

    $hostHeader = ''
    if ($Binding.PSObject.Properties['HostHeader'] -and $Binding.HostHeader) {
        $hostHeader = [string]$Binding.HostHeader
    }
    if (Test-APKIUsableHostname -Name $hostHeader) {
        $names.Add($hostHeader.Trim().TrimEnd('.').ToLowerInvariant())
        $source = 'HostHeader'
    }

    if ($names.Count -eq 0) {
        $thumb = ''
        if ($Binding.PSObject.Properties['Thumbprint'] -and $Binding.Thumbprint) {
            $thumb = [string]$Binding.Thumbprint
        }
        if ($thumb) {
            $store = 'My'
            if ($Binding.PSObject.Properties['StoreName'] -and $Binding.StoreName) {
                $store = [string]$Binding.StoreName
            }
            foreach ($san in @(Get-APKICertificateDnsName -Thumbprint $thumb -StoreName $store)) {
                if (Test-APKIUsableHostname -Name $san) {
                    $n = ([string]$san).Trim().TrimEnd('.').ToLowerInvariant()
                    if (-not $names.Contains($n)) {
                        $names.Add($n)
                    }
                }
            }
            if ($names.Count -gt 0) {
                $source = 'CertificateSan'
            }
        }
    }

    if ($names.Count -eq 0) {
        foreach ($o in @($OverrideName)) {
            if (Test-APKIUsableHostname -Name $o) {
                $n = ([string]$o).Trim().TrimEnd('.').ToLowerInvariant()
                if (-not $names.Contains($n)) {
                    $names.Add($n)
                }
            }
        }
        if ($names.Count -gt 0) {
            $source = 'Override'
        }
    }

    $status = 'NeedsName'
    if ($names.Count -gt 0) {
        $status = 'Usable'
    }

    [pscustomobject]@{
        NameStatus = $status
        Names      = [string[]]$names.ToArray()
        Source     = $source
    }
}
