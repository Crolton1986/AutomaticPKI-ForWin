function Find-APKISiteCandidate {
    <#
    .SYNOPSIS
        Scans IIS and proposes order skeletons (Status 'Proposed') for sites that serve http/https.
    .DESCRIPTION
        One candidate per site, except that sites sharing a non-SNI https IP:port (one http.sys
        certificate) are grouped into a single candidate whose certificate must cover all their names.
        For each site:
          - every https binding is managed (Central Certificate Store bindings are skipped);
          - every http binding with a usable host header that has no https counterpart gets a proposed
            SNI binding <HttpsPort>:host (SslFlags 1) and CreateBinding is set;
          - a site with no names from bindings/certificates uses -HostnameOverride[site]; with overrides
            and no https binding, SNI bindings for those names are proposed.
        Candidate NameStatus is 'Usable' when Hostnames is non-empty, else 'NeedsName' (EventId 2001).
        With -CheckDns, names that do not resolve to an address of this host log EventId 2002.
    .OUTPUTS
        [pscustomobject] Id, Status, SiteName, Hostnames, Bindings, NameStatus, CreateBinding.
        SiteName is the first site of a shared group; each Binding carries its own SiteName.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        # SiteName -> string[] of hostnames from an existing order or operator input.
        [hashtable]$HostnameOverride = @{},

        [switch]$CheckDns,

        [int]$HttpsPort = 443,

        [object]$ServerManager
    )

    if (-not $ServerManager) {
        $ServerManager = Get-APKIServerManager
    }

    $all = @(Get-APKIIisBinding -ServerManager $ServerManager)

    # Sites in configuration order (only those with http/https bindings).
    $siteOrder = New-Object System.Collections.Generic.List[string]
    foreach ($b in $all) {
        if (-not $siteOrder.Contains($b.SiteName)) {
            $siteOrder.Add($b.SiteName)
        }
    }

    # Group sites that share a non-SNI https endpoint.
    $groupOf = @{}
    foreach ($s in $siteOrder) {
        $groupOf[$s] = $s
    }
    foreach ($b in $all) {
        foreach ($other in @($b.SharedWith)) {
            $keep = $groupOf[$b.SiteName]
            $drop = $groupOf[$other]
            if ($keep -ne $drop) {
                foreach ($k in @($groupOf.Keys)) {
                    if ($groupOf[$k] -eq $drop) {
                        $groupOf[$k] = $keep
                    }
                }
            }
        }
    }
    $groups = New-Object System.Collections.Generic.List[string]
    foreach ($s in $siteOrder) {
        if (-not $groups.Contains($groupOf[$s])) {
            $groups.Add($groupOf[$s])
        }
    }

    $usedIds = New-Object System.Collections.Generic.List[string]

    foreach ($g in $groups) {
        $members = @($siteOrder | Where-Object { $groupOf[$_] -eq $g })
        $primary = $members[0]
        $hostnames = New-Object System.Collections.Generic.List[string]
        $bindings = New-Object System.Collections.Generic.List[object]
        $createBinding = $false

        foreach ($site in $members) {
            $override = @()
            if ($HostnameOverride.ContainsKey($site)) {
                $override = @($HostnameOverride[$site])
            }
            $siteHttps = @($all | Where-Object { $_.SiteName -eq $site -and $_.Protocol -eq 'https' })
            $siteHttp = @($all | Where-Object { $_.SiteName -eq $site -and $_.Protocol -eq 'http' })
            $siteNameCount = 0

            foreach ($b in $siteHttps) {
                if (($b.SslFlags -band 2) -ne 0) {
                    Write-APKILog -Message "Site '$site' binding $($b.BindingInformation) uses the Central Certificate Store; not managed." -Level Info
                    continue
                }
                $ns = Get-APKIBindingNameStatus -Binding $b -OverrideName $override
                foreach ($n in $ns.Names) {
                    if (-not $hostnames.Contains($n)) {
                        $hostnames.Add($n)
                    }
                    $siteNameCount++
                }
                $copy = $b.PSObject.Copy()
                $copy.NameStatus = $ns.NameStatus
                $bindings.Add($copy)
            }

            $proposeFor = New-Object System.Collections.Generic.List[string]
            foreach ($b in $siteHttp) {
                if (-not (Test-APKIUsableHostname -Name $b.HostHeader)) {
                    continue
                }
                $n = $b.HostHeader.Trim().TrimEnd('.').ToLowerInvariant()
                if (-not $hostnames.Contains($n)) {
                    $hostnames.Add($n)
                }
                $siteNameCount++
                $hasHttps = @($siteHttps | Where-Object { $_.HostHeader -eq $n }).Count -gt 0
                if (-not $hasHttps -and -not $proposeFor.Contains($n)) {
                    $proposeFor.Add($n)
                }
            }

            if ($siteNameCount -eq 0 -and $siteHttps.Count -eq 0) {
                foreach ($o in $override) {
                    if (Test-APKIUsableHostname -Name $o) {
                        $n = ([string]$o).Trim().TrimEnd('.').ToLowerInvariant()
                        if (-not $hostnames.Contains($n)) {
                            $hostnames.Add($n)
                        }
                        if (-not $proposeFor.Contains($n)) {
                            $proposeFor.Add($n)
                        }
                    }
                }
            }

            foreach ($n in $proposeFor) {
                $bindings.Add([pscustomobject]@{
                        SiteName           = $site
                        Protocol           = 'https'
                        IPAddress          = '*'
                        Port               = $HttpsPort
                        HostHeader         = $n
                        SslFlags           = 1
                        Thumbprint         = ''
                        StoreName          = 'My'
                        NameStatus         = 'Usable'
                        SharedWith         = [string[]]@()
                        BindingInformation = (Join-APKIBindingInformation -IPAddress '*' -Port $HttpsPort -HostHeader $n)
                    })
                $createBinding = $true
            }
        }

        $id = ConvertTo-APKIOrderId -SiteName $primary
        $baseId = $id
        $i = 2
        while ($usedIds.Contains($id)) {
            $id = '{0}-{1}' -f $baseId, $i
            $i++
        }
        $usedIds.Add($id)

        $status = 'NeedsName'
        if ($hostnames.Count -gt 0) {
            $status = 'Usable'
        }
        else {
            Write-APKILog -Message "Site '$($members -join "', '")' has no usable hostname (blank host header, no usable SAN). Supply one before approving." -Level Warning -EventId 2001 -OrderId $id
        }

        if ($CheckDns) {
            foreach ($n in $hostnames) {
                if (-not (Test-APKIHostnameResolvesLocally -Name $n)) {
                    Write-APKILog -Message "Hostname $n does not resolve to an address of this host." -Level Warning -EventId 2002 -OrderId $id
                }
            }
        }

        [pscustomobject]@{
            Id            = $id
            Status        = 'Proposed'
            SiteName      = $primary
            Hostnames     = [string[]]$hostnames.ToArray()
            Bindings      = [object[]]$bindings.ToArray()
            NameStatus    = $status
            CreateBinding = $createBinding
        }
    }
}
