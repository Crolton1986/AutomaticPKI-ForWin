function Set-APKIIisCertificateBinding {
    <#
    .SYNOPSIS
        Puts a certificate on every https binding listed in Order.Bindings, in one CommitChanges.
    .DESCRIPTION
        For each https entry in Order.Bindings:
          - existing binding with a different certificate: the binding is replaced (removed config-only,
            so the shared http.sys entry is not deleted, then re-added with the new hash). Its SslFlags
            are kept bit for bit, including flags this module does not know (Disable* options).
          - existing binding already on the certificate: left alone.
          - missing SNI binding (host header set) and Order.CreateBinding is true: created with
            SslFlags = entry.SslFlags -bor 1 (EventId 1003 after commit).
          - missing binding otherwise, missing site, or a Central Certificate Store binding: throws
            before anything is changed.
        Non-SNI bindings on one IP:port share a single http.sys certificate, so updating one updates
        the certificate seen by every site on that endpoint; a warning names sites on the endpoint
        that are not in Order.Bindings. Only bindings in Order.Bindings are modified in configuration.
        http entries in Order.Bindings are ignored.
    .OUTPUTS
        [pscustomobject] per binding: SiteName, BindingInformation, Action
        (Updated|Created|Unchanged|Skipped), PreviousThumbprint, Thumbprint.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$Order,

        [Parameter(Mandatory)]
        [string]$Thumbprint,

        [ValidateSet('My', 'WebHosting')]
        [string]$StoreName = 'My',

        [object]$ServerManager
    )

    $thumb = ConvertTo-APKIThumbprint -Hash $Thumbprint
    $hash = ConvertTo-APKICertificateHash -Thumbprint $thumb

    $orderId = ''
    if ($Order.PSObject.Properties['Id'] -and $Order.Id) {
        $orderId = [string]$Order.Id
    }
    $createAllowed = $false
    if ($Order.PSObject.Properties['CreateBinding'] -and $Order.CreateBinding) {
        $createAllowed = [bool]$Order.CreateBinding
    }
    $orderBindings = @()
    if ($Order.PSObject.Properties['Bindings'] -and $Order.Bindings) {
        $orderBindings = @($Order.Bindings | Where-Object { $_.PSObject.Properties['Protocol'] -and [string]$_.Protocol -eq 'https' })
    }
    if ($orderBindings.Count -eq 0) {
        Write-APKILog -Message 'Order has no https bindings to update.' -Level Warning -OrderId $orderId
        return
    }

    if (-not $ServerManager) {
        $ServerManager = Get-APKIServerManager
    }

    # Plan every change first so a bad entry aborts before anything is touched.
    $plan = New-Object System.Collections.Generic.List[object]
    $seen = New-Object System.Collections.Generic.List[string]
    foreach ($ob in $orderBindings) {
        $siteName = [string]$ob.SiteName
        $ip = '*'
        if ($ob.PSObject.Properties['IPAddress'] -and $ob.IPAddress) {
            $ip = [string]$ob.IPAddress
        }
        $port = [int]$ob.Port
        $hostHeader = ''
        if ($ob.PSObject.Properties['HostHeader'] -and $ob.HostHeader) {
            $hostHeader = [string]$ob.HostHeader
        }
        $wantedFlags = 0
        if ($ob.PSObject.Properties['SslFlags'] -and $null -ne $ob.SslFlags) {
            $wantedFlags = [int]$ob.SslFlags
        }
        $info = Join-APKIBindingInformation -IPAddress $ip -Port $port -HostHeader $hostHeader
        $key = ('{0}|{1}' -f $siteName, $info).ToLowerInvariant()
        if ($seen.Contains($key)) {
            continue
        }
        $seen.Add($key)

        $found = Find-APKIIisSiteBinding -ServerManager $ServerManager -SiteName $siteName -Protocol 'https' -IPAddress $ip -Port $port -HostHeader $hostHeader
        if (-not $found.Site) {
            throw "IIS site '$siteName' not found."
        }

        if ($found.Binding) {
            $current = ConvertFrom-APKIIisBinding -SiteName $siteName -Binding $found.Binding
            if (($current.SslFlags -band 2) -ne 0) {
                throw "Binding $info on '$siteName' uses the Central Certificate Store and cannot be bound to a thumbprint."
            }
            $action = 'Update'
            if ($current.Thumbprint -eq $thumb -and $current.StoreName -eq $StoreName) {
                $action = 'Unchanged'
            }
            $plan.Add([pscustomobject]@{
                    Site = $found.Site; SiteName = $siteName; Binding = $found.Binding; Info = $info
                    Action = $action; Flags = $current.SslFlags; Previous = $current.Thumbprint
                    IPAddress = $ip; Port = $port; HostHeader = $hostHeader
                })
        }
        else {
            if (-not $hostHeader) {
                throw "Non-SNI binding $info on '$siteName' does not exist; only SNI bindings are created."
            }
            if (-not $createAllowed) {
                throw "Binding $info on '$siteName' does not exist and the order does not allow creating bindings (CreateBinding = false)."
            }
            $plan.Add([pscustomobject]@{
                    Site = $found.Site; SiteName = $siteName; Binding = $null; Info = $info
                    Action = 'Create'; Flags = ($wantedFlags -bor 1); Previous = ''
                    IPAddress = $ip; Port = $port; HostHeader = $hostHeader
                })
        }
    }

    # Sites on a shared non-SNI endpoint that the order does not list still get the new certificate.
    $managedSites = @($orderBindings | ForEach-Object { [string]$_.SiteName })
    foreach ($p in $plan) {
        if ($p.Action -ne 'Update' -or ($p.Flags -band 1) -ne 0) {
            continue
        }
        $others = @(Get-APKIIisEndpointSite -ServerManager $ServerManager -IPAddress $p.IPAddress -Port $p.Port -ExcludeSite $p.SiteName |
                Where-Object { $managedSites -notcontains $_ })
        if ($others.Count -gt 0) {
            Write-APKILog -Message "Endpoint $($p.IPAddress):$($p.Port) is shared (non-SNI); sites $($others -join ', ') will also serve certificate $thumb." -Level Warning -EventId 2006 -OrderId $orderId
        }
    }

    $results = New-Object System.Collections.Generic.List[object]
    $created = New-Object System.Collections.Generic.List[object]
    $changed = 0
    foreach ($p in $plan) {
        $result = [pscustomobject]@{
            SiteName           = $p.SiteName
            BindingInformation = $p.Info
            Action             = 'Unchanged'
            PreviousThumbprint = $p.Previous
            Thumbprint         = $thumb
        }
        if ($p.Action -eq 'Unchanged') {
            $results.Add($result)
            continue
        }
        $verb = 'Replace certificate {0} with {1}' -f $p.Previous, $thumb
        if ($p.Action -eq 'Create') {
            $verb = 'Create https binding (SslFlags {0}) with certificate {1}' -f $p.Flags, $thumb
        }
        if ($PSCmdlet.ShouldProcess(('{0} https {1}' -f $p.SiteName, $p.Info), $verb)) {
            if ($p.Action -eq 'Update') {
                # Config-only removal keeps the http.sys entry other sites may share; Add rewrites it.
                $p.Site.Bindings.Remove($p.Binding, $true)
                [void]$p.Site.Bindings.Add($p.Info, $hash, $StoreName, [int]$p.Flags)
                $result.Action = 'Updated'
            }
            else {
                [void]$p.Site.Bindings.Add($p.Info, $hash, $StoreName, [int]$p.Flags)
                $result.Action = 'Created'
                $created.Add($p)
            }
            $changed++
        }
        else {
            $result.Action = 'Skipped'
        }
        $results.Add($result)
    }

    if ($changed -gt 0) {
        $ServerManager.CommitChanges()
        foreach ($c in $created) {
            Write-APKILog -Message "Created https binding $($c.Info) on site '$($c.SiteName)' with certificate $thumb." -Level Info -EventId 1003 -OrderId $orderId
        }
        Write-APKILog -Message "Bound certificate $thumb to $changed binding(s)." -Level Info -OrderId $orderId
    }

    $results.ToArray()
}
