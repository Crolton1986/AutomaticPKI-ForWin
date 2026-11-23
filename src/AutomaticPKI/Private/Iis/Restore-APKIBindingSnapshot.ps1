function Restore-APKIBindingSnapshot {
    <#
    .SYNOPSIS
        Puts an order's https bindings back to a snapshot taken by Save-APKIBindingSnapshot.
    .DESCRIPTION
        Per snapshot entry, in one CommitChanges:
          - Exists = $false and the binding now exists: removed (created by the swap). The http.sys
            entry is removed too unless another site shares the non-SNI endpoint.
          - Exists = $true and the binding is missing: re-created with the recorded certificate/flags.
          - Exists = $true and thumbprint, store or SslFlags differ: replaced with the recorded values.
        Snapshot source: -Snapshot (object returned by Save-APKIBindingSnapshot, or one read back from
        its JSON file); without -Snapshot the newest file under snapshots\<Order.Id> is used; -Path
        reads a specific file. Throws when a site is missing; callers log EventId 3003 on failure.
    .OUTPUTS
        [pscustomobject] per entry: SiteName, BindingInformation, Action
        (Removed|Recreated|Restored|Unchanged|Skipped).
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium', DefaultParameterSetName = 'Order')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Order')]
        [object]$Order,

        [Parameter(ParameterSetName = 'Order')]
        [object]$Snapshot,

        [Parameter(Mandatory, ParameterSetName = 'Path')]
        [string]$Path,

        [object]$ServerManager
    )

    if ($PSCmdlet.ParameterSetName -eq 'Order' -and -not $Snapshot) {
        $orderId = ''
        if ($Order.PSObject.Properties['Id'] -and $Order.Id) {
            $orderId = [string]$Order.Id
        }
        if ($orderId -notmatch '^[A-Za-z0-9._-]+$') {
            throw "Order Id '$orderId' is not a valid file name."
        }
        $dir = Join-Path (Join-Path (Get-APKIRoot) 'snapshots') $orderId
        $latest = $null
        if (Test-Path -LiteralPath $dir) {
            $latest = Get-ChildItem -LiteralPath $dir -Filter '*.json' -File | Sort-Object -Property Name | Select-Object -Last 1
        }
        if (-not $latest) {
            throw "No binding snapshot found for order '$orderId'."
        }
        $Path = $latest.FullName
    }
    if (-not $Snapshot) {
        $Snapshot = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    $source = 'object'
    if ($Snapshot.PSObject.Properties['Path'] -and $Snapshot.Path) {
        $source = [string]$Snapshot.Path
    }
    elseif ($Path) {
        $source = $Path
    }

    $logId = ''
    if ($Snapshot.PSObject.Properties['OrderId']) {
        $logId = [string]$Snapshot.OrderId
    }
    if ($Order -and $Order.PSObject.Properties['Id'] -and $logId -and [string]$Order.Id -ne $logId) {
        throw "Snapshot belongs to order '$logId', not '$($Order.Id)'."
    }
    $entries = @()
    if ($Snapshot.PSObject.Properties['Bindings'] -and $Snapshot.Bindings) {
        $entries = @($Snapshot.Bindings)
    }

    if (-not $ServerManager) {
        $ServerManager = Get-APKIServerManager
    }

    $results = New-Object System.Collections.Generic.List[object]
    $changed = 0
    foreach ($e in $entries) {
        $siteName = [string]$e.SiteName
        $ip = [string]$e.IPAddress
        $port = [int]$e.Port
        $hostHeader = ''
        if ($e.HostHeader) {
            $hostHeader = [string]$e.HostHeader
        }
        $flags = [int]$e.SslFlags
        $thumb = ConvertTo-APKIThumbprint -Hash ([string]$e.Thumbprint)
        $store = [string]$e.StoreName
        if (-not $store) {
            $store = 'My'
        }
        $info = Join-APKIBindingInformation -IPAddress $ip -Port $port -HostHeader $hostHeader

        $found = Find-APKIIisSiteBinding -ServerManager $ServerManager -SiteName $siteName -Protocol 'https' -IPAddress $ip -Port $port -HostHeader $hostHeader
        if (-not $found.Site) {
            throw "IIS site '$siteName' not found; cannot restore $info."
        }
        $result = [pscustomobject]@{
            SiteName           = $siteName
            BindingInformation = $info
            Action             = 'Unchanged'
        }

        $action = 'Unchanged'
        $current = $null
        if ($found.Binding) {
            $current = ConvertFrom-APKIIisBinding -SiteName $siteName -Binding $found.Binding
        }
        if (-not [bool]$e.Exists) {
            if ($found.Binding) {
                $action = 'Removed'
            }
        }
        elseif (-not $found.Binding) {
            $action = 'Recreated'
        }
        elseif ($current.Thumbprint -ne $thumb -or $current.SslFlags -ne $flags -or ($thumb -and $current.StoreName -ne $store)) {
            $action = 'Restored'
        }

        if ($action -eq 'Unchanged') {
            $results.Add($result)
            continue
        }

        if (-not $PSCmdlet.ShouldProcess(('{0} https {1}' -f $siteName, $info), "$action binding from snapshot")) {
            $result.Action = 'Skipped'
            $results.Add($result)
            continue
        }

        # A non-SNI endpoint used by other sites keeps its http.sys entry when this binding goes away.
        $sharedEndpoint = $false
        if ($found.Binding -and ($current.SslFlags -band 1) -eq 0) {
            $sharedEndpoint = @(Get-APKIIisEndpointSite -ServerManager $ServerManager -IPAddress $ip -Port $port -ExcludeSite $siteName).Count -gt 0
        }

        if ($action -eq 'Removed') {
            $found.Site.Bindings.Remove($found.Binding, $sharedEndpoint)
        }
        else {
            if ($found.Binding) {
                $found.Site.Bindings.Remove($found.Binding, ($sharedEndpoint -or [bool]$thumb))
            }
            if ($thumb) {
                $hash = ConvertTo-APKICertificateHash -Thumbprint $thumb
                [void]$found.Site.Bindings.Add($info, $hash, $store, $flags)
            }
            else {
                $nb = $found.Site.Bindings.Add($info, 'https')
                $nb.SslFlags = $flags
            }
        }
        $result.Action = $action
        $results.Add($result)
        $changed++
    }

    if ($changed -gt 0) {
        $ServerManager.CommitChanges()
        Write-APKILog -Message "Restored $changed binding(s) from snapshot $source." -Level Info -EventId 1006 -OrderId $logId
    }

    $results.ToArray()
}
