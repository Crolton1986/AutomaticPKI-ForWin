function Save-APKIBindingSnapshot {
    <#
    .SYNOPSIS
        Records the current state of an order's https bindings before a certificate swap.
    .DESCRIPTION
        Writes <Get-APKIRoot>\snapshots\<Order.Id>\<yyyyMMddTHHmmssfffZ>.json with, per https entry in
        Order.Bindings: SiteName, Protocol, IPAddress, Port, HostHeader, Exists, SslFlags, Thumbprint,
        StoreName. Exists = $false marks bindings a swap may create, so Restore-APKIBindingSnapshot
        removes them.
        Returns the snapshot object (OrderId, CreatedUtc, Bindings, Path) that
        Restore-APKIBindingSnapshot -Order -Snapshot accepts; the same data is on disk at Path.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$Order,

        [object]$ServerManager
    )

    if (-not ($Order.PSObject.Properties['Id'] -and $Order.Id)) {
        throw 'Order has no Id.'
    }
    $orderId = [string]$Order.Id
    if ($orderId -notmatch '^[A-Za-z0-9._-]+$') {
        throw "Order Id '$orderId' is not a valid file name."
    }
    if (-not $ServerManager) {
        $ServerManager = Get-APKIServerManager
    }

    $entries = New-Object System.Collections.Generic.List[object]
    $orderBindings = @()
    if ($Order.PSObject.Properties['Bindings'] -and $Order.Bindings) {
        $orderBindings = @($Order.Bindings | Where-Object { $_.PSObject.Properties['Protocol'] -and [string]$_.Protocol -eq 'https' })
    }
    foreach ($ob in $orderBindings) {
        $ip = '*'
        if ($ob.PSObject.Properties['IPAddress'] -and $ob.IPAddress) {
            $ip = [string]$ob.IPAddress
        }
        $hostHeader = ''
        if ($ob.PSObject.Properties['HostHeader'] -and $ob.HostHeader) {
            $hostHeader = [string]$ob.HostHeader
        }
        $port = [int]$ob.Port
        $found = Find-APKIIisSiteBinding -ServerManager $ServerManager -SiteName ([string]$ob.SiteName) -Protocol 'https' -IPAddress $ip -Port $port -HostHeader $hostHeader
        $entry = [pscustomobject]@{
            SiteName   = [string]$ob.SiteName
            Protocol   = 'https'
            IPAddress  = $ip
            Port       = $port
            HostHeader = $hostHeader
            Exists     = $false
            SslFlags   = 0
            Thumbprint = ''
            StoreName  = ''
        }
        if ($found.Binding) {
            $current = ConvertFrom-APKIIisBinding -SiteName ([string]$ob.SiteName) -Binding $found.Binding
            $entry.Exists = $true
            $entry.SslFlags = $current.SslFlags
            $entry.Thumbprint = $current.Thumbprint
            $entry.StoreName = $current.StoreName
        }
        $entries.Add($entry)
    }

    $now = (Get-Date).ToUniversalTime()
    $snapshot = [pscustomobject]@{
        OrderId    = $orderId
        CreatedUtc = $now.ToString('o')
        Bindings   = [object[]]$entries.ToArray()
    }

    $dir = Join-Path (Join-Path (Get-APKIRoot) 'snapshots') $orderId
    # File names sort chronologically; on a collision move the stamp forward instead of adding a suffix.
    $stamp = $now
    $path = Join-Path $dir ($stamp.ToString("yyyyMMdd'T'HHmmssfff'Z'") + '.json')
    while (Test-Path -LiteralPath $path) {
        $stamp = $stamp.AddMilliseconds(1)
        $path = Join-Path $dir ($stamp.ToString("yyyyMMdd'T'HHmmssfff'Z'") + '.json')
    }

    if ($PSCmdlet.ShouldProcess($path, 'Save binding snapshot')) {
        if (-not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
        $json = ConvertTo-Json -InputObject $snapshot -Depth 5
        Set-Content -LiteralPath $path -Value $json -Encoding UTF8
    }
    $snapshot | Add-Member -MemberType NoteProperty -Name Path -Value $path
    $snapshot
}
