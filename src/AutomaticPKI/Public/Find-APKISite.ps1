function Find-APKISite {
    <#
    .SYNOPSIS
        Scans IIS and proposes one certificate order per site (or shared non-SNI endpoint).
    .DESCRIPTION
        Returns order objects with Status 'Proposed'. Each records the certificate currently bound
        (CurrentThumbprint), so adopting a site changes nothing until the order is approved.
        Provider is the configured DefaultProvider; ProviderSettings are filled when the order is
        approved (Approve-APKIOrder).

        Hostnames come from host headers, SANs of the bound certificate and -HostnameOverride
        (plus HostnameOverride stored on existing orders). Sites without a usable name are
        proposed with empty Hostnames and NameStatus 'NeedsName' (EventId 2001).

        With -Save, proposals are written to the order store. An existing order with the same Id
        or SiteName is never overwritten.
    .PARAMETER CheckDns
        Log EventId 2002 for hostnames that do not resolve to an address of this host.
    .PARAMETER HostnameOverride
        Hashtable of IIS site name to hostnames, for sites whose bindings carry no usable name.
    .PARAMETER Save
        Save new proposals as orders with Status 'Proposed'.
    .EXAMPLE
        Find-APKISite

        Lists the orders that would be proposed for the IIS sites on this server.
    .EXAMPLE
        Find-APKISite -HostnameOverride @{ 'Default Web Site' = @('intranet.contoso.com') } -Save

        Proposes orders, naming the certificate for a site with a blank host header, and saves them.
    .OUTPUTS
        PSCustomObject order (docs/contracts.md) per proposal.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [switch]$CheckDns,

        [hashtable]$HostnameOverride = @{},

        [switch]$Save
    )

    $config = Get-APKIConfig
    $existing = @(Get-APKIOrderData)

    $override = @{}
    foreach ($o in $existing) {
        $names = @(@(Get-APKIOptionalProperty -InputObject $o -Name 'HostnameOverride' -Default @()) | Where-Object { $_ } | ForEach-Object { [string]$_ })
        if ($names.Count -gt 0) {
            $override[[string]$o.SiteName] = [string[]]$names
        }
    }
    foreach ($key in @($HostnameOverride.Keys)) {
        $override[[string]$key] = [string[]]@(@($HostnameOverride[$key]) | Where-Object { $_ } | ForEach-Object { [string]$_ })
    }

    foreach ($candidate in @(Find-APKISiteCandidate -HostnameOverride $override -CheckDns:$CheckDns)) {
        $thumbprint = $null
        foreach ($binding in @($candidate.Bindings)) {
            $t = ConvertTo-APKINormalizedThumbprint -Thumbprint ([string](Get-APKIOptionalProperty -InputObject $binding -Name 'Thumbprint' -Default ''))
            if ([string](Get-APKIOptionalProperty -InputObject $binding -Name 'Protocol' -Default '') -eq 'https' -and $t) {
                $thumbprint = $t
                break
            }
        }

        $siteOverride = @()
        if ($override.ContainsKey([string]$candidate.SiteName)) {
            $siteOverride = @($override[[string]$candidate.SiteName])
        }

        $order = [pscustomobject][ordered]@{
            Id                 = [string]$candidate.Id
            Status             = 'Proposed'
            SiteName           = [string]$candidate.SiteName
            Hostnames          = [string[]]@($candidate.Hostnames)
            Bindings           = [object[]]@($candidate.Bindings)
            Provider           = [string]$config.DefaultProvider
            ProviderSettings   = $null
            CreateBinding      = [bool]$candidate.CreateBinding
            CurrentThumbprint  = $thumbprint
            PreviousThumbprint = $null
            NameStatus         = [string]$candidate.NameStatus
            HostnameOverride   = [string[]]$siteOverride
        }

        if ($Save) {
            $clash = @($existing | Where-Object { $_.Id -eq $order.Id -or $_.SiteName -eq $order.SiteName })
            if ($clash.Count -gt 0) {
                Write-Verbose "Order '$($clash[0].Id)' already exists for site '$($order.SiteName)'; proposal not saved."
            }
            elseif ($PSCmdlet.ShouldProcess("order '$($order.Id)' (site '$($order.SiteName)')", 'Save proposed order')) {
                Save-APKIOrderData -Order $order -Confirm:$false
                Write-APKILog -Message "Proposed order saved for site '$($order.SiteName)' (current certificate: $thumbprint)." -OrderId $order.Id
            }
        }

        $order
    }
}
