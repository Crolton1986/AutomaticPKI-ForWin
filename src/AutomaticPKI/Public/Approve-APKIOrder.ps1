function Approve-APKIOrder {
    <#
    .SYNOPSIS
        Approves an order so the next renewal run requests and binds a certificate for it.
    .DESCRIPTION
        Sets Status 'Approved'. -Hostname replaces Hostnames (first name = subject CN).
        -Provider / -ProviderSettings replace the order's values; when the order has no
        ProviderSettings they are copied from the configured DefaultProviderSettings (only when
        the order uses the DefaultProvider). Refuses an order without hostnames.
        Approving an Active or Pending order makes the next run request a new certificate.
    .PARAMETER Id
        Order Id (see Get-APKIOrder).
    .PARAMETER Hostname
        Hostnames for the certificate; replaces the order's Hostnames.
    .PARAMETER Provider
        AdcsRpc or AdcsCep.
    .PARAMETER ProviderSettings
        Hashtable or object. AdcsRpc: CAConfig, Template. AdcsCep: CepUrl, Template, CredentialRef.
    .EXAMPLE
        Approve-APKIOrder -Id contoso-web

        Approves a proposed order with the hostnames found by discovery.
    .EXAMPLE
        Approve-APKIOrder -Id default-web-site -Hostname intranet.contoso.com, intranet

        Names the certificate for a site whose binding has no host header, then approves it.
    .EXAMPLE
        Approve-APKIOrder -Id shop -Provider AdcsCep -ProviderSettings @{ CepUrl = 'https://cep.contoso.com/ADPolicyProvider_CEP_Kerberos/service.svc/CEP'; Template = 'WebServer'; CredentialRef = $null }
    .OUTPUTS
        The approved order.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [string]$Id,

        [string[]]$Hostname,

        [ValidateSet('AdcsRpc', 'AdcsCep')]
        [string]$Provider,

        [object]$ProviderSettings
    )

    process {
        $order = Get-APKIOrderData -Id $Id
        if ($null -eq $order) {
            throw "Order '$Id' does not exist."
        }

        if ($PSBoundParameters.ContainsKey('Hostname')) {
            $names = New-Object System.Collections.Generic.List[string]
            foreach ($h in @($Hostname)) {
                $n = ([string]$h).Trim().TrimEnd('.').ToLowerInvariant()
                if ($n -and -not $names.Contains($n)) {
                    $names.Add($n)
                }
            }
            Set-APKIObjectProperty -InputObject $order -Name 'Hostnames' -Value ([string[]]$names.ToArray())
        }

        $hostnames = @(@(Get-APKIOptionalProperty -InputObject $order -Name 'Hostnames' -Default @()) | Where-Object { $_ })
        if ($hostnames.Count -eq 0) {
            throw "Order '$Id' has no hostnames. Supply them with -Hostname."
        }

        if ($Provider) {
            Set-APKIObjectProperty -InputObject $order -Name 'Provider' -Value $Provider
        }

        if ($PSBoundParameters.ContainsKey('ProviderSettings')) {
            $settings = $null
            if ($null -ne $ProviderSettings) {
                $settings = ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $ProviderSettings -Depth 5)
            }
            Set-APKIObjectProperty -InputObject $order -Name 'ProviderSettings' -Value $settings
        }

        if ($null -eq (Get-APKIOptionalProperty -InputObject $order -Name 'ProviderSettings' -Default $null)) {
            $config = Get-APKIConfig
            if ([string]$order.Provider -cne [string]$config.DefaultProvider) {
                throw "Order '$Id' uses provider '$($order.Provider)' but the configured DefaultProvider is '$($config.DefaultProvider)'. Pass -ProviderSettings."
            }
            $defaults = ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $config.DefaultProviderSettings -Depth 5)
            Set-APKIObjectProperty -InputObject $order -Name 'ProviderSettings' -Value $defaults
        }

        $ps = $order.ProviderSettings
        if ([string]$order.Provider -ceq 'AdcsRpc' -and -not [string](Get-APKIOptionalProperty -InputObject $ps -Name 'CAConfig' -Default '')) {
            Write-APKILog -Message "Order '$Id' has no CAConfig; requests will fail until one is configured." -Level Warning -OrderId $Id
        }

        Set-APKIObjectProperty -InputObject $order -Name 'Status' -Value 'Approved'
        Set-APKIObjectProperty -InputObject $order -Name 'PendingRequestId' -Value $null

        if ($PSCmdlet.ShouldProcess("order '$Id'", 'Approve')) {
            Save-APKIOrderData -Order $order -Confirm:$false
            Write-APKILog -Message ("Order approved for {0} via {1}." -f ($hostnames -join ', '), $order.Provider) -OrderId $Id
            $order
        }
    }
}
