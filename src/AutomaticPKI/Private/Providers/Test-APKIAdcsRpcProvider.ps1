function Test-APKIAdcsRpcProvider {
    <#
    .SYNOPSIS
        AdcsRpc provider: checks the CA in Order.ProviderSettings.CAConfig answers
        (certutil -config <CAConfig> -ping). Logs the reason when it returns $false.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [object]$Order
    )

    $orderId = $null
    if ($Order.PSObject.Properties['Id']) { $orderId = [string]$Order.Id }

    $settings = $null
    try {
        $settings = Get-APKIAdcsRpcSetting -Order $Order
    }
    catch {
        Write-APKILog -Message $_.Exception.Message -Level Warning -EventId 3004 -OrderId $orderId
        return $false
    }

    $ping = Invoke-APKICertutil -Arguments @('-config', $settings.CAConfig, '-ping')
    if ($ping.ExitCode -eq 0) {
        return $true
    }

    $detail = (@($ping.Output) | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim() }) -join ' '
    Write-APKILog -Message ("CA '{0}' did not answer certutil -ping (exit {1}): {2}" -f $settings.CAConfig, $ping.ExitCode, $detail) -Level Warning -OrderId $orderId
    $false
}
