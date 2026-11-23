function Test-APKIAdcsCepProvider {
    <#
    .SYNOPSIS
        Checks that an Order's CES/CEP settings are usable: valid settings, loadable credential,
        and an HTTP response from CepUrl.
    .DESCRIPTION
        CepUrl is fetched with an unauthenticated GET. Any HTTP answer below 400, and 401, 403
        or 405 (authentication required, client certificate required, method not allowed),
        counts as reachable. 404, 5xx and network/TLS errors do not.
        This does not authenticate or check the template; Request-APKIAdcsCepCertificate
        reports those failures.
        Returns [bool]; the reason is logged when $false.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [psobject]$Order
    )

    $setting = Get-APKIAdcsCepSetting -Order $Order
    $orderId = $setting.OrderId

    if ($setting.Problem) {
        Write-APKILog -Message "AdcsCep: order configuration invalid: $($setting.Problem)" -Level Error -EventId 3004 -OrderId $orderId
        return $false
    }

    try {
        $null = Get-APKIAdcsCepCredential -CredentialRef $setting.CredentialRef
    }
    catch {
        Write-APKILog -Message "AdcsCep: cannot load credential '$($setting.CredentialRef)': $($_.Exception.Message)" -Level Error -EventId 3004 -OrderId $orderId
        return $false
    }

    try {
        $statusCode = Invoke-APKICepHttpRequest -Uri $setting.CepUrl
    }
    catch {
        Write-APKILog -Message "AdcsCep: enrollment service $($setting.CepUrl) is unreachable: $($_.Exception.Message)" -Level Warning -OrderId $orderId
        return $false
    }

    if ($statusCode -lt 400 -or $statusCode -in @(401, 403, 405)) {
        Write-APKILog -Message "AdcsCep: enrollment service $($setting.CepUrl) is reachable (HTTP $statusCode)." -Level Info -OrderId $orderId
        return $true
    }

    Write-APKILog -Message "AdcsCep: enrollment service $($setting.CepUrl) answered HTTP $statusCode; check CepUrl." -Level Warning -OrderId $orderId
    return $false
}
