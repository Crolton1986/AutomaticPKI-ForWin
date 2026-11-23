function Receive-APKIAdcsCepCertificate {
    <#
    .SYNOPSIS
        Retrieves a pending CES/CEP request (Get-Certificate -Request) once the CA has approved it.
    .DESCRIPTION
        RequestId is the value Request-APKIAdcsCepCertificate returned with Status Pending: the
        40-hex thumbprint of the request object in Cert:\LocalMachine\Request (the private key
        lives with that request, so retrieval must run on the same host).
        Credentials follow Order.ProviderSettings.CredentialRef, as for the original request.

        Returns a ProviderResult: Issued (certificate installed in Cert:\LocalMachine\My),
        Pending (still waiting; logged without an Event Log entry), Denied or Failed.
        With -WhatIf nothing is retrieved and nothing is returned.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [psobject]$Order,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$RequestId
    )

    $setting = Get-APKIAdcsCepSetting -Order $Order
    $orderId = $setting.OrderId

    if ($setting.Problem) {
        $message = "AdcsCep: order configuration invalid: $($setting.Problem)"
        Write-APKILog -Message $message -Level Error -EventId 3004 -OrderId $orderId
        return New-APKIAdcsCepResult -Status Failed -RequestId $RequestId -Message $message
    }

    if ($RequestId -notmatch '^[0-9A-Fa-f]{40}$') {
        $message = "AdcsCep: RequestId '$RequestId' is not a request-store thumbprint (40 hex characters) as returned by Request-APKIAdcsCepCertificate."
        Write-APKILog -Message $message -Level Error -EventId 3004 -OrderId $orderId
        return New-APKIAdcsCepResult -Status Failed -RequestId $RequestId -Message $message
    }
    $thumbprint = $RequestId.ToUpperInvariant()

    try {
        $credential = Get-APKIAdcsCepCredential -CredentialRef $setting.CredentialRef
    }
    catch {
        $message = "AdcsCep: cannot load credential '$($setting.CredentialRef)': $($_.Exception.Message)"
        Write-APKILog -Message $message -Level Error -EventId 3004 -OrderId $orderId
        return New-APKIAdcsCepResult -Status Failed -RequestId $thumbprint -Message $message
    }

    $params = @{
        RequestThumbprint = $thumbprint
    }
    if ($null -ne $credential) {
        $params.Credential = $credential
    }

    if (-not $PSCmdlet.ShouldProcess("pending request $thumbprint", 'Retrieve certificate')) {
        return
    }

    try {
        $enrollment = Invoke-APKIGetCertificate @params
    }
    catch {
        $info = Get-APKIAdcsCepErrorInfo -ErrorRecord $_ -Setting $setting
        Write-APKILog -Message $info.Message -Level Error -EventId $info.EventId -OrderId $orderId
        return New-APKIAdcsCepResult -Status $info.Status -RequestId $thumbprint -Message $info.Message
    }

    ConvertFrom-APKIAdcsCepEnrollmentResult -EnrollmentResult $enrollment -Setting $setting -RequestId $thumbprint -Retrieval
}
