function Request-APKIAdcsCepCertificate {
    <#
    .SYNOPSIS
        Requests a certificate for an Order over CES/CEP (HTTPS) with Get-Certificate.
    .DESCRIPTION
        Uses Order.ProviderSettings:
          CepUrl         enrollment policy (CEP) URL, https only
          Template       template name or OID
          CredentialRef  $null = Kerberos (computer account); otherwise a PSCredential secret
                         loaded with Get-APKISecret
        The request carries SubjectName "CN=<first hostname>" and DnsName = all Hostnames (SAN).
        The issued certificate and its private key land in Cert:\LocalMachine\My.

        Returns a ProviderResult (docs/contracts.md):
          Issued   Thumbprint of the new certificate
          Pending  RequestId = thumbprint of the request object in Cert:\LocalMachine\Request;
                   pass it to Receive-APKIAdcsCepCertificate (keep it in Order.PendingRequestId)
          Denied   the CA denied the request (event 3001)
          Failed   configuration, credential, connectivity, authentication or template error
                   (event 3004 for configuration, 3000 otherwise)
        With -WhatIf nothing is submitted and nothing is returned.
    .NOTES
        Get-Certificate has no key parameters: algorithm, length and exportability come from the
        certificate template (Cryptography and Request Handling tabs). Order.Key is not applied;
        a warning is logged when the issued key differs from Order.Key. Order.Key.Exportable is
        not checked.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [psobject]$Order
    )

    $setting = Get-APKIAdcsCepSetting -Order $Order
    $orderId = $setting.OrderId

    if ($setting.Problem) {
        $message = "AdcsCep: order configuration invalid: $($setting.Problem)"
        Write-APKILog -Message $message -Level Error -EventId 3004 -OrderId $orderId
        return New-APKIAdcsCepResult -Status Failed -Message $message
    }

    try {
        $credential = Get-APKIAdcsCepCredential -CredentialRef $setting.CredentialRef
    }
    catch {
        $message = "AdcsCep: cannot load credential '$($setting.CredentialRef)': $($_.Exception.Message)"
        Write-APKILog -Message $message -Level Error -EventId 3004 -OrderId $orderId
        return New-APKIAdcsCepResult -Status Failed -Message $message
    }

    $params = @{
        Template          = $setting.Template
        Url               = $setting.CepUrl
        DnsName           = [string[]]$setting.Hostnames
        SubjectName       = 'CN=' + $setting.Hostnames[0]
        CertStoreLocation = 'Cert:\LocalMachine\My'
    }
    if ($null -ne $credential) {
        $params.Credential = $credential
    }

    $target = "template '$($setting.Template)' at $($setting.CepUrl) for $($setting.Hostnames -join ', ')"
    if (-not $PSCmdlet.ShouldProcess($target, 'Submit certificate request')) {
        return
    }

    try {
        $enrollment = Invoke-APKIGetCertificate @params
    }
    catch {
        $info = Get-APKIAdcsCepErrorInfo -ErrorRecord $_ -Setting $setting
        Write-APKILog -Message $info.Message -Level Error -EventId $info.EventId -OrderId $orderId
        return New-APKIAdcsCepResult -Status $info.Status -Message $info.Message
    }

    ConvertFrom-APKIAdcsCepEnrollmentResult -EnrollmentResult $enrollment -Setting $setting
}
