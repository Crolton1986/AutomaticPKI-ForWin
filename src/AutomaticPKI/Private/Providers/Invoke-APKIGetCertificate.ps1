function Invoke-APKIGetCertificate {
    <#
    .SYNOPSIS
        Thin wrapper around the PKI module's Get-Certificate cmdlet (the only place it is called).
    .DESCRIPTION
        'Submit' parameter set: submits a new request to a CES/CEP enrollment policy URL.
        'Pending' parameter set: loads the pending request from Cert:\LocalMachine\Request by its
        thumbprint and calls Get-Certificate -Request to retrieve the issued certificate.

        Returns the Microsoft.CertificateServices.Commands.EnrollmentResult object unchanged
        (properties used by callers: Status, Certificate, Request). Errors are terminating.
        Unit tests mock this function; it only runs against the real PKI module.
    .NOTES
        Get-Certificate has no parameters for key algorithm, key length or exportability. The
        certificate template (delivered by the enrollment policy) decides them.
        Get-Certificate -CertStoreLocation only supports the My store.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Submit')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Submit')]
        [string]$Template,

        [Parameter(Mandatory, ParameterSetName = 'Submit')]
        [string]$Url,

        [Parameter(ParameterSetName = 'Submit')]
        [string[]]$DnsName,

        [Parameter(ParameterSetName = 'Submit')]
        [string]$SubjectName,

        [Parameter(ParameterSetName = 'Submit')]
        [string]$CertStoreLocation = 'Cert:\LocalMachine\My',

        # Thumbprint of the request object Get-Certificate left in Cert:\LocalMachine\Request.
        [Parameter(Mandatory, ParameterSetName = 'Pending')]
        [string]$RequestThumbprint,

        # Omit for Kerberos / Windows integrated authentication.
        [pscredential]$Credential
    )

    $params = @{
        ErrorAction = 'Stop'
        Confirm     = $false
    }

    if ($PSCmdlet.ParameterSetName -eq 'Pending') {
        $path = 'Cert:\LocalMachine\Request\' + $RequestThumbprint
        try {
            $request = Get-Item -LiteralPath $path -ErrorAction Stop
        }
        catch {
            throw "Pending request '$RequestThumbprint' was not found in Cert:\LocalMachine\Request (deleted, or already retrieved): $($_.Exception.Message)"
        }
        $params.Request = $request
    }
    else {
        $params.Template = $Template
        $params.Url = $Url
        $params.CertStoreLocation = $CertStoreLocation
        if ($DnsName) { $params.DnsName = $DnsName }
        if ($SubjectName) { $params.SubjectName = $SubjectName }
    }

    if ($null -ne $Credential) {
        $params.Credential = $Credential
    }

    Get-Certificate @params
}
