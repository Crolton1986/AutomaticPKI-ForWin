function Get-APKIGpoEnrollmentPolicyServer {
    <#
    .SYNOPSIS
        Wraps Get-CertificateEnrollmentPolicyServer -Scope All -Context Machine (PKI module).
    .DESCRIPTION
        Returns the machine's enrollment policy server configurations (Group Policy and local)
        unchanged (Microsoft.CertificateServices.Commands.EnrollmentPolicyUrlDescription).
        Callers read Url and, when present, Id / AuthType / FriendlyName. Errors are terminating;
        mock this in tests.
    #>
    [CmdletBinding()]
    param()

    Get-CertificateEnrollmentPolicyServer -Scope All -Context Machine -ErrorAction Stop
}
