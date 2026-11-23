function Get-APKIAdcsCepCredential {
    <#
    .SYNOPSIS
        Resolves ProviderSettings.CredentialRef to a PSCredential for Get-Certificate -Credential.
    .DESCRIPTION
        Null/empty CredentialRef returns $null: Get-Certificate then uses Kerberos / Windows
        integrated authentication as the computer account (scheduled task runs as SYSTEM).
        Otherwise loads the DPAPI-protected secret through Get-APKISecret (T2) and requires a
        PSCredential (user name + password for a CEP/CES endpoint using UsernamePassword auth).
        Throws when the secret cannot be loaded or has the wrong type.
    #>
    [CmdletBinding()]
    [OutputType([pscredential])]
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string]$CredentialRef
    )

    if ([string]::IsNullOrWhiteSpace($CredentialRef)) {
        return $null
    }

    $secret = Get-APKISecret -Name $CredentialRef -ErrorAction Stop
    if ($null -eq $secret) {
        throw "Secret '$CredentialRef' was not found."
    }
    if (-not ($secret -is [pscredential])) {
        throw "Secret '$CredentialRef' is a $($secret.GetType().FullName), expected a PSCredential (user name and password)."
    }
    $secret
}
