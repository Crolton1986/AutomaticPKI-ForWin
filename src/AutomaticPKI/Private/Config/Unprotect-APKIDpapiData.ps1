function Unprotect-APKIDpapiData {
    <#
    .SYNOPSIS
        Decrypts bytes produced by Protect-APKIDpapiData (DPAPI, LocalMachine scope).
    .NOTES
        Wrapper around ProtectedData.Unprotect so tests can mock it on non-Windows hosts.
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]
        [byte[]]$Data
    )

    Import-APKIProtectedDataType
    $entropy = [System.Text.Encoding]::UTF8.GetBytes('AutomaticPKI.Secret.v1')
    $result = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $Data, $entropy, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
    , $result
}
