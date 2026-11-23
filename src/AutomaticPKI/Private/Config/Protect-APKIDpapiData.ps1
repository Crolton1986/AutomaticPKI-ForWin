function Protect-APKIDpapiData {
    <#
    .SYNOPSIS
        Encrypts bytes with DPAPI, LocalMachine scope (any account on this host can decrypt;
        the secrets directory ACL limits who can read the file).
    .NOTES
        Wrapper around ProtectedData.Protect so tests can mock it on non-Windows hosts.
        The fixed entropy must match Unprotect-APKIDpapiData.
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [byte[]]$Data
    )

    Import-APKIProtectedDataType
    $entropy = [System.Text.Encoding]::UTF8.GetBytes('AutomaticPKI.Secret.v1')
    $result = [System.Security.Cryptography.ProtectedData]::Protect(
        $Data, $entropy, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
    # Leading comma: emit the byte[] as one object instead of unrolling it.
    , $result
}
