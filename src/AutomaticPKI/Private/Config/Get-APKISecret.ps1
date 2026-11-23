function Get-APKISecret {
    <#
    .SYNOPSIS
        Reads <root>\secrets\<Name>.xml written by Set-APKISecret and returns a PSCredential.
    .DESCRIPTION
        Throws if the secret does not exist, the file is malformed, or DPAPI cannot decrypt it
        (for example a file copied from another host).
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCredential])]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    Assert-APKISafeName -Name $Name -Kind 'secret name'
    $path = Join-Path (Join-Path (Get-APKIRoot) 'secrets') "$Name.xml"
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Secret '$Name' not found at '$path'. Store it with Set-APKISecret."
    }

    $plainBytes = $null
    $chars = $null
    try {
        $record = Import-Clixml -LiteralPath $path -ErrorAction Stop
        foreach ($required in @('UserName', 'Protected')) {
            if ($null -eq $record.PSObject.Properties[$required] -or [string]::IsNullOrEmpty([string]$record.$required)) {
                throw "the file has no $required."
            }
        }

        [byte[]]$protectedBytes = [System.Convert]::FromBase64String([string]$record.Protected)
        [byte[]]$plainBytes = Unprotect-APKIDpapiData -Data $protectedBytes
        if ($null -eq $plainBytes) {
            $plainBytes = [byte[]]@()
        }

        $chars = [System.Text.Encoding]::UTF8.GetChars($plainBytes)
        $secure = New-Object System.Security.SecureString
        foreach ($c in $chars) {
            $secure.AppendChar($c)
        }
        $secure.MakeReadOnly()

        New-Object System.Management.Automation.PSCredential -ArgumentList ([string]$record.UserName), $secure
    }
    catch {
        throw ("Could not read secret '{0}': {1}" -f $Name, $_.Exception.Message)
    }
    finally {
        if ($null -ne $plainBytes) {
            [System.Array]::Clear($plainBytes, 0, $plainBytes.Length)
        }
        if ($null -ne $chars) {
            [System.Array]::Clear($chars, 0, $chars.Length)
        }
    }
}
