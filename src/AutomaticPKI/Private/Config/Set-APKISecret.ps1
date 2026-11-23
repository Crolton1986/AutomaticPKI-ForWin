function Set-APKISecret {
    <#
    .SYNOPSIS
        Stores a credential as <root>\secrets\<Name>.xml, password encrypted with DPAPI (LocalMachine).
    .DESCRIPTION
        LocalMachine scope means SYSTEM (the scheduled task) and any administrator on this host can
        read it back with Get-APKISecret; the secrets folder ACL keeps other accounts out. The file
        is not portable to another host. The user name is stored in clear text; the password never is.
        Name is what config/order fields like CredentialRef refer to.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential
    )

    Assert-APKISafeName -Name $Name -Kind 'secret name'
    $path = Join-Path (Join-Path (Get-APKIRoot) 'secrets') "$Name.xml"
    if (-not $PSCmdlet.ShouldProcess($path, 'Store DPAPI-protected secret')) {
        return
    }

    $dir = Initialize-APKISecretStore
    $path = Join-Path $dir "$Name.xml"

    $plainBytes = $null
    $protectedBytes = $null
    try {
        $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($Credential.GetNetworkCredential().Password)
        [byte[]]$protectedBytes = Protect-APKIDpapiData -Data $plainBytes
        if ($null -eq $protectedBytes -or $protectedBytes.Length -eq 0) {
            throw 'DPAPI returned no data.'
        }

        $record = [pscustomobject]@{
            Version   = 1
            Name      = $Name
            UserName  = $Credential.UserName
            Scope     = 'LocalMachine'
            Protected = [System.Convert]::ToBase64String($protectedBytes)
            Updated   = (Get-Date).ToUniversalTime().ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
        }

        $tempPath = '{0}.{1}.tmp' -f $path, ([guid]::NewGuid().ToString('N'))
        try {
            Export-Clixml -LiteralPath $tempPath -InputObject $record -Encoding UTF8 -WhatIf:$false -ErrorAction Stop
            Move-Item -LiteralPath $tempPath -Destination $path -Force -WhatIf:$false -ErrorAction Stop
        }
        catch {
            Remove-Item -LiteralPath $tempPath -Force -WhatIf:$false -ErrorAction SilentlyContinue
            throw
        }
    }
    catch {
        throw ("Could not store secret '{0}': {1}" -f $Name, $_.Exception.Message)
    }
    finally {
        if ($null -ne $plainBytes) {
            [System.Array]::Clear($plainBytes, 0, $plainBytes.Length)
        }
    }

    Write-APKILog -Message "Secret '$Name' stored (DPAPI LocalMachine)."
}
