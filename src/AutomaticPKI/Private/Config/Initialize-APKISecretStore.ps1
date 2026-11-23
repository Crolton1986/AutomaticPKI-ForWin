function Initialize-APKISecretStore {
    <#
    .SYNOPSIS
        Creates <root>\secrets and, on Windows, restricts it to SYSTEM and Administrators.
    .DESCRIPTION
        DPAPI LocalMachine scope lets any local account decrypt, so the directory ACL is what keeps
        other users out. Inheritance is disabled; SYSTEM (S-1-5-18) and BUILTIN\Administrators
        (S-1-5-32-544) get Full Control on the folder and the files in it. Returns the directory.
        An ACL failure is logged as a warning, not thrown.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $dir = Join-Path (Get-APKIRoot) 'secrets'
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force -WhatIf:$false -ErrorAction Stop | Out-Null
    }

    if ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) {
        try {
            $acl = New-Object System.Security.AccessControl.DirectorySecurity
            $acl.SetAccessRuleProtection($true, $false)
            foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
                $identity = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList $sid
                $rule = New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList @(
                    $identity,
                    [System.Security.AccessControl.FileSystemRights]::FullControl,
                    ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
                    [System.Security.AccessControl.PropagationFlags]::None,
                    [System.Security.AccessControl.AccessControlType]::Allow)
                $acl.AddAccessRule($rule)
            }
            Set-Acl -LiteralPath $dir -AclObject $acl -WhatIf:$false -ErrorAction Stop
        }
        catch {
            Write-APKILog -Level Warning -Message ("Could not restrict access to '{0}': {1}" -f $dir, $_.Exception.Message)
        }
    }

    $dir
}
