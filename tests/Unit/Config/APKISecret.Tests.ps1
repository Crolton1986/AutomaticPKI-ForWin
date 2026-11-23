BeforeDiscovery {
    # -Skip is evaluated during discovery, before BeforeAll runs.
    $script:IsWindowsHost = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
}

BeforeAll {
    $script:ModulePath = Join-Path $PSScriptRoot '../../../src/AutomaticPKI/AutomaticPKI.psd1'
    Import-Module $script:ModulePath -Force
    $script:SavedRoot = $env:APKI_ROOT

    function Get-TestCredential {
        param(
            [string]$UserName = 'CORP\svc-apki',
            [string]$Plain = 'P@ss w0rd-unit'
        )
        $secure = New-Object System.Security.SecureString
        foreach ($c in $Plain.ToCharArray()) {
            $secure.AppendChar($c)
        }
        New-Object System.Management.Automation.PSCredential -ArgumentList $UserName, $secure
    }
}

AfterAll {
    $env:APKI_ROOT = $script:SavedRoot
}

Describe 'Set-APKISecret / Get-APKISecret' {
    BeforeEach {
        $env:APKI_ROOT = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $env:APKI_ROOT -Force | Out-Null
        $script:SecretDir = Join-Path $env:APKI_ROOT 'secrets'
        Mock Write-APKILog -ModuleName AutomaticPKI { }

        # Reversible stand-in for DPAPI so the round trip runs on any OS. Like DPAPI, the
        # output is never empty (a header byte is prepended).
        Mock Protect-APKIDpapiData -ModuleName AutomaticPKI {
            , [byte[]](@(0xA5) + @($Data | ForEach-Object { $_ -bxor 0x5A }))
        }
        Mock Unprotect-APKIDpapiData -ModuleName AutomaticPKI {
            , [byte[]]@($Data | Select-Object -Skip 1 | ForEach-Object { $_ -bxor 0x5A })
        }
        Mock Initialize-APKISecretStore -ModuleName AutomaticPKI {
            $dir = Join-Path $env:APKI_ROOT 'secrets'
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            $dir
        }
    }

    It 'round-trips a credential through secrets/<Name>.xml' {
        InModuleScope AutomaticPKI -Parameters @{ Credential = (Get-TestCredential) } {
            param($Credential)
            Set-APKISecret -Name 'smtp-relay' -Credential $Credential
        }

        Join-Path $script:SecretDir 'smtp-relay.xml' | Should -Exist
        $credential = InModuleScope AutomaticPKI { Get-APKISecret -Name 'smtp-relay' }

        $credential | Should -BeOfType [System.Management.Automation.PSCredential]
        $credential.UserName | Should -Be 'CORP\svc-apki'
        $credential.GetNetworkCredential().Password | Should -Be 'P@ss w0rd-unit'
        Should -Invoke Protect-APKIDpapiData -ModuleName AutomaticPKI -Times 1 -Exactly
        Should -Invoke Unprotect-APKIDpapiData -ModuleName AutomaticPKI -Times 1 -Exactly
    }

    It 'never writes the password in clear text' {
        InModuleScope AutomaticPKI -Parameters @{ Credential = (Get-TestCredential) } {
            param($Credential)
            Set-APKISecret -Name 'smtp-relay' -Credential $Credential
        }

        $raw = Get-Content -LiteralPath (Join-Path $script:SecretDir 'smtp-relay.xml') -Raw -Encoding UTF8
        $raw | Should -Not -Match 'P@ss w0rd-unit'
        $raw | Should -Match 'LocalMachine'
    }

    It 'round-trips an empty password and non-ASCII characters' {
        InModuleScope AutomaticPKI -Parameters @{ Empty = (Get-TestCredential -Plain ''); Intl = (Get-TestCredential -Plain ([string][char]0x00E9 + [char]0x4E2D + 'x')) } {
            param($Empty, $Intl)
            Set-APKISecret -Name 'empty' -Credential $Empty
            Set-APKISecret -Name 'intl' -Credential $Intl
        }

        (InModuleScope AutomaticPKI { Get-APKISecret -Name 'empty' }).GetNetworkCredential().Password | Should -Be ''
        (InModuleScope AutomaticPKI { Get-APKISecret -Name 'intl' }).GetNetworkCredential().Password |
            Should -Be ([string][char]0x00E9 + [char]0x4E2D + 'x')
    }

    It 'overwrites an existing secret and leaves no temp files' {
        InModuleScope AutomaticPKI -Parameters @{ First = (Get-TestCredential -Plain 'one'); Second = (Get-TestCredential -Plain 'two') } {
            param($First, $Second)
            Set-APKISecret -Name 'cep' -Credential $First
            Set-APKISecret -Name 'cep' -Credential $Second
        }

        (InModuleScope AutomaticPKI { Get-APKISecret -Name 'cep' }).GetNetworkCredential().Password | Should -Be 'two'
        @(Get-ChildItem -LiteralPath $script:SecretDir -Filter '*.tmp').Count | Should -Be 0
    }

    It 'writes nothing with -WhatIf' {
        InModuleScope AutomaticPKI -Parameters @{ Credential = (Get-TestCredential) } {
            param($Credential)
            Set-APKISecret -Name 'smtp-relay' -Credential $Credential -WhatIf
        }

        Join-Path $script:SecretDir 'smtp-relay.xml' | Should -Not -Exist
        Should -Invoke Protect-APKIDpapiData -ModuleName AutomaticPKI -Times 0 -Exactly
    }

    It 'throws a clear error for a missing secret' {
        { InModuleScope AutomaticPKI { Get-APKISecret -Name 'nope' } } | Should -Throw "*Secret 'nope' not found*"
    }

    It 'rejects an unsafe secret name' {
        { InModuleScope AutomaticPKI -Parameters @{ Credential = (Get-TestCredential) } {
                param($Credential)
                Set-APKISecret -Name '..\evil' -Credential $Credential
            } } | Should -Throw '*Invalid secret name*'
    }

    It 'throws a clear error when DPAPI cannot decrypt' {
        InModuleScope AutomaticPKI -Parameters @{ Credential = (Get-TestCredential) } {
            param($Credential)
            Set-APKISecret -Name 'moved' -Credential $Credential
        }
        Mock Unprotect-APKIDpapiData -ModuleName AutomaticPKI { throw 'Key not valid for use in specified state.' }

        { InModuleScope AutomaticPKI { Get-APKISecret -Name 'moved' } } | Should -Throw "*Could not read secret 'moved'*Key not valid*"
    }
}

Describe 'DPAPI wrappers (Windows only)' {
    BeforeEach {
        $env:APKI_ROOT = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $env:APKI_ROOT -Force | Out-Null
        Mock Write-APKILog -ModuleName AutomaticPKI { }
    }

    It 'round-trips bytes with real DPAPI LocalMachine scope' -Skip:(-not $script:IsWindowsHost) {
        $result = InModuleScope AutomaticPKI {
            $plain = [System.Text.Encoding]::UTF8.GetBytes('dpapi round trip')
            [byte[]]$protected = Protect-APKIDpapiData -Data $plain
            [byte[]]$back = Unprotect-APKIDpapiData -Data $protected
            [pscustomobject]@{
                Different = ([System.Convert]::ToBase64String($protected) -ne [System.Convert]::ToBase64String($plain))
                Text      = [System.Text.Encoding]::UTF8.GetString($back)
            }
        }

        $result.Different | Should -BeTrue
        $result.Text | Should -Be 'dpapi round trip'
    }

    It 'restricts the secrets folder to SYSTEM and Administrators' -Skip:(-not $script:IsWindowsHost) {
        $dir = InModuleScope AutomaticPKI { Initialize-APKISecretStore }

        $acl = Get-Acl -LiteralPath $dir
        $acl.AreAccessRulesProtected | Should -BeTrue
        $sids = @($acl.Access | ForEach-Object {
                $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
            } | Sort-Object -Unique)
        ($sids -join ',') | Should -Be 'S-1-5-18,S-1-5-32-544'
    }
}
