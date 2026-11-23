BeforeAll {
    Import-Module ([System.IO.Path]::Combine($PSScriptRoot, '..', '..', '..', 'src', 'AutomaticPKI', 'AutomaticPKI.psd1')) -Force

    $script:BoundThumb = 'A1' * 20
}

AfterAll {
    Remove-Module AutomaticPKI -Force -ErrorAction SilentlyContinue
}

Describe 'Install-APKI' {
    BeforeEach {
        $env:APKI_ROOT = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $script:Destination = Join-Path (Join-Path $env:APKI_ROOT 'modules') 'AutomaticPKI'

        Mock -ModuleName AutomaticPKI Write-APKILog { }
        Mock -ModuleName AutomaticPKI Send-APKINotification { }
        Mock -ModuleName AutomaticPKI Invoke-APKIScheduledTask { } -ParameterFilter { $Operation -eq 'Get' }
        Mock -ModuleName AutomaticPKI Invoke-APKIScheduledTask { [pscustomobject]@{ TaskName = $TaskName } } -ParameterFilter { $Operation -eq 'Register' }
        Mock -ModuleName AutomaticPKI Find-APKISiteCandidate {
            [pscustomobject]@{
                Id            = 'contoso-web'
                Status        = 'Proposed'
                SiteName      = 'Contoso Web'
                Hostnames     = [string[]]@('www.contoso.com')
                Bindings      = [object[]]@([pscustomobject]@{
                        SiteName = 'Contoso Web'; Protocol = 'https'; IPAddress = '*'; Port = 443; HostHeader = 'www.contoso.com'
                        SslFlags = 1; Thumbprint = ('a1' * 20); StoreName = 'My'; NameStatus = 'Usable'; SharedWith = [string[]]@()
                        BindingInformation = '*:443:www.contoso.com'
                    })
                NameStatus    = 'Usable'
                CreateBinding = $false
            }
            [pscustomobject]@{
                Id            = 'default-web-site'
                Status        = 'Proposed'
                SiteName      = 'Default Web Site'
                Hostnames     = [string[]]@()
                Bindings      = [object[]]@()
                NameStatus    = 'NeedsName'
                CreateBinding = $false
            }
        }
        # Nothing may be issued or bound on install.
        Mock -ModuleName AutomaticPKI Request-APKIAdcsRpcCertificate { throw 'must not request' }
        Mock -ModuleName AutomaticPKI Request-APKIAdcsCepCertificate { throw 'must not request' }
        Mock -ModuleName AutomaticPKI Invoke-APKISwapWithRollback { throw 'must not swap' }
        Mock -ModuleName AutomaticPKI Set-APKIIisCertificateBinding { throw 'must not bind' }
    }

    It 'copies the module, registers the task for the installed copy and adopts IIS sites without issuing' {
        $r = Install-APKI -Destination $script:Destination -Config @{ DefaultProviderSettings = @{ CAConfig = 'ca01\Contoso CA' } }

        Join-Path $script:Destination 'AutomaticPKI.psd1' | Should -Exist
        Join-Path $script:Destination 'AutomaticPKI.psm1' | Should -Exist
        Join-Path $script:Destination 'Public' | Should -Exist
        Join-Path $script:Destination 'Private' | Should -Exist

        $manifest = Join-Path $script:Destination 'AutomaticPKI.psd1'
        Should -Invoke -ModuleName AutomaticPKI Invoke-APKIScheduledTask -Times 1 -Exactly -ParameterFilter {
            $Operation -eq 'Register' -and $Argument.Contains($manifest)
        }
        $r.TaskRegistered | Should -BeTrue
        $r.ModulePath | Should -Be $manifest

        @($r.ProposedOrders) | Should -Be @('contoso-web', 'default-web-site')
        $order = Get-APKIOrder -Id 'contoso-web'
        $order.Status | Should -Be 'Proposed'
        $order.CurrentThumbprint | Should -Be $script:BoundThumb
        $order.Provider | Should -Be 'AdcsRpc'
        (Get-APKIOrder -Id 'default-web-site').NameStatus | Should -Be 'NeedsName'

        Should -Invoke -ModuleName AutomaticPKI Request-APKIAdcsRpcCertificate -Times 0 -Exactly
        Should -Invoke -ModuleName AutomaticPKI Invoke-APKISwapWithRollback -Times 0 -Exactly
        Should -Invoke -ModuleName AutomaticPKI Set-APKIIisCertificateBinding -Times 0 -Exactly
    }

    It 'merges -Config into the existing configuration instead of replacing it' {
        InModuleScope AutomaticPKI {
            $c = Get-APKIConfig
            $c.LogRetentionDays = 60
            $c.Smtp.Server = 'mail.contoso.com'
            Set-APKIConfig -Config $c
        }

        $r = Install-APKI -Destination $script:Destination -NoTask -Config @{
            RenewalDaysBefore       = 20
            DefaultProviderSettings = @{ CAConfig = 'ca01\Contoso CA' }
            Smtp                    = @{ Enabled = $true; From = 'pki@contoso.com'; To = @('ops@contoso.com') }
        }

        $config = InModuleScope AutomaticPKI { Get-APKIConfig }
        $config.RenewalDaysBefore | Should -Be 20
        $config.LogRetentionDays | Should -Be 60
        $config.DefaultProviderSettings.CAConfig | Should -Be 'ca01\Contoso CA'
        $config.DefaultProviderSettings.Template | Should -Be 'WebServer'
        $config.Smtp.Server | Should -Be 'mail.contoso.com'
        $config.Smtp.Enabled | Should -BeTrue
        $r.CAConfigured | Should -BeTrue
        $r.TaskRegistered | Should -BeFalse
        Should -Invoke -ModuleName AutomaticPKI Invoke-APKIScheduledTask -Times 0 -Exactly -ParameterFilter { $Operation -eq 'Register' }
    }

    It 'never overwrites an existing order on a second install' {
        $null = Install-APKI -Destination $script:Destination -NoTask
        $existing = Get-APKIOrder -Id 'contoso-web'
        $null = Approve-APKIOrder -Id 'contoso-web' -ProviderSettings @{ CAConfig = 'ca01\Contoso CA'; Template = 'WebServer' }

        $r = Install-APKI -Destination $script:Destination -NoTask
        @($r.ProposedOrders).Count | Should -Be 0
        (Get-APKIOrder -Id 'contoso-web').Status | Should -Be 'Approved'
        $existing.Status | Should -Be 'Proposed'
    }

    It 'marks the T11 hook: warns when no CA is configured' {
        $r = Install-APKI -Destination $script:Destination -NoTask
        $r.CAConfigured | Should -BeFalse
        Should -Invoke -ModuleName AutomaticPKI Write-APKILog -ParameterFilter { $Level -eq 'Warning' -and $Message -match 'No certification authority is configured' }
    }

    It 'refuses a destination that is not an AutomaticPKI folder' {
        { Install-APKI -Destination (Join-Path $TestDrive 'Other') -NoTask } | Should -Throw '*AutomaticPKI*'
    }

    It 'changes nothing under -WhatIf' {
        $r = Install-APKI -Destination $script:Destination -WhatIf
        Join-Path $script:Destination 'AutomaticPKI.psd1' | Should -Not -Exist
        Join-Path $env:APKI_ROOT 'config.json' | Should -Not -Exist
        @($r.ProposedOrders).Count | Should -Be 0
        Should -Invoke -ModuleName AutomaticPKI Invoke-APKIScheduledTask -Times 0 -Exactly -ParameterFilter { $Operation -eq 'Register' }
    }
}
