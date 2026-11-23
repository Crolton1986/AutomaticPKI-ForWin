BeforeAll {
    Import-Module ([System.IO.Path]::Combine($PSScriptRoot, '..', '..', '..', 'src', 'AutomaticPKI', 'AutomaticPKI.psd1')) -Force

    function New-TestCandidate {
        param(
            [string]$Provider = 'AdcsRpc',
            [string]$CAConfig,
            [string]$CepUrl,
            [string]$CAHost,
            [string]$Source = 'AD',
            [bool]$Reachable = $true
        )
        $c = [pscustomobject]@{
            Provider           = $Provider
            CAConfig           = $null
            CepUrl             = $null
            CAHost             = $CAHost
            CAName             = $null
            PublishedTemplates = [string[]]@()
            Source             = $Source
            Reachable          = $Reachable
        }
        if ($CAConfig) {
            $c.CAConfig = $CAConfig
            $c.CAName = ($CAConfig -split '\\', 2)[1]
            $c.PublishedTemplates = [string[]]@('WebServer')
        }
        if ($CepUrl) { $c.CepUrl = $CepUrl }
        $c
    }

    function Get-TestConfig {
        InModuleScope AutomaticPKI { Get-APKIConfig }
    }

    $script:Rpc1 = New-TestCandidate -CAConfig 'ca01.contoso.com\Contoso Issuing CA' -CAHost 'ca01.contoso.com'
    $script:Rpc2 = New-TestCandidate -CAConfig 'ca02.contoso.com\Contoso Issuing CA 2' -CAHost 'ca02.contoso.com'
    $script:RpcDown = New-TestCandidate -CAConfig 'ca09.contoso.com\Old CA' -CAHost 'ca09.contoso.com' -Reachable $false
    $script:Cep = New-TestCandidate -Provider 'AdcsCep' -CepUrl 'https://cep.contoso.com/ADPolicyProvider_CEP_Kerberos/service.svc/CEP' -CAHost 'cep.contoso.com' -Source 'GPO'
}

AfterAll {
    Remove-Variable -Name APKITestCaCandidates -Scope Global -ErrorAction SilentlyContinue
    Remove-Module AutomaticPKI -Force -ErrorAction SilentlyContinue
}

Describe 'Find-APKICA' {
    BeforeEach {
        $env:APKI_ROOT = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $global:APKITestCaCandidates = @()
        Mock -ModuleName AutomaticPKI Write-APKILog { }
        Mock -ModuleName AutomaticPKI Find-APKICertificationAuthority { foreach ($c in $global:APKITestCaCandidates) { $c } }
    }

    It 'returns the candidates and changes nothing without -Accept' {
        $global:APKITestCaCandidates = @($script:Rpc1, $script:RpcDown)

        $r = @(Find-APKICA -Template 'WebServer')

        $r.Count | Should -Be 2
        $r[0].CAConfig | Should -Be 'ca01.contoso.com\Contoso Issuing CA'
        Should -Invoke -ModuleName AutomaticPKI Find-APKICertificationAuthority -Times 1 -Exactly -ParameterFilter { $Template -eq 'WebServer' }
        Join-Path $env:APKI_ROOT 'config.json' | Should -Not -Exist
    }

    It '-Accept saves the single reachable AdcsRpc candidate and keeps the configured Template' {
        InModuleScope AutomaticPKI {
            $c = Get-APKIConfig
            $c.DefaultProviderSettings.Template = 'ContosoWeb'
            Set-APKIConfig -Config $c
        }
        $global:APKITestCaCandidates = @($script:Rpc1, $script:RpcDown)

        $r = @(Find-APKICA -Accept -ErrorVariable apkiErr)

        @($apkiErr).Count | Should -Be 0
        $r.Count | Should -Be 2
        $config = Get-TestConfig
        $config.DefaultProvider | Should -Be 'AdcsRpc'
        $config.DefaultProviderSettings.CAConfig | Should -Be 'ca01.contoso.com\Contoso Issuing CA'
        $config.DefaultProviderSettings.Template | Should -Be 'ContosoWeb'
    }

    It '-Accept saves a single reachable CEP candidate as AdcsCep' {
        $global:APKITestCaCandidates = @($script:Cep)

        $null = Find-APKICA -Accept

        $config = Get-TestConfig
        $config.DefaultProvider | Should -Be 'AdcsCep'
        $config.DefaultProviderSettings.CepUrl | Should -Be 'https://cep.contoso.com/ADPolicyProvider_CEP_Kerberos/service.svc/CEP'
        $config.DefaultProviderSettings.Template | Should -Be 'WebServer'
        $config.DefaultProviderSettings.CredentialRef | Should -BeNullOrEmpty
    }

    It '-Accept refuses to choose between several reachable candidates' {
        $global:APKITestCaCandidates = @($script:Rpc1, $script:Rpc2)

        $r = @(Find-APKICA -Accept -ErrorAction SilentlyContinue -ErrorVariable apkiErr)

        $r.Count | Should -Be 2
        @($apkiErr).Count | Should -Be 1
        [string]$apkiErr[0] | Should -Match 'none is selected automatically'
        [string]$apkiErr[0] | Should -Match 'Set-APKIConfig'
        Join-Path $env:APKI_ROOT 'config.json' | Should -Not -Exist
    }

    It '-Accept with several candidates throws under -ErrorAction Stop' {
        $global:APKITestCaCandidates = @($script:Rpc1, $script:Rpc2)

        { Find-APKICA -Accept -ErrorAction Stop } | Should -Throw '*choose one*'
    }

    It '-Accept changes nothing when a CA is already configured' {
        InModuleScope AutomaticPKI {
            $c = Get-APKIConfig
            $c.DefaultProviderSettings.CAConfig = 'existing.contoso.com\Existing CA'
            Set-APKIConfig -Config $c
        }
        $global:APKITestCaCandidates = @($script:Rpc1)

        $null = Find-APKICA -Accept -ErrorAction SilentlyContinue -ErrorVariable apkiErr

        @($apkiErr).Count | Should -Be 1
        [string]$apkiErr[0] | Should -Match 'already configured'
        (Get-TestConfig).DefaultProviderSettings.CAConfig | Should -Be 'existing.contoso.com\Existing CA'
    }

    It '-Accept reports an error when no candidate is reachable' {
        $global:APKITestCaCandidates = @($script:RpcDown)

        $null = Find-APKICA -Accept -ErrorAction SilentlyContinue -ErrorVariable apkiErr

        @($apkiErr).Count | Should -Be 1
        Join-Path $env:APKI_ROOT 'config.json' | Should -Not -Exist
    }

    It '-Accept -WhatIf writes nothing' {
        $global:APKITestCaCandidates = @($script:Rpc1)

        $null = Find-APKICA -Accept -WhatIf

        Join-Path $env:APKI_ROOT 'config.json' | Should -Not -Exist
    }
}
