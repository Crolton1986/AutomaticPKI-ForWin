BeforeAll {
    Import-Module ([System.IO.Path]::Combine($PSScriptRoot, '..', '..', '..', 'src', 'AutomaticPKI', 'AutomaticPKI.psd1')) -Force

    function Save-ProposedOrder {
        param([string]$Id = 'web', [string[]]$Hostnames = @('web.contoso.com'), [string]$Provider = 'AdcsRpc')
        $order = [pscustomobject]@{
            Id               = $Id
            Status           = 'Proposed'
            SiteName         = 'Web'
            Hostnames        = $Hostnames
            Provider         = $Provider
            ProviderSettings = $null
        }
        InModuleScope AutomaticPKI -Parameters @{ O = $order } {
            param($O)
            Save-APKIOrderData -Order $O
        }
    }
}

AfterAll {
    Remove-Module AutomaticPKI -Force -ErrorAction SilentlyContinue
}

Describe 'Approve-APKIOrder' {
    BeforeEach {
        $env:APKI_ROOT = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        Mock -ModuleName AutomaticPKI Write-APKILog { }
        InModuleScope AutomaticPKI {
            $c = Get-APKIDefaultConfig
            $c.DefaultProviderSettings.CAConfig = 'ca01\Contoso CA'
            Set-APKIConfig -Config $c
        }
    }

    It 'approves and fills ProviderSettings from the configured defaults' {
        Save-ProposedOrder
        $r = Approve-APKIOrder -Id 'web'
        $r.Status | Should -Be 'Approved'
        $saved = Get-APKIOrder -Id 'web'
        $saved.Status | Should -Be 'Approved'
        $saved.Provider | Should -Be 'AdcsRpc'
        $saved.ProviderSettings.CAConfig | Should -Be 'ca01\Contoso CA'
        $saved.ProviderSettings.Template | Should -Be 'WebServer'
    }

    It 'replaces hostnames (normalized, de-duplicated) with -Hostname' {
        Save-ProposedOrder -Hostnames @()
        $null = Approve-APKIOrder -Id 'web' -Hostname 'Intranet.Contoso.com.', 'intranet.contoso.com', 'intranet'
        @((Get-APKIOrder -Id 'web').Hostnames) | Should -Be @('intranet.contoso.com', 'intranet')
    }

    It 'refuses an order without hostnames' {
        Save-ProposedOrder -Hostnames @()
        { Approve-APKIOrder -Id 'web' } | Should -Throw '*no hostnames*'
        (Get-APKIOrder -Id 'web').Status | Should -Be 'Proposed'
    }

    It 'takes -Provider and -ProviderSettings as given' {
        Save-ProposedOrder
        $null = Approve-APKIOrder -Id 'web' -Provider AdcsCep -ProviderSettings @{ CepUrl = 'https://cep.contoso.com/CEP'; Template = 'Web'; CredentialRef = $null }
        $saved = Get-APKIOrder -Id 'web'
        $saved.Provider | Should -Be 'AdcsCep'
        $saved.ProviderSettings.CepUrl | Should -Be 'https://cep.contoso.com/CEP'
    }

    It 'refuses to apply default settings of a different provider' {
        Save-ProposedOrder -Provider 'AdcsCep'
        { Approve-APKIOrder -Id 'web' } | Should -Throw '*ProviderSettings*'
    }

    It 'throws for an unknown order' {
        { Approve-APKIOrder -Id 'nope' } | Should -Throw '*does not exist*'
    }

    It 'saves nothing under -WhatIf' {
        Save-ProposedOrder
        $null = Approve-APKIOrder -Id 'web' -WhatIf
        (Get-APKIOrder -Id 'web').Status | Should -Be 'Proposed'
    }
}
