BeforeAll {
    . (Join-Path $PSScriptRoot 'AdcsCep.TestHelpers.ps1')
    $env:APKI_ROOT = $TestDrive
    Import-AdcsCepTestModule

    function Get-TestSetting {
        param([AllowNull()] $Order)
        InModuleScope AutomaticPKI -Parameters @{ Order = $Order } {
            param($Order)
            Get-APKIAdcsCepSetting -Order $Order
        }
    }
}

AfterAll {
    Remove-Module AutomaticPKI -Force -ErrorAction SilentlyContinue
}

Describe 'Get-APKIAdcsCepSetting' {
    It 'reads a valid order' {
        $setting = Get-TestSetting -Order (Get-AdcsCepTestOrder -CredentialRef 'cep-svc')

        $setting.Problem | Should -BeNullOrEmpty
        $setting.OrderId | Should -Be 'contoso-web'
        $setting.CepUrl | Should -Be 'https://cep.corp.local/ADPolicyProvider_CEP_Kerberos/service.svc/CEP'
        $setting.Template | Should -Be 'WebServer'
        $setting.CredentialRef | Should -Be 'cep-svc'
        $setting.Hostnames | Should -Be @('www.contoso.com', 'contoso.com')
        $setting.Key.Algorithm | Should -Be 'RSA'
        $setting.Key.Length | Should -Be 2048
    }

    It 'treats a null or blank CredentialRef as Kerberos' {
        (Get-TestSetting -Order (Get-AdcsCepTestOrder)).CredentialRef | Should -BeNullOrEmpty
    }

    It 'reads an order parsed from JSON' {
        $json = (Get-AdcsCepTestOrder) | ConvertTo-Json -Depth 5
        $order = $json | ConvertFrom-Json

        $setting = Get-TestSetting -Order $order

        $setting.Problem | Should -BeNullOrEmpty
        $setting.Hostnames.Count | Should -Be 2
    }

    It 'tolerates missing optional properties (Key, CredentialRef)' {
        $order = [pscustomobject]@{
            Id               = 'x'
            Hostnames        = 'single.contoso.com'
            ProviderSettings = [pscustomobject]@{ CepUrl = 'https://cep.corp.local/CEP'; Template = 'WebServer' }
        }

        $setting = Get-TestSetting -Order $order

        $setting.Problem | Should -BeNullOrEmpty
        $setting.Key | Should -BeNullOrEmpty
        $setting.CredentialRef | Should -BeNullOrEmpty
        @($setting.Hostnames) | Should -Be @('single.contoso.com')
    }

    It 'reports a missing ProviderSettings' {
        $order = [pscustomobject]@{ Id = 'x'; Hostnames = @('a.contoso.com') }

        (Get-TestSetting -Order $order).Problem | Should -BeLike '*ProviderSettings is missing*'
    }

    It 'reports every problem at once' {
        $order = Get-AdcsCepTestOrder -CepUrl '' -Template '' -Hostnames @()

        $problem = (Get-TestSetting -Order $order).Problem

        $problem | Should -BeLike '*CepUrl*'
        $problem | Should -BeLike '*Template*'
        $problem | Should -BeLike '*Hostnames*'
    }
}
