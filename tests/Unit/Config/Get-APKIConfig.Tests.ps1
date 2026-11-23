BeforeAll {
    $script:ModulePath = Join-Path $PSScriptRoot '../../../src/AutomaticPKI/AutomaticPKI.psd1'
    Import-Module $script:ModulePath -Force
    $script:SavedRoot = $env:APKI_ROOT
}

AfterAll {
    $env:APKI_ROOT = $script:SavedRoot
}

Describe 'Get-APKIConfig' {
    BeforeEach {
        $env:APKI_ROOT = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $env:APKI_ROOT -Force | Out-Null
        $script:ConfigPath = Join-Path $env:APKI_ROOT 'config.json'
        Mock Write-APKILog -ModuleName AutomaticPKI { }
    }

    It 'returns the defaults when config.json does not exist' {
        $config = InModuleScope AutomaticPKI { Get-APKIConfig }

        $config.RenewalDaysBefore | Should -Be 30
        $config.OldCertRetentionDays | Should -Be 14
        $config.DefaultProvider | Should -Be 'AdcsRpc'
        $config.DefaultProviderSettings.Template | Should -Be 'WebServer'
        $config.Smtp.Enabled | Should -BeFalse
        $config.Smtp.Port | Should -Be 25
        $config.Smtp.UseSsl | Should -BeTrue
        @($config.Smtp.To).Count | Should -Be 0
        $config.Smtp.CredentialRef | Should -BeNullOrEmpty
        $config.LogRetentionDays | Should -Be 30
        $config.RevocationPolicy | Should -Be 'Strict'
    }

    It 'fills missing top-level and nested keys from the defaults and keeps existing values' {
        $json = @'
{
  "RenewalDaysBefore": 10,
  "DefaultProviderSettings": { "CAConfig": "ca01.corp.local\\Corp Issuing CA" },
  "Smtp": { "Enabled": true, "Server": "smtp.corp.local", "To": ["ops@corp.local"] },
  "CustomKey": "kept"
}
'@
        Set-Content -LiteralPath $script:ConfigPath -Value $json -Encoding UTF8

        $config = InModuleScope AutomaticPKI { Get-APKIConfig }

        $config.RenewalDaysBefore | Should -Be 10
        $config.OldCertRetentionDays | Should -Be 14
        $config.LogRetentionDays | Should -Be 30
        $config.DefaultProvider | Should -Be 'AdcsRpc'
        $config.DefaultProviderSettings.CAConfig | Should -Be 'ca01.corp.local\Corp Issuing CA'
        $config.DefaultProviderSettings.Template | Should -Be 'WebServer'
        $config.Smtp.Enabled | Should -BeTrue
        $config.Smtp.Server | Should -Be 'smtp.corp.local'
        $config.Smtp.Port | Should -Be 25
        $config.Smtp.UseSsl | Should -BeTrue
        (@($config.Smtp.To) -join ',') | Should -Be 'ops@corp.local'
        $config.PSObject.Properties['CredentialRef'] | Should -BeNullOrEmpty
        $config.Smtp.PSObject.Properties['CredentialRef'] | Should -Not -BeNullOrEmpty
        $config.CustomKey | Should -Be 'kept'
    }

    It 'replaces a null nested section with the defaults' {
        Set-Content -LiteralPath $script:ConfigPath -Value '{ "Smtp": null }' -Encoding UTF8

        $config = InModuleScope AutomaticPKI { Get-APKIConfig }

        $config.Smtp.Enabled | Should -BeFalse
        $config.Smtp.Port | Should -Be 25
    }

    It 'throws and logs EventId 3004 for <Case>' -TestCases @(
        @{ Case = 'malformed JSON'; Json = '{ "RenewalDaysBefore": 30, ' }
        @{ Case = 'an empty file'; Json = '' }
        @{ Case = 'a JSON array'; Json = '[1, 2, 3]' }
        @{ Case = 'a wrong value type'; Json = '{ "RenewalDaysBefore": "soon" }' }
        @{ Case = 'an unknown provider'; Json = '{ "DefaultProvider": "LetsEncrypt" }' }
        @{ Case = 'an out-of-range port'; Json = '{ "Smtp": { "Port": 70000 } }' }
        @{ Case = 'an unknown RevocationPolicy'; Json = '{ "RevocationPolicy": "Sometimes" }' }
        @{ Case = 'a non-object Smtp section'; Json = '{ "Smtp": "smtp.corp.local" }' }
    ) {
        Set-Content -LiteralPath $script:ConfigPath -Value $Json -Encoding UTF8

        { InModuleScope AutomaticPKI { Get-APKIConfig } } | Should -Throw '*config.json*is invalid*'

        Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter {
            $EventId -eq 3004 -and $Level -eq 'Error'
        }
    }
}
