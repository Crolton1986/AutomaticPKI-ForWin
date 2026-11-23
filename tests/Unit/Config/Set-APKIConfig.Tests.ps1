BeforeAll {
    $script:ModulePath = Join-Path $PSScriptRoot '../../../src/AutomaticPKI/AutomaticPKI.psd1'
    Import-Module $script:ModulePath -Force
    $script:SavedRoot = $env:APKI_ROOT
}

AfterAll {
    $env:APKI_ROOT = $script:SavedRoot
}

Describe 'Set-APKIConfig' {
    BeforeEach {
        $env:APKI_ROOT = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $env:APKI_ROOT -Force | Out-Null
        $script:ConfigPath = Join-Path $env:APKI_ROOT 'config.json'
        Mock Write-APKILog -ModuleName AutomaticPKI { }
    }

    It 'writes a partial hashtable merged with the defaults and reads it back' {
        InModuleScope AutomaticPKI {
            Set-APKIConfig -Config @{
                RenewalDaysBefore = 21
                Smtp              = @{ Enabled = $true; Server = 'smtp.corp.local'; To = @('ops@corp.local') }
            }
        }

        $script:ConfigPath | Should -Exist
        $onDisk = Get-Content -LiteralPath $script:ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $onDisk.RenewalDaysBefore | Should -Be 21
        $onDisk.LogRetentionDays | Should -Be 30
        $onDisk.Smtp.Port | Should -Be 25
        (@($onDisk.Smtp.To) -join ',') | Should -Be 'ops@corp.local'

        $config = InModuleScope AutomaticPKI { Get-APKIConfig }
        $config.RenewalDaysBefore | Should -Be 21
        $config.Smtp.Server | Should -Be 'smtp.corp.local'
    }

    It 'round-trips the object returned by Get-APKIConfig' {
        InModuleScope AutomaticPKI {
            $config = Get-APKIConfig
            $config.LogRetentionDays = 7
            $config | Set-APKIConfig
        }

        (InModuleScope AutomaticPKI { Get-APKIConfig }).LogRetentionDays | Should -Be 7
    }

    It 'leaves no temp files behind' {
        InModuleScope AutomaticPKI { Set-APKIConfig -Config @{ RenewalDaysBefore = 20 } }
        InModuleScope AutomaticPKI { Set-APKIConfig -Config @{ RenewalDaysBefore = 25 } }

        @(Get-ChildItem -LiteralPath $env:APKI_ROOT -Filter '*.tmp').Count | Should -Be 0
        (InModuleScope AutomaticPKI { Get-APKIConfig }).RenewalDaysBefore | Should -Be 25
    }

    It 'rejects invalid values, logs EventId 3004 and keeps the existing file' {
        InModuleScope AutomaticPKI { Set-APKIConfig -Config @{ RenewalDaysBefore = 20 } }
        $before = Get-Content -LiteralPath $script:ConfigPath -Raw -Encoding UTF8

        { InModuleScope AutomaticPKI { Set-APKIConfig -Config @{ DefaultProvider = 'Nope' } } } |
            Should -Throw '*DefaultProvider*'

        Get-Content -LiteralPath $script:ConfigPath -Raw -Encoding UTF8 | Should -Be $before
        Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter { $EventId -eq 3004 }
    }

    It 'writes nothing with -WhatIf' {
        InModuleScope AutomaticPKI { Set-APKIConfig -Config @{ RenewalDaysBefore = 20 } -WhatIf }

        $script:ConfigPath | Should -Not -Exist
    }
}
