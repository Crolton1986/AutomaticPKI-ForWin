BeforeAll {
    $script:ModulePath = Join-Path $PSScriptRoot '../../../src/AutomaticPKI/AutomaticPKI.psd1'
    Import-Module $script:ModulePath -Force
    $script:SavedRoot = $env:APKI_ROOT
}

AfterAll {
    $env:APKI_ROOT = $script:SavedRoot
}

Describe 'Remove-APKIOldLog' {
    BeforeEach {
        $env:APKI_ROOT = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $script:LogDir = Join-Path $env:APKI_ROOT 'logs'
        New-Item -ItemType Directory -Path $script:LogDir -Force | Out-Null

        $today = (Get-Date).Date
        $script:Files = @{
            Old     = Join-Path $script:LogDir ('apki-{0}.log' -f $today.AddDays(-40).ToString('yyyyMMdd'))
            Edge    = Join-Path $script:LogDir ('apki-{0}.log' -f $today.AddDays(-30).ToString('yyyyMMdd'))
            Recent  = Join-Path $script:LogDir ('apki-{0}.log' -f $today.AddDays(-10).ToString('yyyyMMdd'))
            Today   = Join-Path $script:LogDir ('apki-{0}.log' -f $today.ToString('yyyyMMdd'))
            Foreign = Join-Path $script:LogDir 'apki-notadate.log'
        }
        foreach ($file in $script:Files.Values) {
            Set-Content -LiteralPath $file -Value 'x' -Encoding UTF8
        }
    }

    It 'removes only files older than -RetentionDays' {
        InModuleScope AutomaticPKI { Remove-APKIOldLog -RetentionDays 30 }

        $script:Files.Old | Should -Not -Exist
        $script:Files.Edge | Should -Exist
        $script:Files.Recent | Should -Exist
        $script:Files.Today | Should -Exist
        $script:Files.Foreign | Should -Exist
    }

    It 'uses LogRetentionDays from config.json when -RetentionDays is not given' {
        Set-Content -LiteralPath (Join-Path $env:APKI_ROOT 'config.json') -Value '{ "LogRetentionDays": 5 }' -Encoding UTF8

        InModuleScope AutomaticPKI { Remove-APKIOldLog }

        $script:Files.Old | Should -Not -Exist
        $script:Files.Edge | Should -Not -Exist
        $script:Files.Recent | Should -Not -Exist
        $script:Files.Today | Should -Exist
    }

    It 'defaults to 30 days when there is no config.json' {
        InModuleScope AutomaticPKI { Remove-APKIOldLog }

        $script:Files.Old | Should -Not -Exist
        $script:Files.Edge | Should -Exist
    }

    It 'deletes nothing with -WhatIf' {
        InModuleScope AutomaticPKI { Remove-APKIOldLog -RetentionDays 0 -WhatIf }

        $script:Files.Old | Should -Exist
        $script:Files.Recent | Should -Exist
    }
}
