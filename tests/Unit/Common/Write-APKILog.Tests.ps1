BeforeAll {
    $script:ModulePath = Join-Path $PSScriptRoot '../../../src/AutomaticPKI/AutomaticPKI.psd1'
    Import-Module $script:ModulePath -Force
    $script:SavedRoot = $env:APKI_ROOT
}

AfterAll {
    $env:APKI_ROOT = $script:SavedRoot
}

Describe 'Write-APKILog' {
    BeforeEach {
        $env:APKI_ROOT = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $env:APKI_ROOT -Force | Out-Null
        $script:LogFile = Join-Path $env:APKI_ROOT ('logs/apki-{0}.log' -f (Get-Date).ToString('yyyyMMdd'))
        Mock Write-APKIEventLogEntry -ModuleName AutomaticPKI { }
    }

    It 'appends a line to logs/apki-<yyyyMMdd>.log' {
        InModuleScope AutomaticPKI {
            Write-APKILog -Message 'first entry' -OrderId 'contoso-web'
            Write-APKILog -Message 'second entry' -Level Warning -EventId 2001 -WarningAction SilentlyContinue
        }

        $script:LogFile | Should -Exist
        $lines = @(Get-Content -LiteralPath $script:LogFile -Encoding UTF8)
        $lines.Count | Should -Be 2
        $lines[0] | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}[+-]\d{2}:\d{2} \[Info\] \[0\] \[contoso-web\] first entry$'
        $lines[1] | Should -Match '\[Warning\] \[2001\] second entry$'
    }

    It 'keeps one line per entry for multi-line messages' {
        InModuleScope AutomaticPKI {
            Write-APKILog -Message "line one`r`nline two`nline three"
        }

        $lines = @(Get-Content -LiteralPath $script:LogFile -Encoding UTF8)
        $lines.Count | Should -Be 1
        $lines[0] | Should -Match 'line one \| line two \| line three$'
    }

    It 'writes to the Event Log when EventId is greater than 0' {
        InModuleScope AutomaticPKI {
            Write-APKILog -Message 'config broken' -Level Error -EventId 3004 -OrderId 'site1' -WarningAction SilentlyContinue
        }

        Should -Invoke Write-APKIEventLogEntry -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter {
            $EventId -eq 3004 -and $Level -eq 'Error' -and $Message -eq 'config broken' -and $OrderId -eq 'site1'
        }
    }

    It 'does not write to the Event Log when EventId is 0' {
        InModuleScope AutomaticPKI {
            Write-APKILog -Message 'just a file entry'
        }

        Should -Invoke Write-APKIEventLogEntry -ModuleName AutomaticPKI -Times 0 -Exactly
    }

    It 'does not throw when the Event Log write fails' {
        Mock Write-APKIEventLogEntry -ModuleName AutomaticPKI { throw 'event log unavailable' }

        { InModuleScope AutomaticPKI { Write-APKILog -Message 'still fine' -EventId 1000 } } | Should -Not -Throw
        $script:LogFile | Should -Exist
    }

    It 'does not throw when the log file cannot be written' {
        Mock Add-Content -ModuleName AutomaticPKI { throw 'disk full' }
        Mock Start-Sleep -ModuleName AutomaticPKI { }

        { InModuleScope AutomaticPKI { Write-APKILog -Message 'lost' -WarningAction SilentlyContinue } } | Should -Not -Throw
        Should -Invoke Add-Content -ModuleName AutomaticPKI -Times 3 -Exactly
    }

    It 'still writes when the caller runs with -WhatIf' {
        InModuleScope AutomaticPKI {
            Set-Variable -Name WhatIfPreference -Value $true
            Write-APKILog -Message 'logged under WhatIf'
        }

        $script:LogFile | Should -Exist
        Get-Content -LiteralPath $script:LogFile -Raw -Encoding UTF8 | Should -Match 'logged under WhatIf'
    }
}

Describe 'Write-APKIEventLogEntry' {
    It 'never throws, including on hosts without an Event Log' {
        { InModuleScope AutomaticPKI { Write-APKIEventLogEntry -Message 'AutomaticPKI unit test' -Level Info -EventId 1000 } } |
            Should -Not -Throw
    }
}
