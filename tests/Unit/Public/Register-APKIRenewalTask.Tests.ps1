BeforeAll {
    Import-Module ([System.IO.Path]::Combine($PSScriptRoot, '..', '..', '..', 'src', 'AutomaticPKI', 'AutomaticPKI.psd1')) -Force
}

AfterAll {
    Remove-Module AutomaticPKI -Force -ErrorAction SilentlyContinue
}

Describe 'Register-APKIRenewalTask' {
    BeforeEach {
        $env:APKI_ROOT = $TestDrive
        Mock -ModuleName AutomaticPKI Write-APKILog { }
        Mock -ModuleName AutomaticPKI Invoke-APKIScheduledTask { } -ParameterFilter { $Operation -eq 'Get' }
        Mock -ModuleName AutomaticPKI Invoke-APKIScheduledTask { [pscustomobject]@{ TaskName = $TaskName } } -ParameterFilter { $Operation -eq 'Register' }
    }

    It 'registers a daily SYSTEM task with the documented settings' {
        $r = Register-APKIRenewalTask -At '03:00' -RandomDelayMinutes 60 -ModulePath 'C:\Program Files\WindowsPowerShell\Modules\AutomaticPKI\AutomaticPKI.psd1'

        Should -Invoke -ModuleName AutomaticPKI Invoke-APKIScheduledTask -Times 1 -Exactly -ParameterFilter {
            $Operation -eq 'Register' -and
            $TaskName -eq 'AutomaticPKI Renewal' -and
            $TaskPath -eq '\AutomaticPKI\' -and
            $Execute -match 'powershell\.exe$' -and
            $Argument -eq '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Import-Module ''C:\Program Files\WindowsPowerShell\Modules\AutomaticPKI\AutomaticPKI.psd1''; Invoke-APKIRenewal"' -and
            $At.Hour -eq 3 -and $At.Minute -eq 0 -and
            $RandomDelay.TotalMinutes -eq 60 -and
            $UserId -eq 'SYSTEM' -and
            $RunLevel -eq 'Highest' -and
            $ExecutionTimeLimit.TotalHours -eq 2 -and
            $MultipleInstances -eq 'IgnoreNew' -and
            $StartWhenAvailable
        }
        $r.TaskName | Should -Be 'AutomaticPKI Renewal'
    }

    It 'escapes single quotes in the module path' {
        $null = Register-APKIRenewalTask -ModulePath "C:\O'Brien\AutomaticPKI\AutomaticPKI.psd1"
        Should -Invoke -ModuleName AutomaticPKI Invoke-APKIScheduledTask -Times 1 -Exactly -ParameterFilter {
            $Operation -eq 'Register' -and $Argument -like "*Import-Module 'C:\O''Brien\AutomaticPKI\AutomaticPKI.psd1'; Invoke-APKIRenewal*"
        }
    }

    It 'defaults to the manifest of the loaded module' {
        $null = Register-APKIRenewalTask -At '22:30' -RandomDelayMinutes 0
        $expected = Join-Path (Get-Module AutomaticPKI).ModuleBase 'AutomaticPKI.psd1'
        Should -Invoke -ModuleName AutomaticPKI Invoke-APKIScheduledTask -Times 1 -Exactly -ParameterFilter {
            $Operation -eq 'Register' -and $Argument.Contains($expected) -and $At.Hour -eq 22 -and $At.Minute -eq 30 -and $RandomDelay -eq [timespan]::Zero
        }
    }

    It 'refuses to replace an existing task without -Force' {
        Mock -ModuleName AutomaticPKI Invoke-APKIScheduledTask { [pscustomobject]@{ TaskName = 'AutomaticPKI Renewal' } } -ParameterFilter { $Operation -eq 'Get' }
        { Register-APKIRenewalTask -ModulePath 'C:\m\AutomaticPKI.psd1' } | Should -Throw '*already exists*'
        Should -Invoke -ModuleName AutomaticPKI Invoke-APKIScheduledTask -Times 0 -Exactly -ParameterFilter { $Operation -eq 'Register' }

        $null = Register-APKIRenewalTask -ModulePath 'C:\m\AutomaticPKI.psd1' -Force
        Should -Invoke -ModuleName AutomaticPKI Invoke-APKIScheduledTask -Times 1 -Exactly -ParameterFilter { $Operation -eq 'Register' }
    }

    It 'rejects an invalid time' {
        { Register-APKIRenewalTask -At '25:00' -ModulePath 'C:\m\AutomaticPKI.psd1' } | Should -Throw
    }

    It 'registers nothing under -WhatIf' {
        $r = Register-APKIRenewalTask -ModulePath 'C:\m\AutomaticPKI.psd1' -WhatIf
        $r | Should -BeNullOrEmpty
        Should -Invoke -ModuleName AutomaticPKI Invoke-APKIScheduledTask -Times 0 -Exactly -ParameterFilter { $Operation -eq 'Register' }
    }
}
