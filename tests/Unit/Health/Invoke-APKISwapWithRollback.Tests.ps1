BeforeAll {
    . (Join-Path $PSScriptRoot 'HealthTestHelpers.ps1')
    Import-APKITestModule
}

AfterAll {
    Remove-Module AutomaticPKI -Force -ErrorAction SilentlyContinue
}

Describe 'Invoke-APKISwapWithRollback' {
    BeforeAll {
        $env:APKI_ROOT = $TestDrive
        $script:OldThumb = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
        $script:NewThumb = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'
    }

    BeforeEach {
        Mock -ModuleName AutomaticPKI Write-APKILog {}
        Mock -ModuleName AutomaticPKI Send-APKINotification {}
        Mock -ModuleName AutomaticPKI Get-APKIHealthCertificate { [pscustomobject]@{ Thumbprint = $Thumbprint } }
        Mock -ModuleName AutomaticPKI Test-APKICertificatePrecheck {
            [pscustomobject]@{ Check = 'PrivateKey'; Target = 'x'; Passed = $true; Detail = '' }
        }
        Mock -ModuleName AutomaticPKI Save-APKIBindingSnapshot { 'snapshot-1' }
        Mock -ModuleName AutomaticPKI Set-APKIIisCertificateBinding {}
        Mock -ModuleName AutomaticPKI Restore-APKIBindingSnapshot {}
        Mock -ModuleName AutomaticPKI Invoke-APKIHealthCheck {
            [pscustomobject]@{ Passed = $true; Thumbprint = $Thumbprint; Results = @() }
        }
        $script:Order = Get-APKITestOrder -CurrentThumbprint $script:OldThumb
    }

    It 'swaps when precheck and health check pass' {
        $r = InModuleScope AutomaticPKI -Parameters @{ Order = $script:Order; T = $script:NewThumb } {
            param($Order, $T)
            Invoke-APKISwapWithRollback -Order $Order -NewThumbprint $T
        }
        $r.Success | Should -BeTrue
        $r.Outcome | Should -Be 'Swapped'
        $r.ActiveThumbprint | Should -Be $script:NewThumb
        Should -Invoke -ModuleName AutomaticPKI Save-APKIBindingSnapshot -Times 1 -Exactly
        Should -Invoke -ModuleName AutomaticPKI Set-APKIIisCertificateBinding -Times 1 -Exactly -ParameterFilter { $Thumbprint -eq 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB' }
        Should -Invoke -ModuleName AutomaticPKI Restore-APKIBindingSnapshot -Times 0 -Exactly
        Should -Invoke -ModuleName AutomaticPKI Write-APKILog -Times 1 -Exactly -ParameterFilter { $EventId -eq 1001 }
        Should -Invoke -ModuleName AutomaticPKI Send-APKINotification -Times 0 -Exactly
    }

    It 'rolls back and logs 3002 when the health check fails' {
        Mock -ModuleName AutomaticPKI Invoke-APKIHealthCheck {
            $ok = ($Thumbprint -eq 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
            [pscustomobject]@{
                Passed     = $ok
                Thumbprint = $Thumbprint
                Results    = @([pscustomobject]@{ Check = 'HttpProbe'; Target = 'https://www.contoso.com:443/'; Passed = $ok; Detail = 'HTTP 503' })
            }
        }
        $r = InModuleScope AutomaticPKI -Parameters @{ Order = $script:Order; T = $script:NewThumb } {
            param($Order, $T)
            Invoke-APKISwapWithRollback -Order $Order -NewThumbprint $T
        }
        $r.Success | Should -BeFalse
        $r.Outcome | Should -Be 'RolledBack'
        $r.ActiveThumbprint | Should -Be $script:OldThumb
        $r.Error | Should -Match 'HTTP 503'
        Should -Invoke -ModuleName AutomaticPKI Restore-APKIBindingSnapshot -Times 1 -Exactly -ParameterFilter { $Snapshot -eq 'snapshot-1' }
        Should -Invoke -ModuleName AutomaticPKI Invoke-APKIHealthCheck -Times 1 -Exactly -ParameterFilter { $Thumbprint -eq 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' }
        Should -Invoke -ModuleName AutomaticPKI Write-APKILog -Times 1 -Exactly -ParameterFilter { $EventId -eq 3002 -and $Level -eq 'Error' }
        Should -Invoke -ModuleName AutomaticPKI Send-APKINotification -Times 1 -Exactly
    }

    It 'rolls back when the binding update throws' {
        Mock -ModuleName AutomaticPKI Set-APKIIisCertificateBinding { throw 'SSL binding add failed: 0x800700b7' }
        $r = InModuleScope AutomaticPKI -Parameters @{ Order = $script:Order; T = $script:NewThumb } {
            param($Order, $T)
            Invoke-APKISwapWithRollback -Order $Order -NewThumbprint $T
        }
        $r.Outcome | Should -Be 'RolledBack'
        Should -Invoke -ModuleName AutomaticPKI Restore-APKIBindingSnapshot -Times 1 -Exactly
        Should -Invoke -ModuleName AutomaticPKI Write-APKILog -Times 1 -Exactly -ParameterFilter { $EventId -eq 3002 }
    }

    It 'logs 3003 when the restore itself fails' {
        Mock -ModuleName AutomaticPKI Invoke-APKIHealthCheck {
            [pscustomobject]@{ Passed = $false; Thumbprint = $Thumbprint; Results = @([pscustomobject]@{ Check = 'TlsHandshake'; Target = 'www.contoso.com:443'; Passed = $false; Detail = 'timed out' }) }
        }
        Mock -ModuleName AutomaticPKI Restore-APKIBindingSnapshot { throw 'netsh failed' }
        $r = InModuleScope AutomaticPKI -Parameters @{ Order = $script:Order; T = $script:NewThumb } {
            param($Order, $T)
            Invoke-APKISwapWithRollback -Order $Order -NewThumbprint $T
        }
        $r.Success | Should -BeFalse
        $r.Outcome | Should -Be 'RollbackFailed'
        $r.Error | Should -Match 'netsh failed'
        Should -Invoke -ModuleName AutomaticPKI Write-APKILog -Times 1 -Exactly -ParameterFilter { $EventId -eq 3003 -and $Level -eq 'Error' }
        Should -Invoke -ModuleName AutomaticPKI Write-APKILog -Times 0 -Exactly -ParameterFilter { $EventId -eq 3002 }
        Should -Invoke -ModuleName AutomaticPKI Send-APKINotification -Times 1 -Exactly
    }

    It 'logs 3003 when the old certificate fails its health check after restore' {
        Mock -ModuleName AutomaticPKI Invoke-APKIHealthCheck {
            [pscustomobject]@{ Passed = $false; Thumbprint = $Thumbprint; Results = @([pscustomobject]@{ Check = 'SiteState'; Target = 'Contoso'; Passed = $false; Detail = 'start failed' }) }
        }
        $r = InModuleScope AutomaticPKI -Parameters @{ Order = $script:Order; T = $script:NewThumb } {
            param($Order, $T)
            Invoke-APKISwapWithRollback -Order $Order -NewThumbprint $T
        }
        $r.Outcome | Should -Be 'RollbackFailed'
        Should -Invoke -ModuleName AutomaticPKI Invoke-APKIHealthCheck -Times 2 -Exactly
        Should -Invoke -ModuleName AutomaticPKI Write-APKILog -Times 1 -Exactly -ParameterFilter { $EventId -eq 3003 }
    }

    It 'does not touch IIS when the precheck fails' {
        Mock -ModuleName AutomaticPKI Test-APKICertificatePrecheck {
            [pscustomobject]@{ Check = 'SanCoverage'; Target = 'x'; Passed = $false; Detail = 'SAN does not cover: www.contoso.com.' }
        }
        $r = InModuleScope AutomaticPKI -Parameters @{ Order = $script:Order; T = $script:NewThumb } {
            param($Order, $T)
            Invoke-APKISwapWithRollback -Order $Order -NewThumbprint $T
        }
        $r.Outcome | Should -Be 'PrecheckFailed'
        $r.ActiveThumbprint | Should -Be $script:OldThumb
        Should -Invoke -ModuleName AutomaticPKI Save-APKIBindingSnapshot -Times 0 -Exactly
        Should -Invoke -ModuleName AutomaticPKI Set-APKIIisCertificateBinding -Times 0 -Exactly
        Should -Invoke -ModuleName AutomaticPKI Write-APKILog -Times 1 -Exactly -ParameterFilter { $EventId -eq 3005 }
        Should -Invoke -ModuleName AutomaticPKI Send-APKINotification -Times 1 -Exactly
    }

    It 'fails the precheck when the certificate is not in the store' {
        Mock -ModuleName AutomaticPKI Get-APKIHealthCertificate { $null }
        $r = InModuleScope AutomaticPKI -Parameters @{ Order = $script:Order; T = $script:NewThumb } {
            param($Order, $T)
            Invoke-APKISwapWithRollback -Order $Order -NewThumbprint $T
        }
        $r.Outcome | Should -Be 'PrecheckFailed'
        Should -Invoke -ModuleName AutomaticPKI Test-APKICertificatePrecheck -Times 0 -Exactly
    }

    It 'does not swap when the snapshot fails' {
        Mock -ModuleName AutomaticPKI Save-APKIBindingSnapshot { throw 'disk full' }
        $r = InModuleScope AutomaticPKI -Parameters @{ Order = $script:Order; T = $script:NewThumb } {
            param($Order, $T)
            Invoke-APKISwapWithRollback -Order $Order -NewThumbprint $T
        }
        $r.Outcome | Should -Be 'SnapshotFailed'
        Should -Invoke -ModuleName AutomaticPKI Set-APKIIisCertificateBinding -Times 0 -Exactly
    }

    It 'still reports the rollback when the notification fails' {
        Mock -ModuleName AutomaticPKI Set-APKIIisCertificateBinding { throw 'bind failed' }
        Mock -ModuleName AutomaticPKI Send-APKINotification { throw 'SMTP down' }
        $r = InModuleScope AutomaticPKI -Parameters @{ Order = $script:Order; T = $script:NewThumb } {
            param($Order, $T)
            Invoke-APKISwapWithRollback -Order $Order -NewThumbprint $T
        }
        $r.Outcome | Should -Be 'RolledBack'
        Should -Invoke -ModuleName AutomaticPKI Write-APKILog -Times 1 -Exactly -ParameterFilter { $Level -eq 'Warning' -and $Message -match 'SMTP down' }
    }

    It 'changes nothing with -WhatIf' {
        $r = InModuleScope AutomaticPKI -Parameters @{ Order = $script:Order; T = $script:NewThumb } {
            param($Order, $T)
            Invoke-APKISwapWithRollback -Order $Order -NewThumbprint $T -WhatIf
        }
        $r.Outcome | Should -Be 'Skipped'
        Should -Invoke -ModuleName AutomaticPKI Save-APKIBindingSnapshot -Times 0 -Exactly
        Should -Invoke -ModuleName AutomaticPKI Set-APKIIisCertificateBinding -Times 0 -Exactly
    }
}
