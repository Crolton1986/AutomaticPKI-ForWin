BeforeAll {
    Import-Module ([System.IO.Path]::Combine($PSScriptRoot, '..', '..', '..', 'src', 'AutomaticPKI', 'AutomaticPKI.psd1')) -Force

    function Save-CleanupOrder {
        param([string]$Id, [string]$Current, [string]$Previous, [int]$RenewedDaysAgo = 30)
        $order = [pscustomobject]@{
            Id                 = $Id
            Status             = 'Active'
            SiteName           = "Site $Id"
            Hostnames          = @("$Id.contoso.com")
            Provider           = 'AdcsRpc'
            CurrentThumbprint  = $Current
            PreviousThumbprint = $Previous
            LastRenewal        = [datetime]::UtcNow.AddDays(-$RenewedDaysAgo).ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
        }
        InModuleScope AutomaticPKI -Parameters @{ O = $order } {
            param($O)
            Save-APKIOrderData -Order $O
        }
    }

    function Get-CleanupOrder {
        param([string]$Id)
        InModuleScope AutomaticPKI -Parameters @{ I = $Id } {
            param($I)
            Get-APKIOrderData -Id $I
        }
    }

    function Invoke-Cleanup {
        param([int]$RetentionDays = 14)
        @(InModuleScope AutomaticPKI -Parameters @{ R = $RetentionDays } {
                param($R)
                Remove-APKIOldCertificate -RetentionDays $R -Confirm:$false
            })
    }
}

AfterAll {
    Remove-Module AutomaticPKI -Force -ErrorAction SilentlyContinue
}

Describe 'Remove-APKIOldCertificate' {
    BeforeEach {
        $env:APKI_ROOT = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        Mock -ModuleName AutomaticPKI Write-APKILog { }
        Mock -ModuleName AutomaticPKI Get-APKIHealthCertificate { [pscustomobject]@{ Thumbprint = $Thumbprint } }
        Mock -ModuleName AutomaticPKI Remove-APKIMachineCertificate { }
        # 'B1..' is still bound in IIS (e.g. a site outside the order shares it).
        Mock -ModuleName AutomaticPKI Get-APKIBoundThumbprint { @(('A1' * 20), ('A2' * 20), ('B1' * 20)) }

        Save-CleanupOrder -Id 'one' -Current ('A1' * 20) -Previous ('B1' * 20)
        Save-CleanupOrder -Id 'two' -Current ('A2' * 20) -Previous ('B2' * 20)
    }

    It 'removes an unbound previous certificate past retention and never one that is still bound' {
        $r = Invoke-Cleanup
        Should -Invoke -ModuleName AutomaticPKI Remove-APKIMachineCertificate -Times 1 -Exactly
        Should -Invoke -ModuleName AutomaticPKI Remove-APKIMachineCertificate -Times 1 -Exactly -ParameterFilter { $Thumbprint -eq ('B2' * 20) }
        Should -Invoke -ModuleName AutomaticPKI Remove-APKIMachineCertificate -Times 0 -Exactly -ParameterFilter { $Thumbprint -eq ('B1' * 20) }
        Should -Invoke -ModuleName AutomaticPKI Write-APKILog -Times 1 -Exactly -ParameterFilter { $EventId -eq 1004 -and $OrderId -eq 'two' }

        @($r).Count | Should -Be 1
        $r[0].Removed | Should -BeTrue
        (Get-CleanupOrder -Id 'two').PreviousThumbprint | Should -BeNullOrEmpty
        (Get-CleanupOrder -Id 'one').PreviousThumbprint | Should -Be ('B1' * 20)
    }

    It 'keeps a previous certificate that is another order''s current certificate' {
        Mock -ModuleName AutomaticPKI Get-APKIBoundThumbprint { @() }
        Save-CleanupOrder -Id 'three' -Current ('B2' * 20) -Previous ('C3' * 20)
        $null = Invoke-Cleanup
        Should -Invoke -ModuleName AutomaticPKI Remove-APKIMachineCertificate -Times 0 -Exactly -ParameterFilter { $Thumbprint -eq ('B2' * 20) }
    }

    It 'keeps certificates inside the retention period' {
        $null = Invoke-Cleanup -RetentionDays 60
        Should -Invoke -ModuleName AutomaticPKI Remove-APKIMachineCertificate -Times 0 -Exactly
        (Get-CleanupOrder -Id 'two').PreviousThumbprint | Should -Be ('B2' * 20)
    }

    It 'removes nothing when IIS bindings cannot be read' {
        Mock -ModuleName AutomaticPKI Get-APKIBoundThumbprint { throw 'IIS is not available' }
        $null = Invoke-Cleanup -RetentionDays 0
        Should -Invoke -ModuleName AutomaticPKI Remove-APKIMachineCertificate -Times 0 -Exactly
        Should -Invoke -ModuleName AutomaticPKI Write-APKILog -Times 1 -Exactly -ParameterFilter { $Level -eq 'Warning' -and $Message -match 'IIS bindings could not be read' }
    }

    It 'clears PreviousThumbprint without deleting when the certificate is already gone' {
        Mock -ModuleName AutomaticPKI Get-APKIHealthCertificate { $null }
        $r = Invoke-Cleanup
        Should -Invoke -ModuleName AutomaticPKI Remove-APKIMachineCertificate -Times 0 -Exactly
        $r[0].Removed | Should -BeFalse
        (Get-CleanupOrder -Id 'two').PreviousThumbprint | Should -BeNullOrEmpty
    }

    It 'removes nothing under -WhatIf' {
        $null = InModuleScope AutomaticPKI { Remove-APKIOldCertificate -RetentionDays 0 -WhatIf }
        Should -Invoke -ModuleName AutomaticPKI Remove-APKIMachineCertificate -Times 0 -Exactly
        (Get-CleanupOrder -Id 'two').PreviousThumbprint | Should -Be ('B2' * 20)
    }
}

Describe 'Get-APKIBoundThumbprint' {
    It 'returns unique https thumbprints from all IIS bindings' {
        Mock -ModuleName AutomaticPKI Get-APKIIisBinding {
            [pscustomobject]@{ SiteName = 'a'; Protocol = 'https'; Thumbprint = ('a1' * 20) }
            [pscustomobject]@{ SiteName = 'b'; Protocol = 'https'; Thumbprint = ('A1' * 20) }
            [pscustomobject]@{ SiteName = 'b'; Protocol = 'http'; Thumbprint = '' }
            [pscustomobject]@{ SiteName = 'c'; Protocol = 'https'; Thumbprint = ('C3' * 20) }
        }
        $r = @(InModuleScope AutomaticPKI { Get-APKIBoundThumbprint })
        $r | Should -Be @(('A1' * 20), ('C3' * 20))
    }
}
