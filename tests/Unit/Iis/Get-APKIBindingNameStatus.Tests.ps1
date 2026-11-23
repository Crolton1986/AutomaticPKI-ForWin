BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../../src/AutomaticPKI/AutomaticPKI.psd1') -Force
}

Describe 'Test-APKIUsableHostname' {
    It 'accepts <Name>' -TestCases @(
        @{ Name = 'www.contoso.com' }
        @{ Name = 'WWW.Contoso.COM.' }
        @{ Name = 'xn--bcher-kva.example' }
        @{ Name = 'intranet.corp.local' }
        @{ Name = '2019.contoso.com' }
    ) {
        InModuleScope AutomaticPKI -Parameters @{ Name = $Name } {
            param($Name)
            Test-APKIUsableHostname -Name $Name | Should -BeTrue
        }
    }

    It 'rejects <Name>' -TestCases @(
        @{ Name = '' }
        @{ Name = 'localhost' }
        @{ Name = 'app.localhost' }
        @{ Name = 'intranet' }
        @{ Name = '10.0.0.5' }
        @{ Name = '2001:db8::1' }
        @{ Name = '[::1]' }
        @{ Name = '10.1' }
        @{ Name = '*' }
        @{ Name = '*.contoso.com' }
        @{ Name = 'bad_name.contoso.com' }
        @{ Name = '-x.contoso.com' }
    ) {
        InModuleScope AutomaticPKI -Parameters @{ Name = $Name } {
            param($Name)
            Test-APKIUsableHostname -Name $Name | Should -BeFalse
        }
    }
}

Describe 'Get-APKIBindingNameStatus' {
    BeforeEach {
        Mock -ModuleName AutomaticPKI Write-APKILog { }
        Mock -ModuleName AutomaticPKI Get-APKICertificateDnsName { @() }
        Mock -ModuleName AutomaticPKI Get-APKICertificateDnsName { @('www.fabrikam.com', 'localhost', '*.fabrikam.com', 'fabrikam') } -ParameterFilter { $Thumbprint -eq 'SANCERT' }
        Mock -ModuleName AutomaticPKI Get-APKICertificateDnsName { @('*.fabrikam.com') } -ParameterFilter { $Thumbprint -eq 'WILDONLY' }
    }

    It 'uses the host header first' {
        InModuleScope AutomaticPKI {
            $r = Get-APKIBindingNameStatus -Binding ([pscustomobject]@{ HostHeader = 'Shop.Contoso.com'; Thumbprint = 'SANCERT'; StoreName = 'My' }) -OverrideName 'x.contoso.com'
            $r.NameStatus | Should -Be 'Usable'
            $r.Source | Should -Be 'HostHeader'
            @($r.Names) | Should -Be @('shop.contoso.com')
        }
        Should -Invoke Get-APKICertificateDnsName -ModuleName AutomaticPKI -Times 0 -Exactly
    }

    It 'falls back to usable SANs of the bound certificate when the host header is blank' {
        InModuleScope AutomaticPKI {
            $r = Get-APKIBindingNameStatus -Binding ([pscustomobject]@{ HostHeader = ''; Thumbprint = 'SANCERT'; StoreName = 'WebHosting' })
            $r.NameStatus | Should -Be 'Usable'
            $r.Source | Should -Be 'CertificateSan'
            @($r.Names) | Should -Be @('www.fabrikam.com')
        }
        Should -Invoke Get-APKICertificateDnsName -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter { $StoreName -eq 'WebHosting' }
    }

    It 'falls back to SANs when the host header is not a usable name' {
        InModuleScope AutomaticPKI {
            $r = Get-APKIBindingNameStatus -Binding ([pscustomobject]@{ HostHeader = 'intranet'; Thumbprint = 'SANCERT'; StoreName = 'My' })
            $r.Source | Should -Be 'CertificateSan'
        }
    }

    It 'needs a name when the host header is blank and the certificate only has a wildcard' {
        InModuleScope AutomaticPKI {
            $r = Get-APKIBindingNameStatus -Binding ([pscustomobject]@{ HostHeader = ''; Thumbprint = 'WILDONLY'; StoreName = 'My' })
            $r.NameStatus | Should -Be 'NeedsName'
            $r.Source | Should -Be 'None'
            @($r.Names).Count | Should -Be 0
        }
    }

    It 'needs a name for a blank http binding without certificate' {
        InModuleScope AutomaticPKI {
            $r = Get-APKIBindingNameStatus -Binding ([pscustomobject]@{ HostHeader = ''; Thumbprint = ''; StoreName = '' })
            $r.NameStatus | Should -Be 'NeedsName'
        }
    }

    It 'uses order override names last, dropping unusable ones' {
        InModuleScope AutomaticPKI {
            $r = Get-APKIBindingNameStatus -Binding ([pscustomobject]@{ HostHeader = '' }) -OverrideName 'localhost', 'portal.contoso.com', '10.0.0.1'
            $r.NameStatus | Should -Be 'Usable'
            $r.Source | Should -Be 'Override'
            @($r.Names) | Should -Be @('portal.contoso.com')
        }
    }
}
