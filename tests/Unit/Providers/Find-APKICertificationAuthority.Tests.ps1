BeforeAll {
    $env:APKI_ROOT = $TestDrive
    Import-Module ([System.IO.Path]::Combine($PSScriptRoot, '..', '..', '..', 'src', 'AutomaticPKI', 'AutomaticPKI.psd1')) -Force

    function Invoke-Discovery {
        param([string]$Template)
        InModuleScope AutomaticPKI -Parameters @{ Template = $Template } {
            param($Template)
            Find-APKICertificationAuthority -Template $Template
        }
    }

    function New-FakeEnrollmentService {
        param([string]$DnsHostName, [string]$Name, [string[]]$Templates)
        [pscustomobject]@{ DnsHostName = $DnsHostName; Name = $Name; Templates = [string[]]$Templates }
    }

    $script:Ca1 = New-FakeEnrollmentService -DnsHostName 'ca01.contoso.com' -Name 'Contoso Issuing CA' -Templates @('WebServer', 'User', 'Machine')
    $script:Ca2 = New-FakeEnrollmentService -DnsHostName 'ca02.contoso.com' -Name 'Contoso Issuing CA 2' -Templates @('WebServer')
    $script:CaUserOnly = New-FakeEnrollmentService -DnsHostName 'ca03.contoso.com' -Name 'Contoso User CA' -Templates @('User')
    $script:CepUrl = 'https://cep.contoso.com/ADPolicyProvider_CEP_Kerberos/service.svc/CEP'
}

AfterAll {
    Remove-Variable -Name APKITestAdServices, APKITestPolicies, APKITestUnreachable -Scope Global -ErrorAction SilentlyContinue
    Remove-Module AutomaticPKI -Force -ErrorAction SilentlyContinue
}

Describe 'Find-APKICertificationAuthority' {
    BeforeEach {
        # Globals keep the mock bodies independent of the scope Pester runs them in.
        $global:APKITestAdServices = @()
        $global:APKITestPolicies = @()
        $global:APKITestUnreachable = @()

        Mock -ModuleName AutomaticPKI Write-APKILog { }
        Mock -ModuleName AutomaticPKI Test-APKIDomainJoined { $true }
        Mock -ModuleName AutomaticPKI Get-APKIAdEnrollmentService { foreach ($s in $global:APKITestAdServices) { $s } }
        Mock -ModuleName AutomaticPKI Get-APKICertutilAdca { throw 'certutil fallback must not run' }
        Mock -ModuleName AutomaticPKI Get-APKIGpoEnrollmentPolicyServer { foreach ($p in $global:APKITestPolicies) { $p } }
        Mock -ModuleName AutomaticPKI Test-APKIAdcsRpcProvider { $global:APKITestUnreachable -notcontains $Order.ProviderSettings.CAConfig }
        Mock -ModuleName AutomaticPKI Test-APKIAdcsCepProvider { $global:APKITestUnreachable -notcontains $Order.ProviderSettings.CepUrl }
    }

    It 'returns one reachable AD CA as an AdcsRpc candidate and logs 1005' {
        $global:APKITestAdServices = @($script:Ca1)

        $r = @(Invoke-Discovery -Template 'WebServer')

        $r.Count | Should -Be 1
        $r[0].Provider | Should -Be 'AdcsRpc'
        $r[0].CAConfig | Should -Be 'ca01.contoso.com\Contoso Issuing CA'
        $r[0].CepUrl | Should -BeNullOrEmpty
        $r[0].CAHost | Should -Be 'ca01.contoso.com'
        $r[0].CAName | Should -Be 'Contoso Issuing CA'
        @($r[0].PublishedTemplates) | Should -Be @('WebServer', 'User', 'Machine')
        $r[0].Source | Should -Be 'AD'
        $r[0].Reachable | Should -BeTrue

        Should -Invoke -ModuleName AutomaticPKI Test-APKIAdcsRpcProvider -Times 1 -Exactly -ParameterFilter {
            $Order.ProviderSettings.CAConfig -eq 'ca01.contoso.com\Contoso Issuing CA' -and $Order.ProviderSettings.Template -eq 'WebServer'
        }
        Should -Invoke -ModuleName AutomaticPKI Write-APKILog -Times 1 -Exactly -ParameterFilter { $EventId -eq 1005 -and $Message -match 'ca01\.contoso\.com' }
        Should -Invoke -ModuleName AutomaticPKI Write-APKILog -Times 0 -Exactly -ParameterFilter { $EventId -in @(2003, 2004) }
        Should -Invoke -ModuleName AutomaticPKI Get-APKICertutilAdca -Times 0 -Exactly
    }

    It 'returns every match and logs 2003 when more than one CA is reachable' {
        $global:APKITestAdServices = @($script:Ca1, $script:Ca2)

        $r = @(Invoke-Discovery -Template 'WebServer')

        $r.Count | Should -Be 2
        @($r | ForEach-Object { $_.CAConfig }) | Should -Be @('ca01.contoso.com\Contoso Issuing CA', 'ca02.contoso.com\Contoso Issuing CA 2')
        @($r | Where-Object { $_.Reachable }).Count | Should -Be 2
        Should -Invoke -ModuleName AutomaticPKI Write-APKILog -Times 2 -Exactly -ParameterFilter { $EventId -eq 1005 }
        Should -Invoke -ModuleName AutomaticPKI Write-APKILog -Times 1 -Exactly -ParameterFilter { $EventId -eq 2003 -and $Level -eq 'Warning' -and $Message -match 'Set-APKIConfig' }
    }

    It 'drops CAs that do not publish the template and logs 2004 when none is left' {
        $global:APKITestAdServices = @($script:CaUserOnly)

        $r = @(Invoke-Discovery -Template 'WebServer')

        $r.Count | Should -Be 0
        Should -Invoke -ModuleName AutomaticPKI Test-APKIAdcsRpcProvider -Times 0 -Exactly
        Should -Invoke -ModuleName AutomaticPKI Write-APKILog -Times 1 -Exactly -ParameterFilter { $EventId -eq 2004 -and $Message -match 'WebServer' }
    }

    It 'matches the template case-insensitively and lists every CA without -Template' {
        $global:APKITestAdServices = @($script:Ca1, $script:CaUserOnly)

        @(Invoke-Discovery -Template 'webserver').Count | Should -Be 1
        @(Invoke-Discovery).Count | Should -Be 2
    }

    It 'returns an unreachable CA with Reachable $false and logs 2004' {
        $global:APKITestAdServices = @($script:Ca1)
        $global:APKITestUnreachable = @('ca01.contoso.com\Contoso Issuing CA')

        $r = @(Invoke-Discovery -Template 'WebServer')

        $r.Count | Should -Be 1
        $r[0].Reachable | Should -BeFalse
        Should -Invoke -ModuleName AutomaticPKI Write-APKILog -Times 0 -Exactly -ParameterFilter { $EventId -eq 1005 }
        Should -Invoke -ModuleName AutomaticPKI Write-APKILog -Times 1 -Exactly -ParameterFilter { $EventId -eq 2004 -and $Message -match 'did not answer' }
    }

    It 'treats a throwing reachability test as unreachable' {
        $global:APKITestAdServices = @($script:Ca1)
        Mock -ModuleName AutomaticPKI Test-APKIAdcsRpcProvider { throw 'boom' }

        $r = @(Invoke-Discovery -Template 'WebServer')

        $r[0].Reachable | Should -BeFalse
    }

    It 'does not query AD when not domain-joined and logs 2004 with the manual CepUrl hint' {
        Mock -ModuleName AutomaticPKI Test-APKIDomainJoined { $false }
        $global:APKITestAdServices = @($script:Ca1)

        $r = @(Invoke-Discovery -Template 'WebServer')

        $r.Count | Should -Be 0
        Should -Invoke -ModuleName AutomaticPKI Get-APKIAdEnrollmentService -Times 0 -Exactly
        Should -Invoke -ModuleName AutomaticPKI Get-APKIGpoEnrollmentPolicyServer -Times 1 -Exactly
        Should -Invoke -ModuleName AutomaticPKI Write-APKILog -Times 1 -Exactly -ParameterFilter {
            $EventId -eq 2004 -and $Message -match 'set ProviderSettings\.CepUrl manually or via the orchestrator'
        }
    }

    It 'treats a failing domain-membership check as not domain-joined' {
        Mock -ModuleName AutomaticPKI Test-APKIDomainJoined { throw 'CIM unavailable' }

        $r = @(Invoke-Discovery)

        $r.Count | Should -Be 0
        Should -Invoke -ModuleName AutomaticPKI Get-APKIAdEnrollmentService -Times 0 -Exactly
    }

    It 'returns https CEP servers from Group Policy as AdcsCep candidates, unfiltered by template' {
        Mock -ModuleName AutomaticPKI Test-APKIDomainJoined { $false }
        $global:APKITestPolicies = @(
            [pscustomobject]@{ Url = 'ldap:'; Id = 'ad-policy'; AuthType = 'Kerberos' }
            [pscustomobject]@{ Url = [uri]$script:CepUrl; Id = '{2B5A1F3C-0000-4000-8000-000000000001}'; AuthType = 'Kerberos' }
            [pscustomobject]@{ Url = [uri]$script:CepUrl; Id = 'duplicate'; AuthType = 'Kerberos' }
        )

        $r = @(Invoke-Discovery -Template 'WebServer')

        $r.Count | Should -Be 1
        $r[0].Provider | Should -Be 'AdcsCep'
        $r[0].CepUrl | Should -Be $script:CepUrl
        $r[0].CAConfig | Should -BeNullOrEmpty
        $r[0].CAHost | Should -Be 'cep.contoso.com'
        @($r[0].PublishedTemplates).Count | Should -Be 0
        $r[0].Source | Should -Be 'GPO'
        $r[0].Reachable | Should -BeTrue
        Should -Invoke -ModuleName AutomaticPKI Test-APKIAdcsCepProvider -Times 1 -Exactly -ParameterFilter {
            $Order.ProviderSettings.CepUrl -eq 'https://cep.contoso.com/ADPolicyProvider_CEP_Kerberos/service.svc/CEP' -and $Order.ProviderSettings.Template -eq 'WebServer' -and @($Order.Hostnames).Count -gt 0
        }
        Should -Invoke -ModuleName AutomaticPKI Write-APKILog -Times 1 -Exactly -ParameterFilter { $EventId -eq 1005 -and $Message -match 'AdcsCep' }
    }

    It 'combines AD and GPO candidates on a domain member' {
        $global:APKITestAdServices = @($script:Ca1)
        $global:APKITestPolicies = @([pscustomobject]@{ Url = [uri]$script:CepUrl; Id = 'cep' })

        $r = @(Invoke-Discovery -Template 'WebServer')

        @($r | ForEach-Object { $_.Provider }) | Should -Be @('AdcsRpc', 'AdcsCep')
        Should -Invoke -ModuleName AutomaticPKI Write-APKILog -Times 1 -Exactly -ParameterFilter { $EventId -eq 2003 }
    }

    It 'falls back to certutil -ADCA when the LDAP search throws' {
        Mock -ModuleName AutomaticPKI Get-APKIAdEnrollmentService { throw 'The server is not operational.' }
        Mock -ModuleName AutomaticPKI Get-APKICertutilAdca {
            [pscustomobject]@{ DnsHostName = 'ca01.contoso.com'; Name = 'Contoso Issuing CA'; Templates = [string[]]@('WebServer') }
        }

        $r = @(Invoke-Discovery -Template 'WebServer')

        $r.Count | Should -Be 1
        $r[0].CAConfig | Should -Be 'ca01.contoso.com\Contoso Issuing CA'
        $r[0].Source | Should -Be 'AD'
        Should -Invoke -ModuleName AutomaticPKI Get-APKICertutilAdca -Times 1 -Exactly
        Should -Invoke -ModuleName AutomaticPKI Write-APKILog -ParameterFilter { $Level -eq 'Warning' -and $Message -match 'certutil -ADCA' }
    }

    It 'returns nothing and logs 2004 when both LDAP and certutil fail' {
        Mock -ModuleName AutomaticPKI Get-APKIAdEnrollmentService { throw 'ldap down' }
        Mock -ModuleName AutomaticPKI Get-APKICertutilAdca { throw 'certutil down' }

        $r = @(Invoke-Discovery -Template 'WebServer')

        $r.Count | Should -Be 0
        Should -Invoke -ModuleName AutomaticPKI Write-APKILog -Times 1 -Exactly -ParameterFilter { $EventId -eq 2004 }
    }
}

Describe 'Get-APKICertutilAdca' {
    BeforeEach {
        Mock -ModuleName AutomaticPKI Write-APKILog { }
    }

    It 'parses cn, dNSHostName and certificateTemplates for each CA' {
        Mock -ModuleName AutomaticPKI Invoke-APKICertutil {
            [pscustomobject]@{ ExitCode = 0; Output = [string[]]@(
                    '  CN=Contoso Issuing CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                    '    cn = Contoso Issuing CA'
                    '    displayName = Contoso Issuing CA'
                    '    dNSHostName = ca01.contoso.com'
                    '    certificateTemplates ='
                    '      0: WebServer'
                    '      1: "Machine"'
                    '    flags = 10'
                    ''
                    '  CN=Contoso CA 2,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                    '    cn = Contoso CA 2'
                    '    dNSHostName = ca02.contoso.com'
                    '    certificateTemplates = User'
                    '      SubCA'
                    'CertUtil: -ADCA command completed successfully.'
                ) }
        }

        $r = @(InModuleScope AutomaticPKI { Get-APKICertutilAdca })

        Should -Invoke -ModuleName AutomaticPKI Invoke-APKICertutil -Times 1 -Exactly -ParameterFilter { ($Arguments -join '|') -eq '-ADCA' }
        $r.Count | Should -Be 2
        $r[0].Name | Should -Be 'Contoso Issuing CA'
        $r[0].DnsHostName | Should -Be 'ca01.contoso.com'
        @($r[0].Templates) | Should -Be @('WebServer', 'Machine')
        $r[1].Name | Should -Be 'Contoso CA 2'
        $r[1].DnsHostName | Should -Be 'ca02.contoso.com'
        @($r[1].Templates) | Should -Be @('User', 'SubCA')
    }

    It 'throws when certutil fails' {
        Mock -ModuleName AutomaticPKI Invoke-APKICertutil {
            [pscustomobject]@{ ExitCode = -2147016646; Output = [string[]]@('CertUtil: -ADCA command FAILED: 0x8007203a (WIN32: 8250 ERROR_DS_SERVER_DOWN)') }
        }

        { InModuleScope AutomaticPKI { Get-APKICertutilAdca } } | Should -Throw '*ERROR_DS_SERVER_DOWN*'
    }
}
