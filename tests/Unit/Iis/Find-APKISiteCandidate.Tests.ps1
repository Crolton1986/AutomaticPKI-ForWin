BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../../src/AutomaticPKI/AutomaticPKI.psd1') -Force
    . (Join-Path $PSScriptRoot 'FakeIis.ps1')

    $script:ThumbA = 'A1' * 20
    $script:ThumbB = 'B2' * 20
    $script:ThumbC = 'C3' * 20

    function Invoke-Discovery {
        param([object]$ServerManager, [hashtable]$Override = @{}, [switch]$CheckDns)
        @(InModuleScope AutomaticPKI -Parameters @{ SM = $ServerManager; O = $Override; Dns = [bool]$CheckDns } {
                param($SM, $O, $Dns)
                Find-APKISiteCandidate -ServerManager $SM -HostnameOverride $O -CheckDns:$Dns
            })
    }
}

Describe 'Find-APKISiteCandidate' {
    BeforeEach {
        $env:APKI_ROOT = $TestDrive
        Mock -ModuleName AutomaticPKI Write-APKILog { }
        Mock -ModuleName AutomaticPKI Get-APKICertificateDnsName { @() }
        Mock -ModuleName AutomaticPKI Get-APKICertificateDnsName { @('legacy.contoso.com', 'localhost') } -ParameterFilter { $Thumbprint -eq ('B2' * 20) }
    }

    Context 'SNI site' {
        BeforeEach {
            $sm = Build-FakeIisServerManager -Site @(
                @{ Name = 'Contoso Web'; Bindings = @(
                        @{ Protocol = 'http'; BindingInformation = '*:80:www.contoso.com' }
                        @{ Protocol = 'https'; BindingInformation = '*:443:www.contoso.com'; SslFlags = 1; Thumbprint = $script:ThumbA }
                    )
                }
            )
            $script:Result = Invoke-Discovery -ServerManager $sm
        }

        It 'proposes one order skeleton' {
            @($script:Result).Count | Should -Be 1
            $c = $script:Result[0]
            $c.Id | Should -Be 'contoso-web'
            $c.Status | Should -Be 'Proposed'
            $c.SiteName | Should -Be 'Contoso Web'
            $c.NameStatus | Should -Be 'Usable'
            @($c.Hostnames) | Should -Be @('www.contoso.com')
            $c.CreateBinding | Should -BeFalse
        }

        It 'manages only the https binding' {
            $c = $script:Result[0]
            @($c.Bindings).Count | Should -Be 1
            $c.Bindings[0].Protocol | Should -Be 'https'
            $c.Bindings[0].HostHeader | Should -Be 'www.contoso.com'
            $c.Bindings[0].SslFlags | Should -Be 1
            $c.Bindings[0].NameStatus | Should -Be 'Usable'
        }
    }

    Context 'http-only site with a host header' {
        It 'proposes an SNI binding to create' {
            $sm = Build-FakeIisServerManager -Site @(
                @{ Name = 'Shop'; Bindings = @(@{ Protocol = 'http'; BindingInformation = '*:80:shop.contoso.com' }) }
            )
            $c = (Invoke-Discovery -ServerManager $sm)[0]
            $c.CreateBinding | Should -BeTrue
            @($c.Hostnames) | Should -Be @('shop.contoso.com')
            @($c.Bindings).Count | Should -Be 1
            $c.Bindings[0].IPAddress | Should -Be '*'
            $c.Bindings[0].Port | Should -Be 443
            $c.Bindings[0].HostHeader | Should -Be 'shop.contoso.com'
            $c.Bindings[0].SslFlags | Should -Be 1
            $c.Bindings[0].StoreName | Should -Be 'My'
        }
    }

    Context 'non-SNI sites sharing one IP:port' {
        BeforeEach {
            $sm = Build-FakeIisServerManager -Site @(
                @{ Name = 'Legacy1'; Bindings = @(@{ Protocol = 'https'; BindingInformation = '*:443:'; SslFlags = 0; Thumbprint = $script:ThumbB }) }
                @{ Name = 'Other'; Bindings = @(@{ Protocol = 'https'; BindingInformation = '*:443:other.contoso.com'; SslFlags = 1; Thumbprint = $script:ThumbA }) }
                @{ Name = 'Legacy2'; Bindings = @(
                        @{ Protocol = 'https'; BindingInformation = '*:443:legacy2.contoso.com'; SslFlags = 0 }
                        @{ Protocol = 'http'; BindingInformation = '*:80:legacy2.contoso.com' }
                    )
                }
            )
            $script:Result = Invoke-Discovery -ServerManager $sm
        }

        It 'groups them into one candidate' {
            $script:Result.Count | Should -Be 2
            $g = $script:Result | Where-Object SiteName -EQ 'Legacy1'
            $g | Should -Not -BeNullOrEmpty
            @($script:Result | Where-Object SiteName -EQ 'Legacy2').Count | Should -Be 0
        }

        It 'covers the names and bindings of every site in the group' {
            $g = $script:Result | Where-Object SiteName -EQ 'Legacy1'
            @($g.Hostnames) | Should -Contain 'legacy.contoso.com'
            @($g.Hostnames) | Should -Contain 'legacy2.contoso.com'
            @($g.Hostnames) | Should -Not -Contain 'localhost'
            @($g.Bindings | ForEach-Object SiteName) | Should -Be @('Legacy1', 'Legacy2')
            $g.CreateBinding | Should -BeFalse
        }

        It 'keeps SNI sites on the same port separate' {
            $o = $script:Result | Where-Object SiteName -EQ 'Other'
            @($o.Hostnames) | Should -Be @('other.contoso.com')
        }
    }

    Context 'blank host header and IP-only bindings' {
        It 'flags a blank-host site with no certificate as NeedsName (EventId 2001)' {
            $sm = Build-FakeIisServerManager -Site @(
                @{ Name = 'Default Web Site'; Bindings = @(@{ Protocol = 'http'; BindingInformation = '*:80:' }) }
            )
            $c = (Invoke-Discovery -ServerManager $sm)[0]
            $c.NameStatus | Should -Be 'NeedsName'
            @($c.Hostnames).Count | Should -Be 0
            @($c.Bindings).Count | Should -Be 0
            Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter { $EventId -eq 2001 }
        }

        It 'flags an IP-only https binding whose certificate has no usable SAN' {
            $sm = Build-FakeIisServerManager -Site @(
                @{ Name = 'IpOnly'; Bindings = @(@{ Protocol = 'https'; BindingInformation = '10.0.0.5:443:'; SslFlags = 0; Thumbprint = $script:ThumbC }) }
            )
            $c = (Invoke-Discovery -ServerManager $sm)[0]
            $c.NameStatus | Should -Be 'NeedsName'
            $c.Bindings[0].IPAddress | Should -Be '10.0.0.5'
            $c.Bindings[0].NameStatus | Should -Be 'NeedsName'
        }

        It 'uses an override name for an IP-only binding' {
            $sm = Build-FakeIisServerManager -Site @(
                @{ Name = 'IpOnly'; Bindings = @(@{ Protocol = 'https'; BindingInformation = '10.0.0.5:443:'; SslFlags = 0; Thumbprint = $script:ThumbC }) }
            )
            $c = (Invoke-Discovery -ServerManager $sm -Override @{ IpOnly = @('ip.contoso.com') })[0]
            $c.NameStatus | Should -Be 'Usable'
            @($c.Hostnames) | Should -Be @('ip.contoso.com')
            $c.Bindings[0].NameStatus | Should -Be 'Usable'
            $c.CreateBinding | Should -BeFalse
        }

        It 'proposes SNI bindings from override names for a blank-host http site' {
            $sm = Build-FakeIisServerManager -Site @(
                @{ Name = 'Default Web Site'; Bindings = @(@{ Protocol = 'http'; BindingInformation = '*:80:' }) }
            )
            $c = (Invoke-Discovery -ServerManager $sm -Override @{ 'Default Web Site' = @('intranet', 'portal.contoso.com') })[0]
            $c.NameStatus | Should -Be 'Usable'
            @($c.Hostnames) | Should -Be @('portal.contoso.com')
            $c.CreateBinding | Should -BeTrue
            $c.Bindings[0].HostHeader | Should -Be 'portal.contoso.com'
            Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 0 -Exactly -ParameterFilter { $EventId -eq 2001 }
        }

        It 'gives unique ids' {
            $sm = Build-FakeIisServerManager -Site @(
                @{ Name = 'My Site'; Bindings = @(@{ Protocol = 'http'; BindingInformation = '*:80:a.contoso.com' }) }
                @{ Name = 'my-site'; Bindings = @(@{ Protocol = 'http'; BindingInformation = '*:80:b.contoso.com' }) }
            )
            $r = Invoke-Discovery -ServerManager $sm
            @($r | ForEach-Object Id) | Should -Be @('my-site', 'my-site-2')
        }
    }

    Context 'DNS check' {
        BeforeEach {
            $script:DnsSm = Build-FakeIisServerManager -Site @(
                @{ Name = 'Shop'; Bindings = @(@{ Protocol = 'http'; BindingInformation = '*:80:shop.contoso.com' }) }
            )
            Mock -ModuleName AutomaticPKI Get-APKILocalIPAddress { @('10.0.0.1', '127.0.0.1') }
        }

        It 'warns with EventId 2002 when a name resolves elsewhere' {
            Mock -ModuleName AutomaticPKI Resolve-APKIDnsName { @('192.0.2.10') }
            $null = Invoke-Discovery -ServerManager $script:DnsSm -CheckDns
            Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter { $EventId -eq 2002 }
        }

        It 'warns when a name does not resolve at all' {
            Mock -ModuleName AutomaticPKI Resolve-APKIDnsName { @() }
            $null = Invoke-Discovery -ServerManager $script:DnsSm -CheckDns
            Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter { $EventId -eq 2002 }
        }

        It 'stays quiet when a name resolves to this host' {
            Mock -ModuleName AutomaticPKI Resolve-APKIDnsName { @('10.0.0.1') }
            $null = Invoke-Discovery -ServerManager $script:DnsSm -CheckDns
            Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 0 -Exactly -ParameterFilter { $EventId -eq 2002 }
        }

        It 'does not resolve names without -CheckDns' {
            Mock -ModuleName AutomaticPKI Resolve-APKIDnsName { @() }
            $null = Invoke-Discovery -ServerManager $script:DnsSm
            Should -Invoke Resolve-APKIDnsName -ModuleName AutomaticPKI -Times 0 -Exactly
        }
    }
}
