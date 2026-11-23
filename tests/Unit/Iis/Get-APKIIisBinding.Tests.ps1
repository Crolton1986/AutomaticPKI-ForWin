BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../../src/AutomaticPKI/AutomaticPKI.psd1') -Force
    . (Join-Path $PSScriptRoot 'FakeIis.ps1')

    $script:ThumbA = 'A1' * 20
    $script:ThumbB = 'B2' * 20
    $script:ThumbC = 'C3' * 20
}

Describe 'Get-APKIIisBinding' {
    BeforeEach {
        $env:APKI_ROOT = $TestDrive
        Mock -ModuleName AutomaticPKI Write-APKILog { }
        Mock -ModuleName AutomaticPKI Get-APKICertificateDnsName { @() }
        Mock -ModuleName AutomaticPKI Get-APKICertificateDnsName { @('legacy.contoso.com') } -ParameterFilter { $Thumbprint -eq ('B2' * 20) }

        $script:Sm = Build-FakeIisServerManager -Site @(
            @{ Name = 'Contoso'; Bindings = @(
                    @{ Protocol = 'https'; BindingInformation = '*:443:www.contoso.com'; SslFlags = 1; Thumbprint = $script:ThumbA }
                    @{ Protocol = 'http'; BindingInformation = '*:80:www.contoso.com' }
                )
            }
            @{ Name = 'Legacy1'; Bindings = @(
                    @{ Protocol = 'https'; BindingInformation = '*:443:'; SslFlags = 0; Thumbprint = $script:ThumbB; StoreName = 'WebHosting' }
                )
            }
            @{ Name = 'Legacy2'; Bindings = @(
                    @{ Protocol = 'https'; BindingInformation = '*:443:legacy2.contoso.com'; SslFlags = 0 }
                )
            }
            @{ Name = 'IpOnly'; Bindings = @(
                    @{ Protocol = 'https'; BindingInformation = '10.0.0.5:8443:'; SslFlags = 0; Thumbprint = $script:ThumbC }
                    @{ Protocol = 'https'; BindingInformation = '[2001:db8::1]:443:'; SslFlags = 0 }
                )
            }
            @{ Name = 'Ftp'; Bindings = @(
                    @{ Protocol = 'ftp'; BindingInformation = '*:21:' }
                )
            }
        )
        $script:All = @(InModuleScope AutomaticPKI -Parameters @{ SM = $script:Sm } {
                param($SM)
                Get-APKIIisBinding -ServerManager $SM
            })
    }

    It 'returns only http and https bindings' {
        $script:All.Count | Should -Be 6
        @($script:All | Where-Object SiteName -EQ 'Ftp').Count | Should -Be 0
    }

    It 'returns every contract field' {
        $b = $script:All | Where-Object { $_.SiteName -eq 'Contoso' -and $_.Protocol -eq 'https' }
        foreach ($field in 'SiteName', 'Protocol', 'IPAddress', 'Port', 'HostHeader', 'SslFlags', 'Thumbprint', 'StoreName', 'NameStatus', 'SharedWith') {
            $b.PSObject.Properties.Name | Should -Contain $field
        }
    }

    It 'reads an SNI binding' {
        $b = $script:All | Where-Object { $_.SiteName -eq 'Contoso' -and $_.Protocol -eq 'https' }
        $b.IPAddress | Should -Be '*'
        $b.Port | Should -Be 443
        $b.HostHeader | Should -Be 'www.contoso.com'
        $b.SslFlags | Should -Be 1
        $b.Thumbprint | Should -Be $script:ThumbA
        $b.StoreName | Should -Be 'My'
        $b.NameStatus | Should -Be 'Usable'
        @($b.SharedWith).Count | Should -Be 0
    }

    It 'reads an http binding without certificate data' {
        $b = $script:All | Where-Object { $_.SiteName -eq 'Contoso' -and $_.Protocol -eq 'http' }
        $b.Port | Should -Be 80
        $b.SslFlags | Should -Be 0
        $b.Thumbprint | Should -Be ''
        $b.StoreName | Should -Be ''
    }

    It 'reports sites sharing a non-SNI IP:port in SharedWith' {
        $l1 = $script:All | Where-Object SiteName -EQ 'Legacy1'
        $l2 = $script:All | Where-Object SiteName -EQ 'Legacy2'
        @($l1.SharedWith) | Should -Be @('Legacy2')
        @($l2.SharedWith) | Should -Be @('Legacy1')
    }

    It 'shows the shared http.sys certificate on every site of the endpoint' {
        $l2 = $script:All | Where-Object SiteName -EQ 'Legacy2'
        $l2.Thumbprint | Should -Be $script:ThumbB
        $l2.StoreName | Should -Be 'WebHosting'
    }

    It 'uses the bound certificate SANs when the host header is blank' {
        ($script:All | Where-Object SiteName -EQ 'Legacy1').NameStatus | Should -Be 'Usable'
    }

    It 'marks an IP-only binding NeedsName when its certificate has no usable SAN' {
        $b = $script:All | Where-Object { $_.SiteName -eq 'IpOnly' -and $_.Port -eq 8443 }
        $b.IPAddress | Should -Be '10.0.0.5'
        $b.HostHeader | Should -Be ''
        $b.Thumbprint | Should -Be $script:ThumbC
        $b.NameStatus | Should -Be 'NeedsName'
        @($b.SharedWith).Count | Should -Be 0
    }

    It 'parses bracketed IPv6 addresses' {
        $b = $script:All | Where-Object { $_.SiteName -eq 'IpOnly' -and $_.Port -eq 443 }
        $b.IPAddress | Should -Be '2001:db8::1'
        $b.Thumbprint | Should -Be ''
        $b.NameStatus | Should -Be 'NeedsName'
    }

    It 'filters by -SiteName but still computes SharedWith across sites' {
        $only = @(InModuleScope AutomaticPKI -Parameters @{ SM = $script:Sm } {
                param($SM)
                Get-APKIIisBinding -ServerManager $SM -SiteName 'Legacy2'
            })
        $only.Count | Should -Be 1
        @($only[0].SharedWith) | Should -Be @('Legacy1')
    }
}

Describe 'Binding information helpers' {
    It 'splits <Info>' -TestCases @(
        @{ Info = '*:443:www.contoso.com'; Ip = '*'; Port = 443; HostHeader = 'www.contoso.com' }
        @{ Info = ':80:'; Ip = '*'; Port = 80; HostHeader = '' }
        @{ Info = '10.1.2.3:8443:'; Ip = '10.1.2.3'; Port = 8443; HostHeader = '' }
        @{ Info = '[fe80::1]:443:a.contoso.com'; Ip = 'fe80::1'; Port = 443; HostHeader = 'a.contoso.com' }
    ) {
        $r = InModuleScope AutomaticPKI -Parameters @{ Info = $Info } {
            param($Info)
            Split-APKIBindingInformation -BindingInformation $Info
        }
        $r.IPAddress | Should -Be $Ip
        $r.Port | Should -Be $Port
        $r.HostHeader | Should -Be $HostHeader
    }

    It 'joins IPv6 with brackets' {
        InModuleScope AutomaticPKI {
            Join-APKIBindingInformation -IPAddress 'fe80::1' -Port 443 -HostHeader '' | Should -Be '[fe80::1]:443:'
            Join-APKIBindingInformation -IPAddress '*' -Port 443 -HostHeader 'www.contoso.com' | Should -Be '*:443:www.contoso.com'
        }
    }

    It 'round-trips thumbprints and hashes' {
        InModuleScope AutomaticPKI {
            $hash = ConvertTo-APKICertificateHash -Thumbprint 'a1 b2 c3 d4'
            $hash.GetType().FullName | Should -Be 'System.Byte[]'
            $hash.Length | Should -Be 4
            ConvertTo-APKIThumbprint -Hash $hash | Should -Be 'A1B2C3D4'
            ConvertTo-APKIThumbprint -Hash $null | Should -Be ''
        }
    }
}
