BeforeAll {
    Import-Module ([System.IO.Path]::Combine($PSScriptRoot, '..', '..', '..', 'src', 'AutomaticPKI', 'AutomaticPKI.psd1')) -Force
}

AfterAll {
    Remove-Module AutomaticPKI -Force -ErrorAction SilentlyContinue
}

Describe 'ConvertTo-APKIOrderId' {
    It 'slugs <SiteName> to <Expected>' -TestCases @(
        @{ SiteName = 'Default Web Site'; Expected = 'default-web-site' }
        @{ SiteName = 'Contoso Web'; Expected = 'contoso-web' }
        @{ SiteName = '  --Shop__2024!! '; Expected = 'shop-2024' }
        @{ SiteName = 'a.b.c'; Expected = 'a-b-c' }
        @{ SiteName = '!!!'; Expected = 'site' }
        @{ SiteName = ''; Expected = 'site' }
        @{ SiteName = 'CON'; Expected = 'con-site' }
        @{ SiteName = 'com1'; Expected = 'com1-site' }
    ) {
        $id = InModuleScope AutomaticPKI -Parameters @{ S = $SiteName } {
            param($S)
            ConvertTo-APKIOrderId -SiteName $S
        }
        $id | Should -BeExactly $Expected
    }

    It 'caps the length and still passes Assert-APKISafeName' {
        $id = InModuleScope AutomaticPKI {
            $long = ('Very Long Site Name ' * 20)
            $result = ConvertTo-APKIOrderId -SiteName $long
            Assert-APKISafeName -Name $result -Kind 'order Id'
            $result
        }
        $id.Length | Should -BeLessOrEqual 120
        $id | Should -Not -Match '-$'
    }

    It 'is used by Find-APKISiteCandidate' {
        InModuleScope AutomaticPKI {
            Mock Write-APKILog { }
            Mock ConvertTo-APKIOrderId { 'from-slug' }
            Mock Get-APKIIisBinding {
                [pscustomobject]@{
                    SiteName = 'X Site'; Protocol = 'https'; IPAddress = '*'; Port = 443; HostHeader = 'x.contoso.com'
                    SslFlags = 1; Thumbprint = ''; StoreName = 'My'; NameStatus = 'Usable'; SharedWith = [string[]]@()
                    BindingInformation = '*:443:x.contoso.com'
                }
            }
            Mock Get-APKIBindingNameStatus { [pscustomobject]@{ Names = @('x.contoso.com'); NameStatus = 'Usable' } }
            $c = @(Find-APKISiteCandidate -ServerManager ([pscustomobject]@{ Sites = @() }))
            $c[0].Id | Should -Be 'from-slug'
            Should -Invoke ConvertTo-APKIOrderId -Times 1 -Exactly -ParameterFilter { $SiteName -eq 'X Site' }
        }
    }
}
