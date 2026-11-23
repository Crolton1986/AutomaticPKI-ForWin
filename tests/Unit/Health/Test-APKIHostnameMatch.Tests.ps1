BeforeAll {
    . (Join-Path $PSScriptRoot 'HealthTestHelpers.ps1')
    Import-APKITestModule
}

AfterAll {
    Remove-Module AutomaticPKI -Force -ErrorAction SilentlyContinue
}

Describe 'Test-APKIHostnameMatch' {
    It '<Pattern> vs <HostName> = <Expected>' -TestCases @(
        @{ Pattern = 'www.contoso.com'; HostName = 'www.contoso.com'; Expected = $true }
        @{ Pattern = 'WWW.Contoso.com'; HostName = 'www.contoso.COM.'; Expected = $true }
        @{ Pattern = 'www.contoso.com'; HostName = 'contoso.com'; Expected = $false }
        @{ Pattern = '*.contoso.com'; HostName = 'www.contoso.com'; Expected = $true }
        @{ Pattern = '*.contoso.com'; HostName = 'contoso.com'; Expected = $false }
        @{ Pattern = '*.contoso.com'; HostName = 'a.b.contoso.com'; Expected = $false }
        @{ Pattern = '*.contoso.com'; HostName = 'wwwcontoso.com'; Expected = $false }
        @{ Pattern = 'w*.contoso.com'; HostName = 'www.contoso.com'; Expected = $false }
        @{ Pattern = '*.com'; HostName = 'contoso.com'; Expected = $false }
        @{ Pattern = 'www.*.com'; HostName = 'www.contoso.com'; Expected = $false }
        @{ Pattern = ''; HostName = 'www.contoso.com'; Expected = $false }
    ) {
        param($Pattern, $HostName, $Expected)
        $actual = InModuleScope AutomaticPKI -Parameters @{ P = $Pattern; H = $HostName } {
            param($P, $H)
            Test-APKIHostnameMatch -Pattern $P -HostName $H
        }
        $actual | Should -Be $Expected
    }
}
