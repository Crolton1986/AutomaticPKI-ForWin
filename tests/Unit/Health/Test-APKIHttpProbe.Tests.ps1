BeforeAll {
    . (Join-Path $PSScriptRoot 'HealthTestHelpers.ps1')
    Import-APKITestModule
}

AfterAll {
    Remove-Module AutomaticPKI -Force -ErrorAction SilentlyContinue
}

Describe 'Test-APKIHttpProbe' {
    BeforeAll {
        $env:APKI_ROOT = $TestDrive
        Mock -ModuleName AutomaticPKI Write-APKILog {}
    }

    It 'passes on HTTP 200' {
        Mock -ModuleName AutomaticPKI Invoke-APKIHttpRequest { [pscustomobject]@{ StatusCode = 200; StatusDescription = 'OK' } }
        $r = InModuleScope AutomaticPKI { Test-APKIHttpProbe -Url 'https://www.contoso.com/' }
        $r.Check | Should -Be 'HttpProbe'
        $r.Passed | Should -BeTrue
    }

    It 'passes on a redirect (not followed)' {
        Mock -ModuleName AutomaticPKI Invoke-APKIHttpRequest { [pscustomobject]@{ StatusCode = 302; StatusDescription = 'Found' } }
        $r = InModuleScope AutomaticPKI { Test-APKIHttpProbe -Url 'https://www.contoso.com/' }
        $r.Passed | Should -BeTrue
    }

    It 'fails on HTTP 503' {
        Mock -ModuleName AutomaticPKI Invoke-APKIHttpRequest { [pscustomobject]@{ StatusCode = 503; StatusDescription = 'Service Unavailable' } }
        $r = InModuleScope AutomaticPKI { Test-APKIHttpProbe -Url 'https://www.contoso.com/' -ExpectStatusBelow 500 }
        $r.Passed | Should -BeFalse
        $r.Detail | Should -Match '503'
    }

    It 'honours a stricter threshold' {
        Mock -ModuleName AutomaticPKI Invoke-APKIHttpRequest { [pscustomobject]@{ StatusCode = 404; StatusDescription = 'Not Found' } }
        $r = InModuleScope AutomaticPKI { Test-APKIHttpProbe -Url 'https://www.contoso.com/' -ExpectStatusBelow 400 }
        $r.Passed | Should -BeFalse
    }

    It 'passes the Host header through' {
        Mock -ModuleName AutomaticPKI Invoke-APKIHttpRequest { [pscustomobject]@{ StatusCode = 200; StatusDescription = 'OK' } }
        $r = InModuleScope AutomaticPKI { Test-APKIHttpProbe -Url 'https://127.0.0.1:443/' -HostHeader 'www.contoso.com' }
        $r.Target | Should -Match 'Host: www\.contoso\.com'
        Should -Invoke -ModuleName AutomaticPKI Invoke-APKIHttpRequest -Times 1 -Exactly -ParameterFilter { $HostHeader -eq 'www.contoso.com' }
    }

    It 'fails when the request throws' {
        Mock -ModuleName AutomaticPKI Invoke-APKIHttpRequest { throw 'The operation has timed out' }
        $r = InModuleScope AutomaticPKI { Test-APKIHttpProbe -Url 'https://www.contoso.com/' }
        $r.Passed | Should -BeFalse
        $r.Detail | Should -Match 'timed out'
    }
}
