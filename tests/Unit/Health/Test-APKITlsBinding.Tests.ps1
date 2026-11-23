BeforeAll {
    . (Join-Path $PSScriptRoot 'HealthTestHelpers.ps1')
    Import-APKITestModule
}

AfterAll {
    Remove-Module AutomaticPKI -Force -ErrorAction SilentlyContinue
}

Describe 'Test-APKITlsBinding' {
    BeforeAll {
        $env:APKI_ROOT = $TestDrive
        Mock -ModuleName AutomaticPKI Write-APKILog {}
    }

    It 'passes when the served thumbprint matches (case and spaces ignored)' {
        Mock -ModuleName AutomaticPKI Invoke-APKITlsHandshake { [pscustomobject]@{ Thumbprint = 'ABCDEF0123' } }
        $r = InModuleScope AutomaticPKI {
            Test-APKITlsBinding -HostName 'www.contoso.com' -Port 443 -IPAddress '127.0.0.1' -ExpectedThumbprint 'ab cd ef 01 23'
        }
        $r.Check | Should -Be 'TlsHandshake'
        $r.Target | Should -Be 'www.contoso.com:443'
        $r.Passed | Should -BeTrue
        Should -Invoke -ModuleName AutomaticPKI Invoke-APKITlsHandshake -Times 1 -Exactly -ParameterFilter {
            $HostName -eq 'www.contoso.com' -and $IPAddress -eq '127.0.0.1' -and $Port -eq 443
        }
    }

    It 'fails when a different certificate is served' {
        Mock -ModuleName AutomaticPKI Invoke-APKITlsHandshake { [pscustomobject]@{ Thumbprint = '1111' } }
        $r = InModuleScope AutomaticPKI {
            Test-APKITlsBinding -HostName 'www.contoso.com' -ExpectedThumbprint '2222'
        }
        $r.Passed | Should -BeFalse
        $r.Detail | Should -Match '1111'
        $r.Detail | Should -Match '2222'
    }

    It 'resolves the host name when no IP address is given' {
        Mock -ModuleName AutomaticPKI Invoke-APKITlsHandshake { [pscustomobject]@{ Thumbprint = '2222' } }
        InModuleScope AutomaticPKI {
            Test-APKITlsBinding -HostName 'www.contoso.com' -ExpectedThumbprint '2222' | Out-Null
        }
        Should -Invoke -ModuleName AutomaticPKI Invoke-APKITlsHandshake -Times 1 -Exactly -ParameterFilter {
            -not $IPAddress -and $HostName -eq 'www.contoso.com'
        }
    }

    It 'reports a handshake timeout as failed' {
        Mock -ModuleName AutomaticPKI Invoke-APKITlsHandshake { throw [System.TimeoutException]::new('TCP connect timed out after 5 s.') }
        $r = InModuleScope AutomaticPKI {
            Test-APKITlsBinding -HostName 'www.contoso.com' -IPAddress '127.0.0.1' -ExpectedThumbprint '2222' -TimeoutSec 5
        }
        $r.Passed | Should -BeFalse
        $r.Detail | Should -Match 'timed out'
    }

    It 'reports other handshake errors as failed' {
        Mock -ModuleName AutomaticPKI Invoke-APKITlsHandshake { throw 'Authentication failed because the remote party has closed the transport stream.' }
        $r = InModuleScope AutomaticPKI {
            Test-APKITlsBinding -HostName 'www.contoso.com' -ExpectedThumbprint '2222'
        }
        $r.Passed | Should -BeFalse
        $r.Detail | Should -Match 'closed the transport stream'
    }
}
