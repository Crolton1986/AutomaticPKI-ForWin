BeforeAll {
    . (Join-Path $PSScriptRoot 'HealthTestHelpers.ps1')
    Import-APKITestModule
}

AfterAll {
    Remove-Module AutomaticPKI -Force -ErrorAction SilentlyContinue
}

Describe 'Invoke-APKIHealthCheck' {
    BeforeAll {
        $env:APKI_ROOT = $TestDrive
        $script:NewThumb = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'
        Mock -ModuleName AutomaticPKI Write-APKILog {}
    }

    BeforeEach {
        Mock -ModuleName AutomaticPKI Test-APKISiteState {
            [pscustomobject]@{ Check = 'SiteState'; Target = $SiteName; Passed = $true; Detail = 'Started.' }
        }
        Mock -ModuleName AutomaticPKI Test-APKITlsBinding {
            [pscustomobject]@{ Check = 'TlsHandshake'; Target = "${HostName}:$Port"; Passed = $true; Detail = '' }
        }
        Mock -ModuleName AutomaticPKI Test-APKIHttpProbe {
            [pscustomobject]@{ Check = 'HttpProbe'; Target = $Url; Passed = $true; Detail = '' }
        }
    }

    It 'passes and connects to 127.0.0.1 with SNI for an SNI binding' {
        $order = Get-APKITestOrder -ProbeEnabled $true
        $h = InModuleScope AutomaticPKI -Parameters @{ Order = $order; T = $script:NewThumb } {
            param($Order, $T)
            Invoke-APKIHealthCheck -Order $Order -Thumbprint $T
        }
        $h.Passed | Should -BeTrue
        $h.Thumbprint | Should -Be $script:NewThumb
        ($h.Results | Select-Object -ExpandProperty Check) | Should -Be @('SiteState', 'TlsHandshake', 'HttpProbe')
        Should -Invoke -ModuleName AutomaticPKI Test-APKITlsBinding -Times 1 -Exactly -ParameterFilter {
            $HostName -eq 'www.contoso.com' -and $IPAddress -eq '127.0.0.1' -and $Port -eq 443 -and $ExpectedThumbprint -eq 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'
        }
        Should -Invoke -ModuleName AutomaticPKI Test-APKIHttpProbe -Times 1 -Exactly -ParameterFilter {
            $Url -eq 'https://www.contoso.com:443/' -and -not $HostHeader
        }
    }

    It 'uses the binding IP and a Host header for a non-SNI binding' {
        $bindings = @(
            [pscustomobject]@{ SiteName = 'Contoso'; Protocol = 'https'; IPAddress = '10.0.0.5'; Port = 8443; HostHeader = ''; SslFlags = 0; Thumbprint = ''; StoreName = 'My' }
            [pscustomobject]@{ SiteName = 'Contoso'; Protocol = 'http'; IPAddress = '*'; Port = 80; HostHeader = ''; SslFlags = 0; Thumbprint = ''; StoreName = '' }
        )
        $order = Get-APKITestOrder -Bindings $bindings -ProbeEnabled $true
        $h = InModuleScope AutomaticPKI -Parameters @{ Order = $order; T = $script:NewThumb } {
            param($Order, $T)
            Invoke-APKIHealthCheck -Order $Order -Thumbprint $T
        }
        $h.Passed | Should -BeTrue
        Should -Invoke -ModuleName AutomaticPKI Test-APKITlsBinding -Times 1 -Exactly -ParameterFilter {
            $HostName -eq 'www.contoso.com' -and $IPAddress -eq '10.0.0.5' -and $Port -eq 8443
        }
        Should -Invoke -ModuleName AutomaticPKI Test-APKIHttpProbe -Times 1 -Exactly -ParameterFilter {
            $Url -eq 'https://10.0.0.5:8443/' -and $HostHeader -eq 'www.contoso.com'
        }
    }

    It 'uses 127.0.0.1 for a non-SNI all-unassigned binding' {
        $bindings = @([pscustomobject]@{ SiteName = 'Contoso'; Protocol = 'https'; IPAddress = '*'; Port = 443; HostHeader = ''; SslFlags = 0; Thumbprint = ''; StoreName = 'My' })
        $order = Get-APKITestOrder -Bindings $bindings
        InModuleScope AutomaticPKI -Parameters @{ Order = $order; T = $script:NewThumb } {
            param($Order, $T)
            Invoke-APKIHealthCheck -Order $Order -Thumbprint $T | Out-Null
        }
        Should -Invoke -ModuleName AutomaticPKI Test-APKITlsBinding -Times 1 -Exactly -ParameterFilter { $IPAddress -eq '127.0.0.1' }
        Should -Invoke -ModuleName AutomaticPKI Test-APKIHttpProbe -Times 0 -Exactly
    }

    It 'fails overall when the wrong certificate is served' {
        Mock -ModuleName AutomaticPKI Test-APKITlsBinding {
            [pscustomobject]@{ Check = 'TlsHandshake'; Target = "${HostName}:$Port"; Passed = $false; Detail = 'Served certificate AAAA, expected BBBB.' }
        }
        $order = Get-APKITestOrder
        $h = InModuleScope AutomaticPKI -Parameters @{ Order = $order; T = $script:NewThumb } {
            param($Order, $T)
            Invoke-APKIHealthCheck -Order $Order -Thumbprint $T
        }
        $h.Passed | Should -BeFalse
    }

    It 'fails overall when the HTTP probe returns 503' {
        Mock -ModuleName AutomaticPKI Test-APKIHttpProbe {
            [pscustomobject]@{ Check = 'HttpProbe'; Target = $Url; Passed = $false; Detail = 'HTTP 503' }
        }
        $order = Get-APKITestOrder -ProbeEnabled $true
        $h = InModuleScope AutomaticPKI -Parameters @{ Order = $order; T = $script:NewThumb } {
            param($Order, $T)
            Invoke-APKIHealthCheck -Order $Order -Thumbprint $T
        }
        $h.Passed | Should -BeFalse
        ($h.Results | Where-Object Check -EQ 'HttpProbe').Detail | Should -Be 'HTTP 503'
    }

    It 'fails overall when the order has no https binding' {
        $bindings = @([pscustomobject]@{ SiteName = 'Contoso'; Protocol = 'http'; IPAddress = '*'; Port = 80; HostHeader = ''; SslFlags = 0; Thumbprint = ''; StoreName = '' })
        $order = Get-APKITestOrder -Bindings $bindings
        $h = InModuleScope AutomaticPKI -Parameters @{ Order = $order; T = $script:NewThumb } {
            param($Order, $T)
            Invoke-APKIHealthCheck -Order $Order -Thumbprint $T
        }
        $h.Passed | Should -BeFalse
        Should -Invoke -ModuleName AutomaticPKI Test-APKITlsBinding -Times 0 -Exactly
    }
}
