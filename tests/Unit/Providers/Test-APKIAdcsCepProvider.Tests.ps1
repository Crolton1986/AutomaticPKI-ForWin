BeforeAll {
    . (Join-Path $PSScriptRoot 'AdcsCep.TestHelpers.ps1')
    $env:APKI_ROOT = $TestDrive
    Import-AdcsCepTestModule

    function Invoke-TestProvider {
        param([Parameter(Mandatory)] $Order)
        InModuleScope AutomaticPKI -Parameters @{ Order = $Order } {
            param($Order)
            Test-APKIAdcsCepProvider -Order $Order
        }
    }
}

AfterAll {
    Remove-Module AutomaticPKI -Force -ErrorAction SilentlyContinue
}

Describe 'Test-APKIAdcsCepProvider' {
    BeforeEach {
        Mock -ModuleName AutomaticPKI Write-APKILog { }
        Mock -ModuleName AutomaticPKI Get-APKISecret { Get-AdcsCepTestCredential }
        Mock -ModuleName AutomaticPKI Invoke-APKICepHttpRequest { 200 }
    }

    It 'returns $true for HTTP <Code>' -TestCases @(
        @{ Code = 200 }
        @{ Code = 302 }
        @{ Code = 401 }
        @{ Code = 403 }
        @{ Code = 405 }
    ) {
        $script:HttpCode = $Code
        Mock -ModuleName AutomaticPKI Invoke-APKICepHttpRequest { $script:HttpCode }

        $result = Invoke-TestProvider -Order (Get-AdcsCepTestOrder)

        $result | Should -BeOfType [bool]
        $result | Should -BeTrue
        Should -Invoke Invoke-APKICepHttpRequest -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter {
            $Uri -eq 'https://cep.corp.local/ADPolicyProvider_CEP_Kerberos/service.svc/CEP'
        }
    }

    It 'returns $false and logs a warning for HTTP <Code>' -TestCases @(
        @{ Code = 404 }
        @{ Code = 500 }
        @{ Code = 503 }
    ) {
        $script:HttpCode = $Code
        Mock -ModuleName AutomaticPKI Invoke-APKICepHttpRequest { $script:HttpCode }

        $result = Invoke-TestProvider -Order (Get-AdcsCepTestOrder)

        $result | Should -BeFalse
        Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter {
            $Level -eq 'Warning' -and $Message -like "*HTTP $($script:HttpCode)*"
        }
    }

    It 'returns $false and logs the reason when the endpoint is unreachable' {
        Mock -ModuleName AutomaticPKI Invoke-APKICepHttpRequest { throw 'No such host is known.' }

        $result = Invoke-TestProvider -Order (Get-AdcsCepTestOrder)

        $result | Should -BeFalse
        Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter {
            $Level -eq 'Warning' -and $Message -like '*unreachable*No such host*' -and $OrderId -eq 'contoso-web'
        }
    }

    It 'returns $false with event 3004 for invalid settings without probing' {
        $result = Invoke-TestProvider -Order (Get-AdcsCepTestOrder -Template '')

        $result | Should -BeFalse
        Should -Invoke Invoke-APKICepHttpRequest -ModuleName AutomaticPKI -Times 0 -Exactly
        Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter { $EventId -eq 3004 }
    }

    It 'returns $false with event 3004 when the credential cannot be loaded' {
        Mock -ModuleName AutomaticPKI Get-APKISecret { throw 'not found' }

        $result = Invoke-TestProvider -Order (Get-AdcsCepTestOrder -CredentialRef 'missing')

        $result | Should -BeFalse
        Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter { $EventId -eq 3004 }
    }
}
