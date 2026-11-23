BeforeAll {
    . (Join-Path $PSScriptRoot 'AdcsCep.TestHelpers.ps1')
    $env:APKI_ROOT = $TestDrive
    Import-AdcsCepTestModule

    $script:IssuedThumb = 'A1B2C3D4E5F60718293A4B5C6D7E8F9012345678'
    $script:RequestThumb = 'F0E1D2C3B4A5968778695A4B3C2D1E0F12345678'

    function Invoke-TestReceive {
        param([Parameter(Mandatory)] $Order, [Parameter(Mandatory)] [AllowEmptyString()] [string]$RequestId, [switch]$DryRun)
        InModuleScope AutomaticPKI -Parameters @{ Order = $Order; RequestId = $RequestId; DryRun = [bool]$DryRun } {
            param($Order, $RequestId, $DryRun)
            Receive-APKIAdcsCepCertificate -Order $Order -RequestId $RequestId -WhatIf:$DryRun
        }
    }
}

AfterAll {
    Remove-Module AutomaticPKI -Force -ErrorAction SilentlyContinue
}

Describe 'Receive-APKIAdcsCepCertificate' {
    BeforeEach {
        Mock -ModuleName AutomaticPKI Write-APKILog { }
        Mock -ModuleName AutomaticPKI Get-APKISecret { Get-AdcsCepTestCredential }
        Mock -ModuleName AutomaticPKI Get-APKIAdcsCepKeyInfo { [pscustomobject]@{ Algorithm = 'RSA'; Length = 2048 } }
        Mock -ModuleName AutomaticPKI Invoke-APKIGetCertificate {
            Get-AdcsCepTestEnrollmentResult -Status 'Issued' -CertificateThumbprint $script:IssuedThumb
        }
    }

    It 'retrieves the pending request by its request-store thumbprint and returns Issued' {
        $result = Invoke-TestReceive -Order (Get-AdcsCepTestOrder) -RequestId $script:RequestThumb.ToLowerInvariant()

        $result.Status | Should -Be 'Issued'
        $result.Thumbprint | Should -Be $script:IssuedThumb
        $result.RequestId | Should -BeExactly $script:RequestThumb
        Should -Invoke Invoke-APKIGetCertificate -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter {
            $RequestThumbprint -eq $script:RequestThumb -and $null -eq $Credential
        }
    }

    It 'passes the CredentialRef credential on retrieval' {
        $null = Invoke-TestReceive -Order (Get-AdcsCepTestOrder -CredentialRef 'cep-svc') -RequestId $script:RequestThumb

        Should -Invoke Get-APKISecret -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter { $Name -eq 'cep-svc' }
        Should -Invoke Invoke-APKIGetCertificate -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter { $null -ne $Credential }
    }

    It 'returns Pending with the same RequestId while still pending, without event 1002' {
        Mock -ModuleName AutomaticPKI Invoke-APKIGetCertificate {
            Get-AdcsCepTestEnrollmentResult -Status 'Pending' -RequestThumbprint $script:RequestThumb
        }

        $result = Invoke-TestReceive -Order (Get-AdcsCepTestOrder) -RequestId $script:RequestThumb

        $result.Status | Should -Be 'Pending'
        $result.RequestId | Should -Be $script:RequestThumb
        Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 0 -Exactly -ParameterFilter { $EventId -eq 1002 }
    }

    It 'keeps the RequestId when a still-pending result has no request object' {
        Mock -ModuleName AutomaticPKI Invoke-APKIGetCertificate { Get-AdcsCepTestEnrollmentResult -Status 'Pending' }

        $result = Invoke-TestReceive -Order (Get-AdcsCepTestOrder) -RequestId $script:RequestThumb

        $result.Status | Should -Be 'Pending'
        $result.RequestId | Should -Be $script:RequestThumb
    }

    It 'returns Denied with event 3001 when the CA denied the request' {
        Mock -ModuleName AutomaticPKI Invoke-APKIGetCertificate { Get-AdcsCepTestEnrollmentResult -Status 'Denied' }

        $result = Invoke-TestReceive -Order (Get-AdcsCepTestOrder) -RequestId $script:RequestThumb

        $result.Status | Should -Be 'Denied'
        $result.RequestId | Should -Be $script:RequestThumb
        Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter { $EventId -eq 3001 }
    }

    It 'returns Failed with event 3000 when the request is missing from the request store' {
        Mock -ModuleName AutomaticPKI Invoke-APKIGetCertificate {
            throw "Pending request 'F0E1' was not found in Cert:\LocalMachine\Request (deleted, or already retrieved): Cannot find path."
        }

        $result = Invoke-TestReceive -Order (Get-AdcsCepTestOrder) -RequestId $script:RequestThumb

        $result.Status | Should -Be 'Failed'
        $result.Message | Should -BeLike '*not found in Cert:\LocalMachine\Request*'
        Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter { $EventId -eq 3000 }
    }

    It 'rejects a RequestId that is not a thumbprint (<RequestId>)' -TestCases @(
        @{ RequestId = '' }
        @{ RequestId = '1234' }
        @{ RequestId = 'ZZE1D2C3B4A5968778695A4B3C2D1E0F12345678' }
    ) {
        $result = Invoke-TestReceive -Order (Get-AdcsCepTestOrder) -RequestId $RequestId

        $result.Status | Should -Be 'Failed'
        $result.Message | Should -BeLike '*40 hex*'
        Should -Invoke Invoke-APKIGetCertificate -ModuleName AutomaticPKI -Times 0 -Exactly
    }

    It 'fails with event 3004 when the order configuration is invalid' {
        $result = Invoke-TestReceive -Order (Get-AdcsCepTestOrder -CepUrl '') -RequestId $script:RequestThumb

        $result.Status | Should -Be 'Failed'
        Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter { $EventId -eq 3004 }
        Should -Invoke Invoke-APKIGetCertificate -ModuleName AutomaticPKI -Times 0 -Exactly
    }

    It 'does nothing with -WhatIf' {
        $result = Invoke-TestReceive -Order (Get-AdcsCepTestOrder) -RequestId $script:RequestThumb -DryRun

        $result | Should -BeNullOrEmpty
        Should -Invoke Invoke-APKIGetCertificate -ModuleName AutomaticPKI -Times 0 -Exactly
    }
}
