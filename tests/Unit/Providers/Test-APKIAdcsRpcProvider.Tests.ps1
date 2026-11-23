BeforeAll {
    $env:APKI_ROOT = $TestDrive
    Import-Module (Join-Path $PSScriptRoot '../../../src/AutomaticPKI/AutomaticPKI.psd1') -Force
    . (Join-Path $PSScriptRoot 'CertreqFixtures.ps1')

    function Invoke-ProviderTest {
        param([Parameter(Mandatory)][object]$Order)
        InModuleScope AutomaticPKI -Parameters @{ Order = $Order } {
            param($Order)
            Test-APKIAdcsRpcProvider -Order $Order
        }
    }
}

Describe 'Test-APKIAdcsRpcProvider' {
    BeforeEach {
        Mock Write-APKILog -ModuleName AutomaticPKI { }
    }

    It 'returns $true when certutil -ping succeeds against the configured CA' {
        Mock Invoke-APKICertutil -ModuleName AutomaticPKI {
            [pscustomobject]@{ ExitCode = 0; Output = [string[]]@(
                    'Connecting to ca01.corp.local\Corp Issuing CA ...'
                    'Server "Corp Issuing CA" ICertRequest2 interface is alive (0ms)'
                    'CertUtil: -ping command completed successfully.'
                ) }
        }

        $r = Invoke-ProviderTest -Order (New-AdcsRpcTestOrder)

        $r | Should -BeOfType [bool]
        $r | Should -BeTrue
        Should -Invoke Invoke-APKICertutil -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter {
            ($Arguments -join '|') -eq '-config|ca01.corp.local\Corp Issuing CA|-ping'
        }
        Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 0 -Exactly
    }

    It 'returns $false and logs the reason when the CA does not answer' {
        Mock Invoke-APKICertutil -ModuleName AutomaticPKI {
            [pscustomobject]@{ ExitCode = -2147023174; Output = [string[]]@(
                    'Connecting to ca01.corp.local\Corp Issuing CA ...'
                    'Server could not be reached: The RPC server is unavailable. 0x800706ba (WIN32: 1722 RPC_S_SERVER_UNAVAILABLE) -- (31ms)'
                    'CertUtil: -ping command FAILED: 0x800706ba (WIN32: 1722 RPC_S_SERVER_UNAVAILABLE)'
                ) }
        }

        $r = Invoke-ProviderTest -Order (New-AdcsRpcTestOrder)

        $r | Should -BeOfType [bool]
        $r | Should -BeFalse
        Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter {
            $Level -eq 'Warning' -and $Message -match '0x800706ba' -and $OrderId -eq 'www-contoso-com'
        }
    }

    It 'returns $false without pinging when CAConfig is missing' {
        Mock Invoke-APKICertutil -ModuleName AutomaticPKI { throw 'must not be called' }

        $r = Invoke-ProviderTest -Order (New-AdcsRpcTestOrder -CAConfig $null)

        $r | Should -BeFalse
        Should -Invoke Invoke-APKICertutil -ModuleName AutomaticPKI -Times 0 -Exactly
        Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter { $EventId -eq 3004 }
    }
}
