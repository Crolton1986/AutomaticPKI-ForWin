BeforeAll {
    Import-Module ([System.IO.Path]::Combine($PSScriptRoot, '..', '..', '..', 'src', 'AutomaticPKI', 'AutomaticPKI.psd1')) -Force
}

AfterAll {
    Remove-Module AutomaticPKI -Force -ErrorAction SilentlyContinue
}

Describe 'Provider dispatch' {
    BeforeEach {
        Mock -ModuleName AutomaticPKI Write-APKILog { }
        Mock -ModuleName AutomaticPKI Request-APKIAdcsRpcCertificate { [pscustomobject]@{ Status = 'Issued'; Thumbprint = 'RPC'; RequestId = '1'; Message = '' } }
        Mock -ModuleName AutomaticPKI Request-APKIAdcsCepCertificate { [pscustomobject]@{ Status = 'Issued'; Thumbprint = 'CEP'; RequestId = $null; Message = '' } }
        Mock -ModuleName AutomaticPKI Receive-APKIAdcsRpcCertificate { [pscustomobject]@{ Status = 'Issued'; Thumbprint = "RPC-$RequestId"; RequestId = $RequestId; Message = '' } }
        Mock -ModuleName AutomaticPKI Receive-APKIAdcsCepCertificate { [pscustomobject]@{ Status = 'Pending'; Thumbprint = $null; RequestId = $RequestId; Message = '' } }
    }

    It 'requests through the provider function (<Provider>)' -TestCases @(
        @{ Provider = 'AdcsRpc'; Expected = 'RPC' }
        @{ Provider = 'AdcsCep'; Expected = 'CEP' }
    ) {
        $r = InModuleScope AutomaticPKI -Parameters @{ P = $Provider } {
            param($P)
            Invoke-APKIProviderRequest -Order ([pscustomobject]@{ Id = 'o1'; Provider = $P })
        }
        $r.Thumbprint | Should -Be $Expected
    }

    It 'receives through the provider Receive function with the pending request ID' {
        $r = InModuleScope AutomaticPKI {
            Invoke-APKIProviderReceive -Order ([pscustomobject]@{ Id = 'o1'; Provider = 'AdcsRpc'; PendingRequestId = '42' })
        }
        $r.Thumbprint | Should -Be 'RPC-42'
        Should -Invoke -ModuleName AutomaticPKI Receive-APKIAdcsRpcCertificate -Times 1 -Exactly -ParameterFilter { $RequestId -eq '42' }

        $r = InModuleScope AutomaticPKI {
            Invoke-APKIProviderReceive -Order ([pscustomobject]@{ Id = 'o1'; Provider = 'AdcsCep' }) -RequestId 'ABC'
        }
        $r.Status | Should -Be 'Pending'
        $r.RequestId | Should -Be 'ABC'
    }

    It 'fails with EventId 3004 for an unknown provider (<Provider>)' -TestCases @(
        @{ Provider = 'Acme' }
        @{ Provider = 'adcsrpc' }
        @{ Provider = '' }
    ) {
        $r = InModuleScope AutomaticPKI -Parameters @{ P = $Provider } {
            param($P)
            Invoke-APKIProviderRequest -Order ([pscustomobject]@{ Id = 'o1'; Provider = $P })
        }
        $r.Status | Should -Be 'Failed'
        $r.Message | Should -Match 'Unknown certificate provider'
        Should -Invoke -ModuleName AutomaticPKI Write-APKILog -Times 1 -Exactly -ParameterFilter { $EventId -eq 3004 }
        Should -Invoke -ModuleName AutomaticPKI Request-APKIAdcsRpcCertificate -Times 0 -Exactly
    }

    It 'fails with EventId 3004 when receiving without a request ID' {
        $r = InModuleScope AutomaticPKI {
            Invoke-APKIProviderReceive -Order ([pscustomobject]@{ Id = 'o1'; Provider = 'AdcsRpc' })
        }
        $r.Status | Should -Be 'Failed'
        Should -Invoke -ModuleName AutomaticPKI Receive-APKIAdcsRpcCertificate -Times 0 -Exactly
        Should -Invoke -ModuleName AutomaticPKI Write-APKILog -Times 1 -Exactly -ParameterFilter { $EventId -eq 3004 }
    }
}
