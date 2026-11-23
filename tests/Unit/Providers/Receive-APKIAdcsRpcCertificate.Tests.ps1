BeforeAll {
    $env:APKI_ROOT = $TestDrive
    Import-Module (Join-Path $PSScriptRoot '../../../src/AutomaticPKI/AutomaticPKI.psd1') -Force
    . (Join-Path $PSScriptRoot 'CertreqFixtures.ps1')

    function Invoke-Receive {
        param([Parameter(Mandatory)][object]$Order, [Parameter(Mandatory)][string]$RequestId)
        InModuleScope AutomaticPKI -Parameters @{ Order = $Order; RequestId = $RequestId } {
            param($Order, $RequestId)
            Receive-APKIAdcsRpcCertificate -Order $Order -RequestId $RequestId
        }
    }

    function Get-TempLeftovers {
        $tmp = Join-Path $TestDrive 'tmp'
        if (Test-Path -LiteralPath $tmp) { @(Get-ChildItem -LiteralPath $tmp -Force) } else { @() }
    }
}

# Mock bodies only use their own parameters and literals, so they work whatever scope Pester runs them in.
Describe 'Receive-APKIAdcsRpcCertificate' {
    BeforeEach {
        Mock Write-APKILog -ModuleName AutomaticPKI { }
        Mock Invoke-APKICertreq -ModuleName AutomaticPKI -ParameterFilter { $Arguments[0] -eq '-accept' } {
            [pscustomobject]@{ ExitCode = 0; Output = [string[]]@(
                    'Installed Certificate:'
                    '  Serial Number: 4f00000012ab34cd56ef7890120000000012'
                    '  Subject: CN=www.contoso.com (DNS Name=www.contoso.com, DNS Name=contoso.com)'
                    '  Thumbprint: 3f2a6c1b9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a'
                ) }
        }
        Mock Find-APKIMachineCertificate -ModuleName AutomaticPKI {
            [pscustomobject]@{ Thumbprint = '3F2A6C1B9D8E7F6A5B4C3D2E1F0A9B8C7D6E5F4A'; HasPrivateKey = $true }
        }
        Mock Get-APKICertificateFileInfo -ModuleName AutomaticPKI { }
    }

    It 'retrieves an issued certificate, accepts it in machine context and returns Issued' {
        Mock Invoke-APKICertreq -ModuleName AutomaticPKI -ParameterFilter { $Arguments[0] -eq '-retrieve' } {
            Set-Content -LiteralPath $Arguments[-1] -Value '-----BEGIN CERTIFICATE-----' -Encoding UTF8
            [pscustomobject]@{ ExitCode = 0; Output = [string[]]@('Certificate retrieved(Issued) Issued  Resubmitted by CORP\pkiadmin') }
        }

        $r = Invoke-Receive -Order (New-AdcsRpcTestOrder) -RequestId '43'

        $r.Status | Should -Be 'Issued'
        $r.RequestId | Should -Be '43'
        $r.Thumbprint | Should -BeExactly '3F2A6C1B9D8E7F6A5B4C3D2E1F0A9B8C7D6E5F4A'
        Should -Invoke Invoke-APKICertreq -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter {
            $Arguments[0] -eq '-retrieve' -and $Arguments -contains '-q' -and
            ($Arguments -join '|') -like '*|-config|ca01.corp.local\Corp Issuing CA|43|*.cer'
        }
        Should -Invoke Invoke-APKICertreq -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter {
            $Arguments[0] -eq '-accept' -and $Arguments -contains '-machine' -and $Arguments -contains '-q'
        }
        @(Get-TempLeftovers).Count | Should -Be 0
    }

    It 'returns Pending without event 1002 when the request is still pending' {
        Mock Invoke-APKICertreq -ModuleName AutomaticPKI -ParameterFilter { $Arguments[0] -eq '-retrieve' } {
            [pscustomobject]@{ ExitCode = 0; Output = [string[]]@('Certificate request is pending: Taken Under Submission (0)') }
        }

        $r = Invoke-Receive -Order (New-AdcsRpcTestOrder) -RequestId '43'

        $r.Status | Should -Be 'Pending'
        $r.RequestId | Should -Be '43'
        Should -Invoke Invoke-APKICertreq -ModuleName AutomaticPKI -Times 0 -Exactly -ParameterFilter { $Arguments[0] -eq '-accept' }
        Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 0 -Exactly -ParameterFilter { $EventId -eq 1002 }
    }

    It 'returns Denied and logs event 3001 when the CA manager denied the request' {
        Mock Invoke-APKICertreq -ModuleName AutomaticPKI -ParameterFilter { $Arguments[0] -eq '-retrieve' } {
            [pscustomobject]@{ ExitCode = -2146877420; Output = [string[]]@(
                    'Certificate not issued (Denied) Denied by CORP\pkiadmin  0x80094014'
                    'Denied by CORP\pkiadmin  0x80094014'
                ) }
        }

        $r = Invoke-Receive -Order (New-AdcsRpcTestOrder) -RequestId '45'

        $r.Status | Should -Be 'Denied'
        $r.RequestId | Should -Be '45'
        Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter { $EventId -eq 3001 }
        Should -Invoke Invoke-APKICertreq -ModuleName AutomaticPKI -Times 0 -Exactly -ParameterFilter { $Arguments[0] -eq '-accept' }
    }

    It 'returns Failed when the CA is offline' {
        Mock Invoke-APKICertreq -ModuleName AutomaticPKI -ParameterFilter { $Arguments[0] -eq '-retrieve' } {
            [pscustomobject]@{ ExitCode = -2147023174; Output = [string[]]@(
                    'Certificate Request Processor: The RPC server is unavailable. 0x800706ba (WIN32: 1722 RPC_S_SERVER_UNAVAILABLE)'
                ) }
        }

        $r = Invoke-Receive -Order (New-AdcsRpcTestOrder) -RequestId '43'

        $r.Status | Should -Be 'Failed'
        $r.RequestId | Should -Be '43'
        $r.Message | Should -Match '0x800706ba'
        Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter { $EventId -eq 3000 }
    }

    It 'returns Failed for an unknown request id' {
        Mock Invoke-APKICertreq -ModuleName AutomaticPKI -ParameterFilter { $Arguments[0] -eq '-retrieve' } {
            [pscustomobject]@{ ExitCode = -2147024809; Output = [string[]]@(
                    'Certificate Request Processor: The parameter is incorrect. 0x80070057 (WIN32: 87 ERROR_INVALID_PARAMETER)'
                ) }
        }

        (Invoke-Receive -Order (New-AdcsRpcTestOrder) -RequestId '9999').Status | Should -Be 'Failed'
    }

    It 'returns Failed for malformed output' {
        Mock Invoke-APKICertreq -ModuleName AutomaticPKI -ParameterFilter { $Arguments[0] -eq '-retrieve' } {
            [pscustomobject]@{ ExitCode = 0; Output = [string[]]@('Lorem ipsum dolor sit amet') }
        }

        (Invoke-Receive -Order (New-AdcsRpcTestOrder) -RequestId '43').Status | Should -Be 'Failed'
    }

    It 'rejects a non-numeric request id without calling certreq' {
        Mock Invoke-APKICertreq -ModuleName AutomaticPKI { throw 'must not be called' }

        $r = Invoke-Receive -Order (New-AdcsRpcTestOrder) -RequestId '43 -f'

        $r.Status | Should -Be 'Failed'
        Should -Invoke Invoke-APKICertreq -ModuleName AutomaticPKI -Times 0 -Exactly
        Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter { $EventId -eq 3004 }
    }
}
