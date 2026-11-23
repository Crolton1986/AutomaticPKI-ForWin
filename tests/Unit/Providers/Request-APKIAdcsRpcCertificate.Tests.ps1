BeforeAll {
    $env:APKI_ROOT = $TestDrive
    Import-Module (Join-Path $PSScriptRoot '../../../src/AutomaticPKI/AutomaticPKI.psd1') -Force
    . (Join-Path $PSScriptRoot 'CertreqFixtures.ps1')

    function Invoke-Request {
        param([Parameter(Mandatory)][object]$Order, [switch]$DryRun)
        InModuleScope AutomaticPKI -Parameters @{ Order = $Order; WhatIfFlag = [bool]$DryRun } {
            param($Order, $WhatIfFlag)
            Request-APKIAdcsRpcCertificate -Order $Order -WhatIf:$WhatIfFlag
        }
    }

    function Get-TempLeftovers {
        $tmp = Join-Path $TestDrive 'tmp'
        if (Test-Path -LiteralPath $tmp) { @(Get-ChildItem -LiteralPath $tmp -Force) } else { @() }
    }
}

# Mock bodies only use their own parameters and literals, so they work whatever scope Pester runs them in.
Describe 'Request-APKIAdcsRpcCertificate' {
    BeforeEach {
        Mock Write-APKILog -ModuleName AutomaticPKI { }

        Mock Invoke-APKICertreq -ModuleName AutomaticPKI -ParameterFilter { $Arguments[0] -eq '-new' } {
            Set-Content -LiteralPath $Arguments[-1] -Value '-----BEGIN NEW CERTIFICATE REQUEST-----' -Encoding UTF8
            [pscustomobject]@{ ExitCode = 0; Output = [string[]]@('', 'CertReq: Request Created') }
        }

        Mock Invoke-APKICertreq -ModuleName AutomaticPKI -ParameterFilter { $Arguments[0] -eq '-accept' } {
            [pscustomobject]@{ ExitCode = 0; Output = [string[]]@(
                    'Installed Certificate:'
                    '  Serial Number: 4f00000012ab34cd56ef7890120000000012'
                    '  Subject: CN=www.contoso.com (DNS Name=www.contoso.com, DNS Name=contoso.com)'
                    '  NotBefore: 11/23/2026 9:41 AM'
                    '  NotAfter: 11/23/2028 9:41 AM'
                    '  Thumbprint: 3f2a6c1b9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a'
                ) }
        }

        Mock Find-APKIMachineCertificate -ModuleName AutomaticPKI {
            [pscustomobject]@{ Thumbprint = '3F2A6C1B9D8E7F6A5B4C3D2E1F0A9B8C7D6E5F4A'; HasPrivateKey = $true }
        }
        Mock Get-APKICertificateFileInfo -ModuleName AutomaticPKI { }
    }

    Context 'issued' {
        BeforeEach {
            Mock Invoke-APKICertreq -ModuleName AutomaticPKI -ParameterFilter { $Arguments[0] -eq '-submit' } {
                Set-Content -LiteralPath $Arguments[-1] -Value '-----BEGIN CERTIFICATE-----' -Encoding UTF8
                [pscustomobject]@{ ExitCode = 0; Output = [string[]]@(
                        'RequestId: 42'
                        'RequestId: "42"'
                        'Certificate retrieved(Issued) Issued'
                    ) }
            }
        }

        It 'returns Issued with the thumbprint and request id' {
            $r = Invoke-Request -Order (New-AdcsRpcTestOrder)
            $r.Status | Should -Be 'Issued'
            $r.Thumbprint | Should -BeExactly '3F2A6C1B9D8E7F6A5B4C3D2E1F0A9B8C7D6E5F4A'
            $r.RequestId | Should -Be '42'
        }

        It 'runs certreq -new in machine context on an INF, then submits to the configured CA with the template' {
            Invoke-Request -Order (New-AdcsRpcTestOrder) | Out-Null
            Should -Invoke Invoke-APKICertreq -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter {
                $Arguments[0] -eq '-new' -and $Arguments -contains '-machine' -and $Arguments[-2] -like '*.inf' -and $Arguments[-1] -like '*.req'
            }
            Should -Invoke Invoke-APKICertreq -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter {
                $Arguments[0] -eq '-submit' -and
                ($Arguments -join '|') -like '*|-config|ca01.corp.local\Corp Issuing CA|*' -and
                ($Arguments -join '|') -like '*|-attrib|CertificateTemplate:WebServer|*' -and
                $Arguments[-2] -like '*.req' -and $Arguments[-1] -like '*.cer'
            }
            Should -Invoke Invoke-APKICertreq -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter {
                $Arguments[0] -eq '-accept' -and $Arguments -contains '-machine' -and $Arguments[-1] -like '*.cer'
            }
        }

        It 'passes -q on every certreq call' {
            Invoke-Request -Order (New-AdcsRpcTestOrder) | Out-Null
            Should -Invoke Invoke-APKICertreq -ModuleName AutomaticPKI -Times 3 -Exactly
            Should -Invoke Invoke-APKICertreq -ModuleName AutomaticPKI -Times 0 -Exactly -ParameterFilter { $Arguments -notcontains '-q' }
        }

        It 'omits -attrib when the order has no template' {
            Invoke-Request -Order (New-AdcsRpcTestOrder -Template $null) | Out-Null
            Should -Invoke Invoke-APKICertreq -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter {
                $Arguments[0] -eq '-submit' -and $Arguments -notcontains '-attrib'
            }
        }

        It 'writes the INF the builder produced before calling certreq -new' {
            Mock Invoke-APKICertreq -ModuleName AutomaticPKI -ParameterFilter { $Arguments[0] -eq '-new' } {
                $inf = Get-Content -LiteralPath $Arguments[-2] -Raw -Encoding Unicode
                if ($inf -notmatch '(?m)^_continue_ = "dns=contoso.com"') { throw 'INF content not written' }
                Set-Content -LiteralPath $Arguments[-1] -Value 'REQ' -Encoding UTF8
                [pscustomobject]@{ ExitCode = 0; Output = [string[]]@('CertReq: Request Created') }
            }
            (Invoke-Request -Order (New-AdcsRpcTestOrder)).Status | Should -Be 'Issued'
        }

        It 'removes its temp files' {
            Invoke-Request -Order (New-AdcsRpcTestOrder) | Out-Null
            @(Get-TempLeftovers).Count | Should -Be 0
        }

        It 'falls back to the .cer file thumbprint when -accept prints none' {
            Mock Invoke-APKICertreq -ModuleName AutomaticPKI -ParameterFilter { $Arguments[0] -eq '-accept' } {
                [pscustomobject]@{ ExitCode = 0; Output = [string[]]@('Installed Certificate:', '  Subject: CN=www.contoso.com') }
            }
            Mock Get-APKICertificateFileInfo -ModuleName AutomaticPKI {
                [pscustomobject]@{ Thumbprint = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'; SerialNumber = '01' }
            }
            Mock Find-APKIMachineCertificate -ModuleName AutomaticPKI -ParameterFilter { $Thumbprint -eq 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' } {
                [pscustomobject]@{ Thumbprint = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'; HasPrivateKey = $true }
            }
            $r = Invoke-Request -Order (New-AdcsRpcTestOrder)
            $r.Status | Should -Be 'Issued'
            $r.Thumbprint | Should -Be 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
        }

        It 'falls back to the serial number when no thumbprint is available' {
            Mock Invoke-APKICertreq -ModuleName AutomaticPKI -ParameterFilter { $Arguments[0] -eq '-accept' } {
                [pscustomobject]@{ ExitCode = 0; Output = [string[]]@('Installed Certificate:', '  Serial Number: 4f00000012ab34cd56ef7890120000000012') }
            }
            Mock Find-APKIMachineCertificate -ModuleName AutomaticPKI -ParameterFilter { $SerialNumber -eq '4F00000012AB34CD56EF7890120000000012' } {
                [pscustomobject]@{ Thumbprint = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'; HasPrivateKey = $true }
            }
            $r = Invoke-Request -Order (New-AdcsRpcTestOrder)
            $r.Status | Should -Be 'Issued'
            $r.Thumbprint | Should -BeExactly 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'
        }

        It 'fails when the accepted certificate is not in LocalMachine\My' {
            Mock Find-APKIMachineCertificate -ModuleName AutomaticPKI { }
            $r = Invoke-Request -Order (New-AdcsRpcTestOrder)
            $r.Status | Should -Be 'Failed'
            $r.RequestId | Should -Be '42'
            Should -Invoke Write-APKILog -ModuleName AutomaticPKI -ParameterFilter { $EventId -eq 3000 }
        }

        It 'fails when certreq -accept fails' {
            Mock Invoke-APKICertreq -ModuleName AutomaticPKI -ParameterFilter { $Arguments[0] -eq '-accept' } {
                [pscustomobject]@{ ExitCode = -2146885628; Output = [string[]]@('Certificate Request Processor: Cannot find object or property. 0x80092004 (-2146885628 CRYPT_E_NOT_FOUND)') }
            }
            $r = Invoke-Request -Order (New-AdcsRpcTestOrder)
            $r.Status | Should -Be 'Failed'
            $r.Message | Should -Match '0x80092004'
        }
    }

    Context 'pending' {
        BeforeEach {
            Mock Invoke-APKICertreq -ModuleName AutomaticPKI -ParameterFilter { $Arguments[0] -eq '-submit' } {
                [pscustomobject]@{ ExitCode = 0; Output = [string[]]@(
                        'RequestId: 43'
                        'RequestId: "43"'
                        'Certificate request is pending: Taken Under Submission (0)'
                    ) }
            }
        }

        It 'returns Pending with the request id, does not accept, and logs event 1002' {
            $r = Invoke-Request -Order (New-AdcsRpcTestOrder)
            $r.Status | Should -Be 'Pending'
            $r.RequestId | Should -Be '43'
            $r.Thumbprint | Should -BeNullOrEmpty
            Should -Invoke Invoke-APKICertreq -ModuleName AutomaticPKI -Times 0 -Exactly -ParameterFilter { $Arguments[0] -eq '-accept' }
            Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter { $EventId -eq 1002 -and $OrderId -eq 'www-contoso-com' }
            @(Get-TempLeftovers).Count | Should -Be 0
        }
    }

    Context 'denied' {
        It 'returns Denied with the CA reason and logs event 3001' {
            Mock Invoke-APKICertreq -ModuleName AutomaticPKI -ParameterFilter { $Arguments[0] -eq '-submit' } {
                [pscustomobject]@{ ExitCode = -2146875391; Output = [string[]]@(
                        'RequestId: 44'
                        'RequestId: "44"'
                        'Certificate not issued (Denied) Denied by Policy Module  0x80094801, The request does not contain a certificate template extension or the CertificateTemplate request attribute.'
                        'The request does not contain a certificate template extension or the CertificateTemplate request attribute. 0x80094801 (-2146875391 CERTSRV_E_NO_CERT_TYPE)'
                        'Denied by Policy Module  0x80094801, The request does not contain a certificate template extension or the CertificateTemplate request attribute.'
                    ) }
            }
            $r = Invoke-Request -Order (New-AdcsRpcTestOrder)
            $r.Status | Should -Be 'Denied'
            $r.RequestId | Should -Be '44'
            $r.Message | Should -Match 'CERTSRV_E_NO_CERT_TYPE'
            Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter { $EventId -eq 3001 -and $Level -eq 'Error' }
            Should -Invoke Invoke-APKICertreq -ModuleName AutomaticPKI -Times 0 -Exactly -ParameterFilter { $Arguments[0] -eq '-accept' }
        }
    }

    Context 'CA offline' {
        It 'returns Failed with the RPC error and logs event 3000' {
            Mock Invoke-APKICertreq -ModuleName AutomaticPKI -ParameterFilter { $Arguments[0] -eq '-submit' } {
                [pscustomobject]@{ ExitCode = -2147023174; Output = [string[]]@(
                        'Certificate Request Processor: The RPC server is unavailable. 0x800706ba (WIN32: 1722 RPC_S_SERVER_UNAVAILABLE)'
                        'ca01.corp.local\Corp Issuing CA'
                    ) }
            }
            $r = Invoke-Request -Order (New-AdcsRpcTestOrder)
            $r.Status | Should -Be 'Failed'
            $r.Message | Should -Match '0x800706ba'
            $r.Message | Should -Match 'unavailable'
            Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter { $EventId -eq 3000 }
            @(Get-TempLeftovers).Count | Should -Be 0
        }
    }

    Context 'malformed output' {
        It 'returns Failed when certreq -submit output is unrecognisable' {
            Mock Invoke-APKICertreq -ModuleName AutomaticPKI -ParameterFilter { $Arguments[0] -eq '-submit' } {
                [pscustomobject]@{ ExitCode = 0; Output = [string[]]@('Lorem ipsum dolor sit amet', '%%%%') }
            }
            $r = Invoke-Request -Order (New-AdcsRpcTestOrder)
            $r.Status | Should -Be 'Failed'
            $r.Message | Should -Match 'Unrecognised'
            Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter { $EventId -eq 3000 }
        }

        It 'returns Failed when the CA says issued but no certificate file was written' {
            Mock Invoke-APKICertreq -ModuleName AutomaticPKI -ParameterFilter { $Arguments[0] -eq '-submit' } {
                [pscustomobject]@{ ExitCode = 0; Output = [string[]]@('RequestId: 42', 'RequestId: "42"', 'Certificate retrieved(Issued) Issued') }
            }
            $r = Invoke-Request -Order (New-AdcsRpcTestOrder)
            $r.Status | Should -Be 'Failed'
            Should -Invoke Invoke-APKICertreq -ModuleName AutomaticPKI -Times 0 -Exactly -ParameterFilter { $Arguments[0] -eq '-accept' }
        }
    }

    Context 'local failures' {
        It 'returns Failed and does not submit when certreq -new fails' {
            Mock Invoke-APKICertreq -ModuleName AutomaticPKI -ParameterFilter { $Arguments[0] -eq '-new' } {
                [pscustomobject]@{ ExitCode = -2146893802; Output = [string[]]@('Certificate Request Processor: Keyset does not exist 0x80090016 (-2146893802 NTE_BAD_KEYSET)') }
            }
            Mock Invoke-APKICertreq -ModuleName AutomaticPKI -ParameterFilter { $Arguments[0] -eq '-submit' } {
                throw 'submit must not be called'
            }
            $r = Invoke-Request -Order (New-AdcsRpcTestOrder)
            $r.Status | Should -Be 'Failed'
            $r.Message | Should -Match 'NTE_BAD_KEYSET'
            Should -Invoke Invoke-APKICertreq -ModuleName AutomaticPKI -Times 0 -Exactly -ParameterFilter { $Arguments[0] -eq '-submit' }
            @(Get-TempLeftovers).Count | Should -Be 0
        }

        It 'returns Failed with event 3004 and calls no certreq when CAConfig is missing' {
            $r = Invoke-Request -Order (New-AdcsRpcTestOrder -CAConfig $null)
            $r.Status | Should -Be 'Failed'
            Should -Invoke Invoke-APKICertreq -ModuleName AutomaticPKI -Times 0 -Exactly
            Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter { $EventId -eq 3004 }
        }

        It 'does nothing under -WhatIf' {
            $r = Invoke-Request -Order (New-AdcsRpcTestOrder) -DryRun
            $r | Should -BeNullOrEmpty
            Should -Invoke Invoke-APKICertreq -ModuleName AutomaticPKI -Times 0 -Exactly
        }
    }
}
