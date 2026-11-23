BeforeAll {
    . (Join-Path $PSScriptRoot 'AdcsCep.TestHelpers.ps1')
    $env:APKI_ROOT = $TestDrive
    Import-AdcsCepTestModule

    $script:IssuedThumb = 'A1B2C3D4E5F60718293A4B5C6D7E8F9012345678'
    $script:RequestThumb = 'F0E1D2C3B4A5968778695A4B3C2D1E0F12345678'

    function Invoke-TestRequest {
        param([Parameter(Mandatory)] $Order, [switch]$DryRun)
        InModuleScope AutomaticPKI -Parameters @{ Order = $Order; DryRun = [bool]$DryRun } {
            param($Order, $DryRun)
            Request-APKIAdcsCepCertificate -Order $Order -WhatIf:$DryRun
        }
    }
}

AfterAll {
    Remove-Module AutomaticPKI -Force -ErrorAction SilentlyContinue
}

Describe 'Request-APKIAdcsCepCertificate' {
    BeforeEach {
        Mock -ModuleName AutomaticPKI Write-APKILog { }
        Mock -ModuleName AutomaticPKI Get-APKISecret { Get-AdcsCepTestCredential }
        Mock -ModuleName AutomaticPKI Get-APKIAdcsCepKeyInfo { [pscustomobject]@{ Algorithm = 'RSA'; Length = 2048 } }
        Mock -ModuleName AutomaticPKI Invoke-APKIGetCertificate {
            Get-AdcsCepTestEnrollmentResult -Status 'Issued' -CertificateThumbprint $script:IssuedThumb
        }
    }

    Context 'issued' {
        It 'returns Issued with the certificate thumbprint' {
            $result = Invoke-TestRequest -Order (Get-AdcsCepTestOrder)

            $result.Status | Should -Be 'Issued'
            $result.Thumbprint | Should -Be $script:IssuedThumb
            $result.RequestId | Should -BeNullOrEmpty
            $result.Message | Should -Not -BeNullOrEmpty
        }

        It 'passes template, URL, SANs, subject and the machine My store to Get-Certificate' {
            $null = Invoke-TestRequest -Order (Get-AdcsCepTestOrder)

            Should -Invoke Invoke-APKIGetCertificate -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter {
                $Template -eq 'WebServer' -and
                $Url -eq 'https://cep.corp.local/ADPolicyProvider_CEP_Kerberos/service.svc/CEP' -and
                ($DnsName -join ',') -eq 'www.contoso.com,contoso.com' -and
                $SubjectName -eq 'CN=www.contoso.com' -and
                $CertStoreLocation -eq 'Cert:\LocalMachine\My'
            }
        }

        It 'uses Kerberos (no credential) when CredentialRef is null' {
            $null = Invoke-TestRequest -Order (Get-AdcsCepTestOrder)

            Should -Invoke Get-APKISecret -ModuleName AutomaticPKI -Times 0 -Exactly
            Should -Invoke Invoke-APKIGetCertificate -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter { $null -eq $Credential }
        }

        It 'loads CredentialRef through Get-APKISecret and passes the credential' {
            $null = Invoke-TestRequest -Order (Get-AdcsCepTestOrder -CredentialRef 'cep-svc')

            Should -Invoke Get-APKISecret -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter { $Name -eq 'cep-svc' }
            Should -Invoke Invoke-APKIGetCertificate -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter {
                $null -ne $Credential -and $Credential.UserName -eq 'CORP\svc-cep'
            }
        }

        It 'accepts ProviderSettings as a hashtable' {
            $order = Get-AdcsCepTestOrder
            $order.ProviderSettings = @{ CepUrl = 'https://cep2.corp.local/CEP'; Template = 'WebServer2'; CredentialRef = $null }

            $result = Invoke-TestRequest -Order $order

            $result.Status | Should -Be 'Issued'
            Should -Invoke Invoke-APKIGetCertificate -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter {
                $Url -eq 'https://cep2.corp.local/CEP' -and $Template -eq 'WebServer2'
            }
        }

        It 'does not warn when the issued key matches Order.Key' {
            $null = Invoke-TestRequest -Order (Get-AdcsCepTestOrder)

            Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 0 -Exactly -ParameterFilter { $Level -eq 'Warning' }
        }

        It 'warns when the template produced a different key than Order.Key' {
            Mock -ModuleName AutomaticPKI Get-APKIAdcsCepKeyInfo { [pscustomobject]@{ Algorithm = 'RSA'; Length = 4096 } }

            $result = Invoke-TestRequest -Order (Get-AdcsCepTestOrder)

            $result.Status | Should -Be 'Issued'
            Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter {
                $Level -eq 'Warning' -and $Message -like '*RSA 4096*RSA 2048*template*'
            }
        }
    }

    Context 'pending' {
        It 'returns Pending with the request-store thumbprint as RequestId and logs event 1002' {
            Mock -ModuleName AutomaticPKI Invoke-APKIGetCertificate {
                Get-AdcsCepTestEnrollmentResult -Status 'Pending' -RequestThumbprint $script:RequestThumb.ToLowerInvariant()
            }

            $result = Invoke-TestRequest -Order (Get-AdcsCepTestOrder)

            $result.Status | Should -Be 'Pending'
            $result.RequestId | Should -BeExactly $script:RequestThumb
            $result.Thumbprint | Should -BeNullOrEmpty
            Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter {
                $EventId -eq 1002 -and $OrderId -eq 'contoso-web'
            }
        }

        It 'fails when Pending comes back without a request object' {
            Mock -ModuleName AutomaticPKI Invoke-APKIGetCertificate { Get-AdcsCepTestEnrollmentResult -Status 'Pending' }

            $result = Invoke-TestRequest -Order (Get-AdcsCepTestOrder)

            $result.Status | Should -Be 'Failed'
            Should -Invoke Write-APKILog -ModuleName AutomaticPKI -ParameterFilter { $EventId -eq 3000 }
        }
    }

    Context 'denied and failed results' {
        It 'maps EnrollmentResult status Denied to Denied with event 3001' {
            Mock -ModuleName AutomaticPKI Invoke-APKIGetCertificate { Get-AdcsCepTestEnrollmentResult -Status 'Denied' }

            $result = Invoke-TestRequest -Order (Get-AdcsCepTestOrder)

            $result.Status | Should -Be 'Denied'
            Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter { $EventId -eq 3001 -and $Level -eq 'Error' }
        }

        It 'maps a policy-module denial error to Denied with event 3001' {
            Mock -ModuleName AutomaticPKI Invoke-APKIGetCertificate {
                throw 'CertEnroll::CX509Enrollment::Enroll: Denied by Policy Module 0x80094012 (-2146877422 CERTSRV_E_TEMPLATE_DENIED)'
            }

            $result = Invoke-TestRequest -Order (Get-AdcsCepTestOrder)

            $result.Status | Should -Be 'Denied'
            $result.Message | Should -BeLike '*denied*WebServer*'
            Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter { $EventId -eq 3001 }
        }

        It 'reports a missing template as Failed with event 3000' {
            Mock -ModuleName AutomaticPKI Invoke-APKIGetCertificate {
                throw 'CertEnroll::CX509Enrollment::Enroll: The requested certificate template is not supported by this CA. 0x80094800 (-2146875392 CERTSRV_E_UNSUPPORTED_CERT_TYPE)'
            }

            $result = Invoke-TestRequest -Order (Get-AdcsCepTestOrder)

            $result.Status | Should -Be 'Failed'
            $result.Message | Should -BeLike "*Template 'WebServer' was not found*"
            Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter { $EventId -eq 3000 }
        }

        It 'reports an authentication failure as Failed' {
            Mock -ModuleName AutomaticPKI Invoke-APKIGetCertificate { throw 'Access is denied. 0x80070005 (WIN32: 5 ERROR_ACCESS_DENIED)' }

            $result = Invoke-TestRequest -Order (Get-AdcsCepTestOrder -CredentialRef 'cep-svc')

            $result.Status | Should -Be 'Failed'
            $result.Message | Should -BeLike "*Authentication*failed*cep-svc*"
        }

        It 'reports an unreachable endpoint as Failed' {
            Mock -ModuleName AutomaticPKI Invoke-APKIGetCertificate { throw 'The server name or address could not be resolved 0x80072ee7 (WinHttp: 12007 ERROR_WINHTTP_NAME_NOT_RESOLVED)' }

            $result = Invoke-TestRequest -Order (Get-AdcsCepTestOrder)

            $result.Status | Should -Be 'Failed'
            $result.Message | Should -BeLike '*unreachable*'
            Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter { $EventId -eq 3000 }
        }

        It 'maps an unknown status to Failed' {
            Mock -ModuleName AutomaticPKI Invoke-APKIGetCertificate { Get-AdcsCepTestEnrollmentResult -Status 'Unknown' }

            (Invoke-TestRequest -Order (Get-AdcsCepTestOrder)).Status | Should -Be 'Failed'
        }
    }

    Context 'invalid configuration' {
        It 'fails with event 3004 and does not call Get-Certificate when <Case>' -TestCases @(
            @{ Case = 'CepUrl is empty'; CepUrl = ''; Template = 'WebServer'; Hostnames = @('www.contoso.com'); Expected = '*CepUrl*' }
            @{ Case = 'CepUrl is http'; CepUrl = 'http://cep.corp.local/CEP'; Template = 'WebServer'; Hostnames = @('www.contoso.com'); Expected = '*https*' }
            @{ Case = 'CepUrl is relative'; CepUrl = 'cep/service.svc'; Template = 'WebServer'; Hostnames = @('www.contoso.com'); Expected = '*absolute*' }
            @{ Case = 'Template is empty'; CepUrl = 'https://cep.corp.local/CEP'; Template = ''; Hostnames = @('www.contoso.com'); Expected = '*Template*' }
            @{ Case = 'Hostnames is empty'; CepUrl = 'https://cep.corp.local/CEP'; Template = 'WebServer'; Hostnames = @(); Expected = '*Hostnames*' }
        ) {
            $order = Get-AdcsCepTestOrder -CepUrl $CepUrl -Template $Template -Hostnames $Hostnames

            $result = Invoke-TestRequest -Order $order

            $result.Status | Should -Be 'Failed'
            $result.Message | Should -BeLike $Expected
            Should -Invoke Invoke-APKIGetCertificate -ModuleName AutomaticPKI -Times 0 -Exactly
            Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter { $EventId -eq 3004 }
        }

        It 'fails with event 3004 when the credential secret cannot be loaded' {
            Mock -ModuleName AutomaticPKI Get-APKISecret { throw "Secret 'missing' not found." }

            $result = Invoke-TestRequest -Order (Get-AdcsCepTestOrder -CredentialRef 'missing')

            $result.Status | Should -Be 'Failed'
            $result.Message | Should -BeLike "*credential 'missing'*"
            Should -Invoke Invoke-APKIGetCertificate -ModuleName AutomaticPKI -Times 0 -Exactly
            Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter { $EventId -eq 3004 }
        }

        It 'fails when the secret is not a PSCredential' {
            Mock -ModuleName AutomaticPKI Get-APKISecret { 'plain string' }

            $result = Invoke-TestRequest -Order (Get-AdcsCepTestOrder -CredentialRef 'wrongtype')

            $result.Status | Should -Be 'Failed'
            $result.Message | Should -BeLike '*PSCredential*'
        }
    }

    Context 'WhatIf' {
        It 'does not submit a request and returns nothing' {
            $result = Invoke-TestRequest -Order (Get-AdcsCepTestOrder) -DryRun

            $result | Should -BeNullOrEmpty
            Should -Invoke Invoke-APKIGetCertificate -ModuleName AutomaticPKI -Times 0 -Exactly
        }
    }
}
