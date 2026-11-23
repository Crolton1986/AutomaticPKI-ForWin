BeforeAll {
    . (Join-Path $PSScriptRoot 'AdcsCep.TestHelpers.ps1')
    $env:APKI_ROOT = $TestDrive
    Import-AdcsCepTestModule

    function Get-TestErrorInfo {
        param([Parameter(Mandatory)] [System.Exception]$Exception, [string]$CredentialRef)
        $record = New-Object System.Management.Automation.ErrorRecord -ArgumentList $Exception, 'GetCertificate', ([System.Management.Automation.ErrorCategory]::NotSpecified), $null
        $setting = [pscustomobject]@{
            OrderId       = 'contoso-web'
            CepUrl        = 'https://cep.corp.local/CEP'
            Template      = 'WebServer'
            CredentialRef = $CredentialRef
        }
        InModuleScope AutomaticPKI -Parameters @{ Record = $record; Setting = $setting } {
            param($Record, $Setting)
            Get-APKIAdcsCepErrorInfo -ErrorRecord $Record -Setting $Setting
        }
    }
}

AfterAll {
    Remove-Module AutomaticPKI -Force -ErrorAction SilentlyContinue
}

Describe 'Get-APKIAdcsCepErrorInfo' {
    It 'classifies "<Text>" as <Category>' -TestCases @(
        @{ Text = 'CertEnroll::CX509Enrollment::Enroll: Denied by Policy Module 0x80094012 (-2146877422 CERTSRV_E_TEMPLATE_DENIED)'; Category = 'Denied' }
        @{ Text = 'The request was denied by a certificate manager or the CA.'; Category = 'Denied' }
        @{ Text = 'The requested certificate template is not supported by this CA. 0x80094800 (-2146875392 CERTSRV_E_UNSUPPORTED_CERT_TYPE)'; Category = 'TemplateNotFound' }
        @{ Text = "The certificate template 'Foo' could not be found."; Category = 'TemplateNotFound' }
        @{ Text = 'Access is denied. 0x80070005 (WIN32: 5 ERROR_ACCESS_DENIED)'; Category = 'AuthFailed' }
        @{ Text = 'The remote endpoint requires Negotiate authentication. 0x803d001f'; Category = 'AuthFailed' }
        @{ Text = 'The logon attempt failed 0x8009030c (-2146893044 SEC_E_LOGON_DENIED)'; Category = 'AuthFailed' }
        @{ Text = 'The server name or address could not be resolved 0x80072ee7 (WinHttp: 12007 ERROR_WINHTTP_NAME_NOT_RESOLVED)'; Category = 'Unreachable' }
        @{ Text = 'There was an error communicating with the endpoint at https://cep/. 0x803d0010 (-2143485936 WS_E_ENDPOINT_UNREACHABLE)'; Category = 'Unreachable' }
        @{ Text = 'The operation timed out 0x80072ee2'; Category = 'Unreachable' }
        @{ Text = 'Something unexpected happened.'; Category = 'Other' }
    ) {
        $info = Get-TestErrorInfo -Exception (New-Object System.Exception -ArgumentList $Text)

        $info.Category | Should -Be $Category
        if ($Category -eq 'Denied') {
            $info.Status | Should -Be 'Denied'
            $info.EventId | Should -Be 3001
        }
        else {
            $info.Status | Should -Be 'Failed'
            $info.EventId | Should -Be 3000
        }
        $info.Message | Should -BeLike "AdcsCep: *$Text"
    }

    It 'classifies by the HResult of the exception when the text has no code' {
        $exception = New-Object System.Runtime.InteropServices.COMException -ArgumentList 'CertEnroll::CX509Enrollment::Enroll', -2146875392

        (Get-TestErrorInfo -Exception $exception).Category | Should -Be 'TemplateNotFound'
    }

    It 'looks at inner exceptions' {
        $inner = New-Object System.Runtime.InteropServices.COMException -ArgumentList 'inner', -2147012889
        $outer = New-Object System.InvalidOperationException -ArgumentList 'Enrollment failed.', $inner

        (Get-TestErrorInfo -Exception $outer).Category | Should -Be 'Unreachable'
    }

    It 'names the credential in authentication failures' {
        $info = Get-TestErrorInfo -Exception (New-Object System.Exception -ArgumentList 'Access is denied.') -CredentialRef 'cep-svc'

        $info.Message | Should -BeLike "*credential 'cep-svc'*"
    }

    It 'names Kerberos in authentication failures without CredentialRef' {
        $info = Get-TestErrorInfo -Exception (New-Object System.Exception -ArgumentList 'Access is denied.')

        $info.Message | Should -BeLike '*Kerberos*'
    }
}
