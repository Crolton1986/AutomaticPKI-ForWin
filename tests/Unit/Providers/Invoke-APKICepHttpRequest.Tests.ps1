BeforeAll {
    . (Join-Path $PSScriptRoot 'AdcsCep.TestHelpers.ps1')
    $env:APKI_ROOT = $TestDrive
    Import-AdcsCepTestModule

    function Invoke-TestHttp {
        InModuleScope AutomaticPKI {
            Invoke-APKICepHttpRequest -Uri 'https://cep.corp.local/CEP'
        }
    }
}

AfterAll {
    Remove-Module AutomaticPKI -Force -ErrorAction SilentlyContinue
}

Describe 'Invoke-APKICepHttpRequest' {
    It 'returns the status code of a successful response' {
        Mock -ModuleName AutomaticPKI Invoke-WebRequest { [pscustomobject]@{ StatusCode = 200 } }

        Invoke-TestHttp | Should -Be 200
        Should -Invoke Invoke-WebRequest -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter {
            $Uri -eq 'https://cep.corp.local/CEP' -and $Method -eq 'Get'
        }
    }

    It 'returns the status code carried by an HTTP error (e.g. 401) instead of throwing' {
        Mock -ModuleName AutomaticPKI Invoke-WebRequest {
            $exception = New-Object System.Exception -ArgumentList 'Response status code does not indicate success: 401 (Unauthorized).'
            $exception | Add-Member -MemberType NoteProperty -Name Response -Value ([pscustomobject]@{ StatusCode = 401 })
            throw $exception
        }

        Invoke-TestHttp | Should -Be 401
    }

    It 'rethrows errors that have no HTTP response' {
        Mock -ModuleName AutomaticPKI Invoke-WebRequest { throw 'No such host is known.' }

        { Invoke-TestHttp } | Should -Throw '*No such host*'
    }
}
