BeforeDiscovery {
    # CertificateRequest exists on .NET Core / .NET Framework 4.7.2+; skip real-certificate cases without it.
    $script:CanCreateCert = $null -ne ('System.Security.Cryptography.X509Certificates.CertificateRequest' -as [type])
}

BeforeAll {
    . (Join-Path $PSScriptRoot 'AdcsCep.TestHelpers.ps1')
    $env:APKI_ROOT = $TestDrive
    Import-AdcsCepTestModule

    function Get-TestKeyInfo {
        param([AllowNull()] $Certificate)
        InModuleScope AutomaticPKI -Parameters @{ Certificate = $Certificate } {
            param($Certificate)
            Get-APKIAdcsCepKeyInfo -Certificate $Certificate
        }
    }
}

AfterAll {
    Remove-Module AutomaticPKI -Force -ErrorAction SilentlyContinue
}

Describe 'Get-APKIAdcsCepKeyInfo' {
    It 'returns $null for objects that are not X509Certificate2' {
        Get-TestKeyInfo -Certificate ([pscustomobject]@{ Thumbprint = 'AB' }) | Should -BeNullOrEmpty
        Get-TestKeyInfo -Certificate $null | Should -BeNullOrEmpty
    }

    It 'reports RSA key size' -Skip:(-not $script:CanCreateCert) {
        $rsa = [System.Security.Cryptography.RSA]::Create(3072)
        $request = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest -ArgumentList 'CN=rsa.test', $rsa, ([System.Security.Cryptography.HashAlgorithmName]::SHA256), ([System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $cert = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5), [DateTimeOffset]::UtcNow.AddDays(1))

        $info = Get-TestKeyInfo -Certificate $cert

        $info.Algorithm | Should -Be 'RSA'
        $info.Length | Should -Be 3072
    }

    It 'reports ECDSA curve size as ECDSA_P256' -Skip:(-not $script:CanCreateCert) {
        $ecdsa = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
        $request = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest -ArgumentList 'CN=ec.test', $ecdsa, ([System.Security.Cryptography.HashAlgorithmName]::SHA256)
        $cert = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5), [DateTimeOffset]::UtcNow.AddDays(1))

        $info = Get-TestKeyInfo -Certificate $cert

        $info.Algorithm | Should -Be 'ECDSA_P256'
        $info.Length | Should -Be 256
    }
}
