BeforeAll {
    . (Join-Path $PSScriptRoot 'HealthTestHelpers.ps1')
    Import-APKITestModule
}

AfterAll {
    Remove-Module AutomaticPKI -Force -ErrorAction SilentlyContinue
}

Describe 'Test-APKICertificatePrecheck' {
    BeforeAll {
        $env:APKI_ROOT = $TestDrive
        Mock -ModuleName AutomaticPKI Write-APKILog {}
    }

    BeforeEach {
        $script:Info = [pscustomobject]@{
            Thumbprint    = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'
            Subject       = 'CN=www.contoso.com'
            HasPrivateKey = $true
            NotBefore     = (Get-Date).AddDays(-1)
            NotAfter      = (Get-Date).AddDays(365)
            DnsNames      = @('www.contoso.com', '*.api.contoso.com')
            HasEku        = $true
            Ekus          = @('1.3.6.1.5.5.7.3.1')
        }
        $script:Chain = [pscustomobject]@{ Built = $true; Status = @(); StatusInformation = @() }
        $script:ChainModes = New-Object System.Collections.Generic.List[string]
        Mock -ModuleName AutomaticPKI Get-APKICertificateInfo { $script:Info }
        Mock -ModuleName AutomaticPKI Invoke-APKIChainBuild {
            $script:ChainModes.Add($RevocationMode)
            $script:Chain
        }
    }

    It 'passes every sub-check for a good certificate' {
        $r = InModuleScope AutomaticPKI {
            Test-APKICertificatePrecheck -Certificate ([pscustomobject]@{ Thumbprint = 'fake' }) -Hostnames 'www.contoso.com', 'v1.api.contoso.com'
        }
        $r.Count | Should -Be 6
        @($r | Where-Object { -not $_.Passed }).Count | Should -Be 0
        ($r | Select-Object -ExpandProperty Check) | Should -Be @('PrivateKey', 'ValidityPeriod', 'ServerAuthEku', 'SanCoverage', 'ChainTrust', 'RevocationStatus')
        $r[0].Target | Should -Be 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'
        ($script:ChainModes.ToArray() -join ',') | Should -Be 'Online'
    }

    It 'fails SanCoverage when a hostname is missing' {
        $r = InModuleScope AutomaticPKI {
            Test-APKICertificatePrecheck -Certificate 'fake' -Hostnames 'www.contoso.com', 'shop.contoso.com'
        }
        $san = $r | Where-Object Check -EQ 'SanCoverage'
        $san.Passed | Should -BeFalse
        $san.Detail | Should -Match 'shop\.contoso\.com'
    }

    It 'does not let a wildcard cover two labels or the bare domain' {
        $r = InModuleScope AutomaticPKI {
            Test-APKICertificatePrecheck -Certificate 'fake' -Hostnames 'a.b.api.contoso.com', 'api.contoso.com'
        }
        $san = $r | Where-Object Check -EQ 'SanCoverage'
        $san.Passed | Should -BeFalse
        $san.Detail | Should -Match 'a\.b\.api\.contoso\.com'
        $san.Detail | Should -Match 'cover: .*api\.contoso\.com'
    }

    It 'fails ValidityPeriod when expired' {
        $script:Info.NotBefore = (Get-Date).AddDays(-400)
        $script:Info.NotAfter = (Get-Date).AddDays(-1)
        $r = InModuleScope AutomaticPKI { Test-APKICertificatePrecheck -Certificate 'fake' -Hostnames 'www.contoso.com' }
        ($r | Where-Object Check -EQ 'ValidityPeriod').Passed | Should -BeFalse
        ($r | Where-Object Check -EQ 'ValidityPeriod').Detail | Should -Match 'Expired'
    }

    It 'fails ValidityPeriod when not yet valid' {
        $script:Info.NotBefore = (Get-Date).AddDays(2)
        $r = InModuleScope AutomaticPKI { Test-APKICertificatePrecheck -Certificate 'fake' -Hostnames 'www.contoso.com' }
        ($r | Where-Object Check -EQ 'ValidityPeriod').Detail | Should -Match 'Not yet valid'
    }

    It 'fails PrivateKey when the key is absent' {
        $script:Info.HasPrivateKey = $false
        $r = InModuleScope AutomaticPKI { Test-APKICertificatePrecheck -Certificate 'fake' -Hostnames 'www.contoso.com' }
        ($r | Where-Object Check -EQ 'PrivateKey').Passed | Should -BeFalse
    }

    It 'fails ServerAuthEku when EKU lacks Server Authentication' {
        $script:Info.Ekus = @('1.3.6.1.5.5.7.3.2')
        $r = InModuleScope AutomaticPKI { Test-APKICertificatePrecheck -Certificate 'fake' -Hostnames 'www.contoso.com' }
        ($r | Where-Object Check -EQ 'ServerAuthEku').Passed | Should -BeFalse
    }

    It 'passes ServerAuthEku when the certificate has no EKU extension' {
        $script:Info.HasEku = $false
        $script:Info.Ekus = @()
        $r = InModuleScope AutomaticPKI { Test-APKICertificatePrecheck -Certificate 'fake' -Hostnames 'www.contoso.com' }
        ($r | Where-Object Check -EQ 'ServerAuthEku').Passed | Should -BeTrue
    }

    It 'fails ChainTrust on an untrusted root' {
        $script:Chain = [pscustomobject]@{ Built = $false; Status = @('UntrustedRoot'); StatusInformation = @('root not trusted') }
        $r = InModuleScope AutomaticPKI { Test-APKICertificatePrecheck -Certificate 'fake' -Hostnames 'www.contoso.com' }
        ($r | Where-Object Check -EQ 'ChainTrust').Passed | Should -BeFalse
        ($r | Where-Object Check -EQ 'RevocationStatus').Passed | Should -BeTrue
    }

    It 'fails RevocationStatus when revocation is unknown (Strict, default)' {
        $script:Chain = [pscustomobject]@{ Built = $false; Status = @('RevocationStatusUnknown', 'OfflineRevocation'); StatusInformation = @() }
        $r = InModuleScope AutomaticPKI { Test-APKICertificatePrecheck -Certificate 'fake' -Hostnames 'www.contoso.com' }
        ($r | Where-Object Check -EQ 'ChainTrust').Passed | Should -BeTrue
        $rev = $r | Where-Object Check -EQ 'RevocationStatus'
        $rev.Passed | Should -BeFalse
        $rev.Detail | Should -Match 'RevocationStatusUnknown'
    }

    It 'accepts unknown revocation with a warning under Lenient' {
        $script:Chain = [pscustomobject]@{ Built = $false; Status = @('RevocationStatusUnknown'); StatusInformation = @() }
        $r = InModuleScope AutomaticPKI { Test-APKICertificatePrecheck -Certificate 'fake' -Hostnames 'www.contoso.com' -RevocationPolicy Lenient }
        $rev = $r | Where-Object Check -EQ 'RevocationStatus'
        $rev.Passed | Should -BeTrue
        $rev.Detail | Should -Match 'WARNING'
    }

    It 'still fails a revoked certificate under Lenient' {
        $script:Chain = [pscustomobject]@{ Built = $false; Status = @('Revoked'); StatusInformation = @() }
        $r = InModuleScope AutomaticPKI { Test-APKICertificatePrecheck -Certificate 'fake' -Hostnames 'www.contoso.com' -RevocationPolicy Lenient }
        ($r | Where-Object Check -EQ 'RevocationStatus').Passed | Should -BeFalse
    }

    It 'builds the chain with NoCheck under Skip' {
        $r = InModuleScope AutomaticPKI { Test-APKICertificatePrecheck -Certificate 'fake' -Hostnames 'www.contoso.com' -RevocationPolicy Skip }
        ($r | Where-Object Check -EQ 'RevocationStatus').Passed | Should -BeTrue
        ($script:ChainModes.ToArray() -join ',') | Should -Be 'NoCheck'
    }

    It 'fails ChainTrust and RevocationStatus when chain building throws' {
        Mock -ModuleName AutomaticPKI Invoke-APKIChainBuild { throw 'CRYPT_E_NOT_FOUND' }
        $r = InModuleScope AutomaticPKI { Test-APKICertificatePrecheck -Certificate 'fake' -Hostnames 'www.contoso.com' }
        ($r | Where-Object Check -EQ 'ChainTrust').Passed | Should -BeFalse
        ($r | Where-Object Check -EQ 'RevocationStatus').Passed | Should -BeFalse
    }
}
