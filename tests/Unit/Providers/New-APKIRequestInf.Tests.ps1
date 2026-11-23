BeforeAll {
    $env:APKI_ROOT = $TestDrive
    Import-Module (Join-Path $PSScriptRoot '../../../src/AutomaticPKI/AutomaticPKI.psd1') -Force

    function New-TestOrder {
        param(
            [string[]]$Hostnames = @('www.contoso.com', 'contoso.com'),
            [string]$Algorithm = 'RSA',
            [int]$Length = 2048,
            [bool]$Exportable = $false,
            [AllowNull()][string]$Template = 'WebServer'
        )
        [pscustomobject]@{
            Id               = 'www-contoso-com'
            Hostnames        = $Hostnames
            Provider         = 'AdcsRpc'
            ProviderSettings = [pscustomobject]@{ CAConfig = 'ca01.corp.local\Corp Issuing CA'; Template = $Template }
            Key              = [pscustomobject]@{ Algorithm = $Algorithm; Length = $Length; Exportable = $Exportable }
        }
    }

    function Join-InfLines {
        param([string[]]$Lines)
        ($Lines -join "`r`n") + "`r`n"
    }
}

Describe 'New-APKIRequestInf' {
    It 'builds the exact RSA INF with SANs, server-auth EKU and template' {
        $order = New-TestOrder
        $expected = Join-InfLines @(
            '[Version]'
            'Signature="$Windows NT$"'
            ''
            '[NewRequest]'
            'Subject = "CN=www.contoso.com"'
            'KeyAlgorithm = RSA'
            'KeyLength = 2048'
            'ProviderName = "Microsoft RSA SChannel Cryptographic Provider"'
            'ProviderType = 12'
            'KeySpec = 1'
            'KeyUsage = 0xa0'
            'MachineKeySet = TRUE'
            'Exportable = FALSE'
            'RequestType = PKCS10'
            'HashAlgorithm = sha256'
            'SMIME = FALSE'
            'Silent = TRUE'
            'UseExistingKeySet = FALSE'
            'FriendlyName = "AutomaticPKI www-contoso-com"'
            ''
            '[Extensions]'
            '2.5.29.17 = "{text}"'
            '_continue_ = "dns=www.contoso.com&"'
            '_continue_ = "dns=contoso.com"'
            '2.5.29.37 = "{text}1.3.6.1.5.5.7.3.1"'
            ''
            '[RequestAttributes]'
            'CertificateTemplate = "WebServer"'
        )

        $actual = InModuleScope AutomaticPKI -Parameters @{ Order = $order } {
            param($Order)
            New-APKIRequestInf -Order $Order
        }

        $actual | Should -BeExactly $expected
    }

    It 'builds the exact ECDSA_P256 INF with the software KSP and no KeySpec' {
        $order = New-TestOrder -Algorithm 'ECDSA_P256' -Length 256 -Hostnames @('app.contoso.com')
        $expected = Join-InfLines @(
            '[Version]'
            'Signature="$Windows NT$"'
            ''
            '[NewRequest]'
            'Subject = "CN=app.contoso.com"'
            'KeyAlgorithm = ECDSA_P256'
            'KeyLength = 256'
            'ProviderName = "Microsoft Software Key Storage Provider"'
            'KeyUsage = 0x80'
            'MachineKeySet = TRUE'
            'Exportable = FALSE'
            'RequestType = PKCS10'
            'HashAlgorithm = sha256'
            'SMIME = FALSE'
            'Silent = TRUE'
            'UseExistingKeySet = FALSE'
            'FriendlyName = "AutomaticPKI www-contoso-com"'
            ''
            '[Extensions]'
            '2.5.29.17 = "{text}"'
            '_continue_ = "dns=app.contoso.com"'
            '2.5.29.37 = "{text}1.3.6.1.5.5.7.3.1"'
            ''
            '[RequestAttributes]'
            'CertificateTemplate = "WebServer"'
        )

        $actual = InModuleScope AutomaticPKI -Parameters @{ Order = $order } {
            param($Order)
            New-APKIRequestInf -Order $Order
        }

        $actual | Should -BeExactly $expected
    }

    It 'sets Exportable = TRUE when the order key is exportable' {
        $order = New-TestOrder -Exportable $true
        $inf = InModuleScope AutomaticPKI -Parameters @{ Order = $order } { param($Order) New-APKIRequestInf -Order $Order }
        $lines = $inf -split "`r`n"
        $lines | Should -Contain 'Exportable = TRUE'
        $lines | Should -Not -Contain 'Exportable = FALSE'
    }

    It 'omits [RequestAttributes] when no template is set (standalone CA)' {
        $order = New-TestOrder -Template $null
        $inf = InModuleScope AutomaticPKI -Parameters @{ Order = $order } { param($Order) New-APKIRequestInf -Order $Order }
        $inf | Should -Not -Match 'RequestAttributes'
        $inf | Should -Not -Match 'CertificateTemplate'
    }

    It 'honours a larger RSA key length' {
        $order = New-TestOrder -Length 4096
        $inf = InModuleScope AutomaticPKI -Parameters @{ Order = $order } { param($Order) New-APKIRequestInf -Order $Order }
        ($inf -split "`r`n") | Should -Contain 'KeyLength = 4096'
    }

    It 'lists every hostname as a dns= SAN, deduplicated, with & between entries only' {
        $order = New-TestOrder -Hostnames @('a.contoso.com', 'b.contoso.com', 'A.contoso.com', '*.c.contoso.com')
        $inf = InModuleScope AutomaticPKI -Parameters @{ Order = $order } { param($Order) New-APKIRequestInf -Order $Order }
        $san = @(($inf -split "`r`n") | Where-Object { $_ -like '_continue_*' })
        $san | Should -Be @(
            '_continue_ = "dns=a.contoso.com&"'
            '_continue_ = "dns=b.contoso.com&"'
            '_continue_ = "dns=*.c.contoso.com"'
        )
        ($inf -split "`r`n") | Should -Contain 'Subject = "CN=a.contoso.com"'
    }

    It 'defaults to RSA 2048 non-exportable when the order has no Key' {
        $order = [pscustomobject]@{
            Id               = 'site1'
            Hostnames        = @('site1.contoso.com')
            ProviderSettings = [pscustomobject]@{ CAConfig = 'ca\CA'; Template = 'WebServer' }
        }
        $inf = InModuleScope AutomaticPKI -Parameters @{ Order = $order } { param($Order) New-APKIRequestInf -Order $Order }
        $lines = $inf -split "`r`n"
        $lines | Should -Contain 'KeyAlgorithm = RSA'
        $lines | Should -Contain 'KeyLength = 2048'
        $lines | Should -Contain 'Exportable = FALSE'
    }

    It 'rejects <Case>' -TestCases @(
        @{ Case = 'no hostnames'; Hostnames = @(); Algorithm = 'RSA'; Length = 2048 }
        @{ Case = 'a hostname with a quote'; Hostnames = @('www.contoso.com"&dns=evil.com'); Algorithm = 'RSA'; Length = 2048 }
        @{ Case = 'a hostname with a newline'; Hostnames = @("www.contoso.com`r`nExportable = TRUE"); Algorithm = 'RSA'; Length = 2048 }
        @{ Case = 'an unsupported algorithm'; Hostnames = @('www.contoso.com'); Algorithm = 'DSA'; Length = 2048 }
        @{ Case = 'a short RSA key'; Hostnames = @('www.contoso.com'); Algorithm = 'RSA'; Length = 1024 }
    ) {
        param($Case, $Hostnames, $Algorithm, $Length)
        $order = New-TestOrder -Hostnames $Hostnames -Algorithm $Algorithm -Length $Length
        { InModuleScope AutomaticPKI -Parameters @{ Order = $order } { param($Order) New-APKIRequestInf -Order $Order } } |
            Should -Throw
    }
}
