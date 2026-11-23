BeforeAll {
    . (Join-Path $PSScriptRoot 'HealthTestHelpers.ps1')
    Import-APKITestModule
}

AfterAll {
    Remove-Module AutomaticPKI -Force -ErrorAction SilentlyContinue
}

Describe 'ConvertFrom-APKISanExtension' {
    It 'extracts dNSName entries and skips other GeneralName types' {
        # SEQUENCE { [2] "a.contoso.com", [7] 10.0.0.1, [2] "*.contoso.com" }
        $a = [System.Text.Encoding]::ASCII.GetBytes('a.contoso.com')
        $w = [System.Text.Encoding]::ASCII.GetBytes('*.contoso.com')
        $body = @(0x82, $a.Length) + $a + @(0x87, 4, 10, 0, 0, 1) + @(0x82, $w.Length) + $w
        $raw = [byte[]](@(0x30, $body.Count) + $body)
        $names = InModuleScope AutomaticPKI -Parameters @{ Raw = $raw } {
            param($Raw)
            ConvertFrom-APKISanExtension -RawData $Raw
        }
        $names | Should -Be @('a.contoso.com', '*.contoso.com')
    }

    It 'handles long-form DER lengths' {
        $long = ('x' * 150) + '.contoso.com'
        $n = [System.Text.Encoding]::ASCII.GetBytes($long)
        $body = @(0x82, 0x81, $n.Length) + $n
        $raw = [byte[]](@(0x30, 0x81, $body.Count) + $body)
        $names = InModuleScope AutomaticPKI -Parameters @{ Raw = $raw } {
            param($Raw)
            ConvertFrom-APKISanExtension -RawData $Raw
        }
        @($names).Count | Should -Be 1
        @($names)[0] | Should -Be $long
    }

    It 'rejects data that is not a SEQUENCE' {
        {
            InModuleScope AutomaticPKI { ConvertFrom-APKISanExtension -RawData ([byte[]](0x04, 0x00)) }
        } | Should -Throw
    }
}
