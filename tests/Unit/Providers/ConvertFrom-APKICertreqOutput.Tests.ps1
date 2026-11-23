BeforeAll {
    $env:APKI_ROOT = $TestDrive
    Import-Module (Join-Path $PSScriptRoot '../../../src/AutomaticPKI/AutomaticPKI.psd1') -Force
    . (Join-Path $PSScriptRoot 'CertreqFixtures.ps1')

    function Invoke-Parse {
        param([Parameter(Mandatory)][string]$Fixture)
        $f = Get-CertreqFixture -Name $Fixture
        InModuleScope AutomaticPKI -Parameters @{ Output = $f.Output; ExitCode = $f.ExitCode } {
            param($Output, $ExitCode)
            ConvertFrom-APKICertreqOutput -Output $Output -ExitCode $ExitCode
        }
    }
}

Describe 'ConvertFrom-APKICertreqOutput' {
    It 'parses <Fixture> as <Disposition>' -TestCases @(
        @{ Fixture = 'SubmitIssued'; Disposition = 'Issued'; RequestId = '42'; ErrorCode = $null }
        @{ Fixture = 'SubmitPending'; Disposition = 'Pending'; RequestId = '43'; ErrorCode = $null }
        @{ Fixture = 'SubmitDenied'; Disposition = 'Denied'; RequestId = '44'; ErrorCode = '0x80094801' }
        @{ Fixture = 'SubmitCaOffline'; Disposition = 'Unavailable'; RequestId = $null; ErrorCode = '0x800706ba' }
        @{ Fixture = 'SubmitTemplateNotOnCa'; Disposition = 'Denied'; RequestId = $null; ErrorCode = '0x80094800' }
        @{ Fixture = 'Malformed'; Disposition = 'Unknown'; RequestId = $null; ErrorCode = $null }
        @{ Fixture = 'Empty'; Disposition = 'Unknown'; RequestId = $null; ErrorCode = $null }
        @{ Fixture = 'RetrieveIssued'; Disposition = 'Issued'; RequestId = $null; ErrorCode = $null }
        @{ Fixture = 'RetrievePending'; Disposition = 'Pending'; RequestId = $null; ErrorCode = $null }
        @{ Fixture = 'RetrieveDenied'; Disposition = 'Denied'; RequestId = $null; ErrorCode = '0x80094014' }
        @{ Fixture = 'RetrieveUnknownId'; Disposition = 'Error'; RequestId = $null; ErrorCode = '0x80070057' }
        @{ Fixture = 'AcceptFailed'; Disposition = 'Error'; RequestId = $null; ErrorCode = '0x80092004' }
    ) {
        param($Fixture, $Disposition, $RequestId, $ErrorCode)
        $r = Invoke-Parse -Fixture $Fixture
        $r.Disposition | Should -Be $Disposition
        $r.RequestId | Should -Be $RequestId
        $r.ErrorCode | Should -Be $ErrorCode
        $r.Message | Should -Not -BeNullOrEmpty
    }

    It 'extracts thumbprint and serial number from -accept output' {
        $r = Invoke-Parse -Fixture 'AcceptOk'
        $r.Thumbprint | Should -BeExactly '3F2A6C1B9D8E7F6A5B4C3D2E1F0A9B8C7D6E5F4A'
        $r.SerialNumber | Should -BeExactly '4F00000012AB34CD56EF7890120000000012'
    }

    It 'returns no thumbprint when -accept output has none' {
        $r = Invoke-Parse -Fixture 'AcceptNoThumbprint'
        $r.Thumbprint | Should -BeNullOrEmpty
        $r.SerialNumber | Should -BeExactly '4F00000012AB34CD56EF7890120000000012'
    }

    It 'treats unrecognised output with a non-zero exit code as Error' {
        $r = InModuleScope AutomaticPKI {
            ConvertFrom-APKICertreqOutput -Output @('something odd happened') -ExitCode 5
        }
        $r.Disposition | Should -Be 'Error'
    }

    It 'accepts null output' {
        $r = InModuleScope AutomaticPKI { ConvertFrom-APKICertreqOutput -Output $null -ExitCode 0 }
        $r.Disposition | Should -Be 'Unknown'
        $r.Message | Should -Match 'no output'
    }
}
