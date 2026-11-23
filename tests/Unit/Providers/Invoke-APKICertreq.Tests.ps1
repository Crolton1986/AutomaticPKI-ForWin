BeforeAll {
    $env:APKI_ROOT = $TestDrive
    Import-Module (Join-Path $PSScriptRoot '../../../src/AutomaticPKI/AutomaticPKI.psd1') -Force
}

Describe 'Invoke-APKICertreq' {
    # On Windows certreq.exe exists and would really run, so only check the no-certreq path elsewhere.
    It 'returns ExitCode -1 and a message instead of throwing when certreq.exe is missing' -Skip:([bool](Get-Command certreq.exe -ErrorAction SilentlyContinue)) {
        $r = InModuleScope AutomaticPKI { Invoke-APKICertreq -Arguments @('-new', 'x.inf', 'x.req') }
        $r.ExitCode | Should -Be -1
        ($r.Output -join ' ') | Should -Match 'certreq.exe could not be started'
    }
}
