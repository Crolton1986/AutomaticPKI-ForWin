BeforeAll {
    $script:ModulePath = Join-Path $PSScriptRoot '..\..\src\AutomaticPKI\AutomaticPKI.psd1'
}

Describe 'AutomaticPKI module' {
    It 'has a valid manifest' {
        { Test-ModuleManifest -Path $script:ModulePath -ErrorAction Stop } | Should -Not -Throw
    }

    It 'imports without errors' {
        { Import-Module $script:ModulePath -Force -ErrorAction Stop } | Should -Not -Throw
    }

    It 'requires PowerShell 5.1' {
        (Import-PowerShellDataFile $script:ModulePath).PowerShellVersion | Should -Be '5.1'
    }
}
