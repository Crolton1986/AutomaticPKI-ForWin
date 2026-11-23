BeforeAll {
    $script:ModuleRoot = [System.IO.Path]::Combine($PSScriptRoot, '..', '..', '..', 'src', 'AutomaticPKI')
    $script:Manifest = Join-Path $script:ModuleRoot 'AutomaticPKI.psd1'
    Import-Module $script:Manifest -Force
    $script:PublicNames = @(Get-ChildItem -Path (Join-Path $script:ModuleRoot 'Public') -Filter '*.ps1' | ForEach-Object { $_.BaseName } | Sort-Object)
}

AfterAll {
    Remove-Module AutomaticPKI -Force -ErrorAction SilentlyContinue
}

Describe 'Public surface' {
    It 'lists exactly the Public/*.ps1 file names in FunctionsToExport' {
        $exported = @((Import-PowerShellDataFile -Path $script:Manifest).FunctionsToExport | Sort-Object)
        $exported | Should -Be $script:PublicNames
    }

    It 'exports exactly those functions from the loaded module' {
        $loaded = @((Get-Module AutomaticPKI).ExportedFunctions.Keys | Sort-Object)
        $loaded | Should -Be $script:PublicNames
    }

    It 'defines each public function in its own file with comment-based help and an example' {
        foreach ($name in $script:PublicNames) {
            $help = Get-Help -Name $name -Full
            $help.Synopsis | Should -Not -BeNullOrEmpty -Because "$name needs .SYNOPSIS"
            $help.Synopsis | Should -Not -Match "^\s*$name\s*\[" -Because "$name needs comment-based help, not generated syntax"
            @($help.Examples.Example).Count | Should -BeGreaterThan 0 -Because "$name needs an .EXAMPLE"
        }
    }
}
