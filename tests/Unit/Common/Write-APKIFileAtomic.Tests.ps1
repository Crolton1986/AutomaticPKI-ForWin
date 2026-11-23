BeforeAll {
    $script:ModulePath = Join-Path $PSScriptRoot '../../../src/AutomaticPKI/AutomaticPKI.psd1'
    Import-Module $script:ModulePath -Force
}

Describe 'Write-APKIFileAtomic' {
    BeforeEach {
        $script:Dir = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $script:Target = Join-Path $script:Dir 'sub/data.json'
    }

    It 'creates the directory and writes the content' {
        InModuleScope AutomaticPKI -Parameters @{ Target = $script:Target } {
            param($Target)
            Write-APKIFileAtomic -Path $Target -Content '{"a":1}'
        }

        Get-Content -LiteralPath $script:Target -Raw -Encoding UTF8 | Should -Be '{"a":1}'
    }

    It 'replaces an existing file and leaves no temp files' {
        New-Item -ItemType Directory -Path (Split-Path $script:Target -Parent) -Force | Out-Null
        Set-Content -LiteralPath $script:Target -Value 'old' -Encoding UTF8

        InModuleScope AutomaticPKI -Parameters @{ Target = $script:Target } {
            param($Target)
            Write-APKIFileAtomic -Path $Target -Content 'new'
        }

        Get-Content -LiteralPath $script:Target -Raw -Encoding UTF8 | Should -Be 'new'
        @(Get-ChildItem -LiteralPath (Split-Path $script:Target -Parent) -Filter '*.tmp').Count | Should -Be 0
    }

    It 'keeps the previous file intact and removes the temp file when the move fails' {
        New-Item -ItemType Directory -Path (Split-Path $script:Target -Parent) -Force | Out-Null
        Set-Content -LiteralPath $script:Target -Value 'original' -Encoding UTF8 -NoNewline
        Mock Move-APKIFileIntoPlace -ModuleName AutomaticPKI { throw 'simulated crash during rename' }

        {
            InModuleScope AutomaticPKI -Parameters @{ Target = $script:Target } {
                param($Target)
                Write-APKIFileAtomic -Path $Target -Content 'half-written'
            }
        } | Should -Throw '*simulated crash*'

        Get-Content -LiteralPath $script:Target -Raw -Encoding UTF8 | Should -Be 'original'
        @(Get-ChildItem -LiteralPath (Split-Path $script:Target -Parent) -Filter '*.tmp').Count | Should -Be 0
    }
}

Describe 'Assert-APKISafeName' {
    It 'accepts <Name>' -TestCases @(
        @{ Name = 'contoso-web' }
        @{ Name = 'Default_Web_Site' }
        @{ Name = 'www.contoso.com' }
        @{ Name = 'a' }
    ) {
        param($Name)
        { InModuleScope AutomaticPKI -Parameters @{ Name = $Name } { param($Name) Assert-APKISafeName -Name $Name } } |
            Should -Not -Throw
    }

    It 'rejects <Name>' -TestCases @(
        @{ Name = '' }
        @{ Name = '../evil' }
        @{ Name = 'a..b' }
        @{ Name = 'with space' }
        @{ Name = 'back\slash' }
        @{ Name = '.hidden' }
        @{ Name = 'trailing.' }
        @{ Name = 'CON' }
        @{ Name = 'nul.json' }
    ) {
        param($Name)
        { InModuleScope AutomaticPKI -Parameters @{ Name = $Name } { param($Name) Assert-APKISafeName -Name $Name -Kind 'order Id' } } |
            Should -Throw '*Invalid order Id*'
    }
}
