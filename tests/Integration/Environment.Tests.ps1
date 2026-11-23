Describe 'Integration environment' -Tag 'Integration' {
    It 'runs on Windows' {
        $IsWindowsHost = ($PSVersionTable.PSEdition -eq 'Desktop') -or $IsWindows
        $IsWindowsHost | Should -BeTrue
    }

    It 'has IIS installed' {
        (Get-Service W3SVC -ErrorAction SilentlyContinue) | Should -Not -BeNullOrEmpty
    }

    It 'has a reachable certificate authority' {
        & certutil.exe -ping | Out-Null
        $LASTEXITCODE | Should -Be 0
    }
}
