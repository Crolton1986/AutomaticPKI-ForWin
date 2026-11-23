BeforeAll {
    Import-Module ([System.IO.Path]::Combine($PSScriptRoot, '..', '..', '..', 'src', 'AutomaticPKI', 'AutomaticPKI.psd1')) -Force
}

AfterAll {
    Remove-Module AutomaticPKI -Force -ErrorAction SilentlyContinue
}

Describe 'Get-APKIOrder and Remove-APKIOrder' {
    BeforeEach {
        $env:APKI_ROOT = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        Mock -ModuleName AutomaticPKI Write-APKILog { }
        InModuleScope AutomaticPKI {
            Save-APKIOrderData -Order ([pscustomobject]@{ Id = 'a'; Status = 'Active'; SiteName = 'A'; Hostnames = @('a.contoso.com'); Provider = 'AdcsRpc' })
            Save-APKIOrderData -Order ([pscustomobject]@{ Id = 'b'; Status = 'Proposed'; SiteName = 'B'; Hostnames = @(); Provider = 'AdcsRpc' })
        }
    }

    It 'lists all orders, one order, or orders with a status' {
        @(Get-APKIOrder).Count | Should -Be 2
        (Get-APKIOrder -Id 'a').SiteName | Should -Be 'A'
        @(Get-APKIOrder -Status Proposed | ForEach-Object { $_.Id }) | Should -Be @('b')
    }

    It 'writes an error for an unknown Id' {
        { Get-APKIOrder -Id 'zzz' -ErrorAction Stop } | Should -Throw '*does not exist*'
    }

    It 'removes an order, honouring -WhatIf' {
        Remove-APKIOrder -Id 'a' -WhatIf
        Get-APKIOrder -Id 'a' | Should -Not -BeNullOrEmpty
        Remove-APKIOrder -Id 'a' -Confirm:$false
        Get-APKIOrder -Id 'a' -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        @(Get-APKIOrder).Count | Should -Be 1
    }

    It 'removes orders from the pipeline' {
        Get-APKIOrder | Remove-APKIOrder -Confirm:$false
        @(Get-APKIOrder).Count | Should -Be 0
    }

    It 'writes an error when removing an unknown Id' {
        { Remove-APKIOrder -Id 'zzz' -ErrorAction Stop } | Should -Throw '*does not exist*'
    }
}
