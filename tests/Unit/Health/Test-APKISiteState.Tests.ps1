BeforeAll {
    . (Join-Path $PSScriptRoot 'HealthTestHelpers.ps1')
    Import-APKITestModule
}

AfterAll {
    Remove-Module AutomaticPKI -Force -ErrorAction SilentlyContinue
}

Describe 'Test-APKISiteState' {
    BeforeAll {
        $env:APKI_ROOT = $TestDrive
        Mock -ModuleName AutomaticPKI Write-APKILog {}
        Mock -ModuleName AutomaticPKI Start-Sleep {}
    }

    BeforeEach {
        # Fake Microsoft.Web.Administration.ServerManager: hashtables give the string indexers
        # (Sites['name'], ApplicationPools['name']) the real collections have.
        $pool = [pscustomobject]@{ Name = 'ContosoPool'; State = 'Stopped' }
        $pool | Add-Member -MemberType ScriptMethod -Name Start -Value { $this.State = 'Started'; 'Started' }
        $site = [pscustomobject]@{
            Name                = 'Contoso'
            State               = 'Started'
            Applications        = @(
                [pscustomobject]@{ Path = '/'; ApplicationPoolName = 'ContosoPool' }
                [pscustomobject]@{ Path = '/api'; ApplicationPoolName = 'ContosoPool' }
            )
            ApplicationDefaults = [pscustomobject]@{ ApplicationPoolName = 'DefaultAppPool' }
        }
        $site | Add-Member -MemberType ScriptMethod -Name Start -Value { $this.State = 'Started'; 'Started' }
        $script:Pool = $pool
        $script:Site = $site
        $script:Manager = [pscustomobject]@{
            Sites            = @{ 'Contoso' = $site }
            ApplicationPools = @{ 'ContosoPool' = $pool }
        }
        Mock -ModuleName AutomaticPKI Get-APKIServerManager { $script:Manager }
    }

    It 'passes when site and pool are Started' {
        $script:Pool.State = 'Started'
        $r = InModuleScope AutomaticPKI { Test-APKISiteState -SiteName 'Contoso' }
        @($r).Count | Should -Be 2
        @($r | Where-Object { -not $_.Passed }).Count | Should -Be 0
        ($r | Where-Object Check -EQ 'AppPoolState').Target | Should -Be 'ContosoPool'
    }

    It 'starts a stopped application pool and reports it' {
        $r = InModuleScope AutomaticPKI { Test-APKISiteState -SiteName 'Contoso' }
        $poolResult = $r | Where-Object Check -EQ 'AppPoolState'
        $poolResult.Passed | Should -BeTrue
        $poolResult.Detail | Should -Match 'Was Stopped'
        $script:Pool.State | Should -Be 'Started'
    }

    It 'starts a stopped site' {
        $script:Pool.State = 'Started'
        $script:Site.State = 'Stopped'
        $r = InModuleScope AutomaticPKI { Test-APKISiteState -SiteName 'Contoso' }
        ($r | Where-Object Check -EQ 'SiteState').Passed | Should -BeTrue
        $script:Site.State | Should -Be 'Started'
    }

    It 'waits for a pool that reports Starting' {
        $script:Pool | Add-Member -MemberType ScriptMethod -Name Start -Value { $this.State = 'Started'; 'Starting' } -Force
        $r = InModuleScope AutomaticPKI { Test-APKISiteState -SiteName 'Contoso' }
        ($r | Where-Object Check -EQ 'AppPoolState').Passed | Should -BeTrue
        Should -Invoke -ModuleName AutomaticPKI Start-Sleep -Times 1 -Exactly
    }

    It 'does not start anything with -WhatIf' {
        $r = InModuleScope AutomaticPKI { Test-APKISiteState -SiteName 'Contoso' -WhatIf }
        ($r | Where-Object Check -EQ 'AppPoolState').Passed | Should -BeFalse
        ($r | Where-Object Check -EQ 'AppPoolState').Detail | Should -Match 'WhatIf'
        $script:Pool.State | Should -Be 'Stopped'
    }

    It 'fails when the pool cannot be started' {
        $script:Pool | Add-Member -MemberType ScriptMethod -Name Start -Value { throw 'Access denied' } -Force
        $r = InModuleScope AutomaticPKI { Test-APKISiteState -SiteName 'Contoso' }
        ($r | Where-Object Check -EQ 'AppPoolState').Passed | Should -BeFalse
        ($r | Where-Object Check -EQ 'AppPoolState').Detail | Should -Match 'Access denied'
    }

    It 'fails when the site does not exist' {
        $r = InModuleScope AutomaticPKI { Test-APKISiteState -SiteName 'Nope' }
        @($r).Count | Should -Be 1
        $r.Check | Should -Be 'SiteState'
        $r.Passed | Should -BeFalse
    }

    It 'fails when an application pool is missing' {
        $script:Manager.ApplicationPools.Remove('ContosoPool')
        $r = InModuleScope AutomaticPKI { Test-APKISiteState -SiteName 'Contoso' }
        ($r | Where-Object Check -EQ 'AppPoolState').Passed | Should -BeFalse
        ($r | Where-Object Check -EQ 'AppPoolState').Detail | Should -Match 'does not exist'
    }
}
