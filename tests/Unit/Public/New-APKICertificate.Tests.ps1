BeforeAll {
    Import-Module ([System.IO.Path]::Combine($PSScriptRoot, '..', '..', '..', 'src', 'AutomaticPKI', 'AutomaticPKI.psd1')) -Force

    function Save-TestOrder {
        param([string]$Status)
        $order = [pscustomobject]@{ Id = 'web'; Status = $Status; SiteName = 'Web'; Hostnames = @('web.contoso.com'); Provider = 'AdcsRpc'; CurrentThumbprint = ('A1' * 20) }
        InModuleScope AutomaticPKI -Parameters @{ O = $order } {
            param($O)
            Save-APKIOrderData -Order $O
        }
    }
}

AfterAll {
    Remove-Module AutomaticPKI -Force -ErrorAction SilentlyContinue
}

Describe 'New-APKICertificate' {
    BeforeEach {
        $env:APKI_ROOT = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        Mock -ModuleName AutomaticPKI Write-APKILog { }
        Mock -ModuleName AutomaticPKI Invoke-APKIOrderRenewal { [pscustomobject]@{ OrderId = $Order.Id; Outcome = 'Renewed' } }
    }

    It 'runs the order once, passing -Force' {
        Save-TestOrder -Status 'Active'
        $r = New-APKICertificate -Id 'web' -Force
        $r.Outcome | Should -Be 'Renewed'
        Should -Invoke -ModuleName AutomaticPKI Invoke-APKIOrderRenewal -Times 1 -Exactly -ParameterFilter { $Order.Id -eq 'web' -and $Force }
    }

    It 'refuses <Status> orders' -TestCases @(@{ Status = 'Proposed' }, @{ Status = 'Disabled' }) {
        Save-TestOrder -Status $Status
        { New-APKICertificate -Id 'web' } | Should -Throw '*Approve-APKIOrder*'
        Should -Invoke -ModuleName AutomaticPKI Invoke-APKIOrderRenewal -Times 0 -Exactly
    }

    It 'throws for an unknown order' {
        { New-APKICertificate -Id 'nope' } | Should -Throw '*does not exist*'
    }

    It 'does nothing under -WhatIf' {
        Save-TestOrder -Status 'Approved'
        $null = New-APKICertificate -Id 'web' -WhatIf
        Should -Invoke -ModuleName AutomaticPKI Invoke-APKIOrderRenewal -Times 0 -Exactly
    }
}

Describe 'Test-APKISite' {
    BeforeEach {
        $env:APKI_ROOT = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        Mock -ModuleName AutomaticPKI Write-APKILog { }
        Mock -ModuleName AutomaticPKI Get-APKIHealthSiteState { [pscustomobject]@{ SiteName = 'Web'; State = 'Stopped'; AppPools = @() } }
        Mock -ModuleName AutomaticPKI Start-APKIHealthSite { 'Started' }
    }

    It 'health-checks the current certificate without starting a stopped site' {
        Save-TestOrder -Status 'Active'
        $r = Test-APKISite -Id 'web'
        $r.Thumbprint | Should -Be ('A1' * 20)
        $r.Passed | Should -BeFalse
        $site = @($r.Results | Where-Object { $_.Check -eq 'SiteState' })[0]
        $site.Detail | Should -Match 'WhatIf'
        Should -Invoke -ModuleName AutomaticPKI Start-APKIHealthSite -Times 0 -Exactly
    }

    It 'throws when the order has no current certificate' {
        InModuleScope AutomaticPKI {
            Save-APKIOrderData -Order ([pscustomobject]@{ Id = 'web'; Status = 'Approved'; SiteName = 'Web'; Hostnames = @('web.contoso.com'); Provider = 'AdcsRpc' })
        }
        { Test-APKISite -Id 'web' } | Should -Throw '*no current certificate*'
    }
}
