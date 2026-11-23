BeforeAll {
    Import-Module ([System.IO.Path]::Combine($PSScriptRoot, '..', '..', '..', 'src', 'AutomaticPKI', 'AutomaticPKI.psd1')) -Force

    function Save-RunOrder {
        param([string]$Id, [string]$Status = 'Active')
        $order = [pscustomobject]@{
            Id                = $Id
            Status            = $Status
            SiteName          = "Site $Id"
            Hostnames         = @("$Id.contoso.com")
            Provider          = 'AdcsRpc'
            CurrentThumbprint = ('A1' * 20)
        }
        InModuleScope AutomaticPKI -Parameters @{ O = $order } {
            param($O)
            Save-APKIOrderData -Order $O
        }
    }
}

AfterAll {
    Remove-Module AutomaticPKI -Force -ErrorAction SilentlyContinue
}

Describe 'Invoke-APKIRenewal' {
    BeforeEach {
        $env:APKI_ROOT = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        Mock -ModuleName AutomaticPKI Write-APKILog { }
        Mock -ModuleName AutomaticPKI Send-APKINotification { }
        Mock -ModuleName AutomaticPKI Remove-APKIOldCertificate { }
        Mock -ModuleName AutomaticPKI Remove-APKIOldLog { }
        Mock -ModuleName AutomaticPKI Invoke-APKIOrderRenewal {
            switch ($Order.Id) {
                'b-broken' { throw 'boom' }
                'c-pending' { [pscustomobject]@{ OrderId = $Order.Id; Outcome = 'Pending'; Status = 'Pending'; Thumbprint = ''; Message = ''; Order = $Order } }
                'd-proposed' { [pscustomobject]@{ OrderId = $Order.Id; Outcome = 'Skipped'; Status = 'Proposed'; Thumbprint = ''; Message = ''; Order = $Order } }
                default { [pscustomobject]@{ OrderId = $Order.Id; Outcome = 'Renewed'; Status = 'Active'; Thumbprint = ''; Message = ''; Order = $Order } }
            }
        }
        Save-RunOrder -Id 'a-good'
        Save-RunOrder -Id 'b-broken'
        Save-RunOrder -Id 'c-pending' -Status 'Approved'
        Save-RunOrder -Id 'd-proposed' -Status 'Proposed'
        Save-RunOrder -Id 'e-good'
    }

    It 'processes every order even when one throws' {
        $r = Invoke-APKIRenewal
        Should -Invoke -ModuleName AutomaticPKI Invoke-APKIOrderRenewal -Times 5 -Exactly
        Should -Invoke -ModuleName AutomaticPKI Invoke-APKIOrderRenewal -Times 1 -Exactly -ParameterFilter { $Order.Id -eq 'e-good' }
        $r.Renewed | Should -Be 2
        $r.Pending | Should -Be 1
        $r.Failed | Should -Be 1
        $r.Skipped | Should -Be 1
        @($r.Results).Count | Should -Be 5
    }

    It 'records the unexpected failure on the order and notifies' {
        $null = Invoke-APKIRenewal
        $saved = InModuleScope AutomaticPKI { Get-APKIOrderData -Id 'b-broken' }
        $saved.Status | Should -Be 'Failed'
        $saved.LastError | Should -Match 'boom'
        Should -Invoke -ModuleName AutomaticPKI Write-APKILog -Times 1 -Exactly -ParameterFilter { $EventId -eq 3000 -and $OrderId -eq 'b-broken' }
        Should -Invoke -ModuleName AutomaticPKI Send-APKINotification -Times 1 -Exactly -ParameterFilter { $OrderId -eq 'b-broken' }
    }

    It 'cleans up old certificates and logs, then logs the 1000 summary' {
        $null = Invoke-APKIRenewal
        Should -Invoke -ModuleName AutomaticPKI Remove-APKIOldCertificate -Times 1 -Exactly
        Should -Invoke -ModuleName AutomaticPKI Remove-APKIOldLog -Times 1 -Exactly
        Should -Invoke -ModuleName AutomaticPKI Write-APKILog -Times 1 -Exactly -ParameterFilter {
            $EventId -eq 1000 -and $Message -match '2 renewed, 1 pending, 1 failed, 1 skipped'
        }
    }

    It 'still logs the summary when cleanup throws' {
        Mock -ModuleName AutomaticPKI Remove-APKIOldCertificate { throw 'store locked' }
        $null = Invoke-APKIRenewal
        Should -Invoke -ModuleName AutomaticPKI Remove-APKIOldLog -Times 1 -Exactly
        Should -Invoke -ModuleName AutomaticPKI Write-APKILog -Times 1 -Exactly -ParameterFilter { $EventId -eq 1000 }
    }

    It 'passes -Force and runs only the order named by -Id' {
        $null = Invoke-APKIRenewal -Id 'e-good' -Force
        Should -Invoke -ModuleName AutomaticPKI Invoke-APKIOrderRenewal -Times 1 -Exactly
        Should -Invoke -ModuleName AutomaticPKI Invoke-APKIOrderRenewal -Times 1 -Exactly -ParameterFilter { $Order.Id -eq 'e-good' -and $Force }
    }

    It 'renews nothing under -WhatIf' {
        $r = Invoke-APKIRenewal -WhatIf
        Should -Invoke -ModuleName AutomaticPKI Invoke-APKIOrderRenewal -Times 0 -Exactly
        $r.Skipped | Should -Be 5
    }
}
