BeforeAll {
    Import-Module ([System.IO.Path]::Combine($PSScriptRoot, '..', '..', '..', 'src', 'AutomaticPKI', 'AutomaticPKI.psd1')) -Force

    function New-Candidate {
        param([string]$Id, [string]$SiteName, [string[]]$Hostnames, [string]$Thumbprint = '')
        [pscustomobject]@{
            Id            = $Id
            Status        = 'Proposed'
            SiteName      = $SiteName
            Hostnames     = [string[]]$Hostnames
            Bindings      = [object[]]@([pscustomobject]@{
                    SiteName = $SiteName; Protocol = 'https'; IPAddress = '*'; Port = 443; HostHeader = ''
                    SslFlags = 0; Thumbprint = $Thumbprint; StoreName = 'My'; NameStatus = 'Usable'; SharedWith = [string[]]@()
                    BindingInformation = '*:443:'
                })
            NameStatus    = 'Usable'
            CreateBinding = $false
        }
    }
}

AfterAll {
    Remove-Variable -Name APKITestCandidates -Scope Global -ErrorAction SilentlyContinue
    Remove-Module AutomaticPKI -Force -ErrorAction SilentlyContinue
}

Describe 'Find-APKISite' {
    BeforeEach {
        $env:APKI_ROOT = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        Mock -ModuleName AutomaticPKI Write-APKILog { }
        # Global: keeps the mock body independent of the scope Pester runs it in.
        $global:APKITestCandidates = @(
            (New-Candidate -Id 'web' -SiteName 'Web' -Hostnames @('web.contoso.com') -Thumbprint ('c3' * 20)),
            (New-Candidate -Id 'shop' -SiteName 'Shop' -Hostnames @('shop.contoso.com'))
        )
        Mock -ModuleName AutomaticPKI Find-APKISiteCandidate { $global:APKITestCandidates }
    }

    It 'returns proposed orders with the bound certificate and the default provider, without saving' {
        $r = @(Find-APKISite)
        $r.Count | Should -Be 2
        $r[0].Status | Should -Be 'Proposed'
        $r[0].CurrentThumbprint | Should -Be ('C3' * 20)
        $r[0].Provider | Should -Be 'AdcsRpc'
        $r[1].CurrentThumbprint | Should -BeNullOrEmpty
        @(Get-APKIOrder).Count | Should -Be 0
    }

    It 'saves proposals with -Save and never overwrites an existing order' {
        $null = Find-APKISite -Save
        $null = Approve-APKIOrder -Id 'web' -ProviderSettings @{ CAConfig = 'ca\CA'; Template = 'WebServer' }
        $null = Find-APKISite -Save
        (Get-APKIOrder -Id 'web').Status | Should -Be 'Approved'
        (Get-APKIOrder -Id 'shop').Status | Should -Be 'Proposed'
    }

    It 'does not save a proposal for a site an existing order already manages under another Id' {
        InModuleScope AutomaticPKI {
            Save-APKIOrderData -Order ([pscustomobject]@{ Id = 'my-shop'; Status = 'Active'; SiteName = 'Shop'; Hostnames = @('shop.contoso.com'); Provider = 'AdcsRpc' })
        }
        $null = Find-APKISite -Save
        Get-APKIOrder -Id 'shop' -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        (Get-APKIOrder -Id 'web').Status | Should -Be 'Proposed'
    }

    It 'passes -HostnameOverride merged with overrides stored on orders' {
        InModuleScope AutomaticPKI {
            Save-APKIOrderData -Order ([pscustomobject]@{ Id = 'legacy'; Status = 'Proposed'; SiteName = 'Legacy'; Hostnames = @(); Provider = 'AdcsRpc'; HostnameOverride = @('legacy.contoso.com') })
        }
        $null = Find-APKISite -HostnameOverride @{ 'Default Web Site' = 'intranet.contoso.com' } -CheckDns
        Should -Invoke -ModuleName AutomaticPKI Find-APKISiteCandidate -Times 1 -Exactly -ParameterFilter {
            $CheckDns -and
            @($HostnameOverride['Legacy'])[0] -eq 'legacy.contoso.com' -and
            @($HostnameOverride['Default Web Site'])[0] -eq 'intranet.contoso.com'
        }
    }
}
