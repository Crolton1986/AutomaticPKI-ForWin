BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../../src/AutomaticPKI/AutomaticPKI.psd1') -Force
    . (Join-Path $PSScriptRoot 'FakeIis.ps1')

    $script:ThumbA = 'A1' * 20
    $script:ThumbB = 'B2' * 20
    $script:ThumbC = 'C3' * 20
    $script:ThumbNew = 'E5' * 20

    function Get-TestBinding {
        param([string]$SiteName, [string]$IPAddress = '*', [int]$Port = 443, [string]$HostHeader = '', [int]$SslFlags = 0)
        [pscustomobject]@{
            SiteName = $SiteName; Protocol = 'https'; IPAddress = $IPAddress; Port = $Port; HostHeader = $HostHeader
            SslFlags = $SslFlags; Thumbprint = ''; StoreName = 'My'; NameStatus = 'Usable'; SharedWith = @()
        }
    }

    function Get-TestOrder {
        param([object[]]$Bindings, [bool]$CreateBinding = $false)
        [pscustomobject]@{ Id = 'test-order'; Status = 'Active'; SiteName = $Bindings[0].SiteName; Bindings = $Bindings; CreateBinding = $CreateBinding }
    }

    function Invoke-Swap {
        param([object]$ServerManager, [object]$Order, [string]$Thumbprint, [switch]$DryRun)
        @(InModuleScope AutomaticPKI -Parameters @{ SM = $ServerManager; O = $Order; T = $Thumbprint; W = [bool]$DryRun } {
                param($SM, $O, $T, $W)
                Set-APKIIisCertificateBinding -Order $O -Thumbprint $T -ServerManager $SM -WhatIf:$W -Confirm:$false
            })
    }
}

Describe 'Set-APKIIisCertificateBinding' {
    BeforeEach {
        $env:APKI_ROOT = $TestDrive
        Mock -ModuleName AutomaticPKI Write-APKILog { }
        Mock -ModuleName AutomaticPKI Get-APKICertificateDnsName { @() }

        $script:Sm = Build-FakeIisServerManager -Site @(
            @{ Name = 'Contoso'; Bindings = @(
                    @{ Protocol = 'https'; BindingInformation = '*:443:www.contoso.com'; SslFlags = 5; Thumbprint = $script:ThumbA }
                    @{ Protocol = 'https'; BindingInformation = '*:443:api.contoso.com'; SslFlags = 1; Thumbprint = $script:ThumbA }
                    @{ Protocol = 'http'; BindingInformation = '*:80:www.contoso.com' }
                )
            }
            @{ Name = 'Legacy1'; Bindings = @(@{ Protocol = 'https'; BindingInformation = '*:443:'; SslFlags = 0; Thumbprint = $script:ThumbB }) }
            @{ Name = 'Legacy2'; Bindings = @(@{ Protocol = 'https'; BindingInformation = '*:443:legacy2.contoso.com'; SslFlags = 0 }) }
            @{ Name = 'IpOnly'; Bindings = @(@{ Protocol = 'https'; BindingInformation = '10.0.0.5:8443:'; SslFlags = 0; Thumbprint = $script:ThumbC }) }
        )
    }

    Context 'SNI binding' {
        It 'replaces the certificate and keeps every SslFlags bit' {
            $order = Get-TestOrder -Bindings @(Get-TestBinding -SiteName 'Contoso' -HostHeader 'www.contoso.com' -SslFlags 1)
            $r = Invoke-Swap -ServerManager $script:Sm -Order $order -Thumbprint $script:ThumbNew

            @($r).Count | Should -Be 1
            $r[0].Action | Should -Be 'Updated'
            $r[0].PreviousThumbprint | Should -Be $script:ThumbA
            Get-FakeIisCertificate -ServerManager $script:Sm -SiteName 'Contoso' -BindingInformation '*:443:www.contoso.com' | Should -Be $script:ThumbNew
            $b = $script:Sm.Sites[0].Bindings.Items | Where-Object BindingInformation -EQ '*:443:www.contoso.com'
            $b.SslFlags | Should -Be 5
            $script:Sm.CommitCount | Should -Be 1
        }

        It 'does not touch bindings that are not in the order' {
            $order = Get-TestOrder -Bindings @(Get-TestBinding -SiteName 'Contoso' -HostHeader 'www.contoso.com' -SslFlags 1)
            $null = Invoke-Swap -ServerManager $script:Sm -Order $order -Thumbprint $script:ThumbNew
            Get-FakeIisCertificate -ServerManager $script:Sm -SiteName 'Contoso' -BindingInformation '*:443:api.contoso.com' | Should -Be $script:ThumbA
            Get-FakeIisCertificate -ServerManager $script:Sm -SiteName 'Legacy1' -BindingInformation '*:443:' | Should -Be $script:ThumbB
            Get-FakeIisCertificate -ServerManager $script:Sm -SiteName 'IpOnly' -BindingInformation '10.0.0.5:8443:' | Should -Be $script:ThumbC
        }

        It 'accepts a thumbprint with spaces and lower case' {
            $order = Get-TestOrder -Bindings @(Get-TestBinding -SiteName 'Contoso' -HostHeader 'www.contoso.com' -SslFlags 1)
            $spaced = (($script:ThumbNew.ToLowerInvariant() -split '(..)' | Where-Object { $_ }) -join ' ')
            $null = Invoke-Swap -ServerManager $script:Sm -Order $order -Thumbprint $spaced
            Get-FakeIisCertificate -ServerManager $script:Sm -SiteName 'Contoso' -BindingInformation '*:443:www.contoso.com' | Should -Be $script:ThumbNew
        }

        It 'commits nothing when the certificate is already bound' {
            $order = Get-TestOrder -Bindings @(Get-TestBinding -SiteName 'Contoso' -HostHeader 'www.contoso.com' -SslFlags 1)
            $r = Invoke-Swap -ServerManager $script:Sm -Order $order -Thumbprint $script:ThumbA
            $r[0].Action | Should -Be 'Unchanged'
            $script:Sm.CommitCount | Should -Be 0
        }

        It 'changes nothing with -WhatIf' {
            $order = Get-TestOrder -Bindings @(Get-TestBinding -SiteName 'Contoso' -HostHeader 'www.contoso.com' -SslFlags 1)
            $r = Invoke-Swap -ServerManager $script:Sm -Order $order -Thumbprint $script:ThumbNew -DryRun
            $r[0].Action | Should -Be 'Skipped'
            $script:Sm.CommitCount | Should -Be 0
            Get-FakeIisCertificate -ServerManager $script:Sm -SiteName 'Contoso' -BindingInformation '*:443:www.contoso.com' | Should -Be $script:ThumbA
        }
    }

    Context 'non-SNI shared IP:port' {
        It 'updates the shared http.sys certificate seen by every site on the endpoint' {
            $order = Get-TestOrder -Bindings @(
                Get-TestBinding -SiteName 'Legacy1'
                Get-TestBinding -SiteName 'Legacy2' -HostHeader 'legacy2.contoso.com'
            )
            $r = Invoke-Swap -ServerManager $script:Sm -Order $order -Thumbprint $script:ThumbNew
            @($r | Where-Object Action -EQ 'Updated').Count | Should -Be 2
            Get-FakeIisCertificate -ServerManager $script:Sm -SiteName 'Legacy1' -BindingInformation '*:443:' | Should -Be $script:ThumbNew
            Get-FakeIisCertificate -ServerManager $script:Sm -SiteName 'Legacy2' -BindingInformation '*:443:legacy2.contoso.com' | Should -Be $script:ThumbNew
            $script:Sm.CommitCount | Should -Be 1
            Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 0 -Exactly -ParameterFilter { $Level -eq 'Warning' }
        }

        It 'only rewrites listed bindings and warns about unlisted sites on the endpoint' {
            $legacy2Before = ($script:Sm.Sites | Where-Object Name -EQ 'Legacy2').Bindings.Items[0].FakeId
            $order = Get-TestOrder -Bindings @(Get-TestBinding -SiteName 'Legacy1')
            $null = Invoke-Swap -ServerManager $script:Sm -Order $order -Thumbprint $script:ThumbNew

            ($script:Sm.Sites | Where-Object Name -EQ 'Legacy2').Bindings.Items[0].FakeId | Should -Be $legacy2Before
            Get-FakeIisCertificate -ServerManager $script:Sm -SiteName 'Legacy2' -BindingInformation '*:443:legacy2.contoso.com' | Should -Be $script:ThumbNew
            Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter { $Level -eq 'Warning' -and $Message -like '*Legacy2*' }
        }
    }

    Context 'IP-only binding' {
        It 'updates an IP:port binding' {
            $order = Get-TestOrder -Bindings @(Get-TestBinding -SiteName 'IpOnly' -IPAddress '10.0.0.5' -Port 8443)
            $r = Invoke-Swap -ServerManager $script:Sm -Order $order -Thumbprint $script:ThumbNew
            $r[0].Action | Should -Be 'Updated'
            $r[0].BindingInformation | Should -Be '10.0.0.5:8443:'
            Get-FakeIisCertificate -ServerManager $script:Sm -SiteName 'IpOnly' -BindingInformation '10.0.0.5:8443:' | Should -Be $script:ThumbNew
        }
    }

    Context 'missing bindings' {
        It 'creates a missing SNI binding when CreateBinding is true (EventId 1003)' {
            $order = Get-TestOrder -CreateBinding $true -Bindings @(
                Get-TestBinding -SiteName 'Contoso' -HostHeader 'www.contoso.com' -SslFlags 1
                Get-TestBinding -SiteName 'Contoso' -HostHeader 'new.contoso.com' -SslFlags 0
            )
            $r = Invoke-Swap -ServerManager $script:Sm -Order $order -Thumbprint $script:ThumbNew
            ($r | Where-Object BindingInformation -EQ '*:443:new.contoso.com').Action | Should -Be 'Created'
            $nb = $script:Sm.Sites[0].Bindings.Items | Where-Object BindingInformation -EQ '*:443:new.contoso.com'
            $nb.Protocol | Should -Be 'https'
            $nb.SslFlags | Should -Be 1
            Get-FakeIisCertificate -ServerManager $script:Sm -SiteName 'Contoso' -BindingInformation '*:443:new.contoso.com' | Should -Be $script:ThumbNew
            $script:Sm.CommitCount | Should -Be 1
            Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter { $EventId -eq 1003 -and $OrderId -eq 'test-order' }
        }

        It 'throws before changing anything when CreateBinding is false' {
            $order = Get-TestOrder -CreateBinding $false -Bindings @(
                Get-TestBinding -SiteName 'Contoso' -HostHeader 'www.contoso.com' -SslFlags 1
                Get-TestBinding -SiteName 'Contoso' -HostHeader 'new.contoso.com' -SslFlags 1
            )
            { Invoke-Swap -ServerManager $script:Sm -Order $order -Thumbprint $script:ThumbNew } | Should -Throw '*CreateBinding*'
            $script:Sm.CommitCount | Should -Be 0
            Get-FakeIisCertificate -ServerManager $script:Sm -SiteName 'Contoso' -BindingInformation '*:443:www.contoso.com' | Should -Be $script:ThumbA
        }

        It 'never creates a non-SNI binding' {
            $order = Get-TestOrder -CreateBinding $true -Bindings @(Get-TestBinding -SiteName 'Contoso' -IPAddress '10.9.9.9')
            { Invoke-Swap -ServerManager $script:Sm -Order $order -Thumbprint $script:ThumbNew } | Should -Throw '*Non-SNI*'
            $script:Sm.CommitCount | Should -Be 0
        }

        It 'throws when the site does not exist' {
            $order = Get-TestOrder -Bindings @(Get-TestBinding -SiteName 'Nope' -HostHeader 'x.contoso.com' -SslFlags 1)
            { Invoke-Swap -ServerManager $script:Sm -Order $order -Thumbprint $script:ThumbNew } | Should -Throw '*not found*'
        }
    }

    It 'refuses Central Certificate Store bindings' {
        $sm = Build-FakeIisServerManager -Site @(
            @{ Name = 'Ccs'; Bindings = @(@{ Protocol = 'https'; BindingInformation = '*:443:ccs.contoso.com'; SslFlags = 3 }) }
        )
        $order = Get-TestOrder -Bindings @(Get-TestBinding -SiteName 'Ccs' -HostHeader 'ccs.contoso.com' -SslFlags 3)
        { Invoke-Swap -ServerManager $sm -Order $order -Thumbprint $script:ThumbNew } | Should -Throw '*Central Certificate Store*'
    }

    It 'ignores http entries in Order.Bindings' {
        $http = [pscustomobject]@{ SiteName = 'Contoso'; Protocol = 'http'; IPAddress = '*'; Port = 80; HostHeader = 'www.contoso.com'; SslFlags = 0 }
        $order = Get-TestOrder -Bindings @($http, (Get-TestBinding -SiteName 'Contoso' -HostHeader 'www.contoso.com' -SslFlags 1))
        $r = Invoke-Swap -ServerManager $script:Sm -Order $order -Thumbprint $script:ThumbNew
        @($r).Count | Should -Be 1
    }
}
