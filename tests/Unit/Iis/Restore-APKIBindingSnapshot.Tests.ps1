BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../../src/AutomaticPKI/AutomaticPKI.psd1') -Force
    . (Join-Path $PSScriptRoot 'FakeIis.ps1')

    $script:ThumbA = 'A1' * 20
    $script:ThumbB = 'B2' * 20
    $script:ThumbNew = 'E5' * 20

    function Get-TestBinding {
        param([string]$SiteName, [string]$IPAddress = '*', [int]$Port = 443, [string]$HostHeader = '', [int]$SslFlags = 0)
        [pscustomobject]@{
            SiteName = $SiteName; Protocol = 'https'; IPAddress = $IPAddress; Port = $Port; HostHeader = $HostHeader
            SslFlags = $SslFlags; Thumbprint = ''; StoreName = 'My'; NameStatus = 'Usable'; SharedWith = @()
        }
    }
}

Describe 'Save-APKIBindingSnapshot / Restore-APKIBindingSnapshot' {
    BeforeEach {
        $env:APKI_ROOT = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        Mock -ModuleName AutomaticPKI Write-APKILog { }
        Mock -ModuleName AutomaticPKI Get-APKICertificateDnsName { @() }

        $script:Sm = Build-FakeIisServerManager -Site @(
            @{ Name = 'Contoso'; Bindings = @(
                    @{ Protocol = 'https'; BindingInformation = '*:443:www.contoso.com'; SslFlags = 5; Thumbprint = $script:ThumbA }
                    @{ Protocol = 'http'; BindingInformation = '*:80:new.contoso.com' }
                )
            }
            @{ Name = 'Legacy1'; Bindings = @(@{ Protocol = 'https'; BindingInformation = '*:443:'; SslFlags = 0; Thumbprint = $script:ThumbB; StoreName = 'WebHosting' }) }
            @{ Name = 'Legacy2'; Bindings = @(@{ Protocol = 'https'; BindingInformation = '*:443:legacy2.contoso.com'; SslFlags = 0 }) }
        )
        $script:Order = [pscustomobject]@{
            Id            = 'contoso'
            Status        = 'Active'
            SiteName      = 'Contoso'
            CreateBinding = $true
            Bindings      = @(
                Get-TestBinding -SiteName 'Contoso' -HostHeader 'www.contoso.com' -SslFlags 1
                Get-TestBinding -SiteName 'Contoso' -HostHeader 'new.contoso.com' -SslFlags 1
                Get-TestBinding -SiteName 'Legacy1'
            )
        }
    }

    It 'writes the snapshot under snapshots\<Id>\<timestamp>.json' {
        $saved = InModuleScope AutomaticPKI -Parameters @{ SM = $script:Sm; O = $script:Order } {
            param($SM, $O)
            Save-APKIBindingSnapshot -Order $O -ServerManager $SM -Confirm:$false
        }
        $saved.OrderId | Should -Be 'contoso'
        @($saved.Bindings).Count | Should -Be 3
        $path = $saved.Path
        $path | Should -Exist
        (Split-Path (Split-Path $path -Parent) -Leaf) | Should -Be 'contoso'
        (Split-Path (Split-Path (Split-Path $path -Parent) -Parent) -Leaf) | Should -Be 'snapshots'
        (Split-Path $path -Leaf) | Should -Match '^\d{8}T\d{9}Z\.json$'

        $snap = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
        $snap.OrderId | Should -Be 'contoso'
        @($snap.Bindings).Count | Should -Be 3
        $www = $snap.Bindings | Where-Object HostHeader -EQ 'www.contoso.com'
        $www.Exists | Should -BeTrue
        $www.Thumbprint | Should -Be $script:ThumbA
        $www.SslFlags | Should -Be 5
        ($snap.Bindings | Where-Object HostHeader -EQ 'new.contoso.com').Exists | Should -BeFalse
        ($snap.Bindings | Where-Object SiteName -EQ 'Legacy1').StoreName | Should -Be 'WebHosting'
    }

    It 'round-trips: swap then restore puts back thumbprints, stores and flags and removes created bindings' {
        $result = InModuleScope AutomaticPKI -Parameters @{ SM = $script:Sm; O = $script:Order; T = $script:ThumbNew } {
            param($SM, $O, $T)
            $null = Save-APKIBindingSnapshot -Order $O -ServerManager $SM -Confirm:$false
            $swap = @(Set-APKIIisCertificateBinding -Order $O -Thumbprint $T -ServerManager $SM -Confirm:$false)
            $afterSwap = @(Get-APKIIisBinding -ServerManager $SM)
            $restore = @(Restore-APKIBindingSnapshot -Order $O -ServerManager $SM -Confirm:$false)
            [pscustomobject]@{ Swap = $swap; AfterSwap = $afterSwap; Restore = $restore; After = @(Get-APKIIisBinding -ServerManager $SM) }
        }

        # the swap really happened
        ($result.Swap | Where-Object BindingInformation -EQ '*:443:new.contoso.com').Action | Should -Be 'Created'
        ($result.AfterSwap | Where-Object HostHeader -EQ 'new.contoso.com').Thumbprint | Should -Be $script:ThumbNew
        ($result.AfterSwap | Where-Object SiteName -EQ 'Legacy2').Thumbprint | Should -Be $script:ThumbNew

        # and was undone
        ($result.Restore | Where-Object BindingInformation -EQ '*:443:new.contoso.com').Action | Should -Be 'Removed'
        $www = $result.After | Where-Object { $_.Protocol -eq 'https' -and $_.HostHeader -eq 'www.contoso.com' }
        $www.Thumbprint | Should -Be $script:ThumbA
        $www.SslFlags | Should -Be 5
        $www.StoreName | Should -Be 'My'
        $l1 = $result.After | Where-Object SiteName -EQ 'Legacy1'
        $l1.Thumbprint | Should -Be $script:ThumbB
        $l1.StoreName | Should -Be 'WebHosting'
        ($result.After | Where-Object SiteName -EQ 'Legacy2').Thumbprint | Should -Be $script:ThumbB
        @($result.After | Where-Object { $_.Protocol -eq 'https' -and $_.HostHeader -eq 'new.contoso.com' }).Count | Should -Be 0
        $script:Sm.HttpSys.ContainsKey('new.contoso.com:443') | Should -BeFalse
        $script:Sm.CommitCount | Should -Be 2
    }

    It 'does not commit when nothing changed since the snapshot' {
        $r = InModuleScope AutomaticPKI -Parameters @{ SM = $script:Sm; O = $script:Order } {
            param($SM, $O)
            $null = Save-APKIBindingSnapshot -Order $O -ServerManager $SM -Confirm:$false
            @(Restore-APKIBindingSnapshot -Order $O -ServerManager $SM -Confirm:$false)
        }
        @($r | Where-Object Action -NE 'Unchanged').Count | Should -Be 0
        $script:Sm.CommitCount | Should -Be 0
    }

    It 're-creates a binding that disappeared after the snapshot' {
        InModuleScope AutomaticPKI -Parameters @{ SM = $script:Sm; O = $script:Order } {
            param($SM, $O)
            $null = Save-APKIBindingSnapshot -Order $O -ServerManager $SM -Confirm:$false
            $site = @($SM.Sites)[0]
            $www = @($site.Bindings) | Where-Object BindingInformation -EQ '*:443:www.contoso.com'
            $site.Bindings.Remove($www, $false)
            $r = @(Restore-APKIBindingSnapshot -Order $O -ServerManager $SM -Confirm:$false)
            ($r | Where-Object BindingInformation -EQ '*:443:www.contoso.com').Action | Should -Be 'Recreated'
        }
        Get-FakeIisCertificate -ServerManager $script:Sm -SiteName 'Contoso' -BindingInformation '*:443:www.contoso.com' | Should -Be $script:ThumbA
        ($script:Sm.Sites[0].Bindings.Items | Where-Object BindingInformation -EQ '*:443:www.contoso.com').SslFlags | Should -Be 5
    }

    It 'restores the newest snapshot by default and a given one with -Path' {
        $paths = InModuleScope AutomaticPKI -Parameters @{ SM = $script:Sm; O = $script:Order; T = $script:ThumbNew } {
            param($SM, $O, $T)
            $first = Save-APKIBindingSnapshot -Order $O -ServerManager $SM -Confirm:$false
            $null = Set-APKIIisCertificateBinding -Order $O -Thumbprint $T -ServerManager $SM -Confirm:$false
            $second = Save-APKIBindingSnapshot -Order $O -ServerManager $SM -Confirm:$false
            $null = Restore-APKIBindingSnapshot -Order $O -ServerManager $SM -Confirm:$false
            @($first, $second)
        }
        # newest snapshot already matches the swapped state
        Get-FakeIisCertificate -ServerManager $script:Sm -SiteName 'Contoso' -BindingInformation '*:443:www.contoso.com' | Should -Be $script:ThumbNew

        InModuleScope AutomaticPKI -Parameters @{ SM = $script:Sm; P = $paths[0].Path } {
            param($SM, $P)
            $null = Restore-APKIBindingSnapshot -Path $P -ServerManager $SM -Confirm:$false
        }
        Get-FakeIisCertificate -ServerManager $script:Sm -SiteName 'Contoso' -BindingInformation '*:443:www.contoso.com' | Should -Be $script:ThumbA
    }

    It 'restores from the object Save returned (-Order -Snapshot), as the rollback path calls it' {
        InModuleScope AutomaticPKI -Parameters @{ SM = $script:Sm; O = $script:Order; T = $script:ThumbNew } {
            param($SM, $O, $T)
            $snap = Save-APKIBindingSnapshot -Order $O -ServerManager $SM -Confirm:$false
            $null = Set-APKIIisCertificateBinding -Order $O -Thumbprint $T -ServerManager $SM -Confirm:$false
            # a newer snapshot on disk must not win over the explicit object
            $null = Save-APKIBindingSnapshot -Order $O -ServerManager $SM -Confirm:$false
            $null = Restore-APKIBindingSnapshot -Order $O -Snapshot $snap -ServerManager $SM -Confirm:$false
        }
        Get-FakeIisCertificate -ServerManager $script:Sm -SiteName 'Contoso' -BindingInformation '*:443:www.contoso.com' | Should -Be $script:ThumbA
        @($script:Sm.Sites[0].Bindings.Items | Where-Object BindingInformation -EQ '*:443:new.contoso.com').Count | Should -Be 0
    }

    It 'refuses a snapshot of another order' {
        InModuleScope AutomaticPKI -Parameters @{ SM = $script:Sm; O = $script:Order } {
            param($SM, $O)
            $snap = Save-APKIBindingSnapshot -Order $O -ServerManager $SM -Confirm:$false
            $other = [pscustomobject]@{ Id = 'other'; Bindings = @() }
            { Restore-APKIBindingSnapshot -Order $other -Snapshot $snap -ServerManager $SM -Confirm:$false } | Should -Throw '*belongs to order*'
        }
    }

    It 'leaves IIS alone with -WhatIf' {
        InModuleScope AutomaticPKI -Parameters @{ SM = $script:Sm; O = $script:Order; T = $script:ThumbNew } {
            param($SM, $O, $T)
            $null = Save-APKIBindingSnapshot -Order $O -ServerManager $SM -Confirm:$false
            $null = Set-APKIIisCertificateBinding -Order $O -Thumbprint $T -ServerManager $SM -Confirm:$false
            $r = @(Restore-APKIBindingSnapshot -Order $O -ServerManager $SM -WhatIf)
            @($r | Where-Object Action -EQ 'Skipped').Count | Should -BeGreaterThan 0
        }
        $script:Sm.CommitCount | Should -Be 1
        Get-FakeIisCertificate -ServerManager $script:Sm -SiteName 'Contoso' -BindingInformation '*:443:www.contoso.com' | Should -Be $script:ThumbNew
    }

    It 'throws when no snapshot exists' {
        InModuleScope AutomaticPKI -Parameters @{ SM = $script:Sm } {
            param($SM)
            { Restore-APKIBindingSnapshot -Order ([pscustomobject]@{ Id = 'none' }) -ServerManager $SM -Confirm:$false } | Should -Throw '*No binding snapshot*'
        }
    }
}
