BeforeAll {
    Import-Module ([System.IO.Path]::Combine($PSScriptRoot, '..', '..', '..', 'src', 'AutomaticPKI', 'AutomaticPKI.psd1')) -Force

    $script:Thumb = 'A1' * 20
    $script:Now = [datetime]'2026-06-01T12:00:00'

    function Invoke-DueTest {
        param([object]$Order, [int]$GlobalDays = 30)
        InModuleScope AutomaticPKI -Parameters @{ O = $Order; D = $GlobalDays; N = $script:Now } {
            param($O, $D, $N)
            $config = Get-APKIDefaultConfig
            $config.RenewalDaysBefore = $D
            Test-APKIRenewalDue -Order $O -Config $config -Now $N
        }
    }

    function New-DueOrder {
        param([string[]]$Hostnames = @('www.contoso.com'), $RenewalDaysBefore = $null, [string]$Thumbprint = ('A1' * 20))
        [pscustomobject]@{
            Id                = 'contoso-web'
            Status            = 'Active'
            SiteName          = 'Contoso Web'
            Hostnames         = $Hostnames
            Provider          = 'AdcsRpc'
            CurrentThumbprint = $Thumbprint
            RenewalDaysBefore = $RenewalDaysBefore
        }
    }

    function Set-FakeCertificate {
        param([int]$LifetimeDays, [int]$DaysLeft, [string[]]$DnsNames = @('www.contoso.com'))
        $notAfter = $script:Now.AddDays($DaysLeft)
        # Global: the mock body runs in the module's scope.
        $global:APKITestCertInfo = [pscustomobject]@{
            Thumbprint    = $script:Thumb
            NotBefore     = $notAfter.AddDays(-$LifetimeDays)
            NotAfter      = $notAfter
            DnsNames      = $DnsNames
            HasPrivateKey = $true
        }
        Mock -ModuleName AutomaticPKI Get-APKICertificateInfo { $global:APKITestCertInfo }
    }
}

AfterAll {
    Remove-Variable -Name APKITestCertInfo -Scope Global -ErrorAction SilentlyContinue
    Remove-Module AutomaticPKI -Force -ErrorAction SilentlyContinue
}

Describe 'Test-APKIRenewalDue' {
    BeforeEach {
        Mock -ModuleName AutomaticPKI Write-APKILog { }
        Mock -ModuleName AutomaticPKI Find-APKIMachineCertificate { [pscustomobject]@{ Thumbprint = $Thumbprint } }
    }

    It 'is due when the order has no current thumbprint' {
        $r = Invoke-DueTest -Order (New-DueOrder -Thumbprint '')
        $r.Due | Should -BeTrue
        $r.Reason | Should -Match 'no current certificate'
        Should -Invoke -ModuleName AutomaticPKI Find-APKIMachineCertificate -Times 0 -Exactly
    }

    It 'is due when the certificate is missing from the store' {
        Mock -ModuleName AutomaticPKI Find-APKIMachineCertificate { }
        $r = Invoke-DueTest -Order (New-DueOrder)
        $r.Due | Should -BeTrue
        $r.Reason | Should -Match 'not in Cert:'
    }

    It 'is due when a hostname is not covered by the SANs' {
        Set-FakeCertificate -LifetimeDays 365 -DaysLeft 300
        $r = Invoke-DueTest -Order (New-DueOrder -Hostnames @('www.contoso.com', 'shop.contoso.com'))
        $r.Due | Should -BeTrue
        $r.Reason | Should -Match 'shop\.contoso\.com'
    }

    It 'accepts a wildcard SAN for a one-label hostname and an identical wildcard hostname' {
        Set-FakeCertificate -LifetimeDays 365 -DaysLeft 300 -DnsNames @('*.contoso.com')
        $r = Invoke-DueTest -Order (New-DueOrder -Hostnames @('www.contoso.com', '*.contoso.com'))
        $r.Due | Should -BeFalse
    }

    It 'is not due for a fresh one-year certificate' {
        Set-FakeCertificate -LifetimeDays 365 -DaysLeft 200
        $r = Invoke-DueTest -Order (New-DueOrder)
        $r.Due | Should -BeFalse
        $r.NotAfter | Should -Be $script:Now.AddDays(200)
    }

    It 'is due within one third of the lifetime even before RenewalDaysBefore' {
        # 365-day cert: one third is ~121.7 days, earlier than the 30-day setting.
        Set-FakeCertificate -LifetimeDays 365 -DaysLeft 100
        $r = Invoke-DueTest -Order (New-DueOrder)
        $r.Due | Should -BeTrue
        $r.Reason | Should -Match 'renewal window opened'
    }

    It 'is due within RenewalDaysBefore when that is earlier than one third of the lifetime' {
        # 30-day cert: one third = 10 days; global setting 20 days is earlier.
        Set-FakeCertificate -LifetimeDays 30 -DaysLeft 15
        (Invoke-DueTest -Order (New-DueOrder) -GlobalDays 20).Due | Should -BeTrue
        (Invoke-DueTest -Order (New-DueOrder) -GlobalDays 10).Due | Should -BeFalse
    }

    It 'lets the order RenewalDaysBefore override the global value' {
        # 90-day cert, 40 days left: one third = 30 days, global 30 -> not due; order 45 -> due.
        Set-FakeCertificate -LifetimeDays 90 -DaysLeft 40
        (Invoke-DueTest -Order (New-DueOrder)).Due | Should -BeFalse
        (Invoke-DueTest -Order (New-DueOrder -RenewalDaysBefore 45)).Due | Should -BeTrue
    }

    It 'is due when the certificate has already expired' {
        Set-FakeCertificate -LifetimeDays 365 -DaysLeft -1
        (Invoke-DueTest -Order (New-DueOrder)).Due | Should -BeTrue
    }
}
