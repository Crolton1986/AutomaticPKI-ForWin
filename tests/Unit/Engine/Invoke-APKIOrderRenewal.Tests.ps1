BeforeAll {
    Import-Module ([System.IO.Path]::Combine($PSScriptRoot, '..', '..', '..', 'src', 'AutomaticPKI', 'AutomaticPKI.psd1')) -Force

    $script:OldThumb = 'A1' * 20
    $script:NewThumb = 'B2' * 20

    function New-RenewalOrder {
        param([string]$Status = 'Approved', [string]$Current = ('A1' * 20), [string]$PendingRequestId = $null)
        [pscustomobject]@{
            Id                 = 'contoso-web'
            Status             = $Status
            SiteName           = 'Contoso Web'
            Hostnames          = @('www.contoso.com')
            Bindings           = @([pscustomobject]@{
                    SiteName = 'Contoso Web'; Protocol = 'https'; IPAddress = '*'; Port = 443; HostHeader = 'www.contoso.com'
                    SslFlags = 1; Thumbprint = $Current; StoreName = 'My'; NameStatus = 'Usable'; SharedWith = @()
                    BindingInformation = '*:443:www.contoso.com'
                })
            Provider           = 'AdcsRpc'
            ProviderSettings   = [pscustomobject]@{ CAConfig = 'ca01\Contoso CA'; Template = 'WebServer' }
            CurrentThumbprint  = $Current
            PreviousThumbprint = $null
            PendingRequestId   = $PendingRequestId
            LastRenewal        = $null
            LastError          = 'old error'
        }
    }

    function Invoke-Renewal {
        param([object]$Order, [switch]$Force, [string]$RevocationPolicy = 'Lenient')
        InModuleScope AutomaticPKI -Parameters @{ O = $Order; F = [bool]$Force; R = $RevocationPolicy } {
            param($O, $F, $R)
            $config = Get-APKIDefaultConfig
            $config.RevocationPolicy = $R
            Invoke-APKIOrderRenewal -Order $O -Force:$F -Config $config
        }
    }

    function Get-SavedOrder {
        InModuleScope AutomaticPKI { Get-APKIOrderData -Id 'contoso-web' }
    }

    function New-ProviderResult {
        param([string]$Status, [string]$Thumbprint = $null, [string]$RequestId = $null, [string]$Message = '')
        [pscustomobject]@{ Status = $Status; Thumbprint = $Thumbprint; RequestId = $RequestId; Message = $Message }
    }
}

AfterAll {
    Remove-Variable -Name APKITestProviderResult -Scope Global -ErrorAction SilentlyContinue
    Remove-Module AutomaticPKI -Force -ErrorAction SilentlyContinue
}

Describe 'Invoke-APKIOrderRenewal' {
    BeforeEach {
        $env:APKI_ROOT = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        Mock -ModuleName AutomaticPKI Write-APKILog { }
        Mock -ModuleName AutomaticPKI Send-APKINotification { }
        $global:APKITestProviderResult = New-ProviderResult -Status 'Issued' -Thumbprint ('B2' * 20) -RequestId '7'
        Mock -ModuleName AutomaticPKI Request-APKIAdcsRpcCertificate { $global:APKITestProviderResult }
        Mock -ModuleName AutomaticPKI Receive-APKIAdcsRpcCertificate { $global:APKITestProviderResult }
        Mock -ModuleName AutomaticPKI Invoke-APKISwapWithRollback {
            [pscustomobject]@{ Success = $true; Outcome = 'Swapped'; ActiveThumbprint = $NewThumbprint; Error = '' }
        }
        Mock -ModuleName AutomaticPKI Test-APKIRenewalDue {
            [pscustomobject]@{ Due = $true; Reason = 'due (test)'; NotAfter = (Get-Date).AddDays(60); RenewAfter = (Get-Date) }
        }
        Mock -ModuleName AutomaticPKI Get-APKIBoundThumbprint { @('A1' * 20) }
        Mock -ModuleName AutomaticPKI Remove-APKIMachineCertificate { }
    }

    Context 'skipped orders' {
        It 'skips <Status> orders without calling a provider or saving' -TestCases @(
            @{ Status = 'Proposed' }
            @{ Status = 'Disabled' }
        ) {
            $r = Invoke-Renewal -Order (New-RenewalOrder -Status $Status)
            $r.Outcome | Should -Be 'Skipped'
            Should -Invoke -ModuleName AutomaticPKI Request-APKIAdcsRpcCertificate -Times 0 -Exactly
            Get-SavedOrder | Should -BeNullOrEmpty
        }

        It 'leaves an Active order that is not due alone' {
            Mock -ModuleName AutomaticPKI Test-APKIRenewalDue { [pscustomobject]@{ Due = $false; Reason = 'fine'; NotAfter = (Get-Date).AddDays(200); RenewAfter = (Get-Date).AddDays(100) } }
            $r = Invoke-Renewal -Order (New-RenewalOrder -Status 'Active')
            $r.Outcome | Should -Be 'NotDue'
            Should -Invoke -ModuleName AutomaticPKI Request-APKIAdcsRpcCertificate -Times 0 -Exactly
            Get-SavedOrder | Should -BeNullOrEmpty
        }

        It 'renews an Active order that is not due with -Force, without asking Test-APKIRenewalDue' {
            Mock -ModuleName AutomaticPKI Test-APKIRenewalDue { [pscustomobject]@{ Due = $false; Reason = 'fine'; NotAfter = (Get-Date).AddDays(200); RenewAfter = (Get-Date).AddDays(100) } }
            $r = Invoke-Renewal -Order (New-RenewalOrder -Status 'Active') -Force
            $r.Outcome | Should -Be 'Renewed'
            Should -Invoke -ModuleName AutomaticPKI Test-APKIRenewalDue -Times 0 -Exactly
        }
    }

    Context 'Issued' {
        It 'swaps, records thumbprints and saves the order as Active (<Status>)' -TestCases @(
            @{ Status = 'Approved' }
            @{ Status = 'Active' }
            @{ Status = 'Failed' }
        ) {
            $r = Invoke-Renewal -Order (New-RenewalOrder -Status $Status) -RevocationPolicy 'Skip'
            $r.Outcome | Should -Be 'Renewed'
            $r.Thumbprint | Should -Be $script:NewThumb
            Should -Invoke -ModuleName AutomaticPKI Invoke-APKISwapWithRollback -Times 1 -Exactly -ParameterFilter {
                $NewThumbprint -eq ('B2' * 20) -and $RevocationPolicy -eq 'Skip'
            }
            $saved = Get-SavedOrder
            $saved.Status | Should -Be 'Active'
            $saved.CurrentThumbprint | Should -Be $script:NewThumb
            $saved.PreviousThumbprint | Should -Be $script:OldThumb
            $saved.LastError | Should -BeNullOrEmpty
            $saved.LastRenewal | Should -BeOfType [string]
            { [System.DateTimeOffset]::Parse($saved.LastRenewal, [System.Globalization.CultureInfo]::InvariantCulture) } | Should -Not -Throw
        }

        It 'does not modify the caller''s order object' {
            $order = New-RenewalOrder
            $null = Invoke-Renewal -Order $order
            $order.Status | Should -Be 'Approved'
            $order.CurrentThumbprint | Should -Be $script:OldThumb
        }

        It 'sets no PreviousThumbprint for a first issuance' {
            $null = Invoke-Renewal -Order (New-RenewalOrder -Current '')
            $saved = Get-SavedOrder
            $saved.CurrentThumbprint | Should -Be $script:NewThumb
            $saved.PreviousThumbprint | Should -BeNullOrEmpty
        }

        It 'keeps the old thumbprint and marks the order Failed when the swap fails' {
            Mock -ModuleName AutomaticPKI Invoke-APKISwapWithRollback {
                [pscustomobject]@{ Success = $false; Outcome = 'RolledBack'; ActiveThumbprint = ('A1' * 20); Error = 'Health check failed; rolled back.' }
            }
            $r = Invoke-Renewal -Order (New-RenewalOrder -Status 'Active') -Force
            $r.Outcome | Should -Be 'Failed'
            $saved = Get-SavedOrder
            $saved.Status | Should -Be 'Failed'
            $saved.CurrentThumbprint | Should -Be $script:OldThumb
            $saved.PreviousThumbprint | Should -BeNullOrEmpty
            $saved.LastError | Should -Match 'rolled back'
            # The new, unbound certificate is discarded so retries do not pile up certificates.
            Should -Invoke -ModuleName AutomaticPKI Remove-APKIMachineCertificate -Times 1 -Exactly -ParameterFilter { $Thumbprint -eq ('B2' * 20) }
        }

        It 'never deletes the new certificate when the rollback failed' {
            Mock -ModuleName AutomaticPKI Invoke-APKISwapWithRollback {
                [pscustomobject]@{ Success = $false; Outcome = 'RollbackFailed'; ActiveThumbprint = ('A1' * 20); Error = 'Rollback failed.' }
            }
            $null = Invoke-Renewal -Order (New-RenewalOrder -Status 'Active') -Force
            Should -Invoke -ModuleName AutomaticPKI Remove-APKIMachineCertificate -Times 0 -Exactly
            (Get-SavedOrder).CurrentThumbprint | Should -Be $script:OldThumb
        }

        It 'never deletes the new certificate when IIS still binds it' {
            Mock -ModuleName AutomaticPKI Invoke-APKISwapWithRollback {
                [pscustomobject]@{ Success = $false; Outcome = 'RolledBack'; ActiveThumbprint = ('A1' * 20); Error = 'x' }
            }
            Mock -ModuleName AutomaticPKI Get-APKIBoundThumbprint { @(('A1' * 20), ('B2' * 20)) }
            $null = Invoke-Renewal -Order (New-RenewalOrder -Status 'Active') -Force
            Should -Invoke -ModuleName AutomaticPKI Remove-APKIMachineCertificate -Times 0 -Exactly
        }
    }

    Context 'Pending, Denied and Failed provider results' {
        It 'records a pending request and notifies' {
            $global:APKITestProviderResult = New-ProviderResult -Status 'Pending' -RequestId '42' -Message 'pending approval'
            $r = Invoke-Renewal -Order (New-RenewalOrder)
            $r.Outcome | Should -Be 'Pending'
            $saved = Get-SavedOrder
            $saved.Status | Should -Be 'Pending'
            $saved.PendingRequestId | Should -Be '42'
            $saved.CurrentThumbprint | Should -Be $script:OldThumb
            Should -Invoke -ModuleName AutomaticPKI Invoke-APKISwapWithRollback -Times 0 -Exactly
            Should -Invoke -ModuleName AutomaticPKI Send-APKINotification -Times 1 -Exactly -ParameterFilter { $EventId -eq 1002 }
        }

        It 'collects a pending request (Pending -> Receive -> Issued -> Active)' {
            $r = Invoke-Renewal -Order (New-RenewalOrder -Status 'Pending' -PendingRequestId '42')
            $r.Outcome | Should -Be 'Renewed'
            Should -Invoke -ModuleName AutomaticPKI Receive-APKIAdcsRpcCertificate -Times 1 -Exactly -ParameterFilter { $RequestId -eq '42' }
            Should -Invoke -ModuleName AutomaticPKI Request-APKIAdcsRpcCertificate -Times 0 -Exactly
            $saved = Get-SavedOrder
            $saved.Status | Should -Be 'Active'
            $saved.CurrentThumbprint | Should -Be $script:NewThumb
            $saved.PreviousThumbprint | Should -Be $script:OldThumb
            $saved.PendingRequestId | Should -BeNullOrEmpty
        }

        It 'stays Pending without a second notification while the CA has not decided' {
            $global:APKITestProviderResult = New-ProviderResult -Status 'Pending' -RequestId '42'
            $r = Invoke-Renewal -Order (New-RenewalOrder -Status 'Pending' -PendingRequestId '42')
            $r.Outcome | Should -Be 'Pending'
            (Get-SavedOrder).PendingRequestId | Should -Be '42'
            Should -Invoke -ModuleName AutomaticPKI Send-APKINotification -Times 0 -Exactly
        }

        It 'keeps a pending request when retrieval fails transiently' {
            $global:APKITestProviderResult = New-ProviderResult -Status 'Failed' -RequestId '42' -Message 'CA unavailable'
            $r = Invoke-Renewal -Order (New-RenewalOrder -Status 'Pending' -PendingRequestId '42')
            $r.Outcome | Should -Be 'Failed'
            $saved = Get-SavedOrder
            $saved.Status | Should -Be 'Pending'
            $saved.PendingRequestId | Should -Be '42'
            $saved.LastError | Should -Be 'CA unavailable'
        }

        It 'marks the order Failed on <Status> and notifies with <ExpectedEventId>' -TestCases @(
            @{ Status = 'Denied'; ExpectedEventId = 3001 }
            @{ Status = 'Failed'; ExpectedEventId = 3000 }
        ) {
            $global:APKITestProviderResult = New-ProviderResult -Status $Status -RequestId '9' -Message "CA said $Status"
            $r = Invoke-Renewal -Order (New-RenewalOrder -Status 'Active') -Force
            $r.Outcome | Should -Be 'Failed'
            $saved = Get-SavedOrder
            $saved.Status | Should -Be 'Failed'
            $saved.LastError | Should -Be "CA said $Status"
            $saved.CurrentThumbprint | Should -Be $script:OldThumb
            $saved.PendingRequestId | Should -BeNullOrEmpty
            Should -Invoke -ModuleName AutomaticPKI Send-APKINotification -Times 1 -Exactly -ParameterFilter { $EventId -eq $ExpectedEventId }
            Should -Invoke -ModuleName AutomaticPKI Invoke-APKISwapWithRollback -Times 0 -Exactly
        }

        It 'treats a denied pending request as Failed and clears the request ID' {
            $global:APKITestProviderResult = New-ProviderResult -Status 'Denied' -RequestId '42' -Message 'denied'
            $null = Invoke-Renewal -Order (New-RenewalOrder -Status 'Pending' -PendingRequestId '42')
            $saved = Get-SavedOrder
            $saved.Status | Should -Be 'Failed'
            $saved.PendingRequestId | Should -BeNullOrEmpty
        }

        It 'marks the order Failed when the AdcsCep provider fails' {
            $order = New-RenewalOrder
            $order.Provider = 'AdcsCep'
            $order.ProviderSettings = $null
            Mock -ModuleName AutomaticPKI Request-APKIAdcsCepCertificate { [pscustomobject]@{ Status = 'Failed'; Thumbprint = $null; RequestId = $null; Message = 'cep failed' } }
            $r = Invoke-Renewal -Order $order
            $r.Outcome | Should -Be 'Failed'
            (Get-SavedOrder).Status | Should -Be 'Failed'
        }
    }

    Context 'expiry warning' {
        It 'logs 2000 and notifies when the certificate expires within 7 days and renewal fails' {
            Mock -ModuleName AutomaticPKI Test-APKIRenewalDue { [pscustomobject]@{ Due = $true; Reason = 'due'; NotAfter = (Get-Date).AddDays(3); RenewAfter = (Get-Date).AddDays(-20) } }
            $global:APKITestProviderResult = New-ProviderResult -Status 'Failed' -Message 'CA down'
            $null = Invoke-Renewal -Order (New-RenewalOrder -Status 'Active')
            Should -Invoke -ModuleName AutomaticPKI Write-APKILog -Times 1 -Exactly -ParameterFilter { $EventId -eq 2000 }
            Should -Invoke -ModuleName AutomaticPKI Send-APKINotification -Times 1 -Exactly -ParameterFilter { $EventId -eq 2000 -and $Level -eq 'Warning' }
        }

        It 'does not warn when the certificate has more than 7 days left' {
            $global:APKITestProviderResult = New-ProviderResult -Status 'Failed' -Message 'CA down'
            $null = Invoke-Renewal -Order (New-RenewalOrder -Status 'Active')
            Should -Invoke -ModuleName AutomaticPKI Write-APKILog -Times 0 -Exactly -ParameterFilter { $EventId -eq 2000 }
        }

        It 'does not warn when renewal succeeded' {
            Mock -ModuleName AutomaticPKI Test-APKIRenewalDue { [pscustomobject]@{ Due = $true; Reason = 'due'; NotAfter = (Get-Date).AddDays(3); RenewAfter = (Get-Date).AddDays(-20) } }
            $null = Invoke-Renewal -Order (New-RenewalOrder -Status 'Active')
            Should -Invoke -ModuleName AutomaticPKI Write-APKILog -Times 0 -Exactly -ParameterFilter { $EventId -eq 2000 }
        }
    }
}
