BeforeAll {
    $script:ModulePath = Join-Path $PSScriptRoot '../../../src/AutomaticPKI/AutomaticPKI.psd1'
    Import-Module $script:ModulePath -Force
    $script:SavedRoot = $env:APKI_ROOT

    function Get-TestOrder {
        param(
            [string]$Id = 'contoso-web',
            [string]$Status = 'Active'
        )
        [pscustomobject]@{
            Id                 = $Id
            Status             = $Status
            SiteName           = 'Contoso Web'
            Hostnames          = @('www.contoso.com')
            Bindings           = @(
                [pscustomobject]@{
                    SiteName   = 'Contoso Web'
                    Protocol   = 'https'
                    IPAddress  = '*'
                    Port       = 443
                    HostHeader = 'www.contoso.com'
                    SslFlags   = 1
                    Thumbprint = ''
                    StoreName  = 'My'
                    NameStatus = 'Usable'
                    SharedWith = @('Other Site')
                }
            )
            Provider           = 'AdcsRpc'
            ProviderSettings   = [pscustomobject]@{ CAConfig = 'ca01.corp.local\Corp Issuing CA'; Template = 'WebServer' }
            Key                = [pscustomobject]@{ Algorithm = 'RSA'; Length = 2048; Exportable = $false }
            KeyMode            = 'OnHost'
            CreateBinding      = $true
            HttpProbe          = [pscustomobject]@{ Enabled = $true; Path = '/'; ExpectStatusBelow = 500 }
            RenewalDaysBefore  = $null
            CurrentThumbprint  = ''
            PreviousThumbprint = ''
            PendingRequestId   = ''
            LastRenewal        = '2026-11-01T10:00:00.0000000Z'
            LastError          = ''
        }
    }
}

AfterAll {
    $env:APKI_ROOT = $script:SavedRoot
}

Describe 'Order data store' {
    BeforeEach {
        $env:APKI_ROOT = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $env:APKI_ROOT -Force | Out-Null
        $script:OrderDir = Join-Path $env:APKI_ROOT 'orders'
        Mock Write-APKILog -ModuleName AutomaticPKI { }
    }

    Context 'Save-APKIOrderData' {
        It 'writes orders/<Id>.json and reads it back with the contract types' {
            $order = Get-TestOrder
            InModuleScope AutomaticPKI -Parameters @{ Order = $order } {
                param($Order)
                Save-APKIOrderData -Order $Order
            }

            Join-Path $script:OrderDir 'contoso-web.json' | Should -Exist
            $read = InModuleScope AutomaticPKI { Get-APKIOrderData -Id 'contoso-web' }

            $read.Id | Should -Be 'contoso-web'
            $read.Status | Should -Be 'Active'
            ($read.Hostnames -is [array]) | Should -BeTrue
            (@($read.Hostnames) -join ',') | Should -Be 'www.contoso.com'
            ($read.Bindings -is [array]) | Should -BeTrue
            @($read.Bindings).Count | Should -Be 1
            $read.Bindings[0].Port | Should -Be 443
            ($read.Bindings[0].SharedWith -is [array]) | Should -BeTrue
            $read.ProviderSettings.CAConfig | Should -Be 'ca01.corp.local\Corp Issuing CA'
            $read.Key.Length | Should -Be 2048
            $read.RenewalDaysBefore | Should -BeNullOrEmpty
            ($read.LastRenewal -is [string]) | Should -BeTrue
            ([datetime]::Parse($read.LastRenewal)).ToUniversalTime() |
                Should -Be ([datetime]::Parse('2026-11-01T10:00:00Z')).ToUniversalTime()
        }

        It 'accepts a hashtable and does not modify the caller object' {
            $order = @{ Id = 'site-b'; Status = 'Proposed'; SiteName = 'Site B'; Hostnames = 'b.contoso.com'; Provider = 'AdcsCep' }
            InModuleScope AutomaticPKI -Parameters @{ Order = $order } {
                param($Order)
                Save-APKIOrderData -Order $Order
            }

            $order.Hostnames | Should -BeOfType [string]
            $read = InModuleScope AutomaticPKI { Get-APKIOrderData -Id 'site-b' }
            ($read.Hostnames -is [array]) | Should -BeTrue
            $read.Provider | Should -Be 'AdcsCep'
        }

        It 'replaces an existing order atomically and leaves no temp files' {
            InModuleScope AutomaticPKI -Parameters @{ Order = (Get-TestOrder) } {
                param($Order)
                Save-APKIOrderData -Order $Order
                $Order.Status = 'Failed'
                $Order.LastError = 'CA unreachable'
                Save-APKIOrderData -Order $Order
            }

            (@(Get-ChildItem -LiteralPath $script:OrderDir | ForEach-Object { $_.Name }) -join ',') | Should -Be 'contoso-web.json'
            (InModuleScope AutomaticPKI { Get-APKIOrderData -Id 'contoso-web' }).Status | Should -Be 'Failed'
        }

        It 'keeps the previous order when the write fails' {
            InModuleScope AutomaticPKI -Parameters @{ Order = (Get-TestOrder) } {
                param($Order)
                Save-APKIOrderData -Order $Order
            }
            Mock Move-APKIFileIntoPlace -ModuleName AutomaticPKI { throw 'simulated crash during rename' }

            {
                InModuleScope AutomaticPKI -Parameters @{ Order = (Get-TestOrder -Status 'Failed') } {
                    param($Order)
                    Save-APKIOrderData -Order $Order
                }
            } | Should -Throw '*simulated crash*'

            (InModuleScope AutomaticPKI { Get-APKIOrderData -Id 'contoso-web' }).Status | Should -Be 'Active'
            @(Get-ChildItem -LiteralPath $script:OrderDir -Filter '*.tmp').Count | Should -Be 0
        }

        It 'rejects an order with <Case>' -TestCases @(
            @{ Case = 'no Status'; Field = 'Status'; Value = $null; Expected = '*Status*' }
            @{ Case = 'an unknown Status'; Field = 'Status'; Value = 'Done'; Expected = "*Status 'Done' is invalid*" }
            @{ Case = 'a lower-case Status'; Field = 'Status'; Value = 'active'; Expected = '*Status*' }
            @{ Case = 'a path in the Id'; Field = 'Id'; Value = '../escape'; Expected = '*Invalid order Id*' }
            @{ Case = 'no SiteName'; Field = 'SiteName'; Value = ''; Expected = '*SiteName is required*' }
            @{ Case = 'an unknown Provider'; Field = 'Provider'; Value = 'Acme'; Expected = "*Provider 'Acme'*" }
            @{ Case = 'an unknown KeyMode'; Field = 'KeyMode'; Value = 'Cloud'; Expected = '*KeyMode*' }
            @{ Case = 'no Hostnames while Active'; Field = 'Hostnames'; Value = @(); Expected = '*Hostnames must contain at least one*' }
        ) {
            $order = Get-TestOrder
            $order.$Field = $Value

            {
                InModuleScope AutomaticPKI -Parameters @{ Order = $order } {
                    param($Order)
                    Save-APKIOrderData -Order $Order
                }
            } | Should -Throw $Expected

            @(Get-ChildItem -LiteralPath $env:APKI_ROOT -Recurse -Filter '*.json').Count | Should -Be 0
        }

        It 'rejects an order without a Hostnames field' {
            $order = Get-TestOrder
            $order.PSObject.Properties.Remove('Hostnames')

            {
                InModuleScope AutomaticPKI -Parameters @{ Order = $order } {
                    param($Order)
                    Save-APKIOrderData -Order $Order
                }
            } | Should -Throw '*Hostnames is required*'
        }

        It 'allows empty Hostnames on a Proposed order' {
            $order = Get-TestOrder -Status 'Proposed'
            $order.Hostnames = @()

            {
                InModuleScope AutomaticPKI -Parameters @{ Order = $order } {
                    param($Order)
                    Save-APKIOrderData -Order $Order
                }
            } | Should -Not -Throw
            @((InModuleScope AutomaticPKI { Get-APKIOrderData -Id 'contoso-web' }).Hostnames).Count | Should -Be 0
        }

        It 'writes nothing with -WhatIf' {
            InModuleScope AutomaticPKI -Parameters @{ Order = (Get-TestOrder) } {
                param($Order)
                Save-APKIOrderData -Order $Order -WhatIf
            }

            Join-Path $script:OrderDir 'contoso-web.json' | Should -Not -Exist
        }
    }

    Context 'Get-APKIOrderData' {
        It 'returns nothing for an unknown Id' {
            InModuleScope AutomaticPKI { Get-APKIOrderData -Id 'missing' } | Should -BeNullOrEmpty
        }

        It 'returns nothing when no orders exist' {
            @(InModuleScope AutomaticPKI { Get-APKIOrderData }).Count | Should -Be 0
        }

        It 'lists all orders sorted by Id' {
            InModuleScope AutomaticPKI -Parameters @{ A = (Get-TestOrder -Id 'zeta'); B = (Get-TestOrder -Id 'alpha') } {
                param($A, $B)
                Save-APKIOrderData -Order $A
                Save-APKIOrderData -Order $B
            }

            $orders = @(InModuleScope AutomaticPKI { Get-APKIOrderData })
            $orders.Count | Should -Be 2
            $orders[0].Id | Should -Be 'alpha'
            $orders[1].Id | Should -Be 'zeta'
        }

        It 'skips a corrupt order file in the list and logs EventId 3004' {
            InModuleScope AutomaticPKI -Parameters @{ Order = (Get-TestOrder -Id 'good') } {
                param($Order)
                Save-APKIOrderData -Order $Order
            }
            Set-Content -LiteralPath (Join-Path $script:OrderDir 'broken.json') -Value '{ "Id": "broken", ' -Encoding UTF8

            $orders = @(InModuleScope AutomaticPKI { Get-APKIOrderData })

            $orders.Count | Should -Be 1
            $orders[0].Id | Should -Be 'good'
            Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter {
                $EventId -eq 3004 -and $OrderId -eq 'broken'
            }
        }

        It 'throws and logs EventId 3004 for a corrupt order requested by Id' {
            New-Item -ItemType Directory -Path $script:OrderDir -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $script:OrderDir 'broken.json') -Value 'not json' -Encoding UTF8

            { InModuleScope AutomaticPKI { Get-APKIOrderData -Id 'broken' } } | Should -Throw '*broken.json*is invalid*'
            Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter { $EventId -eq 3004 }
        }

        It 'rejects a file whose Id does not match its file name' {
            InModuleScope AutomaticPKI -Parameters @{ Order = (Get-TestOrder -Id 'original') } {
                param($Order)
                Save-APKIOrderData -Order $Order
            }
            Rename-Item -LiteralPath (Join-Path $script:OrderDir 'original.json') -NewName 'renamed.json'

            { InModuleScope AutomaticPKI { Get-APKIOrderData -Id 'renamed' } } | Should -Throw '*does not match*'
        }
    }

    Context 'Remove-APKIOrderData' {
        BeforeEach {
            InModuleScope AutomaticPKI -Parameters @{ Order = (Get-TestOrder) } {
                param($Order)
                Save-APKIOrderData -Order $Order
            }
            $script:OrderFile = Join-Path $script:OrderDir 'contoso-web.json'
        }

        It 'deletes the order file' {
            InModuleScope AutomaticPKI { Remove-APKIOrderData -Id 'contoso-web' }

            $script:OrderFile | Should -Not -Exist
        }

        It 'accepts an order from the pipeline' {
            InModuleScope AutomaticPKI { Get-APKIOrderData -Id 'contoso-web' | Remove-APKIOrderData }

            $script:OrderFile | Should -Not -Exist
        }

        It 'keeps the file with -WhatIf' {
            InModuleScope AutomaticPKI { Remove-APKIOrderData -Id 'contoso-web' -WhatIf }

            $script:OrderFile | Should -Exist
        }

        It 'does nothing for an unknown Id' {
            { InModuleScope AutomaticPKI { Remove-APKIOrderData -Id 'missing' } } | Should -Not -Throw
            $script:OrderFile | Should -Exist
        }
    }
}
