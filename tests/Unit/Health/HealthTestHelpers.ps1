# Shared setup for tests/Unit/Health. Dot-source from BeforeAll.
#
# Health code calls functions owned by parallel tasks (T5 IIS layer, T2 notifications).
# Pester can only Mock commands that exist, so define minimal stubs inside the module when the
# real function is not present yet. Once the real functions are merged the stubs are skipped.

function Import-APKITestModule {
    $manifest = [System.IO.Path]::Combine($PSScriptRoot, '..', '..', '..', 'src', 'AutomaticPKI', 'AutomaticPKI.psd1')
    Import-Module $manifest -Force -ErrorAction Stop

    InModuleScope AutomaticPKI {
        if (-not (Get-Command Get-APKIServerManager -ErrorAction SilentlyContinue)) {
            function script:Get-APKIServerManager {
                [CmdletBinding()]
                param()
                throw 'Get-APKIServerManager stub: mock it.'
            }
        }
        if (-not (Get-Command Save-APKIBindingSnapshot -ErrorAction SilentlyContinue)) {
            function script:Save-APKIBindingSnapshot {
                [CmdletBinding()]
                param($Order)
                throw "Save-APKIBindingSnapshot stub: mock it ($Order)."
            }
        }
        if (-not (Get-Command Restore-APKIBindingSnapshot -ErrorAction SilentlyContinue)) {
            function script:Restore-APKIBindingSnapshot {
                [CmdletBinding()]
                param($Order, $Snapshot)
                throw "Restore-APKIBindingSnapshot stub: mock it ($Order, $Snapshot)."
            }
        }
        if (-not (Get-Command Set-APKIIisCertificateBinding -ErrorAction SilentlyContinue)) {
            function script:Set-APKIIisCertificateBinding {
                [CmdletBinding(SupportsShouldProcess)]
                param($Order, $Thumbprint)
                if ($PSCmdlet.ShouldProcess("$Order", "bind $Thumbprint")) {
                    throw 'Set-APKIIisCertificateBinding stub: mock it.'
                }
            }
        }
        if (-not (Get-Command Send-APKINotification -ErrorAction SilentlyContinue)) {
            function script:Send-APKINotification {
                [CmdletBinding()]
                param($Subject, $Body, $Level, $OrderId)
                throw "Send-APKINotification stub: mock it ($Subject, $Body, $Level, $OrderId)."
            }
        }
    }
}

function Get-APKITestOrder {
    param(
        [object[]]$Bindings,
        [bool]$ProbeEnabled = $false,
        [string]$CurrentThumbprint = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    )
    if (-not $Bindings) {
        $Bindings = @(
            [pscustomobject]@{
                SiteName = 'Contoso'; Protocol = 'https'; IPAddress = '*'; Port = 443
                HostHeader = 'www.contoso.com'; SslFlags = 1; Thumbprint = $CurrentThumbprint
                StoreName = 'My'; NameStatus = 'Usable'; SharedWith = @()
            }
        )
    }
    [pscustomobject]@{
        Id                 = 'contoso'
        Status             = 'Active'
        SiteName           = 'Contoso'
        Hostnames          = @('www.contoso.com')
        Bindings           = $Bindings
        HttpProbe          = [pscustomobject]@{ Enabled = $ProbeEnabled; Path = '/'; ExpectStatusBelow = 500 }
        CurrentThumbprint  = $CurrentThumbprint
        PreviousThumbprint = ''
    }
}
