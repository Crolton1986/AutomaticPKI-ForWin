# Shared helpers for the AdcsCep provider unit tests. Dot-source from BeforeAll.

function Import-AdcsCepTestModule {
    $modulePath = Join-Path $PSScriptRoot '../../../src/AutomaticPKI/AutomaticPKI.psd1'
    Import-Module $modulePath -Force -ErrorAction Stop

    # Get-APKISecret is owned by T2. Define a throwing stub in the module scope only when it
    # does not exist yet, so it can be mocked; tests always mock it.
    InModuleScope AutomaticPKI {
        if (-not (Get-Command -Name Get-APKISecret -CommandType Function -ErrorAction SilentlyContinue)) {
            function script:Get-APKISecret {
                [CmdletBinding()]
                param([string]$Name)
                throw "Get-APKISecret test stub called for '$Name' without a mock."
            }
        }
    }
}

function Get-AdcsCepTestOrder {
    param(
        [string]$CepUrl = 'https://cep.corp.local/ADPolicyProvider_CEP_Kerberos/service.svc/CEP',
        [string]$Template = 'WebServer',
        [AllowNull()]
        [string]$CredentialRef = $null,
        [string[]]$Hostnames = @('www.contoso.com', 'contoso.com')
    )

    $credRefValue = $null
    if ($CredentialRef) { $credRefValue = $CredentialRef }

    [pscustomobject]@{
        Id                 = 'contoso-web'
        Status             = 'Approved'
        SiteName           = 'Contoso Web'
        Hostnames          = $Hostnames
        Bindings           = @()
        Provider           = 'AdcsCep'
        ProviderSettings   = [pscustomobject]@{
            CepUrl        = $CepUrl
            Template      = $Template
            CredentialRef = $credRefValue
        }
        Key                = [pscustomobject]@{ Algorithm = 'RSA'; Length = 2048; Exportable = $false }
        KeyMode            = 'OnHost'
        CreateBinding      = $true
        HttpProbe          = [pscustomobject]@{ Enabled = $true; Path = '/'; ExpectStatusBelow = 500 }
        RenewalDaysBefore  = $null
        CurrentThumbprint  = $null
        PreviousThumbprint = $null
        PendingRequestId   = $null
        LastRenewal        = $null
        LastError          = $null
    }
}

function Get-AdcsCepTestEnrollmentResult {
    # Stand-in for Microsoft.CertificateServices.Commands.EnrollmentResult.
    param(
        [Parameter(Mandatory)]
        [string]$Status,
        [string]$CertificateThumbprint,
        [string]$RequestThumbprint
    )

    $certificate = $null
    if ($CertificateThumbprint) { $certificate = [pscustomobject]@{ Thumbprint = $CertificateThumbprint } }
    $request = $null
    if ($RequestThumbprint) { $request = [pscustomobject]@{ Thumbprint = $RequestThumbprint } }

    [pscustomobject]@{
        Status      = $Status
        Certificate = $certificate
        Request     = $request
    }
}

function Get-AdcsCepTestCredential {
    New-Object System.Management.Automation.PSCredential -ArgumentList 'CORP\svc-cep', (New-Object System.Security.SecureString)
}
