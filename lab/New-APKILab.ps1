<#
.SYNOPSIS
    Builds (or completes) the AutomaticPKI Hyper-V lab: DC01, CA01, CA02, CES01, WEB01, WEB02.
.DESCRIPTION
    Run elevated on the Hyper-V host with Windows PowerShell 5.1. Every step checks before it
    creates, so any step can be rerun after a failure or to repair drift:
        Network  internal switch, host gateway IP, NAT
        VMs      base disk (from ISO if needed), VMs, first boot, static IP/DNS
        Domain   AD DS forest + DNS on DC01, DNS records, CES enrollment account, domain joins
        CA       enterprise CAs on CA01/CA02, APKI templates, template publication, root trust
        CES      CEP (Kerberos + UsernamePassword) and CES (UsernamePassword) on CES01
        Web      IIS and test sites on WEB01 (domain) and WEB02 (workgroup)
    In-guest work uses PowerShell Direct (Invoke-Command -VMName), so the host needs no network
    path to the VMs.
.PARAMETER Step
    One or more steps, or All (default). Steps run in the order listed above.
.PARAMETER AdminCredential
    Lab Administrator password (user name is ignored). Prompted when omitted.
.PARAMETER EnrollUserCredential
    Password for the CEP/CES enrollment account used by WEB02. Prompted when the Domain step runs.
.EXAMPLE
    .\New-APKILab.ps1
.EXAMPLE
    .\New-APKILab.ps1 -Step CA, CES
#>
#Requires -RunAsAdministrator
#Requires -Modules Hyper-V
[CmdletBinding()]
param(
    [ValidateSet('All', 'Network', 'VMs', 'Domain', 'CA', 'CES', 'Web')]
    [string[]]$Step = @('All'),

    [string]$ConfigPath = (Join-Path $PSScriptRoot 'LabConfig.psd1'),

    [pscredential]$AdminCredential,

    [pscredential]$EnrollUserCredential
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

foreach ($file in Get-ChildItem -Path (Join-Path $PSScriptRoot 'Steps') -Filter '*.ps1') {
    . $file.FullName
}

$lab = Import-LabConfig -Path $ConfigPath
$order = @('Network', 'VMs', 'Domain', 'CA', 'CES', 'Web')
$run = @($order | Where-Object { $Step -contains 'All' -or $Step -contains $_ })

$admin = $null
if ($run | Where-Object { $_ -ne 'Network' }) {
    $admin = Get-LabAdminCredential -Lab $lab -Credential $AdminCredential
}
$started = Get-Date

foreach ($current in $run) {
    Write-LabStep "=== Step $current ==="
    switch ($current) {
        'Network' {
            Install-LabNetwork -Lab $lab
        }
        'VMs' {
            Build-LabBaseImage -Lab $lab
            foreach ($vm in $lab.VMs) {
                Install-LabVM -Lab $lab -AdminCredential $admin -VM $vm
            }
        }
        'Domain' {
            if (-not $EnrollUserCredential) {
                $EnrollUserCredential = Get-Credential -UserName $lab.Domain.EnrollUserName -Message "Password for the AD account '$($lab.Domain.EnrollUserName)' (WEB02 uses it for CEP/CES)"
            }
            if (-not $EnrollUserCredential) {
                throw 'An enrollment account credential is required for the Domain step.'
            }
            Install-LabDomainController -Lab $lab -AdminCredential $admin
            Install-LabEnrollmentAccount -Lab $lab -AdminCredential $admin -EnrollUserCredential $EnrollUserCredential
            foreach ($vm in $lab.VMs) {
                if (@('CA', 'CES', 'Web') -contains $vm.Role) {
                    Join-LabDomainMember -Lab $lab -AdminCredential $admin -VMName $vm.Name
                }
            }
        }
        'CA' {
            foreach ($ca in $lab.CertificationAuthorities) {
                Install-LabCertificationAuthority -Lab $lab -AdminCredential $admin -CA $ca
            }
            # The template container exists once the first enterprise CA is installed.
            Install-LabCertificateTemplate -Lab $lab -AdminCredential $admin -Name $lab.Templates.Standard
            Install-LabCertificateTemplate -Lab $lab -AdminCredential $admin -Name $lab.Templates.Approval -RequireApproval $true
            foreach ($ca in $lab.CertificationAuthorities) {
                Publish-LabCATemplate -AdminCredential $admin -CA $ca
            }
            $rootDir = Export-LabRootCertificate -Lab $lab -AdminCredential $admin
            foreach ($vm in $lab.VMs) {
                if (@('CES', 'Web', 'WebWorkgroup') -contains $vm.Role) {
                    Import-LabRootCertificate -Lab $lab -AdminCredential $admin -VMName $vm.Name -CertificateDirectory $rootDir
                }
            }
        }
        'CES' {
            Install-LabEnrollmentService -Lab $lab -AdminCredential $admin
        }
        'Web' {
            foreach ($vm in $lab.VMs) {
                if (@('Web', 'WebWorkgroup') -contains $vm.Role) {
                    Install-LabWebServer -Lab $lab -AdminCredential $admin -VMName $vm.Name
                }
            }
        }
    }
}

$elapsed = (Get-Date) - $started
Write-LabStep ('Done: {0} in {1:hh\:mm\:ss}' -f ($run -join ', '), $elapsed)
if ($run -contains 'CES' -or $run -contains 'Web') {
    $urls = Get-LabEnrollmentUrl -Lab $lab
    Write-LabStep "CEP (Kerberos):     $($urls.CepKerberos)"
    Write-LabStep "CEP (UserName):     $($urls.CepUserName)"
    Write-LabStep "CES (UserName):     $($urls.CesUserName)"
    Write-LabStep 'Next: .\Invoke-APKILabTests.ps1'
}
