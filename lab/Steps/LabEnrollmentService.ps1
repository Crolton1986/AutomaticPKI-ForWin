# Step "CES": Certificate Enrollment Policy web service (Kerberos and UsernamePassword endpoints)
# and Certificate Enrollment Web Service (UsernamePassword) for CA01 on CES01. Idempotent.
#
# CES runs as the CES01 computer account (ApplicationPoolIdentity) on a server other than the CA,
# so CES01 needs constrained delegation with protocol transition to HOST/RPCSS on the CA. The CES
# URL is registered on the CA's AD enrollment object so CEP hands it to clients.

function Get-LabEnrollmentUrl {
    # Returns @{ CepKerberos; CepUserName; CesUserName } for the lab.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Lab
    )
    $cesHost = Get-LabFqdn -Lab $Lab -VMName $Lab.EnrollmentServices.VMName
    $caName = $null
    foreach ($ca in $Lab.CertificationAuthorities) {
        if ($ca.VMName -eq $Lab.EnrollmentServices.CAVMName) { $caName = $ca.CommonName }
    }
    @{
        CepKerberos = 'https://{0}/ADPolicyProvider_CEP_Kerberos/service.svc/CEP' -f $cesHost
        CepUserName = 'https://{0}/ADPolicyProvider_CEP_UsernamePassword/service.svc/CEP' -f $cesHost
        CesUserName = 'https://{0}/{1}_CES_UsernamePassword/service.svc/CES' -f $cesHost, [System.Uri]::EscapeDataString($caName)
    }
}

function Install-LabEnrollmentDelegation {
    # CES01 computer account: trusted to delegate (any protocol) to HOST and RPCSS on the CA.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Lab,

        [Parameter(Mandatory)]
        [hashtable]$AdminCredential
    )
    $dc = @(Get-LabVMConfig -Lab $Lab -Role 'DC')[0]
    $caVM = $Lab.EnrollmentServices.CAVMName
    $caFqdn = Get-LabFqdn -Lab $Lab -VMName $caVM
    $spns = @("HOST/$caFqdn", "HOST/$caVM", "RPCSS/$caFqdn", "RPCSS/$caVM")
    Write-LabStep "Ensuring constrained delegation $($Lab.EnrollmentServices.VMName) -> $caVM (HOST, RPCSS)"
    Invoke-LabGuest -VMName $dc.Name -Credential $AdminCredential.Domain -ArgumentList $Lab.EnrollmentServices.VMName, $spns -ScriptBlock {
        param([string]$ComputerName, [string[]]$Spn)
        $ErrorActionPreference = 'Stop'
        Import-Module ActiveDirectory
        $computer = Get-ADComputer -Identity $ComputerName -Properties 'msDS-AllowedToDelegateTo', TrustedToAuthForDelegation
        $have = @($computer.'msDS-AllowedToDelegateTo')
        $missing = @($Spn | Where-Object { $have -notcontains $_ })
        if ($missing.Count -gt 0) {
            Set-ADComputer -Identity $computer -Add @{ 'msDS-AllowedToDelegateTo' = [string[]]$missing }
        }
        if (-not $computer.TrustedToAuthForDelegation) {
            Set-ADAccountControl -Identity $computer -TrustedToAuthForDelegation $true
        }
    }
}

function Install-LabEnrollmentService {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Lab,

        [Parameter(Mandatory)]
        [hashtable]$AdminCredential
    )
    $vmName = $Lab.EnrollmentServices.VMName
    $fqdn = Get-LabFqdn -Lab $Lab -VMName $vmName
    $caConfig = Get-LabCAConfigString -Lab $Lab -VMName $Lab.EnrollmentServices.CAVMName
    $urls = Get-LabEnrollmentUrl -Lab $Lab

    Install-LabEnrollmentDelegation -Lab $Lab -AdminCredential $AdminCredential

    Write-LabStep "Ensuring CEP (Kerberos, UsernamePassword) and CES (UsernamePassword -> $caConfig) on $vmName"
    Invoke-LabGuest -VMName $vmName -Credential $AdminCredential.Domain -ArgumentList $fqdn, $vmName, $caConfig, $Lab.Templates.Standard, $urls.CesUserName -ScriptBlock {
        param([string]$Fqdn, [string]$ShortName, [string]$CAConfig, [string]$Template, [string]$CesUrl)
        $ErrorActionPreference = 'Stop'
        $null = Install-WindowsFeature -Name ADCS-Enroll-Web-Pol, ADCS-Enroll-Web-Svc, Web-Scripting-Tools -IncludeManagementTools
        Import-Module WebAdministration

        # Pick up the new delegation settings without a reboot.
        $null = & klist.exe -li 0x3e7 purge 2>&1

        # HTTPS certificate for CES01 from CA01 (APKIWebServer allows Domain Computers to enroll).
        $cert = Get-ChildItem -Path 'Cert:\LocalMachine\My' |
            Where-Object { $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date).AddDays(30) -and (@($_.DnsNameList | ForEach-Object { $_.Unicode }) -contains $Fqdn) } |
            Sort-Object -Property NotAfter -Descending | Select-Object -First 1
        if (-not $cert) {
            $enroll = @{
                Template          = $Template
                DnsName           = @($Fqdn, $ShortName)
                SubjectName       = "CN=$Fqdn"
                CertStoreLocation = 'Cert:\LocalMachine\My'
                Url               = 'ldap:'
            }
            $result = Get-Certificate @enroll
            if ($result.Status -ne 'Issued') {
                throw "Get-Certificate for $Fqdn returned $($result.Status)."
            }
            $cert = $result.Certificate
        }
        $thumb = $cert.Thumbprint

        $site = 'Default Web Site'
        if (-not (Get-WebApplication -Site $site -Name 'ADPolicyProvider_CEP_Kerberos')) {
            $null = Install-AdcsEnrollmentPolicyWebService -AuthenticationType Kerberos -SSLCertThumbprint $thumb -Force
        }
        if (-not (Get-WebApplication -Site $site -Name 'ADPolicyProvider_CEP_UsernamePassword')) {
            $null = Install-AdcsEnrollmentPolicyWebService -AuthenticationType UserName -SSLCertThumbprint $thumb -Force
        }
        $caName = $CAConfig.Split('\')[1]
        if (-not (Get-WebApplication -Site $site -Name "${caName}_CES_UsernamePassword")) {
            $ces = @{
                CAConfig                = $CAConfig
                AuthenticationType      = 'UserName'
                SSLCertThumbprint       = $thumb
                ApplicationPoolIdentity = $true
                Force                   = $true
            }
            $null = Install-AdcsEnrollmentWebService @ces
        }

        # Publish the CES URL on the CA's enrollment object; CEP returns it to clients.
        $listing = (& certutil.exe -config $CAConfig -enrollmentServerURL 2>&1) -join "`n"
        if ($listing -notmatch [regex]::Escape($CesUrl)) {
            $out = & certutil.exe -config $CAConfig -enrollmentServerURL $CesUrl UserName 1 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw "certutil -enrollmentServerURL failed: $out"
            }
        }
        & iisreset.exe /noforce | Out-Null
    }
}
