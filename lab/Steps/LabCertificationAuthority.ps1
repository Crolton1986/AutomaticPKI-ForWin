# Step "CA" (part 1): enterprise CAs on CA01/CA02 with an HTTP CRL/AIA location, template
# publication per CA, and root certificate distribution to lab hosts. Idempotent.

function Install-LabCertificationAuthority {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Lab,

        [Parameter(Mandatory)]
        [hashtable]$AdminCredential,

        [Parameter(Mandatory)]
        [hashtable]$CA
    )
    Write-LabStep "Ensuring enterprise CA '$($CA.CommonName)' on $($CA.VMName)"
    Invoke-LabGuest -VMName $CA.VMName -Credential $AdminCredential.Domain -ArgumentList $CA.CommonName -ScriptBlock {
        param([string]$CommonName)
        $ErrorActionPreference = 'Stop'
        $cfgKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
        $active = $null
        if (Test-Path -LiteralPath $cfgKey) {
            $active = (Get-ItemProperty -LiteralPath $cfgKey -ErrorAction SilentlyContinue).Active
        }
        if ($active -and $active -ne $CommonName) {
            throw "A different CA ('$active') is installed on $env:COMPUTERNAME."
        }
        if (-not $active) {
            $null = Install-WindowsFeature -Name ADCS-Cert-Authority -IncludeManagementTools
            # Second root instead of a subordinate: one non-interactive call, no dependency on
            # CA01 being online or on SubCA issuance, safe to rerun. See lab/README.md.
            $ca = @{
                CAType              = 'EnterpriseRootCA'
                CACommonName        = $CommonName
                CryptoProviderName  = 'RSA#Microsoft Software Key Storage Provider'
                KeyLength           = 2048
                HashAlgorithmName   = 'SHA256'
                ValidityPeriod      = 'Years'
                ValidityPeriodUnits = 10
                Force               = $true
            }
            $null = Install-AdcsCertificationAuthority @ca
        }
        if ((Get-Service -Name CertSvc).Status -ne 'Running') {
            Start-Service -Name CertSvc
        }

        # Serve CertEnroll over HTTP so the http:// CDP/AIA URLs in issued certificates work for
        # hosts that cannot read the LDAP locations (the workgroup host).
        $null = Install-WindowsFeature -Name Web-Server, Web-Scripting-Tools
        Import-Module WebAdministration
        $site = 'Default Web Site'
        if (-not (Get-WebVirtualDirectory -Site $site -Name 'CertEnroll')) {
            $null = New-WebVirtualDirectory -Site $site -Name 'CertEnroll' -PhysicalPath (Join-Path $env:SystemRoot 'System32\CertSrv\CertEnroll')
        }
        # Delta CRL file names contain '+'.
        Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location "$site/CertEnroll" -Filter 'system.webServer/security/requestFiltering' -Name 'allowDoubleEscaping' -Value $true
        $null = & certutil.exe -crl
    }
}

function Publish-LabCATemplate {
    # Makes the CA issue exactly the configured templates (Exclusive) or at least them.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AdminCredential,

        [Parameter(Mandatory)]
        [hashtable]$CA
    )
    Write-LabStep "Publishing templates on $($CA.VMName): $($CA.Templates -join ', ')$(if ($CA.Exclusive) { ' (only these)' })"
    Invoke-LabGuest -VMName $CA.VMName -Credential $AdminCredential.Domain -ArgumentList ([string[]]$CA.Templates), $CA.Exclusive -ScriptBlock {
        param([string[]]$Template, [bool]$Exclusive)
        $ErrorActionPreference = 'Stop'
        Import-Module ADCSAdministration
        $current = @(Get-CATemplate | ForEach-Object { $_.Name })
        foreach ($t in $Template) {
            if ($current -contains $t) { continue }
            # A template created moments ago may not be visible to the CA yet.
            $done = $false
            for ($i = 0; $i -lt 8 -and -not $done; $i++) {
                try {
                    Add-CATemplate -Name $t -Force
                    $done = $true
                }
                catch {
                    Start-Sleep -Seconds 15
                }
            }
            if (-not $done) {
                throw "Add-CATemplate $t failed on $env:COMPUTERNAME."
            }
        }
        if ($Exclusive) {
            foreach ($c in $current) {
                if ($Template -notcontains $c) {
                    Remove-CATemplate -Name $c -Force
                }
            }
        }
    }
}

function Export-LabRootCertificate {
    # Copies each CA certificate to <VMPath>\RootCertificates\<VMName>.cer on the host.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Lab,

        [Parameter(Mandatory)]
        [hashtable]$AdminCredential
    )
    $dir = Join-Path $Lab.VMPath 'RootCertificates'
    if (-not (Test-Path -LiteralPath $dir)) {
        $null = New-Item -ItemType Directory -Path $dir -Force
    }
    foreach ($ca in $Lab.CertificationAuthorities) {
        $guestPath = 'C:\Windows\Temp\apki-lab-ca.cer'
        Invoke-LabGuest -VMName $ca.VMName -Credential $AdminCredential.Domain -ArgumentList $guestPath -ScriptBlock {
            param([string]$Path)
            $out = & certutil.exe -f -ca.cert $Path 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw "certutil -ca.cert failed: $out"
            }
        }
        Copy-LabItemFromGuest -VMName $ca.VMName -Credential $AdminCredential.Domain -Path $guestPath -Destination (Join-Path $dir ('{0}.cer' -f $ca.VMName))
    }
    $dir
}

function Import-LabRootCertificate {
    # Puts every lab CA certificate into LocalMachine\Root on the VM (needed on the workgroup host;
    # on domain members it saves waiting for Group Policy) and refreshes policy on members.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Lab,

        [Parameter(Mandatory)]
        [hashtable]$AdminCredential,

        [Parameter(Mandatory)]
        [string]$VMName,

        [Parameter(Mandatory)]
        [string]$CertificateDirectory
    )
    $cred = Resolve-LabGuestCredential -Lab $Lab -AdminCredential $AdminCredential -VMName $VMName
    $guestDir = 'C:\Windows\Temp\apki-lab-roots'
    Invoke-LabGuest -VMName $VMName -Credential $cred -ArgumentList $guestDir -ScriptBlock {
        param([string]$Path)
        if (-not (Test-Path -LiteralPath $Path)) { $null = New-Item -ItemType Directory -Path $Path -Force }
    }
    foreach ($file in Get-ChildItem -LiteralPath $CertificateDirectory -Filter '*.cer') {
        Copy-LabItemToGuest -VMName $VMName -Credential $cred -Path $file.FullName -Destination (Join-Path $guestDir $file.Name)
    }
    Write-LabStep "Trusting lab root CAs on $VMName"
    Invoke-LabGuest -VMName $VMName -Credential $cred -ArgumentList $guestDir -ScriptBlock {
        param([string]$Path)
        $ErrorActionPreference = 'Stop'
        foreach ($f in Get-ChildItem -LiteralPath $Path -Filter '*.cer') {
            $cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $f.FullName
            if (-not (Test-Path -LiteralPath ('Cert:\LocalMachine\Root\{0}' -f $cert.Thumbprint))) {
                $null = Import-Certificate -FilePath $f.FullName -CertStoreLocation 'Cert:\LocalMachine\Root'
            }
        }
        if ((Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain) {
            $null = & gpupdate.exe /target:computer /force 2>&1
            $null = & certutil.exe -pulse 2>&1
        }
    }
}
