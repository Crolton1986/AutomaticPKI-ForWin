# Step "Domain": AD DS forest on DC01 (with DNS), lab DNS records, the CEP/CES enrollment account
# for WEB02, and domain join of CA01, CA02, CES01 and WEB01. Idempotent.

function Install-LabDomainController {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Lab,

        [Parameter(Mandatory)]
        [hashtable]$AdminCredential
    )
    $dc = @(Get-LabVMConfig -Lab $Lab -Role 'DC')[0]
    $cred = Resolve-LabGuestCredential -Lab $Lab -AdminCredential $AdminCredential -VMName $dc.Name

    $role = Invoke-LabGuest -VMName $dc.Name -Credential $cred -ScriptBlock {
        (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole
    }
    $adReady = { Import-Module ActiveDirectory -ErrorAction Stop; $null = Get-ADDomain -ErrorAction Stop; $true }

    if ([int]$role -ge 4) {
        Write-LabStep "$($dc.Name) is already a domain controller"
    }
    else {
        Write-LabStep "Promoting $($dc.Name) to forest root DC for $($Lab.Domain.Name) (10-15 minutes)"
        $boot = Get-LabGuestBootTime -VMName $dc.Name -Credential $cred
        Invoke-LabGuest -VMName $dc.Name -Credential $cred -ArgumentList $Lab.Domain.Name, $Lab.Domain.NetbiosName, $AdminCredential.Password -ScriptBlock {
            param([string]$DomainName, [string]$NetbiosName, [securestring]$SafeModePassword)
            $ErrorActionPreference = 'Stop'
            $null = Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
            $forest = @{
                DomainName                    = $DomainName
                DomainNetbiosName             = $NetbiosName
                SafeModeAdministratorPassword = $SafeModePassword
                InstallDns                    = $true
                NoRebootOnCompletion          = $true
                Force                         = $true
            }
            $null = Install-ADDSForest @forest -WarningAction SilentlyContinue
        }
        # The local account may stop working once promotion has run: restart from the host.
        Invoke-LabGuestReboot -VMName $dc.Name -Credential $cred -CredentialAfter $AdminCredential.Domain -PreviousBootTime $boot -HostRestart -Probe $adReady -TimeoutMinutes 40
    }

    Wait-LabGuest -VMName $dc.Name -Credential $AdminCredential.Domain -Probe $adReady -TimeoutMinutes 20

    # DNS forwarder and lab A records.
    $records = @{}
    foreach ($label in $Lab.Web.DnsRecords.Keys) {
        $records[$label] = (Get-LabVMConfig -Lab $Lab -Name $Lab.Web.DnsRecords[$label]).IPAddress
    }
    $workgroup = @(Get-LabVMConfig -Lab $Lab -Role 'WebWorkgroup')
    foreach ($w in $workgroup) {
        # Not domain-joined, so no dynamic registration.
        $records[$w.Name.ToLowerInvariant()] = $w.IPAddress
    }
    Write-LabStep "Configuring DNS on $($dc.Name)"
    Invoke-LabGuest -VMName $dc.Name -Credential $AdminCredential.Domain -ArgumentList $Lab.Domain.Name, $records, $Lab.Network.DnsForwarder -ScriptBlock {
        param([string]$Zone, [hashtable]$Record, [string]$Forwarder)
        $ErrorActionPreference = 'Stop'
        if ($Forwarder) {
            $current = @((Get-DnsServerForwarder).IPAddress | ForEach-Object { $_.ToString() })
            if ($current -notcontains $Forwarder) {
                Add-DnsServerForwarder -IPAddress $Forwarder
            }
        }
        foreach ($name in $Record.Keys) {
            $ips = @(Get-DnsServerResourceRecord -ZoneName $Zone -Name $name -RRType A -ErrorAction SilentlyContinue |
                    ForEach-Object { $_.RecordData.IPv4Address.ToString() })
            if ($ips.Count -gt 0 -and ($ips.Count -ne 1 -or $ips[0] -ne $Record[$name])) {
                Remove-DnsServerResourceRecord -ZoneName $Zone -Name $name -RRType A -Force
                $ips = @()
            }
            if ($ips.Count -eq 0) {
                Add-DnsServerResourceRecordA -ZoneName $Zone -Name $name -IPv4Address $Record[$name]
            }
        }
    }
}

function Install-LabEnrollmentAccount {
    # Domain user (+ group) that the workgroup host uses for CEP/CES UsernamePassword enrollment.
    # The password is reset on every run so a rerun with a new credential works.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Lab,

        [Parameter(Mandatory)]
        [hashtable]$AdminCredential,

        [Parameter(Mandatory)]
        [pscredential]$EnrollUserCredential
    )
    $dc = @(Get-LabVMConfig -Lab $Lab -Role 'DC')[0]
    Write-LabStep "Ensuring enrollment account '$($Lab.Domain.EnrollUserName)' and group '$($Lab.Domain.EnrollGroup)'"
    Invoke-LabGuest -VMName $dc.Name -Credential $AdminCredential.Domain -ArgumentList $Lab.Domain.EnrollUserName, $Lab.Domain.EnrollGroup, $Lab.Domain.Name, $EnrollUserCredential -ScriptBlock {
        param([string]$UserName, [string]$GroupName, [string]$DomainName, [pscredential]$UserCredential)
        $ErrorActionPreference = 'Stop'
        Import-Module ActiveDirectory
        $group = Get-ADGroup -Filter "Name -eq '$GroupName'"
        if (-not $group) {
            $group = New-ADGroup -Name $GroupName -GroupScope Global -GroupCategory Security -Description 'AutomaticPKI lab: may enroll APKI templates via CES' -PassThru
        }
        $user = Get-ADUser -Filter "SamAccountName -eq '$UserName'"
        if (-not $user) {
            $user = New-ADUser -Name $UserName -SamAccountName $UserName -UserPrincipalName "$UserName@$DomainName" -AccountPassword $UserCredential.Password -Enabled $true -PasswordNeverExpires $true -Description 'AutomaticPKI lab: CEP/CES enrollment for WEB02' -PassThru
        }
        else {
            Set-ADAccountPassword -Identity $user -Reset -NewPassword $UserCredential.Password
            Enable-ADAccount -Identity $user
        }
        $members = @(Get-ADGroupMember -Identity $group | ForEach-Object { $_.SamAccountName })
        if ($members -notcontains $UserName) {
            Add-ADGroupMember -Identity $group -Members $user
        }
    }
}

function Join-LabDomainMember {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Lab,

        [Parameter(Mandatory)]
        [hashtable]$AdminCredential,

        [Parameter(Mandatory)]
        [string]$VMName
    )
    $cred = Resolve-LabGuestCredential -Lab $Lab -AdminCredential $AdminCredential -VMName $VMName
    $joined = Invoke-LabGuest -VMName $VMName -Credential $cred -ArgumentList $Lab.Domain.Name -ScriptBlock {
        param([string]$DomainName)
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem
        $cs.PartOfDomain -and $cs.Domain -eq $DomainName
    }
    if ($joined) {
        Write-LabStep "$VMName is joined to $($Lab.Domain.Name)"
        return
    }
    Write-LabStep "Joining $VMName to $($Lab.Domain.Name)"
    Invoke-LabGuest -VMName $VMName -Credential $cred -ArgumentList $Lab.Domain.Name, $AdminCredential.Domain -ScriptBlock {
        param([string]$DomainName, [pscredential]$DomainCredential)
        $ErrorActionPreference = 'Stop'
        Add-Computer -DomainName $DomainName -Credential $DomainCredential -Force
    }
    Invoke-LabGuestReboot -VMName $VMName -Credential $cred -CredentialAfter $AdminCredential.Domain
}
