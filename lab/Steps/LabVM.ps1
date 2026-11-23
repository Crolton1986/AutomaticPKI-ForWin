# Step "VMs": differencing disk per VM with an injected unattend.xml (computer name, Administrator
# password, time zone), VM creation, first boot, static IP and DNS. Idempotent: existing VMs are
# only started and their IP settings re-applied.

function Get-LabUnattendXml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,

        [Parameter(Mandatory)]
        [securestring]$AdminPassword,

        [Parameter(Mandatory)]
        [string]$TimeZone
    )
    $plain = (New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList 'x', $AdminPassword).GetNetworkCredential().Password
    $esc = [System.Security.SecurityElement]::Escape($plain)
    $arch = 'processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"'
    @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" $arch>
      <ComputerName>$ComputerName</ComputerName>
      <TimeZone>$TimeZone</TimeZone>
    </component>
    <component name="Microsoft-Windows-TerminalServices-LocalSessionManager" $arch>
      <fDenyTSConnections>false</fDenyTSConnections>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-International-Core" $arch>
      <InputLocale>en-US</InputLocale>
      <SystemLocale>en-US</SystemLocale>
      <UILanguage>en-US</UILanguage>
      <UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-Shell-Setup" $arch>
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <SkipMachineOOBE>true</SkipMachineOOBE>
        <ProtectYourPC>3</ProtectYourPC>
      </OOBE>
      <UserAccounts>
        <AdministratorPassword>
          <Value>$esc</Value>
          <PlainText>true</PlainText>
        </AdministratorPassword>
      </UserAccounts>
    </component>
  </settings>
</unattend>
"@
}

function Install-LabUnattendFile {
    # Writes unattend.xml into the Windows volume of a (new) differencing disk.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VhdPath,

        [Parameter(Mandatory)]
        [string]$Content
    )
    $disk = Mount-VHD -Path $VhdPath -Passthru -ErrorAction Stop | Get-Disk
    try {
        $target = $null
        foreach ($part in @(Get-Partition -DiskNumber $disk.Number)) {
            if ($part.Type -eq 'Reserved' -or $part.Type -eq 'System' -or $part.Size -lt 2GB) { continue }
            if (-not $part.DriveLetter -or $part.DriveLetter -eq [char]0) {
                Add-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber -AssignDriveLetter -ErrorAction SilentlyContinue
                $part = Get-Partition -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber
            }
            if ($part.DriveLetter -and (Test-Path -LiteralPath ('{0}:\Windows\System32' -f $part.DriveLetter))) {
                $target = '{0}:\Windows\Panther' -f $part.DriveLetter
                break
            }
        }
        if (-not $target) {
            throw "No Windows volume found in $VhdPath."
        }
        $null = New-Item -ItemType Directory -Path $target -Force
        Set-Content -LiteralPath (Join-Path $target 'unattend.xml') -Value $Content -Encoding UTF8
    }
    finally {
        Dismount-VHD -Path $VhdPath -ErrorAction SilentlyContinue
    }
}

function Install-LabVM {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Lab,

        [Parameter(Mandatory)]
        [hashtable]$AdminCredential,

        [Parameter(Mandatory)]
        [hashtable]$VM
    )
    $name = $VM.Name
    $existing = Get-VM -Name $name -ErrorAction SilentlyContinue
    if ($existing) {
        Write-LabStep "VM $name exists"
    }
    else {
        $baseVhd = $Lab.BaseImage.BaseVhdPath
        $vmDir = Join-Path $Lab.VMPath $name
        $ext = [System.IO.Path]::GetExtension($baseVhd)
        $vhd = Join-Path $vmDir ('{0}{1}' -f $name, $ext)
        if (-not (Test-Path -LiteralPath $vmDir)) {
            $null = New-Item -ItemType Directory -Path $vmDir -Force
        }
        if (Test-Path -LiteralPath $vhd) {
            # Disk without a VM: left over from an interrupted run. Start clean.
            Remove-Item -LiteralPath $vhd -Force
        }
        Write-LabStep "Creating differencing disk for $name"
        $null = New-VHD -Path $vhd -ParentPath $baseVhd -Differencing -ErrorAction Stop
        $xml = Get-LabUnattendXml -ComputerName $name -AdminPassword $AdminCredential.Password -TimeZone $Lab.TimeZone
        Install-LabUnattendFile -VhdPath $vhd -Content $xml

        Write-LabStep "Creating VM $name"
        $null = New-VM -Name $name -Path $Lab.VMPath -Generation $Lab.Generation -MemoryStartupBytes $VM.MemoryBytes -VHDPath $vhd -SwitchName $Lab.Network.SwitchName -ErrorAction Stop
        Set-VM -Name $name -ProcessorCount $VM.ProcessorCount -StaticMemory -AutomaticCheckpointsEnabled $false -AutomaticStopAction ShutDown -ErrorAction Stop
        Enable-VMIntegrationService -VMName $name -Name 'Guest Service Interface' -ErrorAction SilentlyContinue
    }

    if ((Get-VM -Name $name).State -ne 'Running') {
        Write-LabStep "Starting $name"
        Start-VM -Name $name -ErrorAction Stop
    }

    $cred = Resolve-LabGuestCredential -Lab $Lab -AdminCredential $AdminCredential -VMName $name
    Write-LabStep "Waiting for $name (first boot runs specialize/OOBE, several minutes)"
    Wait-LabGuest -VMName $name -Credential $cred -TimeoutMinutes 40

    $dcIp = @(Get-LabVMConfig -Lab $Lab -Role 'DC')[0].IPAddress
    $publicDns = $Lab.Network.DnsForwarder
    if (-not $publicDns) {
        $publicDns = $Lab.Network.Gateway
    }
    $dns = @($dcIp)
    if ($VM.Role -eq 'DC') {
        # Before promotion DC01 has no DNS server yet; Install-ADDSForest switches it to loopback.
        $dns = @($publicDns)
    }
    if ($VM.Role -eq 'WebWorkgroup' -and $Lab.Web.WorkgroupNameResolution -eq 'Hosts') {
        # apki.lab names come from the hosts file (Web step).
        $dns = @($publicDns)
    }

    Write-LabStep "Configuring $name network: $($VM.IPAddress)/$($Lab.Network.PrefixLength)"
    Invoke-LabGuest -VMName $name -Credential $cred -ArgumentList $VM.IPAddress, $Lab.Network.PrefixLength, $Lab.Network.Gateway, $dns, ($VM.Role -eq 'DC') -ScriptBlock {
        param([string]$Address, [int]$PrefixLength, [string]$Gateway, [string[]]$DnsServer, [bool]$IsDC)
        $ErrorActionPreference = 'Stop'
        $adapter = @(Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Sort-Object -Property ifIndex)[0]
        $current = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue)
        if (-not ($current | Where-Object { $_.IPAddress -eq $Address })) {
            Set-NetIPInterface -InterfaceIndex $adapter.ifIndex -Dhcp Disabled
            $current | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
            Get-NetRoute -InterfaceIndex $adapter.ifIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
            $null = New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $Address -PrefixLength $PrefixLength -DefaultGateway $Gateway
        }
        # A promoted DC points at itself; leave its DNS client alone.
        $isPromoted = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole -ge 4
        if (-not ($IsDC -and $isPromoted)) {
            Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $DnsServer
        }
        # Lab only: allow ping and file/printer sharing for troubleshooting.
        Get-NetFirewallRule -DisplayGroup 'File and Printer Sharing' -ErrorAction SilentlyContinue | Enable-NetFirewallRule
        # The unattend file holds the Administrator password in clear text; it is not needed after setup.
        foreach ($f in @('C:\Windows\Panther\unattend.xml', 'C:\Windows\Panther\Unattend\unattend.xml')) {
            if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force }
        }
    }
}
