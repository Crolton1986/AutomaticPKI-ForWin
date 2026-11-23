# Step "Network": internal Hyper-V switch, host gateway address and NAT. Idempotent.

function Install-LabNetwork {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Lab
    )
    $net = $Lab.Network
    $prefix = '{0}/{1}' -f $net.Prefix, $net.PrefixLength

    if (Get-VMSwitch -Name $net.SwitchName -ErrorAction SilentlyContinue) {
        Write-LabStep "Switch '$($net.SwitchName)' exists"
    }
    else {
        Write-LabStep "Creating internal switch '$($net.SwitchName)'"
        $null = New-VMSwitch -Name $net.SwitchName -SwitchType Internal -ErrorAction Stop
    }

    $alias = 'vEthernet ({0})' -f $net.SwitchName
    $hostIp = Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -eq $net.Gateway }
    if ($hostIp) {
        Write-LabStep "Host address $($net.Gateway) on '$alias' exists"
    }
    else {
        Write-LabStep "Assigning $($net.Gateway)/$($net.PrefixLength) to '$alias'"
        $null = New-NetIPAddress -InterfaceAlias $alias -IPAddress $net.Gateway -PrefixLength $net.PrefixLength -ErrorAction Stop
    }

    $nat = Get-NetNat -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $net.NatName }
    if ($nat) {
        if ($nat.InternalIPInterfaceAddressPrefix -ne $prefix) {
            throw "NAT '$($net.NatName)' exists with prefix $($nat.InternalIPInterfaceAddressPrefix), expected $prefix. Remove it or change LabConfig."
        }
        Write-LabStep "NAT '$($net.NatName)' exists"
    }
    else {
        $other = Get-NetNat -ErrorAction SilentlyContinue
        if ($other) {
            # Windows supports one NAT network per host; a second New-NetNat fails.
            Write-Warning "Another NAT exists on this host ($(@($other | ForEach-Object { $_.Name }) -join ', ')). New-NetNat may fail; see README."
        }
        Write-LabStep "Creating NAT '$($net.NatName)' for $prefix"
        $null = New-NetNat -Name $net.NatName -InternalIPInterfaceAddressPrefix $prefix -ErrorAction Stop
    }
}
