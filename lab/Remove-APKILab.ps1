<#
.SYNOPSIS
    Tears down the AutomaticPKI Hyper-V lab: VMs (with their disks), NAT, host IP and switch.
.DESCRIPTION
    Removes only objects named in LabConfig.psd1. The base disk is kept unless -IncludeBaseImage
    is given. Supports -WhatIf and -Confirm.
.EXAMPLE
    .\Remove-APKILab.ps1 -WhatIf
.EXAMPLE
    .\Remove-APKILab.ps1 -Confirm:$false
#>
#Requires -RunAsAdministrator
#Requires -Modules Hyper-V
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'LabConfig.psd1'),

    [switch]$IncludeBaseImage
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$lab = Import-PowerShellDataFile -Path $ConfigPath

foreach ($vmCfg in $lab.VMs) {
    $vm = Get-VM -Name $vmCfg.Name -ErrorAction SilentlyContinue
    $vmDir = Join-Path $lab.VMPath $vmCfg.Name
    if ($vm) {
        if ($PSCmdlet.ShouldProcess($vmCfg.Name, 'Stop and remove VM')) {
            if ($vm.State -ne 'Off') {
                Stop-VM -Name $vmCfg.Name -TurnOff -Force -Confirm:$false
            }
            # Disk paths before the VM object is gone.
            $disks = @(Get-VMHardDiskDrive -VMName $vmCfg.Name | ForEach-Object { $_.Path })
            Remove-VM -Name $vmCfg.Name -Force -Confirm:$false
            foreach ($d in $disks) {
                if ($d -and $d -ne $lab.BaseImage.BaseVhdPath -and (Test-Path -LiteralPath $d)) {
                    Remove-Item -LiteralPath $d -Force -Confirm:$false
                }
            }
        }
    }
    if (Test-Path -LiteralPath $vmDir) {
        if ($PSCmdlet.ShouldProcess($vmDir, 'Remove VM folder')) {
            Remove-Item -LiteralPath $vmDir -Recurse -Force -Confirm:$false
        }
    }
}

$rootDir = Join-Path $lab.VMPath 'RootCertificates'
if ((Test-Path -LiteralPath $rootDir) -and $PSCmdlet.ShouldProcess($rootDir, 'Remove exported CA certificates')) {
    Remove-Item -LiteralPath $rootDir -Recurse -Force -Confirm:$false
}

$net = $lab.Network
$nat = Get-NetNat -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $net.NatName }
if ($nat -and $PSCmdlet.ShouldProcess($net.NatName, 'Remove NAT')) {
    Remove-NetNat -Name $net.NatName -Confirm:$false
}

$alias = 'vEthernet ({0})' -f $net.SwitchName
$ip = Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -eq $net.Gateway }
if ($ip -and $PSCmdlet.ShouldProcess("$($net.Gateway) on $alias", 'Remove host IP address')) {
    $ip | Remove-NetIPAddress -Confirm:$false
}

if ((Get-VMSwitch -Name $net.SwitchName -ErrorAction SilentlyContinue) -and $PSCmdlet.ShouldProcess($net.SwitchName, 'Remove VM switch')) {
    Remove-VMSwitch -Name $net.SwitchName -Force -Confirm:$false
}

if ($IncludeBaseImage) {
    $base = $lab.BaseImage.BaseVhdPath
    if ((Test-Path -LiteralPath $base) -and $PSCmdlet.ShouldProcess($base, 'Remove base disk')) {
        Set-ItemProperty -LiteralPath $base -Name IsReadOnly -Value $false
        Remove-Item -LiteralPath $base -Force -Confirm:$false
    }
}
