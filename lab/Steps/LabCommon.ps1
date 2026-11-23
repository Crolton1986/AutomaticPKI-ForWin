# Shared helpers for the AutomaticPKI Hyper-V lab: config lookup, credentials, PowerShell Direct
# and reboot handling. Dot-sourced by New-APKILab.ps1 and Invoke-APKILabTests.ps1.

function Import-LabConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Lab config not found: $Path"
    }
    Import-PowerShellDataFile -Path $Path
}

function Write-LabStep {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )
    Write-Host ('[{0:HH:mm:ss}] {1}' -f (Get-Date), $Message)
}

function Get-LabVMConfig {
    # Returns VM entries from the config, filtered by -Name or -Role.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Lab,

        [string]$Name,

        [string]$Role
    )
    foreach ($vm in $Lab.VMs) {
        if ($Name -and $vm.Name -ne $Name) { continue }
        if ($Role -and $vm.Role -ne $Role) { continue }
        $vm
    }
}

function Get-LabFqdn {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Lab,

        [Parameter(Mandatory)]
        [string]$VMName
    )
    '{0}.{1}' -f $VMName.ToLowerInvariant(), $Lab.Domain.Name
}

function Get-LabAdminCredential {
    # Prompts once for the lab Administrator password. Returns @{ Password; Domain; UserName };
    # Get-LabLocalCredential builds the per-VM local credential from it.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Lab,

        [pscredential]$Credential
    )
    if (-not $Credential) {
        $Credential = Get-Credential -UserName $Lab.Domain.AdminUserName -Message 'Lab Administrator password (local Administrator on every VM, domain Administrator, DSRM)'
    }
    if (-not $Credential) {
        throw 'An Administrator credential is required.'
    }
    $userName = $Lab.Domain.AdminUserName
    @{
        Password = $Credential.Password
        Domain   = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ('{0}\{1}' -f $Lab.Domain.NetbiosName, $userName), $Credential.Password
        UserName = $userName
    }
}

function Get-LabLocalCredential {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AdminCredential,

        [Parameter(Mandatory)]
        [string]$VMName
    )
    New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ('{0}\{1}' -f $VMName, $AdminCredential.UserName), $AdminCredential.Password
}

function Test-LabGuestLogon {
    # True when PowerShell Direct accepts the credential right now.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VMName,

        [Parameter(Mandatory)]
        [pscredential]$Credential
    )
    try {
        $null = Invoke-Command -VMName $VMName -Credential $Credential -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop
        return $true
    }
    catch {
        Write-Verbose "PowerShell Direct to $VMName as $($Credential.UserName) failed: $($_.Exception.Message)"
        return $false
    }
}

function Resolve-LabGuestCredential {
    # Domain credential once the VM is a DC or domain member, else the local Administrator
    # (the workgroup host always uses its local account). Waits until one of them logs on, so it
    # also covers a VM that is still booting (a promoted DC accepts only the domain account).
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Lab,

        [Parameter(Mandatory)]
        [hashtable]$AdminCredential,

        [Parameter(Mandatory)]
        [string]$VMName,

        [int]$TimeoutMinutes = 40
    )
    $vm = Get-LabVMConfig -Lab $Lab -Name $VMName
    $local = Get-LabLocalCredential -AdminCredential $AdminCredential -VMName $VMName
    $candidates = @($AdminCredential.Domain, $local)
    if ($vm.Role -eq 'WebWorkgroup') {
        $candidates = @($local)
    }
    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    while ((Get-Date) -lt $deadline) {
        foreach ($c in $candidates) {
            if (Test-LabGuestLogon -VMName $VMName -Credential $c) {
                return $c
            }
        }
        Write-Verbose "No logon to $VMName yet; waiting."
        Start-Sleep -Seconds 15
    }
    throw "Timed out after $TimeoutMinutes min: PowerShell Direct logon to $VMName failed with the domain and local Administrator."
}

function Invoke-LabGuest {
    # PowerShell Direct wrapper: runs a script block in the VM, retrying transient session errors
    # (guest still booting, services starting). Errors thrown by the script block itself after a
    # session was established are not retried.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VMName,

        [Parameter(Mandatory)]
        [pscredential]$Credential,

        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,

        [object[]]$ArgumentList = @(),

        [int]$Retry = 6
    )
    $attempt = 0
    while ($true) {
        $attempt++
        $session = $null
        try {
            $session = New-PSSession -VMName $VMName -Credential $Credential -ErrorAction Stop
        }
        catch {
            if ($attempt -ge $Retry) {
                throw "PowerShell Direct to $VMName failed after $attempt attempts: $($_.Exception.Message)"
            }
            Write-Verbose "Session to $VMName not ready ($($_.Exception.Message)); retrying."
            Start-Sleep -Seconds 15
            continue
        }
        try {
            return Invoke-Command -Session $session -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -ErrorAction Stop
        }
        finally {
            Remove-PSSession -Session $session -ErrorAction SilentlyContinue
        }
    }
}

function Get-LabGuestBootTime {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VMName,

        [Parameter(Mandatory)]
        [pscredential]$Credential
    )
    Invoke-LabGuest -VMName $VMName -Credential $Credential -ScriptBlock {
        (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
    }
}

function Wait-LabGuest {
    # Waits until the VM runs, PowerShell Direct logs on with -Credential, the guest boot time
    # differs from -PreviousBootTime (when given) and the optional -Probe returns $true in the guest.
    # Boot times are compared as guest-clock strings, so host/guest clock skew does not matter.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VMName,

        [Parameter(Mandatory)]
        [pscredential]$Credential,

        [string]$PreviousBootTime,

        [scriptblock]$Probe,

        [int]$TimeoutMinutes = 30
    )
    if (-not $Probe) {
        $Probe = { $true }
    }
    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    $lastError = ''
    while ((Get-Date) -lt $deadline) {
        $vm = Get-VM -Name $VMName -ErrorAction Stop
        if ($vm.State -eq 'Running') {
            try {
                $state = Invoke-Command -VMName $VMName -Credential $Credential -ErrorAction Stop -ArgumentList $Probe.ToString() -ScriptBlock {
                    param([string]$ProbeText)
                    $ErrorActionPreference = 'Stop'
                    $ready = $false
                    try {
                        $ready = [bool](& ([scriptblock]::Create($ProbeText)))
                    }
                    catch {
                        $ready = $false
                    }
                    [pscustomobject]@{
                        Boot  = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
                        Ready = $ready
                    }
                }
                $rebooted = (-not $PreviousBootTime) -or ($state.Boot -ne $PreviousBootTime)
                if ($rebooted -and $state.Ready) {
                    return
                }
                $lastError = "rebooted=$rebooted ready=$($state.Ready)"
            }
            catch {
                $lastError = $_.Exception.Message
            }
        }
        else {
            $lastError = "VM state $($vm.State)"
        }
        Write-Verbose "Waiting for $VMName ($lastError)"
        Start-Sleep -Seconds 10
    }
    throw "Timed out after $TimeoutMinutes min waiting for $VMName ($lastError)."
}

function Invoke-LabGuestReboot {
    # Restarts the guest and waits for it to come back (new boot time, logon works, probe passes).
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VMName,

        [Parameter(Mandatory)]
        [pscredential]$Credential,

        # Credential that works after the reboot (e.g. domain credential after a join).
        [pscredential]$CredentialAfter,

        [scriptblock]$Probe,

        # Guest boot time taken earlier (Get-LabGuestBootTime), when -Credential may no longer
        # log on at this point (e.g. right after DC promotion).
        [string]$PreviousBootTime,

        # Shut down through the Hyper-V integration service and start again, instead of an
        # in-guest Restart-Computer.
        [switch]$HostRestart,

        [int]$TimeoutMinutes = 30
    )
    if (-not $CredentialAfter) {
        $CredentialAfter = $Credential
    }
    Write-LabStep "Rebooting $VMName"
    $boot = $PreviousBootTime
    if (-not $boot) {
        $boot = Get-LabGuestBootTime -VMName $VMName -Credential $Credential
    }
    if ($HostRestart) {
        Stop-VM -Name $VMName -Force -ErrorAction Stop
        Start-VM -Name $VMName -ErrorAction Stop
    }
    else {
        try {
            Invoke-Command -VMName $VMName -Credential $Credential -ErrorAction Stop -ScriptBlock { Restart-Computer -Force }
        }
        catch {
            # The session can drop while the guest shuts down; the wait below decides success.
            Write-Verbose "Restart call on ${VMName}: $($_.Exception.Message)"
        }
    }
    Wait-LabGuest -VMName $VMName -Credential $CredentialAfter -PreviousBootTime $boot -Probe $Probe -TimeoutMinutes $TimeoutMinutes
}

function Copy-LabItemToGuest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VMName,

        [Parameter(Mandatory)]
        [pscredential]$Credential,

        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Destination
    )
    $session = New-PSSession -VMName $VMName -Credential $Credential -ErrorAction Stop
    try {
        Copy-Item -Path $Path -Destination $Destination -ToSession $session -Recurse -Force -ErrorAction Stop
    }
    finally {
        Remove-PSSession -Session $session -ErrorAction SilentlyContinue
    }
}

function Copy-LabItemFromGuest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VMName,

        [Parameter(Mandatory)]
        [pscredential]$Credential,

        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Destination
    )
    $session = New-PSSession -VMName $VMName -Credential $Credential -ErrorAction Stop
    try {
        Copy-Item -Path $Path -Destination $Destination -FromSession $session -Force -ErrorAction Stop
    }
    finally {
        Remove-PSSession -Session $session -ErrorAction SilentlyContinue
    }
}

function Get-LabCAConfigString {
    # 'ca01.apki.lab\APKI Lab Root CA' for the CA entry on -VMName.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Lab,

        [Parameter(Mandatory)]
        [string]$VMName
    )
    foreach ($ca in $Lab.CertificationAuthorities) {
        if ($ca.VMName -eq $VMName) {
            return '{0}\{1}' -f (Get-LabFqdn -Lab $Lab -VMName $VMName), $ca.CommonName
        }
    }
    throw "No CertificationAuthorities entry for $VMName."
}
