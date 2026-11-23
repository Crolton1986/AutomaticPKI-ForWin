<#
.SYNOPSIS
    Copies the repo's AutomaticPKI module into WEB01/WEB02 and runs the lab scenarios as a checklist.
.DESCRIPTION
    Scenarios (default: all, in this order):
        Install    Install-APKI on WEB01 and WEB02
        Discovery  messy IIS names on WEB01 (engine + Find-APKISite, Approve-APKIOrder)
        RpcEnroll  APKIWebServer from CA01 over RPC/DCOM on WEB01
        TwoCA      two enterprise CAs: AD topology, CA02 issuance, template filter, Find-APKICA
                   (WEB01: 2 candidates; WEB02: none, not domain-joined)
        Pending    APKIWebServerApproval goes Pending on WEB01, approved here with
                   certutil -resubmit on CA01, then received
        CepEnroll  WEB02 via CEP/CES UsernamePassword; WEB01 Kerberos CEP policy check
        Renewal    Invoke-APKIRenewal on WEB01 and WEB02
    Public cmdlets that do not exist yet report N/A. Exit code 1 when any check FAILs.
.PARAMETER Scenario
    Subset of scenarios to run.
.PARAMETER EnrollUserCredential
    The CEP/CES account password set by New-APKILab (prompted when CepEnroll runs).
#>
#Requires -RunAsAdministrator
#Requires -Modules Hyper-V
[CmdletBinding()]
param(
    [ValidateSet('Install', 'Discovery', 'RpcEnroll', 'TwoCA', 'Pending', 'CepEnroll', 'Renewal')]
    [string[]]$Scenario = @('Install', 'Discovery', 'RpcEnroll', 'TwoCA', 'Pending', 'CepEnroll', 'Renewal'),

    [string]$ConfigPath = (Join-Path $PSScriptRoot 'LabConfig.psd1'),

    [string]$ModulePath = (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'src\AutomaticPKI'),

    [pscredential]$AdminCredential,

    [pscredential]$EnrollUserCredential
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

foreach ($file in Get-ChildItem -Path (Join-Path $PSScriptRoot 'Steps') -Filter '*.ps1') {
    . $file.FullName
}

$lab = Import-LabConfig -Path $ConfigPath
$admin = Get-LabAdminCredential -Lab $lab -Credential $AdminCredential
if ($Scenario -contains 'CepEnroll' -and -not $EnrollUserCredential) {
    $EnrollUserCredential = Get-Credential -UserName ('{0}\{1}' -f $lab.Domain.NetbiosName, $lab.Domain.EnrollUserName) -Message 'CEP/CES enrollment account (as set by New-APKILab)'
}

$web01 = @(Get-LabVMConfig -Lab $lab -Role 'Web')[0].Name
$web02 = @(Get-LabVMConfig -Lab $lab -Role 'WebWorkgroup')[0].Name
$ca01 = $lab.EnrollmentServices.CAVMName
$ca02 = @($lab.CertificationAuthorities | Where-Object { $_.VMName -ne $ca01 })[0].VMName
$urls = Get-LabEnrollmentUrl -Lab $lab
$context = @{
    CA01Config       = Get-LabCAConfigString -Lab $lab -VMName $ca01
    CA02Config       = Get-LabCAConfigString -Lab $lab -VMName $ca02
    StandardTemplate = $lab.Templates.Standard
    ApprovalTemplate = $lab.Templates.Approval
    CepKerberosUrl   = $urls.CepKerberos
    CepUserNameUrl   = $urls.CepUserName
    SecretName       = 'lab-ces'
}

$creds = @{
    $web01 = Resolve-LabGuestCredential -Lab $lab -AdminCredential $admin -VMName $web01
    $web02 = Resolve-LabGuestCredential -Lab $lab -AdminCredential $admin -VMName $web02
}

# Fresh module copy + guest test helpers.
$guestHelper = Join-Path $PSScriptRoot 'Tests\APKILabGuest.ps1'
foreach ($vmName in @($web01, $web02)) {
    Write-LabStep "Copying module to $vmName"
    Invoke-LabGuest -VMName $vmName -Credential $creds[$vmName] -ScriptBlock {
        $target = 'C:\Program Files\WindowsPowerShell\Modules\AutomaticPKI'
        if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force }
        if (-not (Test-Path -LiteralPath 'C:\APKILab')) { $null = New-Item -ItemType Directory -Path 'C:\APKILab' -Force }
    }
    Copy-LabItemToGuest -VMName $vmName -Credential $creds[$vmName] -Path $ModulePath -Destination 'C:\Program Files\WindowsPowerShell\Modules\AutomaticPKI'
    Copy-LabItemToGuest -VMName $vmName -Credential $creds[$vmName] -Path $guestHelper -Destination 'C:\APKILab\APKILabGuest.ps1'
}

$runInGuest = {
    param([string]$Name, [hashtable]$Ctx, [string]$Phase, [string[]]$RequestId, [pscredential]$EnrollCredential)
    . 'C:\APKILab\APKILabGuest.ps1'
    $splat = @{ Scenario = $Name; Context = $Ctx; Phase = $Phase; RequestId = $RequestId }
    if ($EnrollCredential) { $splat.EnrollCredential = $EnrollCredential }
    Invoke-LabScenario @splat
}

$results = New-Object -TypeName System.Collections.Generic.List[object]
$targets = @{
    Install   = @($web01, $web02)
    Discovery = @($web01)
    RpcEnroll = @($web01)
    TwoCA     = @($web01, $web02)
    CepEnroll = @($web01, $web02)
    Renewal   = @($web01, $web02)
}

foreach ($name in @('Install', 'Discovery', 'RpcEnroll', 'TwoCA', 'Pending', 'CepEnroll', 'Renewal')) {
    if ($Scenario -notcontains $name) { continue }
    Write-LabStep "=== Scenario $name ==="

    if ($name -eq 'Pending') {
        $rows = @(Invoke-LabGuest -VMName $web01 -Credential $creds[$web01] -ScriptBlock $runInGuest -ArgumentList $name, $context, 'Request', @(), $null)
        foreach ($r in $rows) { $results.Add($r) }
        $ids = @($rows | Where-Object { $_.RequestId } | ForEach-Object { $_.RequestId })
        if ($ids.Count -eq 0) { continue }

        Write-LabStep "Approving $($ids.Count) request(s) on $ca01 with certutil -resubmit"
        $numbers = @($ids | ForEach-Object { $_.Split(':')[1] })
        $approve = @(Invoke-LabGuest -VMName $ca01 -Credential $admin.Domain -ArgumentList (, [string[]]$numbers) -ScriptBlock {
                param([string[]]$Number)
                foreach ($n in $Number) {
                    $out = & certutil.exe -resubmit $n 2>&1
                    [pscustomobject]@{
                        Host      = $env:COMPUTERNAME
                        Scenario  = 'Pending'
                        Check     = "certutil -resubmit $n"
                        Status    = $(if ($LASTEXITCODE -eq 0) { 'PASS' } else { 'FAIL' })
                        Detail    = (@($out) -join ' ').Trim()
                        RequestId = ''
                    }
                }
            })
        foreach ($r in $approve) { $results.Add($r) }

        $rows = @(Invoke-LabGuest -VMName $web01 -Credential $creds[$web01] -ScriptBlock $runInGuest -ArgumentList $name, $context, 'Receive', ([string[]]$ids), $null)
        foreach ($r in $rows) { $results.Add($r) }
        continue
    }

    foreach ($vmName in $targets[$name]) {
        $enroll = $null
        if ($name -eq 'CepEnroll' -and $vmName -eq $web02) { $enroll = $EnrollUserCredential }
        try {
            $rows = @(Invoke-LabGuest -VMName $vmName -Credential $creds[$vmName] -ScriptBlock $runInGuest -ArgumentList $name, $context, '', @(), $enroll)
            foreach ($r in $rows) { $results.Add($r) }
        }
        catch {
            $results.Add([pscustomobject]@{ Host = $vmName; Scenario = $name; Check = 'run in guest'; Status = 'FAIL'; Detail = $_.Exception.Message; RequestId = '' })
        }
    }
}

$results | Select-Object -Property Status, Host, Scenario, Check, Detail | Format-Table -AutoSize -Wrap | Out-String -Width 220 | Write-Host

$summary = $results | Group-Object -Property Status | ForEach-Object { '{0}={1}' -f $_.Name, $_.Count }
Write-LabStep ('Summary: {0}' -f ($summary -join '  '))
if (@($results | Where-Object { $_.Status -eq 'FAIL' }).Count -gt 0) {
    exit 1
}
