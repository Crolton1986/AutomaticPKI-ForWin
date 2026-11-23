# Runs INSIDE a lab VM (copied to C:\APKILab by Invoke-APKILabTests.ps1, then dot-sourced).
# Each scenario returns result rows: Host, Scenario, Check, Status (PASS/FAIL/N/A/INFO), Detail,
# plus RequestId where a later phase needs it.
#
# Public cmdlets (Install-APKI, Find-APKISite, Approve-APKIOrder, New-APKICertificate,
# Invoke-APKIRenewal, Find-APKICA) are still being built: each call is guarded by Get-Command and
# reports N/A when missing. Parameters are filtered against the cmdlet's real signature. Where a
# provider-level function already exists, the scenario also exercises it directly in module scope.

$ConfirmPreference = 'None'
$env:APKI_ROOT = 'C:\APKILab\data'

function Get-LabCheckResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Scenario,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][ValidateSet('PASS', 'FAIL', 'N/A', 'INFO')][string]$Status,
        [string]$Detail = '',
        [string]$RequestId = ''
    )
    [pscustomobject]@{
        Host      = $env:COMPUTERNAME
        Scenario  = $Scenario
        Check     = $Check
        Status    = $Status
        Detail    = $Detail
        RequestId = $RequestId
    }
}

function Get-LabOptionalValue {
    # StrictMode-safe property read on PSCustomObject or hashtable.
    [CmdletBinding()]
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) { return $InputObject[$Name] }
        return $null
    }
    $p = $InputObject.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    $null
}

function Invoke-LabPublicCommand {
    # Calls a public AutomaticPKI cmdlet if it exists. Unknown parameters are dropped (and
    # reported); a missing mandatory parameter is reported instead of prompting.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [hashtable]$Parameter = @{}
    )
    $result = [pscustomobject]@{ Available = $false; Output = @(); Error = $null; Dropped = @() }
    $cmd = Get-Command -Name $Name -Module AutomaticPKI -ErrorAction SilentlyContinue
    if (-not $cmd) { return $result }
    $result.Available = $true

    $use = @{}
    $dropped = New-Object -TypeName System.Collections.Generic.List[string]
    foreach ($k in $Parameter.Keys) {
        if ($cmd.Parameters.ContainsKey($k)) { $use[$k] = $Parameter[$k] } else { $dropped.Add($k) }
    }
    $result.Dropped = $dropped.ToArray()

    $bindable = $false
    $missing = @()
    foreach ($set in $cmd.ParameterSets) {
        $need = @($set.Parameters | Where-Object { $_.IsMandatory } | ForEach-Object { $_.Name } | Where-Object { -not $use.ContainsKey($_) })
        if ($need.Count -eq 0) { $bindable = $true; break }
        $missing = $need
    }
    if (-not $bindable) {
        $result.Error = "signature mismatch, mandatory parameter(s) not supplied by the lab: $($missing -join ', ')"
        return $result
    }
    try {
        $result.Output = @(& $cmd @use -ErrorAction Stop)
    }
    catch {
        $result.Error = $_.Exception.Message
    }
    $result
}

function Get-LabPublicResult {
    # Converts an Invoke-LabPublicCommand result into a row.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Scenario,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][object]$Call,
        [string]$SuccessDetail = ''
    )
    if (-not $Call.Available) {
        return Get-LabCheckResult -Scenario $Scenario -Check $Check -Status 'N/A' -Detail 'not yet available'
    }
    $note = ''
    if (@($Call.Dropped).Count -gt 0) { $note = " (parameters not in signature: $($Call.Dropped -join ', '))" }
    if ($Call.Error) {
        return Get-LabCheckResult -Scenario $Scenario -Check $Check -Status 'FAIL' -Detail ($Call.Error + $note)
    }
    Get-LabCheckResult -Scenario $Scenario -Check $Check -Status 'PASS' -Detail ($SuccessDetail + $note)
}

function Invoke-LabModuleCommand {
    # Runs a script block inside the AutomaticPKI module scope (private provider functions).
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [object[]]$ArgumentList = @()
    )
    $module = Get-Module -Name AutomaticPKI
    & $module $ScriptBlock @ArgumentList
}

function Get-LabOrder {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string[]]$Hostname,
        [Parameter(Mandatory)][string]$Provider,
        [Parameter(Mandatory)][hashtable]$Setting
    )
    [pscustomobject]@{
        Id               = $Id
        Status           = 'Approved'
        SiteName         = 'APKI-Lab'
        Hostnames        = $Hostname
        Bindings         = @()
        Provider         = $Provider
        ProviderSettings = [pscustomobject]$Setting
        Key              = [pscustomobject]@{ Algorithm = 'RSA'; Length = 2048; Exportable = $true }
        KeyMode          = 'OnHost'
        CreateBinding    = $false
        HttpProbe        = [pscustomobject]@{ Enabled = $false; Path = '/'; ExpectStatusBelow = 500 }
    }
}

function Test-LabIssuedCertificate {
    # Checks an issued certificate in LocalMachine\My: private key, issuer CN, SAN.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Scenario,
        [Parameter(Mandatory)][string]$Check,
        [AllowEmptyString()][string]$Thumbprint,
        [Parameter(Mandatory)][string]$IssuerName,
        [Parameter(Mandatory)][string]$DnsName
    )
    $cert = $null
    if ($Thumbprint) {
        $cert = Get-ChildItem -Path 'Cert:\LocalMachine\My' | Where-Object { $_.Thumbprint -eq $Thumbprint } | Select-Object -First 1
    }
    if (-not $cert) {
        return Get-LabCheckResult -Scenario $Scenario -Check $Check -Status 'FAIL' -Detail "certificate '$Thumbprint' not in LocalMachine\My"
    }
    $problems = @()
    if (-not $cert.HasPrivateKey) { $problems += 'no private key' }
    if ($cert.Issuer -notmatch [regex]::Escape("CN=$IssuerName")) { $problems += "issuer is $($cert.Issuer)" }
    $sans = @($cert.DnsNameList | ForEach-Object { $_.Unicode })
    if ($sans -notcontains $DnsName) { $problems += "SAN lacks $DnsName ($($sans -join ', '))" }
    $tpl = $cert.Extensions | Where-Object { $_.Oid.Value -eq '1.3.6.1.4.1.311.21.7' } | Select-Object -First 1
    $tplText = ''
    if ($tpl) { $tplText = ($tpl.Format($false) -split ',')[0] }
    if ($problems.Count -gt 0) {
        return Get-LabCheckResult -Scenario $Scenario -Check $Check -Status 'FAIL' -Detail ($problems -join '; ')
    }
    Get-LabCheckResult -Scenario $Scenario -Check $Check -Status 'PASS' -Detail "$Thumbprint from $IssuerName, $tplText"
}

function Get-LabCAName {
    # 'host\CA Name' -> 'CA Name'
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$CAConfig)
    $CAConfig.Split('\')[1]
}

function Get-LabHttpsBindingCertificate {
    # Thumbprint bound to the https binding for a host header (SNI) on this server, or ''.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$HostHeader)
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    $path = 'IIS:\SslBindings\!443!{0}' -f $HostHeader
    if (Test-Path -LiteralPath $path) {
        return [string](Get-Item -LiteralPath $path).Thumbprint
    }
    ''
}

# ---------------------------------------------------------------------------------- scenarios

function Invoke-LabScenarioInstall {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context)
    $call = Invoke-LabPublicCommand -Name 'Install-APKI' -Parameter @{ Force = $true }
    Get-LabPublicResult -Scenario 'Install' -Check 'Install-APKI' -Call $call
    $task = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -like '*APKI*' -or $_.TaskPath -like '*APKI*' })
    if ($call.Available -and -not $call.Error) {
        if ($task.Count -gt 0) {
            Get-LabCheckResult -Scenario 'Install' -Check 'Renewal scheduled task exists' -Status 'PASS' -Detail ($task[0].TaskPath + $task[0].TaskName)
        }
        else {
            Get-LabCheckResult -Scenario 'Install' -Check 'Renewal scheduled task exists' -Status 'FAIL' -Detail 'no task matching *APKI*'
        }
    }
    $null = $Context
}

function Invoke-LabScenarioDiscovery {
    # Messy IIS names on WEB01. Expected NameStatus per site (see lab/LabConfig.psd1 Web.Sites).
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context)
    $expect = [ordered]@{
        'APKI-Www'         = @{ Status = 'Usable'; Name = 'www.apki.lab'; Create = $null }
        'APKI-App'         = @{ Status = 'Usable'; Name = 'app.apki.lab'; Create = $null }
        'APKI-BlankHost'   = @{ Status = 'Usable'; Name = 'legacy.apki.lab'; Create = $null }
        'APKI-HttpOnly'    = @{ Status = 'Usable'; Name = 'http-only.apki.lab'; Create = $true }
        'APKI-IpOnly'      = @{ Status = 'NeedsName'; Name = $null; Create = $null }
        'APKI-SingleLabel' = @{ Status = 'NeedsName'; Name = $null; Create = $null }
    }

    $check = {
        param([string]$Source, [object[]]$Candidate)
        foreach ($site in $expect.Keys) {
            $want = $expect[$site]
            $c = @($Candidate | Where-Object { (Get-LabOptionalValue -InputObject $_ -Name 'SiteName') -eq $site }) | Select-Object -First 1
            $label = "$Source $site"
            if (-not $c) {
                Get-LabCheckResult -Scenario 'Discovery' -Check $label -Status 'FAIL' -Detail 'no candidate for site'
                continue
            }
            $status = [string](Get-LabOptionalValue -InputObject $c -Name 'NameStatus')
            $names = @(Get-LabOptionalValue -InputObject $c -Name 'Hostnames')
            $problems = @()
            if ($status -ne $want.Status) { $problems += "NameStatus $status, expected $($want.Status)" }
            if ($want.Name -and $names -notcontains $want.Name) { $problems += "Hostnames [$($names -join ', ')] lack $($want.Name)" }
            if ($null -ne $want.Create -and [bool](Get-LabOptionalValue -InputObject $c -Name 'CreateBinding') -ne $want.Create) { $problems += "CreateBinding is not $($want.Create)" }
            if ($problems.Count -gt 0) {
                Get-LabCheckResult -Scenario 'Discovery' -Check $label -Status 'FAIL' -Detail ($problems -join '; ')
            }
            else {
                Get-LabCheckResult -Scenario 'Discovery' -Check $label -Status 'PASS' -Detail "$status [$($names -join ', ')]"
            }
        }
    }

    # Provider level: IIS discovery engine (private, exists today).
    try {
        $candidates = @(Invoke-LabModuleCommand -ScriptBlock { Find-APKISiteCandidate -CheckDns })
        & $check 'engine' $candidates
    }
    catch {
        Get-LabCheckResult -Scenario 'Discovery' -Check 'engine Find-APKISiteCandidate' -Status 'FAIL' -Detail $_.Exception.Message
    }

    # Public cmdlets.
    $call = Invoke-LabPublicCommand -Name 'Find-APKISite' -Parameter @{ CheckDns = $true }
    Get-LabPublicResult -Scenario 'Discovery' -Check 'Find-APKISite' -Call $call -SuccessDetail "$(@($call.Output).Count) candidate(s)"
    if ($call.Available -and -not $call.Error) {
        & $check 'Find-APKISite' @($call.Output)
        $www = @($call.Output | Where-Object { (Get-LabOptionalValue -InputObject $_ -Name 'SiteName') -eq 'APKI-Www' }) | Select-Object -First 1
        if ($www) {
            $approve = Invoke-LabPublicCommand -Name 'Approve-APKIOrder' -Parameter @{ Id = (Get-LabOptionalValue -InputObject $www -Name 'Id') }
            Get-LabPublicResult -Scenario 'Discovery' -Check 'Approve-APKIOrder (www)' -Call $approve
        }
    }
    elseif (Get-Command -Name 'Approve-APKIOrder' -Module AutomaticPKI -ErrorAction SilentlyContinue) {
        Get-LabCheckResult -Scenario 'Discovery' -Check 'Approve-APKIOrder (www)' -Status 'INFO' -Detail 'skipped: needs a working Find-APKISite'
    }
    else {
        Get-LabCheckResult -Scenario 'Discovery' -Check 'Approve-APKIOrder (www)' -Status 'N/A' -Detail 'not yet available'
    }
    $null = $Context
}

function Invoke-LabScenarioRpcEnroll {
    # WEB01, domain-joined: APKIWebServer from CA01 over RPC/DCOM.
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context)
    $caName = Get-LabCAName -CAConfig $Context.CA01Config
    $hostName = 'app.apki.lab'

    $order = Get-LabOrder -Id 'lab-rpc-app' -Hostname $hostName -Provider 'AdcsRpc' -Setting @{ CAConfig = $Context.CA01Config; Template = $Context.StandardTemplate }
    $r = Invoke-LabModuleCommand -ScriptBlock { param($o) Request-APKIAdcsRpcCertificate -Order $o } -ArgumentList $order
    if ($r -and $r.Status -eq 'Issued') {
        Test-LabIssuedCertificate -Scenario 'RpcEnroll' -Check 'provider AdcsRpc issue (CA01, APKIWebServer)' -Thumbprint $r.Thumbprint -IssuerName $caName -DnsName $hostName
    }
    else {
        Get-LabCheckResult -Scenario 'RpcEnroll' -Check 'provider AdcsRpc issue (CA01, APKIWebServer)' -Status 'FAIL' -Detail "status $(if ($r) { $r.Status + ': ' + $r.Message })"
    }

    $call = Invoke-LabPublicCommand -Name 'New-APKICertificate' -Parameter @{
        SiteName = 'APKI-App'; Hostname = @($hostName); Hostnames = @($hostName)
        Provider = 'AdcsRpc'; CAConfig = $Context.CA01Config; Template = $Context.StandardTemplate
    }
    Get-LabPublicResult -Scenario 'RpcEnroll' -Check 'New-APKICertificate (app, RPC)' -Call $call
    if ($call.Available -and -not $call.Error) {
        $thumb = Get-LabHttpsBindingCertificate -HostHeader $hostName
        Test-LabIssuedCertificate -Scenario 'RpcEnroll' -Check 'https binding app.apki.lab has CA01 cert' -Thumbprint $thumb -IssuerName $caName -DnsName $hostName
    }
}

function Invoke-LabScenarioTwoCA {
    # Two enterprise CAs; APKIWebServer on both, APKIWebServerApproval on CA01 only.
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context)
    $joined = (Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain

    if ($joined) {
        # Lab topology sanity check straight from AD.
        try {
            $root = [adsi]'LDAP://RootDSE'
            $base = 'LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,{0}' -f $root.configurationNamingContext
            $searcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList ([adsi]$base), '(objectClass=pKIEnrollmentService)'
            $cas = @($searcher.FindAll() | ForEach-Object {
                    [pscustomobject]@{ Name = [string]$_.Properties['cn'][0]; Templates = @($_.Properties['certificatetemplates']) }
                })
            $std = @($cas | Where-Object { $_.Templates -contains $Context.StandardTemplate })
            $apr = @($cas | Where-Object { $_.Templates -contains $Context.ApprovalTemplate })
            $ok = ($std.Count -eq 2 -and $apr.Count -eq 1)
            $status = 'FAIL'
            if ($ok) { $status = 'PASS' }
            Get-LabCheckResult -Scenario 'TwoCA' -Check 'AD: 2 CAs publish APKIWebServer, 1 publishes Approval' -Status $status -Detail (($cas | ForEach-Object { "$($_.Name): $($_.Templates -join '/')" }) -join ' | ')
        }
        catch {
            Get-LabCheckResult -Scenario 'TwoCA' -Check 'AD enrollment services query' -Status 'FAIL' -Detail $_.Exception.Message
        }

        # CA02 issues APKIWebServer; refuses the template it does not publish.
        $ca2 = Get-LabCAName -CAConfig $Context.CA02Config
        $order = Get-LabOrder -Id 'lab-rpc-ca02' -Hostname 'www.apki.lab' -Provider 'AdcsRpc' -Setting @{ CAConfig = $Context.CA02Config; Template = $Context.StandardTemplate }
        $r = Invoke-LabModuleCommand -ScriptBlock { param($o) Request-APKIAdcsRpcCertificate -Order $o } -ArgumentList $order
        if ($r -and $r.Status -eq 'Issued') {
            Test-LabIssuedCertificate -Scenario 'TwoCA' -Check 'provider AdcsRpc issue from CA02' -Thumbprint $r.Thumbprint -IssuerName $ca2 -DnsName 'www.apki.lab'
        }
        else {
            Get-LabCheckResult -Scenario 'TwoCA' -Check 'provider AdcsRpc issue from CA02' -Status 'FAIL' -Detail "status $(if ($r) { $r.Status + ': ' + $r.Message })"
        }
        $order = Get-LabOrder -Id 'lab-rpc-ca02-approval' -Hostname 'www.apki.lab' -Provider 'AdcsRpc' -Setting @{ CAConfig = $Context.CA02Config; Template = $Context.ApprovalTemplate }
        $r = Invoke-LabModuleCommand -ScriptBlock { param($o) Request-APKIAdcsRpcCertificate -Order $o } -ArgumentList $order
        $status = 'FAIL'
        if ($r -and ($r.Status -eq 'Denied' -or $r.Status -eq 'Failed')) { $status = 'PASS' }
        Get-LabCheckResult -Scenario 'TwoCA' -Check 'CA02 refuses unpublished APKIWebServerApproval' -Status $status -Detail "status $(if ($r) { $r.Status + ': ' + $r.Message })"
    }

    # Public discovery.
    $call = Invoke-LabPublicCommand -Name 'Find-APKICA' -Parameter @{ Template = $Context.StandardTemplate }
    $n = @($call.Output).Count
    if ($call.Available -and -not $call.Error) {
        $want = 0
        if ($joined) { $want = 2 }
        $status = 'FAIL'
        if ($n -eq $want) { $status = 'PASS' }
        Get-LabCheckResult -Scenario 'TwoCA' -Check "Find-APKICA APKIWebServer -> $want candidate(s), none auto-selected" -Status $status -Detail "$n candidate(s)"
    }
    else {
        Get-LabPublicResult -Scenario 'TwoCA' -Check 'Find-APKICA APKIWebServer' -Call $call
    }
    if ($joined) {
        $call = Invoke-LabPublicCommand -Name 'Find-APKICA' -Parameter @{ Template = $Context.ApprovalTemplate }
        if ($call.Available -and -not $call.Error) {
            $hosts = @($call.Output | ForEach-Object { Get-LabOptionalValue -InputObject $_ -Name 'CAName' })
            $status = 'FAIL'
            if ($hosts.Count -eq 1 -and $hosts[0] -eq (Get-LabCAName -CAConfig $Context.CA01Config)) { $status = 'PASS' }
            Get-LabCheckResult -Scenario 'TwoCA' -Check 'Find-APKICA APKIWebServerApproval -> CA01 only' -Status $status -Detail ($hosts -join ', ')
        }
        else {
            Get-LabPublicResult -Scenario 'TwoCA' -Check 'Find-APKICA APKIWebServerApproval' -Call $call
        }
    }
}

function Invoke-LabScenarioPending {
    # Phase Request: approval template goes Pending (returns RequestId rows for the host, which
    # approves them with certutil -resubmit on CA01). Phase Receive: collect the certificate.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Context,
        [Parameter(Mandatory)][ValidateSet('Request', 'Receive')][string]$Phase,
        [string[]]$RequestId = @()
    )
    $caName = Get-LabCAName -CAConfig $Context.CA01Config
    $hostName = 'www.apki.lab'
    $order = Get-LabOrder -Id 'lab-rpc-pending' -Hostname $hostName -Provider 'AdcsRpc' -Setting @{ CAConfig = $Context.CA01Config; Template = $Context.ApprovalTemplate }

    if ($Phase -eq 'Request') {
        $r = Invoke-LabModuleCommand -ScriptBlock { param($o) Request-APKIAdcsRpcCertificate -Order $o } -ArgumentList $order
        if ($r -and $r.Status -eq 'Pending' -and $r.RequestId -match '^\d+$') {
            Get-LabCheckResult -Scenario 'Pending' -Check 'provider request goes Pending' -Status 'PASS' -Detail "CA request $($r.RequestId)" -RequestId ("provider:{0}" -f $r.RequestId)
        }
        else {
            Get-LabCheckResult -Scenario 'Pending' -Check 'provider request goes Pending' -Status 'FAIL' -Detail "status $(if ($r) { $r.Status + ': ' + $r.Message })"
        }

        $call = Invoke-LabPublicCommand -Name 'New-APKICertificate' -Parameter @{
            SiteName = 'APKI-Www'; Hostname = @($hostName); Hostnames = @($hostName)
            Provider = 'AdcsRpc'; CAConfig = $Context.CA01Config; Template = $Context.ApprovalTemplate
        }
        if ($call.Available -and -not $call.Error) {
            # The order store holds the CA request ID while Pending.
            $pending = @(Get-ChildItem -Path (Join-Path $env:APKI_ROOT 'orders') -Filter '*.json' -ErrorAction SilentlyContinue |
                    ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw -Encoding UTF8 | ConvertFrom-Json } |
                    Where-Object { (Get-LabOptionalValue -InputObject $_ -Name 'Status') -eq 'Pending' })
            if ($pending.Count -gt 0) {
                foreach ($p in $pending) {
                    Get-LabCheckResult -Scenario 'Pending' -Check "New-APKICertificate order $($p.Id) is Pending" -Status 'PASS' -Detail "CA request $($p.PendingRequestId)" -RequestId ("public:{0}" -f $p.PendingRequestId)
                }
            }
            else {
                Get-LabCheckResult -Scenario 'Pending' -Check 'New-APKICertificate order is Pending' -Status 'FAIL' -Detail 'no Pending order in the order store'
            }
        }
        else {
            Get-LabPublicResult -Scenario 'Pending' -Check 'New-APKICertificate (approval template)' -Call $call
        }
        return
    }

    foreach ($id in $RequestId) {
        $kind, $num = $id.Split(':')
        if ($kind -eq 'provider') {
            $r = Invoke-LabModuleCommand -ScriptBlock { param($o, $n) Receive-APKIAdcsRpcCertificate -Order $o -RequestId $n } -ArgumentList $order, $num
            if ($r -and $r.Status -eq 'Issued') {
                Test-LabIssuedCertificate -Scenario 'Pending' -Check "provider receive after approval ($num)" -Thumbprint $r.Thumbprint -IssuerName $caName -DnsName $hostName
            }
            else {
                Get-LabCheckResult -Scenario 'Pending' -Check "provider receive after approval ($num)" -Status 'FAIL' -Detail "status $(if ($r) { $r.Status + ': ' + $r.Message })"
            }
        }
    }
    if (@($RequestId | Where-Object { $_ -like 'public:*' }).Count -gt 0) {
        $call = Invoke-LabPublicCommand -Name 'Invoke-APKIRenewal'
        Get-LabPublicResult -Scenario 'Pending' -Check 'Invoke-APKIRenewal collects approved request' -Call $call
        if ($call.Available -and -not $call.Error) {
            $thumb = Get-LabHttpsBindingCertificate -HostHeader $hostName
            Test-LabIssuedCertificate -Scenario 'Pending' -Check 'https binding www.apki.lab has approved cert' -Thumbprint $thumb -IssuerName $caName -DnsName $hostName
        }
    }
}

function Invoke-LabScenarioCepEnroll {
    # WEB02 (workgroup): UsernamePassword CEP/CES with a stored secret. WEB01 (domain): Kerberos
    # CEP policy check only (the lab's CES endpoint is UsernamePassword).
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Context,
        [pscredential]$EnrollCredential
    )
    $caName = Get-LabCAName -CAConfig $Context.CA01Config
    $joined = (Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain

    if ($joined) {
        $order = Get-LabOrder -Id 'lab-cep-kerberos' -Hostname 'app.apki.lab' -Provider 'AdcsCep' -Setting @{ CepUrl = $Context.CepKerberosUrl; Template = $Context.StandardTemplate; CredentialRef = $null }
        try {
            $ok = Invoke-LabModuleCommand -ScriptBlock { param($o) Test-APKIAdcsCepProvider -Order $o } -ArgumentList $order
            $status = 'FAIL'
            if ($ok) { $status = 'PASS' }
            Get-LabCheckResult -Scenario 'CepEnroll' -Check 'provider CEP Kerberos policy reachable' -Status $status -Detail $Context.CepKerberosUrl
        }
        catch {
            Get-LabCheckResult -Scenario 'CepEnroll' -Check 'provider CEP Kerberos policy reachable' -Status 'FAIL' -Detail $_.Exception.Message
        }
        return
    }

    $hostName = 'web02.apki.lab'
    if (-not $EnrollCredential) {
        Get-LabCheckResult -Scenario 'CepEnroll' -Check 'enrollment credential' -Status 'FAIL' -Detail 'no credential passed'
        return
    }
    try {
        Invoke-LabModuleCommand -ScriptBlock { param($c, $n) Set-APKISecret -Name $n -Credential $c } -ArgumentList $EnrollCredential, $Context.SecretName
    }
    catch {
        Get-LabCheckResult -Scenario 'CepEnroll' -Check 'store CES secret' -Status 'FAIL' -Detail $_.Exception.Message
        return
    }

    $order = Get-LabOrder -Id 'lab-cep-web02' -Hostname $hostName -Provider 'AdcsCep' -Setting @{ CepUrl = $Context.CepUserNameUrl; Template = $Context.StandardTemplate; CredentialRef = $Context.SecretName }
    try {
        $ok = Invoke-LabModuleCommand -ScriptBlock { param($o) Test-APKIAdcsCepProvider -Order $o } -ArgumentList $order
        $status = 'FAIL'
        if ($ok) { $status = 'PASS' }
        Get-LabCheckResult -Scenario 'CepEnroll' -Check 'provider CEP UsernamePassword reachable' -Status $status -Detail $Context.CepUserNameUrl
    }
    catch {
        Get-LabCheckResult -Scenario 'CepEnroll' -Check 'provider CEP UsernamePassword reachable' -Status 'FAIL' -Detail $_.Exception.Message
    }
    $r = Invoke-LabModuleCommand -ScriptBlock { param($o) Request-APKIAdcsCepCertificate -Order $o } -ArgumentList $order
    if ($r -and $r.Status -eq 'Issued') {
        Test-LabIssuedCertificate -Scenario 'CepEnroll' -Check 'provider AdcsCep issue via CES (CA01)' -Thumbprint $r.Thumbprint -IssuerName $caName -DnsName $hostName
    }
    else {
        Get-LabCheckResult -Scenario 'CepEnroll' -Check 'provider AdcsCep issue via CES (CA01)' -Status 'FAIL' -Detail "status $(if ($r) { $r.Status + ': ' + $r.Message })"
    }

    $call = Invoke-LabPublicCommand -Name 'New-APKICertificate' -Parameter @{
        SiteName = 'APKI-Workgroup'; Hostname = @($hostName); Hostnames = @($hostName)
        Provider = 'AdcsCep'; CepUrl = $Context.CepUserNameUrl; Template = $Context.StandardTemplate; CredentialRef = $Context.SecretName
    }
    Get-LabPublicResult -Scenario 'CepEnroll' -Check 'New-APKICertificate (web02, CEP)' -Call $call
    if ($call.Available -and -not $call.Error) {
        $thumb = Get-LabHttpsBindingCertificate -HostHeader $hostName
        Test-LabIssuedCertificate -Scenario 'CepEnroll' -Check 'https binding web02.apki.lab has CA01 cert' -Thumbprint $thumb -IssuerName $caName -DnsName $hostName
    }
}

function Invoke-LabScenarioRenewal {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context)
    $call = Invoke-LabPublicCommand -Name 'Invoke-APKIRenewal'
    Get-LabPublicResult -Scenario 'Renewal' -Check 'Invoke-APKIRenewal run completes' -Call $call
    $null = $Context
}

function Invoke-LabScenario {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Scenario,
        [Parameter(Mandatory)][hashtable]$Context,
        [string]$Phase = '',
        [string[]]$RequestId = @(),
        [pscredential]$EnrollCredential
    )
    if (-not (Get-Module -Name AutomaticPKI)) {
        try {
            Import-Module AutomaticPKI -Force -ErrorAction Stop
        }
        catch {
            return Get-LabCheckResult -Scenario $Scenario -Check 'Import-Module AutomaticPKI' -Status 'FAIL' -Detail $_.Exception.Message
        }
    }
    try {
        switch ($Scenario) {
            'Install' { Invoke-LabScenarioInstall -Context $Context }
            'Discovery' { Invoke-LabScenarioDiscovery -Context $Context }
            'RpcEnroll' { Invoke-LabScenarioRpcEnroll -Context $Context }
            'TwoCA' { Invoke-LabScenarioTwoCA -Context $Context }
            'Pending' { Invoke-LabScenarioPending -Context $Context -Phase $Phase -RequestId $RequestId }
            'CepEnroll' { Invoke-LabScenarioCepEnroll -Context $Context -EnrollCredential $EnrollCredential }
            'Renewal' { Invoke-LabScenarioRenewal -Context $Context }
            default { Get-LabCheckResult -Scenario $Scenario -Check 'scenario' -Status 'FAIL' -Detail 'unknown scenario' }
        }
    }
    catch {
        Get-LabCheckResult -Scenario $Scenario -Check 'scenario threw' -Status 'FAIL' -Detail $_.Exception.Message
    }
}
