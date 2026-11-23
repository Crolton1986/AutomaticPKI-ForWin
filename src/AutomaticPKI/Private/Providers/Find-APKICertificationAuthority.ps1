function Find-APKICertificationAuthority {
    <#
    .SYNOPSIS
        Discovers certification authorities this host can enroll from: enterprise CAs published
        in Active Directory (AdcsRpc) and enrollment policy servers from Group Policy (AdcsCep).
    .DESCRIPTION
        Domain-joined: enterprise CAs are read from AD (Get-APKIAdEnrollmentService); when the
        LDAP search throws, certutil -ADCA (Get-APKICertutilAdca) is used instead. With
        -Template, AD candidates that do not publish the template (case-insensitive) are dropped.
        Not domain-joined: AD is not queried.
        Always: https enrollment policy URLs configured for the machine
        (Get-APKIGpoEnrollmentPolicyServer) become AdcsCep candidates. They cannot be filtered
        by template (PublishedTemplates is empty) and are kept.
        Each candidate is tested with Test-APKIAdcsRpcProvider / Test-APKIAdcsCepProvider;
        unreachable candidates are returned with Reachable = $false.
        Logs 1005 per reachable candidate, 2003 when more than one is reachable, 2004 when none
        is. Never writes configuration (docs/contracts.md, "CA candidate").
    .OUTPUTS
        CA candidate objects (docs/contracts.md): Provider, CAConfig, CepUrl, CAHost, CAName,
        PublishedTemplates, Source, Reachable.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Template
    )

    $templateFilter = $null
    if (-not [string]::IsNullOrWhiteSpace($Template)) { $templateFilter = $Template.Trim() }

    $candidates = New-Object System.Collections.Generic.List[object]

    $newCandidate = {
        param([string]$Provider, [string]$CAConfig, [string]$CepUrl, [string]$CAHost, [string]$CAName, [string[]]$Templates, [string]$Source)
        $c = [pscustomobject]@{
            Provider           = $Provider
            CAConfig           = $null
            CepUrl             = $null
            CAHost             = $CAHost
            CAName             = $null
            PublishedTemplates = [string[]]@()
            Source             = $Source
            Reachable          = $false
        }
        if ($CAConfig) { $c.CAConfig = $CAConfig }
        if ($CepUrl) { $c.CepUrl = $CepUrl }
        if ($CAName) { $c.CAName = $CAName }
        if ($null -ne $Templates) { $c.PublishedTemplates = [string[]]$Templates }
        $c
    }

    # 1. Enterprise CAs from Active Directory (domain members only).
    $domainJoined = $false
    try {
        $domainJoined = [bool](Test-APKIDomainJoined)
    }
    catch {
        Write-APKILog -Message ('CA discovery: cannot tell whether this computer is domain-joined; Active Directory is not queried: {0}' -f $_.Exception.Message) -Level Warning
    }

    if ($domainJoined) {
        $services = @()
        try {
            $services = @(Get-APKIAdEnrollmentService)
        }
        catch {
            Write-APKILog -Message ('CA discovery: LDAP search of Enrollment Services failed ({0}); trying certutil -ADCA.' -f $_.Exception.Message) -Level Warning
            try {
                $services = @(Get-APKICertutilAdca)
            }
            catch {
                Write-APKILog -Message ('CA discovery: certutil -ADCA failed: {0}' -f $_.Exception.Message) -Level Warning
                $services = @()
            }
        }

        $seen = @{}
        foreach ($svc in $services) {
            if ($null -eq $svc) { continue }
            $caHost = ([string](Get-APKIOptionalProperty -InputObject $svc -Name 'DnsHostName' -Default '')).Trim()
            $caName = ([string](Get-APKIOptionalProperty -InputObject $svc -Name 'Name' -Default '')).Trim()
            if (-not $caHost -or -not $caName) {
                Write-Verbose "CA discovery: skipping enrollment service without dNSHostName or cn ('$caHost', '$caName')."
                continue
            }
            $templates = @(@(Get-APKIOptionalProperty -InputObject $svc -Name 'Templates' -Default @()) |
                    Where-Object { $null -ne $_ -and ([string]$_).Trim() } | ForEach-Object { ([string]$_).Trim() })
            # -contains compares strings case-insensitively.
            if ($templateFilter -and $templates -notcontains $templateFilter) {
                Write-Verbose "CA discovery: '$caHost\$caName' does not publish template '$templateFilter'."
                continue
            }
            $caConfig = '{0}\{1}' -f $caHost, $caName
            if ($seen.ContainsKey($caConfig)) { continue }
            $seen[$caConfig] = $true
            $candidates.Add((& $newCandidate -Provider 'AdcsRpc' -CAConfig $caConfig -CAHost $caHost -CAName $caName -Templates ([string[]]$templates) -Source 'AD'))
        }
    }

    # 2. Enrollment policy servers (CEP) configured for the machine, typically by Group Policy.
    $policies = @()
    try {
        $policies = @(Get-APKIGpoEnrollmentPolicyServer)
    }
    catch {
        Write-Verbose ('CA discovery: enrollment policy servers could not be read: {0}' -f $_.Exception.Message)
        $policies = @()
    }
    $seenUrl = @{}
    foreach ($policy in $policies) {
        if ($null -eq $policy) { continue }
        $rawUrl = Get-APKIOptionalProperty -InputObject $policy -Name 'Url' -Default $null
        if ($null -eq $rawUrl) { continue }
        $url = ''
        if ($rawUrl -is [System.Uri]) { $url = $rawUrl.AbsoluteUri } else { $url = ([string]$rawUrl).Trim() }
        $parsed = $null
        # The built-in "Active Directory Enrollment Policy" (ldap:) is covered by step 1.
        if (-not [System.Uri]::TryCreate($url, [System.UriKind]::Absolute, [ref]$parsed) -or $parsed.Scheme -ne 'https') {
            Write-Verbose "CA discovery: skipping enrollment policy '$url' (not an https CEP URL)."
            continue
        }
        if ($seenUrl.ContainsKey($url.ToLowerInvariant())) { continue }
        $seenUrl[$url.ToLowerInvariant()] = $true

        $policyName = [string](Get-APKIOptionalProperty -InputObject $policy -Name 'FriendlyName' -Default '')
        if (-not $policyName) { $policyName = [string](Get-APKIOptionalProperty -InputObject $policy -Name 'Id' -Default '') }
        $candidates.Add((& $newCandidate -Provider 'AdcsCep' -CepUrl $url -CAHost $parsed.DnsSafeHost -CAName $policyName -Source 'GPO'))
    }

    # 3. Reachability through the provider's own test (minimal order).
    $probeTemplate = 'WebServer'
    if ($templateFilter) { $probeTemplate = $templateFilter }
    foreach ($c in $candidates) {
        $reachable = $false
        $target = $c.CAConfig
        if (-not $target) { $target = $c.CepUrl }
        try {
            if ($c.Provider -eq 'AdcsRpc') {
                $order = [pscustomobject]@{
                    Id               = ''
                    Provider         = 'AdcsRpc'
                    Hostnames        = [string[]]@('localhost')
                    ProviderSettings = [pscustomobject]@{ CAConfig = $c.CAConfig; Template = $probeTemplate }
                }
                $reachable = [bool](Test-APKIAdcsRpcProvider -Order $order)
            }
            else {
                $order = [pscustomobject]@{
                    Id               = ''
                    Provider         = 'AdcsCep'
                    Hostnames        = [string[]]@('localhost')
                    ProviderSettings = [pscustomobject]@{ CepUrl = $c.CepUrl; Template = $probeTemplate; CredentialRef = $null }
                }
                $reachable = [bool](Test-APKIAdcsCepProvider -Order $order)
            }
        }
        catch {
            Write-APKILog -Message ('CA discovery: reachability test for {0} failed: {1}' -f $target, $_.Exception.Message) -Level Warning
            $reachable = $false
        }
        $c.Reachable = $reachable
    }

    # 4. Logging.
    $reachableList = @($candidates | Where-Object { $_.Reachable })
    $describe = {
        param($Candidate)
        if ($Candidate.Provider -eq 'AdcsRpc') { return ('{0} (AdcsRpc, {1})' -f $Candidate.CAConfig, $Candidate.Source) }
        ('{0} (AdcsCep, {1})' -f $Candidate.CepUrl, $Candidate.Source)
    }
    foreach ($c in $reachableList) {
        Write-APKILog -Message ('Certification authority discovered: {0}.' -f (& $describe $c)) -Level Info -EventId 1005
    }

    $templateText = ''
    if ($templateFilter) { $templateText = " publishing template '$templateFilter'" }
    if ($reachableList.Count -gt 1) {
        $names = ($reachableList | ForEach-Object { & $describe $_ }) -join '; '
        Write-APKILog -Message ('{0} reachable certification authorities{1} found: {2}. None is selected automatically; choose one with Set-APKIConfig.' -f $reachableList.Count, $templateText, $names) -Level Warning -EventId 2003
    }
    elseif ($reachableList.Count -eq 0) {
        $candidateCount = $candidates.Count
        if (-not $domainJoined -and $candidateCount -eq 0) {
            $message = 'No certification authority found: this computer is not domain-joined and no enrollment policy server is configured. Set ProviderSettings.CepUrl manually or via the orchestrator.'
        }
        elseif ($candidateCount -gt 0) {
            $message = ('No reachable certification authority{0} found ({1} candidate(s) did not answer). Check connectivity or set DefaultProviderSettings with Set-APKIConfig.' -f $templateText, $candidateCount)
            if (-not $domainJoined) {
                $message += ' This computer is not domain-joined: set ProviderSettings.CepUrl manually or via the orchestrator.'
            }
        }
        else {
            $message = ('No certification authority{0} found in Active Directory or enrollment policy. Publish the template on a CA or set DefaultProviderSettings with Set-APKIConfig.' -f $templateText)
        }
        Write-APKILog -Message $message -Level Warning -EventId 2004
    }

    $candidates.ToArray()
}
