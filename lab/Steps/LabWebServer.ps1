# Step "Web": IIS 10 and the lab test sites on WEB01 (domain) and WEB02 (workgroup). Sites and
# bindings are created only when missing; certificates already bound (e.g. by AutomaticPKI test
# runs) are never replaced.

function Install-LabWebServer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Lab,

        [Parameter(Mandatory)]
        [hashtable]$AdminCredential,

        [Parameter(Mandatory)]
        [string]$VMName
    )
    $vm = Get-LabVMConfig -Lab $Lab -Name $VMName
    $cred = Resolve-LabGuestCredential -Lab $Lab -AdminCredential $AdminCredential -VMName $VMName
    $sites = @($Lab.Web.Sites | Where-Object { $_.VMName -eq $VMName })

    if ($vm.Role -eq 'WebWorkgroup' -and $Lab.Web.WorkgroupNameResolution -eq 'Hosts') {
        $lines = New-Object -TypeName System.Collections.Generic.List[string]
        foreach ($other in $Lab.VMs) {
            $lines.Add(('{0} {1} {2}' -f $other.IPAddress, (Get-LabFqdn -Lab $Lab -VMName $other.Name), $other.Name.ToLowerInvariant()))
        }
        foreach ($label in $Lab.Web.DnsRecords.Keys) {
            $target = Get-LabVMConfig -Lab $Lab -Name $Lab.Web.DnsRecords[$label]
            $lines.Add(('{0} {1}.{2}' -f $target.IPAddress, $label, $Lab.Domain.Name))
        }
        Write-LabStep "Writing apki.lab entries to the hosts file on $VMName"
        Invoke-LabGuest -VMName $VMName -Credential $cred -ArgumentList (, $lines.ToArray()) -ScriptBlock {
            param([string[]]$Entry)
            $ErrorActionPreference = 'Stop'
            $hostsFile = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
            $begin = '# APKI lab begin'
            $end = '# APKI lab end'
            $keep = New-Object -TypeName System.Collections.Generic.List[string]
            $inBlock = $false
            foreach ($line in Get-Content -LiteralPath $hostsFile) {
                if ($line -eq $begin) { $inBlock = $true; continue }
                if ($line -eq $end) { $inBlock = $false; continue }
                if (-not $inBlock) { $keep.Add($line) }
            }
            $keep.Add($begin)
            foreach ($e in $Entry) { $keep.Add($e) }
            $keep.Add($end)
            Set-Content -LiteralPath $hostsFile -Value $keep.ToArray() -Encoding ASCII
            Clear-DnsClientCache
        }
    }

    Write-LabStep "Ensuring IIS and $($sites.Count) site(s) on $VMName"
    Invoke-LabGuest -VMName $VMName -Credential $cred -ArgumentList ([object[]]$sites), $Lab.Web.SiteRoot, $vm.IPAddress -ScriptBlock {
        param([object[]]$Site, [string]$SiteRoot, [string]$VMAddress)
        $ErrorActionPreference = 'Stop'
        $null = Install-WindowsFeature -Name Web-Server, Web-Mgmt-Console, Web-Scripting-Tools
        Import-Module WebAdministration

        foreach ($s in $Site) {
            $path = Join-Path $SiteRoot $s.Name
            if (-not (Test-Path -LiteralPath $path)) {
                $null = New-Item -ItemType Directory -Path $path -Force
            }
            Set-Content -LiteralPath (Join-Path $path 'index.html') -Value "<html><body>AutomaticPKI lab: $($s.Name) on $env:COMPUTERNAME</body></html>" -Encoding UTF8

            foreach ($b in $s.Bindings) {
                $ip = $b.IPAddress
                if ($ip -eq 'VM') { $ip = $VMAddress }
                $hostHeader = [string]$b.HostHeader
                $bindingInfo = '{0}:{1}:{2}' -f $ip, $b.Port, $hostHeader
                $sslFlags = 0
                if ($b.Protocol -eq 'https' -and $b.Sni) { $sslFlags = 1 }

                if (-not (Get-Website -Name $s.Name)) {
                    $new = @{
                        Name         = $s.Name
                        PhysicalPath = $path
                        IPAddress    = $ip
                        Port         = [int]$b.Port
                        Force        = $true
                    }
                    if ($hostHeader) { $new.HostHeader = $hostHeader }
                    if ($b.Protocol -eq 'https') {
                        $new.Ssl = $true
                        $new.SslFlags = $sslFlags
                    }
                    $null = New-Website @new
                    continue
                }
                $exists = Get-WebBinding -Name $s.Name | Where-Object { $_.protocol -eq $b.Protocol -and $_.bindingInformation -eq $bindingInfo }
                if (-not $exists) {
                    $nb = @{
                        Name      = $s.Name
                        Protocol  = $b.Protocol
                        IPAddress = $ip
                        Port      = [int]$b.Port
                    }
                    if ($hostHeader) { $nb.HostHeader = $hostHeader }
                    if ($b.Protocol -eq 'https') { $nb.SslFlags = $sslFlags }
                    New-WebBinding @nb
                }
            }

            # Legacy self-signed certificate on non-SNI https bindings that have none yet.
            if ($s.ContainsKey('SelfSignedDnsName') -and $s.SelfSignedDnsName) {
                $friendly = 'APKI lab legacy self-signed'
                $legacy = Get-ChildItem -Path 'Cert:\LocalMachine\My' | Where-Object { $_.FriendlyName -eq $friendly } | Select-Object -First 1
                if (-not $legacy) {
                    $legacy = New-SelfSignedCertificate -DnsName $s.SelfSignedDnsName -CertStoreLocation 'Cert:\LocalMachine\My' -FriendlyName $friendly
                }
                foreach ($b in $s.Bindings) {
                    if ($b.Protocol -ne 'https' -or $b.Sni) { continue }
                    $ip = $b.IPAddress
                    if ($ip -eq 'VM') { $ip = $VMAddress }
                    $sslPath = 'IIS:\SslBindings\{0}!{1}' -f ($ip -replace '^\*$', '0.0.0.0'), $b.Port
                    if (-not (Test-Path -LiteralPath $sslPath)) {
                        $binding = Get-WebBinding -Name $s.Name | Where-Object { $_.protocol -eq 'https' -and $_.bindingInformation -eq ('{0}:{1}:' -f $ip, $b.Port) }
                        $binding.AddSslCertificate($legacy.Thumbprint, 'My')
                    }
                }
            }

            if ((Get-Website -Name $s.Name).State -ne 'Started') {
                Start-Website -Name $s.Name
            }
        }
    }
}
