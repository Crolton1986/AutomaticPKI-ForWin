BeforeDiscovery {
    $script:IsWindowsHost = ($PSVersionTable.PSEdition -eq 'Desktop') -or ((Test-Path variable:IsWindows) -and $IsWindows)
    $script:HasIis = $script:IsWindowsHost -and [bool](Get-Service -Name W3SVC -ErrorAction SilentlyContinue)
}

Describe 'IIS binding engine (real IIS)' -Tag 'Integration' -Skip:(-not $script:HasIis) {
    BeforeAll {
        Import-Module (Join-Path $PSScriptRoot '../../src/AutomaticPKI/AutomaticPKI.psd1') -Force
        $env:APKI_ROOT = Join-Path $TestDrive 'apki'

        $script:SniSite = 'APKI-IT-Sni'
        $script:IpSite = 'APKI-IT-Ip'
        $script:Port = 8443
        $script:IpPort = 8444
        $script:SniHost = 'apki-sni.it.test'
        $script:NewHost = 'apki-new.it.test'
        $script:Ip = '127.0.0.1'

        $script:Certs = @()
        $script:OldSni = New-SelfSignedCertificate -DnsName $script:SniHost -CertStoreLocation 'Cert:\LocalMachine\My' -FriendlyName 'APKI-IT old SNI'
        $script:OldIp = New-SelfSignedCertificate -DnsName 'apki-ip.it.test' -CertStoreLocation 'Cert:\LocalMachine\My' -FriendlyName 'APKI-IT old IP'
        $script:NewCert = New-SelfSignedCertificate -DnsName $script:SniHost, $script:NewHost, 'apki-ip.it.test' -CertStoreLocation 'Cert:\LocalMachine\My' -FriendlyName 'APKI-IT new'
        $script:Certs = @($script:OldSni, $script:OldIp, $script:NewCert)

        foreach ($name in $script:SniSite, $script:IpSite) {
            $dir = Join-Path $TestDrive $name
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }

        InModuleScope AutomaticPKI -Parameters @{
            SniSite = $script:SniSite; IpSite = $script:IpSite; Root = $TestDrive
            Port = $script:Port; IpPort = $script:IpPort; SniHost = $script:SniHost; Ip = $script:Ip
            OldSni = $script:OldSni.Thumbprint; OldIp = $script:OldIp.Thumbprint
        } {
            param($SniSite, $IpSite, $Root, $Port, $IpPort, $SniHost, $Ip, $OldSni, $OldIp)
            $sm = Get-APKIServerManager
            foreach ($n in $SniSite, $IpSite) {
                $existing = $sm.Sites[$n]
                if ($existing) {
                    $sm.Sites.Remove($existing)
                }
            }
            $s1 = $sm.Sites.Add($SniSite, 'http', ('*:8081:{0}' -f $SniHost), (Join-Path $Root $SniSite))
            [void]$s1.Bindings.Add(('*:{0}:{1}' -f $Port, $SniHost), (ConvertTo-APKICertificateHash -Thumbprint $OldSni), 'My', 1)
            $s2 = $sm.Sites.Add($IpSite, 'http', '*:8082:', (Join-Path $Root $IpSite))
            [void]$s2.Bindings.Add(('{0}:{1}:' -f $Ip, $IpPort), (ConvertTo-APKICertificateHash -Thumbprint $OldIp), 'My')
            $sm.CommitChanges()
        }

        $script:Order = [pscustomobject]@{
            Id            = 'apki-it'
            Status        = 'Active'
            SiteName      = $script:SniSite
            CreateBinding = $true
            Bindings      = @(
                [pscustomobject]@{ SiteName = $script:SniSite; Protocol = 'https'; IPAddress = '*'; Port = $script:Port; HostHeader = $script:SniHost; SslFlags = 1 }
                [pscustomobject]@{ SiteName = $script:SniSite; Protocol = 'https'; IPAddress = '*'; Port = $script:Port; HostHeader = $script:NewHost; SslFlags = 1 }
                [pscustomobject]@{ SiteName = $script:IpSite; Protocol = 'https'; IPAddress = $script:Ip; Port = $script:IpPort; HostHeader = ''; SslFlags = 0 }
            )
        }

        function Get-ItBinding {
            param([string]$SiteName)
            @(InModuleScope AutomaticPKI -Parameters @{ S = $SiteName } {
                    param($S)
                    Get-APKIIisBinding -SiteName $S
                })
        }

        function Get-HttpSysCertHash {
            # Certificate hash http.sys holds for an endpoint ('' when there is no entry).
            param([string]$Endpoint, [switch]$Sni)
            $kind = 'ipport'
            if ($Sni) { $kind = 'hostnameport' }
            $out = & netsh.exe http show sslcert ('{0}={1}' -f $kind, $Endpoint) 2>&1 | Out-String
            $m = [regex]::Match($out, 'Certificate Hash\s*:\s*([0-9a-fA-F]+)')
            if ($m.Success) { return $m.Groups[1].Value.ToUpperInvariant() }
            ''
        }
    }

    AfterAll {
        InModuleScope AutomaticPKI -Parameters @{ SniSite = $script:SniSite; IpSite = $script:IpSite } {
            param($SniSite, $IpSite)
            $sm = Get-APKIServerManager
            foreach ($n in $SniSite, $IpSite) {
                $site = $sm.Sites[$n]
                if ($site) {
                    foreach ($b in @($site.Bindings)) {
                        if ($b.Protocol -eq 'https') {
                            $site.Bindings.Remove($b, $false)
                        }
                    }
                    $sm.Sites.Remove($site)
                }
            }
            $sm.CommitChanges()
        }
        foreach ($ep in ('{0}:{1}' -f $script:SniHost, $script:Port), ('{0}:{1}' -f $script:NewHost, $script:Port)) {
            & netsh.exe http delete sslcert ('hostnameport={0}' -f $ep) 2>&1 | Out-Null
        }
        & netsh.exe http delete sslcert ('ipport={0}:{1}' -f $script:Ip, $script:IpPort) 2>&1 | Out-Null
        foreach ($c in $script:Certs) {
            if ($c) {
                Remove-Item -LiteralPath ('Cert:\LocalMachine\My\{0}' -f $c.Thumbprint) -Force -ErrorAction SilentlyContinue
            }
        }
    }

    It 'reads the SNI and IP:port bindings' {
        $sni = Get-ItBinding -SiteName $script:SniSite | Where-Object Protocol -EQ 'https'
        $sni.HostHeader | Should -Be $script:SniHost
        $sni.SslFlags | Should -Be 1
        $sni.Thumbprint | Should -Be $script:OldSni.Thumbprint
        $sni.NameStatus | Should -Be 'Usable'

        $ip = Get-ItBinding -SiteName $script:IpSite | Where-Object Protocol -EQ 'https'
        $ip.IPAddress | Should -Be $script:Ip
        $ip.Port | Should -Be $script:IpPort
        $ip.SslFlags | Should -Be 0
        $ip.Thumbprint | Should -Be $script:OldIp.Thumbprint
        $ip.NameStatus | Should -Be 'Usable'   # SAN apki-ip.it.test on the bound certificate
    }

    It 'swaps, creates and restores bindings' {
        $snapshot = InModuleScope AutomaticPKI -Parameters @{ O = $script:Order } {
            param($O)
            Save-APKIBindingSnapshot -Order $O -Confirm:$false
        }
        $snapshot.Path | Should -Exist

        $swap = @(InModuleScope AutomaticPKI -Parameters @{ O = $script:Order; T = $script:NewCert.Thumbprint } {
                param($O, $T)
                Set-APKIIisCertificateBinding -Order $O -Thumbprint $T -Confirm:$false
            })
        @($swap | Where-Object Action -EQ 'Created').Count | Should -Be 1

        $sniAfter = Get-ItBinding -SiteName $script:SniSite | Where-Object Protocol -EQ 'https'
        @($sniAfter).Count | Should -Be 2
        foreach ($b in $sniAfter) {
            $b.Thumbprint | Should -Be $script:NewCert.Thumbprint
            $b.SslFlags | Should -Be 1
        }
        (Get-ItBinding -SiteName $script:IpSite | Where-Object Protocol -EQ 'https').Thumbprint | Should -Be $script:NewCert.Thumbprint
        Get-HttpSysCertHash -Endpoint ('{0}:{1}' -f $script:SniHost, $script:Port) -Sni | Should -Be $script:NewCert.Thumbprint
        Get-HttpSysCertHash -Endpoint ('{0}:{1}' -f $script:NewHost, $script:Port) -Sni | Should -Be $script:NewCert.Thumbprint
        Get-HttpSysCertHash -Endpoint ('{0}:{1}' -f $script:Ip, $script:IpPort) | Should -Be $script:NewCert.Thumbprint

        $null = InModuleScope AutomaticPKI -Parameters @{ O = $script:Order; S = $snapshot } {
            param($O, $S)
            Restore-APKIBindingSnapshot -Order $O -Snapshot $S -Confirm:$false
        }

        $sniBack = @(Get-ItBinding -SiteName $script:SniSite | Where-Object Protocol -EQ 'https')
        $sniBack.Count | Should -Be 1
        $sniBack[0].HostHeader | Should -Be $script:SniHost
        $sniBack[0].Thumbprint | Should -Be $script:OldSni.Thumbprint
        $sniBack[0].SslFlags | Should -Be 1
        (Get-ItBinding -SiteName $script:IpSite | Where-Object Protocol -EQ 'https').Thumbprint | Should -Be $script:OldIp.Thumbprint
        Get-HttpSysCertHash -Endpoint ('{0}:{1}' -f $script:SniHost, $script:Port) -Sni | Should -Be $script:OldSni.Thumbprint
        Get-HttpSysCertHash -Endpoint ('{0}:{1}' -f $script:NewHost, $script:Port) -Sni | Should -Be ''
        Get-HttpSysCertHash -Endpoint ('{0}:{1}' -f $script:Ip, $script:IpPort) | Should -Be $script:OldIp.Thumbprint
    }

    It 'proposes candidates for the test sites' {
        $candidates = @(InModuleScope AutomaticPKI { Find-APKISiteCandidate })
        $sni = $candidates | Where-Object SiteName -EQ $script:SniSite
        $sni.Status | Should -Be 'Proposed'
        @($sni.Hostnames) | Should -Contain $script:SniHost
        $ip = $candidates | Where-Object SiteName -EQ $script:IpSite
        @($ip.Hostnames) | Should -Contain 'apki-ip.it.test'
    }
}
