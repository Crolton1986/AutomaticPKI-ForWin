# Health checks against a real IIS site on the CI runner (windows-2022, Windows PowerShell 5.1, admin).
# Creates: a self-signed cert in LocalMachine\My, a hosts entry <TestHost> -> 127.0.0.1, an IIS
# site with an SNI https binding on <TestHost>:<Port>. Everything is removed in AfterAll.

BeforeDiscovery {
    $script:IsWindowsHost = ($PSVersionTable.PSEdition -eq 'Desktop') -or ((Get-Variable -Name IsWindows -ValueOnly -ErrorAction SilentlyContinue) -eq $true)
    $script:HasIis = $script:IsWindowsHost -and [bool](Get-Service W3SVC -ErrorAction SilentlyContinue)
}

Describe 'Health checks against IIS' -Tag 'Integration' -Skip:(-not $script:HasIis) {
    BeforeAll {
        $manifest = [System.IO.Path]::Combine($PSScriptRoot, '..', '..', 'src', 'AutomaticPKI', 'AutomaticPKI.psd1')
        Import-Module $manifest -Force -ErrorAction Stop
        $env:APKI_ROOT = $TestDrive

        $script:TestHost = 'apki-health.test'
        $script:Port = 44391
        $script:SiteName = 'APKI-HealthTest'
        $script:HostsMarker = '# APKI-HEALTH-INTEGRATION'
        $script:HostsPath = Join-Path $env:windir 'System32\drivers\etc\hosts'
        $script:SitePath = Join-Path $TestDrive 'site'

        New-Item -ItemType Directory -Path $script:SitePath -Force | Out-Null
        Set-Content -Path (Join-Path $script:SitePath 'index.htm') -Value '<html><body>APKI health test</body></html>' -Encoding UTF8

        $cert = New-SelfSignedCertificate -DnsName $script:TestHost -CertStoreLocation 'Cert:\LocalMachine\My' -NotAfter (Get-Date).AddDays(7)
        $script:Thumbprint = $cert.Thumbprint

        # Hosts entry so the hostname resolves to loopback (HTTP probe uses the hostname URL for SNI).
        [System.IO.File]::AppendAllText($script:HostsPath, ("`r`n127.0.0.1`t{0} {1}`r`n" -f $script:TestHost, $script:HostsMarker), [System.Text.Encoding]::ASCII)
        & ipconfig.exe /flushdns | Out-Null

        Add-Type -Path (Join-Path $env:windir 'System32\inetsrv\Microsoft.Web.Administration.dll')
        $sm = New-Object Microsoft.Web.Administration.ServerManager
        try {
            $existing = $sm.Sites[$script:SiteName]
            if ($existing) {
                $sm.Sites.Remove($existing)
            }
            $site = $sm.Sites.Add($script:SiteName, 'http', ('127.0.0.1:{0}:' -f ($script:Port + 1)), $script:SitePath)
            $hash = [byte[]]($cert.GetCertHash())
            $site.Bindings.Add(('*:{0}:{1}' -f $script:Port, $script:TestHost), $hash, 'My', [Microsoft.Web.Administration.SslFlags]::Sni) | Out-Null
            $sm.CommitChanges()
        }
        finally {
            $sm.Dispose()
        }

        # Wait for the site to come up (WAS picks up the config change asynchronously).
        $deadline = (Get-Date).AddSeconds(30)
        do {
            Start-Sleep -Milliseconds 500
            $probeSm = New-Object Microsoft.Web.Administration.ServerManager
            try {
                $state = [string]$probeSm.Sites[$script:SiteName].State
            }
            catch {
                $state = 'Unknown'
            }
            finally {
                $probeSm.Dispose()
            }
        } while ($state -ne 'Started' -and (Get-Date) -lt $deadline)
    }

    AfterAll {
        try {
            $sm = New-Object Microsoft.Web.Administration.ServerManager
            try {
                $site = $sm.Sites[$script:SiteName]
                if ($site) {
                    $sm.Sites.Remove($site)
                    $sm.CommitChanges()
                }
            }
            finally {
                $sm.Dispose()
            }
        }
        catch {
            Write-Warning "Cleanup: could not remove IIS site: $_"
        }

        # Belt and braces: drop the SNI sslcert entry if IIS left it behind.
        & netsh.exe http delete sslcert ("hostnameport={0}:{1}" -f $script:TestHost, $script:Port) 2>&1 | Out-Null

        if ($script:Thumbprint) {
            Remove-Item -Path ("Cert:\LocalMachine\My\{0}" -f $script:Thumbprint) -Force -ErrorAction SilentlyContinue
        }

        $lines = [System.IO.File]::ReadAllLines($script:HostsPath)
        $kept = @($lines | Where-Object { $_ -notmatch [regex]::Escape($script:HostsMarker) })
        [System.IO.File]::WriteAllLines($script:HostsPath, [string[]]$kept, [System.Text.Encoding]::ASCII)
        & ipconfig.exe /flushdns | Out-Null

        Remove-Module AutomaticPKI -Force -ErrorAction SilentlyContinue
    }

    It 'passes the TLS check with the bound thumbprint (127.0.0.1, SNI = hostname)' {
        $r = InModuleScope AutomaticPKI -Parameters @{ H = $script:TestHost; P = $script:Port; T = $script:Thumbprint } {
            param($H, $P, $T)
            Test-APKITlsBinding -HostName $H -Port $P -IPAddress '127.0.0.1' -ExpectedThumbprint $T -TimeoutSec 10
        }
        $r.Detail | Should -Match 'expected certificate'
        $r.Passed | Should -BeTrue
    }

    It 'passes the TLS check when resolving the hostname' {
        $r = InModuleScope AutomaticPKI -Parameters @{ H = $script:TestHost; P = $script:Port; T = $script:Thumbprint } {
            param($H, $P, $T)
            Test-APKITlsBinding -HostName $H -Port $P -ExpectedThumbprint $T -TimeoutSec 10
        }
        $r.Passed | Should -BeTrue
    }

    It 'fails the TLS check with a wrong thumbprint' {
        $r = InModuleScope AutomaticPKI -Parameters @{ H = $script:TestHost; P = $script:Port } {
            param($H, $P)
            Test-APKITlsBinding -HostName $H -Port $P -IPAddress '127.0.0.1' -ExpectedThumbprint ('0' * 40) -TimeoutSec 10
        }
        $r.Passed | Should -BeFalse
        $r.Detail | Should -Match $script:Thumbprint
    }

    It 'fails the TLS check quickly when nothing listens' {
        $r = InModuleScope AutomaticPKI -Parameters @{ H = $script:TestHost } {
            param($H)
            Test-APKITlsBinding -HostName $H -Port 44399 -IPAddress '127.0.0.1' -ExpectedThumbprint ('0' * 40) -TimeoutSec 5
        }
        $r.Passed | Should -BeFalse
    }

    It 'passes the HTTP probe against the SNI site' {
        $r = InModuleScope AutomaticPKI -Parameters @{ H = $script:TestHost; P = $script:Port } {
            param($H, $P)
            Test-APKIHttpProbe -Url ('https://{0}:{1}/index.htm' -f $H, $P) -ExpectStatusBelow 400 -TimeoutSec 10
        }
        $r.Detail | Should -Match 'HTTP 200'
        $r.Passed | Should -BeTrue
    }

    It 'precheck reads private key, EKU and SAN from a real certificate and rejects the untrusted self-signed chain' {
        $r = InModuleScope AutomaticPKI -Parameters @{ H = $script:TestHost; T = $script:Thumbprint } {
            param($H, $T)
            $c = Get-APKIHealthCertificate -Thumbprint $T
            Test-APKICertificatePrecheck -Certificate $c -Hostnames $H -RevocationPolicy Lenient
        }
        ($r | Where-Object Check -EQ 'PrivateKey').Passed | Should -BeTrue
        ($r | Where-Object Check -EQ 'ValidityPeriod').Passed | Should -BeTrue
        ($r | Where-Object Check -EQ 'ServerAuthEku').Passed | Should -BeTrue
        ($r | Where-Object Check -EQ 'SanCoverage').Passed | Should -BeTrue
        ($r | Where-Object Check -EQ 'ChainTrust').Passed | Should -BeFalse
    }
}
