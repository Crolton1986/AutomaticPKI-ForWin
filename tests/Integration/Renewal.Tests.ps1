# End-to-end renewal against the CI standalone CA (APKI-CI-CA, auto-issue) and a real IIS site.
# Creates: a self-signed cert in LocalMachine\My (the "existing" certificate to adopt), a hosts entry
# <TestHost> -> 127.0.0.1, an IIS site with an SNI https binding, and (only if missing) the CA
# certificate in LocalMachine\Root. Everything is removed in AfterAll.

BeforeDiscovery {
    $script:IsWindowsHost = ($PSVersionTable.PSEdition -eq 'Desktop') -or ((Get-Variable -Name IsWindows -ValueOnly -ErrorAction SilentlyContinue) -eq $true)
    $script:HasIisAndCa = $script:IsWindowsHost -and
    [bool](Get-Service W3SVC -ErrorAction SilentlyContinue) -and
    [bool](Get-Service CertSvc -ErrorAction SilentlyContinue)
}

Describe 'Renewal end to end' -Tag 'Integration' -Skip:(-not $script:HasIisAndCa) {
    BeforeAll {
        $manifest = [System.IO.Path]::Combine($PSScriptRoot, '..', '..', 'src', 'AutomaticPKI', 'AutomaticPKI.psd1')
        Import-Module $manifest -Force -ErrorAction Stop
        $env:APKI_ROOT = Join-Path $TestDrive 'apki'

        $script:CAName = 'APKI-CI-CA'
        $script:CAConfig = '{0}\{1}' -f $env:COMPUTERNAME, $script:CAName
        $script:TestHost = 'apki-renew.test'
        $script:Port = 44392
        $script:SiteName = 'APKI-RenewalTest'
        $script:HostsMarker = '# APKI-RENEWAL-INTEGRATION'
        $script:HostsPath = Join-Path $env:windir 'System32\drivers\etc\hosts'
        $script:SitePath = Join-Path $env:SystemDrive 'inetpub\apki-renewal-test'
        $script:AddedRootThumbprint = $null
        $script:CreatedThumbprints = New-Object System.Collections.Generic.List[string]

        # Trust the CI CA for chain validation if setup did not already do it.
        $caCertPath = Join-Path $TestDrive 'ci-ca.cer'
        & certutil.exe -config $script:CAConfig -ca.cert $caCertPath | Out-Null
        if (Test-Path -LiteralPath $caCertPath) {
            $caCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $caCertPath
            if (-not (Test-Path -LiteralPath ('Cert:\LocalMachine\Root\{0}' -f $caCert.Thumbprint))) {
                $null = Import-Certificate -FilePath $caCertPath -CertStoreLocation 'Cert:\LocalMachine\Root'
                $script:AddedRootThumbprint = $caCert.Thumbprint
            }
        }

        New-Item -ItemType Directory -Path $script:SitePath -Force | Out-Null
        Set-Content -Path (Join-Path $script:SitePath 'index.htm') -Value '<html><body>APKI renewal test</body></html>' -Encoding UTF8

        # The certificate the site already has; Find-APKISite adopts it as CurrentThumbprint.
        $selfSigned = New-SelfSignedCertificate -DnsName $script:TestHost -CertStoreLocation 'Cert:\LocalMachine\My' -NotAfter (Get-Date).AddDays(30)
        $script:SelfSignedThumbprint = $selfSigned.Thumbprint
        $script:CreatedThumbprints.Add($selfSigned.Thumbprint)

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
            $hash = [byte[]]($selfSigned.GetCertHash())
            $site.Bindings.Add(('*:{0}:{1}' -f $script:Port, $script:TestHost), $hash, 'My', [Microsoft.Web.Administration.SslFlags]::Sni) | Out-Null
            $sm.CommitChanges()
        }
        finally {
            $sm.Dispose()
        }

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

        # Standalone CA: no template. Revocation lookups are skipped (no CDP reachable on CI).
        $config = InModuleScope AutomaticPKI { Get-APKIDefaultConfig }
        $config.DefaultProviderSettings.CAConfig = $script:CAConfig
        $config.DefaultProviderSettings.Template = ''
        $config.RevocationPolicy = 'Skip'
        InModuleScope AutomaticPKI -Parameters @{ C = $config } {
            param($C)
            Set-APKIConfig -Config $C
        }

        function Get-BoundThumbprint {
            $bsm = New-Object Microsoft.Web.Administration.ServerManager
            try {
                foreach ($b in $bsm.Sites[$script:SiteName].Bindings) {
                    if ($b.Protocol -eq 'https') {
                        return (($b.CertificateHash | ForEach-Object { $_.ToString('X2') }) -join '')
                    }
                }
            }
            finally {
                $bsm.Dispose()
            }
        }
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
        & netsh.exe http delete sslcert ("hostnameport={0}:{1}" -f $script:TestHost, $script:Port) 2>&1 | Out-Null

        # Every certificate this test created or caused to be issued.
        $orderThumbs = @()
        try {
            $o = Get-APKIOrder | Where-Object { $_.SiteName -eq $script:SiteName } | Select-Object -First 1
            if ($o) {
                $orderThumbs = @($o.CurrentThumbprint, $o.PreviousThumbprint)
            }
        }
        catch {
            Write-Warning "Cleanup: could not read order: $_"
        }
        foreach ($t in @($script:CreatedThumbprints) + $orderThumbs) {
            if ($t) {
                Remove-Item -Path ("Cert:\LocalMachine\My\{0}" -f $t) -DeleteKey -Force -ErrorAction SilentlyContinue
            }
        }
        if ($script:AddedRootThumbprint) {
            Remove-Item -Path ("Cert:\LocalMachine\Root\{0}" -f $script:AddedRootThumbprint) -Force -ErrorAction SilentlyContinue
        }

        if ($script:SitePath -and (Test-Path -LiteralPath $script:SitePath)) {
            Remove-Item -LiteralPath $script:SitePath -Recurse -Force -ErrorAction SilentlyContinue
        }
        $lines = [System.IO.File]::ReadAllLines($script:HostsPath)
        $kept = @($lines | Where-Object { $_ -notmatch [regex]::Escape($script:HostsMarker) })
        [System.IO.File]::WriteAllLines($script:HostsPath, [string[]]$kept, [System.Text.Encoding]::ASCII)
        & ipconfig.exe /flushdns | Out-Null

        Remove-Module AutomaticPKI -Force -ErrorAction SilentlyContinue
    }

    It 'adopts the existing certificate as a Proposed order' {
        $null = Find-APKISite -Save
        $script:Order = Get-APKIOrder | Where-Object { $_.SiteName -eq $script:SiteName } | Select-Object -First 1
        $script:Order | Should -Not -BeNullOrEmpty
        $script:Order.Status | Should -Be 'Proposed'
        $script:Order.CurrentThumbprint | Should -Be $script:SelfSignedThumbprint
        @($script:Order.Hostnames) | Should -Contain $script:TestHost
        Get-BoundThumbprint | Should -Be $script:SelfSignedThumbprint
    }

    It 'issues from the CI CA, binds, and activates the order' {
        $id = $script:Order.Id
        $approved = Approve-APKIOrder -Id $id -Hostname $script:TestHost
        $approved.ProviderSettings.CAConfig | Should -Be $script:CAConfig

        $r = New-APKICertificate -Id $id
        $r.Outcome | Should -Be 'Renewed' -Because $r.Message

        $order = Get-APKIOrder -Id $id
        $order.Status | Should -Be 'Active'
        $order.LastError | Should -BeNullOrEmpty
        $order.PreviousThumbprint | Should -Be $script:SelfSignedThumbprint
        $script:FirstThumbprint = $order.CurrentThumbprint

        $cert = Get-Item -Path ("Cert:\LocalMachine\My\{0}" -f $script:FirstThumbprint)
        $cert.Issuer | Should -Match ('CN={0}' -f [regex]::Escape($script:CAName))
        $cert.HasPrivateKey | Should -BeTrue
        Get-BoundThumbprint | Should -Be $script:FirstThumbprint

        $health = Test-APKISite -Id $id
        $failures = @($health.Results | Where-Object { -not $_.Passed } | ForEach-Object { '{0} {1}: {2}' -f $_.Check, $_.Target, $_.Detail }) -join '; '
        $health.Passed | Should -BeTrue -Because $failures
    }

    It 'does nothing when the certificate is not due' {
        $r = New-APKICertificate -Id $script:Order.Id
        $r.Outcome | Should -Be 'NotDue' -Because $r.Message
        (Get-APKIOrder -Id $script:Order.Id).CurrentThumbprint | Should -Be $script:FirstThumbprint
    }

    It 'replaces the certificate with -Force and records the previous one' {
        $r = New-APKICertificate -Id $script:Order.Id -Force
        $r.Outcome | Should -Be 'Renewed' -Because $r.Message

        $order = Get-APKIOrder -Id $script:Order.Id
        $order.Status | Should -Be 'Active'
        $order.PreviousThumbprint | Should -Be $script:FirstThumbprint
        $order.CurrentThumbprint | Should -Not -Be $script:FirstThumbprint
        Get-BoundThumbprint | Should -Be $order.CurrentThumbprint
        (Test-APKISite -Id $script:Order.Id).Passed | Should -BeTrue

        # The self-signed cert is no longer referenced by the order; AfterAll still removes it
        # (CreatedThumbprints). Track the first issued cert too.
        $script:CreatedThumbprints.Add($script:FirstThumbprint)
    }
}
