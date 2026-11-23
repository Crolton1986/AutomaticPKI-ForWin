BeforeAll {
    $script:ModulePath = Join-Path $PSScriptRoot '../../../src/AutomaticPKI/AutomaticPKI.psd1'
    Import-Module $script:ModulePath -Force
    $script:SavedRoot = $env:APKI_ROOT

    function Set-TestSmtpConfig {
        [CmdletBinding(SupportsShouldProcess)]
        param([hashtable]$Smtp)
        if ($PSCmdlet.ShouldProcess('config.json')) {
            InModuleScope AutomaticPKI -Parameters @{ Smtp = $Smtp } {
                param($Smtp)
                Set-APKIConfig -Config @{ Smtp = $Smtp }
            }
        }
    }
}

AfterAll {
    $env:APKI_ROOT = $script:SavedRoot
}

Describe 'Send-APKINotification' {
    BeforeEach {
        $env:APKI_ROOT = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $env:APKI_ROOT -Force | Out-Null
        Mock Write-APKILog -ModuleName AutomaticPKI { }
        Mock Invoke-APKISmtpSend -ModuleName AutomaticPKI { }

        $script:EnabledSmtp = @{
            Enabled       = $true
            Server        = 'smtp.corp.local'
            Port          = 587
            UseSsl        = $true
            From          = 'apki@corp.local'
            To            = @('ops@corp.local', 'pki@corp.local')
            CredentialRef = $null
        }
    }

    It 'does nothing when SMTP is disabled (default config)' {
        InModuleScope AutomaticPKI {
            Send-APKINotification -Subject 'Certificate issued' -Body 'details' -EventId 1001
        }

        Should -Invoke Invoke-APKISmtpSend -ModuleName AutomaticPKI -Times 0 -Exactly
    }

    It 'sends through Invoke-APKISmtpSend with the configured settings when enabled' {
        Set-TestSmtpConfig -Smtp $script:EnabledSmtp

        InModuleScope AutomaticPKI {
            Send-APKINotification -Subject 'Certificate issued' -Body 'www.contoso.com renewed' -Level Info -EventId 1001 -OrderId 'contoso-web'
        }

        Should -Invoke Invoke-APKISmtpSend -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter {
            $SmtpServer -eq 'smtp.corp.local' -and
            $Port -eq 587 -and
            $UseSsl -eq $true -and
            $From -eq 'apki@corp.local' -and
            (@($To) -join ',') -eq 'ops@corp.local,pki@corp.local' -and
            $Subject -like '`[AutomaticPKI`] INFO *Certificate issued' -and
            $Body -like 'www.contoso.com renewed*' -and
            $Body -match 'Event ID: 1001' -and
            $Body -match 'Order: contoso-web' -and
            ($null -eq $Credential -or $Credential -eq [System.Management.Automation.PSCredential]::Empty)
        }
    }

    It 'passes the credential named by Smtp.CredentialRef' {
        $smtp = $script:EnabledSmtp.Clone()
        $smtp.CredentialRef = 'smtp-relay'
        Set-TestSmtpConfig -Smtp $smtp
        Mock Get-APKISecret -ModuleName AutomaticPKI {
            $secure = New-Object System.Security.SecureString
            $secure.AppendChar('x')
            New-Object System.Management.Automation.PSCredential -ArgumentList 'relay-user', $secure
        }

        InModuleScope AutomaticPKI {
            Send-APKINotification -Subject 'Renewal failed' -Body 'see log' -EventId 3000
        }

        Should -Invoke Get-APKISecret -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter { $Name -eq 'smtp-relay' }
        Should -Invoke Invoke-APKISmtpSend -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter {
            $null -ne $Credential -and $Credential.UserName -eq 'relay-user'
        }
    }

    It 'logs a warning and does not send when the credential is missing' {
        $smtp = $script:EnabledSmtp.Clone()
        $smtp.CredentialRef = 'missing'
        Set-TestSmtpConfig -Smtp $smtp

        { InModuleScope AutomaticPKI { Send-APKINotification -Subject 's' -Body 'b' -EventId 3000 } } | Should -Not -Throw

        Should -Invoke Invoke-APKISmtpSend -ModuleName AutomaticPKI -Times 0 -Exactly
        Should -Invoke Write-APKILog -ModuleName AutomaticPKI -ParameterFilter { $Level -eq 'Warning' -and $Message -like "*Secret 'missing' not found*" }
    }

    It 'logs a warning and does not send when SMTP is enabled but incomplete' {
        Set-TestSmtpConfig -Smtp @{ Enabled = $true; Server = ''; From = 'apki@corp.local'; To = @() }

        InModuleScope AutomaticPKI { Send-APKINotification -Subject 's' -Body 'b' }

        Should -Invoke Invoke-APKISmtpSend -ModuleName AutomaticPKI -Times 0 -Exactly
        Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter {
            $Level -eq 'Warning' -and $Message -like '*Smtp.Server, Smtp.To*'
        }
    }

    It 'does not throw when sending fails, and logs a warning' {
        Set-TestSmtpConfig -Smtp $script:EnabledSmtp
        Mock Invoke-APKISmtpSend -ModuleName AutomaticPKI { throw 'Unable to connect to the remote server' }

        { InModuleScope AutomaticPKI { Send-APKINotification -Subject 's' -Body 'b' -EventId 3002 } } | Should -Not -Throw

        Should -Invoke Write-APKILog -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter {
            $Level -eq 'Warning' -and $Message -like '*Unable to connect*'
        }
    }

    It 'defaults -Level to Error and accepts the T6 call shape' {
        Set-TestSmtpConfig -Smtp $script:EnabledSmtp

        InModuleScope AutomaticPKI {
            Send-APKINotification -Subject 'Rollback failed' -Body 'site may be down' -OrderId 'contoso-web'
            Send-APKINotification -Subject 'Expiring' -Body 'b' -Level 'Warning' -OrderId 'contoso-web'
        }

        Should -Invoke Invoke-APKISmtpSend -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter {
            $Subject -like '`[AutomaticPKI`] ERROR *Rollback failed' -and $Body -match 'Level: Error' -and $Body -notmatch 'Event ID'
        }
        Should -Invoke Invoke-APKISmtpSend -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter {
            $Subject -like '`[AutomaticPKI`] WARNING *Expiring'
        }
    }

    It 'does not throw when config.json is corrupt' {
        Set-Content -LiteralPath (Join-Path $env:APKI_ROOT 'config.json') -Value '{ broken' -Encoding UTF8

        { InModuleScope AutomaticPKI { Send-APKINotification -Subject 's' -Body 'b' } } | Should -Not -Throw

        Should -Invoke Invoke-APKISmtpSend -ModuleName AutomaticPKI -Times 0 -Exactly
    }
}

Describe 'Invoke-APKISmtpSend' {
    It 'maps its parameters onto Send-MailMessage' {
        Mock Send-MailMessage -ModuleName AutomaticPKI { }

        InModuleScope AutomaticPKI {
            Invoke-APKISmtpSend -SmtpServer 'smtp.corp.local' -Port 587 -UseSsl $true -From 'a@corp.local' -To 'b@corp.local' -Subject 's' -Body 'b'
        }

        Should -Invoke Send-MailMessage -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter {
            $SmtpServer -eq 'smtp.corp.local' -and $Port -eq 587 -and $UseSsl -and
            $From -eq 'a@corp.local' -and (@($To) -join ',') -eq 'b@corp.local' -and $null -eq $Credential
        }
    }

    It 'omits -UseSsl when disabled' {
        Mock Send-MailMessage -ModuleName AutomaticPKI { }

        InModuleScope AutomaticPKI {
            Invoke-APKISmtpSend -SmtpServer 'smtp.corp.local' -UseSsl $false -From 'a@corp.local' -To 'b@corp.local' -Subject 's'
        }

        Should -Invoke Send-MailMessage -ModuleName AutomaticPKI -Times 1 -Exactly -ParameterFilter { -not $UseSsl }
    }
}
