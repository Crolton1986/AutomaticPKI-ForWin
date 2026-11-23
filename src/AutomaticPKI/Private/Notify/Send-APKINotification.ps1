function Send-APKINotification {
    <#
    .SYNOPSIS
        E-mails an alert using the Smtp section of config.json. No-op when Smtp.Enabled is false.
    .DESCRIPTION
        Never throws: an unreadable config, incomplete SMTP settings, a missing credential or an
        SMTP failure is logged as a warning and the caller carries on.
        Subject is prefixed with "[AutomaticPKI] <Level> <host>:"; the body gets level, host, event ID,
        order and time appended. Smtp.CredentialRef names a secret stored with Set-APKISecret.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Subject,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Body,

        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = 'Error',

        # Event ID from docs/contracts.md the alert relates to (0 = none).
        [int]$EventId = 0,

        [string]$OrderId
    )

    $config = $null
    try {
        $config = Get-APKIConfig
    }
    catch {
        Write-APKILog -Level Warning -OrderId $OrderId -Message ("Notification '{0}' not sent: configuration unavailable: {1}" -f $Subject, $_.Exception.Message)
        return
    }

    $smtp = $config.Smtp
    if (-not $smtp.Enabled) {
        Write-Verbose "SMTP notifications are disabled; not sending '$Subject'."
        return
    }

    $recipients = @(@($smtp.To) | Where-Object { $_ -is [string] -and $_.Trim() -ne '' })
    $missing = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrWhiteSpace([string]$smtp.Server)) {
        $missing.Add('Smtp.Server')
    }
    if ([string]::IsNullOrWhiteSpace([string]$smtp.From)) {
        $missing.Add('Smtp.From')
    }
    if ($recipients.Count -eq 0) {
        $missing.Add('Smtp.To')
    }
    if ($missing.Count -gt 0) {
        Write-APKILog -Level Warning -OrderId $OrderId -Message ("Notification '{0}' not sent: SMTP is enabled but {1} is not set." -f $Subject, ($missing -join ', '))
        return
    }

    $credential = $null
    if (-not [string]::IsNullOrEmpty([string]$smtp.CredentialRef)) {
        try {
            $credential = Get-APKISecret -Name ([string]$smtp.CredentialRef)
        }
        catch {
            Write-APKILog -Level Warning -OrderId $OrderId -Message ("Notification '{0}' not sent: {1}" -f $Subject, $_.Exception.Message)
            return
        }
    }

    $machine = [System.Environment]::MachineName
    $details = New-Object System.Collections.Generic.List[string]
    $details.Add(('Level: {0}' -f $Level))
    $details.Add(('Host: {0}' -f $machine))
    if ($EventId -gt 0) {
        $details.Add(('Event ID: {0}' -f $EventId))
    }
    if ($OrderId) {
        $details.Add(('Order: {0}' -f $OrderId))
    }
    $details.Add(('Time: {0}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')))

    $sendParams = @{
        SmtpServer = [string]$smtp.Server
        Port       = [int]$smtp.Port
        UseSsl     = [bool]$smtp.UseSsl
        From       = [string]$smtp.From
        To         = [string[]]$recipients
        Subject    = ('[AutomaticPKI] {0} {1}: {2}' -f $Level.ToUpperInvariant(), $machine, $Subject)
        Body       = ($Body + "`r`n`r`n-- `r`n" + ($details -join "`r`n"))
    }
    if ($null -ne $credential) {
        $sendParams['Credential'] = $credential
    }

    try {
        Invoke-APKISmtpSend @sendParams
        Write-APKILog -OrderId $OrderId -Message ("Notification '{0}' sent to {1}." -f $Subject, ($recipients -join ', '))
    }
    catch {
        Write-APKILog -Level Warning -OrderId $OrderId -Message ("Notification '{0}' could not be sent via {1}:{2}: {3}" -f $Subject, $smtp.Server, $smtp.Port, $_.Exception.Message)
    }
}
