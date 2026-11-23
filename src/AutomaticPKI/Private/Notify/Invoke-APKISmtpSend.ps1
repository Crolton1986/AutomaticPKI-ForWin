function Invoke-APKISmtpSend {
    <#
    .SYNOPSIS
        Sends one e-mail with Send-MailMessage. Thin wrapper so tests can mock SMTP.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SmtpServer,

        [ValidateRange(1, 65535)]
        [int]$Port = 25,

        [bool]$UseSsl = $true,

        [Parameter(Mandatory)]
        [string]$From,

        [Parameter(Mandatory)]
        [string[]]$To,

        [Parameter(Mandatory)]
        [string]$Subject,

        [AllowEmptyString()]
        [string]$Body = '',

        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $mailParams = @{
        SmtpServer  = $SmtpServer
        Port        = $Port
        From        = $From
        To          = $To
        Subject     = $Subject
        Body        = $Body
        Encoding    = [System.Text.Encoding]::UTF8
        ErrorAction = 'Stop'
    }
    if ($UseSsl) {
        $mailParams['UseSsl'] = $true
    }
    if ($null -ne $Credential -and $Credential -ne [System.Management.Automation.PSCredential]::Empty) {
        $mailParams['Credential'] = $Credential
    }

    Send-MailMessage @mailParams
}
