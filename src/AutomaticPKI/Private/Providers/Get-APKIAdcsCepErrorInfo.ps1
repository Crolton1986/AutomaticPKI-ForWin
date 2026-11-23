function Get-APKIAdcsCepErrorInfo {
    <#
    .SYNOPSIS
        Classifies an error thrown by Get-Certificate (via Invoke-APKIGetCertificate).
    .DESCRIPTION
        Get-Certificate reports most failures as terminating errors whose text carries the
        CertEnroll / WWS / WinHTTP HRESULT, e.g.
          CertEnroll::CX509Enrollment::Enroll: Denied by Policy Module 0x80094012 (-2146877422 CERTSRV_E_TEMPLATE_DENIED)
        The message text and every HResult in the exception chain are matched against known codes.
        Category: Denied, TemplateNotFound, AuthFailed, Unreachable, Other.
        Status: 'Denied' for Denied, otherwise 'Failed'. EventId: 3001 for Denied, otherwise 3000.
    .NOTES
        WWS codes are matched with facility 0x3D (winerror.h) and 0x4D (as printed on the
        "Windows Web Services Return Values" page) to be safe.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,

        # Output of Get-APKIAdcsCepSetting, used to make the message specific.
        [Parameter(Mandatory)]
        [psobject]$Setting
    )

    $texts = New-Object System.Collections.Generic.List[string]
    $texts.Add([string]$ErrorRecord)
    $exception = $ErrorRecord.Exception
    $depth = 0
    while ($null -ne $exception -and $depth -lt 10) {
        $texts.Add([string]$exception.Message)
        $hresult = 0
        if ($exception.PSObject.Properties['HResult']) { $hresult = [int]$exception.HResult }
        if ($hresult -ne 0) { $texts.Add(('0x{0:X8}' -f $hresult)) }
        $exception = $exception.InnerException
        $depth++
    }
    $haystack = $texts -join ' | '

    $detail = [string]$ErrorRecord.Exception.Message
    if ([string]::IsNullOrWhiteSpace($detail)) { $detail = [string]$ErrorRecord }

    $deniedPattern = '0x80094012|CERTSRV_E_TEMPLATE_DENIED|denied by (the )?policy module|request was denied|request denied'
    $templatePattern = '0x80094800|CERTSRV_E_UNSUPPORTED_CERT_TYPE|0x80094801|CERTSRV_E_NO_CERT_TYPE|template[^|]*(not found|could not be found|not supported|does not exist|is not available)'
    $authPattern = '0x80070005|E_ACCESSDENIED|access is denied|0x80[34]D0005|0x80[34]D001[C-F]|0x8009030C|SEC_E_LOGON_DENIED|0x8009030E|SEC_E_NO_CREDENTIALS|0x80090311|logon failure|unauthori[sz]ed|\b401\b'
    $unreachablePattern = '0x80[34]D000[6DE]|0x80[34]D001[04]|0x80072EE7|0x80072EFD|0x80072EE2|0x80072EFE|0x800706BA|could not be resolved|name not resolved|unable to connect|could not connect|no route|timed out|endpoint (was )?not found|actively refused|RPC server is unavailable'

    $authText = 'Kerberos (computer account)'
    if ($Setting.CredentialRef) { $authText = "credential '$($Setting.CredentialRef)'" }

    if ($haystack -match $deniedPattern) {
        $category = 'Denied'
        $lead = "The CA denied the request for template '$($Setting.Template)' (check template enroll permissions and CA policy)"
    }
    elseif ($haystack -match $templatePattern) {
        $category = 'TemplateNotFound'
        $lead = "Template '$($Setting.Template)' was not found or is not offered by the enrollment policy at $($Setting.CepUrl)"
    }
    elseif ($haystack -match $authPattern) {
        $category = 'AuthFailed'
        $lead = "Authentication to $($Setting.CepUrl) failed using $authText"
    }
    elseif ($haystack -match $unreachablePattern) {
        $category = 'Unreachable'
        $lead = "Enrollment service $($Setting.CepUrl) is unreachable"
    }
    else {
        $category = 'Other'
        $lead = "Certificate request via $($Setting.CepUrl) (template '$($Setting.Template)') failed"
    }

    $status = 'Failed'
    $eventId = 3000
    if ($category -eq 'Denied') {
        $status = 'Denied'
        $eventId = 3001
    }

    [pscustomobject]@{
        Category = $category
        Status   = $status
        EventId  = $eventId
        Message  = "AdcsCep: ${lead}: $detail"
    }
}
