function ConvertFrom-APKICertreqOutput {
    <#
    .SYNOPSIS
        Parses certreq.exe -submit / -retrieve / -accept output. Pure function.
    .DESCRIPTION
        Disposition is one of:
          Issued       "Certificate retrieved(Issued) Issued"
          Denied       "Certificate not issued (Denied) Denied by Policy Module ..." / "(Denied)"
          Pending      "Certificate request is pending: Taken Under Submission (0)"
          Unavailable  RPC/DCOM failure reaching the CA (0x800706ba RPC_S_SERVER_UNAVAILABLE etc.)
          Error        any other HRESULT in the output, or non-zero exit code
          Unknown      nothing recognisable (malformed / empty output, exit code 0)
        Also extracts RequestId, the first HRESULT, and (for -accept) Thumbprint / SerialNumber.
        Parsing relies on English certreq output (en-US Windows Server).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$Output,

        [int]$ExitCode = 0
    )

    $lines = @()
    foreach ($l in @($Output)) {
        if ($null -eq $l) { continue }
        $t = ([string]$l).Trim()
        if ($t) { $lines += $t }
    }
    $text = $lines -join "`n"

    $requestId = $null
    $m = [regex]::Match($text, '(?im)^RequestId:\s*"?(\d+)"?\s*$')
    if ($m.Success) { $requestId = $m.Groups[1].Value }

    $errorCode = $null
    $m = [regex]::Match($text, '0x[0-9a-fA-F]{8}')
    if ($m.Success) { $errorCode = $m.Value.ToLowerInvariant() }

    $thumbprint = $null
    $m = [regex]::Match($text, '(?im)^Thumbprint:\s*([0-9a-f ]+?)\s*$')
    if ($m.Success) {
        $candidate = ($m.Groups[1].Value -replace '\s', '').ToUpperInvariant()
        if ($candidate -match '^[0-9A-F]{40}$') { $thumbprint = $candidate }
    }

    $serial = $null
    $m = [regex]::Match($text, '(?im)^Serial Number:\s*([0-9a-f ]+?)\s*$')
    if ($m.Success) { $serial = ($m.Groups[1].Value -replace '\s', '').ToUpperInvariant() }

    # HRESULTs that mean "could not reach the CA" rather than "the CA said no".
    $unavailableCodes = @(
        '0x800706ba', # RPC_S_SERVER_UNAVAILABLE
        '0x800706be', # RPC_S_CALL_FAILED
        '0x800706bf', # RPC_S_CALL_FAILED_DNE
        '0x800706d9', # EPT_S_NOT_REGISTERED
        '0x80080005', # CO_E_SERVER_EXEC_FAILURE
        '0x80070424'  # ERROR_SERVICE_DOES_NOT_EXIST (CertSvc missing)
    )
    $allCodes = @([regex]::Matches($text, '0x[0-9a-fA-F]{8}') | ForEach-Object { $_.Value.ToLowerInvariant() })

    $unavailable = $false
    foreach ($c in $allCodes) {
        if ($unavailableCodes -contains $c) { $unavailable = $true }
    }
    if ($text -match '(?i)RPC server is unavailable|RPC_S_SERVER_UNAVAILABLE|EPT_S_NOT_REGISTERED') {
        $unavailable = $true
    }

    $disposition = 'Unknown'
    if ($text -match '(?i)\(Issued\)') {
        $disposition = 'Issued'
    }
    elseif ($text -match '(?i)\(Denied\)|Denied by |has been denied') {
        $disposition = 'Denied'
    }
    elseif ($text -match '(?i)request is pending|Taken Under Submission|\(Under Submission\)') {
        $disposition = 'Pending'
    }
    elseif ($unavailable) {
        $disposition = 'Unavailable'
    }
    elseif ($errorCode -or $ExitCode -ne 0) {
        $disposition = 'Error'
    }

    $message = ($lines -join ' ')
    if (-not $message) { $message = "certreq returned no output (exit code $ExitCode)." }

    [pscustomobject]@{
        Disposition  = $disposition
        RequestId    = $requestId
        ErrorCode    = $errorCode
        Thumbprint   = $thumbprint
        SerialNumber = $serial
        ExitCode     = $ExitCode
        Message      = $message
    }
}
