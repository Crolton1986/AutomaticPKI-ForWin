function Write-APKILog {
    <#
    .SYNOPSIS
        Central logging entry point. Every module component logs through this.
    .DESCRIPTION
        Appends one line to <root>\logs\apki-<yyyyMMdd>.log. When EventId is greater than 0 the
        entry is also written to the Application event log under source 'AutomaticPKI'.
        Never throws: a logging failure must not break a renewal.
    .NOTES
        Signature is a contract: do not change parameters without updating docs/contracts.md.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = 'Info',

        # Fixed event ID from docs/contracts.md. 0 = no Event Log entry.
        [int]$EventId = 0,

        # Order the message relates to, if any.
        [string]$OrderId
    )

    $now = Get-Date
    $orderPart = ''
    if ($OrderId) {
        $orderPart = "[$OrderId] "
    }
    # One entry per line in the file; the Event Log keeps the original text.
    $flatMessage = $Message -replace "\r?\n", ' | '
    $line = '{0} [{1}] [{2}] {3}{4}' -f $now.ToString('yyyy-MM-ddTHH:mm:ss.fffzzz'), $Level, $EventId, $orderPart, $flatMessage

    switch ($Level) {
        'Warning' { Write-Warning $line }
        'Error'   { Write-Warning $line }
        default   { Write-Verbose $line }
    }

    # -WhatIf:$false everywhere: logging must happen even when a caller runs with -WhatIf.
    try {
        $logDir = Join-Path (Get-APKIRoot) 'logs'
        if (-not (Test-Path -LiteralPath $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force -WhatIf:$false -ErrorAction Stop | Out-Null
        }
        $logFile = Join-Path $logDir ('apki-{0}.log' -f $now.ToString('yyyyMMdd'))

        # Another process (scheduled task + interactive admin) may hold the file briefly.
        $attempt = 0
        $written = $false
        while (-not $written) {
            $attempt++
            try {
                Add-Content -LiteralPath $logFile -Value $line -Encoding UTF8 -WhatIf:$false -ErrorAction Stop
                $written = $true
            }
            catch {
                if ($attempt -ge 3) {
                    throw
                }
                Start-Sleep -Milliseconds 100
            }
        }
    }
    catch {
        Write-Warning ('AutomaticPKI: could not write log file: {0}' -f $_.Exception.Message)
    }

    if ($EventId -gt 0) {
        try {
            Write-APKIEventLogEntry -Message $Message -Level $Level -EventId $EventId -OrderId $OrderId
        }
        catch {
            Write-Verbose ('AutomaticPKI: could not write Event Log entry: {0}' -f $_.Exception.Message)
        }
    }
}
