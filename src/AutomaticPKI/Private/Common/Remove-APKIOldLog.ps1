function Remove-APKIOldLog {
    <#
    .SYNOPSIS
        Deletes logs\apki-<yyyyMMdd>.log files older than the retention period.
    .DESCRIPTION
        Retention comes from -RetentionDays, or config LogRetentionDays (default 30).
        A file dated exactly RetentionDays ago is kept; today's file is always kept.
        Files that do not match the apki-<yyyyMMdd>.log pattern are ignored.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidateRange(0, 36500)]
        [int]$RetentionDays
    )

    $days = 30
    if ($PSBoundParameters.ContainsKey('RetentionDays')) {
        $days = $RetentionDays
    }
    else {
        try {
            $config = Get-APKIConfig
            $days = [int]$config.LogRetentionDays
        }
        catch {
            Write-APKILog -Level Warning -Message ('Log cleanup uses the default retention of 30 days: {0}' -f $_.Exception.Message)
        }
    }

    $logDir = Join-Path (Get-APKIRoot) 'logs'
    if (-not (Test-Path -LiteralPath $logDir)) {
        return
    }

    $cutoff = (Get-Date).Date.AddDays(-$days)
    $removed = 0
    foreach ($file in @(Get-ChildItem -LiteralPath $logDir -Filter 'apki-*.log' -File)) {
        if ($file.Name -notmatch '^apki-(\d{8})\.log$') {
            continue
        }
        $fileDate = $null
        try {
            $fileDate = [datetime]::ParseExact($Matches[1], 'yyyyMMdd', [System.Globalization.CultureInfo]::InvariantCulture)
        }
        catch {
            Write-Verbose "Ignoring log file with an invalid date: $($file.Name)"
            continue
        }
        if ($fileDate -lt $cutoff) {
            if ($PSCmdlet.ShouldProcess($file.FullName, 'Remove old log file')) {
                try {
                    Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop
                    $removed++
                }
                catch {
                    Write-APKILog -Level Warning -Message ('Could not remove old log file {0}: {1}' -f $file.FullName, $_.Exception.Message)
                }
            }
        }
    }

    if ($removed -gt 0) {
        Write-APKILog -Message ('Removed {0} log file(s) older than {1} days.' -f $removed, $days)
    }
}
