function Register-APKIRenewalTask {
    <#
    .SYNOPSIS
        Registers the daily scheduled task that runs Invoke-APKIRenewal as SYSTEM.
    .DESCRIPTION
        Task '\AutomaticPKI\AutomaticPKI Renewal': daily at -At with a random delay of up to
        -RandomDelayMinutes, principal SYSTEM with highest privileges, starts when available after
        a missed run, stops after 2 hours, a new instance is ignored while one runs. Action:
          powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass
            -Command "Import-Module '<ModulePath>'; Invoke-APKIRenewal"
        An existing task is replaced only with -Force.
    .PARAMETER At
        Time of day, HH:mm (24 h).
    .PARAMETER RandomDelayMinutes
        Random start delay, spreads renewals of many servers over time.
    .PARAMETER ModulePath
        Module manifest the task imports. Default: the manifest of the loaded module.
    .PARAMETER Force
        Replace an existing task.
    .EXAMPLE
        Register-APKIRenewalTask

        Runs the renewal daily between 03:00 and 04:00.
    .EXAMPLE
        Register-APKIRenewalTask -At '22:30' -RandomDelayMinutes 30 -Force

        Moves the daily run to 22:30-23:00, replacing the existing task.
    .OUTPUTS
        PSCustomObject: TaskName, TaskPath, At, RandomDelayMinutes, Execute, Argument.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [ValidatePattern('^([01][0-9]|2[0-3]):[0-5][0-9]$')]
        [string]$At = '03:00',

        [ValidateRange(0, 720)]
        [int]$RandomDelayMinutes = 60,

        [string]$ModulePath,

        [switch]$Force
    )

    $taskName = 'AutomaticPKI Renewal'
    $taskPath = '\AutomaticPKI\'

    if (-not $ModulePath) {
        $ModulePath = Join-Path $MyInvocation.MyCommand.Module.ModuleBase 'AutomaticPKI.psd1'
    }

    $existing = Invoke-APKIScheduledTask -Operation Get -TaskName $taskName -TaskPath $taskPath
    if ($existing -and -not $Force) {
        throw "Scheduled task '$taskPath$taskName' already exists. Use -Force to replace it."
    }

    $execute = 'powershell.exe'
    if ($env:SystemRoot) {
        $execute = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    }
    $quotedPath = $ModulePath.Replace("'", "''")
    $argument = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Import-Module ''{0}''; Invoke-APKIRenewal"' -f $quotedPath
    $time = [datetime]::ParseExact($At, 'HH:mm', [System.Globalization.CultureInfo]::InvariantCulture)

    if (-not $PSCmdlet.ShouldProcess("$taskPath$taskName", "Register daily renewal task at $At")) {
        return
    }

    $definition = @{
        Operation          = 'Register'
        TaskName           = $taskName
        TaskPath           = $taskPath
        Execute            = $execute
        Argument           = $argument
        At                 = $time
        RandomDelay        = [timespan]::FromMinutes($RandomDelayMinutes)
        UserId             = 'SYSTEM'
        RunLevel           = 'Highest'
        ExecutionTimeLimit = [timespan]::FromHours(2)
        MultipleInstances  = 'IgnoreNew'
        StartWhenAvailable = $true
        Description        = 'AutomaticPKI: renews ADCS certificates bound in IIS.'
    }
    $null = Invoke-APKIScheduledTask @definition -Confirm:$false
    Write-APKILog -Message "Scheduled task '$taskPath$taskName' registered (daily $At, random delay $RandomDelayMinutes min, module '$ModulePath')."

    [pscustomobject]@{
        TaskName           = $taskName
        TaskPath           = $taskPath
        At                 = $At
        RandomDelayMinutes = $RandomDelayMinutes
        Execute            = $execute
        Argument           = $argument
    }
}
