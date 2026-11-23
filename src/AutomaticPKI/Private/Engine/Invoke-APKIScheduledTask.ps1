function Invoke-APKIScheduledTask {
    <#
    .SYNOPSIS
        The only place that calls the ScheduledTasks module (mock target).
    .DESCRIPTION
        -Operation Get       returns the task (Get-ScheduledTask) or nothing.
        -Operation Register  builds a daily task from the given values and registers it with
                             Register-ScheduledTask -Force (replaces an existing task).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Get', 'Register')]
        [string]$Operation,

        [Parameter(Mandatory)]
        [string]$TaskName,

        [string]$TaskPath = '\',

        [string]$Execute,

        [string]$Argument,

        [datetime]$At,

        [timespan]$RandomDelay = [timespan]::Zero,

        [string]$UserId = 'SYSTEM',

        [ValidateSet('Highest', 'Limited')]
        [string]$RunLevel = 'Highest',

        [timespan]$ExecutionTimeLimit = [timespan]::FromHours(2),

        [ValidateSet('IgnoreNew', 'Parallel', 'Queue', 'StopExisting')]
        [string]$MultipleInstances = 'IgnoreNew',

        [switch]$StartWhenAvailable,

        [string]$Description = ''
    )

    if ($Operation -eq 'Get') {
        return (Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue)
    }

    if (-not $PSCmdlet.ShouldProcess("$TaskPath$TaskName", 'Register scheduled task')) {
        return
    }

    $action = New-ScheduledTaskAction -Execute $Execute -Argument $Argument
    $trigger = New-ScheduledTaskTrigger -Daily -At $At -RandomDelay $RandomDelay
    $principal = New-ScheduledTaskPrincipal -UserId $UserId -LogonType ServiceAccount -RunLevel $RunLevel
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable:$StartWhenAvailable -ExecutionTimeLimit $ExecutionTimeLimit -MultipleInstances $MultipleInstances
    Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description $Description -Force
}
