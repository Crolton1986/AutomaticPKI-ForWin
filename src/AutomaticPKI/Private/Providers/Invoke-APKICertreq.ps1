function Invoke-APKICertreq {
    <#
    .SYNOPSIS
        The only place certreq.exe is executed. Mock this in tests.
    .DESCRIPTION
        Always runs certreq in quiet mode (-q) so it can never block on a UI prompt in a
        scheduled task; -q is inserted after the verb if the caller left it out.
        Never throws for a certreq failure: the caller reads ExitCode and Output.
    .OUTPUTS
        [pscustomobject] @{ ExitCode = [int]; Output = [string[]] }
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string[]]$Arguments
    )

    $argList = @($Arguments)
    if ($argList -notcontains '-q') {
        if ($argList.Count -gt 0 -and $argList[0] -like '-*') {
            $argList = @($argList[0], '-q') + @($argList | Select-Object -Skip 1)
        }
        else {
            $argList = @('-q') + $argList
        }
    }

    # Native stderr merged via 2>&1 becomes ErrorRecords; with EAP=Stop on 5.1 that would throw.
    $ErrorActionPreference = 'Continue'
    $lines = @()
    $exitCode = -1
    try {
        $lines = @(& certreq.exe @argList 2>&1 | ForEach-Object { [string]$_ })
        $exitCode = $LASTEXITCODE
        if ($null -eq $exitCode) { $exitCode = -1 }
    }
    catch {
        $lines = @("certreq.exe could not be started: $($_.Exception.Message)")
        $exitCode = -1
    }

    [pscustomobject]@{
        ExitCode = [int]$exitCode
        Output   = [string[]]$lines
    }
}
