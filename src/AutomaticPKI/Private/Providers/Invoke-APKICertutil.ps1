function Invoke-APKICertutil {
    <#
    .SYNOPSIS
        The only place providers execute certutil.exe. Mock this in tests.
    .DESCRIPTION
        Never throws for a certutil failure: the caller reads ExitCode and Output.
    .OUTPUTS
        [pscustomobject] @{ ExitCode = [int]; Output = [string[]] }
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string[]]$Arguments
    )

    # Native stderr merged via 2>&1 becomes ErrorRecords; with EAP=Stop on 5.1 that would throw.
    $ErrorActionPreference = 'Continue'
    $lines = @()
    $exitCode = -1
    try {
        $lines = @(& certutil.exe @Arguments 2>&1 | ForEach-Object { [string]$_ })
        $exitCode = $LASTEXITCODE
        if ($null -eq $exitCode) { $exitCode = -1 }
    }
    catch {
        $lines = @("certutil.exe could not be started: $($_.Exception.Message)")
        $exitCode = -1
    }

    [pscustomobject]@{
        ExitCode = [int]$exitCode
        Output   = [string[]]$lines
    }
}
