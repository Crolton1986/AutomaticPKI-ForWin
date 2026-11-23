[CmdletBinding()]
param(
    [ValidateSet('Unit', 'Integration', 'All')]
    [string]$Suite = 'Unit',
    [switch]$CI
)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent

$pester = Get-Module -ListAvailable Pester | Where-Object { $_.Version -ge [version]'5.5.0' } | Select-Object -First 1
if (-not $pester) {
    Install-Module Pester -MinimumVersion 5.5.0 -Scope CurrentUser -Force -SkipPublisherCheck
}
Import-Module Pester -MinimumVersion 5.5.0

$paths = switch ($Suite) {
    'Unit'        { @(Join-Path $PSScriptRoot 'Unit') }
    'Integration' { @(Join-Path $PSScriptRoot 'Integration') }
    'All'         { @((Join-Path $PSScriptRoot 'Unit'), (Join-Path $PSScriptRoot 'Integration')) }
}

$config = New-PesterConfiguration
$config.Run.Path = $paths
$config.Run.PassThru = $true
$config.Output.Verbosity = 'Detailed'
$config.TestResult.Enabled = [bool]$CI
$config.TestResult.OutputPath = Join-Path $root "testResults-$Suite-$($PSVersionTable.PSEdition).xml"
$result = Invoke-Pester -Configuration $config

if ($result.FailedCount -gt 0 -or $result.FailedContainersCount -gt 0) {
    Write-Output ''
    Write-Output "===== FAILURE SUMMARY ($($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)) ====="
    foreach ($c in $result.Containers | Where-Object { $_.Result -eq 'Failed' -and $_.ErrorRecord }) {
        Write-Output ('CONTAINER {0}: {1}' -f $c.Item, ($c.ErrorRecord | Select-Object -First 1))
    }
    foreach ($t in $result.Failed) {
        $msg = ''
        if ($t.ErrorRecord) { $msg = ($t.ErrorRecord | Select-Object -First 1).Exception.Message -replace '\s+', ' ' }
        Write-Output ('FAIL {0} :: {1}' -f $t.ExpandedPath, $msg)
    }
    if ($CI) { exit 1 }
}
