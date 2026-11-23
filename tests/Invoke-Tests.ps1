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
$config.Run.Exit = [bool]$CI
$config.Output.Verbosity = 'Detailed'
$config.TestResult.Enabled = [bool]$CI
$config.TestResult.OutputPath = Join-Path $root "testResults-$Suite-$($PSVersionTable.PSEdition).xml"
Invoke-Pester -Configuration $config
