function Get-APKIRoot {
    <#
    .SYNOPSIS
        Returns the data directory (config, orders, state, logs). Created on first call.
    .NOTES
        Override with $env:APKI_ROOT (tests point it at TestDrive).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $root = $env:APKI_ROOT
    if (-not $root) {
        $root = Join-Path $env:ProgramData 'AutomaticPKI'
    }
    if (-not (Test-Path -LiteralPath $root)) {
        New-Item -ItemType Directory -Path $root -Force | Out-Null
    }
    $root
}
