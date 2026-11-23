function Move-APKIFileIntoPlace {
    <#
    .SYNOPSIS
        Moves a finished temp file over its target. Mock target for Write-APKIFileAtomic tests.
    .DESCRIPTION
        Existing target: [IO.File]::Replace, a single atomic swap on NTFS (Move-Item -Force on
        Windows PowerShell 5.1 is delete-then-move). New target: plain rename.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Source,

        [Parameter(Mandatory)]
        [string]$Destination
    )

    if (Test-Path -LiteralPath $Destination) {
        [System.IO.File]::Replace($Source, $Destination, [NullString]::Value)
    }
    else {
        Move-Item -LiteralPath $Source -Destination $Destination -WhatIf:$false -ErrorAction Stop
    }
}
