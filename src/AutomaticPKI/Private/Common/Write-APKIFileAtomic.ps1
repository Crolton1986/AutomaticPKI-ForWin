function Write-APKIFileAtomic {
    <#
    .SYNOPSIS
        Writes text to a file by writing a temp file in the same directory and moving it over the target.
    .DESCRIPTION
        A crash or error mid-write leaves the previous file intact and no temp file behind.
        Callers handle -WhatIf themselves; this helper always writes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Content
    )

    $dir = Split-Path -Path $Path -Parent
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force -WhatIf:$false -ErrorAction Stop | Out-Null
    }

    # Same directory as the target so the move is a rename on the same volume.
    $tempPath = '{0}.{1}.tmp' -f $Path, ([guid]::NewGuid().ToString('N'))
    try {
        Set-Content -LiteralPath $tempPath -Value $Content -Encoding UTF8 -NoNewline -WhatIf:$false -ErrorAction Stop
        if (Test-Path -LiteralPath $Path) {
            # Single atomic swap on NTFS; Move-Item -Force on 5.1 is delete-then-move.
            [System.IO.File]::Replace($tempPath, $Path, [NullString]::Value)
        }
        else {
            Move-Item -LiteralPath $tempPath -Destination $Path -WhatIf:$false -ErrorAction Stop
        }
    }
    catch {
        Remove-Item -LiteralPath $tempPath -Force -WhatIf:$false -ErrorAction SilentlyContinue
        throw
    }
}
