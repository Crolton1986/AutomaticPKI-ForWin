function Assert-APKISafeName {
    <#
    .SYNOPSIS
        Throws unless Name is safe to use as a file name under the data root (order Id, secret name).
    .DESCRIPTION
        Allowed: letters, digits, '.', '_', '-'; must start and end with a letter, digit, '_' or '-';
        at most 128 characters; no '..'; not a reserved Windows device name.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Name,

        [string]$Kind = 'name'
    )

    $valid = $true
    if ([string]::IsNullOrEmpty($Name)) {
        $valid = $false
    }
    elseif ($Name -notmatch '^[A-Za-z0-9_-](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9_-])?$') {
        $valid = $false
    }
    elseif ($Name.Contains('..')) {
        $valid = $false
    }
    elseif ($Name -match '^(?i:CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\.|$)') {
        $valid = $false
    }

    if (-not $valid) {
        throw ("Invalid {0} '{1}': use 1-128 characters from A-Z, a-z, 0-9, '.', '_' and '-' (no '..', no leading or trailing '.')." -f $Kind, $Name)
    }
}
