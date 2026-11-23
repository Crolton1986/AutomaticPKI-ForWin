function Get-APKIOrderData {
    <#
    .SYNOPSIS
        Reads orders from <root>\orders\<Id>.json.
    .DESCRIPTION
        With -Id: returns that order, nothing if the file does not exist, and logs EventId 3004
        and throws if the file is invalid.
        Without -Id: returns every valid order sorted by Id; invalid files are logged (3004) and
        skipped so one bad file cannot stop the others.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string]$Id
    )

    $orderDir = Join-Path (Get-APKIRoot) 'orders'

    if ($PSBoundParameters.ContainsKey('Id')) {
        Assert-APKISafeName -Name $Id -Kind 'order Id'
        $path = Join-Path $orderDir "$Id.json"
        if (-not (Test-Path -LiteralPath $path)) {
            Write-Verbose "Order '$Id' not found at '$path'."
            return
        }
        try {
            return (Read-APKIOrderFile -Path $path)
        }
        catch {
            $message = "Order file '$path' is invalid: $($_.Exception.Message)"
            Write-APKILog -Message $message -Level Error -EventId 3004 -OrderId $Id
            throw $message
        }
    }

    if (-not (Test-Path -LiteralPath $orderDir)) {
        return
    }

    $files = @(Get-ChildItem -LiteralPath $orderDir -Filter '*.json' -File |
            Where-Object { $_.Extension -eq '.json' } |
            Sort-Object -Property Name)
    foreach ($file in $files) {
        try {
            Read-APKIOrderFile -Path $file.FullName
        }
        catch {
            $message = "Skipping invalid order file '$($file.FullName)': $($_.Exception.Message)"
            Write-APKILog -Message $message -Level Error -EventId 3004 -OrderId $file.BaseName
        }
    }
}
