function Read-APKIOrderFile {
    <#
    .SYNOPSIS
        Reads, normalizes and validates one orders\<Id>.json file. Throws on any problem.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 -ErrorAction Stop
    if ($null -eq $raw -or $raw.Trim().Length -eq 0) {
        throw 'the file is empty.'
    }
    $order = $null
    try {
        $order = ConvertFrom-Json -InputObject $raw -ErrorAction Stop
    }
    catch {
        throw ('it is not valid JSON ({0})' -f $_.Exception.Message)
    }
    if ($order -isnot [System.Management.Automation.PSCustomObject]) {
        throw 'the top-level value must be a JSON object.'
    }

    $order = ConvertTo-APKINormalizedOrder -Order $order
    Assert-APKIOrderData -Order $order

    $expectedId = [System.IO.Path]::GetFileNameWithoutExtension($Path)
    if ($order.Id -cne $expectedId) {
        throw ("its Id '{0}' does not match the file name '{1}'." -f $order.Id, $expectedId)
    }

    $order
}
