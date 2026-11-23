function Save-APKIOrderData {
    <#
    .SYNOPSIS
        Validates an order and writes it atomically to <root>\orders\<Id>.json.
    .DESCRIPTION
        Accepts a PSCustomObject or hashtable. The caller's object is not modified. Throws on an
        invalid order without touching an existing file.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$Order
    )

    process {
        $normalized = $null
        try {
            # JSON round-trip: deep copy, and hashtables become PSCustomObjects.
            $json = ConvertTo-Json -InputObject $Order -Depth 10
            $normalized = ConvertFrom-Json -InputObject $json -ErrorAction Stop
            if ($normalized -isnot [System.Management.Automation.PSCustomObject]) {
                throw 'Order must be an object or hashtable.'
            }
            $normalized = ConvertTo-APKINormalizedOrder -Order $normalized
            Assert-APKIOrderData -Order $normalized
        }
        catch {
            throw "Order is invalid and was not saved: $($_.Exception.Message)"
        }

        $path = Join-Path (Join-Path (Get-APKIRoot) 'orders') "$($normalized.Id).json"
        if ($PSCmdlet.ShouldProcess($path, 'Save AutomaticPKI order')) {
            Write-APKIFileAtomic -Path $path -Content (ConvertTo-Json -InputObject $normalized -Depth 10)
            Write-Verbose "Order '$($normalized.Id)' saved to '$path'."
        }
    }
}
