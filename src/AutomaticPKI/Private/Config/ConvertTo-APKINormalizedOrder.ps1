function ConvertTo-APKINormalizedOrder {
    <#
    .SYNOPSIS
        Normalizes an order object read from JSON so it matches docs/contracts.md types.
    .DESCRIPTION
        - Hostnames, Bindings and each Binding's SharedWith become arrays (a one-element JSON
          array or a bare string must not collapse to a scalar).
        - LastRenewal stays an ISO 8601 string (pwsh 7 ConvertFrom-Json turns dates into DateTime).
        Modifies the object in place and returns it.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$Order
    )

    $toArray = {
        param($Property)
        if ($null -ne $Property) {
            if ($null -eq $Property.Value) {
                $Property.Value = @()
            }
            else {
                $Property.Value = @($Property.Value)
            }
        }
    }

    & $toArray ($Order.PSObject.Properties['Hostnames'])
    & $toArray ($Order.PSObject.Properties['Bindings'])

    $bindingsProperty = $Order.PSObject.Properties['Bindings']
    if ($null -ne $bindingsProperty) {
        foreach ($binding in @($bindingsProperty.Value)) {
            if ($binding -is [System.Management.Automation.PSCustomObject]) {
                & $toArray ($binding.PSObject.Properties['SharedWith'])
            }
        }
    }

    $lastRenewal = $Order.PSObject.Properties['LastRenewal']
    if ($null -ne $lastRenewal -and $lastRenewal.Value -is [datetime]) {
        $lastRenewal.Value = $lastRenewal.Value.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
    }

    $Order
}
