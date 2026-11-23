function Assert-APKIOrderData {
    <#
    .SYNOPSIS
        Throws with a list of problems unless Order has the required fields from docs/contracts.md.
    .DESCRIPTION
        Required: Id (safe file name), Status (enum), SiteName, Hostnames, Provider (enum).
        Hostnames may be empty only while Status is 'Proposed' or 'Disabled' (discovery can
        propose an order for a binding that still needs a name). Optional fields are checked
        only when present and not null: KeyMode, Bindings, Key.Algorithm.
        Enum values are case-sensitive so files stay canonical.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Order
    )

    if ($Order -isnot [System.Management.Automation.PSCustomObject]) {
        throw 'Order must be an object.'
    }

    $problems = New-Object System.Collections.Generic.List[string]
    $get = {
        param($Name)
        $property = $Order.PSObject.Properties[$Name]
        if ($null -eq $property) {
            return $null
        }
        $property.Value
    }

    $id = & $get 'Id'
    if ($id -isnot [string] -or $id -eq '') {
        $problems.Add('Id is required.')
    }
    else {
        try {
            Assert-APKISafeName -Name $id -Kind 'order Id'
        }
        catch {
            $problems.Add($_.Exception.Message)
        }
    }

    $statuses = @('Proposed', 'Approved', 'Pending', 'Active', 'Failed', 'Disabled')
    $status = & $get 'Status'
    if ($statuses -cnotcontains $status) {
        $problems.Add(("Status '{0}' is invalid; expected one of: {1}." -f $status, ($statuses -join ', ')))
    }

    $siteName = & $get 'SiteName'
    if ($siteName -isnot [string] -or $siteName.Trim() -eq '') {
        $problems.Add('SiteName is required.')
    }

    if ($null -eq $Order.PSObject.Properties['Hostnames']) {
        $problems.Add('Hostnames is required.')
    }
    else {
        $hostnames = @(& $get 'Hostnames' | Where-Object { $null -ne $_ })
        foreach ($hostname in $hostnames) {
            if ($hostname -isnot [string] -or $hostname.Trim() -eq '') {
                $problems.Add('Hostnames must contain only non-empty strings.')
                break
            }
        }
        if ($hostnames.Count -eq 0 -and @('Proposed', 'Disabled') -cnotcontains $status) {
            $problems.Add("Hostnames must contain at least one name unless Status is 'Proposed' or 'Disabled'.")
        }
    }

    $providers = @('AdcsRpc', 'AdcsCep')
    $provider = & $get 'Provider'
    if ($providers -cnotcontains $provider) {
        $problems.Add(("Provider '{0}' is invalid; expected one of: {1}." -f $provider, ($providers -join ', ')))
    }

    $keyMode = & $get 'KeyMode'
    if ($null -ne $keyMode -and @('OnHost', 'Central') -cnotcontains $keyMode) {
        $problems.Add("KeyMode '$keyMode' is invalid; expected 'OnHost' or 'Central'.")
    }

    $key = & $get 'Key'
    if ($null -ne $key) {
        if ($key -isnot [System.Management.Automation.PSCustomObject]) {
            $problems.Add('Key must be an object.')
        }
        else {
            $algorithmProperty = $key.PSObject.Properties['Algorithm']
            if ($null -ne $algorithmProperty -and $null -ne $algorithmProperty.Value -and
                @('RSA', 'ECDSA_P256') -cnotcontains $algorithmProperty.Value) {
                $problems.Add(("Key.Algorithm '{0}' is invalid; expected 'RSA' or 'ECDSA_P256'." -f $algorithmProperty.Value))
            }
        }
    }

    foreach ($binding in @(& $get 'Bindings' | Where-Object { $null -ne $_ })) {
        if ($binding -isnot [System.Management.Automation.PSCustomObject]) {
            $problems.Add('Bindings must contain only objects.')
            break
        }
    }

    if ($problems.Count -gt 0) {
        throw ($problems -join ' ')
    }
}
