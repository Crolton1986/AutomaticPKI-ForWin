function Get-APKIAdcsRpcSetting {
    <#
    .SYNOPSIS
        Reads and validates AdcsRpc ProviderSettings (CAConfig, Template) from an Order.
    .OUTPUTS
        [pscustomobject] @{ CAConfig; Template }. Template is $null for a standalone CA.
        Throws when CAConfig is missing or malformed.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$Order
    )

    $caConfig = $null
    $template = $null
    if ($Order.PSObject.Properties['ProviderSettings'] -and $null -ne $Order.ProviderSettings) {
        $ps = $Order.ProviderSettings
        if ($ps.PSObject.Properties['CAConfig'] -and $ps.CAConfig) { $caConfig = ([string]$ps.CAConfig).Trim() }
        if ($ps.PSObject.Properties['Template'] -and $ps.Template) { $template = ([string]$ps.Template).Trim() }
    }

    # CAConfig is "<CA host>\<CA common name>"; quotes or control chars would break argument passing.
    if (-not $caConfig) {
        throw 'AdcsRpc: ProviderSettings.CAConfig is not set.'
    }
    if ($caConfig -notmatch '^[^\\"\r\n]+\\[^\\"\r\n]+$') {
        throw "AdcsRpc: ProviderSettings.CAConfig '$caConfig' is not in the form 'host\CA Name'."
    }
    if ($template -and $template -notmatch '^[A-Za-z0-9 ._()-]+$') {
        throw "AdcsRpc: ProviderSettings.Template '$template' contains invalid characters."
    }

    [pscustomobject]@{
        CAConfig = $caConfig
        Template = $template
    }
}
