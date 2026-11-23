function Get-APKIAdcsCepSetting {
    <#
    .SYNOPSIS
        Reads and validates the AdcsCep fields of an Order.
    .DESCRIPTION
        Accepts Order / ProviderSettings / Key as PSCustomObject (from JSON) or hashtable.
        Never throws for bad input: problems are joined into the Problem property (empty = valid).
    .OUTPUTS
        PSCustomObject: OrderId, CepUrl, Template, CredentialRef, Hostnames, Key (Algorithm, Length
        or $null), Problem.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Order
    )

    # Returns a member of a hashtable or object, $null if missing (StrictMode-safe).
    $read = {
        param($Source, [string]$Name)
        if ($null -eq $Source) { return $null }
        if ($Source -is [System.Collections.IDictionary]) {
            if ($Source.Contains($Name)) { return $Source[$Name] }
            return $null
        }
        $prop = $Source.PSObject.Properties[$Name]
        if ($null -ne $prop) { return $prop.Value }
        return $null
    }

    $problems = New-Object System.Collections.Generic.List[string]

    $orderId = [string](& $read $Order 'Id')

    $cepUrl = ''
    $template = ''
    $credentialRef = $null
    $settings = & $read $Order 'ProviderSettings'
    if ($null -eq $Order) {
        $problems.Add('Order is null')
    }
    elseif ($null -eq $settings) {
        $problems.Add('ProviderSettings is missing')
    }
    else {
        $cepUrl = [string](& $read $settings 'CepUrl')
        $template = [string](& $read $settings 'Template')
        $ref = & $read $settings 'CredentialRef'
        if ($null -ne $ref -and -not [string]::IsNullOrWhiteSpace([string]$ref)) {
            $credentialRef = [string]$ref
        }

        if ([string]::IsNullOrWhiteSpace($cepUrl)) {
            $problems.Add('ProviderSettings.CepUrl is empty')
        }
        else {
            $parsed = $null
            if (-not [System.Uri]::TryCreate($cepUrl, [System.UriKind]::Absolute, [ref]$parsed)) {
                $problems.Add("ProviderSettings.CepUrl '$cepUrl' is not an absolute URL")
            }
            elseif ($parsed.Scheme -ne 'https') {
                $problems.Add("ProviderSettings.CepUrl '$cepUrl' must use https")
            }
        }
        if ([string]::IsNullOrWhiteSpace($template)) {
            $problems.Add('ProviderSettings.Template is empty')
        }
    }

    $hostnames = @()
    $rawHostnames = & $read $Order 'Hostnames'
    if ($null -ne $rawHostnames) {
        $hostnames = @(@($rawHostnames) | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { ([string]$_).Trim() })
    }
    if ($null -ne $Order -and $hostnames.Count -eq 0) {
        $problems.Add('Hostnames is empty')
    }

    $key = $null
    $rawKey = & $read $Order 'Key'
    if ($null -ne $rawKey) {
        $length = 0
        $rawLength = & $read $rawKey 'Length'
        $asInt = $rawLength -as [int]
        if ($null -ne $asInt) { $length = $asInt }
        $key = [pscustomobject]@{
            Algorithm = [string](& $read $rawKey 'Algorithm')
            Length    = $length
        }
    }

    [pscustomobject]@{
        OrderId       = $orderId
        CepUrl        = $cepUrl
        Template      = $template
        CredentialRef = $credentialRef
        Hostnames     = [string[]]$hostnames
        Key           = $key
        Problem       = ($problems -join '; ')
    }
}
