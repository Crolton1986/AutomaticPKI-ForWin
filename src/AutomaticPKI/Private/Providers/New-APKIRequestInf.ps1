function New-APKIRequestInf {
    <#
    .SYNOPSIS
        Builds the certreq.exe policy INF text for an Order. Pure function: no IO.
    .DESCRIPTION
        Subject CN = first hostname; every hostname goes into the SAN extension (2.5.29.17) as dns=.
        Key: RSA uses the SChannel CSP (works with every IIS/SChannel version), ECDSA_P256 uses the
        Microsoft Software Key Storage Provider. Keys are machine keys (MachineKeySet = TRUE) so IIS
        (running as the machine) can use them. EKU is Server Authentication only.
        Syntax per https://learn.microsoft.com/windows-server/administration/windows-commands/certreq_1
    .OUTPUTS
        [string] INF content, CRLF line endings.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Pure function: returns text, changes no state.')]
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [object]$Order
    )

    # Hostname: optional leading wildcard label, then LDH labels. Anything else (quotes, spaces,
    # newlines) could inject INF syntax, so it is rejected rather than escaped.
    $hostPattern = '^(\*\.)?[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$'
    $safeValuePattern = '^[A-Za-z0-9 ._()-]+$'

    $hostnames = New-Object System.Collections.Generic.List[string]
    if ($Order.PSObject.Properties['Hostnames'] -and $null -ne $Order.Hostnames) {
        foreach ($h in @($Order.Hostnames)) {
            if ($null -eq $h) { continue }
            $name = ([string]$h).Trim()
            if (-not $name) { continue }
            if ($name -notmatch $hostPattern) {
                throw "New-APKIRequestInf: invalid hostname '$name'."
            }
            $already = $false
            foreach ($existing in $hostnames) {
                if ([string]::Equals($existing, $name, [System.StringComparison]::OrdinalIgnoreCase)) { $already = $true }
            }
            if (-not $already) { $hostnames.Add($name) }
        }
    }
    if ($hostnames.Count -eq 0) {
        throw 'New-APKIRequestInf: Order has no hostnames.'
    }

    # Key settings with contract defaults (RSA 2048, not exportable).
    $algorithm = 'RSA'
    $length = 2048
    $exportable = $false
    if ($Order.PSObject.Properties['Key'] -and $null -ne $Order.Key) {
        $key = $Order.Key
        if ($key.PSObject.Properties['Algorithm'] -and $key.Algorithm) { $algorithm = [string]$key.Algorithm }
        if ($key.PSObject.Properties['Length'] -and $key.Length) { $length = [int]$key.Length }
        if ($key.PSObject.Properties['Exportable'] -and $null -ne $key.Exportable) { $exportable = [bool]$key.Exportable }
    }

    $template = $null
    if ($Order.PSObject.Properties['ProviderSettings'] -and $null -ne $Order.ProviderSettings) {
        $ps = $Order.ProviderSettings
        if ($ps.PSObject.Properties['Template'] -and $ps.Template) {
            $template = ([string]$ps.Template).Trim()
            if ($template -notmatch $safeValuePattern) {
                throw "New-APKIRequestInf: invalid template name '$template'."
            }
        }
    }

    $orderId = $null
    if ($Order.PSObject.Properties['Id'] -and $Order.Id) {
        $orderId = [string]$Order.Id
        if ($orderId -notmatch $safeValuePattern) {
            throw "New-APKIRequestInf: invalid order id '$orderId'."
        }
    }

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('[Version]')
    $lines.Add('Signature="$Windows NT$"')
    $lines.Add('')
    $lines.Add('[NewRequest]')
    $lines.Add(('Subject = "CN={0}"' -f $hostnames[0]))

    switch ($algorithm) {
        'RSA' {
            if ($length -lt 2048) {
                throw "New-APKIRequestInf: RSA key length $length is below 2048."
            }
            $lines.Add('KeyAlgorithm = RSA')
            $lines.Add(('KeyLength = {0}' -f $length))
            $lines.Add('ProviderName = "Microsoft RSA SChannel Cryptographic Provider"')
            $lines.Add('ProviderType = 12')
            # AT_KEYEXCHANGE: required for SChannel RSA key exchange.
            $lines.Add('KeySpec = 1')
            # Digital signature | key encipherment.
            $lines.Add('KeyUsage = 0xa0')
        }
        'ECDSA_P256' {
            $lines.Add('KeyAlgorithm = ECDSA_P256')
            $lines.Add('KeyLength = 256')
            $lines.Add('ProviderName = "Microsoft Software Key Storage Provider"')
            # Digital signature only; ECDSA cannot encipher keys.
            $lines.Add('KeyUsage = 0x80')
        }
        default {
            throw "New-APKIRequestInf: unsupported key algorithm '$algorithm'."
        }
    }

    $lines.Add('MachineKeySet = TRUE')
    if ($exportable) { $lines.Add('Exportable = TRUE') } else { $lines.Add('Exportable = FALSE') }
    $lines.Add('RequestType = PKCS10')
    $lines.Add('HashAlgorithm = sha256')
    $lines.Add('SMIME = FALSE')
    $lines.Add('Silent = TRUE')
    $lines.Add('UseExistingKeySet = FALSE')
    if ($orderId) {
        $lines.Add(('FriendlyName = "AutomaticPKI {0}"' -f $orderId))
    }

    $lines.Add('')
    $lines.Add('[Extensions]')
    $lines.Add('2.5.29.17 = "{text}"')
    for ($i = 0; $i -lt $hostnames.Count; $i++) {
        $sep = '&'
        if ($i -eq ($hostnames.Count - 1)) { $sep = '' }
        $lines.Add(('_continue_ = "dns={0}{1}"' -f $hostnames[$i], $sep))
    }
    # Enhanced Key Usage: Server Authentication.
    $lines.Add('2.5.29.37 = "{text}1.3.6.1.5.5.7.3.1"')

    if ($template) {
        $lines.Add('')
        $lines.Add('[RequestAttributes]')
        $lines.Add(('CertificateTemplate = "{0}"' -f $template))
    }

    ($lines.ToArray() -join "`r`n") + "`r`n"
}
