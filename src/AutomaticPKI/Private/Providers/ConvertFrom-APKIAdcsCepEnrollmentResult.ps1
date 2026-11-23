function ConvertFrom-APKIAdcsCepEnrollmentResult {
    <#
    .SYNOPSIS
        Maps a Get-Certificate EnrollmentResult to a ProviderResult and logs the outcome.
    .DESCRIPTION
        EnrollmentResult.Status 'Issued'  -> Issued,  Thumbprint = Certificate.Thumbprint
        EnrollmentResult.Status 'Pending' -> Pending, RequestId  = Request.Thumbprint
            (the request object Get-Certificate stored in Cert:\LocalMachine\Request; this is
            what Receive-APKIAdcsCepCertificate / Get-Certificate -Request needs, not the CA's
            numeric request ID, which Get-Certificate does not expose)
        EnrollmentResult.Status 'Denied'  -> Denied
        anything else                     -> Failed
        Status is compared as a string, so a deserialized result (PowerShell 7 Windows
        compatibility session) maps the same way.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$EnrollmentResult,

        # Output of Get-APKIAdcsCepSetting.
        [Parameter(Mandatory)]
        [psobject]$Setting,

        # Set when retrieving an earlier pending request: the request ID that was used.
        [string]$RequestId,

        # Retrieval of an earlier pending request (a repeated Pending is not re-logged as 1002).
        [switch]$Retrieval
    )

    $orderId = $Setting.OrderId
    $status = ''
    $certificate = $null
    $request = $null
    if ($null -ne $EnrollmentResult) {
        if ($EnrollmentResult.PSObject.Properties['Status']) { $status = [string]$EnrollmentResult.Status }
        if ($EnrollmentResult.PSObject.Properties['Certificate']) { $certificate = $EnrollmentResult.Certificate }
        if ($EnrollmentResult.PSObject.Properties['Request']) { $request = $EnrollmentResult.Request }
    }

    switch ($status) {
        'Issued' {
            $thumbprint = $null
            if ($null -ne $certificate -and $certificate.PSObject.Properties['Thumbprint']) {
                $thumbprint = [string]$certificate.Thumbprint
            }
            if ([string]::IsNullOrWhiteSpace($thumbprint)) {
                $message = "AdcsCep: Get-Certificate reported Issued but returned no certificate (CepUrl $($Setting.CepUrl), template '$($Setting.Template)')."
                Write-APKILog -Message $message -Level Error -EventId 3000 -OrderId $orderId
                return New-APKIAdcsCepResult -Status Failed -RequestId $RequestId -Message $message
            }

            $message = "AdcsCep: certificate $thumbprint issued via $($Setting.CepUrl) (template '$($Setting.Template)') into Cert:\LocalMachine\My."
            Write-APKILog -Message $message -Level Info -OrderId $orderId

            if ($null -ne $Setting.Key -and $Setting.Key.Algorithm) {
                $actual = $null
                try {
                    $actual = Get-APKIAdcsCepKeyInfo -Certificate $certificate
                }
                catch {
                    $actual = $null
                }
                if ($null -ne $actual) {
                    $wanted = [string]$Setting.Key.Algorithm
                    $mismatch = $actual.Algorithm -ne $wanted
                    if (-not $mismatch -and $wanted -eq 'RSA' -and $Setting.Key.Length -gt 0) {
                        $mismatch = [int]$actual.Length -ne [int]$Setting.Key.Length
                    }
                    if ($mismatch) {
                        $wantedText = $wanted
                        if ($wanted -eq 'RSA') { $wantedText = "RSA $($Setting.Key.Length)" }
                        $actualText = $actual.Algorithm
                        if ($actual.Algorithm -eq 'RSA') { $actualText = "RSA $($actual.Length)" }
                        $warning = "AdcsCep: issued key is $actualText but Order.Key asks for $wantedText. Get-Certificate uses the key settings of template '$($Setting.Template)'; change the template to match."
                        Write-APKILog -Message $warning -Level Warning -OrderId $orderId
                    }
                }
            }

            return New-APKIAdcsCepResult -Status Issued -Thumbprint $thumbprint -RequestId $RequestId -Message $message
        }
        'Pending' {
            $pendingId = $null
            if ($null -ne $request -and $request.PSObject.Properties['Thumbprint']) {
                $pendingId = [string]$request.Thumbprint
            }
            if ([string]::IsNullOrWhiteSpace($pendingId)) { $pendingId = $RequestId }
            if ([string]::IsNullOrWhiteSpace($pendingId)) {
                $message = "AdcsCep: request is pending at $($Setting.CepUrl) but Get-Certificate returned no request object; it cannot be retrieved automatically."
                Write-APKILog -Message $message -Level Error -EventId 3000 -OrderId $orderId
                return New-APKIAdcsCepResult -Status Failed -Message $message
            }
            $pendingId = $pendingId.ToUpperInvariant()

            if ($Retrieval) {
                $message = "AdcsCep: request $pendingId is still pending CA approval (template '$($Setting.Template)')."
                Write-APKILog -Message $message -Level Info -OrderId $orderId
            }
            else {
                $message = "AdcsCep: request pending CA approval (template '$($Setting.Template)' via $($Setting.CepUrl)); request stored as Cert:\LocalMachine\Request\$pendingId."
                Write-APKILog -Message $message -Level Info -EventId 1002 -OrderId $orderId
            }
            return New-APKIAdcsCepResult -Status Pending -RequestId $pendingId -Message $message
        }
        'Denied' {
            $message = "AdcsCep: the CA denied the request for template '$($Setting.Template)' via $($Setting.CepUrl)."
            Write-APKILog -Message $message -Level Error -EventId 3001 -OrderId $orderId
            return New-APKIAdcsCepResult -Status Denied -RequestId $RequestId -Message $message
        }
        default {
            $shown = $status
            if ([string]::IsNullOrWhiteSpace($shown)) { $shown = '<none>' }
            $message = "AdcsCep: Get-Certificate returned unexpected status '$shown' (CepUrl $($Setting.CepUrl), template '$($Setting.Template)')."
            Write-APKILog -Message $message -Level Error -EventId 3000 -OrderId $orderId
            return New-APKIAdcsCepResult -Status Failed -RequestId $RequestId -Message $message
        }
    }
}
