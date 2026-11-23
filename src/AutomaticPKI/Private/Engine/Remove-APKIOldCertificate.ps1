function Remove-APKIOldCertificate {
    <#
    .SYNOPSIS
        Deletes superseded certificates (Order.PreviousThumbprint) once the retention period is over.
    .DESCRIPTION
        For each order with a PreviousThumbprint:
          - kept while LastRenewal is less than OldCertRetentionDays ago (or unreadable);
          - kept while any IIS https binding uses it, or it is any order's CurrentThumbprint;
          - otherwise deleted with its private key from Cert:\LocalMachine\My (EventId 1004),
            and PreviousThumbprint is cleared and the order saved. A certificate already gone
            from the store only clears PreviousThumbprint.
        When IIS bindings cannot be read nothing is deleted.
    .OUTPUTS
        PSCustomObject per handled order: OrderId, Thumbprint, Removed (bool).
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    [OutputType([pscustomobject])]
    param(
        # Orders to inspect (default: every order on disk).
        [object[]]$Order,

        # Default: config OldCertRetentionDays.
        [ValidateRange(0, 36500)]
        [int]$RetentionDays,

        [datetime]$Now = (Get-Date)
    )

    if (-not $PSBoundParameters.ContainsKey('Order')) {
        $Order = @(Get-APKIOrderData)
    }
    $days = 14
    if ($PSBoundParameters.ContainsKey('RetentionDays')) {
        $days = $RetentionDays
    }
    else {
        try {
            $days = [int](Get-APKIConfig).OldCertRetentionDays
        }
        catch {
            Write-APKILog -Message ('Old certificate cleanup uses the default retention of 14 days: {0}' -f $_.Exception.Message) -Level Warning
        }
    }
    $nowUtc = $Now.ToUniversalTime()

    $candidates = @($Order | Where-Object {
            $null -ne $_ -and (ConvertTo-APKINormalizedThumbprint -Thumbprint ([string](Get-APKIOptionalProperty -InputObject $_ -Name 'PreviousThumbprint' -Default '')))
        })
    if ($candidates.Count -eq 0) {
        return
    }

    $inUse = New-Object System.Collections.Generic.List[string]
    foreach ($o in @($Order)) {
        $t = ConvertTo-APKINormalizedThumbprint -Thumbprint ([string](Get-APKIOptionalProperty -InputObject $o -Name 'CurrentThumbprint' -Default ''))
        if ($t) {
            $inUse.Add($t)
        }
    }
    try {
        foreach ($t in @(Get-APKIBoundThumbprint)) {
            $inUse.Add($t)
        }
    }
    catch {
        Write-APKILog -Message ('Old certificates not removed: IIS bindings could not be read: {0}' -f $_.Exception.Message) -Level Warning
        return
    }

    foreach ($o in $candidates) {
        $orderId = [string](Get-APKIOptionalProperty -InputObject $o -Name 'Id' -Default '')
        $previous = ConvertTo-APKINormalizedThumbprint -Thumbprint ([string]$o.PreviousThumbprint)

        if ($inUse.Contains($previous)) {
            Write-Verbose "Order '$orderId': previous certificate $previous is still in use; kept."
            continue
        }

        $replacedUtc = $null
        $lastRenewal = [string](Get-APKIOptionalProperty -InputObject $o -Name 'LastRenewal' -Default '')
        try {
            $replacedUtc = [System.DateTimeOffset]::Parse($lastRenewal, [System.Globalization.CultureInfo]::InvariantCulture).UtcDateTime
        }
        catch {
            Write-Verbose "Order '$orderId': LastRenewal '$lastRenewal' is not a date; previous certificate kept."
            continue
        }
        if (($nowUtc - $replacedUtc).TotalDays -lt $days) {
            continue
        }

        $certificate = Get-APKIHealthCertificate -Thumbprint $previous
        $removed = $false
        if ($null -ne $certificate) {
            if (-not $PSCmdlet.ShouldProcess("Cert:\LocalMachine\My\$previous (order '$orderId')", 'Remove old certificate')) {
                continue
            }
            try {
                Remove-APKIMachineCertificate -Thumbprint $previous -Confirm:$false
            }
            catch {
                Write-APKILog -Message ('Could not remove old certificate {0}: {1}' -f $previous, $_.Exception.Message) -Level Warning -OrderId $orderId
                continue
            }
            $removed = $true
            Write-APKILog -Message "Removed old certificate $previous (replaced $lastRenewal, retention $days days)." -EventId 1004 -OrderId $orderId
        }

        Set-APKIObjectProperty -InputObject $o -Name 'PreviousThumbprint' -Value $null
        try {
            Save-APKIOrderData -Order $o
        }
        catch {
            Write-APKILog -Message ('Could not save order after old certificate cleanup: {0}' -f $_.Exception.Message) -Level Warning -OrderId $orderId
        }

        [pscustomobject]@{
            OrderId    = $orderId
            Thumbprint = $previous
            Removed    = $removed
        }
    }
}
