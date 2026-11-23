function Invoke-APKISwapWithRollback {
    <#
    .SYNOPSIS
        Binds a new certificate to an order's IIS bindings, verifies it, and rolls back on failure.
    .DESCRIPTION
        1. Precheck the new certificate (Test-APKICertificatePrecheck). Failure: nothing is
           changed, event 3005 logged, notification sent.
        2. Save-APKIBindingSnapshot.  Failure: nothing is changed, event 3005, notification.
        3. Set-APKIIisCertificateBinding, then Invoke-APKIHealthCheck against the new thumbprint.
           Success: event 1001.
        4. On any failure in 3: Restore-APKIBindingSnapshot and re-run the health check against
           the previous thumbprint (Order.CurrentThumbprint). Event 3002 if the restore and the
           re-check pass, else 3003. A notification is sent in both cases.
        The order object is not modified; the caller records CurrentThumbprint/PreviousThumbprint.
    .OUTPUTS
        PSCustomObject: Success, Outcome ('Swapped', 'PrecheckFailed', 'SnapshotFailed',
        'RolledBack', 'RollbackFailed', 'Skipped'), ActiveThumbprint (expected to be served now),
        Precheck, HealthCheck, RollbackHealthCheck, Error.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$Order,

        [Parameter(Mandatory)]
        [string]$NewThumbprint,

        [ValidateSet('Strict', 'Lenient', 'Skip')]
        [string]$RevocationPolicy = 'Strict',

        [ValidateRange(1, 600)]
        [int]$TimeoutSec = 10
    )

    $orderId = [string](Get-APKIOptionalProperty -InputObject $Order -Name 'Id' -Default '')
    $siteName = [string](Get-APKIOptionalProperty -InputObject $Order -Name 'SiteName' -Default '')
    $hostnames = @(@(Get-APKIOptionalProperty -InputObject $Order -Name 'Hostnames' -Default @()) | Where-Object { $_ } | ForEach-Object { [string]$_ })
    $oldThumbprint = ConvertTo-APKINormalizedThumbprint -Thumbprint ([string](Get-APKIOptionalProperty -InputObject $Order -Name 'CurrentThumbprint' -Default ''))
    $newThumb = ConvertTo-APKINormalizedThumbprint -Thumbprint $NewThumbprint

    $result = [pscustomobject]@{
        Success             = $false
        Outcome             = 'Skipped'
        ActiveThumbprint    = $oldThumbprint
        Precheck            = @()
        HealthCheck         = $null
        RollbackHealthCheck = $null
        Error               = ''
    }

    $formatFailures = {
        param($items)
        (@($items | Where-Object { -not $_.Passed } | ForEach-Object { '{0} {1}: {2}' -f $_.Check, $_.Target, $_.Detail }) -join '; ')
    }

    $notify = {
        param([string]$Subject, [string]$Body)
        try {
            Send-APKINotification -Subject $Subject -Body $Body -Level 'Error' -OrderId $orderId
        }
        catch {
            Write-APKILog -Message ('Notification failed: {0}' -f $_.Exception.Message) -Level Warning -OrderId $orderId
        }
    }

    if (-not $PSCmdlet.ShouldProcess("IIS site '$siteName' (order '$orderId')", "Bind certificate $newThumb with health check and rollback")) {
        return $result
    }

    # 1. Precheck
    $certificate = $null
    try {
        $certificate = Get-APKIHealthCertificate -Thumbprint $newThumb
    }
    catch {
        $certificate = $null
    }
    if ($null -eq $certificate) {
        $result.Precheck = @(New-APKIHealthResult -Check 'CertificatePresent' -Target $newThumb -Passed $false -Detail 'Certificate not found in Cert:\LocalMachine\My.')
    }
    else {
        $result.Precheck = @(Test-APKICertificatePrecheck -Certificate $certificate -Hostnames $hostnames -RevocationPolicy $RevocationPolicy)
    }
    $precheckFailures = & $formatFailures $result.Precheck
    if ($precheckFailures) {
        $result.Outcome = 'PrecheckFailed'
        $result.Error = "Precheck failed for $newThumb; bindings unchanged. $precheckFailures"
        Write-APKILog -Message $result.Error -Level Error -EventId 3005 -OrderId $orderId
        & $notify "AutomaticPKI: certificate precheck failed for $orderId" $result.Error
        return $result
    }

    # 2. Snapshot
    $snapshot = $null
    try {
        $snapshot = Save-APKIBindingSnapshot -Order $Order
    }
    catch {
        $result.Outcome = 'SnapshotFailed'
        $result.Error = 'Could not snapshot bindings; swap not attempted: {0}' -f $_.Exception.Message
        Write-APKILog -Message $result.Error -Level Error -EventId 3005 -OrderId $orderId
        & $notify "AutomaticPKI: binding snapshot failed for $orderId" $result.Error
        return $result
    }

    # 3. Bind and verify
    $failure = ''
    try {
        Set-APKIIisCertificateBinding -Order $Order -Thumbprint $newThumb -Confirm:$false
        $result.HealthCheck = Invoke-APKIHealthCheck -Order $Order -Thumbprint $newThumb -TimeoutSec $TimeoutSec
        if (-not $result.HealthCheck.Passed) {
            $failure = 'Health check failed: {0}' -f (& $formatFailures $result.HealthCheck.Results)
        }
    }
    catch {
        $failure = 'Binding update failed: {0}' -f $_.Exception.Message
    }

    if (-not $failure) {
        $result.Success = $true
        $result.Outcome = 'Swapped'
        $result.ActiveThumbprint = $newThumb
        Write-APKILog -Message "Certificate $newThumb bound to site '$siteName' and health check passed." -Level Info -EventId 1001 -OrderId $orderId
        return $result
    }

    # 4. Roll back
    $result.ActiveThumbprint = $oldThumbprint
    $rollbackError = ''
    try {
        Restore-APKIBindingSnapshot -Order $Order -Snapshot $snapshot
    }
    catch {
        $rollbackError = 'Restore of binding snapshot failed: {0}' -f $_.Exception.Message
    }

    if (-not $rollbackError) {
        if ($oldThumbprint) {
            try {
                $result.RollbackHealthCheck = Invoke-APKIHealthCheck -Order $Order -Thumbprint $oldThumbprint -TimeoutSec $TimeoutSec
                if (-not $result.RollbackHealthCheck.Passed) {
                    $rollbackError = 'Health check after rollback failed: {0}' -f (& $formatFailures $result.RollbackHealthCheck.Results)
                }
            }
            catch {
                $rollbackError = 'Health check after rollback threw: {0}' -f $_.Exception.Message
            }
        }
    }

    if ($rollbackError) {
        $result.Outcome = 'RollbackFailed'
        $result.Error = "Swap to $newThumb failed ($failure) and rollback failed ($rollbackError). Site '$siteName' may be down."
        Write-APKILog -Message $result.Error -Level Error -EventId 3003 -OrderId $orderId
        & $notify "AutomaticPKI: ROLLBACK FAILED for $orderId, site may be down" $result.Error
    }
    else {
        $result.Outcome = 'RolledBack'
        $verified = 'previous certificate verified'
        if (-not $oldThumbprint) {
            $verified = 'no previous certificate to verify'
        }
        $result.Error = "Swap to $newThumb failed ($failure); bindings restored, $verified."
        Write-APKILog -Message $result.Error -Level Error -EventId 3002 -OrderId $orderId
        & $notify "AutomaticPKI: health check failed for $orderId, rolled back" $result.Error
    }

    $result
}
