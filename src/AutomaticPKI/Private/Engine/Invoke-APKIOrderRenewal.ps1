function Invoke-APKIOrderRenewal {
    <#
    .SYNOPSIS
        Runs one order through request/receive, swap with rollback, and saves the new state.
    .DESCRIPTION
        Status flow:
          Proposed, Disabled   skipped, nothing saved.
          Pending (with PendingRequestId)  Invoke-APKIProviderReceive.
          Active               Test-APKIRenewalDue first (skipped with -Force); not due -> NotDue.
          Approved, Failed     Invoke-APKIProviderRequest (Failed retries on every run).
        Provider result:
          Issued   Invoke-APKISwapWithRollback (RevocationPolicy from config). Success: Previous =
                   old Current, Current = new, LastRenewal (ISO 8601 UTC), Status Active,
                   LastError $null. Failure: Status Failed, LastError, CurrentThumbprint kept; the
                   unused new certificate is deleted when the swap left it unbound.
          Pending  Status Pending, PendingRequestId, notification (the provider logs 1002).
          Denied   Status Failed, notification.
          Failed   Status Failed, notification. A failed retrieval of a pending request keeps
                   Status Pending so the next run retries the same request.
        Unless the renewal succeeded, a certificate expiring within 7 days logs 2000 and notifies.
        The order is saved with Save-APKIOrderData; the caller's object is not modified.
        Nothing is requested, bound or saved under -WhatIf (honoured through $WhatIfPreference).
    .OUTPUTS
        PSCustomObject: OrderId, Outcome (Renewed|Pending|Failed|NotDue|Skipped), Status,
        Thumbprint, Message, Order (the updated copy).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$Order,

        # Renew even when the current certificate is not due.
        [switch]$Force,

        # Global configuration (Get-APKIConfig when omitted).
        [object]$Config
    )

    if ($null -eq $Config) {
        $Config = Get-APKIConfig
    }

    # Work on a deep copy so the caller's object is never left half-updated.
    $work = ConvertTo-APKINormalizedOrder -Order (ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $Order -Depth 10))
    $orderId = [string](Get-APKIOptionalProperty -InputObject $work -Name 'Id' -Default '')
    $status = [string](Get-APKIOptionalProperty -InputObject $work -Name 'Status' -Default '')
    $current = ConvertTo-APKINormalizedThumbprint -Thumbprint ([string](Get-APKIOptionalProperty -InputObject $work -Name 'CurrentThumbprint' -Default ''))
    $pendingId = [string](Get-APKIOptionalProperty -InputObject $work -Name 'PendingRequestId' -Default '')

    $newResult = {
        param([string]$Outcome, [string]$Message, [string]$Thumbprint)
        [pscustomobject]@{
            OrderId    = $orderId
            Outcome    = $Outcome
            Status     = [string](Get-APKIOptionalProperty -InputObject $work -Name 'Status' -Default '')
            Thumbprint = $Thumbprint
            Message    = $Message
            Order      = $work
        }
    }
    $set = {
        param([string]$Name, $Value)
        Set-APKIObjectProperty -InputObject $work -Name $Name -Value $Value
    }
    $notify = {
        param([string]$Subject, [string]$Body, [string]$Level, [int]$EventId)
        try {
            Send-APKINotification -Subject $Subject -Body $Body -Level $Level -EventId $EventId -OrderId $orderId
        }
        catch {
            Write-APKILog -Message ('Notification failed: {0}' -f $_.Exception.Message) -Level Warning -OrderId $orderId
        }
    }

    if (@('Approved', 'Active', 'Failed', 'Pending') -cnotcontains $status) {
        return (& $newResult 'Skipped' "Order status is '$status'; not renewed." $current)
    }

    # 1. Ask the provider.
    $due = $null
    $receiving = ($status -ceq 'Pending' -and [bool]$pendingId)
    $providerOutput = @()
    if ($receiving) {
        $providerOutput = @(Invoke-APKIProviderReceive -Order $work -RequestId $pendingId)
    }
    else {
        if ($status -ceq 'Active' -and -not $Force) {
            $due = Test-APKIRenewalDue -Order $work -Config $Config
            if (-not $due.Due) {
                return (& $newResult 'NotDue' $due.Reason $current)
            }
            Write-APKILog -Message "Renewal due: $($due.Reason)" -OrderId $orderId
        }
        $providerOutput = @(Invoke-APKIProviderRequest -Order $work)
    }

    if ($providerOutput.Count -eq 0) {
        return (& $newResult 'Skipped' 'No certificate was requested (WhatIf).' $current)
    }
    $providerResult = $providerOutput[$providerOutput.Count - 1]
    $providerStatus = [string](Get-APKIOptionalProperty -InputObject $providerResult -Name 'Status' -Default '')
    $providerMessage = [string](Get-APKIOptionalProperty -InputObject $providerResult -Name 'Message' -Default '')

    # 2. Apply the result.
    $outcome = 'Failed'
    $message = ''
    $activeThumbprint = $current
    switch ($providerStatus) {
        'Issued' {
            $newThumb = ConvertTo-APKINormalizedThumbprint -Thumbprint ([string](Get-APKIOptionalProperty -InputObject $providerResult -Name 'Thumbprint' -Default ''))
            & $set 'PendingRequestId' $null
            if (-not $newThumb) {
                $message = 'The provider reported the certificate as issued but returned no thumbprint.'
                & $set 'Status' 'Failed'
                & $set 'LastError' $message
                Write-APKILog -Message $message -Level Error -EventId 3000 -OrderId $orderId
                & $notify "AutomaticPKI: certificate request failed for $orderId" $message 'Error' 3000
                break
            }

            $swap = Invoke-APKISwapWithRollback -Order $work -NewThumbprint $newThumb -RevocationPolicy ([string]$Config.RevocationPolicy)
            if ($swap.Success) {
                if ($current -and $current -ne $newThumb) {
                    & $set 'PreviousThumbprint' $current
                }
                & $set 'CurrentThumbprint' $newThumb
                & $set 'LastRenewal' ([datetime]::UtcNow.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture))
                & $set 'Status' 'Active'
                & $set 'LastError' $null
                $outcome = 'Renewed'
                $activeThumbprint = $newThumb
                $message = "Certificate $newThumb issued and bound."
            }
            else {
                # Invoke-APKISwapWithRollback has logged (3002/3003/3005) and notified.
                $message = [string]$swap.Error
                if (-not $message) {
                    $message = "Binding certificate $newThumb did not complete ($($swap.Outcome))."
                }
                & $set 'Status' 'Failed'
                & $set 'LastError' $message

                # A certificate the swap left unbound would pile up on every retry: delete it.
                if (@('PrecheckFailed', 'SnapshotFailed', 'RolledBack') -contains [string]$swap.Outcome -and $newThumb -ne $current) {
                    try {
                        $bound = @(Get-APKIBoundThumbprint)
                        if ($bound -notcontains $newThumb) {
                            Remove-APKIMachineCertificate -Thumbprint $newThumb -Confirm:$false
                            Write-APKILog -Message "Deleted unused certificate $newThumb after the failed swap." -OrderId $orderId
                        }
                    }
                    catch {
                        Write-APKILog -Message ('Could not delete unused certificate {0}: {1}' -f $newThumb, $_.Exception.Message) -Level Warning -OrderId $orderId
                    }
                }
            }
        }
        'Pending' {
            $requestId = [string](Get-APKIOptionalProperty -InputObject $providerResult -Name 'RequestId' -Default '')
            if (-not $requestId) {
                $requestId = $pendingId
            }
            & $set 'Status' 'Pending'
            & $set 'PendingRequestId' $requestId
            & $set 'LastError' $null
            $outcome = 'Pending'
            $message = $providerMessage
            if (-not $message) {
                $message = "Certificate request $requestId is pending CA approval."
            }
            if (-not $receiving) {
                & $notify "AutomaticPKI: certificate request pending approval for $orderId" ("{0} Request ID: {1}" -f $message, $requestId) 'Info' 1002
            }
        }
        'Denied' {
            $message = $providerMessage
            if (-not $message) {
                $message = 'The CA denied the certificate request.'
            }
            & $set 'Status' 'Failed'
            & $set 'PendingRequestId' $null
            & $set 'LastError' $message
            & $notify "AutomaticPKI: certificate request denied for $orderId" $message 'Error' 3001
        }
        default {
            $message = $providerMessage
            if (-not $message) {
                $message = "Certificate request failed (provider status '$providerStatus')."
            }
            if ($receiving) {
                # Transient retrieval error: keep the pending request for the next run.
                & $set 'Status' 'Pending'
            }
            else {
                & $set 'Status' 'Failed'
                & $set 'PendingRequestId' $null
            }
            & $set 'LastError' $message
            & $notify "AutomaticPKI: certificate request failed for $orderId" $message 'Error' 3000
        }
    }

    Save-APKIOrderData -Order $work

    # 3. Expiry warning when renewal is not succeeding.
    if ($outcome -ne 'Renewed' -and $current) {
        try {
            if ($null -eq $due) {
                $due = Test-APKIRenewalDue -Order $work -Config $Config
            }
            if ($null -ne $due.NotAfter) {
                $left = ([datetime]$due.NotAfter - (Get-Date)).TotalDays
                if ($left -le 7) {
                    $expires = ([datetime]$due.NotAfter).ToString('yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture)
                    $warning = "Certificate $current expires $expires and renewal is not succeeding: $message"
                    Write-APKILog -Message $warning -Level Warning -EventId 2000 -OrderId $orderId
                    & $notify "AutomaticPKI: certificate for $orderId expires $expires" $warning 'Warning' 2000
                }
            }
        }
        catch {
            Write-APKILog -Message ('Could not check expiry of {0}: {1}' -f $current, $_.Exception.Message) -Level Warning -OrderId $orderId
        }
    }

    & $newResult $outcome $message $activeThumbprint
}
