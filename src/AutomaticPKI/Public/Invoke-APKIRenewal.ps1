function Invoke-APKIRenewal {
    <#
    .SYNOPSIS
        Renewal run: processes every eligible order, then removes old certificates and logs.
    .DESCRIPTION
        This is what the scheduled task runs. For each order (or the one named by -Id):
          Approved and Failed orders are requested, Pending orders collect their request,
          Active orders are renewed when due (Test-APKIRenewalDue), Proposed and Disabled
          orders are skipped.
        Each order runs in its own try/catch: one failure never stops the others. An
        unexpected error marks the order Failed (Pending orders stay Pending) and is logged
        (EventId 3000).
        Afterwards superseded certificates past OldCertRetentionDays and unused by IIS are
        deleted, old log files are removed, and EventId 1000 summarises the run.
    .PARAMETER Id
        Process only this order.
    .PARAMETER Force
        Renew Active orders even when their certificate is not due.
    .EXAMPLE
        Invoke-APKIRenewal

        Runs the renewal pass for all orders (what the scheduled task does).
    .EXAMPLE
        Invoke-APKIRenewal -WhatIf -Verbose

        Shows which orders would be processed without requesting or binding anything.
    .OUTPUTS
        PSCustomObject: Renewed, Pending, Failed, Skipped (counts; Skipped includes orders not
        due), Results (per-order results).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Position = 0)]
        [string]$Id,

        [switch]$Force
    )

    $config = Get-APKIConfig

    $orders = @()
    if ($Id) {
        $orders = @(Get-APKIOrderData -Id $Id)
        if ($orders.Count -eq 0) {
            throw "Order '$Id' does not exist."
        }
    }
    else {
        $orders = @(Get-APKIOrderData)
    }

    $renewed = 0
    $pending = 0
    $failed = 0
    $skipped = 0
    $results = New-Object System.Collections.Generic.List[object]

    foreach ($order in $orders) {
        $orderId = [string](Get-APKIOptionalProperty -InputObject $order -Name 'Id' -Default '')
        try {
            if (-not $PSCmdlet.ShouldProcess("order '$orderId'", 'Renew certificate if due')) {
                $skipped++
                continue
            }
            $result = @(Invoke-APKIOrderRenewal -Order $order -Force:$Force -Config $config) | Select-Object -Last 1
            switch ([string]$result.Outcome) {
                'Renewed' { $renewed++ }
                'Pending' { $pending++ }
                'Failed' { $failed++ }
                default { $skipped++ }
            }
            $results.Add($result)
        }
        catch {
            $failed++
            $message = "Renewal of order '$orderId' failed unexpectedly: $($_.Exception.Message)"
            Write-APKILog -Message $message -Level Error -EventId 3000 -OrderId $orderId
            try {
                if ([string]$order.Status -cne 'Pending') {
                    Set-APKIObjectProperty -InputObject $order -Name 'Status' -Value 'Failed'
                }
                Set-APKIObjectProperty -InputObject $order -Name 'LastError' -Value $message
                Save-APKIOrderData -Order $order
            }
            catch {
                Write-APKILog -Message ('Could not record the failure on the order: {0}' -f $_.Exception.Message) -Level Warning -OrderId $orderId
            }
            try {
                Send-APKINotification -Subject "AutomaticPKI: renewal failed for $orderId" -Body $message -Level Error -EventId 3000 -OrderId $orderId
            }
            catch {
                Write-APKILog -Message ('Notification failed: {0}' -f $_.Exception.Message) -Level Warning -OrderId $orderId
            }
            $results.Add([pscustomobject]@{
                    OrderId    = $orderId
                    Outcome    = 'Failed'
                    Status     = [string](Get-APKIOptionalProperty -InputObject $order -Name 'Status' -Default '')
                    Thumbprint = [string](Get-APKIOptionalProperty -InputObject $order -Name 'CurrentThumbprint' -Default '')
                    Message    = $message
                    Order      = $order
                })
        }
    }

    try {
        $null = Remove-APKIOldCertificate
    }
    catch {
        Write-APKILog -Message ('Old certificate cleanup failed: {0}' -f $_.Exception.Message) -Level Warning
    }
    try {
        Remove-APKIOldLog
    }
    catch {
        Write-APKILog -Message ('Log cleanup failed: {0}' -f $_.Exception.Message) -Level Warning
    }

    $summary = 'Renewal run completed: {0} renewed, {1} pending, {2} failed, {3} skipped ({4} orders).' -f $renewed, $pending, $failed, $skipped, $orders.Count
    Write-APKILog -Message $summary -Level Info -EventId 1000

    [pscustomobject]@{
        Renewed = $renewed
        Pending = $pending
        Failed  = $failed
        Skipped = $skipped
        Results = $results.ToArray()
    }
}
