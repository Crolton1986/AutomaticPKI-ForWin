function Receive-APKIAdcsRpcCertificate {
    <#
    .SYNOPSIS
        AdcsRpc provider: collects a previously pending request from the CA.
    .DESCRIPTION
        certreq -retrieve -config <CAConfig> <RequestId> <file>, then certreq -accept -machine,
        which pairs the certificate with the key left in the machine request store by
        Request-APKIAdcsRpcCertificate. Still pending -> Status Pending; denied -> Status Denied.
    .OUTPUTS
        ProviderResult (docs/contracts.md). Nothing under -WhatIf.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$Order,

        [Parameter(Mandatory)]
        [string]$RequestId
    )

    $orderId = $null
    if ($Order.PSObject.Properties['Id']) { $orderId = [string]$Order.Id }

    $settings = $null
    try {
        $settings = Get-APKIAdcsRpcSetting -Order $Order
        if ($RequestId -notmatch '^\d+$') {
            throw "RequestId '$RequestId' is not a numeric CA request ID."
        }
    }
    catch {
        $msg = "Cannot retrieve request for the AdcsRpc provider: $($_.Exception.Message)"
        Write-APKILog -Message $msg -Level Error -EventId 3004 -OrderId $orderId
        return New-APKIAdcsRpcResult -Status Failed -RequestId $RequestId -Message $msg
    }

    if (-not $PSCmdlet.ShouldProcess($settings.CAConfig, "Retrieve and install certificate for request $RequestId")) {
        return
    }

    $workDir = $null
    try {
        $workDir = Join-Path (Join-Path (Get-APKIRoot) 'tmp') ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $workDir -Force -WhatIf:$false | Out-Null
        $cerPath = Join-Path $workDir 'issued.cer'

        $retrieve = Invoke-APKICertreq -Arguments @('-retrieve', '-q', '-config', $settings.CAConfig, $RequestId, $cerPath)
        $response = ConvertFrom-APKICertreqOutput -Output $retrieve.Output -ExitCode $retrieve.ExitCode
        Resolve-APKIAdcsRpcResponse -Order $Order -Response $response -CertificatePath $cerPath -RequestId $RequestId -Retrieval
    }
    catch {
        $msg = "Retrieving request $RequestId failed: $($_.Exception.Message)"
        Write-APKILog -Message $msg -Level Error -EventId 3000 -OrderId $orderId
        New-APKIAdcsRpcResult -Status Failed -RequestId $RequestId -Message $msg
    }
    finally {
        if ($workDir -and (Test-Path -LiteralPath $workDir)) {
            Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue -WhatIf:$false
        }
    }
}
