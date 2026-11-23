function Request-APKIAdcsRpcCertificate {
    <#
    .SYNOPSIS
        AdcsRpc provider: requests a certificate for an Order from an ADCS CA over RPC/DCOM.
    .DESCRIPTION
        1. certreq -new -machine   : generates the key in the machine request store and a PKCS#10 .req
        2. certreq -submit -config : sends it to Order.ProviderSettings.CAConfig
        3. Issued  -> certreq -accept -machine, returns the thumbprint (Cert:\LocalMachine\My)
           Pending -> returns Status Pending + RequestId. The private key stays in the machine
                      request store until Receive-APKIAdcsRpcCertificate accepts the certificate.
           Denied / CA unavailable / other -> Denied / Failed with the certreq message.
        Working files live in <data root>\tmp\<guid> and are removed in all cases.
    .OUTPUTS
        ProviderResult (docs/contracts.md). Nothing under -WhatIf.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$Order
    )

    $orderId = $null
    if ($Order.PSObject.Properties['Id']) { $orderId = [string]$Order.Id }

    $settings = $null
    $inf = $null
    try {
        $settings = Get-APKIAdcsRpcSetting -Order $Order
        $inf = New-APKIRequestInf -Order $Order
    }
    catch {
        $msg = "Order is not valid for the AdcsRpc provider: $($_.Exception.Message)"
        Write-APKILog -Message $msg -Level Error -EventId 3004 -OrderId $orderId
        return New-APKIAdcsRpcResult -Status Failed -Message $msg
    }

    $target = '{0} ({1})' -f $settings.CAConfig, (@($Order.Hostnames) -join ', ')
    if (-not $PSCmdlet.ShouldProcess($target, 'Request certificate from ADCS (certreq)')) {
        return
    }

    $workDir = $null
    try {
        $workDir = Join-Path (Join-Path (Get-APKIRoot) 'tmp') ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $workDir -Force -WhatIf:$false | Out-Null
        $infPath = Join-Path $workDir 'request.inf'
        $reqPath = Join-Path $workDir 'request.req'
        $cerPath = Join-Path $workDir 'issued.cer'

        # UTF-16 LE with BOM: the INF encoding certreq/SetupAPI is documented to read reliably.
        Set-Content -LiteralPath $infPath -Value $inf -Encoding Unicode -NoNewline -WhatIf:$false

        $new = Invoke-APKICertreq -Arguments @('-new', '-q', '-machine', $infPath, $reqPath)
        if ($new.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $reqPath)) {
            $detail = (@($new.Output) | Where-Object { $_ }) -join ' '
            $msg = "certreq -new failed (exit $($new.ExitCode)): $detail"
            Write-APKILog -Message $msg -Level Error -EventId 3000 -OrderId $orderId
            return New-APKIAdcsRpcResult -Status Failed -Message $msg
        }

        $submitArgs = @('-submit', '-q', '-config', $settings.CAConfig)
        if ($settings.Template) {
            $submitArgs += @('-attrib', ('CertificateTemplate:{0}' -f $settings.Template))
        }
        $submitArgs += @($reqPath, $cerPath)

        $submit = Invoke-APKICertreq -Arguments $submitArgs
        $response = ConvertFrom-APKICertreqOutput -Output $submit.Output -ExitCode $submit.ExitCode
        Resolve-APKIAdcsRpcResponse -Order $Order -Response $response -CertificatePath $cerPath
    }
    catch {
        $msg = "Certificate request failed: $($_.Exception.Message)"
        Write-APKILog -Message $msg -Level Error -EventId 3000 -OrderId $orderId
        New-APKIAdcsRpcResult -Status Failed -Message $msg
    }
    finally {
        if ($workDir -and (Test-Path -LiteralPath $workDir)) {
            Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue -WhatIf:$false
        }
    }
}
