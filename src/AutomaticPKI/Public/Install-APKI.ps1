function Install-APKI {
    <#
    .SYNOPSIS
        Installs AutomaticPKI on this server: module files, configuration, scheduled task, and
        adoption of the certificates IIS already serves.
    .DESCRIPTION
        1. Copies the module to -Destination (Private, Public and the manifest are replaced, so
           no stale files survive an upgrade).
        2. Writes config.json with Set-APKIConfig: -Config values are merged over the existing
           configuration (nested objects such as Smtp key by key); nothing else is changed.
        3. Registers the daily renewal task for the installed copy (skipped with -NoTask).
        4. Adopts existing IIS certificates: Find-APKISite -Save records a Proposed order for
           every site, with the currently bound certificate as CurrentThumbprint. Nothing is
           requested or replaced; review with Get-APKIOrder and approve with Approve-APKIOrder.
        Run elevated.
    .PARAMETER Destination
        Module folder (must be named AutomaticPKI).
    .PARAMETER Config
        Configuration values to set, e.g. @{ DefaultProviderSettings = @{ CAConfig = 'ca01.contoso.com\Contoso Issuing CA' } }.
    .PARAMETER NoTask
        Do not register the scheduled task.
    .EXAMPLE
        Import-Module .\src\AutomaticPKI\AutomaticPKI.psd1; Install-APKI -Config @{ DefaultProviderSettings = @{ CAConfig = 'ca01.contoso.com\Contoso Issuing CA'; Template = 'WebServer' } }

        Installs to Program Files, sets the CA, registers the task and proposes orders for the IIS sites.
    .EXAMPLE
        Install-APKI -NoTask -WhatIf

        Shows what would be installed.
    .OUTPUTS
        PSCustomObject: ModulePath, TaskRegistered, ProposedOrders (Ids saved by this run),
        CAConfigured.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    [OutputType([pscustomobject])]
    param(
        [string]$Destination = "$env:ProgramFiles\WindowsPowerShell\Modules\AutomaticPKI",

        [hashtable]$Config,

        [switch]$NoTask
    )

    $source = [System.IO.Path]::GetFullPath($MyInvocation.MyCommand.Module.ModuleBase).TrimEnd('\', '/')
    $target = [System.IO.Path]::GetFullPath($Destination).TrimEnd('\', '/')
    if ((Split-Path -Path $target -Leaf) -ne 'AutomaticPKI') {
        throw "Destination '$target' must be a folder named 'AutomaticPKI'."
    }
    $manifestPath = Join-Path $target 'AutomaticPKI.psd1'

    # 1. Module files
    if ($source -eq $target) {
        Write-Verbose "Module already runs from '$target'; files not copied."
    }
    elseif ($PSCmdlet.ShouldProcess($target, "Install AutomaticPKI module from '$source'")) {
        if (-not (Test-Path -LiteralPath $target)) {
            New-Item -ItemType Directory -Path $target -Force | Out-Null
        }
        foreach ($name in @('Private', 'Public', 'AutomaticPKI.psd1', 'AutomaticPKI.psm1')) {
            $old = Join-Path $target $name
            if (Test-Path -LiteralPath $old) {
                Remove-Item -LiteralPath $old -Recurse -Force -ErrorAction Stop
            }
        }
        foreach ($item in @(Get-ChildItem -LiteralPath $source -Force)) {
            Copy-Item -LiteralPath $item.FullName -Destination $target -Recurse -Force -ErrorAction Stop
        }
        Write-APKILog -Message "AutomaticPKI module installed to '$target'."
    }

    # 2. Configuration (merge over what exists)
    $merged = Get-APKIConfig
    if ($Config) {
        $incoming = ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $Config -Depth 10)
        $merged = Merge-APKIConfigDefault -InputObject $incoming -Default $merged
    }
    if ($PSCmdlet.ShouldProcess('AutomaticPKI configuration', 'Write config.json')) {
        Set-APKIConfig -Config $merged -Confirm:$false
    }

    # --- T11 HOOK: CA discovery ------------------------------------------------------------
    # When no CA is configured, T11 calls Find-APKICertificationAuthority here and proposes the
    # result (discovery never writes config on its own; docs/contracts.md "CA candidate").
    $providerSettings = $merged.DefaultProviderSettings
    $caConfigured = [bool]([string](Get-APKIOptionalProperty -InputObject $providerSettings -Name 'CAConfig' -Default '')) -or
    [bool]([string](Get-APKIOptionalProperty -InputObject $providerSettings -Name 'CepUrl' -Default ''))
    if (-not $caConfigured) {
        Write-APKILog -Message 'No certification authority is configured (DefaultProviderSettings.CAConfig is empty). Set it with Install-APKI -Config or Set-APKIConfig before approving orders.' -Level Warning
    }
    # --- end T11 HOOK -----------------------------------------------------------------------

    # 3. Scheduled task
    $taskRegistered = $false
    if (-not $NoTask) {
        $task = Register-APKIRenewalTask -ModulePath $manifestPath -Force -Confirm:$false
        $taskRegistered = ($null -ne $task)
    }

    # 4. Adopt existing IIS certificates as Proposed orders (nothing is issued or replaced).
    $before = @(Get-APKIOrderData | ForEach-Object { [string]$_.Id })
    $proposed = New-Object System.Collections.Generic.List[string]
    try {
        foreach ($order in @(Find-APKISite -Save -Confirm:$false)) {
            $id = [string]$order.Id
            if ($before -notcontains $id -and $null -ne (Get-APKIOrderData -Id $id)) {
                $proposed.Add($id)
            }
        }
    }
    catch {
        Write-APKILog -Message ('IIS sites could not be scanned; no orders proposed: {0}' -f $_.Exception.Message) -Level Warning
    }

    [pscustomobject]@{
        ModulePath     = $manifestPath
        TaskRegistered = $taskRegistered
        ProposedOrders = [string[]]$proposed.ToArray()
        CAConfigured   = $caConfigured
    }
}
