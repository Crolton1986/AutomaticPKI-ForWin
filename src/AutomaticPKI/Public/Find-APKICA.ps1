function Find-APKICA {
    <#
    .SYNOPSIS
        Lists the certification authorities this server can enroll from, and optionally makes the
        single reachable one the default.
    .DESCRIPTION
        Domain members: enterprise CAs published in Active Directory (AdcsRpc). All servers:
        https certificate enrollment policy (CEP) servers configured for the computer, usually by
        Group Policy (AdcsCep). Each candidate reports whether it answered (Reachable).
        Without -Accept nothing is changed. With -Accept, DefaultProvider and
        DefaultProviderSettings are written with Set-APKIConfig, but only when exactly one
        candidate is reachable and no CA (CAConfig / CepUrl) is configured yet; the configured
        Template is kept. With several reachable candidates nothing is selected: choose one with
        Set-APKIConfig.
    .PARAMETER Template
        Only list AD CAs that publish this certificate template (case-insensitive). CEP
        candidates cannot be filtered by template and are always listed.
    .PARAMETER Accept
        Save the single reachable candidate as the default CA (see Description).
    .EXAMPLE
        Find-APKICA -Template WebServer

        Lists the CAs that publish the WebServer template and whether each one answers.
    .EXAMPLE
        Find-APKICA -Template WebServer -Accept

        Makes the only reachable CA the default when none is configured yet.
    .EXAMPLE
        Install-APKI -NoTask -Config @{ DefaultProvider = 'AdcsRpc'; DefaultProviderSettings = @{ CAConfig = 'ca02.contoso.com\Contoso Issuing CA 2' } }

        Chooses a CA yourself when Find-APKICA reports several (merges into config.json through
        Set-APKIConfig).
    .OUTPUTS
        CA candidate objects: Provider, CAConfig, CepUrl, CAHost, CAName, PublishedTemplates,
        Source, Reachable.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    [OutputType([pscustomobject])]
    param(
        [string]$Template,

        [switch]$Accept
    )

    $candidates = @(Find-APKICertificationAuthority -Template $Template)

    if ($Accept) {
        $config = Get-APKIConfig
        $settings = $config.DefaultProviderSettings
        $configuredCa = [string](Get-APKIOptionalProperty -InputObject $settings -Name 'CAConfig' -Default '')
        $configuredCep = [string](Get-APKIOptionalProperty -InputObject $settings -Name 'CepUrl' -Default '')
        $reachable = @($candidates | Where-Object { $_.Reachable })

        if ($configuredCa -or $configuredCep) {
            $current = $configuredCa
            if (-not $current) { $current = $configuredCep }
            Write-Error -Message ("A certification authority is already configured ('{0}'); -Accept changes nothing. Use Set-APKIConfig to change it." -f $current) -Category ResourceExists
        }
        elseif ($reachable.Count -eq 0) {
            Write-Error -Message 'No reachable certification authority was found; nothing to accept. Set DefaultProviderSettings with Set-APKIConfig.' -Category ObjectNotFound
        }
        elseif ($reachable.Count -gt 1) {
            $names = ($reachable | ForEach-Object { if ($_.CAConfig) { $_.CAConfig } else { $_.CepUrl } }) -join "', '"
            Write-Error -Message ("{0} reachable certification authorities found ('{1}'); none is selected automatically. Choose one and save it with Set-APKIConfig (DefaultProvider and DefaultProviderSettings.CAConfig or CepUrl), e.g. via Install-APKI -Config." -f $reachable.Count, $names) -Category InvalidOperation
        }
        else {
            $chosen = $reachable[0]
            $templateValue = [string](Get-APKIOptionalProperty -InputObject $settings -Name 'Template' -Default '')
            if (-not $templateValue -and $Template) { $templateValue = $Template }

            # Copy the existing settings so unknown keys survive, then set the CA.
            $newSettings = ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $settings -Depth 10)
            if ($newSettings -isnot [System.Management.Automation.PSCustomObject]) { $newSettings = [pscustomobject]@{} }
            Add-Member -InputObject $newSettings -NotePropertyName 'Template' -NotePropertyValue $templateValue -Force
            if ($chosen.Provider -eq 'AdcsRpc') {
                Add-Member -InputObject $newSettings -NotePropertyName 'CAConfig' -NotePropertyValue ([string]$chosen.CAConfig) -Force
                $target = [string]$chosen.CAConfig
            }
            else {
                Add-Member -InputObject $newSettings -NotePropertyName 'CepUrl' -NotePropertyValue ([string]$chosen.CepUrl) -Force
                if ($null -eq $newSettings.PSObject.Properties['CredentialRef']) {
                    Add-Member -InputObject $newSettings -NotePropertyName 'CredentialRef' -NotePropertyValue $null -Force
                }
                $target = [string]$chosen.CepUrl
            }

            if ($PSCmdlet.ShouldProcess('AutomaticPKI configuration', ("Set default CA to '{0}' ({1})" -f $target, $chosen.Provider))) {
                $config.DefaultProvider = [string]$chosen.Provider
                $config.DefaultProviderSettings = $newSettings
                Set-APKIConfig -Config $config -Confirm:$false
                Write-APKILog -Message ("Default certification authority set to '{0}' ({1}, discovered from {2})." -f $target, $chosen.Provider, $chosen.Source)
            }
        }
    }

    $candidates
}
