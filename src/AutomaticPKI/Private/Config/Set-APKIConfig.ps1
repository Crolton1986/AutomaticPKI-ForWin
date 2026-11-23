function Set-APKIConfig {
    <#
    .SYNOPSIS
        Validates a configuration object and writes it atomically to <root>\config.json.
    .DESCRIPTION
        Accepts a PSCustomObject (e.g. from Get-APKIConfig) or a hashtable. Keys missing from the
        input are filled from the defaults, not from the existing file: to change one value, use
        Get-APKIConfig, modify, then Set-APKIConfig. Invalid input logs EventId 3004 and throws
        without touching the existing file.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$Config
    )

    process {
        $normalized = $null
        try {
            # JSON round-trip: deep copy, and hashtables become PSCustomObjects.
            $json = ConvertTo-Json -InputObject $Config -Depth 10
            $normalized = ConvertFrom-Json -InputObject $json -ErrorAction Stop
            if ($normalized -isnot [System.Management.Automation.PSCustomObject]) {
                throw 'configuration must be an object or hashtable.'
            }
            $normalized = Merge-APKIConfigDefault -InputObject $normalized -Default (Get-APKIDefaultConfig)
            Assert-APKIConfig -Config $normalized
        }
        catch {
            $message = "Configuration is invalid and was not saved: $($_.Exception.Message)"
            Write-APKILog -Message $message -Level Error -EventId 3004
            throw $message
        }

        $path = Join-Path (Get-APKIRoot) 'config.json'
        if ($PSCmdlet.ShouldProcess($path, 'Write AutomaticPKI configuration')) {
            Write-APKIFileAtomic -Path $path -Content (ConvertTo-Json -InputObject $normalized -Depth 10)
            Write-APKILog -Message "Configuration saved to '$path'."
        }
    }
}
