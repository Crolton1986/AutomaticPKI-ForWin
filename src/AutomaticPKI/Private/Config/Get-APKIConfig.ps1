function Get-APKIConfig {
    <#
    .SYNOPSIS
        Reads <root>\config.json and returns it with defaults filled in for missing keys.
    .DESCRIPTION
        Returns the defaults when config.json does not exist. Invalid JSON or invalid values log
        EventId 3004 and throw.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $path = Join-Path (Get-APKIRoot) 'config.json'
    if (-not (Test-Path -LiteralPath $path)) {
        Write-Verbose "No configuration at '$path'; using defaults."
        return (Get-APKIDefaultConfig)
    }

    $config = $null
    try {
        $raw = Get-Content -LiteralPath $path -Raw -Encoding UTF8 -ErrorAction Stop
        if ($null -eq $raw -or $raw.Trim().Length -eq 0) {
            throw 'the file is empty.'
        }
        try {
            $config = ConvertFrom-Json -InputObject $raw -ErrorAction Stop
        }
        catch {
            throw ('it is not valid JSON ({0})' -f $_.Exception.Message)
        }
        if ($config -isnot [System.Management.Automation.PSCustomObject]) {
            throw 'the top-level value must be a JSON object.'
        }
        $config = Merge-APKIConfigDefault -InputObject $config -Default (Get-APKIDefaultConfig)
        Assert-APKIConfig -Config $config
    }
    catch {
        $message = "Configuration file '$path' is invalid: $($_.Exception.Message)"
        Write-APKILog -Message $message -Level Error -EventId 3004
        throw $message
    }

    $config
}
