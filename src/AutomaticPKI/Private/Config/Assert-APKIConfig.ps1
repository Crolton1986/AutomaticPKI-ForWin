function Assert-APKIConfig {
    <#
    .SYNOPSIS
        Throws with a list of problems unless Config has the shapes and types from docs/contracts.md.
    .DESCRIPTION
        Expects defaults to be merged already. Does not log; callers log EventId 3004.
        SMTP completeness (server/from/to when Enabled) is checked at send time instead, so a
        mail typo cannot stop renewals.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Config
    )

    $problems = New-Object System.Collections.Generic.List[string]

    # ConvertFrom-Json yields Int32 on 5.1 and Int64 on 7.
    $isInteger = {
        param($Value)
        ($Value -is [int]) -or ($Value -is [long])
    }
    $isObject = {
        param($Value)
        $Value -is [System.Management.Automation.PSCustomObject]
    }

    if (-not (& $isObject $Config)) {
        throw 'Configuration must be a JSON object.'
    }

    $minimums = [ordered]@{
        RenewalDaysBefore    = 1
        OldCertRetentionDays = 0
        LogRetentionDays     = 1
    }
    foreach ($name in $minimums.Keys) {
        $value = $Config.PSObject.Properties[$name].Value
        if (-not (& $isInteger $value) -or $value -lt $minimums[$name]) {
            $problems.Add(('{0} must be an integer >= {1}.' -f $name, $minimums[$name]))
        }
    }

    if (@('AdcsRpc', 'AdcsCep') -cnotcontains $Config.DefaultProvider) {
        $problems.Add("DefaultProvider must be 'AdcsRpc' or 'AdcsCep'.")
    }

    if (@('Strict', 'Lenient', 'Skip') -cnotcontains $Config.RevocationPolicy) {
        $problems.Add("RevocationPolicy must be 'Strict', 'Lenient' or 'Skip'.")
    }

    if (-not (& $isObject $Config.DefaultProviderSettings)) {
        $problems.Add('DefaultProviderSettings must be an object.')
    }

    $smtp = $Config.Smtp
    if (-not (& $isObject $smtp)) {
        $problems.Add('Smtp must be an object.')
    }
    else {
        if ($smtp.Enabled -isnot [bool]) {
            $problems.Add('Smtp.Enabled must be true or false.')
        }
        if ($smtp.UseSsl -isnot [bool]) {
            $problems.Add('Smtp.UseSsl must be true or false.')
        }
        if (-not (& $isInteger $smtp.Port) -or $smtp.Port -lt 1 -or $smtp.Port -gt 65535) {
            $problems.Add('Smtp.Port must be an integer between 1 and 65535.')
        }
        foreach ($name in @('Server', 'From')) {
            $value = $smtp.PSObject.Properties[$name].Value
            if ($null -ne $value -and $value -isnot [string]) {
                $problems.Add("Smtp.$name must be a string.")
            }
        }
        foreach ($recipient in @($smtp.To)) {
            if ($null -ne $recipient -and $recipient -isnot [string]) {
                $problems.Add('Smtp.To must be a list of e-mail addresses.')
                break
            }
        }
        $credentialRef = $smtp.CredentialRef
        if ($null -ne $credentialRef) {
            if ($credentialRef -isnot [string]) {
                $problems.Add('Smtp.CredentialRef must be a secret name or null.')
            }
            elseif ($credentialRef -ne '') {
                try {
                    Assert-APKISafeName -Name $credentialRef -Kind 'Smtp.CredentialRef'
                }
                catch {
                    $problems.Add($_.Exception.Message)
                }
            }
        }
    }

    if ($problems.Count -gt 0) {
        throw ($problems -join ' ')
    }
}
