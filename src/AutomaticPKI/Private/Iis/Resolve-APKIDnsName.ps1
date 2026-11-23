function Resolve-APKIDnsName {
    <#
    .SYNOPSIS
        Resolves a hostname to IP address strings. Mockable wrapper around Resolve-DnsName.
    .DESCRIPTION
        Uses Resolve-DnsName (DnsClient, in-box on Server 2016+) when present, otherwise
        System.Net.Dns. Returns an empty array when the name does not resolve.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    $result = New-Object System.Collections.Generic.List[string]
    try {
        if (Get-Command -Name 'Resolve-DnsName' -ErrorAction SilentlyContinue) {
            foreach ($r in @(Resolve-DnsName -Name $Name -ErrorAction Stop)) {
                if ($r.PSObject.Properties['IPAddress'] -and $r.IPAddress) {
                    $result.Add([string]$r.IPAddress)
                }
            }
        }
        else {
            foreach ($a in [System.Net.Dns]::GetHostAddresses($Name)) {
                $result.Add($a.ToString())
            }
        }
    }
    catch {
        Write-APKILog -Message "DNS lookup for $Name failed: $($_.Exception.Message)" -Level Info
    }
    $result.ToArray()
}
