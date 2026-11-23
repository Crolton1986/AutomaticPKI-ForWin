function Get-APKILocalIPAddress {
    <#
    .SYNOPSIS
        IP addresses assigned to this host (all interfaces, including loopback). Mockable.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    $result = New-Object System.Collections.Generic.List[string]
    foreach ($nic in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
        foreach ($u in $nic.GetIPProperties().UnicastAddresses) {
            $s = $u.Address.ToString()
            if (-not $result.Contains($s)) {
                $result.Add($s)
            }
        }
    }
    $result.ToArray()
}
