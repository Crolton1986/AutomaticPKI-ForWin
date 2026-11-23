function Import-APKIProtectedDataType {
    <#
    .SYNOPSIS
        Makes [System.Security.Cryptography.ProtectedData] available, or throws if DPAPI is unavailable.
    .NOTES
        Windows PowerShell 5.1: lives in System.Security.dll (not loaded by default).
        PowerShell 7 on Windows: System.Security.Cryptography.ProtectedData.dll ships with pwsh.
    #>
    [CmdletBinding()]
    param()

    foreach ($assemblyName in @('System.Security', 'System.Security.Cryptography.ProtectedData')) {
        if ('System.Security.Cryptography.ProtectedData' -as [type]) {
            break
        }
        try {
            Add-Type -AssemblyName $assemblyName -ErrorAction Stop
        }
        catch {
            Write-Verbose ('Could not load assembly {0}: {1}' -f $assemblyName, $_.Exception.Message)
        }
    }

    if (-not ('System.Security.Cryptography.ProtectedData' -as [type])) {
        throw 'DPAPI (System.Security.Cryptography.ProtectedData) is not available on this platform.'
    }
}
