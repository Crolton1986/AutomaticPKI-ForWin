function Get-APKIServerManager {
    <#
    .SYNOPSIS
        Returns a fresh Microsoft.Web.Administration.ServerManager.
    .DESCRIPTION
        Primary path: load %windir%\system32\inetsrv\Microsoft.Web.Administration.dll (present on
        every IIS 10 host, Server 2016+) and create a new ServerManager, so every caller reads the
        committed configuration and http.sys state instead of a cached view.
        Fallback: Get-IISServerManager from the in-box IISAdministration module. That cmdlet returns
        a module-cached instance that can be stale, so it is only used when the DLL cannot be loaded.

        All IIS functions take an optional -ServerManager so unit tests can pass a fake object graph;
        this wrapper is the only place that touches the real assembly.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param()

    $typeName = 'Microsoft.Web.Administration.ServerManager'
    if (-not ($typeName -as [type])) {
        $windir = $env:windir
        if ($windir) {
            $dll = Join-Path $windir 'system32\inetsrv\Microsoft.Web.Administration.dll'
            if (Test-Path -LiteralPath $dll) {
                try {
                    Add-Type -Path $dll -ErrorAction Stop
                }
                catch {
                    Write-APKILog -Message "Could not load ${dll}: $($_.Exception.Message)" -Level Warning
                }
            }
        }
    }

    if ($typeName -as [type]) {
        return (New-Object -TypeName $typeName)
    }

    if (Get-Command -Name 'Get-IISServerManager' -ErrorAction SilentlyContinue) {
        return (Get-IISServerManager)
    }

    throw 'IIS is not available: Microsoft.Web.Administration could not be loaded and Get-IISServerManager is missing. Install the Web-Server and Web-Scripting-Tools features.'
}
