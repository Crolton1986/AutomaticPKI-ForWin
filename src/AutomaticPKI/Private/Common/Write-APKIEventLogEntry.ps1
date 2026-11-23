function Write-APKIEventLogEntry {
    <#
    .SYNOPSIS
        Writes one entry to the Application event log under source 'AutomaticPKI'.
    .DESCRIPTION
        Creates the event source when it is missing and the process is elevated.
        Silently does nothing on non-Windows hosts or when the Event Log is unavailable.
        Never throws. Called only by Write-APKILog; wrapped so tests can mock it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = 'Info',

        [Parameter(Mandatory)]
        [ValidateRange(1, 65535)]
        [int]$EventId,

        [string]$OrderId
    )

    if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
        Write-Verbose 'AutomaticPKI: Event Log not available on this platform.'
        return
    }

    $source = 'AutomaticPKI'
    try {
        # 5.1: in System.dll (always loaded). pwsh 7: separate assembly shipped with pwsh.
        if (-not ('System.Diagnostics.EventLog' -as [type])) {
            Add-Type -AssemblyName 'System.Diagnostics.EventLog' -ErrorAction Stop
        }

        # SourceExists searches every log, including Security, and throws for non-admins
        # when the source is not found early. Treat that as "unknown" and just try to write.
        $exists = $null
        try {
            $exists = [System.Diagnostics.EventLog]::SourceExists($source)
        }
        catch {
            Write-Verbose ('AutomaticPKI: cannot check Event Log source: {0}' -f $_.Exception.Message)
        }

        if ($false -eq $exists) {
            $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = New-Object System.Security.Principal.WindowsPrincipal -ArgumentList $identity
            if ($principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
                [System.Diagnostics.EventLog]::CreateEventSource($source, 'Application')
            }
            else {
                Write-Verbose "AutomaticPKI: Event Log source '$source' is missing and this process is not elevated."
                return
            }
        }

        $entryType = switch ($Level) {
            'Warning' { [System.Diagnostics.EventLogEntryType]::Warning }
            'Error'   { [System.Diagnostics.EventLogEntryType]::Error }
            default   { [System.Diagnostics.EventLogEntryType]::Information }
        }

        $text = $Message
        if ($OrderId) {
            $text = "Order: $OrderId`r`n$Message"
        }
        # Event Log message limit is 31839 characters.
        if ($text.Length -gt 31000) {
            $text = $text.Substring(0, 31000) + ' ...(truncated)'
        }

        [System.Diagnostics.EventLog]::WriteEntry($source, $text, $entryType, $EventId)
    }
    catch {
        Write-Verbose ('AutomaticPKI: could not write Event Log entry: {0}' -f $_.Exception.Message)
    }
}
