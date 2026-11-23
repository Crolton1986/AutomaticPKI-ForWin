function Write-APKILog {
    <#
    .SYNOPSIS
        Central logging entry point. Every module component logs through this.
    .NOTES
        Stub from scaffold. T2 replaces the body with file + Event Log output.
        Signature is a contract: do not change parameters without updating docs/contracts.md.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = 'Info',

        # Fixed event ID from docs/contracts.md. 0 = no Event Log entry.
        [int]$EventId = 0,

        # Order the message relates to, if any.
        [string]$OrderId
    )

    $line = '{0:u} [{1}] {2}{3}' -f (Get-Date), $Level, $(if ($OrderId) { "[$OrderId] " } else { '' }), $Message
    switch ($Level) {
        'Warning' { Write-Warning $line }
        'Error'   { Write-Warning $line }
        default   { Write-Verbose $line }
    }
}
