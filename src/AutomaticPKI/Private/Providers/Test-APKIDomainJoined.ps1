function Test-APKIDomainJoined {
    <#
    .SYNOPSIS
        Returns $true when this computer is joined to an AD domain (Win32_ComputerSystem.PartOfDomain).
    .DESCRIPTION
        The only place CA discovery queries CIM. Errors are terminating; mock this in tests.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    [bool]$computer.PartOfDomain
}
