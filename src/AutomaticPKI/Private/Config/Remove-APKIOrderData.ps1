function Remove-APKIOrderData {
    <#
    .SYNOPSIS
        Deletes <root>\orders\<Id>.json. Does nothing if the order does not exist.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$Id
    )

    process {
        Assert-APKISafeName -Name $Id -Kind 'order Id'
        $path = Join-Path (Join-Path (Get-APKIRoot) 'orders') "$Id.json"
        if (-not (Test-Path -LiteralPath $path)) {
            Write-Verbose "Order '$Id' does not exist."
            return
        }
        if ($PSCmdlet.ShouldProcess($path, 'Remove AutomaticPKI order')) {
            Remove-Item -LiteralPath $path -Force -ErrorAction Stop
            Write-APKILog -Message "Order '$Id' removed." -OrderId $Id
        }
    }
}
