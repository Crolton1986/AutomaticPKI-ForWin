function Get-APKICertutilAdca {
    <#
    .SYNOPSIS
        Fallback CA listing: runs certutil -ADCA and parses each CA's cn, dNSHostName and
        certificateTemplates. Used only when the LDAP search fails.
    .DESCRIPTION
        The output layout of certutil -ADCA is not documented, so the parser is tolerant:
        "attribute = value" (or "attribute: value") lines; a multi-valued attribute continues on
        the following lines, optionally numbered ("0: WebServer") or quoted. A new CA starts at
        a distinguished-name line (CN=...,CN=Enrollment Services,...) or at a second cn line.
        Entries without both cn and dNSHostName are dropped. Throws when certutil fails.
    .OUTPUTS
        PSCustomObject per CA: DnsHostName, Name, Templates (string[]); the same shape as
        Get-APKIAdEnrollmentService.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $run = Invoke-APKICertutil -Arguments @('-ADCA')
    if ($run.ExitCode -ne 0) {
        $detail = (@($run.Output) | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim() }) -join ' '
        throw ('certutil -ADCA failed (exit {0}): {1}' -f $run.ExitCode, $detail)
    }

    $list = New-Object System.Collections.Generic.List[object]
    $state = @{ Name = ''; DnsHostName = ''; Templates = (New-Object System.Collections.Generic.List[string]) }
    $inTemplates = $false

    $clean = {
        param([string]$Value)
        $v = $Value.Trim() -replace '^\d+\s*:\s*', ''
        $v.Trim().Trim('"').Trim()
    }
    $flush = {
        if ($state.Name -and $state.DnsHostName) {
            $list.Add([pscustomobject]@{
                    DnsHostName = [string]$state.DnsHostName
                    Name        = [string]$state.Name
                    Templates   = [string[]]$state.Templates.ToArray()
                })
        }
        $state.Name = ''
        $state.DnsHostName = ''
        $state.Templates = New-Object System.Collections.Generic.List[string]
    }

    foreach ($raw in @($run.Output)) {
        $line = ([string]$raw).Trim()
        if ($line.Length -eq 0) { continue }

        if ($line -match '^(?i)CN=[^,]+,.*CN=Enrollment Services') {
            & $flush
            $inTemplates = $false
            continue
        }
        if ($line -match '^(?i)CertUtil:') {
            $inTemplates = $false
            continue
        }
        if ($line -match '^(?i)cn\s*[=:]\s*(.+)$') {
            if ($state.Name) { & $flush }
            $state.Name = & $clean $Matches[1]
            $inTemplates = $false
            continue
        }
        if ($line -match '^(?i)dNSHostName\s*[=:]\s*(.+)$') {
            $state.DnsHostName = & $clean $Matches[1]
            $inTemplates = $false
            continue
        }
        if ($line -match '^(?i)certificateTemplates\s*[=:]\s*(.*)$') {
            $inTemplates = $true
            $rest = & $clean $Matches[1]
            if ($rest) { $state.Templates.Add($rest) }
            continue
        }
        if ($line -match '^[A-Za-z][A-Za-z0-9-]*\s*=') {
            # Any other attribute ends the templates list.
            $inTemplates = $false
            continue
        }
        if ($inTemplates) {
            $value = & $clean $line
            if ($value) { $state.Templates.Add($value) }
        }
    }
    & $flush

    $list.ToArray()
}
