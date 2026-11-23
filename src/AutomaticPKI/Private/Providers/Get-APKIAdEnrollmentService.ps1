function Get-APKIAdEnrollmentService {
    <#
    .SYNOPSIS
        Lists the enterprise CAs (pKIEnrollmentService objects) published in Active Directory.
    .DESCRIPTION
        Reads configurationNamingContext from RootDSE, then searches
        CN=Enrollment Services,CN=Public Key Services,CN=Services,<configurationNamingContext>
        one level deep for objectClass=pKIEnrollmentService, loading cn, dNSHostName and
        certificateTemplates (the attributes MS-WCCE 3.2.2.1.1.1 reads). Uses
        System.DirectoryServices only (no RSAT). Errors are terminating; mock this in tests.
    .OUTPUTS
        PSCustomObject per CA: DnsHostName, Name, Templates (string[]).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $rootDse = [adsi]'LDAP://RootDSE'
    $searchRoot = $null
    $searcher = $null
    $results = $null
    $list = New-Object System.Collections.Generic.List[object]
    try {
        $configNc = [string]$rootDse.Properties['configurationNamingContext'].Value
        if ([string]::IsNullOrWhiteSpace($configNc)) {
            throw 'RootDSE did not return configurationNamingContext.'
        }

        $basePath = 'LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,{0}' -f $configNc
        $searchRoot = New-Object System.DirectoryServices.DirectoryEntry($basePath)
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($searchRoot)
        $searcher.Filter = '(objectClass=pKIEnrollmentService)'
        $searcher.SearchScope = [System.DirectoryServices.SearchScope]::OneLevel
        $searcher.PageSize = 200
        foreach ($attribute in @('cn', 'dnshostname', 'certificatetemplates')) {
            $null = $searcher.PropertiesToLoad.Add($attribute)
        }

        $results = $searcher.FindAll()
        foreach ($result in $results) {
            # ResultPropertyCollection keys are lower-case attribute names.
            $props = $result.Properties
            $name = ''
            $dnsHostName = ''
            $templates = New-Object System.Collections.Generic.List[string]
            if ($props.Contains('cn') -and $props['cn'].Count -gt 0) { $name = [string]$props['cn'][0] }
            if ($props.Contains('dnshostname') -and $props['dnshostname'].Count -gt 0) { $dnsHostName = [string]$props['dnshostname'][0] }
            if ($props.Contains('certificatetemplates')) {
                foreach ($t in $props['certificatetemplates']) { $templates.Add([string]$t) }
            }
            $list.Add([pscustomobject]@{
                    DnsHostName = $dnsHostName
                    Name        = $name
                    Templates   = [string[]]$templates.ToArray()
                })
        }
    }
    finally {
        # SearchResultCollection holds unmanaged resources until disposed.
        if ($null -ne $results) { $results.Dispose() }
        if ($null -ne $searcher) { $searcher.Dispose() }
        if ($null -ne $searchRoot) { $searchRoot.Dispose() }
        $rootDse.Dispose()
    }

    $list.ToArray()
}
