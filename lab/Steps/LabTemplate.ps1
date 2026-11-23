# Step "CA" (part 2): version 2 certificate templates in AD, created on DC01 with the
# ActiveDirectory module (there is no in-box cmdlet that duplicates a template).
#   APKIWebServer          copy of WebServer: RSA 2048 minimum, exportable key, subject from request,
#                          Enroll for Domain Computers, Domain Admins and the CES enrollment group.
#   APKIWebServerApproval  same, plus "CA certificate manager approval" (requests go Pending).
# Existing templates are not recreated; key flags and permissions are re-applied on every run.

function Install-LabCertificateTemplate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Lab,

        [Parameter(Mandatory)]
        [hashtable]$AdminCredential,

        [Parameter(Mandatory)]
        [string]$Name,

        [bool]$RequireApproval = $false
    )
    $dc = @(Get-LabVMConfig -Lab $Lab -Role 'DC')[0]
    $principals = @('Domain Computers', 'Domain Admins', $Lab.Domain.EnrollGroup)
    Write-LabStep "Ensuring certificate template '$Name' (approval required: $RequireApproval)"
    Invoke-LabGuest -VMName $dc.Name -Credential $AdminCredential.Domain -ArgumentList $Name, $RequireApproval, $principals -ScriptBlock {
        param([string]$TemplateName, [bool]$Approval, [string[]]$Principal)
        $ErrorActionPreference = 'Stop'
        Import-Module ActiveDirectory

        $configNC = (Get-ADRootDSE).configurationNamingContext
        $pks = "CN=Public Key Services,CN=Services,$configNC"
        $templates = "CN=Certificate Templates,$pks"
        $oidContainer = "CN=OID,$pks"
        $dn = "CN=$TemplateName,$templates"

        # msPKI-Enrollment-Flag 0x2 = CT_FLAG_PEND_ALL_REQUESTS (CA manager approval).
        $enrollmentFlag = 0
        if ($Approval) { $enrollmentFlag = 2 }
        $enforced = @{
            'msPKI-Enrollment-Flag'       = [int]$enrollmentFlag
            'msPKI-Private-Key-Flag'      = [int]16    # CT_FLAG_EXPORTABLE_KEY
            'msPKI-Minimal-Key-Size'      = [int]2048
            'msPKI-Certificate-Name-Flag' = [int]1     # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
            'msPKI-RA-Signature'          = [int]0
        }

        $existing = Get-ADObject -SearchBase $templates -SearchScope OneLevel -LDAPFilter "(cn=$TemplateName)"
        if (-not $existing) {
            $src = Get-ADObject -Identity "CN=WebServer,$templates" -Properties *
            $forestOid = (Get-ADObject -Identity $oidContainer -Properties 'msPKI-Cert-Template-OID').'msPKI-Cert-Template-OID'

            # New template OID under the forest's enterprise OID, registered in the OID container.
            $oid = $null
            $oidName = $null
            do {
                $part1 = Get-Random -Minimum 1000000 -Maximum 99999999
                $part2 = Get-Random -Minimum 1000000 -Maximum 99999999
                $oid = '{0}.{1}.{2}' -f $forestOid, $part1, $part2
                $oidName = '{0}.{1}' -f $part2, ([guid]::NewGuid().ToString('N').ToUpperInvariant())
            } while (Get-ADObject -SearchBase $oidContainer -LDAPFilter "(msPKI-Cert-Template-OID=$oid)")
            New-ADObject -Path $oidContainer -Type 'msPKI-Enterprise-Oid' -Name $oidName -OtherAttributes @{
                'flags'                   = [int]1
                'displayName'             = $TemplateName
                'msPKI-Cert-Template-OID' = $oid
            }

            # flags: drop CT_FLAG_IS_DEFAULT (0x10000), set CT_FLAG_IS_MODIFIED (0x20000), as the
            # Certificate Templates console does when duplicating.
            $flags = ([int]$src.flags -band (-bnot 0x10000)) -bor 0x20000
            $attrs = @{
                'flags'                                = [int]$flags
                'revision'                             = [int]100
                'msPKI-Template-Schema-Version'        = [int]2
                'msPKI-Template-Minor-Revision'        = [int]1
                'msPKI-Cert-Template-OID'              = $oid
                'msPKI-Certificate-Application-Policy' = [string[]]@('1.3.6.1.5.5.7.3.1')
                'pKIDefaultKeySpec'                    = [int]$src.pKIDefaultKeySpec
                'pKIMaxIssuingDepth'                   = [int]$src.pKIMaxIssuingDepth
                'pKIKeyUsage'                          = [byte[]]$src.pKIKeyUsage
                'pKIExpirationPeriod'                  = [byte[]]$src.pKIExpirationPeriod
                'pKIOverlapPeriod'                     = [byte[]]$src.pKIOverlapPeriod
                'pKIExtendedKeyUsage'                  = [string[]]@($src.pKIExtendedKeyUsage)
                'pKICriticalExtensions'                = [string[]]@($src.pKICriticalExtensions)
                'pKIDefaultCSPs'                       = [string[]]@($src.pKIDefaultCSPs)
            }
            foreach ($k in $enforced.Keys) { $attrs[$k] = $enforced[$k] }
            New-ADObject -Path $templates -Type 'pKICertificateTemplate' -Name $TemplateName -DisplayName $TemplateName -OtherAttributes $attrs
        }
        else {
            Set-ADObject -Identity $dn -Replace $enforced
        }

        # Permissions: Read + Enroll for each principal.
        $enrollGuid = [guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
        $adPath = "AD:\$dn"
        $acl = Get-Acl -Path $adPath
        $changed = $false
        foreach ($p in $Principal) {
            $sid = (Get-ADGroup -Identity $p).SID
            $rules = @($acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]) |
                    Where-Object { $_.IdentityReference -eq $sid -and $_.AccessControlType -eq 'Allow' })
            if (-not ($rules | Where-Object { $_.ObjectType -eq $enrollGuid })) {
                $acl.AddAccessRule((New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $sid, ([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight), ([System.Security.AccessControl.AccessControlType]::Allow), $enrollGuid))
                $changed = $true
            }
            if (-not ($rules | Where-Object { ($_.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty) -ne 0 })) {
                $acl.AddAccessRule((New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $sid, ([System.DirectoryServices.ActiveDirectoryRights]'ReadProperty, GenericExecute'), ([System.Security.AccessControl.AccessControlType]::Allow)))
                $changed = $true
            }
        }
        if ($changed) {
            Set-Acl -Path $adPath -AclObject $acl
        }
    }
}
