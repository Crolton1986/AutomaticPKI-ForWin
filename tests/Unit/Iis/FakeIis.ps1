<#
    Fake Microsoft.Web.Administration object graph for unit tests (no IIS needed).

    ServerManager : PSCustomObject { Sites, HttpSys, CommitCount } + ScriptMethod CommitChanges()
    Site          : PSCustomObject { Name, Id, Bindings }
    Bindings      : FakeIisBindingCollection (enumerable; Add/Remove overloads used by the module)
    Binding       : PSCustomObject { Protocol, BindingInformation, SslFlags } + ScriptProperties
                    CertificateHash / CertificateStoreName read from the shared HttpSys table.

    HttpSys mimics http.sys: one certificate entry per endpoint. Non-SNI bindings use "ip:port"
    (with * mapped to 0.0.0.0), SNI bindings use "host:port". Several sites on the same non-SNI
    endpoint therefore see the same certificate, as on a real server.
    Changes apply immediately; CommitCount records how often CommitChanges() was called.
#>

class FakeIisBindingCollection : System.Collections.IEnumerable {
    [string]$SiteName
    [hashtable]$HttpSys
    [System.Collections.Generic.List[object]]$Items

    FakeIisBindingCollection([string]$siteName, [hashtable]$httpSys) {
        $this.SiteName = $siteName
        $this.HttpSys = $httpSys
        $this.Items = New-Object System.Collections.Generic.List[object]
    }

    [System.Collections.IEnumerator] GetEnumerator() {
        return $this.Items.GetEnumerator()
    }

    static [string] GetHttpSysKey([string]$bindingInformation, [int]$sslFlags) {
        $last = $bindingInformation.LastIndexOf(':')
        $hostName = $bindingInformation.Substring($last + 1)
        $rest = $bindingInformation.Substring(0, $last)
        $sep = $rest.LastIndexOf(':')
        $ip = $rest.Substring(0, $sep)
        $port = $rest.Substring($sep + 1)
        if (($sslFlags -band 1) -ne 0) {
            return ('{0}:{1}' -f $hostName, $port).ToLowerInvariant()
        }
        if ($ip -eq '*' -or $ip -eq '') {
            $ip = '0.0.0.0'
        }
        return ('{0}:{1}' -f $ip, $port).ToLowerInvariant()
    }

    [object] AddRaw([string]$protocol, [string]$bindingInformation, [int]$sslFlags) {
        foreach ($existing in $this.Items) {
            if ($existing.Protocol -eq $protocol -and $existing.BindingInformation -eq $bindingInformation) {
                throw "Cannot add duplicate collection entry of type 'binding' with combined key attributes 'protocol, bindingInformation' respectively set to '$protocol, $bindingInformation'"
            }
        }
        $key = ''
        if ($protocol -eq 'https') {
            $key = [FakeIisBindingCollection]::GetHttpSysKey($bindingInformation, $sslFlags)
        }
        $binding = [pscustomobject]@{
            Protocol           = $protocol
            BindingInformation = $bindingInformation
            SslFlags           = $sslFlags
            HttpSys            = $this.HttpSys
            HttpSysKey         = $key
            FakeId             = [guid]::NewGuid().ToString()
        }
        $binding | Add-Member -MemberType ScriptProperty -Name CertificateHash -Value {
            if ($this.HttpSysKey -and $this.HttpSys.ContainsKey($this.HttpSysKey)) {
                return , $this.HttpSys[$this.HttpSysKey].Hash
            }
            return $null
        }
        $binding | Add-Member -MemberType ScriptProperty -Name CertificateStoreName -Value {
            if ($this.HttpSysKey -and $this.HttpSys.ContainsKey($this.HttpSysKey)) {
                return $this.HttpSys[$this.HttpSysKey].Store
            }
            return $null
        }
        $this.Items.Add($binding)
        return $binding
    }

    # BindingCollection.Add(string bindingInformation, byte[] certificateHash, string certificateStoreName, SslFlags sslFlags)
    [object] Add([string]$bindingInformation, [byte[]]$certificateHash, [string]$certificateStoreName, [int]$sslFlags) {
        $binding = $this.AddRaw('https', $bindingInformation, $sslFlags)
        if ($null -ne $certificateHash -and $certificateHash.Length -gt 0) {
            $key = [FakeIisBindingCollection]::GetHttpSysKey($bindingInformation, $sslFlags)
            $this.HttpSys[$key] = @{ Hash = $certificateHash; Store = $certificateStoreName }
        }
        return $binding
    }

    # BindingCollection.Add(string bindingInformation, string protocol)
    [object] Add([string]$bindingInformation, [string]$protocol) {
        return $this.AddRaw($protocol, $bindingInformation, 0)
    }

    # BindingCollection.Remove(Binding binding, bool removeConfigOnly)
    [void] Remove([object]$binding, [bool]$removeConfigOnly) {
        # Match on FakeId: PSCustomObject equality is not reliable across PowerShell versions.
        $index = -1
        for ($i = 0; $i -lt $this.Items.Count; $i++) {
            if ($this.Items[$i].FakeId -eq $binding.FakeId) {
                $index = $i
                break
            }
        }
        if ($index -lt 0) {
            throw 'Binding is not in this collection.'
        }
        $removed = $this.Items[$index]
        $this.Items.RemoveAt($index)
        if (-not $removeConfigOnly -and $removed.HttpSysKey) {
            $this.HttpSys.Remove($removed.HttpSysKey)
        }
    }
}

function ConvertTo-FakeHashByte {
    param([string]$Thumbprint)
    $bytes = New-Object byte[] ($Thumbprint.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($Thumbprint.Substring($i * 2, 2), 16)
    }
    , $bytes
}

function Build-FakeIisServerManager {
    <#
        -Site: array of hashtables
            @{ Name = 'Contoso'; Bindings = @(
                @{ Protocol = 'https'; BindingInformation = '*:443:www.contoso.com'; SslFlags = 1; Thumbprint = 'AB..'; StoreName = 'My' }
                @{ Protocol = 'http';  BindingInformation = '*:80:www.contoso.com' } ) }
        A Thumbprint on a non-SNI binding sets the shared endpoint certificate.
    #>
    param([object[]]$Site = @())

    $httpSys = @{}
    $sites = New-Object System.Collections.Generic.List[object]
    $sm = [pscustomobject]@{
        Sites       = $sites
        HttpSys     = $httpSys
        CommitCount = 0
    }
    $sm | Add-Member -MemberType ScriptMethod -Name CommitChanges -Value { $this.CommitCount = $this.CommitCount + 1 }

    $id = 1
    foreach ($s in $Site) {
        $coll = [FakeIisBindingCollection]::new([string]$s.Name, $httpSys)
        foreach ($b in @($s.Bindings)) {
            $flags = 0
            if ($b.ContainsKey('SslFlags')) {
                $flags = [int]$b.SslFlags
            }
            $null = $coll.AddRaw([string]$b.Protocol, [string]$b.BindingInformation, $flags)
            if ($b.ContainsKey('Thumbprint') -and $b.Thumbprint) {
                $key = [FakeIisBindingCollection]::GetHttpSysKey([string]$b.BindingInformation, $flags)
                $store = 'My'
                if ($b.ContainsKey('StoreName') -and $b.StoreName) {
                    $store = [string]$b.StoreName
                }
                $httpSys[$key] = @{ Hash = (ConvertTo-FakeHashByte -Thumbprint $b.Thumbprint); Store = $store }
            }
        }
        $sites.Add([pscustomobject]@{ Name = [string]$s.Name; Id = $id; Bindings = $coll })
        $id++
    }
    $sm
}

function Get-FakeIisCertificate {
    # Thumbprint currently served for a binding of the fake, as upper-case hex ('' when none).
    param([object]$ServerManager, [string]$SiteName, [string]$BindingInformation)
    foreach ($s in $ServerManager.Sites) {
        if ($s.Name -ne $SiteName) { continue }
        foreach ($b in $s.Bindings) {
            if ($b.Protocol -eq 'https' -and $b.BindingInformation -eq $BindingInformation) {
                $h = $b.CertificateHash
                if ($null -eq $h) { return '' }
                return (($h | ForEach-Object { ([byte]$_).ToString('X2') }) -join '')
            }
        }
    }
    return $null
}
