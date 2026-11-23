<#
    Fake Microsoft.Web.Administration object graph for unit tests (no IIS needed).

    ServerManager : PSCustomObject { Sites, HttpSys, CommitCount } + ScriptMethod CommitChanges()
    Site          : PSCustomObject { Name, Id, Bindings }
    Bindings      : List[object] with Add/Remove script methods (New-FakeIisBindingCollection)
    Binding       : PSCustomObject { Protocol, BindingInformation, SslFlags } + ScriptProperties
                    CertificateHash / CertificateStoreName read from the shared HttpSys table.

    HttpSys mimics http.sys: one certificate entry per endpoint. Non-SNI bindings use "ip:port"
    (with * mapped to 0.0.0.0), SNI bindings use "host:port". Several sites on the same non-SNI
    endpoint therefore see the same certificate, as on a real server.
    Changes apply immediately; CommitCount records how often CommitChanges() was called.
#>

function New-FakeIisBindingCollection {
    <#
        Plain List[object] with script methods that mimic BindingCollection.
        (A PowerShell class here failed with "Argument types do not match" when module code used it.)
        Methods: Add(info, hash, store, flags) / Add(info, protocol), Remove(binding, removeConfigOnly),
        AddRaw(protocol, info, flags). Items points back at the list for test readability.
    #>
    param([string]$SiteName, [hashtable]$HttpSys)

    $list = New-Object System.Collections.Generic.List[object]
    Add-Member -InputObject $list -MemberType NoteProperty -Name SiteName -Value $SiteName
    Add-Member -InputObject $list -MemberType NoteProperty -Name HttpSys -Value $HttpSys
    Add-Member -InputObject $list -MemberType NoteProperty -Name Items -Value $list

    # http.sys key: SNI -> host:port, otherwise ip:port with * as 0.0.0.0.
    Add-Member -InputObject $list -MemberType NoteProperty -Name KeyFn -Value {
        param([string]$bindingInformation, [int]$sslFlags)
        $last = $bindingInformation.LastIndexOf(':')
        $hostName = $bindingInformation.Substring($last + 1)
        $rest = $bindingInformation.Substring(0, $last)
        $sep = $rest.LastIndexOf(':')
        $ip = $rest.Substring(0, $sep)
        $port = $rest.Substring($sep + 1)
        if (($sslFlags -band 1) -ne 0) {
            return ('{0}:{1}' -f $hostName, $port).ToLowerInvariant()
        }
        if ($ip -eq '*' -or $ip -eq '') { $ip = '0.0.0.0' }
        ('{0}:{1}' -f $ip, $port).ToLowerInvariant()
    }

    Add-Member -InputObject $list -MemberType ScriptMethod -Name AddRaw -Value {
        param([string]$protocol, [string]$bindingInformation, [int]$sslFlags)
        for ($i = 0; $i -lt $this.Count; $i++) {
            $existing = $this[$i]
            if ($existing.Protocol -eq $protocol -and $existing.BindingInformation -eq $bindingInformation) {
                throw "Cannot add duplicate collection entry of type 'binding' with combined key attributes 'protocol, bindingInformation' respectively set to '$protocol, $bindingInformation'"
            }
        }
        $key = ''
        if ($protocol -eq 'https') {
            $key = & $this.KeyFn $bindingInformation $sslFlags
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
        # Insert, not Add: the Add script method below shadows List.Add.
        $this.Insert($this.Count, $binding)
        return $binding
    }

    # BindingCollection.Add(info, byte[] hash, store, flags) and Add(info, protocol)
    Add-Member -InputObject $list -MemberType ScriptMethod -Name Add -Value {
        if ($args.Count -eq 4) {
            $info = [string]$args[0]
            $hash = $args[1]
            $store = [string]$args[2]
            $flags = [int]$args[3]
            $binding = $this.AddRaw('https', $info, $flags)
            if ($null -ne $hash -and @($hash).Count -gt 0) {
                $key = & $this.KeyFn $info $flags
                $this.HttpSys[$key] = @{ Hash = [byte[]]$hash; Store = $store }
            }
            return $binding
        }
        if ($args.Count -eq 2) {
            return $this.AddRaw([string]$args[1], [string]$args[0], 0)
        }
        throw "Fake BindingCollection.Add: unsupported overload with $($args.Count) arguments."
    }

    # BindingCollection.Remove(Binding binding, bool removeConfigOnly)
    Add-Member -InputObject $list -MemberType ScriptMethod -Name Remove -Value {
        param([object]$binding, [bool]$removeConfigOnly)
        $index = -1
        for ($i = 0; $i -lt $this.Count; $i++) {
            if ($this[$i].FakeId -eq $binding.FakeId) {
                $index = $i
                break
            }
        }
        if ($index -lt 0) {
            throw 'Binding is not in this collection.'
        }
        $removed = $this[$index]
        $this.RemoveAt($index)
        if (-not $removeConfigOnly -and $removed.HttpSysKey) {
            $this.HttpSys.Remove($removed.HttpSysKey)
        }
    }

    , $list
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
        $coll = New-FakeIisBindingCollection -SiteName ([string]$s.Name) -HttpSys $httpSys
        foreach ($b in @($s.Bindings)) {
            $flags = 0
            if ($b.ContainsKey('SslFlags')) {
                $flags = [int]$b.SslFlags
            }
            $null = $coll.AddRaw([string]$b.Protocol, [string]$b.BindingInformation, $flags)
            if ($b.ContainsKey('Thumbprint') -and $b.Thumbprint) {
                $key = & $coll.KeyFn ([string]$b.BindingInformation) $flags
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
