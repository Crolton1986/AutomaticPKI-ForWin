# AutomaticPKI Hyper-V lab configuration. Read by New-APKILab.ps1, Remove-APKILab.ps1 and
# Invoke-APKILabTests.ps1 with Import-PowerShellDataFile.
# No passwords here: the scripts prompt with Get-Credential (or take -AdminCredential /
# -EnrollUserCredential) at runtime.
@{
    # Root folder for VM configuration files and differencing disks (one subfolder per VM).
    VMPath         = 'C:\Hyper-V\APKILab'

    # Sysprepped Windows Server 2022 base disk. Every VM gets a differencing disk on top of it.
    # If BaseVhdPath does not exist and IsoPath is set, New-APKILab builds a generation 2 VHDX
    # from the ISO (in-box DISM cmdlets). A Microsoft eval .vhd works too: set Generation = 1.
    BaseImage      = @{
        BaseVhdPath = 'C:\Hyper-V\APKILab\Base\WS2022-Base.vhdx'
        IsoPath     = 'C:\ISO\SERVER_EVAL_x64FRE_en-us.iso'
        # install.wim index: 2 = Standard (Desktop Experience) on the 2022 eval ISO.
        ImageIndex  = 2
        SizeBytes   = 60GB
    }
    Generation     = 2
    TimeZone       = 'UTC'

    Network        = @{
        SwitchName   = 'APKI-Lab'
        NatName      = 'APKI-Lab-NAT'
        Prefix       = '192.168.77.0'
        PrefixLength = 24
        Gateway      = '192.168.77.1'
        # DNS forwarder on DC01 for internet names; empty string = none.
        DnsForwarder = '1.1.1.1'
    }

    Domain         = @{
        Name           = 'apki.lab'
        NetbiosName    = 'APKI'
        # Built-in Administrator; the same password is used locally on every VM, for the
        # domain Administrator after promotion and as the DSRM password.
        AdminUserName  = 'Administrator'
        # Domain user that WEB02 (workgroup) uses for CEP/CES UsernamePassword enrollment.
        EnrollUserName = 'svc-apki-web02'
        EnrollGroup    = 'APKI CES Enrollers'
    }

    # Role: DC, CA, CES, Web (domain-joined), WebWorkgroup (not joined).
    VMs            = @(
        @{ Name = 'DC01'; Role = 'DC'; IPAddress = '192.168.77.10'; MemoryBytes = 2GB; ProcessorCount = 2 }
        @{ Name = 'CA01'; Role = 'CA'; IPAddress = '192.168.77.11'; MemoryBytes = 2GB; ProcessorCount = 2 }
        @{ Name = 'CA02'; Role = 'CA'; IPAddress = '192.168.77.12'; MemoryBytes = 2GB; ProcessorCount = 2 }
        @{ Name = 'CES01'; Role = 'CES'; IPAddress = '192.168.77.13'; MemoryBytes = 2GB; ProcessorCount = 2 }
        @{ Name = 'WEB01'; Role = 'Web'; IPAddress = '192.168.77.21'; MemoryBytes = 2GB; ProcessorCount = 2 }
        @{ Name = 'WEB02'; Role = 'WebWorkgroup'; IPAddress = '192.168.77.22'; MemoryBytes = 2GB; ProcessorCount = 2 }
    )

    CertificationAuthorities = @(
        # CA01: enterprise root that also issues. Publishes WebServer plus both lab templates.
        @{ VMName = 'CA01'; CommonName = 'APKI Lab Root CA'; Templates = @('WebServer', 'APKIWebServer', 'APKIWebServerApproval'); Exclusive = $false }
        # CA02: second enterprise root (see README). Publishes APKIWebServer and nothing else.
        @{ VMName = 'CA02'; CommonName = 'APKI Lab Issuing CA 2'; Templates = @('APKIWebServer'); Exclusive = $true }
    )

    Templates      = @{
        Standard = 'APKIWebServer'
        Approval = 'APKIWebServerApproval'
    }

    EnrollmentServices = @{
        VMName = 'CES01'
        # CES instance is created for this CA (VMName of an entry above).
        CAVMName = 'CA01'
    }

    Web            = @{
        # WEB02 name resolution for apki.lab: 'Dns' (DC01 as DNS server) or 'Hosts' (hosts file).
        WorkgroupNameResolution = 'Dns'
        # Site content root inside the web VMs (under C:\inetpub so app pools can read it).
        SiteRoot                = 'C:\inetpub\apki'

        # A records created in apki.lab (label -> VM). 'intranet' backs the single-label site.
        DnsRecords              = @{
            'www'       = 'WEB01'
            'app'       = 'WEB01'
            'legacy'    = 'WEB01'
            'http-only' = 'WEB01'
            'intranet'  = 'WEB01'
            'web02'     = 'WEB02'
        }

        # IIS sites. IPAddress 'VM' = the VM's own address. Sni applies to https bindings.
        # SelfSignedDnsName: bind a self-signed certificate with this SAN (simulates a legacy cert,
        # gives discovery a name for the blank-host binding).
        Sites                   = @(
            # Good SNI names.
            @{ VMName = 'WEB01'; Name = 'APKI-Www'; Bindings = @(
                    @{ Protocol = 'https'; IPAddress = '*'; Port = 443; HostHeader = 'www.apki.lab'; Sni = $true }
                    @{ Protocol = 'http'; IPAddress = '*'; Port = 80; HostHeader = 'www.apki.lab'; Sni = $false }
                ) }
            @{ VMName = 'WEB01'; Name = 'APKI-App'; Bindings = @(
                    @{ Protocol = 'https'; IPAddress = '*'; Port = 443; HostHeader = 'app.apki.lab'; Sni = $true }
                ) }
            # Blank host header https on IP:443 (non-SNI), legacy self-signed cert bound.
            @{ VMName = 'WEB01'; Name = 'APKI-BlankHost'; SelfSignedDnsName = 'legacy.apki.lab'; Bindings = @(
                    @{ Protocol = 'https'; IPAddress = 'VM'; Port = 443; HostHeader = ''; Sni = $false }
                ) }
            # http only, with a host header: discovery proposes an https binding.
            @{ VMName = 'WEB01'; Name = 'APKI-HttpOnly'; Bindings = @(
                    @{ Protocol = 'http'; IPAddress = '*'; Port = 80; HostHeader = 'http-only.apki.lab'; Sni = $false }
                ) }
            # IP only, no host header anywhere: discovery must report NeedsName.
            @{ VMName = 'WEB01'; Name = 'APKI-IpOnly'; Bindings = @(
                    @{ Protocol = 'http'; IPAddress = 'VM'; Port = 8080; HostHeader = ''; Sni = $false }
                ) }
            # Single-label host name: not usable as a SAN, NeedsName.
            @{ VMName = 'WEB01'; Name = 'APKI-SingleLabel'; Bindings = @(
                    @{ Protocol = 'https'; IPAddress = '*'; Port = 443; HostHeader = 'intranet'; Sni = $true }
                    @{ Protocol = 'http'; IPAddress = '*'; Port = 80; HostHeader = 'intranet'; Sni = $false }
                ) }
            # Workgroup host.
            @{ VMName = 'WEB02'; Name = 'APKI-Workgroup'; Bindings = @(
                    @{ Protocol = 'https'; IPAddress = '*'; Port = 443; HostHeader = 'web02.apki.lab'; Sni = $true }
                    @{ Protocol = 'http'; IPAddress = '*'; Port = 80; HostHeader = 'web02.apki.lab'; Sni = $false }
                ) }
        )
    }
}
