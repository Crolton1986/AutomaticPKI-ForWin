# AutomaticPKI Hyper-V lab

An idempotent lab for the things CI cannot test: a real domain, custom templates, Kerberos and
UsernamePassword CEP/CES, CA manager approval, two enterprise CAs and a workgroup web server.
Nothing here runs in CI (it is only linted).

| VM | Role | IP (default) |
|---|---|---|
| DC01 | AD DS forest root `apki.lab`, DNS | 192.168.77.10 |
| CA01 | Enterprise root CA "APKI Lab Root CA": WebServer, APKIWebServer, APKIWebServerApproval | .11 |
| CA02 | Enterprise root CA "APKI Lab Issuing CA 2": APKIWebServer only | .12 |
| CES01 | CEP (Kerberos + UsernamePassword), CES for CA01 (UsernamePassword) | .13 |
| WEB01 | IIS 10, domain-joined, messy test sites | .21 |
| WEB02 | IIS 10, workgroup, enrolls via CEP/CES as `APKI\svc-apki-web02` | .22 |

All Windows Server 2022 on an internal switch with NAT (gateway 192.168.77.1). Names, IPs, sizes
and paths are in [LabConfig.psd1](LabConfig.psd1).

## Prerequisites
- Windows 10/11 Pro or Windows Server 2016+ host with Hyper-V and the Hyper-V PowerShell module,
  elevated Windows PowerShell 5.1.
- About 16 GB RAM free (6 VMs x 2 GB static) and 80 GB disk.
- Windows Server 2022 media, either:
  - the evaluation ISO (`IsoPath`): the VMs step builds a generation 2 base VHDX from `install.wim`
    (index 2 = Standard with Desktop Experience), or
  - a sysprepped base disk (`BaseVhdPath`). The Microsoft eval `.vhd` is generation 1: set
    `Generation = 1`.
- No other NAT network on the host (WinNAT allows one), or change `Network` to match yours.

Passwords are never stored in the repo. The scripts prompt for the lab Administrator password
(local Administrator on every VM, domain Administrator, DSRM) and for the enrollment account.
The Administrator password is written into each VM's `unattend.xml` for first boot and that file
is deleted from the guest once the VM is reachable.

## Build
```powershell
cd lab
.\New-APKILab.ps1                      # everything, 1.5-2 h on SSD
.\New-APKILab.ps1 -Step CA, CES        # rerun selected steps
```
| Step | Does | Time |
|---|---|---|
| Network | internal switch, host IP, NAT | < 1 min |
| VMs | base disk (if missing), differencing disks, unattend, first boot, static IP | 30-40 min |
| Domain | forest + DNS, A records, `svc-apki-web02` in group "APKI CES Enrollers", domain joins | 20-30 min |
| CA | both CAs (+ HTTP CRL/AIA), templates, publication, lab roots trusted on CES/WEB VMs | 10-15 min |
| CES | delegation for CES01, HTTPS cert from CA01, CEP x2, CES, CES URL on CA01's AD object | 5-10 min |
| Web | IIS and sites on WEB01/WEB02 | 5-10 min |

Each step checks state first, so reruns only fix what is missing. In-guest work uses PowerShell
Direct (`Invoke-Command -VMName`); reboots are detected by a changed guest boot time, not by
sleeping.

### Design notes
- **CA02 is a second enterprise root, not a subordinate of CA01.** A subordinate needs CA01
  online, the SubCA template and an issue/install round trip that can leave a half-configured CA
  when interrupted. A second root is one `Install-AdcsCertificationAuthority` call that either
  completes or can simply be rerun. For AutomaticPKI the hierarchy does not matter: discovery reads
  `pKIEnrollmentService` objects and their `certificateTemplates`, and both roots are published to
  AD so domain members trust them (the workgroup host gets both roots imported).
- **Templates** are created on DC01 with the ActiveDirectory module as version 2 copies of WebServer
  (new OID registered in the forest OID container): RSA 2048 minimum, exportable key, subject from
  request, Read+Enroll for Domain Computers, Domain Admins and "APKI CES Enrollers".
  `APKIWebServerApproval` additionally sets `CT_FLAG_PEND_ALL_REQUESTS`.
- **CES** runs as the CES01 computer account; CES01 gets constrained delegation with protocol
  transition to HOST/RPCSS on CA01, which UsernamePassword authentication against a remote CA needs.
  The CES URL is added to CA01 with `certutil -enrollmentServerURL ... UserName`, so CEP hands it out.
- **CRL/AIA over HTTP**: each CA serves `CertEnroll` from IIS so the workgroup host (which cannot read
  the LDAP locations) passes revocation checks under `RevocationPolicy = Strict`.

URLs (defaults):
- CEP Kerberos `https://ces01.apki.lab/ADPolicyProvider_CEP_Kerberos/service.svc/CEP`
- CEP UsernamePassword `https://ces01.apki.lab/ADPolicyProvider_CEP_UsernamePassword/service.svc/CEP`
- CES `https://ces01.apki.lab/APKI%20Lab%20Root%20CA_CES_UsernamePassword/service.svc/CES`

### WEB01 sites
| Site | Bindings | Discovery should report |
|---|---|---|
| APKI-Www | https `*:443:www.apki.lab` (SNI), http `*:80:www.apki.lab` | Usable |
| APKI-App | https `*:443:app.apki.lab` (SNI) | Usable |
| APKI-BlankHost | https `192.168.77.21:443:` (non-SNI), self-signed `legacy.apki.lab` bound | Usable, name from bound cert |
| APKI-HttpOnly | http `*:80:http-only.apki.lab` | Usable, proposes https binding |
| APKI-IpOnly | http `192.168.77.21:8080:` | NeedsName |
| APKI-SingleLabel | https/http `intranet` | NeedsName (single label) |

WEB02 has `APKI-Workgroup` on `web02.apki.lab`. Its apki.lab names come from DC01 DNS, or from the
hosts file with `Web.WorkgroupNameResolution = 'Hosts'`.

## Test
```powershell
.\Invoke-APKILabTests.ps1                         # all scenarios
.\Invoke-APKILabTests.ps1 -Scenario Pending, TwoCA
```
Copies `src\AutomaticPKI` to WEB01/WEB02 (`C:\Program Files\WindowsPowerShell\Modules`), runs each
scenario in the guest with `APKI_ROOT = C:\APKILab\data`, prints a PASS/FAIL/N/A/INFO checklist and
exits 1 on any FAIL. Public cmdlets that do not exist yet (or are not exported by the manifest) show
N/A; where a provider function already exists the scenario also calls it directly in module scope.

| Scenario | Proves |
|---|---|
| Install | `Install-APKI` sets up the host (scheduled task) on domain and workgroup hosts |
| Discovery | IIS discovery handles SNI, blank host, http-only, IP-only and single-label names; `Find-APKISite` + `Approve-APKIOrder` |
| RpcEnroll | certreq RPC/DCOM enrollment with a custom v2 template from an enterprise CA; `New-APKICertificate` binds it |
| TwoCA | two CAs publish APKIWebServer, only CA01 publishes the approval template; CA02 issues and refuses the unpublished template; `Find-APKICA` returns both and never auto-selects; none on the workgroup host |
| Pending | approval template returns Pending with a CA request ID; after `certutil -resubmit` on CA01 the certificate is received (`Receive-APKIAdcsRpcCertificate`, `Invoke-APKIRenewal`) |
| CepEnroll | workgroup host enrolls through CEP/CES UsernamePassword with a DPAPI-stored secret; Kerberos CEP reachable from WEB01 |
| Renewal | `Invoke-APKIRenewal` completes on both hosts |

Reset a test host by deleting `C:\APKILab\data` and unwanted certificates in `LocalMachine\My`, or
checkpoint WEB01/WEB02 after the Web step and revert.

## Cleanup
```powershell
.\Remove-APKILab.ps1 -WhatIf               # show what would go
.\Remove-APKILab.ps1                       # VMs, disks, NAT, host IP, switch (base disk kept)
.\Remove-APKILab.ps1 -IncludeBaseImage -Confirm:$false
```
