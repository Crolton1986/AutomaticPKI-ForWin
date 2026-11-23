# Internal contracts

Components are built in parallel. These shapes are fixed; change them only with a matching update here.

## Data root
`Get-APKIRoot` → `$env:APKI_ROOT` or `%ProgramData%\AutomaticPKI`.
```
config.json            global settings
orders\<Id>.json       one order per file
snapshots\<Id>\<ts>.json  binding snapshots before a swap
logs\apki-<yyyyMMdd>.log
tmp\<guid>\            per-operation scratch, always deleted in finally
```
Functions that honor `-WhatIf` return nothing when the operation is skipped.

Shared helpers (reuse, don't duplicate): `Invoke-APKICertreq`, `Invoke-APKICertutil`, `Find-APKIMachineCertificate` (Private/Providers).

## Global config (`config.json`)
```json
{
  "RenewalDaysBefore": 30,
  "OldCertRetentionDays": 14,
  "DefaultProvider": "AdcsRpc",
  "DefaultProviderSettings": { "CAConfig": "ca01.corp.local\\Corp Issuing CA", "Template": "WebServer" },
  "Smtp": { "Enabled": false, "Server": "", "Port": 25, "UseSsl": true, "From": "", "To": [], "CredentialRef": null },
  "LogRetentionDays": 30,
  "RevocationPolicy": "Strict"
}
```
`RevocationPolicy`: `Strict` (unknown/offline revocation fails precheck), `Lenient` (warn), `Skip`. Revoked always fails.

`CredentialRef` names a DPAPI-protected secret stored by T2 (`secrets\<name>.xml`), never plain text.

## Order (`orders\<Id>.json`, PSCustomObject in memory)
| Field | Type | Notes |
|---|---|---|
| Id | string | slug of site name, unique |
| Status | string | `Proposed`, `Approved`, `Pending`, `Active`, `Failed`, `Disabled` |
| SiteName | string | IIS site |
| Hostnames | string[] | SANs; first is subject CN |
| Bindings | Binding[] | bindings this order manages |
| Provider | string | `AdcsRpc` or `AdcsCep` |
| ProviderSettings | object | AdcsRpc: `CAConfig`, `Template`. AdcsCep: `CepUrl`, `Template`, `CredentialRef` (null = Kerberos) |
| Key | object | `Algorithm` (`RSA`/`ECDSA_P256`), `Length` (2048), `Exportable` (bool). Honored by AdcsRpc only; AdcsCep uses the template's key settings and logs a warning on mismatch |
| KeyMode | string | `OnHost` (default) or `Central` |
| CreateBinding | bool | create https binding if missing |
| HttpProbe | object | `Enabled`, `Path` (`/`), `ExpectStatusBelow` (500) |
| RenewalDaysBefore | int/null | overrides global |
| CurrentThumbprint, PreviousThumbprint | string | |
| PendingRequestId | string | provider-specific while `Pending`: AdcsRpc = numeric CA request ID; AdcsCep = thumbprint of the request in `Cert:\LocalMachine\Request` (retrieval must run on the same host) |
| LastRenewal | string | ISO 8601 |
| LastError | string | |

## Binding (IIS layer output)
| Field | Type | Notes |
|---|---|---|
| SiteName | string | |
| Protocol | string | `https` / `http` |
| IPAddress | string | `*` or literal IP |
| Port | int | |
| HostHeader | string | empty for non-SNI |
| SslFlags | int | 0 none, 1 SNI |
| Thumbprint | string | empty for http |
| StoreName | string | `My` / `WebHosting` |
| NameStatus | string | `Usable`, `NeedsName` |
| SharedWith | string[] | other sites on the same non-SNI IP:port |

## Provider functions
Each provider `<P>` (`AdcsRpc`, `AdcsCep`) implements:
- `Request-APKI<P>Certificate -Order <Order>` → ProviderResult
- `Receive-APKI<P>Certificate -Order <Order> -RequestId <string>` → ProviderResult (pending retrieval)
- `Test-APKI<P>Provider -Order <Order>` → `[bool]`, logs reason on false

ProviderResult: `Status` (`Issued`/`Pending`/`Denied`/`Failed`), `Thumbprint`, `RequestId`, `Message`.
Issued certs land in `Cert:\LocalMachine\My` with private key. Providers log issuance without an event ID; `Invoke-APKISwapWithRollback` logs 1001 after binding and health check succeed; nothing else logs 1001.

`Get-APKISecret -Name` returns a `[pscredential]`.

## CA candidate (`Find-APKICertificationAuthority`)
| Field | Type | Notes |
|---|---|---|
| Provider | string | `AdcsRpc` or `AdcsCep` |
| CAConfig | string | `host\CA Name` (AdcsRpc), else null |
| CepUrl | string | AdcsCep only, else null |
| CAHost | string | CA DNS host name (`dNSHostName`) |
| CAName | string | CA name (`cn`) |
| PublishedTemplates | string[] | from `certificateTemplates`; empty for CEP |
| Source | string | `AD`, `GPO`, `Manual` |
| Reachable | bool | result of `Test-APKI<Provider>Provider` |

Discovery never writes config on its own. One reachable match with empty `DefaultProviderSettings` is proposed; the admin confirms via `Set-APKIConfig` or `Find-APKICA -Accept`. More than one match is never auto-selected.

## Health check result
Each check returns `[pscustomobject]@{ Check = 'TlsHandshake'; Target = 'www.contoso.com:443'; Passed = $true; Detail = '...' }`.

`Invoke-APKIHealthCheck` → `{ Passed; Thumbprint; Results[] }`.
`Invoke-APKISwapWithRollback` → `{ Success; Outcome; ActiveThumbprint; Precheck; HealthCheck; RollbackHealthCheck; Error }`. It never mutates the order; the caller saves Current/PreviousThumbprint.

Binding.IPAddress for IPv6 is stored without brackets.

## IIS layer functions (called by Health)
- `Get-APKIServerManager` (no params)
- `Save-APKIBindingSnapshot -Order` → snapshot object
- `Restore-APKIBindingSnapshot -Order -Snapshot`
- `Set-APKIIisCertificateBinding -Order -Thumbprint` (SupportsShouldProcess)

## Notification
`Send-APKINotification -Subject -Body [-Level Info|Warning|Error] [-EventId] [-OrderId]`

## Logging
`Write-APKILog -Message -Level Info|Warning|Error -EventId <int> -OrderId <string>`. Event Log source `AutomaticPKI`, log `Application`.

| ID | Level | Meaning |
|---|---|---|
| 1000 | Info | Renewal run completed |
| 1001 | Info | Certificate issued and bound |
| 1002 | Info | Request pending CA approval |
| 1003 | Info | HTTPS binding created |
| 1004 | Info | Old certificate removed |
| 1005 | Info | Certification authority discovered |
| 2000 | Warning | Certificate expiring, renewal not succeeding |
| 2001 | Warning | Binding needs a hostname (discovery) |
| 2002 | Warning | Hostname does not resolve to this host |
| 2003 | Warning | Multiple CAs match, admin must choose |
| 2004 | Warning | No CA found (not domain-joined or none publishes template) |
| 3000 | Error | Certificate request failed |
| 3001 | Error | Certificate request denied |
| 3002 | Error | Health check failed, rolled back |
| 3003 | Error | Rollback failed, site may be down |
| 3004 | Error | Configuration invalid |
| 3005 | Error | Pre-swap check failed (precheck or snapshot), no change made |
