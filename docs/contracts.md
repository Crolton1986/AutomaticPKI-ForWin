# Internal contracts

Components are built in parallel. These shapes are fixed; change them only with a matching update here.

## Data root
`Get-APKIRoot` → `$env:APKI_ROOT` or `%ProgramData%\AutomaticPKI`.
```
config.json            global settings
orders\<Id>.json       one order per file
snapshots\<Id>\<ts>.json  binding snapshots before a swap
logs\apki-<yyyyMMdd>.log
```

## Global config (`config.json`)
```json
{
  "RenewalDaysBefore": 30,
  "OldCertRetentionDays": 14,
  "DefaultProvider": "AdcsRpc",
  "DefaultProviderSettings": { "CAConfig": "ca01.corp.local\\Corp Issuing CA", "Template": "WebServer" },
  "Smtp": { "Enabled": false, "Server": "", "Port": 25, "UseSsl": true, "From": "", "To": [], "CredentialRef": null },
  "LogRetentionDays": 30
}
```
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
| Key | object | `Algorithm` (`RSA`/`ECDSA_P256`), `Length` (2048), `Exportable` (bool) |
| KeyMode | string | `OnHost` (default) or `Central` |
| CreateBinding | bool | create https binding if missing |
| HttpProbe | object | `Enabled`, `Path` (`/`), `ExpectStatusBelow` (500) |
| RenewalDaysBefore | int/null | overrides global |
| CurrentThumbprint, PreviousThumbprint | string | |
| PendingRequestId | string | CA request ID while `Pending` |
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
Issued certs land in `Cert:\LocalMachine\My` with private key.

## Health check result
Each check returns `[pscustomobject]@{ Check = 'TlsHandshake'; Target = 'www.contoso.com:443'; Passed = $true; Detail = '...' }`.

## Logging
`Write-APKILog -Message -Level Info|Warning|Error -EventId <int> -OrderId <string>`. Event Log source `AutomaticPKI`, log `Application`.

| ID | Level | Meaning |
|---|---|---|
| 1000 | Info | Renewal run completed |
| 1001 | Info | Certificate issued and bound |
| 1002 | Info | Request pending CA approval |
| 1003 | Info | HTTPS binding created |
| 1004 | Info | Old certificate removed |
| 2000 | Warning | Certificate expiring, renewal not succeeding |
| 2001 | Warning | Binding needs a hostname (discovery) |
| 2002 | Warning | Hostname does not resolve to this host |
| 3000 | Error | Certificate request failed |
| 3001 | Error | Certificate request denied |
| 3002 | Error | Health check failed, rolled back |
| 3003 | Error | Rollback failed, site may be down |
| 3004 | Error | Configuration invalid |
