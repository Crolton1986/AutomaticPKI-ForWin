# AutomaticPKI-ForWin

PowerShell module that issues web certs from ADCS (certreq RPC/DCOM, CES/CEP), binds them in IIS 10, health-checks, rolls back on failure, renews on a schedule. Plan of record: see `docs/contracts.md` for shared data shapes.

## Hard rules
- Must run on **Windows PowerShell 5.1** (Server 2016+). Also load on pwsh 7 for tests. Forbidden: ternary `?:`, `??`, `?.`, `&&`/`||` pipeline chains, `ForEach-Object -Parallel`, `ConvertFrom-Json -AsHashtable`, `Get-Content -AsByteStream`, `using namespace` after code, `[ordered]` casts of PSCustomObject, `-SkipCertificateCheck`. Use `-Encoding UTF8` explicitly.
- No external module dependencies at runtime. In-box only: PKI, IISAdministration/WebAdministration, ScheduledTasks, certreq/certutil, .NET Framework 4.x.
- `Set-StrictMode -Version 3.0` is on. Initialize variables; check property existence on JSON objects.
- One function per file. File name = function name. Public functions in `Public/`, everything else in `Private/<Area>/`. Prefix all functions with `APKI` noun (`Get-APKIOrder`).
- Log only via `Write-APKILog` with event IDs from `docs/contracts.md`. No `Write-Host`.
- Wrap every external call (certreq.exe, IIS cmdlets, `Get-Certificate`, `SslStream`, `Send-MailMessage`) in a small private function so tests can `Mock` it.
- State-changing functions support `-WhatIf` (`SupportsShouldProcess`).
- Never write secrets or private keys to disk unencrypted; PFX files get random passwords and are deleted after import.

## Tests
- Pester 5. Unit tests in `tests/Unit/<Area>/<Function>.Tests.ps1`, must pass on non-Windows pwsh with mocks (no real IIS/CA). Use `InModuleScope AutomaticPKI` for private functions, `$env:APKI_ROOT = $TestDrive`.
- Integration tests in `tests/Integration/`, tagged `Integration`, run on the GitHub `windows-2022` runner (IIS + standalone CA installed by CI).
- Run: `./tests/Invoke-Tests.ps1 -Suite Unit`. Lint: `Invoke-ScriptAnalyzer -Path src -Recurse -Settings ./PSScriptAnalyzerSettings.psd1`.
