# AutomaticPKI-ForWin

certbot-style automation for Windows: request web server certificates from Active Directory Certificate Services, bind them in IIS, verify the site still serves HTTPS, and renew them before they expire.

Status: early development. Not ready for production.

- Windows Server 2016+ / IIS 10, Windows PowerShell 5.1, no external dependencies
- ADCS enrollment over RPC/DCOM (`certreq`) or CES/CEP over HTTPS
- SNI and non-SNI bindings, hostname discovery from IIS with admin approval
- Post-swap TLS + HTTP health checks with automatic rollback
- Event Log and SMTP alerting
- Runs as a local scheduled task or pushed to a fleet from a management host over WinRM

Contributor rules are in [CLAUDE.md](CLAUDE.md); shared data shapes in [docs/contracts.md](docs/contracts.md).
