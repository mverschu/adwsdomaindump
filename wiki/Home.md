# ADWSDomainDump Wiki

Documentation for [ADWSDomainDump](https://github.com/mverschu/adwsdomaindump) — Active Directory enumeration over **ADWS** (TCP 9389), not LDAP.

## Pages

- **[Output formats & flags](Output-formats-and-flags)** — HTML, JSON, grep, Markdown, `--all`, `--minimal`, `--resolve`
- **[BloodHound export](BloodHound-export)** — `--bloodhound`, `--acl`, zip ingest, ACL parsing
- **[AD CS collection](AD-CS-collection)** — `--adcs`, Configuration partition, limits vs SharpHound/Certipy
- **[Lab test data](Lab-test-data)** — local seed scripts for BloodHound labs (not in repo)

## How it works

All collection goes through **ADWS** (`ADWSConnection` on port 9389). The tool does not bind to LDAP (389/636) during a dump.

| | ADWSDomainDump | ldapdomaindump / SharpHound |
|--|----------------|----------------------------|
| Protocol | ADWS (9389) | LDAP (+ host collection for sessions) |
| Users, groups, computers, trusts | Yes | Yes |
| GPOs, OUs, containers | With `--all` | Yes |
| BloodHound DACL edges | `--bloodhound --all` | Yes |
| AD CS (directory objects) | `--bloodhound --adcs` or `--all` | Yes (+ registry/HTTP for some ESC) |
| Sessions / local admin / RDP | No | Yes |

Credentials: `DOMAIN\user`, `user@domain`, or `-` to prompt for a password.

Output directory: `-o /path/to/outdir` (default: current directory). Dump artifacts are gitignored — see `.gitignore`.
