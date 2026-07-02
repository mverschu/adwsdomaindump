# AD CS collection

Enabled with `--adcs` or automatically with `--all` (requires `--bloodhound`).

## ADWS only

Collection uses **ADWS** (port 9389) against the **Configuration** naming context. No LDAP connection is opened during a dump.

Parsing and BloodHound CE JSON use [CertiHound](https://pypi.org/project/certihound/) behind an ADWS search adapter (`ADWSConnection.search()`).

## Objects collected (when present in AD)

| Object | Location (under `CN=Configuration,...`) | BloodHound file |
|--------|----------------------------------------|-----------------|
| Certificate templates | `CN=Certificate Templates,CN=Public Key Services,...` | `certtemplates.json` |
| Enterprise CAs | `CN=Enrollment Services,...` | `enterprisecas.json` |
| Root CAs | `CN=Certification Authorities,...` | `rootcas.json` |
| NTAuth store | `CN=NTAuthCertificates,...` | `ntauthstores.json` |
| AIA CAs | `CN=AIA,...` | `aiacas.json` |

## BloodHound edges (AD-visible)

- Template / CA ACLs (Enroll, ManageCA, …)
- `PublishedTo`, Enroll relationships
- ESC detection from directory attributes where supported: ESC1, ESC2, ESC4, ESC7, etc.

## Not available via ADWS alone

| Gap | Why |
|-----|-----|
| ESC6 / ESC11 / ESC16 | CA **registry** flags on the CA host |
| ESC8 (confirmed) | HTTP web enrollment / EPA checks on CA |
| Live issuance | CertSrv / enrollment API on host |
| Full production PKI without AD CS feature | No real `pKIEnrollmentService` until AD CS is installed |

## Example stdout

```
[*] AD CS collection enabled — PKI objects collected from Configuration partition via ADWS
[*] Wrote BloodHound certtemplates: ./certtemplates.json (1 objects)
[*] Wrote BloodHound enterprisecas: ./enterprisecas.json (1 objects)
[+] Collected AD CS via ADWS: 1 templates, 1 enterprise CAs, 0 root CAs, 0 NTAuth stores, 0 AIA CAs
[+] Wrote BloodHound archive: ./bloodhound_example.local.zip (9 files)
```

Upload the zip to BloodHound CE. Verify with Cypher, e.g. `MATCH (n:CertTemplate) RETURN n.name LIMIT 10`.
