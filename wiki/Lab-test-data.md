# Lab test data

Optional **local** seed scripts for BloodHound testing — not shipped in the repository. Keep them in a local `scripts/` directory (gitignored). **Not run automatically** by `adwsdomaindump`.

Both scripts use **LDAP** (`ldap3`) and Impacket `dacledit.py` to modify the lab domain. Collection remains ADWS-only.

## Prerequisites

- Domain admin (or sufficient rights to create users/groups/OUs and modify ACLs)
- Impacket examples on PATH (e.g. `/usr/share/doc/python3-impacket/examples/dacledit.py`)
- For AD CS seed: `openssl` for a self-signed CA cert blob

Edit `DC`, `DOMAIN`, and passwords at the top of each script before running.

## BloodHound ACL / path lab

```sh
python3 scripts/setup_bloodhound_testdata.py
```

Creates:

- `BH-Lab` OU tree, users, groups, computers
- Nested group chains, delegation, RBCD
- ACL edges (ForceChangePassword, GenericAll, DCSync, etc.)
- Broad-group ACL demo (Domain Users, Everyone, Authenticated Users, …)

Re-collect:

```sh
adwsdomaindump -u 'DOMAIN\Administrator' -p 'pass' dc -o ./out --all --bloodhound
```

## AD CS lab (directory objects)

```sh
python3 scripts/setup_adcs_bloodhound_testdata.py
```

Creates:

- `BH-ESC1-Demo` certificate template (ESC1-style flags)
- `BH-Lab-CA` enterprise CA object
- Domain Users enroll ACL on the template

Does **not** install the AD CS Windows feature. For a real CA, install on the DC:

```powershell
Install-WindowsFeature AD-Certificate -IncludeManagementTools
Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -CACommonName YOUR-CA -Force
```

Then re-run collection with `--all --bloodhound`.

## Cypher examples (BloodHound CE)

Broad-group ACL paths:

```cypher
MATCH p=(n:Group)-[:GenericAll|ForceChangePassword|AddMember|GetChanges|GetChangesAll]->(:Base)
WHERE n.objectid ENDS WITH "-513"
   OR n.objectid ENDS WITH "-515"
   OR n.objectid ENDS WITH "-S-1-5-11"
RETURN p LIMIT 25
```

AD CS nodes:

```cypher
MATCH (t:CertTemplate)-[:PublishedTo]->(ca:EnterpriseCA) RETURN t.name, ca.name
```
