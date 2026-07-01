# BloodHound export

Requires `--bloodhound`. Produces `bloodhound_<domain>.zip` for BloodHound CE (Administration → File Ingest).

## Flags

| Flag | Description |
|------|-------------|
| `--bloodhound` | Export users, groups, computers, domains (JSON v5/v6) |
| `--all` | Also gpos, ous, containers; enables `--adcs` |
| `--acl` | Parse `nTSecurityDescriptor` into `Aces` on BloodHound objects |
| `--adcs` | AD CS objects from Configuration partition (included in `--all`) |

Example:

```sh
adwsdomaindump -u 'DOMAIN\user' -p 'pass' dc.example.com \
  --all --bloodhound --acl -o ./out
```

## ACL collection (`--acl`)

- Fetches security descriptors via **ADWS** only.
- Populates BloodHound `Aces`: `GenericAll`, `WriteDacl`, `ForceChangePassword`, `AddMember`, `GetChanges` / `GetChangesAll` (DCSync), etc.
- Requires read access to `nTSecurityDescriptor` on target objects.

Stdout includes per-file ACE counts and a summary, for example:

```
[*] Wrote BloodHound users: ./users.json (30 objects, 263 ACEs)
[+] Parsed ACLs: 139 objects with security descriptors, 0 without, 1059 BloodHound ACE edges
```

If ACE counts are **0**, check account rights or reinstall from current source.

## Zip contents (typical `--all --bloodhound --acl`)

| File | Description |
|------|-------------|
| `users.json`, `groups.json`, `computers.json`, `domains.json` | Core graph |
| `gpos.json`, `ous.json`, `containers.json` | With `--all` |
| `certtemplates.json`, `enterprisecas.json`, … | With `--adcs` / `--all` — see [[AD-CS-collection]] |

## vs SharpHound

BloodHound export covers **Active Directory data** reachable over ADWS: membership, delegation, RBCD, trusts, GPO links, DACLs, AD-stored PKI.

It does **not** collect sessions, local group membership, `AdminTo`, RDP/PSRemote, or other host-based edges.
