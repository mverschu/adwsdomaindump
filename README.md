# ADWSDomainDump
Active Directory information dumper via ADWS (Active Directory Web Services).</br>
<img width="350" height="350" alt="image" src="https://github.com/user-attachments/assets/6d624141-005c-49a1-88ee-e6c431ff0b57" />

## Install
Recommended install:

```sh
pipx install git+https://github.com/mverschu/adwsdomaindump
# or
pipx install .
```

## Usage

```sh
adwsdomaindump -u 'corp.local\jsmith' -p 'password' -n 10.0.0.1 dc01.corp.local
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

Use `--force` to skip the ADWS port connectivity check.

## Collection

Everything is queried over **ADWS** (port 9389), not LDAP.

| Data | Default | With `--all` | BloodHound extras |
|------|---------|--------------|-------------------|
| Users, groups, computers | Yes | Yes | `--bloodhound` |
| Domain policy, trusts | Yes | Yes | `--bloodhound` |
| GPOs, OUs, containers | No | Yes | `--bloodhound --all` |
| DACL / object-control edges | No | No | `--bloodhound --acl` |
| AD CS (templates, enterprise CAs, …) | No | Yes* | `--bloodhound --all` or `--adcs` |

\* AD CS requires `--bloodhound`. `--all` enables `--adcs` automatically.

**Not collected** (ADWS / directory data only — unlike SharpHound): logon sessions, local group membership, `AdminTo`, RDP/PSRemote, CA registry flags (ESC6/11/16), or HTTP enrollment checks (ESC8).

## Output formats

| Format | Flag | Use for |
|--------|------|---------|
| **HTML** | default | Browse users, groups, computers, policy, trusts in a browser |
| **JSON** | default | Scripting and automation on raw AD attributes |
| **Greppable** | default | `grep` / `cut` pipelines (`-d` sets delimiter) |
| **Markdown** | `--markdown` | Notes or docs from the same data as HTML |
| **BloodHound** | `--bloodhound` | Import into BloodHound CE (`bloodhound_<domain>.zip`) |

Disable defaults with `--no-html`, `--no-json`, or `--no-grep`. Use `--all` for GPOs, OUs, containers, and AD CS (with `--bloodhound`). Add `--acl` for DACL edges in the BloodHound export.

BloodHound example (ACLs + AD CS, all via ADWS):

```sh
adwsdomaindump -u 'corp.local\Administrator' -p 'password' dc01.corp.local \
  --all --bloodhound --acl -o ./out
```

More detail (flags, file list, BloodHound/AD CS): **[wiki](https://github.com/mverschu/adwsdomaindump/wiki)**.

## Evasion

Currently tested against:

| EDR | Bypassed |
|-----|----------|
| Microsoft Defender for Endpoint | Yes |
| CrowdStrike Falcon | Yes |


## Credits

This project is a fork/adaptation of [ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump) by Dirk-jan Mollema, converted to use ADWS instead of LDAP.

Original work: Copyright (c) 2017 Dirk-jan Mollema

## License
MIT
