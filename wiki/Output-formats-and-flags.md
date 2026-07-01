# Output formats & flags

## Collection flags

These change **what is queried from AD**, not just the file format.

| Flag | Description |
|------|-------------|
| *(default)* | Users, groups, computers, domain policy, and trusts |
| `--all` | GPOs, OUs, containers; extended attributes; enables BloodHound `--adcs` |
| `--minimal` | Smaller attribute set (overridden by `--all`) |
| `--resolve` | Resolve computer DNS to IPv4 (extra DNS traffic) |
| `--force` | Skip ADWS port 9389 connectivity check |

Disable default outputs: `--no-html`, `--no-json`, `--no-grep`. Enable Markdown: `--markdown`. Greppable delimiter: `-d`.

## Output options

| Option | Default | Output | Can do | Cannot do |
|--------|---------|--------|--------|-----------|
| **HTML** | on | `domain_*.html`, grouped views | Human-readable tables | No ACL/path edges |
| **JSON** | on | `domain_*.json` | Scripting, raw attributes | No BloodHound `Aces` (use `--bloodhound`) |
| **Greppable** | on | `domain_*.grep` | `grep` / `cut` pipelines | No binary / nested fields |
| **Markdown** | off | `domain_*.md` | Docs / notes | Same limits as HTML |
| **Grouped JSON** | off | `domain_users_by_group.json`, etc. | Nested membership views | Not BloodHound format |
| **BloodHound** | off | `bloodhound_<domain>.zip` | BloodHound CE import | AD data only — no sessions |

## Standard output files

| Basename | Contents | Requires |
|----------|----------|----------|
| `domain_users` | User accounts | — |
| `domain_groups` | Groups | — |
| `domain_computers` | Computer accounts | — |
| `domain_policy` | Password policy, functional level | — |
| `domain_trusts` | Domain trusts | — |
| `domain_gpos` | GPOs | `--all` |
| `domain_ous` | OUs | `--all` |
| `domain_containers` | Containers | `--all` |
| `domain_users_by_group` | Users by group | HTML / MD / grouped JSON |
| `domain_computers_by_os` | Computers by OS | HTML |
| `bloodhound_<domain>.zip` | BloodHound CE archive | `--bloodhound` |

BloodHound-specific files inside the zip are documented on [[BloodHound-export]] and [[AD-CS-collection]].
