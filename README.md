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
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

Use `--force` to skip the ADWS port connectivity check.

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







