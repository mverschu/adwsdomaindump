# ADWSDomainDump
Active Directory information dumper via ADWS (Active Directory Web Services), fork of LDAPDomainDump (https://github.com/dirkjanm/ldapdomaindump/).

## Introduction
In an Active Directory domain, a lot of interesting information can be retrieved via ADWS by any authenticated user (or machine).
This makes ADWS an interesting protocol for gathering information in the recon phase of a pentest of an internal network.
A problem is that data from ADWS often is not available in an easy to read format.

## Install
Recommended install:

```sh
pipx install .
```

## Usage

```sh
adwsdomaindump -u 'corp.local\jsmith' -p 'password' -n 10.0.0.1 dc01.corp.local
[*] Connecting to ADWS host...
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

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


