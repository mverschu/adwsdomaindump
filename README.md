# ADWSDomainDump
Active Directory information dumper via ADWS (Active Directory Web Services)

## Introduction
In an Active Directory domain, a lot of interesting information can be retrieved via ADWS by any authenticated user (or machine).
This makes ADWS an interesting protocol for gathering information in the recon phase of a pentest of an internal network.
A problem is that data from ADWS often is not available in an easy to read format.

adwsdomaindump is a tool which aims to solve this problem, by collecting and parsing information available via ADWS and outputting it in a human readable HTML format, as well as machine readable json and csv/tsv/greppable files.

The tool was designed with the following goals in mind:
- Easy overview of all users/groups/computers/policies in the domain
- Authentication via username and password, or NTLM hashes
- Uses ADWS (port 9389) instead of LDAP for communication

The tool outputs several files containing an overview of objects in the domain:
- *domain_groups*: List of groups in the domain
- *domain_users*: List of users in the domain
- *domain_computers*: List of computer accounts in the domain
- *domain_policy*: Domain policy such as password requirements and lockout policy
- *domain_trusts*: Incoming and outgoing domain trusts, and their properties

As well as two grouped files:
- *domain_users_by_group*: Domain users per group they are member of
- *domain_computers_by_os*: Domain computers sorted by Operating System

## Dependencies and installation
Requires [impacket](https://github.com/fortra/impacket) >= 0.11.0, [pycryptodomex](https://github.com/Legrandin/pycryptodome), and [dnspython](https://github.com/rthalley/dnspython). adwsdomaindump requires Python 3.6 or greater.

Dependencies can be installed manually with `pip install impacket pycryptodomex dnspython`, but should in most cases be handled by pip when you install the main package.

The adwsdomaindump package can be installed with:
- `pip install .` from the source directory
- `pipx install .` for isolated installation
- Or install from PyPI (when published): `pip install adwsdomaindump`

## Usage
There are 3 ways to use the tool:
- With just the source, run `python -m adwsdomaindump`
- After installing, by running `python -m adwsdomaindump`
- After installing, by running `adwsdomaindump`

Help can be obtained with the -h switch:
```
usage: adwsdomaindump [-h] [-u USERNAME] [-p PASSWORD] [-at {NTLM}]
                      [-o DIRECTORY] [--no-html] [--no-json] [--no-grep]
                      [--grouped-json] [-d DELIMITER] [-r] [-n DNS_SERVER]
                      [-m]
                      HOSTNAME

Domain information dumper via ADWS. Dumps users/computers/groups and
OS/membership information to HTML/JSON/greppable output.

Required options:
  HOSTNAME              Hostname/ip of domain controller to connect to via ADWS (port 9389)

Main options:
  -h, --help            show this help message and exit
  -u USERNAME, --user USERNAME
                        DOMAIN\username or user@domain.com for authentication
  -p PASSWORD, --password PASSWORD
                        Password or LM:NTLM hash, will prompt if not specified
  -at {NTLM}, --authtype {NTLM}
                        Authentication type (NTLM only for ADWS, default: NTLM)

Output options:
  -o DIRECTORY, --outdir DIRECTORY
                        Directory in which the dump will be saved (default:
                        current)
  --no-html             Disable HTML output
  --no-json             Disable JSON output
  --no-grep             Disable Greppable output
  --grouped-json        Also write json files for grouped files (default:
                        disabled)
  -d DELIMITER, --delimiter DELIMITER
                        Field delimiter for greppable output (default: tab)

Misc options:
  -r, --resolve         Resolve computer hostnames (might take a while and
                        cause high traffic on large networks)
  -n DNS_SERVER, --dns-server DNS_SERVER
                        Use custom DNS resolver instead of system DNS (try a
                        domain controller IP)
  -m, --minimal         Only query minimal set of attributes to limit memmory
                        usage
```

## Options
### Authentication
ADWS uses NTLM authentication. Provide credentials using DOMAIN\\username or user@domain.com format.

### Output formats
By default the tool outputs all files in HTML, JSON and tab delimited output (greppable). There are also two grouped files (users_by_group and computers_by_os) for convenience. These do not have a greppable output. JSON output for grouped files is disabled by default since it creates very large files without any data that isn't present in the other files already.

### DNS resolving
An important option is the *-r* option, which decides if a computers DNSHostName attribute should be resolved to an IPv4 address. 
While this can be very useful, the DNSHostName attribute is not automatically updated. When the AD Domain uses subdomains for computer hostnames, the DNSHostName will often be incorrect and will not resolve. Also keep in mind that resolving every hostname in the domain might cause a high load on the domain controller.

### Minimizing network and memory usage
By default adwsdomaindump will try to dump every single attribute it can read to disk in the .json files. In large networks, this uses a lot of memory (since group relationships are currently calculated in memory before being written to disk). To dump only the minimal required attributes (the ones shown by default in the .html and .grep files), use the `--minimal` switch.

## Visualizing groups with BloodHound
ADWSDomainDump includes a utility that can be used to convert adwsdomaindumps `.json` files to CSV files suitable for BloodHound. The utility is called `adwsd2bloodhound` and is added to your path upon installation. Alternatively you can run it with `python -m adwsdomaindump.convert` or with `python adwsdomaindump/convert.py` if you are running it from the source.
The conversion tool will take the users/groups/computers/trusts `.json` file and convert those to `group_membership.csv` and `trust.csv` which you can add to BloodHound. *Note that these files are only compatible with **BloodHound 1.x** which is quite old. There are no plans to support the latest version as the [BloodHound.py project](https://github.com/fox-it/BloodHound.py) was made for this.*

## Visualizing dump with a pretty output like enum4linux
ADWSDomainDump includes a utility that can be used to output adwsdomaindumps `.json` files to an enum4linux like output. The utility is called `adwsd2pretty` and is added to your path upon installation. Alternatively you can run it with `python -m adwsdomaindump.pretty` or with `python adwsdomaindump/pretty.py` if you are running it from the source.

## Credits

This project is a fork/adaptation of [ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump) by Dirk-jan Mollema, converted to use ADWS instead of LDAP.

Original work: Copyright (c) 2017 Dirk-jan Mollema

## License
MIT
