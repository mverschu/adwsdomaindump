####################
#
# Copyright (c) 2017 Dirk-jan Mollema
# Copyright (c) 2024 mverschu (ADWS adaptation)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
####################
import sys, os, re, codecs, json, argparse, getpass, base64, socket
# import class and constants
from datetime import datetime, timedelta
from uuid import UUID
from urllib.parse import quote_plus
# ADWS imports instead of LDAP
from .adws_wrapper import ADWSServer, ADWSConnection, ADWSEntry, ADWSAttribute
from impacket.ldap.ldaptypes import LDAP_SID

# Compatibility exceptions for existing code
class LDAPKeyError(KeyError):
    pass

class LDAPAttributeError(AttributeError):
    pass

class LDAPCursorError(IndexError):
    pass

class LDAPInvalidDnError(ValueError):
    pass

# Compatibility classes for existing code
class attribute:
    class Attribute:
        def __init__(self, attr_def, entry, value):
            self.key = attr_def if isinstance(attr_def, str) else getattr(attr_def, 'name', 'unknown')
            self.value = value
            self.values = [value] if not isinstance(value, list) else value
            self.raw_values = self.values

class attrDef:
    class AttrDef:
        def __init__(self, name):
            self.name = name

# DN parsing utility (simplified)
class dn:
    @staticmethod
    def parse_dn(dn_string):
        """Simple DN parser - returns list of tuples like [('CN', 'value'), ...]"""
        result = []
        parts = dn_string.split(',')
        for part in parts:
            part = part.strip()
            if '=' in part:
                key, value = part.split('=', 1)
                result.append((key.strip(), value.strip()))
        return result

# dnspython, for resolving hostnames
import dns.resolver


# User account control flags
# From: https://blogs.technet.microsoft.com/askpfeplat/2014/01/15/understanding-the-useraccountcontrol-attribute-in-active-directory/
uac_flags = {'ACCOUNT_DISABLED':0x00000002,
             'ACCOUNT_LOCKED':0x00000010,
             'PASSWD_NOTREQD':0x00000020,
             'PASSWD_CANT_CHANGE': 0x00000040,
             'PASSWORD_STORE_CLEARTEXT': 0x00000080,
             'NORMAL_ACCOUNT': 0x00000200,
             'WORKSTATION_ACCOUNT':0x00001000,
             'SERVER_TRUST_ACCOUNT': 0x00002000,
             'DONT_EXPIRE_PASSWD': 0x00010000,
             'SMARTCARD_REQUIRED': 0x00040000,
             'TRUSTED_FOR_DELEGATION': 0x00080000,
             'NOT_DELEGATED': 0x00100000,
             'USE_DES_KEY_ONLY': 0x00200000,
             'DONT_REQ_PREAUTH': 0x00400000,
             'PASSWORD_EXPIRED': 0x00800000,
             'TRUSTED_TO_AUTH_FOR_DELEGATION': 0x01000000,
             'PARTIAL_SECRETS_ACCOUNT': 0x04000000
            }

# Password policy flags
pwd_flags = {'PASSWORD_COMPLEX':0x01,
             'PASSWORD_NO_ANON_CHANGE': 0x02,
             'PASSWORD_NO_CLEAR_CHANGE': 0x04,
             'LOCKOUT_ADMINS': 0x08,
             'PASSWORD_STORE_CLEARTEXT': 0x10,
             'REFUSE_PASSWORD_CHANGE': 0x20}

# Domain trust flags
# From: https://msdn.microsoft.com/en-us/library/cc223779.aspx
trust_flags = {'NON_TRANSITIVE':0x00000001,
               'UPLEVEL_ONLY':0x00000002,
               'QUARANTINED_DOMAIN':0x00000004,
               'FOREST_TRANSITIVE':0x00000008,
               'CROSS_ORGANIZATION':0x00000010,
               'WITHIN_FOREST':0x00000020,
               'TREAT_AS_EXTERNAL':0x00000040,
               'USES_RC4_ENCRYPTION':0x00000080,
               'CROSS_ORGANIZATION_NO_TGT_DELEGATION':0x00000200,
               'CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION':0x00000800,
               'PIM_TRUST':0x00000400}

# Domain trust direction
# From: https://msdn.microsoft.com/en-us/library/cc223768.aspx
trust_directions = {'INBOUND':0x01,
                    'OUTBOUND':0x02,
                    'BIDIRECTIONAL':0x03}
# Domain trust types
trust_type = {'DOWNLEVEL':0x01,
              'UPLEVEL':0x02,
              'MIT':0x03}

def get_full_build_number(hostname, domain, username, password, lm_hash='', nt_hash='', timeout=5):
    """
    Query the full OS build number (e.g. "14393.8246") from a remote Windows host
    via the Remote Registry protocol over SMB.

    Requires the RemoteRegistry service to be running on the target. Any
    authenticated domain user can read HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion
    without admin privileges (default ACL grants Authenticated Users read access).

    Returns a string like "14393.8246" on success, or None on failure.
    """
    try:
        from impacket.smbconnection import SMBConnection
        from impacket.dcerpc.v5 import transport, rrp
    except ImportError:
        return None

    smb = None
    dce = None
    try:
        smb = SMBConnection(hostname, hostname, sess_port=445, timeout=timeout)
        smb.login(username, password, domain, lmhash=lm_hash, nthash=nt_hash)

        rpc_transport = transport.SMBTransport(hostname, filename=r'\winreg', smb_connection=smb)
        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.bind(rrp.MSRPC_UUID_RRP)

        root_handle = rrp.hOpenLocalMachine(dce)['phKey']
        key_handle = rrp.hBaseRegOpenKey(dce, root_handle,
                                          r'SOFTWARE\Microsoft\Windows NT\CurrentVersion')['phkResult']

        _, build_str = rrp.hBaseRegQueryValue(dce, key_handle, 'CurrentBuildNumber')
        _, ubr = rrp.hBaseRegQueryValue(dce, key_handle, 'UBR')

        rrp.hBaseRegCloseKey(dce, key_handle)
        rrp.hBaseRegCloseKey(dce, root_handle)

        build_str = build_str.rstrip('\x00') if isinstance(build_str, str) else str(build_str)
        return '%s.%s' % (build_str, ubr)
    except Exception:
        return None
    finally:
        try:
            if dce:
                dce.disconnect()
        except Exception:
            pass
        try:
            if smb:
                smb.logoff()
        except Exception:
            pass


# Common attribute pretty translations
attr_translations = {'sAMAccountName':'SAM Name',
                     'cn':'CN',
                     'operatingSystem':'Operating System',
                     'operatingSystemServicePack':'Service Pack',
                     'operatingSystemVersion':'OS Version',
                     'operatingSystemBuildNumber':'OS Build',
                     'userAccountControl':'Flags',
                     'objectSid':'SID',
                     'memberOf':'Member of groups',
                     'primaryGroupId':'Primary group',
                     'dNSHostName':'DNS Hostname',
                     'whenCreated':'Created on',
                     'whenChanged':'Changed on',
                     'IPv4':'IPv4 Address',
                     'lockOutObservationWindow':'Lockout time window',
                     'lockoutDuration':'Lockout Duration',
                     'lockoutThreshold':'Lockout Threshold',
                     'maxPwdAge':'Max password age',
                     'minPwdAge':'Min password age',
                     'minPwdLength':'Min password length',
                     'pwdHistoryLength':'Password history length',
                     'pwdProperties':'Password properties',
                     'msDS-MachineAccountQuota':'Machine Account Quota',
                     'flatName':'NETBIOS Domain name'}

MINIMAL_COMPUTERATTRIBUTES = ['cn', 'sAMAccountName', 'dNSHostName', 'operatingSystem', 'operatingSystemServicePack', 'operatingSystemVersion', 'lastLogon', 'lastLogonTimestamp', 'userAccountControl', 'whenCreated', 'objectSid', 'primaryGroupId', 'description', 'objectClass', 'msDS-AllowedToDelegateTo']
MINIMAL_USERATTRIBUTES = ['cn', 'name', 'sAMAccountName', 'memberOf', 'primaryGroupId', 'whenCreated', 'whenChanged', 'lastLogon', 'userAccountControl', 'pwdLastSet', 'objectSid', 'description', 'servicePrincipalName', 'objectClass']
MINIMAL_GROUPATTRIBUTES = ['cn', 'name', 'sAMAccountName', 'memberOf', 'description', 'whenCreated', 'whenChanged', 'objectSid', 'distinguishedName', 'objectClass']

#Class containing the default config
class domainDumpConfig():
    def __init__(self):
        #Base path
        self.basepath = '.'

        #Output files basenames
        self.groupsfile = 'domain_groups' #Groups
        self.usersfile = 'domain_users' #User accounts
        self.computersfile = 'domain_computers' #Computer accounts
        self.policyfile = 'domain_policy' #General domain attributes
        self.trustsfile = 'domain_trusts' #Domain trusts attributes
        self.gposfile = 'domain_gpos'
        self.ousfile = 'domain_ous'
        self.containersfile = 'domain_containers'

        #Combined files basenames
        self.users_by_group = 'domain_users_by_group' #Users sorted by group
        self.computers_by_os = 'domain_computers_by_os' #Computers sorted by OS

        #Output formats
        self.outputhtml = True
        self.outputjson = True
        self.outputgrep = True
        self.outputmarkdown = False
        self.outputbloodhound = False
        self.collect_all = False
        self.collect_acl = False
        self.collect_adcs = False
        self.collect_adcs = False

        #Output json for groups
        self.groupedjson = False

        #Default field delimiter for greppable format is a tab
        self.grepsplitchar = '\t'

        #Other settings
        self.lookuphostnames = False #Look up hostnames of computers to get their IP address
        self.dnsserver = '' #Addres of the DNS server to use, if not specified default DNS will be used
        self.minimal = False #Only query minimal list of attributes
        self.full_build = False #Enrich computers with full OS build (e.g. 14393.8246) via remote registry

#Domaindumper main class
class domainDumper():
    def __init__(self, server, connection, config, root=None):
        self.server = server
        self.connection = connection
        self.config = config
        #Unless the root is specified we get it from the server
        if root is None:
            self.root = self.getRoot()
        else:
            self.root = root
        self.users = None #Domain users
        self.groups = None #Domain groups
        self.computers = None #Domain computers
        self.policy = None #Domain policy
        self.groups_dnmap = None #CN map for group IDs to CN
        self.groups_dict = None #Dictionary of groups by CN
        self.trusts = None #Domain trusts
        self.gpos = None
        self.ous = None
        self.containers = None
        self._child_object_cache = {}

    def _query_attributes(self, minimal_attributes, kind='user'):
        if self.config.minimal:
            attrs = minimal_attributes
        elif self.config.collect_all or getattr(self.config, 'collect_acl', False) or getattr(self.config, 'outputbloodhound', False):
            from .bloodhound_export import (
                extended_user_attributes, extended_computer_attributes, extended_group_attributes,
            )
            if kind == 'computer':
                attrs = extended_computer_attributes()
            elif kind == 'group':
                attrs = extended_group_attributes()
            else:
                attrs = extended_user_attributes()
        else:
            from .adws_wrapper import DEFAULT_ATTRIBUTES
            attrs = list(DEFAULT_ATTRIBUTES)
        if getattr(self.config, 'collect_acl', False):
            from .bloodhound_export import with_acl_attributes
            attrs = with_acl_attributes(attrs)
        return attrs

    def _paged_search(self, search_base, search_filter, attributes):
        self.connection.extend.standard.paged_search(
            search_base, search_filter, attributes=attributes, paged_size=500, generator=False
        )
        return self.connection.entries

    #Get the server root from the default naming context
    def getRoot(self):
        try:
            return self.server.info.other['defaultNamingContext'][0]
        except (KeyError, IndexError):
            # Fallback: construct from domain
            domain = self.server.domain
            return f"DC={',DC='.join(domain.split('.'))}"

    #Query the groups of the current user
    def getCurrentUserGroups(self, username, domainsid=None):
        self.connection.search(self.root, '(&(objectCategory=person)(objectClass=user)(sAMAccountName=%s))' % username, attributes=['cn', 'memberOf', 'primaryGroupId'])
        try:
            entry = self.connection.entries[0]
            member_of = entry['memberOf'].values if 'memberOf' in entry else []
            groups = member_of if isinstance(member_of, list) else [member_of]
            if domainsid is not None and 'primaryGroupId' in entry:
                groups.append(self.getGroupDNfromID(domainsid, entry['primaryGroupId'].value))
            return groups
        except (LDAPKeyError, KeyError, IndexError):
            #No groups, probably just member of the primary group
            try:
                if domainsid is not None and len(self.connection.entries) > 0:
                    entry = self.connection.entries[0]
                    if 'primaryGroupId' in entry:
                        primarygroup = self.getGroupDNfromID(domainsid, entry['primaryGroupId'].value)
                        return [primarygroup]
            except (KeyError, IndexError):
                pass
            return []

    #Check if the user is part of the Domain Admins or Enterprise Admins group, or any of their subgroups
    def isDomainAdmin(self, username):
        domainsid = self.getRootSid()
        groups = self.getCurrentUserGroups(username, domainsid)
        #Get DA and EA group DNs
        dagroupdn = self.getDAGroupDN(domainsid)
        eagroupdn = self.getEAGroupDN(domainsid)
        #First, simple checks
        for group in groups:
            if 'CN=Administrators' in group or 'CN=Domain Admins' in group or dagroupdn == group:
                return True
            #Also for enterprise admins if applicable
            if 'CN=Enterprise Admins' in group or (eagroupdn is not False and eagroupdn == group):
                return True
        #Now, just do a recursive check in both groups and their subgroups using LDAP_MATCHING_RULE_IN_CHAIN
        self.connection.search(self.root, '(&(objectCategory=person)(objectClass=user)(sAMAccountName=%s)(memberOf:1.2.840.113556.1.4.1941:=%s))' % (username, dagroupdn), attributes=['cn', 'sAMAccountName'])
        if len(self.connection.entries) > 0:
            return True
        self.connection.search(self.root, '(&(objectCategory=person)(objectClass=user)(sAMAccountName=%s)(memberOf:1.2.840.113556.1.4.1941:=%s))' % (username, eagroupdn), attributes=['cn', 'sAMAccountName'])
        if len(self.connection.entries) > 0:
            return True
        #At last, check the users primary group ID
        return False

    #Get all users
    def getAllUsers(self):
        attrs = self._query_attributes(MINIMAL_USERATTRIBUTES, 'user')
        return self._paged_search(self.root, '(&(objectCategory=person)(objectClass=user))', attrs)

    #Get all computers in the domain
    def getAllComputers(self):
        attrs = self._query_attributes(MINIMAL_COMPUTERATTRIBUTES, 'computer')
        return self._paged_search(self.root, '(&(objectClass=computer)(objectClass=user))', attrs)

    #Get all user SPNs
    def getAllUserSpns(self):
        attrs = self._query_attributes(MINIMAL_USERATTRIBUTES, 'user')
        return self._paged_search(self.root, '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))', attrs)

    #Get all defined groups
    def getAllGroups(self):
        attrs = self._query_attributes(MINIMAL_GROUPATTRIBUTES, 'group')
        return self._paged_search(self.root, '(objectClass=group)', attrs)

    #Get the domain policies (such as lockout policy)
    def getDomainPolicy(self):
        if self.config.collect_all:
            from .bloodhound_export import domain_policy_attributes
            attrs = domain_policy_attributes()
        else:
            from .adws_wrapper import DOMAIN_POLICY_ATTRIBUTES
            attrs = list(DOMAIN_POLICY_ATTRIBUTES)
        if getattr(self.config, 'collect_acl', False):
            from .bloodhound_export import with_acl_attributes
            attrs = with_acl_attributes(attrs)
        return self._paged_search(self.root, '(objectClass=domain)', attrs)

    #Get domain trusts
    def getTrusts(self):
        from .adws_wrapper import TRUST_OBJECT_ATTRIBUTES
        return self._paged_search(self.root, '(objectClass=trustedDomain)', list(TRUST_OBJECT_ATTRIBUTES))

    #Get all defined security groups
    #Syntax from:
    #https://ldapwiki.willeke.com/wiki/Active%20Directory%20Group%20Related%20Searches
    def getAllSecurityGroups(self):
        attrs = self._query_attributes(['cn'])
        return self._paged_search(self.root, '(groupType:1.2.840.113556.1.4.803:=2147483648)', attrs)

    def getAllGPOs(self):
        from .bloodhound_export import gpo_attributes, with_acl_attributes
        attrs = gpo_attributes()
        if getattr(self.config, 'collect_acl', False):
            attrs = with_acl_attributes(attrs)
        return self._paged_search(self.root, '(objectCategory=groupPolicyContainer)', attrs)

    def getAllOUs(self):
        from .bloodhound_export import ou_attributes, with_acl_attributes
        attrs = ou_attributes()
        if getattr(self.config, 'collect_acl', False):
            attrs = with_acl_attributes(attrs)
        return self._paged_search(self.root, '(objectCategory=organizationalUnit)', attrs)

    def getAllContainers(self):
        from .bloodhound_export import container_attributes, with_acl_attributes
        attrs = container_attributes()
        if getattr(self.config, 'collect_acl', False):
            attrs = with_acl_attributes(attrs)
        return self._paged_search(self.root, '(objectClass=container)', attrs)

    def getChildObjects(self, dn):
        dn_key = dn.upper()
        if dn_key in self._child_object_cache:
            return self._child_object_cache[dn_key]
        child_filter = '(|(objectClass=container)(objectClass=organizationalUnit)(objectClass=group)(objectClass=computer)(&(objectCategory=person)(objectClass=user)))'
        attrs = ['distinguishedName', 'objectClass', 'objectSid', 'objectGUID', 'sAMAccountName', 'name']
        entries = self._paged_search(dn, child_filter, attrs)
        from .bloodhound_export import is_direct_child
        filtered = []
        for entry in entries:
            child_dn = None
            try:
                child_dn = entry['distinguishedName'].value
            except (KeyError, AttributeError):
                continue
            if child_dn and is_direct_child(dn, child_dn):
                filtered.append(entry)
        self._child_object_cache[dn_key] = filtered
        return filtered

    #Get the SID of the root object
    def getRootSid(self):
        if self.policy:
            try:
                entry = self.policy[0]
                sid_attr = entry['objectSid'] if 'objectSid' in entry else None
                if sid_attr:
                    sid = sid_attr.value
                    if isinstance(sid, bytes):
                        from impacket.ldap.ldaptypes import LDAP_SID
                        return LDAP_SID(sid).formatCanonical()
                    if isinstance(sid, str) and sid.startswith('S-'):
                        return sid
            except (LDAPAttributeError, LDAPCursorError, IndexError, KeyError, ValueError):
                pass
        self.connection.extend.standard.paged_search(
            self.root, '(objectClass=domain)', attributes=['distinguishedName', 'objectSid'],
            paged_size=500, generator=False
        )
        try:
            entry = self.connection.entries[0]
            sid_attr = entry['objectSid'] if 'objectSid' in entry else None
            if sid_attr:
                sid = sid_attr.value
                if isinstance(sid, bytes):
                    from impacket.ldap.ldaptypes import LDAP_SID
                    sid = LDAP_SID(sid).formatCanonical()
                return sid
        except (LDAPAttributeError, LDAPCursorError, IndexError, KeyError):
            return False
        return False

    #Get group members recursively using LDAP_MATCHING_RULE_IN_CHAIN (1.2.840.113556.1.4.1941)
    def getRecursiveGroupmembers(self, groupdn):
        self.connection.extend.standard.paged_search(self.root, '(&(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=%s))' % groupdn, attributes=MINIMAL_USERATTRIBUTES, paged_size=500, generator=False)
        return self.connection.entries

    #Resolve group ID to DN
    def getGroupDNfromID(self, domainsid, gid):
        self.connection.search(self.root, '(objectSid=%s-%d)' % (domainsid, gid), attributes=['distinguishedName'])
        try:
            entry = self.connection.entries[0]
            dn_attr = entry['distinguishedName'] if 'distinguishedName' in entry else None
            if dn_attr:
                return dn_attr.value
        except (IndexError, KeyError):
            pass
        return None

    #Get Domain Admins group DN
    def getDAGroupDN(self, domainsid):
        return self.getGroupDNfromID(domainsid, 512)

    #Get Enterprise Admins group DN
    def getEAGroupDN(self, domainsid):
        try:
            return self.getGroupDNfromID(domainsid, 519)
        except (LDAPAttributeError, LDAPCursorError, IndexError):
            #This does not exist, could be in a parent domain
            return False


    #Lookup all computer DNS names to get their IP
    def lookupComputerDnsNames(self):
        dnsresolver = dns.resolver.Resolver()
        dnsresolver.lifetime = 2
        if self.config.dnsserver != '':
            dnsresolver.nameservers = [self.config.dnsserver]
        for computer in self.computers:
            try:
                dns_hostname = computer['dNSHostName'].value if 'dNSHostName' in computer else None
                if not dns_hostname:
                    ip = 'error.NOHOSTNAME'
                else:
                    answers = dnsresolver.query(dns_hostname, 'A')
                    ip = str(answers.response.answer[0][0])
            except dns.resolver.NXDOMAIN:
                ip = 'error.NXDOMAIN'
            except dns.resolver.Timeout:
                ip = 'error.TIMEOUT'
            except (LDAPAttributeError, LDAPCursorError, KeyError):
                ip = 'error.NOHOSTNAME'
            #Construct a custom attribute as workaround
            ipatt = ADWSAttribute('IPv4', ip)
            #Add the attribute to the entry's dictionary
            computer._attributes['IPv4'] = ipatt

    def enrichComputerBuildNumbers(self):
        """
        For each computer, attempt a remote-registry lookup to retrieve the full
        OS build number (CurrentBuildNumber.UBR, e.g. "14393.8246") and inject it
        as the synthetic 'operatingSystemBuildNumber' attribute.

        Requires the RemoteRegistry service running on each target. Any authenticated
        domain user can read HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion
        without admin privileges.
        """
        domain = self.server.domain
        username = self.connection.user or ''
        password = self.connection.password or ''
        lm_hash = ''
        nt_hash = ''

        if '\\' in username:
            domain, username = username.split('\\', 1)
        elif '@' in username:
            username, domain = username.rsplit('@', 1)

        if password and ':' in password and len(password.split(':')) == 2:
            lm_hash, nt_hash = password.split(':', 1)
            password = ''

        total = len(self.computers)
        success = 0
        log_info('Fetching full OS build numbers via remote registry (%d computers)' % total)
        for computer in self.computers:
            try:
                hostname = computer['dNSHostName'].value if 'dNSHostName' in computer else None
                if not hostname:
                    cn = computer['cn'].value if 'cn' in computer else None
                    hostname = '%s.%s' % (cn, self.server.domain) if cn else None
                if not hostname:
                    continue

                full_build = get_full_build_number(hostname, domain, username, password,
                                                   lm_hash=lm_hash, nt_hash=nt_hash)
                if full_build:
                    computer._attributes['operatingSystemBuildNumber'] = ADWSAttribute(
                        'operatingSystemBuildNumber', full_build)
                    success += 1
            except Exception:
                continue

        if success == 0 and total > 0:
            log_warn('Full build numbers: 0/%d — check RemoteRegistry service and SMB reachability on targets' % total)
        else:
            log_info('Full build numbers retrieved for %d/%d computers' % (success, total))

    #Create a dictionary of all operating systems with the computer accounts that are associated
    def sortComputersByOS(self, items):
        osdict = {}
        for computer in items:
            try:
                cos = computer['operatingSystem'].value if 'operatingSystem' in computer else None
                cos = cos or 'Unknown'
            except (LDAPAttributeError, LDAPCursorError, KeyError):
                cos = 'Unknown'
            try:
                osdict[cos].append(computer)
            except KeyError:
                #New OS
                osdict[cos] = [computer]
        return osdict

    #Map all groups on their ID (taken from their SID) to CNs
    #This is used for getting the primary group of a user
    def mapGroupsIdsToDns(self):
        dnmap = {}
        for group in self.groups:
            try:
                sid = group['objectSid'].value
                if isinstance(sid, bytes):
                    from impacket.ldap.ldaptypes import LDAP_SID
                    sid = LDAP_SID(sid).formatCanonical()
                gid = int(sid.split('-')[-1])
                dn = group['distinguishedName'].value if 'distinguishedName' in group else None
                if dn:
                    dnmap[gid] = dn if isinstance(dn, str) else dn[0] if isinstance(dn, list) else str(dn)
            except (KeyError, ValueError, IndexError, AttributeError):
                continue
        self.groups_dnmap = dnmap
        return dnmap

    #Create a dictionary where a groups CN returns the full object
    def createGroupsDictByCn(self):
        gdict = {}
        for grp in self.groups:
            try:
                cn = grp['cn'].value if 'cn' in grp else None
                if cn:
                    cn = cn if isinstance(cn, str) else cn[0] if isinstance(cn, list) else str(cn)
                    gdict[cn] = grp
            except (KeyError, AttributeError):
                continue
        self.groups_dict = gdict
        return gdict

    #Get CN from DN
    def getGroupCnFromDn(self, dnin):
        cn = self.unescapecn(dn.parse_dn(dnin)[0][1])
        return cn

    #Unescape special DN characters from a CN (only needed if it comes from a DN)
    def unescapecn(self, cn):
        for c in ' "#+,;<=>\\\00':
            cn = cn.replace('\\'+c, c)
        return cn

    #Sort users by group they belong to
    def sortUsersByGroup(self, items):
        groupsdict = {}
        #Make sure the group CN mapping already exists
        if self.groups_dnmap is None:
            self.mapGroupsIdsToDns()
        for user in items:
            try:
                member_of = user['memberOf'].values if 'memberOf' in user else []
                ugroups = [self.getGroupCnFromDn(group) for group in member_of]
            #If the user is only in the default group, its memberOf property wont exist
            except (LDAPAttributeError, LDAPCursorError, KeyError):
                ugroups = []
            #Add the user default group
            try:
                primary_group_id = user['primaryGroupId'].value if 'primaryGroupId' in user else None
                if primary_group_id and primary_group_id in self.groups_dnmap:
                    ugroups.append(self.getGroupCnFromDn(self.groups_dnmap[primary_group_id]))
            # Sometimes we can't query this group or it doesn't exist
            except (KeyError, AttributeError):
                pass
            for group in ugroups:
                try:
                    groupsdict[group].append(user)
                except KeyError:
                    #Group is not yet in dict
                    groupsdict[group] = [user]

        #Append any groups that are members of groups
        for group in self.groups:
            try:
                member_of = group['memberOf'].values if 'memberOf' in group else []
                for parentgroup in member_of:
                    try:
                        parent_cn = self.getGroupCnFromDn(parentgroup)
                        groupsdict[parent_cn].append(group)
                    except KeyError:
                        #Group is not yet in dict
                        groupsdict[parent_cn] = [group]
            #Without subgroups this attribute does not exist
            except (LDAPAttributeError, LDAPCursorError, KeyError):
                pass

        return groupsdict

    #Main function
    def domainDump(self):
        self.users = self.getAllUsers()
        self.computers = self.getAllComputers()
        self.groups = self.getAllGroups()
        if self.config.lookuphostnames:
            self.lookupComputerDnsNames()
        if getattr(self.config, 'full_build', False):
            self.enrichComputerBuildNumbers()
        self.policy = self.getDomainPolicy()
        self.trusts = self.getTrusts()
        if self.config.collect_all:
            log_info('Collecting extended data (GPOs, OUs, containers, additional attributes)')
            self.gpos = self.getAllGPOs()
            self.ous = self.getAllOUs()
            self.containers = self.getAllContainers()
        if getattr(self.config, 'collect_acl', False):
            targets = []
            if self.config.outputbloodhound:
                targets.append('BloodHound export')
            if self.config.outputmarkdown:
                targets.append('Markdown')
            log_info(
                'ACL parsing enabled — nTSecurityDescriptor collected via ADWS for %s'
                % (' and '.join(targets) if targets else 'export')
            )
        if getattr(self.config, 'collect_adcs', False):
            log_info('AD CS collection enabled — PKI objects collected from Configuration partition via ADWS')
        rw = reportWriter(self.config)
        rw.generateUsersReport(self)
        rw.generateGroupsReport(self)
        rw.generateComputersReport(self)
        rw.generatePolicyReport(self)
        rw.generateTrustsReport(self)
        if self.config.collect_all:
            rw.generateGposReport(self)
            rw.generateOusReport(self)
            rw.generateContainersReport(self)
        rw.generateComputersByOsReport(self)
        rw.generateUsersByGroupReport(self)
        if self.config.outputbloodhound:
            from .bloodhound_export import BloodHoundExporter
            log_info('Writing BloodHound JSON export')
            BloodHoundExporter(self.config).export(self)
            log_success('BloodHound export finished')
        if getattr(self.config, 'collect_acl', False) and self.config.outputmarkdown:
            from .acl_markdown_export import AclMarkdownExporter
            log_info('Writing ACL Markdown export')
            AclMarkdownExporter(self.config).export(self)

class reportWriter():
    def __init__(self, config):
        self.config = config
        self.dd = None
        if self.config.lookuphostnames:
            self.computerattributes = ['cn', 'sAMAccountName', 'dNSHostName', 'IPv4', 'operatingSystem', 'operatingSystemServicePack', 'operatingSystemVersion', 'lastLogon', 'userAccountControl', 'whenCreated', 'objectSid', 'description']
        else:
            self.computerattributes = ['cn', 'sAMAccountName', 'dNSHostName', 'operatingSystem', 'operatingSystemServicePack', 'operatingSystemVersion', 'lastLogon', 'userAccountControl', 'whenCreated', 'objectSid', 'description']
        if getattr(self.config, 'full_build', False):
            self.computerattributes.append('operatingSystemBuildNumber')
        self.userattributes = ['cn', 'name', 'sAMAccountName', 'memberOf', 'primaryGroupId', 'whenCreated', 'whenChanged', 'lastLogon', 'userAccountControl', 'pwdLastSet', 'objectSid', 'description', 'servicePrincipalName']
        #In grouped view, don't include the memberOf property to reduce output size
        self.userattributes_grouped = ['cn', 'name', 'sAMAccountName', 'whenCreated', 'whenChanged', 'lastLogon', 'userAccountControl', 'pwdLastSet', 'objectSid', 'description', 'servicePrincipalName']
        self.groupattributes = ['cn', 'sAMAccountName', 'memberOf', 'description', 'whenCreated', 'whenChanged', 'objectSid']
        self.policyattributes = ['distinguishedName', 'lockOutObservationWindow', 'lockoutDuration', 'lockoutThreshold', 'maxPwdAge', 'minPwdAge', 'minPwdLength', 'pwdHistoryLength', 'pwdProperties', 'msDS-Behavior-Version', 'gPLink']
        self.trustattributes = ['cn', 'flatName', 'securityIdentifier', 'trustAttributes', 'trustDirection', 'trustType']
        self.gpoattributes = ['cn', 'displayName', 'distinguishedName', 'gPCFileSysPath', 'description', 'whenCreated', 'objectGUID']
        self.ouattributes = ['cn', 'name', 'distinguishedName', 'gPLink', 'gPOptions', 'description', 'whenCreated', 'objectGUID']
        self.containerattributes = ['cn', 'name', 'distinguishedName', 'description', 'whenCreated', 'objectGUID']

    def _entry_attribute_names(self, entries):
        names = []
        seen = set()
        for entry in entries or []:
            attrs = entry._attributes if hasattr(entry, '_attributes') else {}
            for key in attrs:
                if key not in seen:
                    seen.add(key)
                    names.append(key)
        return sorted(names)

    def _report_attributes(self, entries, default_attrs):
        if self.config.collect_all and entries:
            dynamic = self._entry_attribute_names(entries)
            if dynamic:
                return dynamic
        return default_attrs

    #Escape HTML special chars
    def htmlescape(self, html):
        return (html.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("'", "&#39;").replace('"', "&quot;"))

    #Unescape special DN characters from a CN (only needed if it comes from a DN)
    def unescapecn(self, cn):
        for c in ' "#+,;<=>\\\00':
            cn = cn.replace('\\'+c, c)
        return cn

    #Convert password max age (in 100 nanoseconds), to days
    def nsToDays(self, length):
        # ldap3 >= 2.6 returns timedelta
        if isinstance(length, timedelta):
            return length.total_seconds() / 86400
        else:
            # Convert string to number if needed
            try:
                if isinstance(length, str):
                    length = int(length)
                return abs(length) * .0000001 / 86400
            except (ValueError, TypeError):
                return 0.0

    def nsToMinutes(self, length):
        # ldap3 >= 2.6 returns timedelta
        if isinstance(length, timedelta):
            return length.total_seconds() / 60
        else:
            # Convert string to number if needed
            try:
                if isinstance(length, str):
                    length = int(length)
                return abs(length) * .0000001 / 60
            except (ValueError, TypeError):
                return 0.0

    #Parse bitwise flags into a list
    def parseFlags(self, attr, flags_def):
        outflags = []
        if attr is None:
            return outflags
        # Handle both ADWSAttribute and legacy attribute objects
        if hasattr(attr, 'value'):
            attr_value = attr.value
        else:
            attr_value = attr
        if attr_value is None:
            return outflags
        try:
            flag_int = int(attr_value)
            for flag, val in flags_def.items():
                if flag_int & val:
                    outflags.append(flag)
        except (ValueError, TypeError):
            pass
        return outflags

    def formatSidValue(self, att_value, att_raw_values):
        try:
            sid_bytes = att_raw_values[0] if att_raw_values else att_value
            if isinstance(sid_bytes, bytes):
                return LDAP_SID(sid_bytes).formatCanonical()
            if isinstance(sid_bytes, str):
                if sid_bytes.startswith('S-'):
                    return sid_bytes
                try:
                    return LDAP_SID(base64.b64decode(sid_bytes)).formatCanonical()
                except Exception:
                    return sid_bytes
            return str(sid_bytes)
        except (IndexError, AttributeError, ValueError, TypeError):
            return self.formatString(att_value)

    def formatObjectGuidValue(self, att_value, att_raw_values):
        try:
            guid_bytes = att_raw_values[0] if att_raw_values else att_value
            if isinstance(guid_bytes, bytes):
                return str(UUID(bytes_le=guid_bytes)).upper()
            if isinstance(guid_bytes, str):
                if guid_bytes.startswith('{'):
                    return guid_bytes
                try:
                    return str(UUID(bytes_le=base64.b64decode(guid_bytes))).upper()
                except Exception:
                    return guid_bytes
            return str(guid_bytes)
        except (IndexError, AttributeError, ValueError, TypeError):
            return self.formatString(att_value)

    #Parse bitwise trust direction - only one flag applies here, 0x03 overlaps
    def parseSingleFlag(self, attr, flags_def):
        outflags = []
        if attr is None:
            return outflags
        # Handle both ADWSAttribute and legacy attribute objects
        if hasattr(attr, 'value'):
            attr_value = attr.value
        else:
            attr_value = attr
        if attr_value is None:
            return outflags
        try:
            flag_int = int(attr_value)
            for flag, val in flags_def.items():
                if flag_int == val:
                    outflags.append(flag)
        except (ValueError, TypeError):
            pass
        return outflags

    #Generate a HTML table from a list of entries, with the specified attributes as column
    def generateHtmlTable(self, listable, attributes, header='', firstTable=True, specialGroupsFormat=False):
        of = []
        #Only if this is the first table it is an actual table, the others are just bodies of the first table
        #This makes sure that multiple tables have their columns aligned to make it less messy
        if firstTable:
            of.append('<table>')
        #Table header
        if header != '':
            of.append('<thead><tr><td colspan="%d" id="cn_%s">%s</td></tr></thead>' % (len(attributes), self.formatId(header), header))
        of.append('<tbody><tr>')
        for hdr in attributes:
            try:
                #Print alias of this attribute if there is one
                of.append('<th>%s</th>' % self.htmlescape(attr_translations[hdr]))
            except KeyError:
                of.append('<th>%s</th>' % self.htmlescape(hdr))
        of.append('</tr>\n')
        for li in listable:
            #Whether we should format group objects separately
            object_class = li.get('objectClass')
            if object_class:
                oc_values = object_class.values if hasattr(object_class, 'values') else [object_class] if not isinstance(object_class, list) else object_class
                oc_lower = [str(oc).lower() for oc in oc_values]
            else:
                oc_lower = []
            
            if specialGroupsFormat and 'group' in oc_lower:
                #Give it an extra class and pass it to the function below to make sure the CN is a link
                liIsGroup = True
                of.append('<tr class="group">')
            else:
                liIsGroup = False
                of.append('<tr>')
            for att in attributes:
                try:
                    of.append('<td>%s</td>' % self.formatAttribute(li[att], liIsGroup))
                except (LDAPKeyError, LDAPCursorError, KeyError):
                    of.append('<td>&nbsp;</td>')
            of.append('</tr>\n')
        of.append('</tbody>\n')
        return ''.join(of)

    #Generate several HTML tables for grouped reports
    def generateGroupedHtmlTables(self, groups, attributes):
        first = True
        for groupname, members in groups.items():
            yield self.generateHtmlTable(members, attributes, groupname, first, specialGroupsFormat=True)
            if first:
                first = False

    #Escape characters that break markdown tables
    def mdescape(self, value):
        if value is None:
            return ''
        text = ''.join(c if c.isprintable() or c in ' \t' else '?' for c in str(value))
        return text.replace('|', '\\|').replace('\n', ' ').replace('\r', '')

    def _markdownColumnHeader(self, hdr):
        try:
            return attr_translations[hdr]
        except KeyError:
            return hdr

    #Generate a markdown table from a list of entries
    def generateMarkdownTable(self, listable, attributes, header='', header_level=2):
        lines = []
        if header:
            lines.append('%s %s\n' % ('#' * min(header_level, 6), header))
        headers = [self._markdownColumnHeader(h) for h in attributes]
        lines.append('| ' + ' | '.join(self.mdescape(h) for h in headers) + ' |')
        lines.append('| ' + ' | '.join('---' for _ in attributes) + ' |')
        for li in listable:
            row = []
            for att in attributes:
                try:
                    row.append(self.mdescape(self.formatGrepAttribute(li[att])))
                except (LDAPKeyError, LDAPCursorError, KeyError):
                    row.append('')
            lines.append('| ' + ' | '.join(row) + ' |')
        return '\n'.join(lines) + '\n'

    #Generate markdown sections for grouped reports
    def generateGroupedMarkdownSections(self, groups, attributes):
        for groupname, members in groups.items():
            yield self.generateMarkdownTable(members, attributes, groupname, header_level=2)

    #Write generated HTML to file
    def writeHtmlFile(self, rel_outfile, body, genfunc=None, genargs=None, closeTable=True):
        if not os.path.exists(self.config.basepath):
            os.makedirs(self.config.basepath)
        outfile = os.path.join(self.config.basepath, rel_outfile)
        with codecs.open(outfile, 'w', 'utf8') as of:
            of.write('<!DOCTYPE html>\n<html>\n<head><meta charset="UTF-8">')
            #Include the style
            try:
                with open(os.path.join(os.path.dirname(__file__), 'style.css'), 'r') as sf:
                    of.write('<style type="text/css">')
                    of.write(sf.read())
                    of.write('</style>')
            except IOError:
                log_warn('style.css not found in package directory, styling will be skipped')
            of.write('</head><body>')
            #If the generator is not specified, we should write the HTML blob directly
            if genfunc is None:
                of.write(body)
            else:
                for tpart in genfunc(*genargs):
                    of.write(tpart)
            #Does the body contain an open table?
            if closeTable:
                of.write('</table>')
            of.write('</body></html>')

    #Write generated JSON to file
    def writeJsonFile(self, rel_outfile, jsondata, genfunc=None, genargs=None):
        if not os.path.exists(self.config.basepath):
            os.makedirs(self.config.basepath)
        outfile = os.path.join(self.config.basepath, rel_outfile)
        with codecs.open(outfile, 'w', 'utf8') as of:
            #If the generator is not specified, we should write the JSON blob directly
            if genfunc is None:
                of.write(jsondata)
            else:
                for jpart in genfunc(*genargs):
                    of.write(jpart)

    #Write generated Greppable stuff to file
    def writeGrepFile(self, rel_outfile, body):
        if not os.path.exists(self.config.basepath):
            os.makedirs(self.config.basepath)
        outfile = os.path.join(self.config.basepath, rel_outfile)
        with codecs.open(outfile, 'w', 'utf8') as of:
            of.write(body)

    #Write generated Markdown to file
    def writeMarkdownFile(self, rel_outfile, body, genfunc=None, genargs=None, title=None):
        if not os.path.exists(self.config.basepath):
            os.makedirs(self.config.basepath)
        outfile = os.path.join(self.config.basepath, rel_outfile)
        with codecs.open(outfile, 'w', 'utf8') as of:
            if title:
                of.write('# %s\n\n' % title)
            if genfunc is None:
                of.write(body)
            else:
                for part in genfunc(*genargs):
                    of.write(part)
                    of.write('\n')

    #Parse LDAP timestamp formats to datetime
    def parseLdapTimestamp(self, value):
        """Parse LDAP timestamp formats (generalized time or Windows FILETIME) to datetime"""
        if value is None:
            return None
        
        # Handle special "never" values
        if value == 0 or value == "0" or value == -9223372036854775808:
            return None  # Return None to indicate "never" - will be handled by caller
        
        # Try LDAP generalized time format: YYYYMMDDHHmmss.fZ
        if isinstance(value, str):
            # Remove .0Z or similar suffix
            value_clean = value.rstrip('Z').split('.')[0]
            if len(value_clean) == 14 and value_clean.isdigit():
                try:
                    year = int(value_clean[0:4])
                    month = int(value_clean[4:6])
                    day = int(value_clean[6:8])
                    hour = int(value_clean[8:10])
                    minute = int(value_clean[10:12])
                    second = int(value_clean[12:14])
                    return datetime(year, month, day, hour, minute, second)
                except (ValueError, IndexError):
                    pass
        
        # Try Windows FILETIME (100-nanosecond intervals since Jan 1, 1601)
        if isinstance(value, (int, str)):
            try:
                if isinstance(value, str):
                    # Check if it's a large number string
                    if not value.isdigit():
                        return None
                    filetime = int(value)
                else:
                    filetime = value
                
                # FILETIME epoch: January 1, 1601
                # Convert to Unix timestamp
                if filetime > 0 and filetime < 2**63:  # Reasonable range check
                    # FILETIME is in 100-nanosecond intervals
                    # Convert to seconds since Jan 1, 1601
                    unix_epoch = datetime(1970, 1, 1)
                    filetime_epoch = datetime(1601, 1, 1)
                    epoch_delta = (unix_epoch - filetime_epoch).total_seconds()
                    
                    # Convert FILETIME to seconds
                    seconds_since_1601 = filetime / 10000000.0
                    # Convert to Unix timestamp
                    unix_timestamp = seconds_since_1601 - epoch_delta
                    
                    if unix_timestamp > 0:
                        return datetime.fromtimestamp(unix_timestamp)
            except (ValueError, OverflowError, OSError):
                pass
        
        return None

    #Format a value for HTML
    def formatString(self, value):
        if type(value) is datetime:
            try:
                return value.strftime('%x %X')
            except ValueError:
                #Invalid date
                return '0'
        
        # Check for special "never" values first
        if value == 0 or value == "0" or value == -9223372036854775808:
            return "Never"
        
        # Try to parse as LDAP timestamp
        parsed_date = self.parseLdapTimestamp(value)
        if parsed_date:
            try:
                return parsed_date.strftime('%x %X')
            except ValueError:
                pass
        
        # Make sure it's a unicode string
        if type(value) is bytes:
            try:
                return LDAP_SID(value).formatCanonical()
            except Exception:
                pass
            if len(value) == 16:
                try:
                    return str(UUID(bytes_le=value)).upper()
                except Exception:
                    pass
            return base64.b64encode(value).decode('ascii')
        if type(value) is str:
            return value#.encode('utf8')
        if type(value) is int:
            return str(value)
        if value is None:
            return ''
        #Other type: just return it
        return value

    #Format an attribute to a human readable format
    def formatAttribute(self, att, formatCnAsGroup=False):
        # Handle both ADWSAttribute and legacy attribute objects
        if hasattr(att, 'key'):
            aname = att.key.lower()
            att_value = att.value if hasattr(att, 'value') else None
            att_values = att.values if hasattr(att, 'values') else [att_value] if att_value else []
            att_raw_values = att.raw_values if hasattr(att, 'raw_values') else att_values
        else:
            # Fallback for other attribute types
            aname = str(att).lower()
            att_value = att
            att_values = [att]
            att_raw_values = [att]
        
        #User flags
        if aname == 'useraccountcontrol':
            return ', '.join(self.parseFlags(att, uac_flags))
        #List of groups
        if aname == 'member' or (aname == 'memberof' and isinstance(att_values, list)):
            return self.formatGroupsHtml(att_values)
        if aname == 'serviceprincipalname' and isinstance(att_values, list):
            return self.formatSPNsHtml(att_values)
        #Primary group
        if aname == 'primarygroupid':
            try:
                return self.formatGroupsHtml([self.dd.groups_dnmap[att_value]])
            except (KeyError, AttributeError):
                return 'NOT FOUND!'
        if aname == 'description' and isinstance(att_values, list):
             return " ".join(att_values)
        #Pwd flags
        if aname == 'pwdproperties':
            return ', '.join(self.parseFlags(att, pwd_flags))
        #Domain trust flags
        if aname == 'trustattributes':
            return ', '.join(self.parseFlags(att, trust_flags))
        if aname == 'trustdirection':
            if att_value == 0:
                return 'DISABLED'
            else:
                return ', '.join(self.parseSingleFlag(att, trust_directions))
        if aname == 'trusttype':
            return ', '.join(self.parseSingleFlag(att, trust_type))
        if aname == 'securityidentifier':
            return self.formatSidValue(att_value, att_raw_values)
        if aname == 'objectguid':
            return self.formatObjectGuidValue(att_value, att_raw_values)
        if aname == 'minpwdage' or  aname == 'maxpwdage':
            return '%.2f days' % self.nsToDays(att_value)
        if aname == 'lockoutobservationwindow' or  aname == 'lockoutduration':
            return '%.1f minutes' % self.nsToMinutes(att_value)
        if aname == 'objectsid':
            sid_str = self.formatSidValue(att_value, att_raw_values)
            return '<abbr title="%s">%s</abbr>' % (sid_str, sid_str.split('-')[-1] if '-' in sid_str else sid_str)
        #Special case where the attribute is a CN and it should be made clear its a group
        if aname == 'cn' and formatCnAsGroup:
            return self.formatCnWithGroupLink(att_value)
        #Other
        return self.htmlescape(self.formatString(att_value))


    def formatCnWithGroupLink(self, cn):
        return 'Group: <a href="#cn_%s" title="%s">%s</a>' % (self.formatId(cn), self.htmlescape(cn), self.htmlescape(cn))

    #Convert a CN to a valid HTML id by replacing all non-ascii characters with a _
    def formatId(self, cn):
        return re.sub(r'[^a-zA-Z0-9_\-]+', '_', cn)

    # Fallback function for dirty DN parsing in case ldap3 functions error out
    def parseDnFallback(self, dn):
        try:
            indcn = dn[3:].index(',CN=')
            indou = dn[3:].index(',OU=')
            if indcn < indou:
                cn = dn[3:].split(',CN=')[0]
            else:
                cn = dn[3:].split(',OU=')[0]
        except ValueError:
            cn = dn
        return cn

    #Format groups to readable HTML
    def formatGroupsHtml(self, grouplist):
        outcache = []
        for group in grouplist:
            try:
                cn = self.unescapecn(dn.parse_dn(group)[0][1])
            except LDAPInvalidDnError:
                # Parsing failed, do it manually
                cn = self.unescapecn(self.parseDnFallback(group))
            outcache.append('<a href="%s.html#cn_%s" title="%s">%s</a>' % (self.config.users_by_group, quote_plus(self.formatId(cn)), self.htmlescape(group), self.htmlescape(cn)))
        return ', '.join(outcache)

    #Format groups to greppable format
    def formatGroupsGrep(self, grouplist):
        outcache = []
        for group in grouplist:
            try:
                cn = self.unescapecn(dn.parse_dn(group)[0][1])
            except LDAPInvalidDnError:
                # Parsing failed, do it manually
                cn = self.unescapecn(self.parseDnFallback(group))
            outcache.append(cn)
        return ', '.join(outcache)

    #Format SPNs to readable HTML
    def formatSPNsHtml(self, spnlist):
        return '<br />'.join(spnlist)

    #Format SPNs to greppable format
    def formatSPNsGrep(self, spnlist):
        return ','.join(spnlist)

    #Format attribute for grepping
    def formatGrepAttribute(self, att):
        # Handle both ADWSAttribute and legacy attribute objects
        if hasattr(att, 'key'):
            aname = att.key.lower()
            att_value = att.value if hasattr(att, 'value') else None
            att_values = att.values if hasattr(att, 'values') else [att_value] if att_value else []
            att_raw_values = att.raw_values if hasattr(att, 'raw_values') else att_values
        else:
            # Fallback for other attribute types
            aname = str(att).lower()
            att_value = att
            att_values = [att]
            att_raw_values = [att]
        
        #User flags
        if aname == 'useraccountcontrol':
            return ', '.join(self.parseFlags(att, uac_flags))
        #List of groups
        if aname == 'member' or (aname == 'memberof' and isinstance(att_values, list)):
            return self.formatGroupsGrep(att_values)
        if aname == 'serviceprincipalname' and isinstance(att_values, list):
            return self.formatSPNsGrep(att_values)
        if aname == 'primarygroupid':
            try:
                return self.formatGroupsGrep([self.dd.groups_dnmap[att_value]])
            except (KeyError, AttributeError):
                return 'NOT FOUND!'
        if aname == 'description' and isinstance(att_values, list):
            return " ".join(att_values)
        #Domain trust flags
        if aname == 'trustattributes':
            return ', '.join(self.parseFlags(att, trust_flags))
        if aname == 'trustdirection':
            if att_value == 0:
                return 'DISABLED'
            else:
                return ', '.join(self.parseSingleFlag(att, trust_directions))
        if aname == 'trusttype':
            return ', '.join(self.parseSingleFlag(att, trust_type))
        if aname == 'securityidentifier' or aname == 'objectsid':
            return self.formatSidValue(att_value, att_raw_values)
        if aname == 'objectguid':
            return self.formatObjectGuidValue(att_value, att_raw_values)
        #Pwd flags
        if aname == 'pwdproperties':
            return ', '.join(self.parseFlags(att, pwd_flags))
        if aname == 'minpwdage' or  aname == 'maxpwdage':
            return '%.2f days' % self.nsToDays(att_value)
        if aname == 'lockoutobservationwindow' or  aname == 'lockoutduration':
            return '%.1f minutes' % self.nsToMinutes(att_value)
        return self.formatString(att_value)

    #Generate grep/awk/cut-able output
    def generateGrepList(self, entrylist, attributes):
        hdr = self.config.grepsplitchar.join(attributes)
        out = [hdr]
        for entry in entrylist:
            eo = []
            for attr in attributes:
                try:
                    eo.append(self.formatGrepAttribute(entry[attr]) or '')
                except (LDAPKeyError, LDAPCursorError, KeyError):
                    eo.append('')
            out.append(self.config.grepsplitchar.join(eo))
        return '\n'.join(out)

    #Convert a list of entities to a JSON string
    #String concatenation is used here since the entities have their own json generate
    #method and converting the string back to json just to process it would be inefficient
    def generateJsonList(self, entrylist):
        out = '[' + ','.join([entry.entry_to_json() for entry in entrylist]) + ']'
        return out

    #Convert a group key/value pair to json
    #Same methods as previous function are used
    def generateJsonGroup(self, group):
        out = '{%s:%s}' % (json.dumps(group[0]), self.generateJsonList(group[1]))
        return out

    #Convert a list of group dicts with entry lists to JSON string
    #Same methods as previous functions are used, except that text is returned
    #from a generator rather than allocating everything in memory
    def generateJsonGroupedList(self, groups):
        #Start of the list
        yield '['
        firstGroup = True
        for group in groups.items():
            if not firstGroup:
                #Separate items
                yield ','
            else:
                firstGroup = False
            yield self.generateJsonGroup(group)
        yield ']'

    #Generate report of all computers grouped by OS family
    def generateComputersByOsReport(self, dd):
        grouped = dd.sortComputersByOS(dd.computers)
        attrs = self._report_attributes(dd.computers, self.computerattributes)
        if self.config.outputhtml:
            #Use the generator approach to save memory
            self.writeHtmlFile('%s.html' % self.config.computers_by_os, None, genfunc=self.generateGroupedHtmlTables, genargs=(grouped, attrs))
        if self.config.outputmarkdown:
            self.writeMarkdownFile('%s.md' % self.config.computers_by_os, None, genfunc=self.generateGroupedMarkdownSections, genargs=(grouped, attrs), title='Domain computers by OS')
        if self.config.outputjson and self.config.groupedjson:
            self.writeJsonFile('%s.json' % self.config.computers_by_os, None, genfunc=self.generateJsonGroupedList, genargs=(grouped, ))

    #Generate report of all groups and detailled user info
    def generateUsersByGroupReport(self, dd):
        grouped = dd.sortUsersByGroup(dd.users)
        attrs = self._report_attributes(dd.users, self.userattributes_grouped)
        if self.config.outputhtml:
            #Use the generator approach to save memory
            self.writeHtmlFile('%s.html' % self.config.users_by_group, None, genfunc=self.generateGroupedHtmlTables, genargs=(grouped, attrs))
        if self.config.outputmarkdown:
            self.writeMarkdownFile('%s.md' % self.config.users_by_group, None, genfunc=self.generateGroupedMarkdownSections, genargs=(grouped, attrs), title='Domain users by group')
        if self.config.outputjson and self.config.groupedjson:
            self.writeJsonFile('%s.json' % self.config.users_by_group, None, genfunc=self.generateJsonGroupedList, genargs=(grouped, ))

    #Generate report with just a table of all users
    def generateUsersReport(self, dd):
        #Copy dd to this object, to be able to reference it
        self.dd = dd
        dd.mapGroupsIdsToDns()
        attrs = self._report_attributes(dd.users, self.userattributes)
        if self.config.outputhtml:
            html = self.generateHtmlTable(dd.users, attrs, 'Domain users')
            self.writeHtmlFile('%s.html' % self.config.usersfile, html)
        if self.config.outputgrep:
            grepout = self.generateGrepList(dd.users, attrs)
            self.writeGrepFile('%s.grep' % self.config.usersfile, grepout)
        if self.config.outputmarkdown:
            md = self.generateMarkdownTable(dd.users, attrs, 'Domain users', header_level=1)
            self.writeMarkdownFile('%s.md' % self.config.usersfile, md)
        if self.config.outputjson:
            jsonout = self.generateJsonList(dd.users)
            self.writeJsonFile('%s.json' % self.config.usersfile, jsonout)

    #Generate report with just a table of all computer accounts
    def generateComputersReport(self, dd):
        attrs = self._report_attributes(dd.computers, self.computerattributes)
        if self.config.outputhtml:
            html = self.generateHtmlTable(dd.computers, attrs, 'Domain computer accounts')
            self.writeHtmlFile('%s.html' % self.config.computersfile, html)
        if self.config.outputgrep:
            grepout = self.generateGrepList(dd.computers, attrs)
            self.writeGrepFile('%s.grep' % self.config.computersfile, grepout)
        if self.config.outputmarkdown:
            md = self.generateMarkdownTable(dd.computers, attrs, 'Domain computer accounts', header_level=1)
            self.writeMarkdownFile('%s.md' % self.config.computersfile, md)
        if self.config.outputjson:
            jsonout = self.generateJsonList(dd.computers)
            self.writeJsonFile('%s.json' % self.config.computersfile, jsonout)

    #Generate report with just a table of all computer accounts
    def generateGroupsReport(self, dd):
        attrs = self._report_attributes(dd.groups, self.groupattributes)
        if self.config.outputhtml:
            html = self.generateHtmlTable(dd.groups, attrs, 'Domain groups')
            self.writeHtmlFile('%s.html' % self.config.groupsfile, html)
        if self.config.outputgrep:
            grepout = self.generateGrepList(dd.groups, attrs)
            self.writeGrepFile('%s.grep' % self.config.groupsfile, grepout)
        if self.config.outputmarkdown:
            md = self.generateMarkdownTable(dd.groups, attrs, 'Domain groups', header_level=1)
            self.writeMarkdownFile('%s.md' % self.config.groupsfile, md)
        if self.config.outputjson:
            jsonout = self.generateJsonList(dd.groups)
            self.writeJsonFile('%s.json' % self.config.groupsfile, jsonout)

    #Generate policy report
    def generatePolicyReport(self, dd):
        attrs = self._report_attributes(dd.policy, self.policyattributes)
        if self.config.outputhtml:
            html = self.generateHtmlTable(dd.policy, attrs, 'Domain policy')
            self.writeHtmlFile('%s.html' % self.config.policyfile, html)
        if self.config.outputgrep:
            grepout = self.generateGrepList(dd.policy, attrs)
            self.writeGrepFile('%s.grep' % self.config.policyfile, grepout)
        if self.config.outputmarkdown:
            md = self.generateMarkdownTable(dd.policy, attrs, 'Domain policy', header_level=1)
            self.writeMarkdownFile('%s.md' % self.config.policyfile, md)
        if self.config.outputjson:
            jsonout = self.generateJsonList(dd.policy)
            self.writeJsonFile('%s.json' % self.config.policyfile, jsonout)

    #Generate policy report
    def generateTrustsReport(self, dd):
        attrs = self._report_attributes(dd.trusts, self.trustattributes)
        if self.config.outputhtml:
            html = self.generateHtmlTable(dd.trusts, attrs, 'Domain trusts')
            self.writeHtmlFile('%s.html' % self.config.trustsfile, html)
        if self.config.outputgrep:
            grepout = self.generateGrepList(dd.trusts, attrs)
            self.writeGrepFile('%s.grep' % self.config.trustsfile, grepout)
        if self.config.outputmarkdown:
            md = self.generateMarkdownTable(dd.trusts, attrs, 'Domain trusts', header_level=1)
            self.writeMarkdownFile('%s.md' % self.config.trustsfile, md)
        if self.config.outputjson:
            jsonout = self.generateJsonList(dd.trusts)
            self.writeJsonFile('%s.json' % self.config.trustsfile, jsonout)

    def generateGposReport(self, dd):
        attrs = self._report_attributes(dd.gpos, self.gpoattributes)
        if self.config.outputhtml:
            html = self.generateHtmlTable(dd.gpos, attrs, 'Group Policy Objects')
            self.writeHtmlFile('%s.html' % self.config.gposfile, html)
        if self.config.outputgrep:
            grepout = self.generateGrepList(dd.gpos, attrs)
            self.writeGrepFile('%s.grep' % self.config.gposfile, grepout)
        if self.config.outputmarkdown:
            md = self.generateMarkdownTable(dd.gpos, attrs, 'Group Policy Objects', header_level=1)
            self.writeMarkdownFile('%s.md' % self.config.gposfile, md)
        if self.config.outputjson:
            jsonout = self.generateJsonList(dd.gpos)
            self.writeJsonFile('%s.json' % self.config.gposfile, jsonout)

    def generateOusReport(self, dd):
        attrs = self._report_attributes(dd.ous, self.ouattributes)
        if self.config.outputhtml:
            html = self.generateHtmlTable(dd.ous, attrs, 'Organizational Units')
            self.writeHtmlFile('%s.html' % self.config.ousfile, html)
        if self.config.outputgrep:
            grepout = self.generateGrepList(dd.ous, attrs)
            self.writeGrepFile('%s.grep' % self.config.ousfile, grepout)
        if self.config.outputmarkdown:
            md = self.generateMarkdownTable(dd.ous, attrs, 'Organizational Units', header_level=1)
            self.writeMarkdownFile('%s.md' % self.config.ousfile, md)
        if self.config.outputjson:
            jsonout = self.generateJsonList(dd.ous)
            self.writeJsonFile('%s.json' % self.config.ousfile, jsonout)

    def generateContainersReport(self, dd):
        attrs = self._report_attributes(dd.containers, self.containerattributes)
        if self.config.outputhtml:
            html = self.generateHtmlTable(dd.containers, attrs, 'Containers')
            self.writeHtmlFile('%s.html' % self.config.containersfile, html)
        if self.config.outputgrep:
            grepout = self.generateGrepList(dd.containers, attrs)
            self.writeGrepFile('%s.grep' % self.config.containersfile, grepout)
        if self.config.outputmarkdown:
            md = self.generateMarkdownTable(dd.containers, attrs, 'Containers', header_level=1)
            self.writeMarkdownFile('%s.md' % self.config.containersfile, md)
        if self.config.outputjson:
            jsonout = self.generateJsonList(dd.containers)
            self.writeJsonFile('%s.json' % self.config.containersfile, jsonout)

#Some quick logging helpers
def log_warn(text):
    print('[!] %s' % text)
def log_info(text):
    print('[*] %s' % text)
def log_success(text):
    print('[+] %s' % text)

def test_adws_port(host, port=9389, timeout=5):
    """
    Test if ADWS port is reachable
    Returns True if connection succeeds, False otherwise
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False

def main():
    parser = argparse.ArgumentParser(description='Domain information dumper via ADWS. Dumps users/computers/groups and OS/membership information to HTML/JSON/greppable/Markdown output.')
    parser._optionals.title = "Main options"
    parser._positionals.title = "Required options"

    #Main parameters
    #maingroup = parser.add_argument_group("Main options")
    parser.add_argument("host", type=str, metavar='HOSTNAME', help="Hostname/ip of domain controller to connect to via ADWS (port 9389)")
    parser.add_argument("-u", "--user", type=str, metavar='USERNAME', help="DOMAIN\\username or user@domain.com for authentication")
    parser.add_argument("-p", "--password", type=str, metavar='PASSWORD', help="Password or LM:NTLM hash, will prompt if not specified")
    parser.add_argument("-at", "--authtype", type=str, choices=['NTLM'], default='NTLM', help="Authentication type (NTLM only for ADWS, default: NTLM)")

    #Output parameters
    outputgroup = parser.add_argument_group("Output options")
    outputgroup.add_argument("-o", "--outdir", type=str, metavar='DIRECTORY', help="Directory in which the dump will be saved (default: current)")
    outputgroup.add_argument("--no-html", action='store_true', help="Disable HTML output")
    outputgroup.add_argument("--no-json", action='store_true', help="Disable JSON output")
    outputgroup.add_argument("--no-grep", action='store_true', help="Disable Greppable output")
    outputgroup.add_argument("--markdown", action='store_true', help="Also write Markdown output (.md files)")
    outputgroup.add_argument("--bloodhound", action='store_true', help="Write BloodHound-compatible JSON and zip it for import (bloodhound_<domain>.zip)")
    outputgroup.add_argument("--acl", action='store_true', help="Parse DACLs from nTSecurityDescriptor without --all (requires --bloodhound and/or --markdown; included in --all)")
    outputgroup.add_argument("--adcs", action='store_true', help="Collect AD CS (certificate templates, enterprise CAs) for BloodHound (requires --bloodhound; ADWS only; included in --all)")
    outputgroup.add_argument("--grouped-json", action='store_true', default=False, help="Also write json files for grouped files (default: disabled)")
    outputgroup.add_argument("-d", "--delimiter", help="Field delimiter for greppable output (default: tab)")

    #Additional options
    miscgroup = parser.add_argument_group("Misc options")
    miscgroup.add_argument("-a", "--all", action='store_true',
                           help="Collect extended ADWS attributes and extra object types (GPOs, OUs, containers). "
                                "All fetched attributes are included in JSON/HTML/grep/Markdown output and in the "
                                "BloodHound export when --bloodhound is used. Enables --adcs and --acl (DACL parsing).")
    miscgroup.add_argument("-r", "--resolve", action='store_true', help="Resolve computer hostnames (might take a while and cause high traffic on large networks)")
    miscgroup.add_argument("--full-build", action='store_true', default=False,
                           help="Enrich computers with the full OS build number (e.g. 14393.8246) via remote registry over SMB. "
                                "Requires RemoteRegistry service on each target. Any authenticated domain user can read this "
                                "(no admin required). Not included in BloodHound export.")
    miscgroup.add_argument("-n", "--dns-server", help="Use custom DNS resolver instead of system DNS (try a domain controller IP)")
    miscgroup.add_argument("-m", "--minimal", action='store_true', default=False, help="Only query minimal set of attributes to limit memmory usage")
    miscgroup.add_argument("--force", action='store_true', help="Skip ADWS port connectivity check")

    args = parser.parse_args()
    #Create default config
    cnf = domainDumpConfig()
    #Dns lookups?
    if args.resolve:
        cnf.lookuphostnames = True
    #Custom dns server?
    if args.dns_server is not None:
        cnf.dnsserver = args.dns_server
    #Minimal attributes?
    if args.minimal:
        cnf.minimal = True
    if args.all:
        cnf.collect_all = True
        cnf.collect_adcs = True
        cnf.collect_acl = True
        if cnf.minimal:
            log_warn('--all overrides --minimal (extended collection enabled)')
            cnf.minimal = False
    if args.full_build:
        cnf.full_build = True
    #Custom separator?
    if args.delimiter is not None:
        cnf.grepsplitchar = args.delimiter
    #Disable html?
    if args.no_html:
        cnf.outputhtml = False
    #Disable json?
    if args.no_json:
        cnf.outputjson = False
    #Disable grep?
    if args.no_grep:
        cnf.outputgrep = False
    #Enable markdown?
    if args.markdown:
        cnf.outputmarkdown = True
    #Enable bloodhound?
    if args.bloodhound:
        cnf.outputbloodhound = True
    if args.acl:
        if not args.bloodhound and not args.markdown:
            parser.error('--acl requires --bloodhound and/or --markdown')
        cnf.collect_acl = True
    if args.adcs:
        if not args.bloodhound:
            parser.error('--adcs requires --bloodhound')
        cnf.collect_adcs = True
    #Custom outdir?
    if args.outdir is not None:
        cnf.basepath = args.outdir
    #Do we really need grouped json files?
    cnf.groupedjson = args.grouped_json

    #Parse host and domain
    host = args.host
    # Remove ldap:// or ldaps:// prefix if present (ADWS uses net.tcp://)
    if host.startswith('ldap://'):
        host = host[7:]
    elif host.startswith('ldaps://'):
        host = host[8:]
    # Remove port if specified (ADWS uses port 9389)
    if ':' in host:
        host = host.split(':')[0]
    
    # Extract domain from username or use hostname
    domain = None
    username = args.user
    if args.user is not None:
        if '\\' in args.user:
            domain, username = args.user.split('\\', 1)
        elif '@' in args.user:
            username, domain = args.user.rsplit('@', 1)
        else:
            # Try to extract domain from hostname
            if '.' in host:
                domain = '.'.join(host.split('.')[1:])
            else:
                log_warn('Username must include a domain, use: DOMAIN\\username or user@domain.com')
                sys.exit(1)
    else:
        # Try to extract domain from hostname
        if '.' in host:
            domain = '.'.join(host.split('.')[1:])
        else:
            log_warn('Cannot determine domain. Please specify username with domain (DOMAIN\\username or user@domain.com)')
            sys.exit(1)
    
    if args.password is None and args.user is not None:
        args.password = getpass.getpass()
    
    # define the server and the connection using ADWS
    s = ADWSServer(host, domain)
    log_info('Connecting to ADWS host...')
    
    # Test ADWS port connectivity (unless --force is used)
    if not args.force:
        if test_adws_port(host, 9389):
            log_success('ADWS port 9389 is reachable')
        else:
            log_warn('ADWS port 9389 is not reachable')
    else:
        log_info('Skipping port check (--force specified)')

    c = ADWSConnection(s, user=args.user, password=args.password)
    log_info('Binding to ADWS host')
    # perform the Bind operation
    if not c.bind():
        log_warn('Could not bind with specified credentials')
        if hasattr(c, 'result'):
            log_warn(c.result)
        sys.exit(1)
    log_success('Bind OK')
    log_info('Starting domain dump')
    #Create domaindumper object
    dd = domainDumper(s, c, cnf)

    #Do the actual dumping
    dd.domainDump()
    log_success('Domain dump finished')

if __name__ == '__main__':
    main()
