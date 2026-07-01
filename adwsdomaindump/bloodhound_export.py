"""
Export ADWS domain dump data in BloodHound-compatible JSON format (schema version 5).

Produces users.json, groups.json, computers.json and domains.json suitable for
import into BloodHound CE / bloodhound.py (group + objectprops + trusts collection).
"""
from __future__ import unicode_literals

import base64
import calendar
import codecs
import json
import logging
import os
import re
from datetime import datetime
from uuid import UUID
from zipfile import ZipFile, ZIP_DEFLATED

from impacket.ldap.ldaptypes import LDAP_SID, SR_SECURITY_DESCRIPTOR

logger = logging.getLogger(__name__)

GENERIC_ALL_MASK = 0x10000000

EXTENDED_DUMP_ATTRIBUTES = [
    'displayName', 'gPCFileSysPath', 'gPLink', 'gPOptions', 'adminCount',
    'msDS-AllowedToDelegateTo', 'mail', 'title', 'lastLogonTimestamp', 'sIDHistory',
]

DEFAULT_PRIMARY_GROUP_RID = {
    "computer": 515,  # Domain Computers
    "user": 513,      # Domain Users
}

DOMAIN_USERS_GROUP_RID = 513
DOMAIN_COMPUTERS_GROUP_RID = 515

FUNCTIONAL_LEVELS = {
    0: "2000 Mixed/Native",
    1: "2003 Interim",
    2: "2003",
    3: "2008",
    4: "2008 R2",
    5: "2012",
    6: "2012 R2",
    7: "2016",
}


ACL_ATTRIBUTES = ['nTSecurityDescriptor', 'msDS-GroupMSAMembership']


def with_acl_attributes(attributes):
    merged = list(attributes or [])
    for attr in ACL_ATTRIBUTES:
        if attr not in merged:
            merged.append(attr)
    return merged


def _merge_attributes(base, extra):
    merged = list(base)
    for attr in extra:
        if attr not in merged:
            merged.append(attr)
    return merged


def base_attributes():
    from .adws_wrapper import CORE_OBJECT_ATTRIBUTES
    return list(CORE_OBJECT_ATTRIBUTES)


def domain_policy_attributes():
    from .adws_wrapper import DOMAIN_POLICY_ATTRIBUTES
    return list(DOMAIN_POLICY_ATTRIBUTES)


def extended_user_attributes():
    return _merge_attributes(base_attributes(), [
        'mail', 'title', 'adminCount', 'msDS-AllowedToDelegateTo',
        'lastLogonTimestamp', 'sIDHistory', 'displayName',
    ])


def extended_computer_attributes():
    return _merge_attributes(base_attributes(), [
        'adminCount', 'msDS-AllowedToDelegateTo', 'lastLogonTimestamp', 'sIDHistory',
        'msDS-AllowedToActOnBehalfOfOtherIdentity',
    ])


def extended_group_attributes():
    return _merge_attributes(base_attributes(), ['adminCount'])


def gpo_attributes():
    return _merge_attributes(base_attributes(), ['displayName', 'gPCFileSysPath'])


def ou_attributes():
    return _merge_attributes(base_attributes(), ['gPLink', 'gPOptions'])


def container_attributes():
    return base_attributes()


def extended_attributes():
    """Legacy helper — prefer object-type-specific attribute lists for ADWS."""
    return _merge_attributes(base_attributes(), EXTENDED_DUMP_ATTRIBUTES)


def guid_to_string(value):
    if value is None:
        return None
    if isinstance(value, bytes):
        return str(UUID(bytes_le=value)).upper()
    text = str(value).strip('{}').upper()
    return text


def parse_gplink_string(linkstr):
    if not linkstr:
        return
    for links in str(linkstr).split('LDAP://')[1:]:
        dn, options = links.rstrip('][ ').split(';')
        yield dn, int(options)


def is_filtered_container(containerdn):
    if not containerdn:
        return False
    upper = containerdn.upper()
    if "CN=DOMAINUPDATES,CN=SYSTEM,DC=" in upper:
        return True
    if "CN=POLICIES,CN=SYSTEM,DC=" in upper and (upper.startswith('CN=USER') or upper.startswith('CN=MACHINE')):
        return True
    return False


def is_filtered_container_child(containerdn):
    if not containerdn:
        return False
    upper = containerdn.upper()
    if "CN=PROGRAM DATA,DC=" in upper:
        return True
    if "CN=SYSTEM,DC=" in upper:
        return True
    return False


def is_direct_child(parent_dn, child_dn):
    parent = parent_dn.upper().strip()
    child = child_dn.upper().strip()
    return child.endswith(',' + parent) and child.count(',') == parent.count(',') + 1

# Well-known SIDs keyed by short name (ForeignSecurityPrincipals CN) or full SID
WELLKNOWN_SIDS = {
    "S-1-0": ("Null Authority", "User"),
    "S-1-0-0": ("Nobody", "User"),
    "S-1-1": ("World Authority", "User"),
    "S-1-1-0": ("Everyone", "Group"),
    "S-1-2": ("Local Authority", "User"),
    "S-1-2-0": ("Local", "Group"),
    "S-1-2-1": ("Console Logon", "Group"),
    "S-1-3": ("Creator Authority", "User"),
    "S-1-3-0": ("Creator Owner", "User"),
    "S-1-3-1": ("Creator Group", "Group"),
    "S-1-3-2": ("Creator Owner Server", "Computer"),
    "S-1-3-3": ("Creator Group Server", "Computer"),
    "S-1-3-4": ("Owner Rights", "Group"),
    "S-1-4": ("Non-unique Authority", "User"),
    "S-1-5": ("NT Authority", "User"),
    "S-1-5-1": ("Dialup", "Group"),
    "S-1-5-2": ("Network", "Group"),
    "S-1-5-3": ("Batch", "Group"),
    "S-1-5-4": ("Interactive", "Group"),
    "S-1-5-6": ("Service", "Group"),
    "S-1-5-7": ("Anonymous", "Group"),
    "S-1-5-8": ("Proxy", "Group"),
    "S-1-5-9": ("Enterprise Domain Controllers", "Group"),
    "S-1-5-10": ("Principal Self", "User"),
    "S-1-5-11": ("Authenticated Users", "Group"),
    "S-1-5-12": ("Restricted Code", "Group"),
    "S-1-5-13": ("Terminal Server Users", "Group"),
    "S-1-5-14": ("Remote Interactive Logon", "Group"),
    "S-1-5-15": ("This Organization", "Group"),
    "S-1-5-17": ("IUSR", "User"),
    "S-1-5-18": ("Local System", "User"),
    "S-1-5-19": ("Local Service", "User"),
    "S-1-5-20": ("Network Service", "User"),
}

HIGHVALUE_GROUP_SUFFIXES = ("-512", "-516", "-519")
HIGHVALUE_GROUP_SIDS = {
    "S-1-5-32-544",
    "S-1-5-32-550",
    "S-1-5-32-549",
    "S-1-5-32-551",
    "S-1-5-32-548",
}

BH_TRUST_TYPE = {
    "ParentChild": 0,
    "CrossLink": 1,
    "Forest": 2,
    "External": 3,
    "Unknown": 4,
}

TRUST_FLAGS = {
    "NON_TRANSITIVE": 0x00000001,
    "UPLEVEL_ONLY": 0x00000002,
    "QUARANTINED_DOMAIN": 0x00000004,
    "FOREST_TRANSITIVE": 0x00000008,
    "CROSS_ORGANIZATION": 0x00000010,
    "WITHIN_FOREST": 0x00000020,
    "TREAT_AS_EXTERNAL": 0x00000040,
    "USES_RC4_ENCRYPTION": 0x00000080,
}


def ldap_to_domain(ldap_dn):
    return re.sub(r",DC=", ".", ldap_dn[ldap_dn.find("DC="):], flags=re.I)[3:]


def win_timestamp_to_unix(seconds):
    seconds = int(seconds)
    if seconds == 0:
        return 0
    return int((seconds - 116444736000000000) / 10000000)


def ldap_generalized_time_to_unix(value):
    if value is None:
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        value_clean = value.rstrip("Z").split(".")[0]
        if len(value_clean) == 14 and value_clean.isdigit():
            dt = datetime(
                int(value_clean[0:4]),
                int(value_clean[4:6]),
                int(value_clean[6:8]),
                int(value_clean[8:10]),
                int(value_clean[10:12]),
                int(value_clean[12:14]),
            )
            return calendar.timegm(dt.timetuple())
    return 0


def sid_to_string(value):
    if value is None:
        return ""
    if isinstance(value, bytes):
        return LDAP_SID(value).formatCanonical()
    if isinstance(value, str):
        if value.startswith("S-"):
            return value
        try:
            return LDAP_SID(base64.b64decode(value)).formatCanonical()
        except Exception:
            return value
    return str(value)


def get_entry_property(entry, prop, default=None, as_list=False):
    if prop not in entry:
        return default
    attr = entry[prop]
    if hasattr(attr, "values"):
        values = attr.values
    elif hasattr(attr, "value"):
        values = attr.value if isinstance(attr.value, list) else [attr.value]
    else:
        values = [attr]
    if values is None:
        return default
    if as_list:
        return values if values else (default if default is not None else [])
    if not values:
        return default
    return values[0]


def get_object_classes(entry):
    oc = get_entry_property(entry, "objectClass", default=[], as_list=True)
    if isinstance(oc, str):
        return [oc.lower()]
    return [str(c).lower() for c in oc]


def get_int(value, default=0):
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


class BloodHoundExporter:
    def __init__(self, config):
        self.config = config
        self.domain = ""
        self.domain_sid = ""
        self.dncache = {}
        self.sidcache = {}
        self.guidcache = {}
        self.hostcache = {}
        self.collect_acl = getattr(config, 'collect_acl', False)
        self.collect_adcs = getattr(config, 'collect_adcs', False)
        self.objecttype_guid_map = {}
        self._acl_objects_with_sd = 0
        self._acl_objects_missing_sd = 0
        self._acl_total_edges = 0
        if self.collect_acl:
            from .schema_map import get_objecttype_guid_map
            self.objecttype_guid_map = get_objecttype_guid_map()

        self._written_files = []

    def export(self, dd):
        self._written_files = []
        self.domain = dd.server.domain.upper()
        self.domain_sid = dd.getRootSid()
        if not self.domain_sid:
            logger.error("Could not determine domain SID, skipping BloodHound export")
            return

        self._build_caches(dd.users, dd.groups, dd.computers)

        users = self._build_users(dd.users)
        groups = self._build_groups(dd.groups)
        computers = self._build_computers(dd.computers)
        self._sync_primary_group_members(users, groups, computers)

        gpos = []
        ous = []
        containers = []
        if getattr(self.config, 'collect_all', False):
            gpos = self._build_gpos(getattr(dd, 'gpos', []))

        domains = self._build_domains(dd.policy, dd.trusts, dd.computers, dd)

        users.extend(self._default_users())
        groups.extend(self._default_groups(dd.computers))

        self._write_file("users", users)
        self._write_file("groups", groups)
        self._write_file("computers", computers)
        self._write_file("domains", domains)

        if getattr(self.config, 'collect_all', False):
            ous = self._build_ous(getattr(dd, 'ous', []), dd)
            containers = self._build_containers(getattr(dd, 'containers', []), dd)
            self._write_file("gpos", gpos)
            self._write_file("ous", ous)
            self._write_file("containers", containers)

        if self.collect_adcs:
            self._export_adcs(dd)

        if self.collect_acl:
            self._log_acl_summary()

        return self._create_zip()

    def _zip_basename(self):
        safe_domain = re.sub(r'[^a-zA-Z0-9._-]+', '_', self.domain.lower()).strip('_')
        return "bloodhound_%s.zip" % (safe_domain or "export")

    def _create_zip(self):
        if not self._written_files:
            return None
        if not os.path.exists(self.config.basepath):
            os.makedirs(self.config.basepath)
        zip_path = os.path.join(self.config.basepath, self._zip_basename())
        with ZipFile(zip_path, "w", compression=ZIP_DEFLATED) as zf:
            for path in self._written_files:
                zf.write(path, arcname=os.path.basename(path))
        for path in self._written_files:
            try:
                os.remove(path)
            except OSError as exc:
                logger.warning("Could not remove BloodHound JSON %s: %s", path, exc)
        try:
            from adwsdomaindump import log_success
            log_success("Wrote BloodHound archive: %s (%d files)" % (zip_path, len(self._written_files)))
        except ImportError:
            logger.info("Wrote BloodHound archive: %s", zip_path)
        return zip_path

    def _filename(self, basename):
        return "%s.json" % basename

    def _write_file(self, obj_type, items):
        if not os.path.exists(self.config.basepath):
            os.makedirs(self.config.basepath)
        outfile = os.path.join(self.config.basepath, self._filename(obj_type))
        payload = {
            "data": items,
            "meta": {
                "methods": 0,
                "type": obj_type,
                "count": len(items),
                "version": 5,
            },
        }
        with codecs.open(outfile, "w", "utf-8") as out:
            json.dump(payload, out)
        self._written_files.append(outfile)
        try:
            from adwsdomaindump import log_info
            if self.collect_acl:
                ace_count = sum(len(o.get("Aces") or []) for o in items)
                log_info(
                    "Wrote BloodHound %s: %s (%d objects, %d ACEs)"
                    % (obj_type, outfile, len(items), ace_count)
                )
            else:
                log_info("Wrote BloodHound %s: %s (%d objects)" % (obj_type, outfile, len(items)))
        except ImportError:
            logger.info("Wrote BloodHound %s export: %s (%d objects)", obj_type, outfile, len(items))

    def _record_acl_edges(self, aces, had_descriptor, count_object=True):
        if not self.collect_acl:
            return
        if count_object:
            if had_descriptor:
                self._acl_objects_with_sd += 1
            else:
                self._acl_objects_missing_sd += 1
        self._acl_total_edges += len(aces or [])

    def _write_raw_json(self, obj_type, payload):
        if not os.path.exists(self.config.basepath):
            os.makedirs(self.config.basepath)
        outfile = os.path.join(self.config.basepath, self._filename(obj_type))
        with codecs.open(outfile, "w", "utf-8") as out:
            json.dump(payload, out)
        self._written_files.append(outfile)
        count = len(payload.get("data") or [])
        try:
            from adwsdomaindump import log_info
            log_info("Wrote BloodHound %s: %s (%d objects)" % (obj_type, outfile, count))
        except ImportError:
            logger.info("Wrote BloodHound %s: %s (%d objects)", obj_type, outfile, count)

    def _export_adcs(self, dd):
        try:
            from .adcs_collect import collect_adcs, adcs_summary
            data, result = collect_adcs(dd)
            summary = adcs_summary(data)
            for obj_type, blob in result.to_dict().items():
                if blob.get("data"):
                    self._write_raw_json(obj_type, blob)
            try:
                from adwsdomaindump import log_success
                log_success(
                    "Collected AD CS via ADWS: %d templates, %d enterprise CAs, %d root CAs, %d NTAuth stores, %d AIA CAs"
                    % (
                        summary["templates"],
                        summary["enterprise_cas"],
                        summary["root_cas"],
                        summary["ntauth_stores"],
                        summary["aia_cas"],
                    )
                )
            except ImportError:
                logger.info("AD CS collection summary: %s", summary)
        except Exception as exc:
            logger.error("AD CS collection failed: %s", exc)
            try:
                from adwsdomaindump import log_warn
                log_warn("AD CS collection failed: %s" % exc)
            except ImportError:
                pass

    def _log_acl_summary(self):
        try:
            from adwsdomaindump import log_info, log_success
        except ImportError:
            log_info = log_success = logger.info

        if self._acl_objects_with_sd == 0 and self._acl_total_edges == 0:
            log_info(
                "ACL parsing produced no edges — nTSecurityDescriptor may be missing from ADWS "
                "results (check account rights or reinstall adwsdomaindump)"
            )
            return

        log_success(
            "Parsed ACLs: %d objects with security descriptors, %d without, %d BloodHound ACE edges"
            % (self._acl_objects_with_sd, self._acl_objects_missing_sd, self._acl_total_edges)
        )

    def _build_caches(self, users, groups, computers):
        for entry in list(users or []) + list(groups or []) + list(computers or []):
            resolved = self._resolve_entry(entry)
            if not resolved:
                continue
            dn = get_entry_property(entry, "distinguishedName", default="")
            if dn:
                self.dncache[dn.upper()] = resolved
            sid = resolved.get("objectid")
            if sid:
                self.sidcache[sid] = resolved
            hostname = get_entry_property(entry, "dNSHostName", default="")
            if hostname:
                self.hostcache[hostname.lower()] = resolved
                self.hostcache[hostname.lower().split(".")[0]] = resolved
            account = get_entry_property(entry, "sAMAccountName", default="")
            if account:
                self.hostcache[account.lower()] = resolved
                self.hostcache[account.rstrip("$").lower()] = resolved

    def _cache_guid_entry(self, entry, object_type, name):
        guid = guid_to_string(get_entry_property(entry, "objectGUID", default=None))
        dn = get_entry_property(entry, "distinguishedName", default="")
        if not guid:
            return
        link = {"ObjectIdentifier": guid, "ObjectType": object_type}
        self.guidcache[guid] = link
        if dn:
            self.dncache[dn.upper()] = {
                "objectid": guid,
                "type": object_type.lower(),
                "principal": name,
            }

    def _resolve_child_objects(self, dd, parent_dn):
        children = []
        for child in dd.getChildObjects(parent_dn):
            if is_filtered_container_child(get_entry_property(child, "distinguishedName", default="")):
                continue
            resolved = self._resolve_entry(child)
            if not resolved or not resolved.get("objectid"):
                continue
            children.append({
                "ObjectIdentifier": resolved["objectid"],
                "ObjectType": resolved["type"] if resolved["type"] == "OU" else resolved["type"].capitalize(),
            })
        return children

    def _resolve_gpo_links(self, entry):
        links = []
        for gplink_dn, option in parse_gplink_string(get_entry_property(entry, "gPLink", default="")):
            if option not in (0, 2):
                continue
            cached = self.dncache.get(gplink_dn.upper())
            if not cached:
                continue
            guid = cached.get("objectid")
            if not guid:
                continue
            links.append({"IsEnforced": option == 2, "GUID": guid})
        return links

    def _build_gpos(self, gpos):
        out = []
        for entry in gpos or []:
            guid = guid_to_string(get_entry_property(entry, "objectGUID", default=None))
            if not guid:
                continue
            display = get_entry_property(entry, "displayName", default="") or get_entry_property(entry, "cn", default="")
            name = "%s@%s" % (display.upper(), self.domain)
            gpo = {
                "ObjectIdentifier": guid,
                "Properties": {
                    "domain": self.domain,
                    "name": name,
                    "distinguishedname": get_entry_property(entry, "distinguishedName", default="").upper(),
                    "domainsid": self.domain_sid,
                    "highvalue": False,
                    "gpcpath": (get_entry_property(entry, "gPCFileSysPath", default="") or "").upper(),
                    "description": get_entry_property(entry, "description", default="") or "",
                    "whencreated": ldap_generalized_time_to_unix(get_entry_property(entry, "whenCreated", default=0)),
                },
                "IsDeleted": False,
                "IsACLProtected": False,
                "Aces": [],
            }
            self._cache_guid_entry(entry, "GPO", name)
            self._apply_acls(gpo, entry, "gpo")
            out.append(gpo)
        return out

    def _build_ous(self, ous, dd):
        out = []
        for entry in ous or []:
            guid = guid_to_string(get_entry_property(entry, "objectGUID", default=None))
            if not guid:
                continue
            dn = get_entry_property(entry, "distinguishedName", default="").upper()
            name = "%s@%s" % (get_entry_property(entry, "name", default="").upper(), self.domain)
            ou = {
                "ObjectIdentifier": guid,
                "Properties": {
                    "domain": self.domain,
                    "name": name,
                    "distinguishedname": dn,
                    "domainsid": self.domain_sid,
                    "highvalue": False,
                    "blocksinheritance": get_int(get_entry_property(entry, "gPOptions", default=0)) == 1,
                    "description": get_entry_property(entry, "description", default=None) or None,
                    "whencreated": ldap_generalized_time_to_unix(get_entry_property(entry, "whenCreated", default=0)),
                },
                "IsDeleted": False,
                "IsACLProtected": False,
                "Aces": [],
                "Links": self._resolve_gpo_links(entry),
                "ChildObjects": self._resolve_child_objects(dd, dn),
                "GPOChanges": {
                    "AffectedComputers": [],
                    "DcomUsers": [],
                    "LocalAdmins": [],
                    "PSRemoteUsers": [],
                    "RemoteDesktopUsers": [],
                },
            }
            self._cache_guid_entry(entry, "OU", name)
            self._apply_acls(ou, entry, "organizational-unit")
            out.append(ou)
        return out

    def _build_containers(self, containers, dd):
        out = []
        for entry in containers or []:
            dn = get_entry_property(entry, "distinguishedName", default="")
            if is_filtered_container(dn):
                continue
            guid = guid_to_string(get_entry_property(entry, "objectGUID", default=None))
            if not guid:
                continue
            dn = dn.upper()
            name = "%s@%s" % (get_entry_property(entry, "name", default="").upper(), self.domain)
            container = {
                "ObjectIdentifier": guid,
                "Properties": {
                    "domain": self.domain,
                    "name": name,
                    "distinguishedname": dn,
                    "domainsid": self.domain_sid,
                    "highvalue": False,
                    "description": get_entry_property(entry, "description", default="") or "",
                    "whencreated": ldap_generalized_time_to_unix(get_entry_property(entry, "whenCreated", default=0)),
                },
                "IsDeleted": False,
                "IsACLProtected": False,
                "Aces": [],
                "ChildObjects": self._resolve_child_objects(dd, dn),
            }
            self._cache_guid_entry(entry, "Container", name)
            self._apply_acls(container, entry, "container")
            out.append(container)
        return out

    def _resolve_entry(self, entry):
        dn = get_entry_property(entry, "distinguishedName", default="")
        if not dn:
            return None

        domain = ldap_to_domain(dn).upper()
        account = get_entry_property(entry, "sAMAccountName", default="")
        sid = sid_to_string(get_entry_property(entry, "objectSid", default=None))
        object_classes = get_object_classes(entry)

        resolved = {
            "objectid": sid,
            "principal": "",
            "type": "Base",
        }

        if not account:
            if "ForeignSecurityPrincipals" in dn and "container" not in object_classes:
                ename = get_entry_property(entry, "name", default="")
                resolved["principal"] = domain
                resolved["type"] = "foreignsecurityprincipal"
                if ename in WELLKNOWN_SIDS:
                    name, sidtype = WELLKNOWN_SIDS[ename]
                    resolved["type"] = sidtype
                    resolved["principal"] = "%s@%s" % (name.upper(), domain)
                    resolved["objectid"] = "%s-%s" % (domain, ename)
                elif ename:
                    resolved["objectid"] = ename
            else:
                guid = get_entry_property(entry, "objectGUID", default=None)
                if guid:
                    if isinstance(guid, bytes):
                        from uuid import UUID
                        resolved["objectid"] = str(UUID(bytes_le=guid)).upper()
                    else:
                        resolved["objectid"] = str(guid).upper().strip("{}")
                name = get_entry_property(entry, "name", default="")
                resolved["principal"] = "%s@%s" % (name.upper(), domain) if name else domain
                if "organizationalunit" in object_classes:
                    resolved["type"] = "OU"
                elif "container" in object_classes:
                    resolved["type"] = "Container"
            return resolved

        if "group" in object_classes:
            resolved["type"] = "Group"
            resolved["principal"] = "%s@%s" % (account.upper(), domain)
        elif "computer" in object_classes:
            resolved["type"] = "Computer"
            resolved["principal"] = "%s.%s" % (account.rstrip("$").upper(), domain)
        elif "user" in object_classes:
            resolved["type"] = "User"
            resolved["principal"] = "%s@%s" % (account.upper(), domain)
        else:
            resolved["type"] = "Base"
            resolved["principal"] = "%s@%s" % (account.upper(), domain)

        if sid in WELLKNOWN_SIDS:
            resolved["objectid"] = "%s-%s" % (domain, sid)

        return resolved

    def _link_from_resolved(self, resolved):
        return {
            "ObjectIdentifier": resolved["objectid"],
            "ObjectType": resolved["type"].capitalize() if resolved["type"] != "OU" else "OU",
        }

    def _resolve_member(self, member_dn):
        member_dn = member_dn.upper()
        if member_dn in self.dncache:
            return self._link_from_resolved(self.dncache[member_dn])
        return None

    def _default_primary_group_rid(self, entry):
        object_classes = get_object_classes(entry)
        if "computer" in object_classes:
            return DEFAULT_PRIMARY_GROUP_RID["computer"]
        if "user" in object_classes:
            return DEFAULT_PRIMARY_GROUP_RID["user"]
        return None

    def _primary_group_sid(self, entry):
        sid = sid_to_string(get_entry_property(entry, "objectSid", default=None))
        if not sid:
            return None
        pgid = get_entry_property(entry, "primaryGroupId", default=None)
        if pgid is None:
            pgid = self._default_primary_group_rid(entry)
        if pgid is None:
            return None
        return "%s-%s" % ("-".join(sid.split("-")[:-1]), int(pgid))

    def _append_group_member(self, groups, group_sid, member_link):
        for group in groups:
            if group.get("ObjectIdentifier") != group_sid:
                continue
            members = group.setdefault("Members", [])
            oid = member_link.get("ObjectIdentifier")
            if oid and not any(m.get("ObjectIdentifier") == oid for m in members):
                members.append(member_link)
            return True
        return False

    def _sync_primary_group_members(self, users, groups, computers):
        """ADWS often omits primaryGroupId; infer defaults and populate builtin groups."""
        domain_users_sid = "%s-%d" % (self.domain_sid, DOMAIN_USERS_GROUP_RID)
        domain_computers_sid = "%s-%d" % (self.domain_sid, DOMAIN_COMPUTERS_GROUP_RID)

        for user in users or []:
            pgsid = user.get("PrimaryGroupSID")
            if pgsid == domain_users_sid:
                self._append_group_member(groups, domain_users_sid, {
                    "ObjectIdentifier": user["ObjectIdentifier"],
                    "ObjectType": "User",
                })

        for computer in computers or []:
            pgsid = computer.get("PrimaryGroupSID")
            if pgsid == domain_computers_sid:
                self._append_group_member(groups, domain_computers_sid, {
                    "ObjectIdentifier": computer["ObjectIdentifier"],
                    "ObjectType": "Computer",
                })

    def _win_timestamp_property(self, entry, attr, default=0):
        value = win_timestamp_to_unix(get_entry_property(entry, attr, default=default))
        if attr == "lastLogonTimestamp" and value == 0:
            return -1
        return value

    def _resolve_sid_link(self, sid):
        if not sid:
            return None
        if sid in WELLKNOWN_SIDS:
            name, sidtype = WELLKNOWN_SIDS[sid]
            return {
                "ObjectIdentifier": "%s-%s" % (self.domain, sid),
                "ObjectType": sidtype.capitalize(),
            }
        resolved = self.sidcache.get(sid)
        if resolved:
            return {
                "ObjectIdentifier": resolved["objectid"],
                "ObjectType": resolved["type"].capitalize() if resolved["type"] != "OU" else "OU",
            }
        return {"ObjectIdentifier": sid, "ObjectType": "Base"}

    def _parse_dacl_principal_sids(self, raw_sd):
        if not raw_sd or not isinstance(raw_sd, (bytes, bytearray)):
            return []
        try:
            sd = SR_SECURITY_DESCRIPTOR(bytes(raw_sd))
        except Exception as exc:
            logger.debug("Failed to parse security descriptor: %s", exc)
            return []
        dacl = sd["Dacl"]
        if not dacl:
            return []
        sids = []
        for ace in dacl.aces:
            if ace["AceType"] not in (0, 5):
                continue
            mask = ace["Ace"]["Mask"]
            mask_val = int(mask["Mask"]) if "Mask" in mask.fields else int(mask)
            if mask_val & GENERIC_ALL_MASK or mask_val & 0x000F01FF == 0x000F01FF:
                sids.append(ace["Ace"]["Sid"].formatCanonical())
        return sids

    def _resolve_allowed_to_act(self, entry):
        raw = get_entry_property(entry, "msDS-AllowedToActOnBehalfOfOtherIdentity", default=None)
        links = []
        seen = set()
        for sid in self._parse_dacl_principal_sids(raw):
            if sid in seen:
                continue
            seen.add(sid)
            link = self._resolve_sid_link(sid)
            if link:
                links.append(link)
        return links

    def _resolve_allowed_to_delegate(self, entry):
        targets = []
        seen = set()
        for host in get_entry_property(entry, "msDS-AllowedToDelegateTo", default=[], as_list=True) or []:
            try:
                target = host.split("/")[1].split(":")[0].lower()
            except IndexError:
                continue
            if target in seen:
                continue
            seen.add(target)
            resolved = self.hostcache.get(target)
            if not resolved:
                sam = target.upper().split(".")[0].split("\\")[0]
                resolved = self.hostcache.get(sam.lower()) or self.hostcache.get("%s$" % sam.lower())
            if resolved:
                targets.append({
                    "ObjectIdentifier": resolved["objectid"],
                    "ObjectType": resolved["type"].capitalize() if resolved["type"] != "OU" else "OU",
                })
        return targets

    def _delegation_hosts(self, entry):
        return list(get_entry_property(entry, "msDS-AllowedToDelegateTo", default=[], as_list=True) or [])

    def _resolve_aces(self, relations):
        resolved = []
        for ace in relations or []:
            sid = ace.get("sid")
            out = {
                "RightName": ace.get("rightname"),
                "IsInherited": ace.get("inherited", False),
            }
            if sid in WELLKNOWN_SIDS:
                out["PrincipalSID"] = "%s-%s" % (self.domain, sid)
                out["PrincipalType"] = WELLKNOWN_SIDS[sid][1].capitalize()
            else:
                link = self._resolve_sid_link(sid)
                out["PrincipalSID"] = sid
                out["PrincipalType"] = link["ObjectType"] if link else "Base"
            resolved.append(out)
        return resolved

    def _apply_acls(self, bh_entry, ldap_entry, entrytype):
        if not self.collect_acl:
            return
        raw = get_entry_property(ldap_entry, "nTSecurityDescriptor", default=None)
        if not raw:
            bh_entry.setdefault("Aces", [])
            self._record_acl_edges([], had_descriptor=False)
            return
        from .acl_parser import parse_binary_acl
        updated, relations = parse_binary_acl(bh_entry, entrytype, raw, self.objecttype_guid_map)
        if "IsACLProtected" in updated:
            bh_entry["IsACLProtected"] = updated["IsACLProtected"]
        bh_entry["Aces"] = self._resolve_aces(relations)
        self._record_acl_edges(bh_entry["Aces"], had_descriptor=True)

    def _apply_gmsa_acls(self, user_obj, entry):
        if not self.collect_acl:
            return
        raw = get_entry_property(entry, "msDS-GroupMSAMembership", default=None)
        if not raw:
            return
        from .acl_parser import parse_binary_acl
        _, aces = parse_binary_acl(user_obj, "user", raw, self.objecttype_guid_map)
        added = []
        for ace in self._resolve_aces(aces):
            if ace["RightName"] == "Owns":
                continue
            ace["RightName"] = "ReadGMSAPassword"
            user_obj.setdefault("Aces", []).append(ace)
            added.append(ace)
        if added:
            self._record_acl_edges(added, had_descriptor=True, count_object=False)

    def _is_highvalue_group(self, sid):
        if any(sid.endswith(suffix) for suffix in HIGHVALUE_GROUP_SUFFIXES):
            return True
        return sid in HIGHVALUE_GROUP_SIDS

    def _user_properties(self, entry, resolved):
        uac = get_int(get_entry_property(entry, "userAccountControl", default=0))
        dn = get_entry_property(entry, "distinguishedName", default="").upper()
        spns = get_entry_property(entry, "servicePrincipalName", default=[], as_list=True)
        if isinstance(spns, str):
            spns = [spns]

        props = {
            "name": resolved["principal"],
            "domain": self.domain,
            "domainsid": self.domain_sid,
            "distinguishedname": dn,
            "unconstraineddelegation": bool(uac & 0x00080000),
            "trustedtoauth": bool(uac & 0x01000000),
            "passwordnotreqd": bool(uac & 0x00000020),
            "enabled": uac & 2 == 0,
            "lastlogon": self._win_timestamp_property(entry, "lastLogon"),
            "lastlogontimestamp": self._win_timestamp_property(entry, "lastLogonTimestamp"),
            "pwdlastset": win_timestamp_to_unix(get_entry_property(entry, "pwdLastSet", default=0)),
            "dontreqpreauth": bool(uac & 0x00400000),
            "pwdneverexpires": bool(uac & 0x00010000),
            "sensitive": bool(uac & 0x00100000),
            "serviceprincipalnames": spns,
            "hasspn": len(spns) > 0,
            "description": get_entry_property(entry, "description", default=None) or None,
            "admincount": False,
            "whencreated": ldap_generalized_time_to_unix(get_entry_property(entry, "whenCreated", default=0)),
            "samaccountname": get_entry_property(entry, "sAMAccountName", default=""),
        }
        return props

    def _build_users(self, users):
        out = []
        for entry in users or []:
            resolved = self._resolve_entry(entry)
            if not resolved or resolved["type"] == "trustaccount":
                continue
            sid = sid_to_string(get_entry_property(entry, "objectSid", default=None))
            if not sid:
                continue
            props = self._user_properties(entry, resolved)
            deleg_hosts = self._delegation_hosts(entry)
            if deleg_hosts:
                props["allowedtodelegate"] = deleg_hosts
            user_obj = {
                "AllowedToDelegate": self._resolve_allowed_to_delegate(entry),
                "ObjectIdentifier": sid,
                "PrimaryGroupSID": self._primary_group_sid(entry),
                "Properties": props,
                "Aces": [],
                "SPNTargets": [],
                "HasSIDHistory": [],
                "IsDeleted": False,
                "IsACLProtected": False,
            }
            self._apply_acls(user_obj, entry, "user")
            self._apply_gmsa_acls(user_obj, entry)
            out.append(user_obj)
        return out

    def _build_groups(self, groups):
        out = []
        for entry in groups or []:
            sid = sid_to_string(get_entry_property(entry, "objectSid", default=None))
            if not sid:
                continue
            resolved = self._resolve_entry(entry)
            if not resolved:
                continue

            object_id = sid
            if sid in WELLKNOWN_SIDS:
                object_id = "%s-%s" % (self.domain, sid)

            members = []
            for member_dn in get_entry_property(entry, "member", default=[], as_list=True):
                link = self._resolve_member(member_dn)
                if link:
                    members.append(link)

            group = {
                "ObjectIdentifier": object_id,
                "Properties": {
                    "domain": self.domain,
                    "domainsid": self.domain_sid,
                    "highvalue": self._is_highvalue_group(sid),
                    "name": resolved["principal"],
                    "distinguishedname": get_entry_property(entry, "distinguishedName", default="").upper(),
                    "description": get_entry_property(entry, "description", default=None) or None,
                    "samaccountname": get_entry_property(entry, "sAMAccountName", default=""),
                    "admincount": False,
                    "whencreated": ldap_generalized_time_to_unix(get_entry_property(entry, "whenCreated", default=0)),
                },
                "Members": members,
                "Aces": [],
                "IsDeleted": False,
                "IsACLProtected": False,
            }
            self._apply_acls(group, entry, "group")
            out.append(group)
        return out

    def _empty_collection(self):
        return {"Collected": False, "FailureReason": None, "Results": []}

    def _build_computers(self, computers):
        out = []
        for entry in computers or []:
            sid = sid_to_string(get_entry_property(entry, "objectSid", default=None))
            if not sid:
                continue
            resolved = self._resolve_entry(entry)
            if not resolved:
                continue

            hostname = get_entry_property(entry, "dNSHostName", default="")
            if not hostname:
                sam = get_entry_property(entry, "sAMAccountName", default="")
                hostname = "%s.%s" % (sam.rstrip("$").upper(), self.domain) if sam else resolved["principal"]

            uac = get_int(get_entry_property(entry, "userAccountControl", default=0))
            osname = get_entry_property(entry, "operatingSystem", default="")
            ossp = get_entry_property(entry, "operatingSystemServicePack", default="")
            osver = get_entry_property(entry, "operatingSystemVersion", default="")

            deleg_hosts = self._delegation_hosts(entry)
            computer = {
                "ObjectIdentifier": sid,
                "AllowedToAct": self._resolve_allowed_to_act(entry),
                "PrimaryGroupSID": self._primary_group_sid(entry),
                "LocalAdmins": self._empty_collection(),
                "PSRemoteUsers": self._empty_collection(),
                "Properties": {
                    "name": hostname.upper(),
                    "domainsid": self.domain_sid,
                    "domain": self.domain,
                    "distinguishedname": get_entry_property(entry, "distinguishedName", default="").upper(),
                    "unconstraineddelegation": bool(uac & 0x00080000),
                    "enabled": uac & 2 == 0,
                    "trustedtoauth": bool(uac & 0x01000000),
                    "samaccountname": get_entry_property(entry, "sAMAccountName", default=""),
                    "lastlogon": self._win_timestamp_property(entry, "lastLogon"),
                    "lastlogontimestamp": self._win_timestamp_property(entry, "lastLogonTimestamp"),
                    "pwdlastset": win_timestamp_to_unix(get_entry_property(entry, "pwdLastSet", default=0)),
                    "whencreated": ldap_generalized_time_to_unix(get_entry_property(entry, "whenCreated", default=0)),
                    "serviceprincipalnames": get_entry_property(entry, "servicePrincipalName", default=[], as_list=True) or [],
                    "description": get_entry_property(entry, "description", default=None) or None,
                    "operatingsystem": "%s %s" % (osname, ossp) if ossp else osname,
                    "operatingsystemname": osname,
                    "operatingsystemservicepack": ossp,
                    "operatingsystemversion": osver,
                    "haslaps": False,
                },
                "RemoteDesktopUsers": self._empty_collection(),
                "DcomUsers": self._empty_collection(),
                "AllowedToDelegate": self._resolve_allowed_to_delegate(entry),
                "Sessions": self._empty_collection(),
                "PrivilegedSessions": self._empty_collection(),
                "RegistrySessions": self._empty_collection(),
                "Aces": [],
                "HasSIDHistory": [],
                "IsDeleted": False,
                "IsACLProtected": False,
                "Status": None,
            }
            if deleg_hosts:
                computer["Properties"]["allowedtodelegate"] = deleg_hosts
            self._apply_acls(computer, entry, "computer")
            out.append(computer)
        return out

    def _trust_to_output(self, trust_entry):
        flags = get_int(get_entry_property(trust_entry, "trustAttributes", default=0))
        direction = get_int(get_entry_property(trust_entry, "trustDirection", default=0))
        target_name = get_entry_property(trust_entry, "name", default="")
        target_sid = sid_to_string(get_entry_property(trust_entry, "securityIdentifier", default=None))

        trusttype = "Unknown"
        is_transitive = False
        sid_filtering = True

        if flags & TRUST_FLAGS["WITHIN_FOREST"] == TRUST_FLAGS["WITHIN_FOREST"]:
            trusttype = "ParentChild"
            is_transitive = True
            sid_filtering = bool(flags & TRUST_FLAGS["QUARANTINED_DOMAIN"])
        elif flags & TRUST_FLAGS["FOREST_TRANSITIVE"] == TRUST_FLAGS["FOREST_TRANSITIVE"]:
            trusttype = "Forest"
            is_transitive = True
            sid_filtering = not bool(flags & TRUST_FLAGS["TREAT_AS_EXTERNAL"])
        elif flags & TRUST_FLAGS["TREAT_AS_EXTERNAL"] or flags & TRUST_FLAGS["CROSS_ORGANIZATION"]:
            trusttype = "External"
            is_transitive = False
            sid_filtering = True
        else:
            is_transitive = not bool(flags & TRUST_FLAGS["NON_TRANSITIVE"])

        return {
            "TargetDomainName": target_name.upper(),
            "TargetDomainSid": target_sid,
            "IsTransitive": is_transitive,
            "TrustDirection": direction,
            "TrustType": BH_TRUST_TYPE.get(trusttype, 4),
            "SidFilteringEnabled": sid_filtering,
        }

    def _build_domains(self, policy_entries, trust_entries, computers, dd=None):
        domain_entry = policy_entries[0] if policy_entries else None
        if domain_entry:
            dn = get_entry_property(domain_entry, "distinguishedName", default="")
            description = get_entry_property(domain_entry, "description", default="") or ""
            whencreated = ldap_generalized_time_to_unix(get_entry_property(domain_entry, "whenCreated", default=0))
            level_id = get_int(get_entry_property(domain_entry, "msDS-Behavior-Version", default=-1), -1)
            functional_level = FUNCTIONAL_LEVELS.get(level_id, "Unknown")
        else:
            dn = "DC=%s" % ",DC=".join(self.domain.split("."))
            description = ""
            whencreated = 0
            functional_level = "Unknown"
            domain_entry = None

        trusts = [self._trust_to_output(t) for t in (trust_entries or [])]

        domain = {
            "ObjectIdentifier": self.domain_sid,
            "Properties": {
                "name": self.domain,
                "domain": self.domain,
                "domainsid": self.domain_sid,
                "distinguishedname": dn.upper(),
                "description": description,
                "functionallevel": functional_level,
                "highvalue": True,
                "whencreated": whencreated,
            },
            "Trusts": trusts,
            "Aces": [],
            "Links": self._resolve_gpo_links(domain_entry) if domain_entry else [],
            "ChildObjects": self._resolve_child_objects(dd, dn.upper()) if dd else [],
            "GPOChanges": {
                "AffectedComputers": [],
                "DcomUsers": [],
                "LocalAdmins": [],
                "PSRemoteUsers": [],
                "RemoteDesktopUsers": [],
            },
            "IsDeleted": False,
            "IsACLProtected": False,
        }
        if domain_entry:
            self._apply_acls(domain, domain_entry, "domain")
        return [domain]

    def _default_users(self):
        return [{
            "AllowedToDelegate": [],
            "ObjectIdentifier": "%s-S-1-5-20" % self.domain,
            "PrimaryGroupSID": None,
            "Properties": {
                "domain": self.domain,
                "domainsid": self.domain_sid,
                "name": "NT AUTHORITY@%s" % self.domain,
            },
            "Aces": [],
            "SPNTargets": [],
            "HasSIDHistory": [],
            "IsDeleted": False,
            "IsACLProtected": False,
        }]

    def _default_groups(self, computers):
        dc_members = []
        for entry in computers or []:
            dn = get_entry_property(entry, "distinguishedName", default="")
            if "OU=DOMAIN CONTROLLERS," not in dn.upper():
                continue
            resolved = self._resolve_entry(entry)
            if resolved:
                dc_members.append(self._link_from_resolved(resolved))

        return [
            {
                "IsDeleted": False,
                "IsACLProtected": False,
                "ObjectIdentifier": "%s-S-1-5-9" % self.domain,
                "Properties": {
                    "domain": self.domain,
                    "name": "ENTERPRISE DOMAIN CONTROLLERS@%s" % self.domain,
                },
                "Members": dc_members,
                "Aces": [],
            },
            {
                "IsDeleted": False,
                "IsACLProtected": False,
                "ObjectIdentifier": "%s-S-1-1-0" % self.domain,
                "Properties": {
                    "domain": self.domain,
                    "domainsid": self.domain_sid,
                    "name": "EVERYONE@%s" % self.domain,
                },
                "Members": [],
                "Aces": [],
            },
            {
                "IsDeleted": False,
                "IsACLProtected": False,
                "ObjectIdentifier": "%s-S-1-5-11" % self.domain,
                "Properties": {
                    "domain": self.domain,
                    "domainsid": self.domain_sid,
                    "name": "AUTHENTICATED USERS@%s" % self.domain,
                },
                "Members": [],
                "Aces": [],
            },
            {
                "IsDeleted": False,
                "IsACLProtected": False,
                "ObjectIdentifier": "%s-S-1-5-4" % self.domain,
                "Properties": {
                    "domain": self.domain,
                    "domainsid": self.domain_sid,
                    "name": "INTERACTIVE@%s" % self.domain,
                },
                "Members": [],
                "Aces": [],
            },
        ]
