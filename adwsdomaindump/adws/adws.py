"""
Standalone ADWS implementation - adapted from Soaphound
"""
import datetime
import logging
import socket
from base64 import b64decode
from enum import IntFlag
from typing import Self, Type
from uuid import UUID, uuid4
from xml.etree import ElementTree

from impacket.ldap.ldaptypes import (
    ACCESS_ALLOWED_ACE,
    ACCESS_ALLOWED_CALLBACK_ACE,
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE,
    ACCESS_ALLOWED_OBJECT_ACE,
    LDAP_SID,
    SR_SECURITY_DESCRIPTOR,
    SYSTEM_MANDATORY_LABEL_ACE,
)
from pyasn1.type.useful import GeneralizedTime

from .ms_nmf import NMFConnection
from .ms_nns import NNS
from .soap_templates import (
    LDAP_PULL_FSTRING,
    LDAP_PUT_FSTRING,
    LDAP_QUERY_FSTRING,
    NAMESPACES,
    LDAP_ROOT_DSE_FSTRING,
)

# --- Enums and Constants ---
class SystemFlags(IntFlag):
    NONE = 0x00000000
    NO_REPLICATION = 0x00000001
    REPLICATE_TO_GC = 0x00000002
    CONSTRUCTED = 0x00000004
    CATEGORY_1 = 0x00000010
    NOT_DELETED = 0x02000000
    CANNOT_MOVE = 0x04000000
    CANNOT_RENAME = 0x08000000
    MOVED_WITH_RESTRICTIONS = 0x10000000
    MOVED = 0x20000000
    RENAMED = 0x40000000
    CANNOT_DELETE = 0x80000000

class InstanceTypeFlags(IntFlag):
    HEAD_OF_NAMING_CONTEXT = 0x00000001
    REPLICA_NOT_INSTANTIATED = 0x00000002
    OBJECT_WRITABLE = 0x00000004
    NAMING_CONTEXT_HELD = 0x00000008
    CONSTRUCTING_NAMING_CONTEXT = 0x00000010
    REMOVING_NAMING_CONTEXT = 0x00000020

class GroupTypeFlags(IntFlag):
    SYSTEM_GROUP = 0x00000001
    GLOBAL_SCOPE = 0x00000002
    DOMAIN_LOCAL_SCOPE = 0x00000004
    UNIVERSAL_SCOPE = 0x00000008
    APP_BASIC_GROUP = 0x00000010
    APP_QUERY_GROUP = 0x00000020
    SECURITY_GROUP = 0x80000000

class AccountPropertyFlag(IntFlag):
    SCRIPT = 0x0001
    ACCOUNTDISABLE = 0x0002
    HOMEDIR_REQUIRED = 0x0008
    LOCKOUT = 0x0010
    PASSWD_NOTREQD = 0x0020
    PASSWD_CANT_CHANGE = 0x0040
    ENCRYPTED_TEXT_PWD_ALLOWED = 0x0080
    TEMP_DUPLICATE_ACCOUNT = 0x0100
    NORMAL_ACCOUNT = 0x0200
    INTERDOMAIN_TRUST_ACCOUNT = 0x0800
    WORKSTATION_TRUST_ACCOUNT = 0x1000
    SERVER_TRUST_ACCOUNT = 0x2000
    DONT_EXPIRE_PASSWORD = 0x10000
    MNS_LOGON_ACCOUNT = 0x20000
    SMARTCARD_REQUIRED = 0x40000
    TRUSTED_FOR_DELEGATION = 0x80000
    NOT_DELEGATED = 0x100000
    USE_DES_KEY_ONLY = 0x200000
    DONT_REQ_PREAUTH = 0x400000
    PASSWORD_EXPIRED = 0x800000
    TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000
    PARTIAL_SECRETS_ACCOUNT = 0x04000000

class SamAccountType(IntFlag):
    SAM_DOMAIN_OBJECT = 0x00000000
    SAM_GROUP_OBJECT = 0x10000000
    SAM_NON_SECURITY_GROUP_OBJECT = 0x10000001
    SAM_ALIAS_OBJECT = 0x20000000
    SAM_NON_SECURITY_ALIAS_OBJECT = 0x20000001
    SAM_USER_OBJECT = 0x30000000
    SAM_MACHINE_ACCOUNT = 0x30000001
    SAM_TRUST_ACCOUNT = 0x30000002
    SAM_APP_BASIC_GROUP = 0x40000000
    SAM_APP_QUERY_GROUP = 0x40000001

BUILT_IN_GROUPS = {
    "498": "Enterprise Read-Only Domain Controllers", "512": "Domain Admins",
    "513": "Domain Users", "514": "Domain Guests", "515": "Domain Computers",
    "516": "Domain Controllers", "517": "Cert Publishers", "518": "Schema Admins",
    "519": "Enterprise Admins", "520": "Group Policy Creator Owners",
    "521": "Read-Only Domain Controllers", "522": "Cloneable Controllers",
    "525": "Protected Users", "526": "Key Admins", "527": "Enterprise Key Admins",
    "553": "RAS and IAS Servers", "571": "Allowed RODC Password Replication Group",
    "572": "Denied RODC Password Replication Group",
}
WELL_KNOWN_SIDS = {
    "S-1-0": "Null Authority", "S-1-0-0": "Nobody", "S-1-1": "World Authority", "S-1-1-0": "Everyone",
    "S-1-2": "Local Authority", "S-1-2-0": "Local", "S-1-2-1": "Console Logon",
    "S-1-3": "Creator Authority", "S-1-3-0": "Creator Owner", "S-1-3-1": "Creator Group",
    "S-1-3-2": "Creator Owner Server", "S-1-3-3": "Creator Group Server", "S-1-3-4": "Owner Rights",
    "S-1-5-80-0": "All Services", "S-1-4": "Non-unique Authority", "S-1-5": "NT Authority",
    "S-1-5-1": "Dialup", "S-1-5-2": "Network", "S-1-5-3": "Batch", "S-1-5-4": "Interactive",
    "S-1-5-6": "Service", "S-1-5-7": "Anonymous", "S-1-5-8": "Proxy",
    "S-1-5-9": "Enterprise Domain Controllers", "S-1-5-10": "Principal Self",
    "S-1-5-11": "Authenticated Users", "S-1-5-12": "Restricted Code", "S-1-5-13": "Terminal Server Users",
    "S-1-5-14": "Remote Interactive Logon", "S-1-5-15": "This Organization", "S-1-5-17": "This Organization",
    "S-1-5-18": "Local System", "S-1-5-19": "NT Authority", "S-1-5-20": "NT Authority",
    "S-1-5-32-544": "Administrators", "S-1-5-32-545": "Users", "S-1-5-32-546": "Guests",
    "S-1-5-32-547": "Power Users", "S-1-5-32-548": "Account Operators", "S-1-5-32-549": "Server Operators",
    "S-1-5-32-550": "Print Operators", "S-1-5-32-551": "Backup Operators", "S-1-5-32-552": "Replicators",
    "S-1-5-64-10": "NTLM Authentication", "S-1-5-64-14": "SChannel Authentication", "S-1-5-64-21": "Digest Authority",
    "S-1-5-80": "NT Service", "S-1-5-83-0": "NT VIRTUAL MACHINE\\Virtual Machines",
    "S-1-16-0": "Untrusted Mandatory Level", "S-1-16-4096": "Low Mandatory Level",
    "S-1-16-8192": "Medium Mandatory Level", "S-1-16-8448": "Medium Plus Mandatory Level",
    "S-1-16-12288": "High Mandatory Level", "S-1-16-16384": "System Mandatory Level",
    "S-1-16-20480": "Protected Process Mandatory Level", "S-1-16-28672": "Secure Process Mandatory Level",
    "S-1-5-32-554": "BUILTIN\\Pre-Windows 2000 Compatible Access", "S-1-5-32-555": "BUILTIN\\Remote Desktop Users",
    "S-1-5-32-557": "BUILTIN\\Incoming Forest Trust Builders", "S-1-5-32-556": "BUILTIN\\Network Configuration Operators",
    "S-1-5-32-558": "BUILTIN\\Performance Monitor Users", "S-1-5-32-559": "BUILTIN\\Performance Log Users",
    "S-1-5-32-560": "BUILTIN\\Windows Authorization Access Group", "S-1-5-32-561": "BUILTIN\\Terminal Server License Servers",
    "S-1-5-32-562": "BUILTIN\\Distributed COM Users", "S-1-5-32-569": "BUILTIN\\Cryptographic Operators",
    "S-1-5-32-573": "BUILTIN\\Event Log Readers", "S-1-5-32-574": "BUILTIN\\Certificate Service DCOM Access",
    "S-1-5-32-575": "BUILTIN\\RDS Remote Access Servers", "S-1-5-32-576": "BUILTIN\\RDS Endpoint Servers",
    "S-1-5-32-577": "BUILTIN\\RDS Management Servers", "S-1-5-32-578": "BUILTIN\\Hyper-V Administrators",
    "S-1-5-32-579": "BUILTIN\\Access Control Assistance Operators", "S-1-5-32-580": "BUILTIN\\Remote Management Users",
}

class ADWSError(Exception): ...
class ADWSAuthType: ...

class NTLMAuth(ADWSAuthType):
    def __init__(self, password: str | None = None, hashes: str | None = None):
        if not (password or hashes):
            raise ValueError("NTLM auth requires either a password or hashes.")
        if password and hashes:
            raise ValueError("Provide either a password or hashes, not both.")
        self.nt = hashes if hashes else None
        self.password = password

class ADWSConnect:
    def __init__(self, fqdn: str, domain: str, username: str, auth: NTLMAuth, resource: str ):
        self._fqdn = fqdn
        self._domain = domain
        self._username = username
        self._auth = auth
        self._resource: str = resource
        self._nmf: NMFConnection = self._connect(self._fqdn, self._resource)

    def _create_NNS_from_auth(self, sock: socket.socket) -> NNS:
        if isinstance(self._auth, NTLMAuth):
            return NNS(socket=sock, fqdn=self._fqdn, domain=self._domain, username=self._username,
                       password=self._auth.password, nt=self._auth.nt if self._auth.nt else "")
        raise NotImplementedError("Authentication type not supported")

    def _connect(self, remoteName: str, resource: str) -> NMFConnection:
        server_address: tuple[str, int] = (remoteName, 9389)
        logging.debug(f"Connecting to {remoteName}:{server_address[1]} for ADWS {self._resource} endpoint")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect(server_address)
        except Exception as e:
            logging.error(f"Failed to connect to {remoteName}:{server_address[1]}: {e}")
            raise ADWSError(f"Connection failed: {e}")

        nmf = NMFConnection(self._create_NNS_from_auth(sock), fqdn=remoteName)
        try:
            nmf.connect(f"Windows/{resource}")
        except Exception as e:
            logging.error(f"NMF connection to resource 'Windows/{resource}' failed: {e}")
            sock.close()
            raise ADWSError(f"NMF connection failed: {e}")
        return nmf

    def get_root_domain_dn(self, fqdn: str) -> str:
        """
        Transforms an FQDN (e.g., sub1.sub.tld) into the root domain DN (e.g., DC=sub,DC=tld)
        """
        parts = fqdn.split('.')
        root = parts[-2:]
        dn = ','.join(f"DC={p}" for p in root)
        return dn

    def _query_enumeration(
        self, remoteName: str, nmf: NMFConnection, query: str, attributes: list,
        base_object_dn_for_soap: str | None = None, use_schema=False, schema_dn: str | None = None
    ) -> str | None:
        fAttributes: str = "".join([f"<ad:SelectionProperty>addata:{attr}</ad:SelectionProperty>\n" for attr in attributes])

        if use_schema:
            if schema_dn is not None:
                effective_base_obj = schema_dn
            else:
                forest_dn = self.get_root_domain_dn(self._domain)
                effective_base_obj = f"CN=Schema,CN=Configuration,{forest_dn}"
        else:
            effective_base_obj = base_object_dn_for_soap if base_object_dn_for_soap else ",".join([f"DC={i}" for i in self._domain.split(".")])

        query_vars = {
            "uuid": str(uuid4()), "fqdn": remoteName, "query": query,
            "attributes": fAttributes, "baseobj": effective_base_obj,
        }
        enumeration_request_soap = LDAP_QUERY_FSTRING.format(**query_vars)

        nmf.send(enumeration_request_soap)
        enumerationResponse = nmf.recv()

        et = self._handle_str_to_xml(enumerationResponse)
        if et is None:
            logging.error("Failed to parse XML from enumeration response.")
            return None

        enum_ctx_elem = et.find(".//wsen:EnumerationContext", NAMESPACES)
        if enum_ctx_elem is None or enum_ctx_elem.text is None:
            logging.error("No EnumerationContext found in the server response.")
            if enumerationResponse and len(enumerationResponse) < 1000:
                logging.debug(f"Full Enumeration Response without context: {enumerationResponse}")
            return None
        return enum_ctx_elem.text

    def get_rootdse_contexts(self, remoteName: str, nmf: NMFConnection) -> dict:
        """
        Gets key contexts from RootDSE in a single Resource request.
        Returns a dict with fields:
        - schemaNamingContext
        - rootDomainNamingContext
        - configurationNamingContext
        - defaultNamingContext
        - namingContexts (list)
        All values are strings (or list of strings for namingContexts).
        """
        from xml.etree import ElementTree as ET
        from uuid import uuid4

        req = {
            "uuid": str(uuid4()),
            "fqdn": remoteName,
        }
        soap_request = LDAP_ROOT_DSE_FSTRING.format(**req)

        nmf.send(soap_request)
        response = nmf.recv()

        try:
            et = ET.fromstring(response)
        except Exception as e:
            raise RuntimeError(f"Error parsing RootDSE: {e}\nRaw response: {response[:500]}")

        NAMESPACES_LOCAL = {
            'addata': "http://schemas.microsoft.com/2008/1/ActiveDirectory/Data",
            'ad': "http://schemas.microsoft.com/2008/1/ActiveDirectory",
        }

        def getval(xpath):
            val_elem = et.find(xpath, namespaces=NAMESPACES_LOCAL)
            return val_elem.text.strip() if val_elem is not None and val_elem.text else None

        def getvals(xpath):
            return [
                v.text.strip()
                for v in et.findall(xpath, namespaces=NAMESPACES_LOCAL)
                if v is not None and v.text
            ]

        return {
            "schemaNamingContext": getval(".//addata:schemaNamingContext/ad:value"),
            "rootDomainNamingContext": getval(".//addata:rootDomainNamingContext/ad:value"),
            "configurationNamingContext": getval(".//addata:configurationNamingContext/ad:value"),
            "defaultNamingContext": getval(".//addata:defaultNamingContext/ad:value"),
            "namingContexts": getvals(".//addata:namingContexts/ad:value"),
            "domainFunctionality": getvals(".//addata:domainFunctionality/ad:value"),
            "forestFunctionality": getval(".//addata:forestFunctionality/ad:value")
        }

    def _pull_results(self, remoteName: str, nmf: NMFConnection, enum_ctx: str) -> tuple[ElementTree.Element | None, bool]:
        pull_vars = {"uuid": str(uuid4()), "fqdn": remoteName, "enum_ctx": enum_ctx}
        pull_request_soap = LDAP_PULL_FSTRING.format(**pull_vars)

        nmf.send(pull_request_soap)
        pullResponse = nmf.recv()

        et = self._handle_str_to_xml(pullResponse)
        if et is None:
            logging.error(f"Failed to parse XML from pull response for context: {enum_ctx}")
            return (None, False)

        final_pkt = et.find(".//wsen:EndOfSequence", namespaces=NAMESPACES)
        return (et, final_pkt is None)  # True if more results (EndOfSequence NOT found)

    def _handle_str_to_xml(self, xmlstr: str) -> ElementTree.Element | None:
        if not xmlstr:
            logging.error("Received empty XML string from server.")
            return None
        try:
            parsed_et = ElementTree.fromstring(xmlstr)

            # Explicitly check for SOAP fault
            fault_node_s = parsed_et.find(f".//{{{NAMESPACES['s']}}}Fault")
            fault_node_soapenv = parsed_et.find(f".//{{{NAMESPACES['soapenv']}}}Fault")
            fault_node = fault_node_s if fault_node_s is not None else fault_node_soapenv

            if fault_node is not None:
                reason_text_s = fault_node.findtext(f".//{{{NAMESPACES['s']}}}Reason/{{{NAMESPACES['s']}}}Text")
                reason_text_soapenv = fault_node.findtext(f".//{{{NAMESPACES['soapenv']}}}Reason/{{{NAMESPACES['soapenv']}}}Text")
                reason = reason_text_s or reason_text_soapenv or "Unknown SOAP Fault reason"

                detail_node_s = fault_node.find(f".//{{{NAMESPACES['s']}}}Detail")
                detail_node_soapenv = fault_node.find(f".//{{{NAMESPACES['soapenv']}}}Detail")
                detail_node = detail_node_s if detail_node_s is not None else detail_node_soapenv
                detail_text = ElementTree.tostring(detail_node, encoding='unicode').strip() if detail_node is not None else "No detail"

                logging.error(f"SOAP Fault received: {reason}\nDetail: {detail_text}")
                return None

            return parsed_et
        except ElementTree.ParseError as e_parse:
            logging.error(f"XML ParseError in _handle_str_to_xml: {e_parse}. XML (first 500 chars): {xmlstr[:500]}")
            if ":Text" in xmlstr:
                start_tag_search = xmlstr.find(":Text>")
                if start_tag_search != -1:
                    starttag = start_tag_search + len(":Text>")
                    endtag = xmlstr.find("</", starttag)
                    if endtag != -1:
                        fault_text = xmlstr[starttag: endtag]
                        logging.error(f"Manually extracted text (possibly fault): {fault_text.strip()}")
            return None

    def pull(
        self, query: str, attributes: list,
        print_incrementally: bool = False,
        base_object_dn_for_soap: str | None = None, use_schema=False
    ) -> ElementTree.Element | None:
        if self._resource != "Enumeration":
            raise NotImplementedError("Pull is only supported on 'pull' (Enumeration) clients")
        if use_schema:
            enum_ctx = self._query_enumeration(
                remoteName=self._fqdn, nmf=self._nmf, query=query,
                attributes=attributes, base_object_dn_for_soap=base_object_dn_for_soap, use_schema=True
            )
        else:
            enum_ctx = self._query_enumeration(
                remoteName=self._fqdn, nmf=self._nmf, query=query,
                attributes=attributes, base_object_dn_for_soap=base_object_dn_for_soap
            )
        if enum_ctx is None:
            return None

        ElementTree.register_namespace("wsen", NAMESPACES["wsen"])
        aggregated_items_root = ElementTree.Element(f"{{{NAMESPACES['wsen']}}}Items")

        more_results_expected = True
        batches_processed = 0
        total_items_in_all_batches = 0

        while more_results_expected:
            batches_processed += 1
            logging.debug(f"Pulling batch {batches_processed} for context {enum_ctx[:20]}...")

            batch_xml_response_et, more_results_expected = self._pull_results(
                remoteName=self._fqdn, nmf=self._nmf, enum_ctx=enum_ctx
            )

            if batch_xml_response_et is None:
                logging.error(f"Error occurred while pulling batch {batches_processed}. Aborting pull for this context.")
                break

            items_in_batch_container = batch_xml_response_et.find(".//wsen:Items", NAMESPACES)

            current_batch_item_count = 0
            if items_in_batch_container is not None:
                for actual_ad_object_element in list(items_in_batch_container):
                    aggregated_items_root.append(actual_ad_object_element)
                    current_batch_item_count += 1
                total_items_in_all_batches += current_batch_item_count

            logging.debug(f"Batch {batches_processed} contained {current_batch_item_count} items. More results expected: {more_results_expected}")

        if total_items_in_all_batches == 0:
            logging.debug(f"Query '{query}' with base '{base_object_dn_for_soap or self._domain}' resulted in 0 objects collected overall.")
        else:
            logging.debug(f"Finished pulling all batches for query '{query}'. Total items aggregated: {total_items_in_all_batches}")

        return aggregated_items_root

    @classmethod
    def pull_client(cls, ip: str, domain: str, username: str, auth: NTLMAuth) -> Self:
        return cls(ip, domain, username, auth, "Enumeration")

    @classmethod
    def put_client(cls, ip: str, domain: str, username: str, auth: NTLMAuth) -> Self:
        return cls(ip, domain, username, auth, "Resource")

