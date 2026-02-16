"""
ADWS wrapper to replace LDAP functionality
This module provides a compatibility layer that mimics ldap3's Connection and Entry classes
but uses ADWS (Active Directory Web Services) instead of LDAP.
"""
import sys
import os
import base64
from xml.etree import ElementTree
from uuid import UUID
from datetime import datetime
from typing import List, Optional, Any
import logging

# Use local standalone ADWS implementation
try:
    from .adws import ADWSConnect, NTLMAuth, ADWSError, NAMESPACES, KNOWN_BINARY_ADWS_ATTRIBUTES
    from impacket.ldap.ldaptypes import LDAP_SID
except ImportError as e:
    raise ImportError(f"Failed to import ADWS modules: {e}")

logger = logging.getLogger(__name__)


class ADWSEntry:
    """
    Mimics ldap3 Entry class for compatibility with existing code
    """
    def __init__(self, xml_element: ElementTree.Element, attributes: List[str]):
        self._xml_element = xml_element
        self._attributes = {}
        self._parse_xml_element(attributes)
    
    def _parse_xml_element(self, requested_attributes: List[str]):
        """Parse XML element and extract attribute values"""
        for attr_name in requested_attributes:
            attr_name_lower = attr_name.lower()
            # Try original case first
            attr_elems = self._xml_element.findall(f".//addata:{attr_name}/ad:value", namespaces=NAMESPACES)
            if not attr_elems and attr_name != attr_name_lower:
                # Try lowercase
                attr_elems = self._xml_element.findall(f".//addata:{attr_name_lower}/ad:value", namespaces=NAMESPACES)
            
            if attr_elems:
                values = []
                for val_elem in attr_elems:
                    if val_elem.text is None:
                        continue
                    is_b64_by_type = val_elem.attrib.get('{http://www.w3.org/2001/XMLSchema-instance}type') == 'ad:base64Binary'
                    if is_b64_by_type or attr_name_lower in KNOWN_BINARY_ADWS_ATTRIBUTES:
                        if isinstance(val_elem.text, str):
                            try:
                                values.append(base64.b64decode(val_elem.text))
                            except Exception:
                                values.append(val_elem.text)
                        else:
                            values.append(val_elem.text)
                    else:
                        values.append(val_elem.text)
                
                if values:
                    # Store as single value if only one, otherwise as list
                    if len(values) == 1:
                        self._attributes[attr_name] = ADWSAttribute(attr_name, values[0])
                    else:
                        self._attributes[attr_name] = ADWSAttribute(attr_name, values)
        
        # Always try to get distinguishedName and objectClass
        if 'distinguishedName' not in self._attributes:
            dn_elem = self._xml_element.find(".//addata:distinguishedName/ad:value", namespaces=NAMESPACES)
            if dn_elem is not None and dn_elem.text is not None:
                self._attributes['distinguishedName'] = ADWSAttribute('distinguishedName', dn_elem.text)
        
        if 'objectClass' not in self._attributes:
            oc_vals = [oc.text for oc in self._xml_element.findall(".//addata:objectClass/ad:value", namespaces=NAMESPACES) if oc.text]
            if oc_vals:
                self._attributes['objectClass'] = ADWSAttribute('objectClass', oc_vals if len(oc_vals) > 1 else oc_vals[0])
    
    def __getitem__(self, key):
        """Allow dictionary-like access"""
        if key in self._attributes:
            return self._attributes[key]
        raise KeyError(f"Attribute '{key}' not found")
    
    def __contains__(self, key):
        """Check if attribute exists"""
        return key in self._attributes
    
    def get(self, key, default=None):
        """Get attribute with default"""
        return self._attributes.get(key, default)
    
    def entry_to_json(self):
        """Convert entry to JSON string (mimics ldap3)"""
        import json
        result = {}
        for key, attr in self._attributes.items():
            if isinstance(attr, ADWSAttribute):
                result[key] = attr.value if not isinstance(attr.value, bytes) else base64.b64encode(attr.value).decode('ascii')
            else:
                result[key] = attr
        return json.dumps(result)


class ADWSAttribute:
    """
    Mimics ldap3 Attribute class
    """
    def __init__(self, key: str, value: Any):
        self.key = key
        self._value = value
        self._raw_values = [value] if not isinstance(value, list) else value
    
    @property
    def value(self):
        """Get single value (first if list)"""
        if isinstance(self._value, list):
            return self._value[0] if self._value else None
        return self._value
    
    @property
    def values(self):
        """Get all values as list"""
        if isinstance(self._value, list):
            return self._value
        return [self._value]
    
    @property
    def raw_values(self):
        """Get raw values"""
        return self._raw_values


class ADWSServer:
    """
    Mimics ldap3 Server class for compatibility
    """
    def __init__(self, host: str, domain: str):
        self.host = host
        self.domain = domain
        self.info = ADWSServerInfo(domain)
    
    def __repr__(self):
        return f"ADWSServer(host={self.host}, domain={self.domain})"


class ADWSServerInfo:
    """
    Mimics ldap3 Server.info for compatibility
    """
    def __init__(self, domain: str):
        self.other = {
            'defaultNamingContext': [f"DC={',DC='.join(domain.split('.'))}"]
        }


class ADWSConnection:
    """
    Mimics ldap3 Connection class but uses ADWS
    """
    def __init__(self, server: ADWSServer, user: Optional[str] = None, 
                 password: Optional[str] = None, authentication: Any = None):
        self.server = server
        self.user = user
        self.password = password
        self.authentication = authentication
        self.entries = []
        self._adws_client = None
        self._root_dn = None
        self._bound = False
    
    def bind(self) -> bool:
        """Bind to ADWS server"""
        try:
            # Parse domain and username
            domain = self.server.domain
            username = self.user or ""
            
            if '\\' in username:
                domain, username = username.split('\\', 1)
            elif '@' in username:
                username, domain = username.rsplit('@', 1)
            
            # Determine if password is a hash (LM:NTLM format)
            hashes = None
            password = self.password
            if password and ':' in password and len(password.split(':')) == 2:
                hashes = password
                password = None
            
            # Create NTLM auth
            auth = NTLMAuth(password=password, hashes=hashes)
            
            # Create ADWS connection
            self._adws_client = ADWSConnect.pull_client(
                ip=self.server.host,
                domain=domain,
                username=username,
                auth=auth
            )
            
            # Get root DN from RootDSE
            rootdse = self._adws_client.get_rootdse_contexts(self.server.host, self._adws_client._nmf)
            self._root_dn = rootdse.get('defaultNamingContext') or rootdse.get('rootDomainNamingContext')
            if self._root_dn:
                self.server.info.other['defaultNamingContext'] = [self._root_dn]
            
            self._bound = True
            return True
        except Exception as e:
            logger.error(f"ADWS bind failed: {e}")
            self.result = {'description': str(e)}
            return False
    
    def search(self, search_base: str, search_filter: str, attributes: List[str] = None):
        """
        Search using ADWS (mimics ldap3 search)
        """
        if not self._bound:
            raise RuntimeError("Not bound to ADWS server")
        
        if attributes is None:
            attributes = ['*']
        
        # Use ALL_ATTRIBUTES equivalent
        if attributes == ['*'] or (isinstance(attributes, list) and len(attributes) == 1 and attributes[0] == '*'):
            # For now, use a comprehensive list - in production you might want to query schema
            attributes = [
                'cn', 'name', 'sAMAccountName', 'distinguishedName', 'objectClass',
                'objectSid', 'objectGUID', 'memberOf', 'primaryGroupId', 'userAccountControl',
                'whenCreated', 'whenChanged', 'lastLogon', 'pwdLastSet', 'description',
                'servicePrincipalName', 'operatingSystem', 'operatingSystemServicePack',
                'operatingSystemVersion', 'dNSHostName', 'lockOutObservationWindow',
                'lockoutDuration', 'lockoutThreshold', 'maxPwdAge', 'minPwdAge',
                'minPwdLength', 'pwdHistoryLength', 'pwdProperties',
                'ms-DS-MachineAccountQuota', 'flatName', 'securityIdentifier',
                'trustAttributes', 'trustDirection', 'trustType', 'member'
            ]
        
        try:
            # Use pull to get all results
            pull_result = self._adws_client.pull(
                query=search_filter,
                attributes=attributes,
                base_object_dn_for_soap=search_base
            )
            
            if pull_result is None:
                self.entries = []
                return
            
            # Convert XML elements to ADWSEntry objects
            self.entries = []
            for item_elem in pull_result:
                entry = ADWSEntry(item_elem, attributes)
                if 'distinguishedName' in entry:
                    self.entries.append(entry)
        except Exception as e:
            logger.error(f"ADWS search failed: {e}")
            self.entries = []
    
    class ExtendStandard:
        """Mimics ldap3 extend.standard for paged_search"""
        def __init__(self, connection):
            self._connection = connection
        
        def paged_search(self, search_base: str, search_filter: str, 
                         attributes: List[str] = None, paged_size: int = 500, 
                         generator: bool = False):
            """
            Paged search (ADWS handles paging internally, so this is just a regular search)
            """
            self._connection.search(search_base, search_filter, attributes)
            if generator:
                return iter(self._connection.entries)
            return self._connection.entries
    
    class Extend:
        """Mimics ldap3 extend for paged_search"""
        def __init__(self, connection):
            self._connection = connection
        
        @property
        def standard(self):
            """Mimics ldap3 extend.standard"""
            return ADWSConnection.ExtendStandard(self._connection)
    
    @property
    def extend(self):
        """Mimics ldap3 extend property"""
        return ADWSConnection.Extend(self)

