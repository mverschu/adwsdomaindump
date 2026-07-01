"""
Default Active Directory schemaIDGUID map for BloodHound ACL parsing.

ADWS schema partition enumeration is unreliable on some hosts, so we ship the
standard class/property GUIDs bloodhound.py expects (lowercase hyphenated UUIDs).
"""

DEFAULT_OBJECTTYPE_GUID_MAP = {
    "user": "bf967aba-0de6-11d0-a285-00aa003049e2",
    "group": "bf967a9c-0de6-11d0-a285-00aa003049e2",
    "computer": "bf967a86-0de6-11d0-a285-00aa003049e2",
    "domain": "19195a5a-6da0-11d0-afd3-00c04fd930c9",
    "organizational-unit": "bf967aa5-0de6-11d0-a285-00aa003049e2",
    "container": "bf967a85-0de6-11d0-a285-00aa003049e2",
    "gpo": "f30e3bc2-9ff0-11d1-b603-0000f80367c1",
    "service-principal-name": "c0ea6840-d41b-4b76-9050-b4742ddcf0f8",
    "ms-mcs-admpwd": "7737fd82-34d4-4d4a-a3b3-0a6678480acd",
    "ms-laps-password": "d31bd875-dbbe-4a4c-8c84-c32e34ffee74",
    "ms-laps-encryptedpassword": "d31bd875-dbbe-4a4c-8c84-c32e34ffee74",
    "ms-ds-key-credential-link": "5b47d60f-6090-40b2-9779-a51a603b0f6a",
}


def get_objecttype_guid_map():
    return dict(DEFAULT_OBJECTTYPE_GUID_MAP)
