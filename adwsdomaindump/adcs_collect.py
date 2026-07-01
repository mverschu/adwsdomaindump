"""Collect Active Directory Certificate Services data via ADWS."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


class ADWSADCSAdapter:
    """Minimal ldap3-like adapter so CertiHound can search through ADWS."""

    def __init__(self, connection):
        self._connection = connection
        self.entries = []

    def search(self, search_base, search_filter, attributes=None, **kwargs):
        self._connection.search(search_base, search_filter, attributes or [])
        self.entries = list(self._connection.entries)
        return True


def configuration_dn(domain: str) -> str:
    return f"CN=Configuration,DC={',DC='.join(domain.split('.'))}"


def collect_adcs(dd):
    """Collect AD CS objects from the Configuration partition using ADWS only."""
    try:
        from certihound.collector import ExternalADCSCollector
        from certihound.exporter import BloodHoundCEExporter
    except ImportError as exc:
        raise RuntimeError(
            "AD CS collection requires certihound. Install with: pipx inject adwsdomaindump certihound"
        ) from exc

    domain = dd.server.domain
    domain_sid = dd.getRootSid()
    if not domain_sid:
        raise RuntimeError("Could not determine domain SID for AD CS export")

    adapter = ADWSADCSAdapter(dd.connection)
    collector = ExternalADCSCollector(
        ldap_connection=adapter,
        domain=domain,
        domain_sid=domain_sid,
        base_dn=dd.root,
    )
    data = collector.collect_all()
    exporter = BloodHoundCEExporter(domain, domain_sid)
    # AD-visible detection only (no RPC/registry); ESC8/11/16 may be incomplete without host data.
    result = exporter.export(data, process_acls=True, run_detection=True)
    return data, result


def adcs_summary(data) -> dict[str, int]:
    return {
        "templates": len(data.templates),
        "enterprise_cas": len(data.enterprise_cas),
        "root_cas": len(data.root_cas),
        "ntauth_stores": len(data.ntauth_stores),
        "aia_cas": len(data.aia_cas),
    }
