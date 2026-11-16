"""
Enumerate and reach domains beyond the connection's default naming context:
same-forest replicas on the DC and trusted external forests over ADWS.
"""
import ipaddress
import re
import socket

import dns.resolver

from .adws_wrapper import ADWSServer, ADWSConnection

# trustAttributes bit from MS-ADTS
TRUST_ATTR_WITHIN_FOREST = 0x00000020


def naming_context_to_dns(nc):
    """Convert a domain NC DN (DC=a,DC=b,DC=com) to DNS name a.b.com."""
    if not nc:
        return None
    labels = []
    for part in nc.split(','):
        part = part.strip()
        if part.upper().startswith('DC='):
            labels.append(part[3:])
    return '.'.join(labels).lower() if labels else None


def is_domain_naming_context(nc):
    if not nc or not nc.upper().startswith('DC='):
        return False
    upper = nc.upper()
    if ',CN=CONFIGURATION,' in f',{upper},' or upper.startswith('CN=CONFIGURATION,'):
        return False
    if 'DOMAINDNSZONES' in upper or 'FORESTDNSZONES' in upper:
        return False
    return True


def domain_naming_contexts(server):
    """Domain NCs held on this DC (forest partitions + local domain)."""
    raw = server.info.other.get('namingContexts') or []
    seen = set()
    out = []
    for nc in raw:
        if is_domain_naming_context(nc):
            key = nc.upper()
            if key not in seen:
                seen.add(key)
                out.append(nc)
    return out


def extra_forest_domains(server, primary_root):
    """Same-forest domains other than the NC used for the primary dump."""
    primary = (primary_root or '').upper()
    domains = []
    for nc in domain_naming_contexts(server):
        if nc.upper() == primary:
            continue
        dns = naming_context_to_dns(nc)
        if dns:
            domains.append((dns, nc))
    return domains


def _trust_attribute_value(entry):
    try:
        from .bloodhound_export import get_int, get_entry_property
        return get_int(get_entry_property(entry, 'trustAttributes', default=0))
    except ImportError:
        try:
            raw = entry['trustAttributes'].value
            return int(raw)
        except (KeyError, AttributeError, TypeError, ValueError):
            return 0


def trusted_external_domain_names(trust_entries):
    """
    DNS names of trusts that are not parent/child inside the forest.
    """
    names = []
    seen = set()
    for entry in trust_entries or []:
        flags = _trust_attribute_value(entry)
        if flags & TRUST_ATTR_WITHIN_FOREST:
            continue
        try:
            name = entry['name'].value
        except (KeyError, AttributeError):
            try:
                name = entry['cn'].value
            except (KeyError, AttributeError):
                continue
        if not name:
            continue
        key = str(name).lower()
        if key in seen:
            continue
        seen.add(key)
        names.append(key)
    return names


def safe_domain_dirname(dns_name):
    return re.sub(r'[^a-zA-Z0-9._-]+', '_', (dns_name or '').lower()).strip('_') or 'domain'


_DNS_ERRORS = (
    dns.resolver.NXDOMAIN,
    dns.resolver.NoAnswer,
    dns.resolver.Timeout,
    dns.resolver.LifetimeTimeout,
)


def dns_server_nameserver_ips(dns_server):
    """
    Return IP strings for dnspython's resolver.nameservers (hostnames are not accepted).
    """
    dns_server = (dns_server or '').strip()
    if not dns_server:
        return []
    try:
        ipaddress.ip_address(dns_server)
        return [dns_server]
    except ValueError:
        pass
    try:
        ips = []
        seen = set()
        for info in socket.getaddrinfo(dns_server, 53, type=socket.SOCK_DGRAM):
            ip = info[4][0]
            if ip not in seen:
                seen.add(ip)
                ips.append(ip)
        return ips
    except OSError:
        return []


def resolve_domain_dc_hosts(domain_dns, dns_server=''):
    """
    Return candidate DC hostnames for ADWS, in SRV priority order (all KDC/LDAP SRV targets).
    """
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5
    if dns_server:
        ns_ips = dns_server_nameserver_ips(dns_server)
        if ns_ips:
            resolver.nameservers = ns_ips
    hosts = []
    seen = set()
    name = domain_dns.rstrip('.')
    try:
        srv = '_ldap._tcp.dc._msdcs.%s' % name
        answers = resolver.resolve(srv, 'SRV')
        for rr in sorted(answers, key=lambda r: (r.priority, -r.weight)):
            target = str(rr.target).rstrip('.').lower()
            if target and target not in seen:
                seen.add(target)
                hosts.append(target)
    except _DNS_ERRORS:
        pass
    if not hosts:
        try:
            resolver.resolve(name, 'A')
            hosts.append(name.lower())
        except _DNS_ERRORS:
            pass
    return hosts


def resolve_domain_dc_hostname(domain_dns, dns_server=''):
    """First candidate DC from :func:`resolve_domain_dc_hosts`."""
    hosts = resolve_domain_dc_hosts(domain_dns, dns_server)
    return hosts[0] if hosts else None


def clone_config_for_domain(base_config, domain_dns):
    """Shallow copy of dump config with output under a per-domain subdirectory."""
    import copy
    cfg = copy.copy(base_config)
    root_base = getattr(base_config, '_basepath_root', base_config.basepath)
    cfg._basepath_root = root_base
    cfg.basepath = __import__('os').path.join(root_base, safe_domain_dirname(domain_dns))
    cfg.target_domain_dns = domain_dns
    return cfg


def connect_adws(host, domain_dns, user, password):
    server = ADWSServer(host, domain_dns)
    connection = ADWSConnection(server, user=user, password=password)
    if not connection.bind():
        return None, None
    return server, connection


def connect_adws_domain(domain_dns, user, password, dns_server='', force=False, log=None):
    """
    Try every resolved DC for domain_dns until ADWS is reachable and bind succeeds.
    log is called as log(level, message) with level in ('info', 'warn', 'success').
    Returns (server, connection, host_used) or (None, None, None).
    """
    if log is None:
        def log(_level, _msg):
            pass

    hosts = resolve_domain_dc_hosts(domain_dns, dns_server)
    if not hosts:
        log('warn', 'Could not resolve any domain controller for %s' % domain_dns)
        return None, None, None

    log('info', 'Cross-forest: %d DC candidate(s) for %s' % (len(hosts), domain_dns))
    for host in hosts:
        if not force and not adws_reachable(host):
            log('info', 'ADWS port 9389 not reachable on %s (%s), trying next DC' % (host, domain_dns))
            continue
        log('info', 'Trying ADWS bind on %s for %s' % (host, domain_dns))
        server, connection = connect_adws(host, domain_dns, user, password)
        if connection is not None:
            log('success', 'Bound to ADWS on %s for %s' % (host, domain_dns))
            return server, connection, host
        log('warn', 'ADWS bind failed on %s for %s, trying next DC' % (host, domain_dns))

    log('warn', 'No DC accepted ADWS connection for trusted domain %s' % domain_dns)
    return None, None, None


def adws_reachable(host, port=9389, timeout=5):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        ok = sock.connect_ex((host, port)) == 0
        sock.close()
        return ok
    except OSError:
        return False