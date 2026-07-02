"""
Write parsed DACL / ACE data as Markdown tables alongside other report output.
"""
from __future__ import unicode_literals

import codecs
import os

from .bloodhound_export import BloodHoundExporter, WELLKNOWN_SIDS


def _mdescape(value):
    if value is None:
        return ''
    text = ''.join(c if c.isprintable() or c in ' \t' else '?' for c in str(value))
    return text.replace('|', '\\|').replace('\n', ' ').replace('\r', '')


class AclMarkdownExporter:
    COLUMNS = [
        ('object', 'Object'),
        ('dn', 'Distinguished name'),
        ('right', 'Right'),
        ('principal', 'Principal'),
        ('principal_type', 'Principal type'),
        ('inherited', 'Inherited'),
        ('protected', 'ACL protected'),
    ]

    def __init__(self, config):
        self.config = config

    def export(self, dd):
        from adwsdomaindump import log_info, log_success

        exporter = BloodHoundExporter(self.config)
        exporter.domain = dd.server.domain.upper()
        exporter.domain_sid = dd.getRootSid()
        if not exporter.domain_sid:
            log_info('Skipping ACL Markdown export — could not determine domain SID')
            return

        exporter._build_caches(dd.users, dd.groups, dd.computers)

        datasets = [
            (self.config.usersfile, 'Domain users — DACL / ACEs', exporter._build_users(dd.users)),
            (self.config.groupsfile, 'Domain groups — DACL / ACEs', exporter._build_groups(dd.groups)),
            (self.config.computersfile, 'Domain computers — DACL / ACEs', exporter._build_computers(dd.computers)),
            (
                self.config.policyfile,
                'Domain — DACL / ACEs',
                exporter._build_domains(dd.policy, dd.trusts, dd.computers, dd),
            ),
        ]
        if getattr(self.config, 'collect_all', False):
            datasets.extend([
                (
                    self.config.gposfile,
                    'Group Policy Objects — DACL / ACEs',
                    exporter._build_gpos(getattr(dd, 'gpos', [])),
                ),
                (
                    self.config.ousfile,
                    'Organizational Units — DACL / ACEs',
                    exporter._build_ous(getattr(dd, 'ous', []), dd),
                ),
                (
                    self.config.containersfile,
                    'Containers — DACL / ACEs',
                    exporter._build_containers(getattr(dd, 'containers', []), dd),
                ),
            ])

        total_edges = 0
        files_written = 0
        for basename, title, objects in datasets:
            rows = self._rows_from_objects(exporter, objects)
            total_edges += len(rows)
            self._write_file(basename, title, rows)
            files_written += 1

        log_success(
            'Wrote ACL Markdown: %d ACE entries in %d file(s)'
            % (total_edges, files_written)
        )

    def _rows_from_objects(self, exporter, objects):
        rows = []
        for obj in objects or []:
            aces = obj.get('Aces') or []
            if not aces:
                continue
            props = obj.get('Properties') or {}
            obj_name = props.get('name') or props.get('samaccountname') or obj.get('ObjectIdentifier', '')
            obj_dn = props.get('distinguishedname', '')
            protected = 'Yes' if obj.get('IsACLProtected') else 'No'
            for ace in aces:
                rows.append({
                    'object': obj_name,
                    'dn': obj_dn,
                    'right': ace.get('RightName', ''),
                    'principal': self._principal_label(exporter, ace),
                    'principal_type': ace.get('PrincipalType', ''),
                    'inherited': 'Yes' if ace.get('IsInherited') else 'No',
                    'protected': protected,
                })
        rows.sort(key=lambda row: (
            row['object'].lower(),
            row['right'].lower(),
            row['principal'].lower(),
        ))
        return rows

    def _principal_label(self, exporter, ace):
        sid = ace.get('PrincipalSID', '')
        if not sid:
            return ''

        prefix = '%s-' % exporter.domain
        if sid.startswith(prefix):
            short = sid[len(prefix):]
            if short in WELLKNOWN_SIDS:
                return WELLKNOWN_SIDS[short][0]

        if sid in WELLKNOWN_SIDS:
            return WELLKNOWN_SIDS[sid][0]

        resolved = exporter.sidcache.get(sid)
        if resolved and resolved.get('principal'):
            return resolved['principal']
        return sid

    def _write_file(self, basename, title, rows):
        if not os.path.exists(self.config.basepath):
            os.makedirs(self.config.basepath)
        outfile = os.path.join(self.config.basepath, '%s_aces.md' % basename)
        with codecs.open(outfile, 'w', 'utf8') as handle:
            handle.write('# %s\n\n' % title)
            if not rows:
                handle.write('_No ACEs parsed for this object type._\n')
                return
            headers = [label for _, label in self.COLUMNS]
            keys = [key for key, _ in self.COLUMNS]
            handle.write('| ' + ' | '.join(_mdescape(h) for h in headers) + ' |\n')
            handle.write('| ' + ' | '.join('---' for _ in headers) + ' |\n')
            for row in rows:
                handle.write(
                    '| ' + ' | '.join(_mdescape(row.get(key, '')) for key in keys) + ' |\n'
                )
