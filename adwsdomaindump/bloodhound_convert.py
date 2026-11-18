"""
Upgrade legacy BloodHound JSON / zip exports for BloodHound CE (schema v6, string trust enums).
"""
from __future__ import unicode_literals

import codecs
import json
import os
import re
import shutil
import sys
import tempfile
from zipfile import ZipFile, ZIP_DEFLATED

from .bloodhound_export import (
    BLOODHOUND_SCHEMA_VERSION,
    BH_TRUST_DIRECTION,
    BH_TRUST_TYPE_BY_ID,
)

_TRUST_DIRECTION_VALUES = set(BH_TRUST_DIRECTION.values())
_TRUST_TYPE_VALUES = set(BH_TRUST_TYPE_BY_ID.values())


def _normalize_enum(value, id_map, valid_strings):
    if value is None:
        return id_map.get(4, "Unknown")
    if isinstance(value, bool):
        return id_map.get(4, "Unknown")
    if isinstance(value, int):
        return id_map.get(value, id_map.get(4, "Unknown"))
    if isinstance(value, float) and value == int(value):
        return id_map.get(int(value), id_map.get(4, "Unknown"))
    if isinstance(value, str):
        if value in valid_strings:
            return value
        upper = value.upper()
        for candidate in valid_strings:
            if candidate.upper() == upper:
                return candidate
        if upper in ("INBOUND", "OUTBOUND", "BIDIRECTIONAL", "DISABLED"):
            return value.capitalize() if value.islower() else value
    return value


def fix_trust_entry(trust):
    if not isinstance(trust, dict):
        return False
    changed = False
    if "TrustDirection" in trust:
        new_dir = _normalize_enum(
            trust.get("TrustDirection"), BH_TRUST_DIRECTION, _TRUST_DIRECTION_VALUES
        )
        if trust.get("TrustDirection") != new_dir:
            trust["TrustDirection"] = new_dir
            changed = True
    if "TrustType" in trust:
        new_type = _normalize_enum(
            trust.get("TrustType"), BH_TRUST_TYPE_BY_ID, _TRUST_TYPE_VALUES
        )
        if trust.get("TrustType") != new_type:
            trust["TrustType"] = new_type
            changed = True
    return changed


def fix_bloodhound_payload(payload):
    """Return (payload, trust_fix_count, meta_updated)."""
    if not isinstance(payload, dict):
        return payload, 0, False
    trust_fixes = 0
    meta_updated = False
    meta = payload.get("meta")
    if isinstance(meta, dict):
        version = meta.get("version")
        if version is None or int(version) < BLOODHOUND_SCHEMA_VERSION:
            meta["version"] = BLOODHOUND_SCHEMA_VERSION
            meta_updated = True
        if "count" in meta and isinstance(payload.get("data"), list):
            meta["count"] = len(payload["data"])
    data = payload.get("data")
    if not isinstance(data, list):
        return payload, trust_fixes, meta_updated
    obj_type = (meta or {}).get("type") if isinstance(meta, dict) else None
    for item in data:
        if not isinstance(item, dict):
            continue
        trusts = item.get("Trusts")
        if trusts is None and obj_type != "domains":
            continue
        if trusts is None:
            continue
        for trust in trusts:
            if fix_trust_entry(trust):
                trust_fixes += 1
    return payload, trust_fixes, meta_updated


def _default_output_path(input_path):
    base, ext = os.path.splitext(os.path.abspath(input_path))
    if ext.lower() == ".zip":
        return base + "_ce.zip"
    if ext.lower() == ".json":
        return base + "_ce.json"
    return input_path.rstrip(os.sep) + "_ce.zip"


def _iter_json_members(paths):
    for path in paths:
        if os.path.isfile(path) and path.lower().endswith(".json"):
            yield path, os.path.basename(path)
        elif os.path.isdir(path):
            for name in sorted(os.listdir(path)):
                if name.lower().endswith(".json"):
                    full = os.path.join(path, name)
                    yield full, name


def _load_json_file(path):
    with codecs.open(path, "r", "utf-8") as handle:
        return json.load(handle)


def _write_json_file(path, payload):
    with codecs.open(path, "w", "utf-8") as handle:
        json.dump(payload, handle, separators=(",", ":"))


def convert_bloodhound_input(input_path, output_path=None):
    """
    Convert BloodHound zip, single .json, or directory of .json files to CE-ready format.

    Returns path to output zip (or json if input was a single json and output not zip).
    """
    input_path = os.path.abspath(input_path)
    if not os.path.exists(input_path):
        raise FileNotFoundError(input_path)

    if output_path:
        output_path = os.path.abspath(output_path)
    else:
        output_path = _default_output_path(input_path)

    stats = {
        "files": 0,
        "trusts_fixed": 0,
        "meta_updated": 0,
    }

    def process_payload(raw):
        fixed, trust_count, meta_changed = fix_bloodhound_payload(raw)
        stats["trusts_fixed"] += trust_count
        if meta_changed:
            stats["meta_updated"] += 1
        return fixed

    if input_path.lower().endswith(".json") and os.path.isfile(input_path):
        payload = process_payload(_load_json_file(input_path))
        out = output_path if output_path.lower().endswith(".json") else _default_output_path(input_path)
        _write_json_file(out, payload)
        stats["files"] = 1
        return stats, out

    tempdir = tempfile.mkdtemp(prefix="adwsdomaindump_bh_convert_")
    try:
        members = []
        if input_path.lower().endswith(".zip"):
            with ZipFile(input_path, "r") as zf:
                for info in zf.infolist():
                    if info.is_dir() or not info.filename.lower().endswith(".json"):
                        continue
                    name = os.path.basename(info.filename)
                    raw = json.loads(zf.read(info).decode("utf-8"))
                    payload = process_payload(raw)
                    out_member = os.path.join(tempdir, name)
                    _write_json_file(out_member, payload)
                    members.append((out_member, name))
        else:
            for full, name in _iter_json_members([input_path]):
                payload = process_payload(_load_json_file(full))
                out_member = os.path.join(tempdir, name)
                _write_json_file(out_member, payload)
                members.append((out_member, name))

        if not members:
            raise ValueError("No BloodHound JSON files found in %s" % input_path)

        if not output_path.lower().endswith(".zip"):
            output_path += ".zip"

        outdir = os.path.dirname(output_path)
        if outdir and not os.path.exists(outdir):
            os.makedirs(outdir)

        with ZipFile(output_path, "w", compression=ZIP_DEFLATED) as zf:
            for filesystem_path, arcname in members:
                zf.write(filesystem_path, arcname=arcname)

        stats["files"] = len(members)
        return stats, output_path
    finally:
        shutil.rmtree(tempdir, ignore_errors=True)


def main_convert(input_path, output_path=None):
    from adwsdomaindump import log_info, log_success, log_warn

    try:
        stats, out = convert_bloodhound_input(input_path, output_path)
    except Exception as exc:
        log_warn("BloodHound convert failed: %s" % exc)
        return 1

    if stats["trusts_fixed"]:
        log_info(
            "Normalized %d trust entries (TrustDirection/TrustType) to CE string enums"
            % stats["trusts_fixed"]
        )
    else:
        log_info("Trust fields already used string enums (no trust rewrites needed)")
    if stats["meta_updated"]:
        log_info("Bumped meta.version to %d on %d file(s)" % (
            BLOODHOUND_SCHEMA_VERSION, stats["meta_updated"]))
    log_success(
        "Wrote BloodHound CE archive: %s (%d json file(s))"
        % (out, stats["files"])
    )
    return 0


def run_from_cli(input_path, output_path=None):
    """CLI entry: convert and exit with status code."""
    return main_convert(input_path, output_path)