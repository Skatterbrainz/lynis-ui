"""
Parsing helpers for Lynis report data and the custom.prf exemption profile.

This module has no Flask dependency so it can be tested/imported standalone.
"""
from __future__ import annotations

import os
import re
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

# Default locations. The primary report path requires root to read; a home
# directory copy is used as a fallback for local development without sudo.
DEFAULT_REPORT_PATHS = [
    "/var/log/lynis-report.dat",
    os.path.expanduser("~/lynis-report.dat"),
]
CUSTOM_PROFILE_PATH = "/etc/lynis/custom.prf"

_LINE_RE = re.compile(r"^(?P<key>[A-Za-z_]+)(\[\])?=(?P<value>.*)$")
_SKIP_TEST_RE = re.compile(r"^\s*skip-test\s*=\s*([A-Za-z0-9\-]+)(:.*)?\s*$")


def find_report_path(candidates: Optional[List[str]] = None) -> Optional[str]:
    """Return the first readable report path from the candidate list."""
    for path in candidates or DEFAULT_REPORT_PATHS:
        if os.path.isfile(path) and os.access(path, os.R_OK):
            return path
    return None


def parse_report(path: str) -> Dict:
    """
    Parse a Lynis report.dat file.

    Returns a dict with:
      - meta: header fields (hostname, lynis_version, hardening_index, etc.)
      - findings: dict keyed by test_id -> {test_id, kind, descriptions: [...]}
    """
    meta: Dict[str, str] = {}
    findings: Dict[str, Dict] = {}

    with open(path, "r", errors="replace") as fh:
        for raw_line in fh:
            line = raw_line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            match = _LINE_RE.match(line)
            if not match:
                continue
            key = match.group("key")
            value = match.group("value")

            if key in ("suggestion", "warning"):
                parts = value.split("|")
                test_id = parts[0].strip()
                description = parts[1].strip() if len(parts) > 1 else ""
                if not test_id:
                    continue
                entry = findings.setdefault(
                    test_id,
                    {"test_id": test_id, "kind": "suggestion", "descriptions": []},
                )
                if key == "warning":
                    entry["kind"] = "warning"
                if description and description not in entry["descriptions"]:
                    entry["descriptions"].append(description)
            else:
                # Scalar header fields: keep the first occurrence.
                if key not in meta:
                    meta[key] = value

    return {"meta": meta, "findings": findings}


def parse_custom_profile(path: str = CUSTOM_PROFILE_PATH) -> Dict[str, Set[str]]:
    """
    Parse an existing custom.prf for skip-test entries.

    Returns:
      {
        "full": {TEST-ID, ...},              # fully-exempted test IDs
        "partial": {"TEST-ID": {"sub1", ...}}  # sub-key exemptions (e.g. KRNL-6000:xyz)
      }
    """
    full: Set[str] = set()
    partial: Dict[str, Set[str]] = {}

    if not os.path.isfile(path):
        return {"full": full, "partial": partial}

    with open(path, "r", errors="replace") as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            match = _SKIP_TEST_RE.match(line)
            if not match:
                continue
            test_id = match.group(1)
            sub_key = match.group(2)
            if sub_key:
                partial.setdefault(test_id, set()).add(sub_key.lstrip(":"))
            else:
                full.add(test_id)

    return {"full": full, "partial": partial}


def append_exemptions(
    test_ids: List[str],
    reason: str,
    path: str = CUSTOM_PROFILE_PATH,
) -> Tuple[List[str], List[str]]:
    """
    Append skip-test= lines for the given test IDs to the custom profile,
    skipping any that are already fully exempted. Returns (added, skipped).
    """
    existing = parse_custom_profile(path)
    already = existing["full"]

    to_add = [tid for tid in dict.fromkeys(test_ids) if tid not in already]
    skipped = [tid for tid in test_ids if tid in already]

    if not to_add:
        return [], skipped

    os.makedirs(os.path.dirname(path), exist_ok=True)
    is_new_file = not os.path.isfile(path)

    with open(path, "a") as fh:
        if is_new_file:
            fh.write(
                "# Custom Lynis profile — accepted-risk exemptions\n"
                "# Managed in part by the lynis-webui dashboard.\n"
                "# Do NOT edit default.prf directly; put overrides here instead.\n\n"
            )
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
        safe_reason = reason.strip() or "Accepted risk"
        fh.write(f"\n# Accepted risk ({timestamp}): {safe_reason}\n")
        for tid in to_add:
            fh.write(f"skip-test={tid}\n")

    return to_add, skipped


def remove_exemptions(
    test_ids: List[str],
    path: str = CUSTOM_PROFILE_PATH,
) -> List[str]:
    """
    Remove full skip-test= entries for the given test IDs from the custom
    profile. Rather than deleting the line outright, it is commented out
    with a removal note so the file stays human-auditable. Returns the list
    of test IDs that were actually found and removed.
    """
    if not os.path.isfile(path):
        return []

    target_ids = set(test_ids)
    removed: List[str] = []
    out_lines: List[str] = []
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")

    with open(path, "r", errors="replace") as fh:
        lines = fh.readlines()

    for raw_line in lines:
        stripped = raw_line.strip()
        if not stripped.startswith("#"):
            match = _SKIP_TEST_RE.match(raw_line)
            if match and not match.group(2) and match.group(1) in target_ids:
                tid = match.group(1)
                removed.append(tid)
                out_lines.append(
                    f"# skip-test={tid}  (exemption removed via dashboard on {timestamp})\n"
                )
                continue
        out_lines.append(raw_line)

    if removed:
        with open(path, "w") as fh:
            fh.writelines(out_lines)

    return removed


def build_findings_list(
    report_path: Optional[str] = None,
    knowledge: Optional[Dict[str, Dict]] = None,
    custom_profile_path: str = CUSTOM_PROFILE_PATH,
) -> Dict:
    """
    High-level helper used by the Flask app: parses the report + custom
    profile, merges in curated knowledge, and returns a ready-to-serialize
    dict with 'meta' and 'findings' (list, sorted by test_id).
    """
    path = report_path or find_report_path()
    if not path:
        raise FileNotFoundError(
            "No readable Lynis report found. Checked: "
            + ", ".join(DEFAULT_REPORT_PATHS)
            + ". Run this app with sudo (./run.sh) so it can read /var/log/lynis-report.dat."
        )

    parsed = parse_report(path)
    exemptions = parse_custom_profile(custom_profile_path)
    knowledge = knowledge or {}

    findings_out = []
    for test_id, entry in sorted(parsed["findings"].items()):
        info = knowledge.get(test_id, {})
        findings_out.append(
            {
                "test_id": test_id,
                "kind": entry["kind"],
                "descriptions": entry["descriptions"],
                "category": info.get("category", "Uncategorized"),
                "severity": info.get("severity", "Unclassified"),
                "impact": info.get("impact", "Unknown"),
                "remediation": info.get("remediation", "See Lynis suggestion text above."),
                "explanation": info.get("explanation", "Not yet documented."),
                "exempted": test_id in exemptions["full"],
                "partial_exemptions": sorted(exemptions["partial"].get(test_id, [])),
            }
        )

    return {
        "meta": {
            "report_path": path,
            "hostname": parsed["meta"].get("hostname"),
            "lynis_version": parsed["meta"].get("lynis_version"),
            "os_fullname": parsed["meta"].get("os_fullname"),
            "hardening_index": parsed["meta"].get("hardening_index"),
            "report_datetime_start": parsed["meta"].get("report_datetime_start"),
            "report_datetime_end": parsed["meta"].get("report_datetime_end"),
            "lynis_tests_done": parsed["meta"].get("lynis_tests_done"),
            "custom_profile_path": custom_profile_path,
            "custom_profile_exists": os.path.isfile(custom_profile_path),
        },
        "findings": findings_out,
    }
