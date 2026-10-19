"""
Keeps docs/SEVERITY.md in sync with the analyzer code.

Every finding ID the analyzers can emit must be documented with the same
severity level(s), and the document must not list IDs that no longer exist.
"""
import re
from pathlib import Path

from app.analyzers.header_check import SECURITY_HEADERS

BACKEND = Path(__file__).resolve().parents[1]
DOC = BACKEND.parent / "docs" / "SEVERITY.md"
ANALYZERS = BACKEND / "app" / "analyzers"

# Matches:  id="SOME_ID",  <newline> title=...,  <newline> severity=<expression>,
_FINDING_RE = re.compile(r'id="([A-Z_]+)",\s*\n\s*title=.*\n\s*severity=([^\n]+)')
_LEVEL_RE = re.compile(r"Severity\.([A-Z]+)")


def _code_severities():
    found = {}
    for path in ANALYZERS.glob("*.py"):
        for finding_id, expr in _FINDING_RE.findall(path.read_text(encoding="utf-8")):
            found[finding_id] = {lvl.lower() for lvl in _LEVEL_RE.findall(expr)}
    # Header IDs built from the SECURITY_HEADERS table.
    for info in SECURITY_HEADERS.values():
        level = {info["severity"].value}
        found[info["id"]] = level
        found[f"{info['prefix']}_EMPTY"] = level
    return found


def _doc_severities():
    found = {}
    for line in DOC.read_text(encoding="utf-8").splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) >= 2:
            match = re.fullmatch(r"`([A-Z_]+)`", cells[0])
            if match:
                found[match.group(1)] = set(re.findall(r"`(info|low|medium|high|critical)`", cells[1]))
    return found


def test_code_finding_ids_were_extracted():
    # Guards against the regex silently matching nothing after a refactor.
    assert len(_code_severities()) >= 30


def test_every_finding_id_is_documented():
    missing = set(_code_severities()) - set(_doc_severities())
    assert not missing, f"Finding IDs missing from docs/SEVERITY.md: {sorted(missing)}"


def test_document_lists_no_stale_ids():
    stale = set(_doc_severities()) - set(_code_severities())
    assert not stale, f"docs/SEVERITY.md lists IDs not found in code: {sorted(stale)}"


def test_documented_severities_match_code():
    code, doc = _code_severities(), _doc_severities()
    mismatched = {
        fid: {"code": sorted(code[fid]), "doc": sorted(doc[fid])}
        for fid in code.keys() & doc.keys()
        if code[fid] != doc[fid]
    }
    assert not mismatched, f"Severity mismatch between code and docs: {mismatched}"


def test_critical_is_not_used_by_passive_scanner():
    assert all("critical" not in levels for levels in _code_severities().values())
