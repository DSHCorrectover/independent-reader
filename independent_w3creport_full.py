#!/usr/bin/env python3
"""
Independent W3C-Report Corpus Semantic Adjudicator
===================================================
agent-evidence-vectors v0.17.4 — vectors-w3c-report/ corpus (235 vectors)

SHARES NO CODE with the upstream agent_evidence_vectors package.
Every rule is re-implemented from scratch using Python stdlib only.
Judgment is derived from each vector's raw test-case bytes.
The MANIFEST expected values are ONLY used for post-hoc comparison.

Usage:
    python3 independent_w3creport_full.py [--corpus-dir DIR] [--json-output PATH]

Default corpus dir: /tmp/aev/agent_evidence_vectors/corpora/vectors-w3c-report/
"""

from __future__ import annotations

import decimal
import hashlib
import json
import os
import re
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

# ============================================================================
# Configuration
# ============================================================================
DEFAULT_CORPUS_DIR = "/tmp/aev/agent_evidence_vectors/corpora/vectors-w3c-report"
DEFAULT_OUTPUT = None  # auto-generate


# ============================================================================
# Utility — all from scratch, stdlib only
# ============================================================================
def sha(data: bytes) -> str:
    """SHA-256 hex digest."""
    return hashlib.sha256(data).hexdigest()


def compact(value: Any) -> bytes:
    """Compact JSON: sorted keys, no whitespace, ASCII-escaped.
    Floats and Decimals are REFUSED — this is the same behavior as the
    Go reader's CPython-compatible encoder."""
    _refuse_floats(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


class FloatRefused(ValueError):
    """A float/Decimal inside a digested payload."""


def _refuse_floats(value: Any) -> None:
    if isinstance(value, (float, decimal.Decimal)):
        raise FloatRefused(f"float/Decimal found in digested payload: {value}")
    if isinstance(value, dict):
        for item in value.values():
            _refuse_floats(item)
    elif isinstance(value, list):
        for item in value:
            _refuse_floats(item)


def flat_root(leaves: list[bytes]) -> str:
    """SHA-256 over concatenated SHA-256 of each leaf, in order."""
    return sha(b"".join(hashlib.sha256(leaf).digest() for leaf in leaves))


def rfc6962_root(leaves: list[bytes]) -> str:
    """Merkle tree hash of RFC 6962 section 2.1 with domain separation."""
    return _mth(leaves).hex()


def _mth(leaves: list[bytes]) -> bytes:
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return hashlib.sha256(b"\x00" + leaves[0]).digest()
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    return hashlib.sha256(b"\x01" + _mth(leaves[:k]) + _mth(leaves[k:])).digest()


# Closed set of tree shapes
ROOTS: dict[str, Callable[[list[bytes]], str]] = {
    "flat": flat_root,
    "rfc6962": rfc6962_root,
    "RFC9162_SHA256": rfc6962_root,
}
TREE_SHAPES = tuple(ROOTS)


def check_set_root(checks: list[dict], shape: str) -> str:
    root_fn = ROOTS.get(shape)
    if root_fn is None:
        raise ValueError(f"unknown tree shape: {shape!r}")
    return root_fn([compact(c) for c in checks])


# ============================================================================
# Type helpers
# ============================================================================
def _is_str(v: Any) -> bool:
    return isinstance(v, str)

def _is_obj(v: Any) -> bool:
    return isinstance(v, dict)

def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)

def _get(obj: dict, key: str) -> Any:
    return obj.get(key)


# ============================================================================
# VOCABULARIES — from v0.1 spec
# ============================================================================
STATES = ("pass", "fail", "inconclusive", "not-exercised", "void")
VERDICT_STATES = ("pass", "fail")
NON_VERDICT_STATES = ("inconclusive", "not-exercised", "void")

CAUSES = (
    "not_applicable", "disabled_by_policy", "unsupported_input",
    "resource_exhausted", "failed", "unavailable", "out_of_scope",
    "withheld", "evidence-does-not-hold", "integrity-failure",
    "availability-failure", "precondition-unsatisfiable",
    "confinement-failed-during-check",
)
VOID_CAUSE = "evidence-does-not-hold"
CONFINEMENT_CAUSE = "confinement-failed-during-check"
NEVER_EXAMINED = ("not_applicable", "out_of_scope", "withheld")

OTHER_VERDICT = ("unknown", "possible-not-demonstrated", "demonstrated", "foreclosed")
DISCRIMINATION = ("unknown", "demonstrated")
NEGATIVE_CAPABLE = ("shown-by-run", "control-failed", "prior-discriminating-run", "nothing")
CHANGED = ("input artifact", "checker rule", "constraint")
SLOTS = ("verdict", "fired-rule list", "error list")

FORMAT = "public-agent-conformance/report/v0.1"

# Requirement IDs
R = {n: f"W3C-R-{n:03d}" for n in range(1, 30)}

# ============================================================================
# REPORT SHAPE VALIDATION
# ============================================================================
def _shape_slots(check: dict, where: str, out: list[str]) -> None:
    for slot in ("cause", "other-verdict", "discrimination"):
        if slot in check and not _is_obj(check[slot]):
            out.append(f"{where}.{slot} is present and is not an object")
    cause = _get(check, "cause")
    if _is_obj(cause) and not _is_str(cause.get("code")):
        out.append(f"{where}.cause carries no string code")
    for slot in ("other-verdict", "discrimination"):
        value = _get(check, slot)
        if _is_obj(value) and not _is_str(value.get("value")):
            out.append(f"{where}.{slot} carries no string value")


def _shape_check(check: Any, index: int, out: list[str]) -> None:
    where = f"checks[{index}]"
    if not _is_obj(check):
        out.append(f"{where} is not an object")
        return
    if not _is_str(check.get("check")):
        out.append(f"{where} carries no string check identity")
    if not _is_str(check.get("state")):
        out.append(f"{where} carries no string state")
    _shape_slots(check, where, out)
    if "declared-exclusion" in check and not isinstance(check["declared-exclusion"], bool):
        out.append(f"{where}.declared-exclusion is present and is not a boolean")


def _shape_evidence(item: Any, index: int, out: list[str]) -> None:
    where = f"evidence[{index}]"
    if not _is_obj(item):
        out.append(f"{where} is not an object")
        return
    if not _is_str(item.get("id")):
        out.append(f"{where} carries no string id")
    if not _is_str(item.get("changed")):
        out.append(f"{where} carries no string changed slot")
    if not _is_obj(item.get("fixed")):
        out.append(f"{where} carries no fixed object")
    for slot in ("compared", "moved"):
        values = item.get(slot)
        if not isinstance(values, list) or not all(_is_str(v) for v in values):
            out.append(f"{where}.{slot} is not a list of strings")
    if "delta" in item and not _is_obj(item["delta"]):
        out.append(f"{where}.delta is present and is not an object")
    _shape_observations(item.get("observations"), where, out)


def _shape_observations(observations: Any, where: str, out: list[str]) -> None:
    if not isinstance(observations, list):
        out.append(f"{where}.observations is not a list")
        return
    for j, obs in enumerate(observations):
        if not _is_obj(obs) or (("reference" in obs) == ("carried" in obs)):
            out.append(f"{where}.observations[{j}] is not exactly one of reference or carried")
        elif not _is_obj(obs.get("reference", obs.get("carried"))):
            out.append(f"{where}.observations[{j}] carries a form that is not an object")


def _duplicate_ids(items: list, key: str) -> bool:
    ids = [item.get(key) for item in items if _is_obj(item)]
    return len(set(ids)) != len(ids)


def _shape_lists(report: dict, out: list[str]) -> None:
    checks = report.get("checks")
    if not isinstance(checks, list):
        out.append("checks is not a list")
        checks = []
    for i, check in enumerate(checks):
        _shape_check(check, i, out)
    if _duplicate_ids(checks, "check"):
        out.append("two checks carry one identity")
    evidence = report.get("evidence", [])
    if not isinstance(evidence, list):
        out.append("evidence is present and is not a list")
        evidence = []
    for i, item in enumerate(evidence):
        _shape_evidence(item, i, out)
    if _duplicate_ids(evidence, "id"):
        out.append("two evidence objects carry one id")


def _shape_domain(report: dict, out: list[str]) -> None:
    domain = _get(report, "domain")
    if not _is_obj(domain) or not _is_str(domain.get("id")):
        out.append("the report declares no domain object with a string id")
        return
    declared = domain["id"]
    checks = report.get("checks", []) if isinstance(report.get("checks"), list) else []
    for i, check in enumerate(checks):
        other = check.get("other-verdict") if _is_obj(check) else None
        named = other.get("domain") if _is_obj(other) else None
        if _is_str(named) and named != declared:
            out.append(f"checks[{i}].other-verdict names a domain the run does not declare")
    evidence = report.get("evidence", []) if isinstance(report.get("evidence"), list) else []
    for i, item in enumerate(evidence):
        fixed = item.get("fixed") if _is_obj(item) else None
        named = fixed.get("domain") if _is_obj(fixed) else None
        if _is_str(named) and named != declared:
            out.append(f"evidence[{i}].fixed names a domain the run does not declare")


def shape_errors(report: Any) -> list[str]:
    """Every way the report fails to be a v0.1 report at all."""
    out: list[str] = []
    if not _is_obj(report):
        return ["the report is not a JSON object"]
    if report.get("format") != FORMAT:
        out.append(f"the report does not declare format '{FORMAT}'")
    _shape_lists(report, out)
    _shape_domain(report, out)
    for slot in ("roll-up", "check-set", "fixed"):
        if slot in report and not _is_obj(report[slot]):
            out.append(f"{slot} is present and is not an object")
    return out


# ============================================================================
# REPORT REJECTION RULES — independent re-implementation
# ============================================================================

def _row_cause(check: dict, state: str, out: set[str]) -> None:
    cause = check.get("cause")
    if state in NON_VERDICT_STATES and cause is None:
        out.add(R[1])
    if state in VERDICT_STATES and cause is not None:
        out.add(R[7])
    if cause is None:
        return
    code = cause["code"]
    if code not in CAUSES:
        out.add(R[19])
    if state == "void" and code in NEVER_EXAMINED:
        out.add(R[2])
    if state == "not-exercised" and code == "integrity-failure":
        out.add(R[3])
    if code == CONFINEMENT_CAUSE and state != "void":
        out.add(R[4])


def _row_pairs(check: dict, state: str, out: set[str]) -> None:
    if check.get("declared-exclusion") is True and state != "not-exercised":
        out.add(R[5])


def _resolves(ref: Any, evidence: dict) -> bool:
    return _is_str(ref) and ref in evidence


MISMATCH = "mismatch"
Outcome = tuple  # (verdict: str, rules: list[str])


def _outcome_of(body: Any) -> tuple | None:
    if not _is_obj(body):
        return None
    verdict, rules = body.get("verdict"), body.get("rules")
    if not _is_str(verdict) or not isinstance(rules, list) or not all(_is_str(r) for r in rules):
        return None
    return (verdict, sorted(rules))


def _read_observation(observation: dict, resolves_store: dict) -> tuple | str | None:
    """Returns: outcome tuple, MISMATCH string, or None."""
    if "carried" in observation:
        return _outcome_of(observation["carried"])
    reference = observation.get("reference")
    if not _is_obj(reference) or not _is_str(reference.get("sha256")):
        return None
    locator = reference.get("vector")
    if not _is_str(locator) or locator not in resolves_store:
        return None
    resolved = resolves_store[locator]
    if not _is_obj(resolved) or resolved.get("sha256") != reference["sha256"]:
        return MISMATCH
    return _outcome_of(resolved)


def _recomputed_moved(item: dict, resolves_store: dict) -> set | str | None:
    """The slots that moved between two observations, MISMATCH, or None."""
    observations = item["observations"]
    if len(observations) != 2:
        return None
    read = [_read_observation(o, resolves_store) for o in observations]
    if any(r == MISMATCH for r in read):
        return MISMATCH
    if read[0] is None or read[1] is None or isinstance(read[0], str) or isinstance(read[1], str):
        return None
    first, second = read[0], read[1]
    moved = set()
    if first[0] != second[0]:
        moved.add("verdict")
    if first[1] != second[1]:
        moved.add("fired-rule list")
    return moved


def _row_other_verdict(other: dict, ov: str, evidence: dict, resolves_store: dict, out: set) -> None:
    has_domain = "domain" in other
    if has_domain and not _is_str(other["domain"]):
        out.add(R[28])
    if ov == "foreclosed" and not (_is_str(other.get("constraint-set")) and has_domain):
        out.add(R[10])
    ref = other.get("ref")
    if ov in ("demonstrated", "foreclosed") and not _resolves(ref, evidence):
        out.add(R[11])
        return
    if ov == "demonstrated":
        moved = _recomputed_moved(evidence[ref], resolves_store)
        if isinstance(moved, set) and "verdict" not in moved:
            out.add(R[25])


def _delta_changes(item: dict) -> list | None:
    delta = _get(item, "delta")
    if not _is_obj(delta):
        return None
    changes = delta.get("changes")
    if not isinstance(changes, list) or not changes:
        return None
    if not all(_is_obj(c) and _is_str(c.get("field")) and bool(c["field"]) for c in changes):
        return None
    return changes


def arity(item: dict) -> int:
    changes = _delta_changes(item)
    return 0 if changes is None else len(changes)


def _delta_related(item: dict) -> bool:
    fixed = item["fixed"]
    pinned = all(
        _is_str(fixed.get(k)) and bool(fixed[k]) for k in ("checker", "constraint-set", "domain")
    )
    return len(item["observations"]) == 2 and _delta_changes(item) is not None and pinned


def _row_discrimination(disc: dict, evidence: dict, out: set) -> None:
    ref = disc.get("ref")
    if not _resolves(ref, evidence):
        out.add(R[11])
        return
    if evidence[ref].get("changed") == "checker rule":
        out.add(R[12])
    if not _delta_related(evidence[ref]):
        out.add(R[24])


def _row_recomputed_moved(item: dict, resolves_store: dict, out: set) -> None:
    recomputed = _recomputed_moved(item, resolves_store)
    if recomputed == MISMATCH:
        out.add(R[20])
        return
    if not isinstance(recomputed, set):
        return
    declared = {v for v in item["moved"] if v in ("verdict", "fired-rule list")}
    if declared != recomputed:
        out.add(R[21])


def _row_qualifiers(check: dict, state: str, evidence: dict, resolves_store: dict, out: set) -> None:
    other = check.get("other-verdict") or {}
    disc = check.get("discrimination") or {}
    if state in NON_VERDICT_STATES and ("other-verdict" in check or "discrimination" in check):
        out.add(R[6])
    ov = other.get("value", "unknown")
    dv = disc.get("value", "unknown")
    if ov not in OTHER_VERDICT or dv not in DISCRIMINATION:
        out.add(R[19])
        return
    if ov == "foreclosed" and dv == "demonstrated":
        out.add(R[8])
    if dv == "demonstrated" and ov in ("unknown", "possible-not-demonstrated"):
        out.add(R[9])
    _row_other_verdict(other, ov, evidence, resolves_store, out)
    if dv == "demonstrated":
        _row_discrimination(disc, evidence, out)


def _digest_referenced(observation: dict) -> bool:
    if "carried" in observation:
        return True
    reference = observation.get("reference")
    return _is_obj(reference) and _is_str(reference.get("sha256"))


def _rows_evidence_form(item: dict, out: set) -> None:
    if item["moved"] and not all(_digest_referenced(o) for o in item["observations"]):
        out.add(R[26])
    delta = item.get("delta")
    if "arity" in item or (_is_obj(delta) and "arity" in delta):
        out.add(R[27])
    if not _is_str(item["fixed"].get("domain")):
        out.add(R[28])


def _rows_evidence(item: dict, resolves_store: dict, out: set) -> None:
    if item["changed"] not in CHANGED:
        out.add(R[19])
    compared, moved = item["compared"], item["moved"]
    if any(v not in SLOTS for v in compared + moved):
        out.add(R[19])
    if not set(moved) <= set(compared):
        out.add(R[16])
    _rows_evidence_form(item, out)
    _row_recomputed_moved(item, resolves_store, out)


def _counts(checks: list) -> dict:
    counts = {"declared": len(checks), "exercised": 0}
    for state in STATES:
        counts[state] = 0
    for check in checks:
        state = check["state"]
        if state in counts:
            counts[state] += 1
        if state != "not-exercised":
            counts["exercised"] += 1
    return counts


def _set_binding(ref: Any, out: set) -> bool:
    if not _is_obj(ref) or not _is_str(ref.get("sha256")):
        out.add(R[15])
        return False
    count = ref.get("leaf-count")
    if not _is_int(count) or count < 0:
        out.add(R[15])
        return False
    if ref.get("tree-shape") not in TREE_SHAPES:
        out.add(R[15])
        return False
    return True


def _identity(checks_ref: Any, ids: set) -> bool:
    if not isinstance(checks_ref, list) or not checks_ref:
        return False
    return all(_is_str(c) and c in ids for c in checks_ref)


BINDING_SLOTS = ("checker", "constraint-set")


def _row_control_binding(bound: Any, run_fixed: Any, out: set) -> None:
    if not (_is_obj(bound) and _is_obj(run_fixed)):
        return
    if any(bound.get(slot) != run_fixed.get(slot) for slot in BINDING_SLOTS):
        out.add(R[29])


def _row_control(field: dict, ids: set, run_fixed: Any, out: set) -> None:
    control = _get(field, "control")
    if not _is_obj(control) or not _identity(control.get("checks"), ids):
        out.add(R[13])
    elif control.get("state") != "fail":
        out.add(R[13])
    else:
        _row_control_binding(control.get("fixed"), run_fixed, out)


def _rows_negative_capable(rollup: dict, counts: dict, ids: set, run_fixed: Any, out: set) -> None:
    field = _get(rollup, "negative-capable")
    if not _is_obj(field) or not _is_str(field.get("kind")):
        out.add(R[13])
        return
    kind = field["kind"]
    if kind not in NEGATIVE_CAPABLE:
        out.add(R[19])
    elif kind == "shown-by-run" and counts["fail"] < 1:
        out.add(R[13])
    elif kind == "control-failed":
        _row_control(field, ids, run_fixed, out)
    elif kind == "prior-discriminating-run":
        if not _identity(field.get("check-identity"), ids):
            out.add(R[14])
        _set_binding(field.get("reference"), out)


COVERAGE_STRINGS = ("surface", "scan-depth", "point-in-time", "linked-repo")


def _count_field(value: Any) -> bool:
    return _is_int(value) and value >= 0


def _coverage_well_formed(coverage: dict) -> bool:
    if not all(_is_str(coverage.get(k)) for k in COVERAGE_STRINGS):
        return False
    snapshots = coverage.get("snapshots")
    if not isinstance(snapshots, list):
        return False
    if not all(_is_obj(s) and _is_str(s.get("name")) and _is_str(s.get("date")) for s in snapshots):
        return False
    if not isinstance(coverage.get("live-observed"), bool):
        return False
    if not isinstance(coverage.get("sampled"), bool):
        return False
    scannable = coverage.get("scannable-files")
    if not _count_field(scannable):
        return False
    if coverage["sampled"]:
        scanned = coverage.get("scanned-files")
        if not _count_field(scanned) or scanned > scannable:
            return False
    return True


def _rows_coverage(report: dict, out: set) -> None:
    coverage = _get(report, "coverage")
    if coverage is None:
        return
    if not _is_obj(coverage) or not _coverage_well_formed(coverage):
        out.add(R[22])


CLAIMS = ("satisfied", "not-satisfied", "not-claimable")
NO_VOID = "no-void"


def _demonstrated(check: dict) -> bool:
    disc = _get(check, "discrimination")
    return bool(_is_obj(disc) and disc.get("value") == "demonstrated")


def _claim_holds(name: str, claim: dict, checks: list, counts: dict) -> bool:
    populations = {
        "accounting": counts["declared"],
        "execution": counts["declared"],
        "evidence": counts["pass"] + counts["fail"],
        NO_VOID: counts["declared"],
    }
    population, value = claim.get("population"), claim.get("claim")
    if population != populations[name] or value not in CLAIMS:
        return False
    if population == 0:
        return bool(value == "not-claimable")
    if value != "satisfied":
        return True
    if name == "execution":
        return counts["exercised"] == counts["declared"]
    if name == "evidence":
        return all(_demonstrated(c) for c in checks if c["state"] == "pass")
    if name == NO_VOID:
        return counts["void"] == 0
    return True


def _rows_completeness(rollup: dict, checks: list, counts: dict, out: set) -> None:
    claims = _get(rollup, "completeness")
    if claims is None:
        return
    if not _is_obj(claims):
        out.add(R[23])
        return
    for name in ("accounting", "execution", "evidence"):
        claim = _get(claims, name)
        if not _is_obj(claim) or not _claim_holds(name, claim, checks, counts):
            out.add(R[23])
            return
    if NO_VOID in claims:
        claim = claims[NO_VOID]
        if not _is_obj(claim) or not _claim_holds(NO_VOID, claim, checks, counts):
            out.add(R[23])


def _carried_referenced(report: dict) -> tuple:
    carried = referenced = 0
    for item in report.get("evidence", []):
        for observation in item["observations"]:
            if "carried" in observation:
                carried += 1
            else:
                referenced += 1
    return carried, referenced


def _rows_rollup(report: dict, checks: list, out: set) -> None:
    counts = _counts(checks)
    rollup = _get(report, "roll-up")
    if rollup is None:
        out.add(R[17])
        return
    if any(rollup.get(key) != value for key, value in counts.items()):
        out.add(R[17])
    carried, referenced = _carried_referenced(report)
    if rollup.get("carried") != carried or rollup.get("referenced") != referenced:
        out.add(R[18])
    _rows_negative_capable(
        rollup, counts, {c["check"] for c in checks}, report.get("fixed"), out
    )
    _rows_completeness(rollup, checks, counts, out)


def _rows_check_set(report: dict, checks: list, out: set) -> None:
    binding = _get(report, "check-set")
    if not _set_binding(binding, out):
        return
    if binding["leaf-count"] != len(checks):
        out.add(R[15])
        return
    try:
        root = check_set_root(checks, binding["tree-shape"])
    except FloatRefused:
        out.add(R[20])
        return
    if binding["sha256"] != root:
        out.add(R[20])


def report_rejections(report: dict, resolves_store: dict | None = None) -> list[str]:
    """The requirement identifiers this report is rejected under, sorted."""
    out: set[str] = set()
    store = resolves_store or {}
    checks = report["checks"]
    evidence = {e["id"]: e for e in report.get("evidence", [])}
    for check in checks:
        state = check["state"]
        if state not in STATES:
            out.add(R[19])
            continue
        _row_cause(check, state, out)
        _row_pairs(check, state, out)
        _row_qualifiers(check, state, evidence, store, out)
    for item in evidence.values():
        _rows_evidence(item, store, out)
    _rows_rollup(report, checks, out)
    _rows_check_set(report, checks, out)
    _rows_coverage(report, out)
    return sorted(out)


# ============================================================================
# AGENT-RUN-METRICS VALIDATOR (ARM-R-001 to ARM-R-022)
# ============================================================================
ARM_STATUSES = ("running", "completed", "failed", "aborted")
ARM_ENDED = ("completed", "failed", "aborted")
ARM_RUN_MEMBERS = (
    "version", "run_id", "parent_run_id", "root_run_id", "start", "end", "status",
    "termination_reason", "agent", "models", "step_count", "steps", "totals",
    "subtree_totals", "cost", "labels", "errors", "revision", "trace_id",
)
ARM_IDENTIFIERS = ("run_id", "parent_run_id", "root_run_id")
ARM_TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z$")
ARM_AMOUNT = re.compile(r"^-?[0-9]+(\.[0-9]+)?$")
ARM_R = {n: f"ARM-R-{n:03d}" for n in range(1, 23)}


def arm_shape_errors(document: Any) -> list[str]:
    if not _is_obj(document):
        return ["the document is not a JSON object"]
    out: list[str] = []
    for member in ("version", "run_id", "start", "status", "step_count", "totals"):
        if member not in document:
            out.append(f"the Run carries no {member} member")
    if "steps" in document and not isinstance(document["steps"], list):
        out.append("steps is present and is not an array")
    for i, step in enumerate(document.get("steps") or []):
        if not _is_obj(step):
            out.append(f"steps[{i}] is not an object")
        elif not _is_int(step.get("index")) or not _is_str(step.get("kind")):
            out.append(f"steps[{i}] carries no integer index or no string kind")
    return out


def _arm_rows_status(run: dict, out: set) -> None:
    if run["version"] != "1":
        out.add(ARM_R[1])
    status = run["status"]
    if status not in ARM_STATUSES:
        out.add(ARM_R[4])
    elif (status in ARM_ENDED) != ("end" in run):
        out.add(ARM_R[2])
    start, end = run.get("start"), run.get("end")
    if _is_str(start) and _is_str(end) and ARM_TIMESTAMP.match(start) and ARM_TIMESTAMP.match(end):
        if end < start:
            out.add(ARM_R[3])
    steps = run.get("steps")
    if isinstance(steps, list) and _is_int(run["step_count"]) and run["step_count"] < len(steps):
        out.add(ARM_R[5])


def _arm_rows_members(run: dict, out: set) -> None:
    if "root_run_id" in run and "parent_run_id" not in run and run["root_run_id"] != run["run_id"]:
        out.add(ARM_R[16])
    if any(m not in ARM_RUN_MEMBERS and not m.startswith("x-") for m in run):
        out.add(ARM_R[21])
    labels = run.get("labels")
    if labels is not None and (not _is_obj(labels) or not all(_is_str(v) for v in labels.values())):
        out.add(ARM_R[18])
    cost = run.get("cost")
    if _is_obj(cost) and not (_is_str(cost.get("amount")) and ARM_AMOUNT.match(cost["amount"])):
        out.add(ARM_R[17])


def _arm_rows_timestamps(run: dict, out: set) -> None:
    stamps = [run.get("start"), run.get("end")]
    for step in run.get("steps") or []:
        stamps.append(step.get("start"))
        stamps.append(step.get("end"))
    if any(s is not None and not (_is_str(s) and ARM_TIMESTAMP.match(s)) for s in stamps):
        out.add(ARM_R[19])
    names = [run.get(k) for k in ARM_IDENTIFIERS if k in run]
    for step in run.get("steps") or []:
        if "invocation_id" in step:
            names.append(step["invocation_id"])
        if _is_obj(step.get("tool")) and "name" in step["tool"]:
            names.append(step["tool"]["name"])
    if any(not (_is_str(n) and 0 < len(str(n)) <= 128) for n in names):
        out.add(ARM_R[20])


def _arm_rows_usage(usage: Any, out: set) -> None:
    if not _is_obj(usage):
        return
    counters = {k: v for k, v in usage.items() if k != "cache_writes"}
    if any(not _is_int(v) or v < 0 for v in counters.values()):
        out.add(ARM_R[9])
        return
    read = counters.get("cache_read_tokens", 0)
    write = counters.get("cache_write_tokens", 0)
    if "input_tokens" in counters:
        if read > counters["input_tokens"]:
            out.add(ARM_R[10])
        elif read + write > counters["input_tokens"]:
            out.add(ARM_R[11])
    reasoning = counters.get("reasoning_tokens", 0)
    if "output_tokens" in counters and reasoning > counters["output_tokens"]:
        out.add(ARM_R[22])
    writes = usage.get("cache_writes")
    if not isinstance(writes, list):
        return
    lifetimes = [w.get("lifetime") for w in writes if _is_obj(w)]
    if len(set(lifetimes)) != len(lifetimes):
        out.add(ARM_R[13])
    tokens = [w.get("tokens") for w in writes if _is_obj(w)]
    if all(_is_int(t) for t in tokens) and sum(tokens) != write:
        out.add(ARM_R[14])


def _arm_rows_steps(run: dict, out: set) -> None:
    steps = run.get("steps") or []
    indexes = [s["index"] for s in steps]
    starts = [s.get("start") for s in steps]
    pairs = list(zip(starts, starts[1:]))
    ordered = all(_is_str(a) and _is_str(b) and a <= b for a, b in pairs)
    if len(set(indexes)) != len(indexes) or indexes != sorted(indexes) or not ordered:
        out.add(ARM_R[6])
    invocations: list[str] = []
    for step in steps:
        kind = step["kind"]
        if kind == "model_invocation":
            if not (_is_obj(step.get("usage")) and _is_obj(step.get("model"))):
                out.add(ARM_R[7])
            if _is_str(step.get("invocation_id")):
                invocations.append(step["invocation_id"])
        elif kind == "tool_call" and (not _is_obj(step.get("tool")) or "usage" in step):
            out.add(ARM_R[8])
        _arm_rows_usage(step.get("usage"), out)
    if len(set(invocations)) != len(invocations):
        out.add(ARM_R[15])


def _arm_rows_totals(run: dict, out: set) -> None:
    totals = run["totals"]
    _arm_rows_usage(totals, out)
    steps = run.get("steps")
    if not isinstance(steps, list) or not _is_obj(totals) or run["step_count"] != len(steps):
        return
    usages = [s["usage"] for s in steps if _is_obj(s.get("usage"))]
    if any(not _is_int(v) for u in usages for k, v in u.items() if k != "cache_writes"):
        return
    members = {k for u in usages for k in u if k != "cache_writes"} | {
        k for k in totals if k != "cache_writes"
    }
    for member in members:
        expected = sum(u.get(member, 0) for u in usages)
        if totals.get(member) != expected:
            out.add(ARM_R[12])
            return


def arm_rejections(document: dict) -> list[str]:
    out: set[str] = set()
    _arm_rows_status(document, out)
    _arm_rows_members(document, out)
    _arm_rows_timestamps(document, out)
    _arm_rows_steps(document, out)
    _arm_rows_totals(document, out)
    return sorted(out)


# ============================================================================
# LLM-CONTEXT-DISCOVERY VALIDATOR (LCD-R-001 to LCD-R-011)
# ============================================================================
LCD_WELL_KNOWN = "/.well-known/llm-context"
LCD_REDIRECTS = (301, 302, 307, 308)
LCD_R = {n: f"LCD-R-{n:03d}" for n in range(1, 12)}


def lcd_shape_errors(document: Any) -> list[str]:
    if not _is_obj(document):
        return ["the document is not a JSON object"]
    out: list[str] = []
    if not _is_str(document.get("origin")):
        out.append("the snapshot carries no string origin")
    if not _is_obj(document.get("resources")):
        out.append("the snapshot carries no resources object")
    if not _is_obj(document.get("consumer")):
        out.append("the snapshot carries no consumer object")
    for slot in ("well-known", "link", "robots"):
        if slot in document and document[slot] is not None and not _is_obj(document[slot]):
            out.append(f"{slot} is present and is not an object")
    return out


def _lcd_absolute(uri: Any) -> bool:
    return _is_str(uri) and (uri.startswith("https://") or uri.startswith("http://"))


def _lcd_origin_of(uri: str) -> str:
    scheme, _, rest = uri.partition("://")
    return scheme + "://" + rest.split("/", 1)[0]


def _lcd_path_of(uri: str) -> str:
    _, _, rest = uri.partition("://")
    return "/" + rest.split("/", 1)[1] if "/" in rest else "/"


def _lcd_disallowed(uri: str, origin: str, robots: dict | None) -> bool:
    if not _lcd_absolute(uri) or _lcd_origin_of(uri) != origin or robots is None:
        return False
    rules = [r for r in robots.get("disallow") or [] if _is_str(r) and r]
    return any(_lcd_path_of(uri).startswith(rule) for rule in rules)


def _lcd_records(robots: dict | None) -> list:
    if robots is None:
        return []
    out = []
    for record in robots.get("records") or []:
        if not _is_obj(record) or not _is_str(record.get("name")):
            continue
        if record["name"].lower() == "llm-context":
            out.append(record.get("value"))
    return out


def _lcd_well_known_target(document: dict, out: set) -> str | None:
    response = document.get("well-known")
    if response is None:
        return None
    status = response.get("status")
    if status == 404:
        return None
    if _is_int(status) and 200 <= status < 300:
        content_type = response.get("content-type")
        if _is_str(content_type) and content_type.lower().startswith("text/html"):
            out.add(LCD_R[1])
        if response.get("negotiated") is True and not _is_str(response.get("content-language")):
            out.add(LCD_R[10])
        return str(document["origin"]) + LCD_WELL_KNOWN
    if status in LCD_REDIRECTS and _lcd_absolute(response.get("location")):
        return str(response["location"])
    out.add(LCD_R[3])
    return None


def _lcd_rows_publisher(document: dict, out: set) -> str | None:
    origin = document["origin"]
    resources = document["resources"]
    robots = document.get("robots")
    link = document.get("link")
    link_target = link.get("target") if _is_obj(link) else None
    well_known = _lcd_well_known_target(document, out)
    robots_targets: list[str] = []
    for value in _lcd_records(robots):
        if not _lcd_absolute(value):
            out.add(LCD_R[4])
            continue
        if _lcd_disallowed(value, origin, robots):
            out.add(LCD_R[5])
        robots_targets.append(value)
    targets = [t for t in [link_target, well_known, *robots_targets] if _is_str(t)]
    for target in targets:
        resource = resources.get(target)
        if _is_obj(resource) and resource.get("role") == "detail":
            out.add(LCD_R[2])
            break
    if _is_str(link_target):
        return link_target
    if well_known is not None:
        return well_known
    return robots_targets[0] if robots_targets else None


def _lcd_rows_consumer(document: dict, selected: str | None, out: set) -> None:
    origin = document["origin"]
    resources = document["resources"]
    robots = document.get("robots")
    consumer = document["consumer"]
    resolved = consumer.get("resolved")
    if resolved is not None and resolved != selected:
        out.add(LCD_R[6])
    retrieved = [u for u in consumer.get("retrieved") or [] if _is_str(u)]
    known = [u for u in retrieved if _is_obj(resources.get(u))]
    indexes = [u for u in known if resources[u].get("role") == "index"]
    if len(indexes) > 1:
        out.add(LCD_R[7])
    foreign = _lcd_absolute(resolved) and _lcd_origin_of(str(resolved)) != origin
    if foreign and consumer.get("attributed-to") == origin:
        out.add(LCD_R[8])
    ceiling = consumer.get("ceiling-octets")
    if not _is_int(ceiling) or ceiling <= 0:
        out.add(LCD_R[9])
    if any(_lcd_disallowed(u, origin, robots) for u in retrieved):
        out.add(LCD_R[11])


def lcd_rejections(document: dict) -> list[str]:
    out: set[str] = set()
    selected = _lcd_rows_publisher(document, out)
    _lcd_rows_consumer(document, selected, out)
    return sorted(out)


# ============================================================================
# DISPATCHER — route by subjectType
# ============================================================================
def subject_shape_errors(subject_type: str, subject: Any) -> list[str]:
    if subject_type == "agent-run-metrics":
        return arm_shape_errors(subject)
    if subject_type == "llm-context-discovery":
        return lcd_shape_errors(subject)
    return shape_errors(subject)


def subject_rejections(subject_type: str, subject: dict, resolves_store: dict | None = None) -> list[str]:
    if subject_type == "agent-run-metrics":
        return arm_rejections(subject)
    if subject_type == "llm-context-discovery":
        return lcd_rejections(subject)
    return report_rejections(subject, resolves_store)


# ============================================================================
# MEMBER IDENTITY — same algorithm as upstream, independent impl
# ============================================================================
ID_FIELDS = ("kind", "family", "requirements", "subjectType", "subject", "resolves", "expected")


def identify(document: dict) -> str:
    return "v" + sha(compact({k: document.get(k) for k in ID_FIELDS}))[:16]


# ============================================================================
# MAIN ADJUDICATOR
# ============================================================================
def load_vector(path: str) -> dict | None:
    """Load a vector file, parsing floats as Decimal to preserve exact bytes."""
    try:
        with open(path, "rb") as f:
            raw = f.read()
        doc = json.loads(raw, parse_float=decimal.Decimal)
        return doc
    except Exception as e:
        print(f"  ERROR loading {path}: {e}", file=sys.stderr)
        return None


def adjudicate_vector(entry: dict, corpus_dir: str) -> dict:
    """Judge one vector independently, without reading expected for judgment."""
    vid = entry["id"]
    file_path = os.path.join(corpus_dir, entry["file"])
    
    result = {
        "id": vid,
        "family": entry.get("family", ""),
        "subject_type": entry.get("subjectType", ""),
        "file": entry["file"],
    }
    
    # Load the document
    doc = load_vector(file_path)
    if doc is None:
        result["error"] = "failed to load vector file"
        result["computed_verdict"] = "error"
        result["computed_rejects"] = []
        return result
    
    # Extract subject
    subject_type = str(entry.get("subjectType", "report"))
    subject = doc.get("subject")
    
    # Shape check first
    shape = subject_shape_errors(subject_type, subject)
    if shape:
        result["shape_errors"] = shape
        # Shape errors mean we can't run rule-based judgment
        # But we still try to get the rejection list
        result["computed_verdict"] = "reject"
        result["computed_rejects"] = []
        result["computed_rejects_note"] = f"shape error: {'; '.join(shape[:3])}"
        return result
    
    # Get resolves store
    resolves_raw = doc.get("resolves")
    resolves_store = resolves_raw if _is_obj(resolves_raw) else {}
    
    # Run the validator
    try:
        computed_rejects = subject_rejections(subject_type, subject, resolves_store)
    except Exception as e:
        result["error"] = f"validator exception: {e}"
        result["computed_verdict"] = "error"
        result["computed_rejects"] = []
        return result
    
    # Determine computed verdict
    if computed_rejects:
        result["computed_verdict"] = "reject"
    else:
        result["computed_verdict"] = "accept"
    result["computed_rejects"] = computed_rejects
    
    # Verify identity (independent computation)
    try:
        recomputed_id = identify(doc)
        if recomputed_id != vid:
            result["identity_mismatch"] = True
            result["recomputed_id"] = recomputed_id
    except FloatRefused:
        result["float_refused_in_id"] = True
    except Exception as e:
        result["identity_error"] = str(e)
    
    return result


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Independent W3C-Report Corpus Adjudicator")
    parser.add_argument("--corpus-dir", default=DEFAULT_CORPUS_DIR, help="Corpus directory")
    parser.add_argument("--json-output", default=None, help="Output JSON path")
    args = parser.parse_args()
    
    corpus_dir = args.corpus_dir
    manifest_path = os.path.join(corpus_dir, "MANIFEST.json")
    
    print(f"=== Independent W3C-Report Corpus Adjudicator ===")
    print(f"Corpus: {corpus_dir}")
    print(f"Manifest: {manifest_path}")
    
    t0 = time.time()
    
    # Load manifest
    with open(manifest_path, encoding="utf-8") as f:
        manifest = json.load(f)
    
    vectors = manifest["vectors"]
    print(f"Vectors: {len(vectors)}")
    
    # Process each vector
    results = []
    agree_count = 0
    disagree_count = 0
    error_count = 0
    
    for i, entry in enumerate(vectors):
        if (i + 1) % 50 == 0:
            print(f"  Processing {i+1}/{len(vectors)}...")
        
        vec_result = adjudicate_vector(entry, corpus_dir)
        
        # Post-hoc comparison with expected
        expected = entry.get("expected", {})
        expected_verdict = expected.get("verdict", "")
        expected_rejects = expected.get("rejects", [])
        
        vec_result["expected_verdict"] = expected_verdict
        vec_result["expected_rejects"] = expected_rejects
        
        computed_verdict = vec_result.get("computed_verdict", "error")
        computed_rejects = vec_result.get("computed_rejects", [])
        
        if computed_verdict == "error":
            error_count += 1
            vec_result["agree"] = False
        else:
            # Compare verdict and rejects
            verdict_match = (computed_verdict == expected_verdict)
            rejects_match = (sorted(computed_rejects) == sorted(expected_rejects))
            vec_result["verdict_match"] = verdict_match
            vec_result["rejects_match"] = rejects_match
            vec_result["agree"] = verdict_match and rejects_match
            
            if vec_result["agree"]:
                agree_count += 1
            else:
                disagree_count += 1
        
        results.append(vec_result)
    
    elapsed = time.time() - t0
    
    # Summary
    summary = {
        "total": len(vectors),
        "agree": agree_count,
        "disagree": disagree_count,
        "error": error_count,
        "elapsed_seconds": round(elapsed, 2),
    }
    
    print(f"\n=== RESULTS ===")
    print(f"Total: {summary['total']}")
    print(f"Agree: {summary['agree']}")
    print(f"Disagree: {summary['disagree']}")
    print(f"Error: {summary['error']}")
    print(f"Time: {summary['elapsed_seconds']}s")
    
    # Print disagree details
    if disagree_count > 0:
        print(f"\n=== DISAGREEMENTS ===")
        for r in results:
            if not r.get("agree"):
                print(f"  {r['id']}:")
                print(f"    family={r.get('family')} subject_type={r.get('subject_type')}")
                print(f"    expected: verdict={r['expected_verdict']} rejects={r['expected_rejects']}")
                print(f"    computed: verdict={r.get('computed_verdict')} rejects={r.get('computed_rejects')}")
                if r.get('shape_errors'):
                    print(f"    shape_errors: {r['shape_errors'][:3]}")
                if r.get('computed_rejects_note'):
                    print(f"    note: {r['computed_rejects_note']}")
    
    # Output JSON
    output = {
        "script": "independent_w3creport_full.py",
        "description": "Independent semantic adjudication of vectors-w3c-report corpus",
        "corpus_dir": corpus_dir,
        "summary": summary,
        "results": results,
    }
    
    output_path = args.json_output or os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        f"adjudication_results_{int(time.time())}.json"
    )
    
    # Convert Decimals to strings for JSON serialization
    def sanitize(obj):
        if isinstance(obj, decimal.Decimal):
            return str(obj)
        if isinstance(obj, dict):
            return {k: sanitize(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [sanitize(v) for v in obj]
        return obj
    
    output = sanitize(output)
    
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    
    print(f"\nResults written to: {output_path}")
    
    return 0 if disagree_count == 0 and error_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
