#!/usr/bin/env python3
"""
Independent Adjudication: anchored-record-chain corpus (v0.17.6)
=================================================================

SHARES NO CODE with agent_evidence_vectors. Every check is rewritten from
scratch using Python stdlib + cryptography (Ed25519 only).

Reads upstream anchoredchain.py and README.md for rule derivation ONLY.
All decisions come from raw case bytes (store.jsonl / case.json / anchor.json).
MANIFEST.json expected values are loaded solely for post-hoc comparison.

Check order (per upstream contract, README §"The reader checks in this order"):
  1. signature_invalid        – every record Ed25519 under producer key
  2. anchor_signature_invalid – anchor Ed25519 under anchor key
  3. record_from_other_chain  – every record.chain == case.chain
  4. chain_link_broken        – every record.prev == SHA-256(prev raw line)
  5. anchored_head_missing    – store still holds record at anchor.index
  6. anchored_head_mismatch   – that record's digest == anchor.head

A store passing all six is verified:
  chain_anchored             – anchor.index == len(lines)-1
  records_after_last_anchor  – anchor.index <  len(lines)-1

Usage:
  python3 independent_anchored_full.py --corpus-dir /tmp/a176/.../vectors-anchored-chain
  python3 independent_anchored_full.py --corpus-dir /tmp/a176/.../vectors-anchored-chain --json-output PATH

Exit 0.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

# ---------- cryptography (sole external dep, for Ed25519) ----------
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

GENESIS = "0" * 64

# Check order = the contract: first failing check names the reason.
CHECK_ORDER = (
    "signature_invalid",
    "anchor_signature_invalid",
    "record_from_other_chain",
    "chain_link_broken",
    "anchored_head_missing",
    "anchored_head_mismatch",
)


# ====================================================================
# From-scratch primitives
# ====================================================================

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def jcs_dumps(obj: Any) -> bytes:
    """RFC 8785 JCS canonical JSON — from scratch.
    Compact (no whitespace), keys sorted by Unicode code-point order
    (identical to UTF-16 code-unit order for BMP-only ASCII keys)."""
    def ser(v: Any) -> str:
        if v is None:
            return "null"
        if v is True:
            return "true"
        if v is False:
            return "false"
        if isinstance(v, int):
            return str(v)
        if isinstance(v, float):
            # JCS float: not needed for this corpus (no floats in records)
            return json.dumps(v)
        if isinstance(v, str):
            return _jcs_string(v)
        if isinstance(v, list):
            return "[" + ",".join(ser(x) for x in v) + "]"
        if isinstance(v, dict):
            keys = sorted(v.keys())
            return "{" + ",".join(_jcs_string(k) + ":" + ser(v[k]) for k in keys) + "}"
        raise ValueError(f"JCS: unsupported type {type(v)}")
    return ser(obj).encode("utf-8")


def _jcs_string(s: str) -> str:
    """RFC 8785 §3.2.2.2 JSON string canonicalisation."""
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == '\\':
            out.append('\\\\')
        elif o == 0x0008:
            out.append('\\b')
        elif o == 0x0009:
            out.append('\\t')
        elif o == 0x000A:
            out.append('\\n')
        elif o == 0x000C:
            out.append('\\f')
        elif o == 0x000D:
            out.append('\\r')
        elif o < 0x20:
            out.append(f'\\u{o:04x}')
        elif 0x7F <= o <= 0x9F:
            out.append(f'\\u{o:04x}')
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def ed25519_verify(pub_raw: bytes, msg: bytes, sig: bytes) -> bool:
    """Verify Ed25519 signature. pub_raw = 32-byte raw public key."""
    try:
        Ed25519PublicKey.from_public_bytes(pub_raw).verify(sig, msg)
        return True
    except (InvalidSignature, ValueError):
        return False


def b64decode_strict(s: str) -> bytes | None:
    """Strict base64 decode (standard alphabet, padded)."""
    try:
        return base64.b64decode(s, validate=True)
    except (ValueError, base64.binascii.Error):
        return None


# ====================================================================
# Corpus loading
# ====================================================================

def load_case(case_dir: Path) -> tuple[dict, list[bytes], dict]:
    """Load case.json, store.jsonl raw lines, anchor.json from a case dir."""
    case = json.loads((case_dir / "case.json").read_text("utf-8"))
    store_path = case_dir / case["store"]
    raw = store_path.read_bytes()
    lines = [ln for ln in raw.split(b"\n") if ln]
    anchor = json.loads((case_dir / case["anchor"]).read_text("utf-8"))
    return case, lines, anchor


def envelope_signature_ok(envelope: dict, body_key: str, pub_hex: str) -> bool:
    """Verify envelope.sig over JCS(envelope[body_key]) under hex-encoded key."""
    pub_raw = bytes.fromhex(pub_hex)
    sig_b64 = envelope.get("sig", "")
    sig = b64decode_strict(sig_b64)
    if sig is None:
        return False
    body = envelope.get(body_key)
    if not isinstance(body, dict):
        return False
    msg = jcs_dumps(body)
    return ed25519_verify(pub_raw, msg, sig)


# ====================================================================
# The six checks — from scratch, bytes-driven
# ====================================================================

def check_signature_invalid(case: dict, envelopes: list[dict]) -> bool:
    """Check 1: Does any record signature fail under the producer key?"""
    producer_hex = case["keys"]["producer"]
    for env in envelopes:
        if not envelope_signature_ok(env, "record", producer_hex):
            return True  # failure detected
    return False


def check_anchor_signature_invalid(case: dict, anchor: dict) -> bool:
    """Check 2: Does the anchor signature fail under the anchor key?"""
    anchor_hex = case["keys"]["anchor"]
    return not envelope_signature_ok(anchor, "anchor", anchor_hex)


def check_record_from_other_chain(case: dict, envelopes: list[dict]) -> bool:
    """Check 3: Does any record name a different chain?"""
    expected_chain = case["chain"]
    for env in envelopes:
        record = env.get("record", {})
        if record.get("chain") != expected_chain:
            return True
    return False


def check_chain_link_broken(envelopes: list[dict], raw_lines: list[bytes]) -> bool:
    """Check 4: Does any record.prev != SHA-256(previous raw line)?
    First record's prev must be GENESIS (64 zeros)."""
    for i, env in enumerate(envelopes):
        record = env.get("record", {})
        prev_claimed = record.get("prev", "")
        if i == 0:
            expected_prev = GENESIS
        else:
            expected_prev = sha256_hex(raw_lines[i - 1])
        if prev_claimed != expected_prev:
            return True
    return False


def check_anchored_head_missing(anchor: dict, envelopes: list[dict]) -> bool:
    """Check 5: Is the anchored record missing from the store?
    anchor.index must be a valid index (< len(envelopes))."""
    idx = anchor.get("anchor", {}).get("index", -1)
    return idx >= len(envelopes)


def check_anchored_head_mismatch(
    anchor: dict, raw_lines: list[bytes]
) -> bool:
    """Check 6: Does the anchored record's digest differ from anchor.head?
    Also triggers if index is out of range (missing)."""
    anc = anchor.get("anchor", {})
    idx = anc.get("index", -1)
    if idx >= len(raw_lines):
        return True  # missing ≡ mismatch in upstream logic
    actual_head = sha256_hex(raw_lines[idx])
    expected_head = anc.get("head", "")
    return actual_head != expected_head


# ====================================================================
# Full adjudication for one case
# ====================================================================

def adjudicate_case(case_dir: Path) -> dict[str, str]:
    """Return {"decision": ..., "reason": ...} from raw bytes only."""
    case, raw_lines, anchor = load_case(case_dir)

    # Parse envelopes from raw lines
    envelopes = [json.loads(line) for line in raw_lines]

    # Run the six checks in contract order
    check_results: dict[str, bool] = {}

    # 1. Record signatures
    check_results["signature_invalid"] = check_signature_invalid(case, envelopes)

    # 2. Anchor signature
    check_results["anchor_signature_invalid"] = check_anchor_signature_invalid(case, anchor)

    # 3. Chain identity
    check_results["record_from_other_chain"] = check_record_from_other_chain(case, envelopes)

    # 4. Chain links
    check_results["chain_link_broken"] = check_chain_link_broken(envelopes, raw_lines)

    # 5. Anchored record present
    check_results["anchored_head_missing"] = check_anchored_head_missing(anchor, envelopes)

    # 6. Anchored record digest match
    check_results["anchored_head_mismatch"] = check_anchored_head_mismatch(anchor, raw_lines)

    # First failing check names the reason
    for check_name in CHECK_ORDER:
        if check_results[check_name]:
            return {"decision": "rejected", "reason": check_name}

    # All checks passed → verified
    anc_idx = anchor["anchor"]["index"]
    records_after = len(raw_lines) - 1 - anc_idx
    if records_after > 0:
        reason = "records_after_last_anchor"
    else:
        reason = "chain_anchored"
    return {"decision": "verified", "reason": reason}


# ====================================================================
# Corpus-level driver
# ====================================================================

def adjudicate_corpus(corpus_dir: Path) -> dict:
    """Run all cases, compare to MANIFEST expected, produce report."""
    manifest_path = corpus_dir / "MANIFEST.json"
    manifest = json.loads(manifest_path.read_text("utf-8"))
    vectors = manifest["vectors"]

    results = []
    agree_count = 0
    disagree_count = 0
    disagree_details = []

    for entry in vectors:
        case_id = entry["id"]
        case_dir = corpus_dir / entry["path"]
        expected = entry["expected"]

        computed = adjudicate_case(case_dir)

        agree = (computed["decision"] == expected["decision"] and
                 computed["reason"] == expected["reason"])

        result_entry = {
            "id": case_id,
            "expected_decision": expected["decision"],
            "expected_reason": expected["reason"],
            "computed_decision": computed["decision"],
            "computed_reason": computed["reason"],
            "agree": agree,
        }

        # Extra diagnostic info
        result_entry["manifest_storeSignaturesVerify"] = entry.get("storeSignaturesVerify")
        result_entry["edit"] = entry.get("edit", "")

        results.append(result_entry)

        if agree:
            agree_count += 1
        else:
            disagree_count += 1
            disagree_details.append({
                "id": case_id,
                "expected": f"{expected['decision']}/{expected['reason']}",
                "computed": f"{computed['decision']}/{computed['reason']}",
                "edit": entry.get("edit", ""),
            })

    report = {
        "suite": "anchored-record-chain/v1",
        "adjudicator": "independent_anchored_full.py (shares no code with upstream)",
        "corpus_dir": str(corpus_dir),
        "corpusDigest": manifest.get("corpusDigest", ""),
        "summary": {
            "total": len(vectors),
            "agree": agree_count,
            "disagree": disagree_count,
            "all_agree": disagree_count == 0,
        },
        "results": results,
    }

    if disagree_details:
        report["disagree_details"] = disagree_details

    return report


# ====================================================================
# CLI
# ====================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Independent adjudication of anchored-record-chain corpus"
    )
    parser.add_argument(
        "--corpus-dir", required=True,
        help="Path to vectors-anchored-chain/ corpus directory"
    )
    parser.add_argument(
        "--json-output", default=None,
        help="Write full JSON report to this path"
    )
    args = parser.parse_args()

    corpus_dir = Path(args.corpus_dir)
    if not corpus_dir.is_dir():
        print(f"ERROR: corpus dir not found: {corpus_dir}", file=sys.stderr)
        sys.exit(2)

    manifest_path = corpus_dir / "MANIFEST.json"
    if not manifest_path.is_file():
        print(f"ERROR: MANIFEST.json not found in {corpus_dir}", file=sys.stderr)
        sys.exit(2)

    report = adjudicate_corpus(corpus_dir)

    # Summary to stdout
    s = report["summary"]
    print(f"anchored-record-chain/v1: {s['total']} cases, "
          f"{s['agree']} agree, {s['disagree']} disagree")
    print(f"All agree: {s['all_agree']}")

    if report.get("disagree_details"):
        print("\nDisagreements:")
        for d in report["disagree_details"]:
            print(f"  {d['id']}: expected={d['expected']} computed={d['computed']}")
            print(f"    edit: {d['edit']}")

    # Write JSON report
    output_path = args.json_output
    if output_path is None:
        output_path = str(Path("./codeact/output/anchored_chain_adjudication.json").resolve())

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8"
    )
    print(f"\nReport written to: {output_path}")

    # Also print per-case summary table
    print("\nPer-case results:")
    print(f"{'Case':<42} {'Expected':<38} {'Computed':<38} {'Agree'}")
    print("-" * 125)
    for r in report["results"]:
        exp = f"{r['expected_decision']}/{r['expected_reason']}"
        comp = f"{r['computed_decision']}/{r['computed_reason']}"
        mark = "✓" if r["agree"] else "✗ MISMATCH"
        print(f"{r['id']:<42} {exp:<38} {comp:<38} {mark}")


if __name__ == "__main__":
    main()
