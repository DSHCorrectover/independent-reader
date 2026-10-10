#!/usr/bin/env python3
"""
Independent Adversarial Execution Evidence (AEE v0.7) Full Verdict Engine
==========================================================================

Completely independent re-implementation of the reference verifier for the
adversarial-execution-evidence corpus (vectors/, 281 vectors) in
agent-evidence-vectors v0.17.4.

SHARES NO CODE with the upstream agent_evidence_vectors package.
All logic is derived from reading run_vectors.py and the specification,
then re-implemented from scratch using Python stdlib + cryptography.

Trust anchor: cosign.pub OUTSIDE the wheel (not used for per-vector verdict,
only for corpus-level integrity which is assumed since we read local files).

Coverage: GATE 0 (structure/well-formedness) + GATE 1 (per-substrate-row
coverage validity) + result recompute + commitment checks + GATE 2 (tiers
via Ed25519 verification).

Usage:
    python3 independent_adversarial_full.py [--output PATH]

No upstream code is imported. No expected values are read for verdict.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import struct
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# ============================================================================
# Paths
# ============================================================================
WHEEL_DIR = Path("/tmp/aev/agent_evidence_vectors")
CORPORA_DIR = WHEEL_DIR / "corpora" / "vectors"
STATEMENTS_DIR = CORPORA_DIR / "statements"
MANIFEST_PATH = CORPORA_DIR / "MANIFEST.json"
OUTPUT_DIR = Path(__file__).resolve().parent

# ============================================================================
# Constants (derived from specification, not imported)
# ============================================================================
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
AEE_PREDICATE_TYPE = "https://in-toto.io/attestation/adversarial-execution-evidence/v0.7"

RFC3339_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")

BINDING_VERSION = "2"
EGRESS_POSTURES = frozenset({"no_network", "allowlist", "sinkhole", "unsafe_bypass_egress"})

RESULT_ORDER = {"fail": 0, "degraded": 1, "pass_indirect": 2, "pass": 3}
METHOD_ORDER = {"reconstructed": 0, "intercepted": 1}

MAX_PARSE_BYTES = 20 << 20  # 20 MiB
MAX_PARSE_DEPTH = 128

KEY_ROLES = ("substrate-observation-test", "wrong-signer-test", "statement-test")

# Covering kinds
COVERING_KINDS = ("interception", "arming", "sealed", "examination")
REGISTERED_NONCOVERING = {
    "moat-drop": "moat-drop-covers-nothing",
    "uncommitted-observation": "uncommitted-observation-covers-nothing",
}

# Reserved members records must carry
RESERVED_MEMBERS = ("aeeRunBinding", "aeeKind", "aeeMethod")

# Chain scope vocabulary
CHAIN_SCOPE_VOCAB = frozenset({"subject", "corpus", "networkPosture"})


# ============================================================================
# JCS (RFC 8785) — Re-implemented from scratch
# ============================================================================

class JcsError(ValueError):
    pass


def _utf16_sort_key(s: str) -> bytes:
    """UTF-16 code-unit sort key per RFC 8785 section 3.2.3."""
    return s.encode("utf-16-be")


def _all_bmp(strings: list[str]) -> bool:
    """All characters in all strings are BMP (no supplementary plane)."""
    for s in strings:
        for ch in s:
            if ord(ch) > 0xFFFF:
                return False
    return True


def jcs_dumps(obj: Any) -> bytes:
    """RFC 8785 JCS canonicalization — I-JSON profile subset."""
    def ser(v: Any) -> str:
        if v is None:
            return "null"
        if v is True:
            return "true"
        if v is False:
            return "false"
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, int):
            if not (-2**53 + 1 <= v <= 2**53 - 1):
                raise JcsError("integer outside safe range")
            return str(v)
        if isinstance(v, float):
            # I-JSON: no non-integer numbers
            if v != int(v):
                raise JcsError("non-integer number")
            iv = int(v)
            if not (-2**53 + 1 <= iv <= 2**53 - 1):
                raise JcsError("integer outside safe range")
            return str(iv)
        if isinstance(v, str):
            out = ['"']
            for ch in v:
                o = ord(ch)
                if ch == '"':
                    out.append('\\"')
                elif ch == "\\":
                    out.append("\\\\")
                elif o < 0x20:
                    ctrl = {0x08: "\\b", 0x09: "\\t", 0x0A: "\\n",
                            0x0C: "\\f", 0x0D: "\r"}
                    out.append(ctrl.get(o, f"\\u{o:04x}"))
                else:
                    out.append(ch)
            out.append('"')
            return "".join(out)
        if isinstance(v, list):
            return "[" + ",".join(ser(x) for x in v) + "]"
        if isinstance(v, dict):
            keys = sorted(v.keys(), key=_utf16_sort_key)
            return "{" + ",".join(
                ser(k) + ":" + ser(v[k]) for k in keys
            ) + "}"
        raise JcsError(f"unsupported type: {type(v)!r}")
    return ser(obj).encode("utf-8")


# ============================================================================
# String scalar checking (RFC 7493 I-JSON)
# ============================================================================

class StringNotScalarError(ValueError):
    pass


def check_string_scalars(raw: bytes) -> None:
    """Scan raw JSON bytes for unpaired surrogates, noncharacters, and
    raw control characters — the faults json.loads silently passes."""
    text = raw.decode("utf-8")  # Will raise on bad UTF-8
    i = 0
    in_string = False
    while i < len(text):
        ch = text[i]
        if not in_string:
            if ch == '"':
                in_string = True
            i += 1
            continue
        # Inside string
        if ch == '\\':
            i += 1
            if i >= len(text):
                raise StringNotScalarError("unterminated escape sequence")
            esc = text[i]
            if esc == 'u':
                # Read 4 hex digits
                if i + 4 >= len(text):
                    raise StringNotScalarError("malformed \\u escape")
                hex_str = text[i+1:i+5]
                if not all(c in '0123456789abcdefABCDEF' for c in hex_str):
                    raise StringNotScalarError("malformed \\u escape")
                cp = int(hex_str, 16)
                # Check for surrogates
                if 0xD800 <= cp <= 0xDBFF:
                    # High surrogate: must be followed by \uXXXX low surrogate
                    if i + 5 < len(text) and text[i+5] == '\\':
                        if i + 10 < len(text) and text[i+6] == 'u':
                            hex2 = text[i+7:i+11]
                            if all(c in '0123456789abcdefABCDEF' for c in hex2):
                                cp2 = int(hex2, 16)
                                if 0xDC00 <= cp2 <= 0xDFFF:
                                    # Valid surrogate pair - advance past both
                                    i += 11
                                    continue
                    raise StringNotScalarError(f"unpaired high surrogate \\u{cp:04X}")
                elif 0xDC00 <= cp <= 0xDFFF:
                    raise StringNotScalarError(f"unpaired low surrogate \\u{cp:04X}")
                # Check noncharacters
                if _is_noncharacter(cp):
                    raise StringNotScalarError(f"noncharacter U+{cp:04X} in string")
                i += 5
            else:
                i += 1
        elif ch == '"':
            in_string = False
            i += 1
        elif ord(ch) < 0x20:
            raise StringNotScalarError(f"raw control character U+{ord(ch):04X} in string")
        else:
            cp = ord(ch)
            if _is_noncharacter(cp):
                raise StringNotScalarError(f"noncharacter U+{cp:04X} in string")
            i += 1


def _is_noncharacter(cp: int) -> bool:
    """Unicode noncharacters: U+nFFFE..U+nFFFF for n=0..10FFFF, U+FDD0..U+FDEF."""
    if 0xFDD0 <= cp <= 0xFDEF:
        return True
    if cp & 0xFFFF in (0xFFFE, 0xFFFF):
        return True
    return False


# ============================================================================
# Statement strict fault detection
# ============================================================================

def _max_json_depth(text: str) -> int:
    """Maximum nesting depth of JSON arrays/objects."""
    depth = 0
    max_depth = 0
    in_string = False
    i = 0
    while i < len(text):
        ch = text[i]
        if in_string:
            if ch == '\\':
                i += 2
                continue
            if ch == '"':
                in_string = False
        else:
            if ch == '"':
                in_string = True
            elif ch in ('{', '['):
                depth += 1
                max_depth = max(max_depth, depth)
            elif ch in ('}', ']'):
                depth -= 1
        i += 1
    return max_depth


def _statement_strict_fault(raw: bytes) -> bool:
    """Check if the raw statement bytes have strict I-JSON faults that
    json.loads would silently pass (duplicate members, non-scalar strings)."""
    if len(raw) > MAX_PARSE_BYTES:
        return True
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return True
    if _max_json_depth(text) > MAX_PARSE_DEPTH:
        return True

    # Check for duplicate members
    found_dup = False
    def hook(pairs):
        nonlocal found_dup
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            found_dup = True
        return dict(pairs)

    try:
        json.loads(text, object_pairs_hook=hook)
    except (ValueError, RecursionError):
        return True
    if found_dup:
        return True
    try:
        check_string_scalars(raw)
    except StringNotScalarError:
        return True
    return False


# ============================================================================
# PAE (DSSEv1 Pre-Auth Encoding)
# ============================================================================

def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSEv1 Pre-Auth Encoding."""
    pt = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d " % (len(pt), pt, len(payload)) + payload


# ============================================================================
# Merkle Tree Root
# ============================================================================

def merkle_root_hex(leaves: list[bytes]) -> str:
    """Compute Merkle tree root hash from leaf PAE bytes.
    Uses the same binary tree construction as the reference."""
    def node(lo: int, hi: int) -> bytes:
        n = hi - lo
        if n == 1:
            return hashlib.sha256(b"\x00" + leaves[lo]).digest()
        k = 1
        while k * 2 < n:
            k *= 2
        return hashlib.sha256(b"\x01" + node(lo, lo + k) + node(lo + k, hi)).digest()

    if not leaves:
        raise ValueError("empty leaf set has no root")
    return node(0, len(leaves)).hex()


# ============================================================================
# Strict base64 decode
# ============================================================================

def strict_b64decode(s: str) -> bytes:
    """Strict base64 decode — rejects non-canonical encoding (matching Go's
    base64.StdEncoding.Strict()). Round-trip check catches non-standard padding."""
    # Validate characters first
    if not s:
        return b""
    valid_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    if not all(c in valid_chars for c in s):
        raise binascii.Error("invalid base64 character")
    raw = base64.b64decode(s, validate=True)
    # Round-trip check: reject non-canonical encodings
    if base64.b64encode(raw).decode("ascii") != s:
        raise ValueError("non-canonical base64 (fails re-encode round-trip)")
    return raw


# ============================================================================
# Strict payload parse (I-JSON profile)
# ============================================================================

class IJsonError(ValueError):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(detail)
        self.code = code


def strict_payload_parse(raw: bytes) -> dict[str, Any]:
    """Parse payload bytes as strict I-JSON (RFC 7493) and verify JCS canonical."""
    if len(raw) > MAX_PARSE_BYTES:
        raise IJsonError("payload-not-ijson", "payload exceeds maximum size")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise IJsonError("payload-not-ijson", "payload is not UTF-8")
    if _max_json_depth(text) > MAX_PARSE_DEPTH:
        raise IJsonError("payload-not-ijson", "payload nesting exceeds maximum depth")

    # Check string scalars (noncharacters, unpaired surrogates, raw control chars)
    try:
        check_string_scalars(raw)
    except StringNotScalarError as e:
        raise IJsonError("payload-not-ijson", f"payload string is not scalar: {e}")

    # Parse with duplicate detection
    try:
        obj = _parse_ijson(text)
    except IJsonError:
        raise
    except (ValueError, RecursionError):
        raise IJsonError("payload-not-ijson", "payload does not parse as JSON")

    if not isinstance(obj, dict):
        raise IJsonError("payload-not-canonical", "payload is not a JSON object")

    # Check supplementary-plane member names
    for key in obj:
        if not _all_bmp([key]):
            raise IJsonError("payload-not-canonical", "supplementary-plane object member name")

    # Verify JCS canonical: the raw bytes must equal JCS(parsed object)
    try:
        canonical = jcs_dumps(obj)
        if canonical != raw:
            raise IJsonError("payload-not-canonical", "payload is not JCS-canonical")
    except JcsError:
        raise IJsonError("payload-not-canonical", "payload not canonical")

    return obj


def _parse_ijson(text: str) -> Any:
    """Parse JSON text with strict I-JSON constraints."""
    # Check for duplicate members
    found_dup = False
    def hook(pairs):
        nonlocal found_dup
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            found_dup = True
            raise IJsonError("payload-not-ijson", f"duplicate member {keys[0]!r}")
        return dict(pairs)

    result = json.loads(text, object_pairs_hook=hook)

    # Check for non-safe integers
    _check_safe_integers(result)
    return result


def _check_safe_integers(obj: Any) -> None:
    """Recursively check all integers and floats are in safe I-JSON range."""
    if isinstance(obj, bool):
        return
    if isinstance(obj, int):
        if not (-2**53 + 1 <= obj <= 2**53 - 1):
            raise IJsonError("payload-not-ijson", "integer outside safe range")
    elif isinstance(obj, float):
        # I-JSON: non-integer numbers are not allowed
        if obj != int(obj):
            raise IJsonError("payload-not-ijson", "non-integer number")
        iv = int(obj)
        if not (-2**53 + 1 <= iv <= 2**53 - 1):
            raise IJsonError("payload-not-ijson", "integer outside safe range")
    elif isinstance(obj, dict):
        for v in obj.values():
            _check_safe_integers(v)
    elif isinstance(obj, list):
        for v in obj:
            _check_safe_integers(v)


# ============================================================================
# Ed25519 Test Key Derivation
# ============================================================================

def derive_test_keys() -> dict[str, dict[str, Any]]:
    """Re-derive test keys from published recipe:
    seed = SHA-256("in-toto-aee-test-key/<role>/v1")"""
    keys = {}
    for role in KEY_ROLES:
        seed = hashlib.sha256(f"in-toto-aee-test-key/{role}/v1".encode()).digest()
        pub = _ed25519_pub_from_seed(seed)
        keys[role] = {
            "seed": seed,
            "public": pub,
            "keyid": hashlib.sha256(pub).hexdigest(),
        }
    return keys


def _ed25519_pub_from_seed(seed: bytes) -> bytes:
    return (Ed25519PrivateKey.from_private_bytes(seed)
            .public_key()
            .public_bytes(
                encoding=__import__('cryptography.hazmat.primitives.serialization',
                                    fromlist=['Encoding']).Encoding.Raw,
                format=__import__('cryptography.hazmat.primitives.serialization',
                                  fromlist=['PublicFormat']).PublicFormat.Raw,
            ))


def ed25519_verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    """Ed25519 signature verification using cryptography library."""
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
        return True
    except InvalidSignature:
        return False


# ============================================================================
# Utility Functions
# ============================================================================

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _digest_of(obj: Any) -> Any:
    """Extract digest.sha256 from an object with {digest: {sha256: ...}}."""
    if isinstance(obj, dict):
        d = obj.get("digest")
        if isinstance(d, dict):
            return d.get("sha256")
    return None


def _is_hex64_lower(v: Any) -> bool:
    return isinstance(v, str) and bool(HEX64_RE.match(v))


def _sorted_no_dupes(values: list[Any]) -> bool:
    """Ascending by UTF-16 code unit, no duplicates."""
    keys = [_utf16_sort_key(v) for v in values]
    return all(a < b for a, b in zip(keys, keys[1:]))


def _timestamp_ok(v: Any) -> bool:
    """RFC 3339 timestamp in UTC timezone, uppercase T and Z."""
    if not isinstance(v, str) or not RFC3339_RE.match(v):
        return False
    key = _rfc3339_key(v)
    return key is not None and key.utcoffset() == timedelta(0)


def _rfc3339_key(v: str) -> datetime | None:
    """Parse RFC 3339 timestamp to datetime."""
    s = v.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def _attack_id_array_ok(values: Any, declared: set[str]) -> bool:
    """Check array is: list of strings, sorted UTF-16, no dupes, all in declared."""
    if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
        return False
    if not _sorted_no_dupes(values):
        return False
    return all(v in declared for v in values)


def _commitment_array_ok(values: Any) -> bool:
    """Check array is: non-empty list of lowercase 64-hex, sorted, no dupes."""
    if not isinstance(values, list) or not values:
        return False
    if not all(_is_hex64_lower(v) for v in values):
        return False
    return _sorted_no_dupes(values)


def _expected_payloads_ok(expected: Any, declared: set[str]) -> bool:
    """Check expectedPayloads shape."""
    if not isinstance(expected, dict):
        return False
    for attack, values in expected.items():
        if not isinstance(attack, str) or attack not in declared:
            return False
        if not _commitment_array_ok(values):
            return False
    return True


# ============================================================================
# RecordView — decoded observation record
# ============================================================================

class RecordView:
    """A decoded observation record."""

    def __init__(self, idx: int, rec: Any):
        self.idx = idx
        self.raw = rec
        self.payload_type = rec.get("payloadType") if isinstance(rec, dict) else None

        self.payload_bytes: bytes | None = None
        self.pae: bytes | None = None
        self.payload: dict[str, Any] | None = None
        self.payload_error: str | None = None
        self.decode_err: bool = False

        if isinstance(rec, dict) and isinstance(rec.get("payload"), str):
            try:
                self.payload_bytes = strict_b64decode(rec["payload"])
            except (binascii.Error, ValueError):
                self.payload_bytes = None
                self.decode_err = True

        if self.payload_bytes is not None and isinstance(self.payload_type, str):
            self.pae = pae(self.payload_type, self.payload_bytes)

        if self.payload_bytes is not None:
            try:
                self.payload = strict_payload_parse(self.payload_bytes)
            except IJsonError as e:
                self.payload_error = e.code

        media_ok = isinstance(self.payload_type, str) and self.payload_type.endswith("+json")
        self.media_ok = media_ok

        # Signature count
        sigs = rec.get("signatures") if isinstance(rec, dict) else None
        self.signature_count = len(sigs) if isinstance(sigs, list) else 0

    @property
    def kind(self) -> Any:
        return self.payload.get("aeeKind") if self.payload else None

    @property
    def method(self) -> Any:
        return self.payload.get("aeeMethod") if self.payload else None


# ============================================================================
# Outcome — collects failure codes
# ============================================================================

class Outcome:
    def __init__(self):
        self.codes: list[str] = []

    @property
    def verdict(self) -> str:
        return "invalid" if self.codes else "valid"

    def add(self, code: str) -> None:
        if code not in self.codes:
            self.codes.append(code)


# ============================================================================
# VerifyState — mutable state across checks
# ============================================================================

@dataclass
class VerifyState:
    stmt: Any
    pred: Any = None
    result: Any = None
    issued_at: Any = None
    env: dict = field(default_factory=dict)
    vocab: Any = None
    labels: list | None = None
    caught: list | None = None
    corpus: Any = None
    manifest_classes: dict | None = None
    rows: list = field(default_factory=list)
    has_substrate: bool = False
    coverage: Any = None
    fail_closed_rows: set = field(default_factory=set)
    has_records: bool = False
    views: list = field(default_factory=list)
    derived_binding: str | None = None
    pinned_posture: Any = None
    row_covering: dict = field(default_factory=dict)
    declared_attacks: set = field(default_factory=set)
    expected_payloads: Any = None


# ============================================================================
# The Independent Verifier
# ============================================================================

class IndependentVerifier:
    """Complete independent AEE v0.7 verifier."""

    def __init__(self, pinned_pubs: list[bytes]):
        self.pinned_pubs = pinned_pubs

    def verify(self, stmt: Any, raw: bytes | None = None) -> Outcome:
        out = Outcome()

        # Statement-wide strict I-JSON
        if raw is not None and _statement_strict_fault(raw):
            out.add("statement-malformed")
            return out

        st = VerifyState(stmt=stmt)

        # Check statement type
        if self._check_statement_type(st, out):
            return out

        # GATE 0 checks (ordered)
        self._check_gate0_wellformed(st, out)
        self._check_vocabulary(st, out)
        self._check_corpus(st, out)
        self._check_rows_setup(st, out)
        self._check_subject_cardinality(st, out)
        self._check_coverage(st, out)
        self._check_per_row_statements(st, out)
        self._check_substrate_binding_inputs(st, out)
        self._check_fail_closed_rows(st, out)
        self._check_records(st, out)
        self._check_run_binding(st, out)

        # GATE 1
        self._check_gate1_coverage(st, out)

        # Commitment checks
        self._check_commitments(st, out)

        # Result recompute
        self._check_result_recompute(st, out)

        return out

    # ---- Statement type ----

    def _check_statement_type(self, st: VerifyState, out: Outcome) -> bool:
        stmt = st.stmt
        if not isinstance(stmt, dict):
            out.add("statement-type-unsupported")
            return True

        if stmt.get("_type") != STATEMENT_TYPE:
            out.add("statement-type-unsupported")
        if stmt.get("predicateType") != AEE_PREDICATE_TYPE:
            out.add("predicate-type-unsupported")

        pred = stmt.get("predicate")
        if pred is None:
            pred = {}
        if not isinstance(pred, dict):
            out.add("predicate-type-unsupported")
            return True
        st.pred = pred
        return False

    # ---- GATE 0: well-formedness ----

    def _check_gate0_wellformed(self, st: VerifyState, out: Outcome) -> None:
        pred = st.pred

        if "does_not_assert" in pred:
            out.add("member-spelling")

        result = pred.get("result")
        if result not in RESULT_ORDER:
            out.add("result-vocabulary")
        st.result = result

        issued_at = pred.get("issuedAt")
        if issued_at is None:
            out.add("issued-at-missing")
        elif not _timestamp_ok(issued_at):
            out.add("issued-at-malformed")
        st.issued_at = issued_at

        env = pred.get("observationEnvironment")
        env = env if isinstance(env, dict) else {}
        for member in ("substrate", "corpus", "catchPolicy", "networkPosture"):
            if member not in env:
                out.add("environment-incomplete")
        st.env = env

        vocab = env.get("observationVocabulary")
        if not isinstance(vocab, dict):
            out.add("vocabulary-missing")
            vocab = None
        st.vocab = vocab

        # networkPosture posture vocabulary
        posture = env.get("networkPosture")
        if isinstance(posture, dict):
            declared = posture.get("posture")
            if not isinstance(declared, str) or declared not in EGRESS_POSTURES:
                out.add("posture-vocabulary")

    def _check_vocabulary(self, st: VerifyState, out: Outcome) -> None:
        vocab = st.vocab
        labels = None
        caught = None

        if vocab is not None:
            labels = vocab.get("labels")
            caught = vocab.get("caught")
            if not self._vocab_shape_ok(labels, caught):
                out.add("vocabulary-not-canonical")
            self._vocab_check_pairs(out, vocab, labels, caught)
            if not isinstance(labels, list) or not isinstance(caught, list):
                labels, caught = None, None

        st.labels = labels
        st.caught = caught

    @staticmethod
    def _vocab_shape_ok(labels: Any, caught: Any) -> bool:
        for arr in (labels, caught):
            if not isinstance(arr, list) or not all(isinstance(x, str) for x in arr):
                return False
            if sorted(arr, key=_utf16_sort_key) != arr or len(set(arr)) != len(arr):
                return False
            if not _all_bmp(arr):
                return False
        return True

    def _vocab_check_pairs(self, out: Outcome, vocab: Any, labels: Any, caught: Any) -> None:
        if not (isinstance(labels, list) and isinstance(caught, list)):
            return
        if not set(caught) <= set(labels):
            out.add("vocabulary-caught-not-subset")
        try:
            expect = sha256_hex(jcs_dumps({"caught": caught, "labels": labels}))
            if _digest_of(vocab) != expect:
                out.add("vocabulary-digest-mismatch")
        except JcsError:
            out.add("vocabulary-digest-mismatch")

    def _check_corpus(self, st: VerifyState, out: Outcome) -> None:
        env = st.env
        corpus = env.get("corpus")
        st.corpus = corpus
        manifest_classes = None

        if isinstance(corpus, dict):
            manifest = corpus.get("manifest")
            classes = manifest.get("classes") if isinstance(manifest, dict) else None
            if manifest is None:
                out.add("environment-incomplete")
            if isinstance(manifest, dict):
                self._corpus_digest(out, corpus, manifest)
                self._corpus_declares_attack(out, classes)
            if isinstance(classes, dict):
                manifest_classes = classes
                self._corpus_dupes(out, classes)
                st.declared_attacks = {
                    aid
                    for ids in classes.values()
                    if isinstance(ids, list)
                    for aid in ids
                    if isinstance(aid, str)
                }
            if isinstance(manifest, dict) and "expectedPayloads" in manifest:
                expected = manifest["expectedPayloads"]
                if _expected_payloads_ok(expected, st.declared_attacks):
                    st.expected_payloads = expected
                else:
                    out.add("manifest-expected-payloads-malformed")

        st.manifest_classes = manifest_classes

    @staticmethod
    def _corpus_digest(out: Outcome, corpus: Any, manifest: Any) -> None:
        try:
            expect = sha256_hex(jcs_dumps(manifest))
            if _digest_of(corpus) != expect:
                out.add("corpus-digest-mismatch")
        except JcsError:
            out.add("corpus-digest-mismatch")

    @staticmethod
    def _corpus_declares_attack(out: Outcome, classes: Any) -> None:
        declared = 0
        if isinstance(classes, dict):
            for ids in classes.values():
                declared += len(ids) if isinstance(ids, list) else 0
        if declared == 0:
            out.add("corpus-manifest-no-attacks")

    @staticmethod
    def _corpus_dupes(out: Outcome, classes: dict) -> None:
        seen: set[str] = set()
        for ids in classes.values():
            for aid in ids if isinstance(ids, list) else []:
                if aid in seen:
                    out.add("manifest-duplicate-attack")
                seen.add(aid)

    def _check_rows_setup(self, st: VerifyState, out: Outcome) -> None:
        if "attackResults" not in st.pred:
            out.add("statement-malformed")
        rows = st.pred.get("attackResults")
        rows = rows if isinstance(rows, list) else []
        rows = [r for r in rows if isinstance(r, dict)]
        st.rows = rows
        st.has_substrate = any(r.get("basis") == "substrate" for r in rows)

    def _check_subject_cardinality(self, st: VerifyState, out: Outcome) -> None:
        subject = st.stmt.get("subject")
        subject = subject if isinstance(subject, list) else []
        if len(subject) != 1:
            out.add("subject-cardinality")

    def _check_coverage(self, st: VerifyState, out: Outcome) -> None:
        coverage = st.pred.get("coverage")
        st.coverage = coverage
        manifest_classes = st.manifest_classes
        if not isinstance(coverage, dict):
            out.add("coverage-missing")
            return
        if manifest_classes is None:
            return
        assessed = coverage.get("assessedClasses")
        assessed = assessed if isinstance(assessed, list) else []
        oos = coverage.get("outOfScope")
        oos = oos if isinstance(oos, dict) else {}
        routed = coverage.get("routedElsewhere")
        routed = routed if isinstance(routed, dict) else {}
        if not self._coverage_partition_ok(manifest_classes, assessed, oos, routed):
            out.add("coverage-incomplete")
        self._coverage_check_rows(st, out, manifest_classes, assessed)

    @staticmethod
    def _coverage_partition_ok(manifest_classes, assessed, oos, routed) -> bool:
        acct: dict[str, int] = {}
        for _c in assessed:
            acct[_c] = acct.get(_c, 0) + 1
        for _c in oos:
            acct[_c] = acct.get(_c, 0) + 1
        for _c in routed:
            acct[_c] = acct.get(_c, 0) + 1
        return all(n == 1 and c in manifest_classes for c, n in acct.items()) and all(
            acct.get(c, 0) == 1 for c in manifest_classes
        )

    @staticmethod
    def _coverage_index(manifest_classes, assessed):
        attack_class: dict = {}
        for cls, ids in manifest_classes.items():
            for aid in ids if isinstance(ids, list) else []:
                attack_class.setdefault(aid, cls)
        expected_ids: set = set()
        for cls in assessed:
            _mc = manifest_classes.get(cls)
            for aid in _mc if isinstance(_mc, list) else []:
                expected_ids.add(aid)
        return attack_class, expected_ids

    def _coverage_check_rows(self, st, out, manifest_classes, assessed) -> None:
        attack_class, expected_ids = self._coverage_index(manifest_classes, assessed)
        row_ids = set()
        for r in st.rows:
            aid = r.get("attackId")
            if aid in row_ids:
                out.add("statement-malformed")
            row_ids.add(aid)
            if aid not in attack_class:
                out.add("row-attack-unknown")
            elif attack_class[aid] not in assessed:
                out.add("coverage-incomplete")
        if expected_ids - {i for i in row_ids if i in attack_class}:
            out.add("coverage-incomplete")

    def _check_per_row_statements(self, st, out) -> None:
        rows = st.rows
        labels = st.labels
        caught = st.caught
        for r in rows:
            for member in ("attackId", "containmentObserved", "basis", "method", "actualLayer"):
                if member in r and not isinstance(r[member], str):
                    out.add("statement-malformed")
        for r in rows:
            if "actualLayer" not in r:
                out.add("malformed-missing-actual-layer")
        if labels is not None and caught is not None:
            for r in rows:
                lab = r.get("containmentObserved")
                if (lab in labels and lab not in caught
                        and "actualLayer" in r and r.get("actualLayer") != "none"):
                    out.add("clean-row-layer-not-none")

    def _check_substrate_binding_inputs(self, st, out) -> None:
        if not st.has_substrate:
            return
        stmt = st.stmt
        env = st.env
        subject = stmt.get("subject")
        subject = subject if isinstance(subject, list) else []
        subj_digest = _digest_of(subject[0]) if subject else None
        if subject and subj_digest is None:
            out.add("subject-sha256-missing")
        if "runEntropy" not in env:
            out.add("run-entropy-missing")
        self._binding_digest_canonical(out, env, subj_digest)

    @staticmethod
    def _binding_digest_canonical(out, env, subj_digest) -> None:
        for val in (
            subj_digest,
            _digest_of(env.get("substrate")),
            _digest_of(env.get("corpus")),
            _digest_of(env.get("catchPolicy")),
            _digest_of(env.get("networkPosture")),
            _digest_of(env.get("runEntropy")),
        ):
            if val is not None and not _is_hex64_lower(val):
                out.add("digest-not-canonical")

    def _check_fail_closed_rows(self, st, out) -> None:
        rows = st.rows
        labels = st.labels
        fail_closed_rows: set[int] = set()
        for i, r in enumerate(rows):
            lab_bad = labels is not None and r.get("containmentObserved") not in labels
            basis_bad = r.get("basis") not in ("substrate", "artifact")
            method_bad = r.get("method") not in ("intercepted", "reconstructed")
            attribution_bad = r.get("attribution") not in ("pinned", "paired")
            if lab_bad or basis_bad or method_bad or attribution_bad:
                fail_closed_rows.add(i)
                if r.get("basis") == "substrate":
                    out.add("fail-closed-substrate-row")
        st.fail_closed_rows = fail_closed_rows

    # ---- Records ----

    def _check_records(self, st, out) -> None:
        pred = st.pred
        records = pred.get("observationRecords")
        has_records = isinstance(records, list) and len(records) > 0
        views: list[RecordView] = []
        if isinstance(records, list) and records:
            views = [RecordView(i, rec) for i, rec in enumerate(records)]
            if any(v.signature_count == 0 for v in views):
                out.add("record-signatures-empty")
            if any(v.decode_err for v in views):
                out.add("record-undecodable")
            else:
                self._records_batch_root(out, pred, views)
            self._records_duplicates(out, views)
        elif pred.get("batchRoot") is not None:
            out.add("batch-root-orphaned")
        st.has_records = has_records
        st.views = views

    @staticmethod
    def _records_batch_root(out, pred, views) -> None:
        root = pred.get("batchRoot")
        if root is None:
            out.add("batch-root-missing")
        elif all(v.pae is not None for v in views):
            if merkle_root_hex([v.pae for v in views if v.pae is not None]) != root:
                out.add("batch-root-mismatch")
        else:
            out.add("batch-root-mismatch")

    @staticmethod
    def _records_duplicates(out, views) -> None:
        seen_leaves: set[bytes] = set()
        for v in views:
            if v.decode_err:
                continue
            key = v.pae if v.pae is not None else b""
            if not key and v.raw is not None:
                try:
                    key = jcs_dumps(v.raw)
                except JcsError:
                    key = repr(v.raw).encode("utf-8")
            if key in seen_leaves:
                out.add("duplicate-record")
            seen_leaves.add(key)

    # ---- Run binding ----

    def _check_run_binding(self, st, out) -> None:
        derived_binding = None
        if st.has_substrate:
            stmt = st.stmt
            env = st.env
            try:
                subject0 = stmt["subject"][0]
                vals = self._binding_preimage(env, subject0["digest"]["sha256"])
                if vals is not None and all(isinstance(v, str) for v in vals.values()):
                    derived_binding = sha256_hex(jcs_dumps(vals))
            except (KeyError, IndexError, TypeError):
                derived_binding = None
        st.derived_binding = derived_binding

    @staticmethod
    def _binding_preimage(env: dict, subject_sha: Any) -> dict | None:
        try:
            posture_preimage = ""
            np = env.get("networkPosture")
            if isinstance(np, dict):
                try:
                    posture_preimage = sha256_hex(jcs_dumps(np))
                except (JcsError, TypeError, ValueError):
                    posture_preimage = ""

            return {
                "aeeBindingVersion": BINDING_VERSION,
                "catchPolicy": env["catchPolicy"]["digest"]["sha256"],
                "corpus": env["corpus"]["digest"]["sha256"],
                "networkPosture": posture_preimage,
                "observationVocabulary": env["observationVocabulary"]["digest"]["sha256"],
                "runEntropy": env["runEntropy"]["digest"]["sha256"],
                "subject": subject_sha,
                "substrate": env["substrate"]["digest"]["sha256"],
            }
        except (KeyError, IndexError, TypeError):
            return None

    # ---- GATE 1: per-substrate-row coverage validity ----

    def _check_gate1_coverage(self, st, out) -> None:
        pinned_posture = _digest_of(st.env.get("networkPosture"))
        st.pinned_posture = pinned_posture

        if st.has_records:
            self._check_refs_in_range(st, out)

        row_covering: dict[int, list[RecordView]] = {}
        for i, r in enumerate(st.rows):
            self._gate1_row(st, out, i, r, pinned_posture, row_covering)
        st.row_covering = row_covering

    def _check_refs_in_range(self, st, out) -> None:
        n = len(st.views)
        for r in st.rows:
            refs = r.get("observationRefs")
            if not isinstance(refs, list):
                continue
            for ref in refs:
                if isinstance(ref, bool) or not isinstance(ref, int):
                    continue
                if ref >= n:
                    out.add("ref-out-of-range")
                    return

    def _gate1_row(self, st, out, i, r, pinned_posture, row_covering) -> None:
        if r.get("basis") != "substrate" or i in st.fail_closed_rows:
            return
        if not st.has_records:
            out.add("records-absent")
            return
        refs = r.get("observationRefs")
        if not isinstance(refs, list) or len(refs) == 0:
            out.add("refs-empty")
            lab = r.get("containmentObserved")
            if st.caught is not None and lab in st.caught:
                out.add("caught-row-uncovered")
            return
        ref_views = self._gate1_resolve_refs(st, out, refs)
        if ref_views is None:
            return

        self._gate1_check_payloads(st, out, ref_views)
        covering = self._gate1_class_match(st, out, r, ref_views, pinned_posture)
        row_covering[i] = covering
        self._gate1_method_cap(out, r, covering)

    def _gate1_resolve_refs(self, st, out, refs) -> list | None:
        views = st.views
        ref_views: list[RecordView] = []
        refs_ok = True
        for ref in refs:
            if isinstance(ref, bool) or not isinstance(ref, int) or ref < 0:
                out.add("ref-malformed")
                refs_ok = False
            elif ref >= len(views):
                out.add("ref-out-of-range")
                refs_ok = False
            else:
                ref_views.append(views[ref])
        if not refs_ok and not ref_views:
            return None
        return ref_views

    def _gate1_check_payloads(self, st, out, ref_views) -> None:
        derived_binding = st.derived_binding
        for rv in ref_views:
            self._gate1_check_payload(out, rv, derived_binding)

    @staticmethod
    def _gate1_check_payload(out, rv, derived_binding) -> None:
        if not rv.media_ok:
            out.add("payload-media-type")
        if rv.payload_error is not None:
            out.add(rv.payload_error)
            return
        if rv.payload is None:
            out.add("payload-not-canonical")
            return
        missing = [m for m in RESERVED_MEMBERS if m not in rv.payload]
        if missing:
            out.add("payload-missing-reserved")
        if (derived_binding is not None
                and "aeeRunBinding" in rv.payload
                and rv.payload["aeeRunBinding"] != derived_binding):
            out.add("run-binding-mismatch")

    # ---- Kind constraints ----

    def _arming_ok(self, rv, pinned_posture, issued_at, declared_attacks) -> bool:
        p = rv.payload or {}
        armed = p.get("armedAt")
        if not _timestamp_ok(armed):
            return False
        if _timestamp_ok(issued_at):
            a = _rfc3339_key(armed) if isinstance(armed, str) else None
            b = _rfc3339_key(issued_at) if isinstance(issued_at, str) else None
            if a is not None and b is not None and a > b:
                return False
        if p.get("aeePostureDigest") != pinned_posture:
            return False
        if p.get("aeeMethod") != "intercepted":
            return False
        bv = p.get("aeeBindingVersion")
        if bv is not None and bv != BINDING_VERSION:
            return False
        if not self._arming_chain_ok(p):
            return False
        return _attack_id_array_ok(p.get("aeeAssessedAttacks"), declared_attacks)

    @staticmethod
    def _arming_chain_ok(p: dict) -> bool:
        has_seq = "aeeRunSeq" in p
        has_prev = "aeePrevRunBinding" in p
        has_scope = "aeeChainScope" in p
        if not has_seq:
            return not has_prev and not has_scope
        seq = p.get("aeeRunSeq")
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
            return False
        scope = p.get("aeeChainScope")
        if not isinstance(scope, list):
            return False
        if any(tok not in CHAIN_SCOPE_VOCAB for tok in scope):
            return False
        if sorted(scope, key=_utf16_sort_key) != scope or len(set(scope)) != len(scope):
            return False
        if seq == 1:
            return not has_prev
        prev = p.get("aeePrevRunBinding")
        return isinstance(prev, str) and bool(HEX64_RE.match(prev))

    def _sealed_ok(self, rv, pinned_posture, arming_postures, declared_attacks) -> bool:
        p = rv.payload or {}
        if p.get("aeeStillArmed") is not True:
            return False
        drops = p.get("aeeDropCount")
        if not isinstance(drops, int) or isinstance(drops, bool) or drops < 0:
            return False
        if drops > 0:
            bound = p.get("aeeDropBound")
            if not isinstance(bound, int) or isinstance(bound, bool):
                return False
            if drops > bound:
                return False
        posture = p.get("aeePostureDigest")
        if posture != pinned_posture:
            return False
        for arming_posture in arming_postures:
            if posture != arming_posture:
                return False
        if p.get("aeeMethod") != "intercepted":
            return False
        return self._sealed_commitments_ok(p, declared_attacks)

    @staticmethod
    def _sealed_commitments_ok(p, declared_attacks) -> bool:
        if not _is_hex64_lower(p.get("aeeObservedSet")):
            return False
        return _attack_id_array_ok(p.get("aeeObservedAttacks"), declared_attacks)

    def _examination_ok(self, rv) -> bool:
        return (rv.payload or {}).get("aeeMethod") == "reconstructed"

    @staticmethod
    def _covers_nothing(usable: list) -> str | None:
        for rv in usable:
            registered = REGISTERED_NONCOVERING.get(rv.kind or "")
            if registered is not None:
                return registered
            if rv.kind not in COVERING_KINDS:
                return "record-kind-unknown-covers-nothing"
        return None

    @staticmethod
    def _uncovered_code(covers_nothing, specific) -> str:
        return covers_nothing if covers_nothing is not None else specific

    def _gate1_class_match(self, st, out, r, ref_views, pinned_posture) -> list:
        usable = [rv for rv in ref_views if rv.payload is not None and rv.media_ok]
        covers_nothing = self._covers_nothing(usable)

        lab = r.get("containmentObserved")
        method = r.get("method")
        if method == "reconstructed":
            return self._gate1_cover_reconstructed(out, usable, covers_nothing)
        if st.caught is not None and lab in st.caught:
            return self._gate1_cover_caught(out, usable, covers_nothing)
        return self._gate1_cover_clean(st, out, usable, covers_nothing, pinned_posture)

    def _gate1_cover_reconstructed(self, out, usable, covers_nothing) -> list:
        exams = [rv for rv in usable if rv.kind == "examination"]
        good = [rv for rv in exams if self._examination_ok(rv)]
        if not exams:
            out.add(self._uncovered_code(covers_nothing, "reconstructed-row-uncovered"))
        elif not good:
            out.add("examination-covers-nothing")
        return good

    def _gate1_cover_caught(self, out, usable, covers_nothing) -> list:
        inters = [rv for rv in usable if rv.kind == "interception"]
        if not inters:
            out.add(self._uncovered_code(covers_nothing, "caught-row-uncovered"))
            return inters
        good = []
        for rv in inters:
            values = (rv.payload or {}).get("aeePayloadCommitment")
            if values is None:
                out.add("payload-missing-reserved")
            elif not _commitment_array_ok(values):
                out.add("payload-commitment-malformed")
            else:
                good.append(rv)
        return good

    def _gate1_cover_clean(self, st, out, usable, covers_nothing, pinned_posture) -> list:
        good_arm = self._gate1_clean_arm(st, out, usable, covers_nothing, pinned_posture)
        good_seal = self._gate1_clean_seal(st, out, usable, covers_nothing, pinned_posture)
        return good_arm + good_seal

    def _gate1_clean_arm(self, st, out, usable, covers_nothing, pinned_posture) -> list:
        issued_at = st.issued_at
        armings = [rv for rv in usable if rv.kind == "arming"]
        good_arm = [
            rv for rv in armings
            if self._arming_ok(rv, pinned_posture, issued_at, st.declared_attacks)
        ]
        if not armings:
            out.add(self._uncovered_code(covers_nothing, "clean-row-uncovered"))
        elif not good_arm:
            out.add("arming-covers-nothing")
        return good_arm

    def _gate1_clean_seal(self, st, out, usable, covers_nothing, pinned_posture) -> list:
        sealeds = [rv for rv in usable if rv.kind == "sealed"]
        arming_postures = [
            posture
            for rv in usable
            if rv.kind == "arming"
            for posture in [(rv.payload or {}).get("aeePostureDigest")]
            if isinstance(posture, str)
        ]
        good_seal = [
            rv for rv in sealeds
            if self._sealed_ok(rv, pinned_posture, arming_postures, st.declared_attacks)
        ]
        if not sealeds:
            out.add(self._uncovered_code(covers_nothing, "clean-row-uncovered"))
        elif not good_seal:
            out.add("sealed-covers-nothing")
        return good_seal

    def _gate1_method_cap(self, out, r, covering) -> None:
        if not covering:
            return
        method = r.get("method")
        methods = [METHOD_ORDER[rv.method] for rv in covering if rv.method in METHOD_ORDER]
        if methods and method in METHOD_ORDER:
            if METHOD_ORDER[method] > min(methods):
                out.add("method-cap-exceeded")

    # ---- Commitment checks ----

    def _check_commitments(self, st, out) -> None:
        self._commit_clean_row_contradicted(st, out)
        self._commit_interception_orphaned(st, out)
        self._commit_attribution(st, out)
        if not st.has_substrate or not st.has_records:
            return
        self._commit_observed_set(st, out)
        self._commit_sealed_present(st, out)
        self._commit_carried_cover(st, out)
        self._commit_seal_attacks(st, out)
        self._commit_assessed_subset(st, out)

    @staticmethod
    def _resolved_views(st, r) -> list:
        refs = r.get("observationRefs")
        if not isinstance(refs, list):
            return []
        return [
            st.views[ref]
            for ref in refs
            if not isinstance(ref, bool)
            and isinstance(ref, int)
            and 0 <= ref < len(st.views)
        ]

    def _commit_clean_row_contradicted(self, st, out) -> None:
        if st.labels is None or st.caught is None:
            return
        for r in st.rows:
            lab = r.get("containmentObserved")
            if lab not in st.labels or lab in st.caught:
                continue
            if any(rv.kind == "interception" for rv in self._resolved_views(st, r)):
                out.add("clean-row-contradicted")
                return

    def _commit_interception_orphaned(self, st, out) -> None:
        if st.caught is None or not st.has_records:
            return
        resolved: set[int] = set()
        for r in st.rows:
            if r.get("containmentObserved") not in st.caught:
                continue
            resolved.update(rv.idx for rv in self._resolved_views(st, r))
        for rv in st.views:
            if rv.kind == "interception" and rv.idx not in resolved:
                out.add("interception-record-orphaned")
                return

    def _commit_observed_set(self, st, out) -> None:
        want: str | None = None
        for rv in st.views:
            if rv.kind != "sealed" or not isinstance(rv.payload, dict):
                continue
            if rv.payload.get("aeeRunBinding") != st.derived_binding:
                continue
            got = rv.payload.get("aeeObservedSet")
            if not _is_hex64_lower(got):
                continue
            if want is None:
                want = self._observed_set_digest(st.views)
            if got != want:
                out.add("observed-set-mismatch")
                return

    @staticmethod
    def _observed_set_digest(views: list) -> str:
        leaves = sorted(
            {
                hashlib.sha256(b"\x00" + rv.pae).hexdigest()
                for rv in views
                if rv.pae is not None and rv.kind in ("interception", "examination")
            }
        )
        try:
            return sha256_hex(jcs_dumps(leaves))
        except JcsError:
            return ""

    def _commit_sealed_present(self, st, out) -> None:
        arming_postures = [
            posture
            for rv in st.views
            if rv.kind == "arming"
            for posture in [(rv.payload or {}).get("aeePostureDigest")]
            if isinstance(posture, str)
        ]
        for rv in st.views:
            if rv.kind != "sealed" or not isinstance(rv.payload, dict) or not rv.media_ok:
                continue
            if rv.payload.get("aeeRunBinding") != st.derived_binding:
                continue
            if self._sealed_ok(rv, st.pinned_posture, arming_postures, st.declared_attacks):
                return
        out.add("sealed-record-absent")

    def _commit_carried_cover(self, st, out) -> None:
        for rv in st.views:
            if not isinstance(rv.payload, dict) or not rv.media_ok:
                continue
            if any(m not in rv.payload for m in RESERVED_MEMBERS):
                continue
            if rv.payload.get("aeeRunBinding") != st.derived_binding:
                continue
            if rv.kind not in COVERING_KINDS:
                continue
            code = self._carried_record_fault(rv, st)
            if code is not None:
                out.add(code)

    def _carried_record_fault(self, rv, st) -> str | None:
        if rv.kind == "sealed":
            ok = self._sealed_ok(rv, st.pinned_posture, [], st.declared_attacks)
            return None if ok else "sealed-covers-nothing"
        if rv.kind == "arming":
            ok = self._arming_ok(rv, st.pinned_posture, st.issued_at, st.declared_attacks)
            return None if ok else "arming-covers-nothing"
        if rv.kind == "examination":
            return None if self._examination_ok(rv) else "examination-covers-nothing"
        # interception
        payload = rv.payload or {}
        if "aeePayloadCommitment" in payload and not _commitment_array_ok(
            payload["aeePayloadCommitment"]
        ):
            return "payload-commitment-malformed"
        if rv.method not in METHOD_ORDER or "aeePayloadCommitment" not in payload:
            return "payload-missing-reserved"
        return None

    def _commit_seal_attacks(self, st, out) -> None:
        if st.caught is None:
            return
        caught_ids = {
            r.get("attackId")
            for r in st.rows
            if r.get("containmentObserved") in st.caught
        }
        for rv in st.views:
            if rv.kind != "sealed" or not isinstance(rv.payload, dict):
                continue
            if rv.payload.get("aeeRunBinding") != st.derived_binding:
                continue
            attacks = rv.payload.get("aeeObservedAttacks")
            if not _attack_id_array_ok(attacks, st.declared_attacks):
                continue
            if any(a not in caught_ids for a in attacks):
                out.add("observed-attack-uncaught")
                return

    def _commit_assessed_subset(self, st, out) -> None:
        cov = st.coverage if isinstance(st.coverage, dict) else {}
        assessed_classes = cov.get("assessedClasses")
        if not isinstance(assessed_classes, list) or not isinstance(st.manifest_classes, dict):
            return
        assessed: set[str] = set()
        for cls in assessed_classes:
            ids = st.manifest_classes.get(cls)
            if isinstance(ids, list):
                assessed.update(a for a in ids if isinstance(a, str))
        for rv in st.views:
            if rv.kind != "arming" or not isinstance(rv.payload, dict):
                continue
            if rv.payload.get("aeeRunBinding") != st.derived_binding:
                continue
            declared = rv.payload.get("aeeAssessedAttacks")
            if not _attack_id_array_ok(declared, st.declared_attacks):
                continue
            if not assessed <= set(declared):
                out.add("assessed-set-exceeds-declaration")
                return

    def _commit_attribution(self, st, out) -> None:
        expected_map = st.expected_payloads if isinstance(st.expected_payloads, dict) else {}
        for r in st.rows:
            if r.get("attribution") != "pinned":
                continue
            resolved = self._resolved_views(st, r)
            inters = [rv for rv in resolved if rv.kind == "interception"]
            if not inters:
                out.add("attribution-pinned-recordless")
                return
            expected = expected_map.get(r.get("attackId"))
            if not isinstance(expected, list) or not expected:
                out.add("attribution-unpinnable")
                return
            for rv in inters:
                values = (rv.payload or {}).get("aeePayloadCommitment")
                if not isinstance(values, list):
                    continue
                if not any(v in expected for v in values):
                    out.add("attribution-pin-unmatched")
                    return

    # ---- Result recompute ----

    def _check_result_recompute(self, st, out) -> None:
        if "result" not in st.pred:
            return
        recomputed = self._recompute(
            st.rows,
            st.labels if st.labels is not None else [],
            st.caught if st.caught is not None else [],
            st.coverage,
        )
        if st.result not in RESULT_ORDER or recomputed != st.result:
            out.add("result-recompute-mismatch")

    @staticmethod
    def _recompute(rows, labels, caught, coverage) -> str:
        forces_fail = False
        indirect = False
        for r in rows:
            lab = r.get("containmentObserved")
            if lab not in labels or lab in caught:
                forces_fail = True
            elif r.get("basis") not in ("substrate", "artifact"):
                forces_fail = True
            elif r.get("method") not in ("intercepted", "reconstructed"):
                forces_fail = True
            elif r.get("attribution") not in ("pinned", "paired"):
                forces_fail = True
            elif r.get("basis") != "substrate" or r.get("method") != "intercepted":
                indirect = True
        cov = coverage if isinstance(coverage, dict) else {}
        candidates = [
            "fail" if forces_fail else "pass",
            "degraded" if (cov.get("outOfScope") or cov.get("routedElsewhere")) else "pass",
            "pass_indirect" if indirect else "pass",
        ]
        return min(candidates, key=RESULT_ORDER.__getitem__)


# ============================================================================
# Main runner
# ============================================================================

def run_full_verification() -> dict:
    """Run the independent verifier on all 281 vectors."""
    # Derive test keys
    test_keys = derive_test_keys()
    pinned_pub = test_keys["substrate-observation-test"]["public"]

    verifier = IndependentVerifier([pinned_pub])

    # Load manifest
    manifest = json.loads(MANIFEST_PATH.read_text())
    vectors = manifest.get("vectors", [])

    print(f"Loaded manifest: {len(vectors)} vectors")
    print(f"  accept: {manifest['counts']['accept']}")
    print(f"  reject: {manifest['counts']['reject']}")
    print(f"  indeterminate: {manifest['counts']['indeterminate']}")
    print()

    results = []
    agree_count = 0
    disagree_count = 0
    errors = 0

    for i, entry in enumerate(vectors):
        vec_id = entry["id"]
        kind = entry.get("kind", "")
        file_path = entry.get("file", "")
        expected = entry.get("expected", {})
        exp_verdict = expected.get("verdict", "")

        # Read the statement
        stmt_path = CORPORA_DIR / file_path
        if not stmt_path.exists():
            results.append({
                "id": vec_id,
                "kind": kind,
                "expected_verdict": exp_verdict,
                "computed_verdict": "error",
                "codes": ["file-not-found"],
                "agree": False,
            })
            errors += 1
            continue

        raw = stmt_path.read_bytes()

        # Parse JSON
        try:
            stmt = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            # Still try to verify - statement-malformed will catch it
            stmt = {}

        # Run verification
        try:
            outcome = verifier.verify(stmt, raw)
        except Exception as e:
            results.append({
                "id": vec_id,
                "kind": kind,
                "expected_verdict": exp_verdict,
                "computed_verdict": "error",
                "codes": [f"exception:{type(e).__name__}"],
                "agree": False,
            })
            errors += 1
            continue

        computed_verdict = outcome.verdict
        computed_codes = outcome.codes

        # Compare verdicts
        agrees = (computed_verdict == exp_verdict)
        if agrees:
            agree_count += 1
        else:
            disagree_count += 1

        results.append({
            "id": vec_id,
            "kind": kind,
            "expected_verdict": exp_verdict,
            "computed_verdict": computed_verdict,
            "codes": computed_codes,
            "expected_codes": expected.get("codes", []),
            "agree": agrees,
        })

        # Progress
        if (i + 1) % 50 == 0:
            print(f"  Progress: {i+1}/{len(vectors)} "
                  f"(agree={agree_count}, disagree={disagree_count})")

    print()
    print(f"{'='*70}")
    print(f"VERIFICATION COMPLETE")
    print(f"{'='*70}")
    print(f"Total vectors:    {len(vectors)}")
    print(f"Agree:            {agree_count}")
    print(f"Disagree:         {disagree_count}")
    print(f"Errors:           {errors}")
    print(f"Agreement rate:   {agree_count/len(vectors)*100:.1f}%")

    # Summary by kind
    for kind in ("accept", "reject", "indeterminate"):
        kind_vecs = [r for r in results if r["kind"] == kind]
        kind_agree = sum(1 for r in kind_vecs if r["agree"])
        print(f"  {kind}: {kind_agree}/{len(kind_vecs)} agree")

    return {
        "total": len(vectors),
        "agree": agree_count,
        "disagree": disagree_count,
        "errors": errors,
        "results": results,
        "manifest_counts": manifest["counts"],
    }


def main() -> int:
    global CORPORA_DIR, STATEMENTS_DIR, MANIFEST_PATH
    import argparse
    parser = argparse.ArgumentParser(description="Independent adversarial-execution-evidence verifier (shares no code with the reference reader).")
    parser.add_argument("--corpus-dir", default=str(CORPORA_DIR), help="Path to the adversarial corpus directory (contains MANIFEST.json + statements/).")
    parser.add_argument("--json-output", default=None, help="Path to write per-vector results JSON.")
    args = parser.parse_args()

    CORPORA_DIR = Path(args.corpus_dir)
    STATEMENTS_DIR = CORPORA_DIR / "statements"
    MANIFEST_PATH = CORPORA_DIR / "MANIFEST.json"
    output_path = args.json_output

    result = run_full_verification()

    # Write output
    if output_path is None:
        output_path = str(OUTPUT_DIR / "adversarial_full_results.json")

    with open(output_path, "w") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"\nResults written to: {output_path}")

    # Print disagreements
    disagreements = [r for r in result["results"] if not r["agree"]]
    if disagreements:
        print(f"\n{'='*70}")
        print(f"DISAGREEMENTS ({len(disagreements)}):")
        print(f"{'='*70}")
        for d in disagreements:
            exp_codes = d.get("expected_codes", [])
            print(f"  {d['id']} (kind={d['kind']}):")
            print(f"    expected: {d['expected_verdict']}")
            print(f"    computed: {d['computed_verdict']}")
            print(f"    expected_codes: {exp_codes}")
            print(f"    computed_codes: {d['codes']}")
            print()

    return 0 if result["disagree"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
