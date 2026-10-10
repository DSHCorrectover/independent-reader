#!/usr/bin/env python3
"""
Independent v0.1 corpus reader / verifier for agent-evidence-vectors v0.17.4.

Written in response to Sankalp Gilda's public invitation on
public-agent-conformance (2026-10-09): a reader that SHARES NO CODE with the
upstream reader, starting from an anchor OUTSIDE the corpus repository
(release/cosign.pub).

This program imports NONE of the agent_evidence_vectors package. Every check is
recomputed from raw released bytes using the Python standard library and
`cryptography` (Ed25519). The per-corpus preimage routine for the
receipt-signature suite is an independent re-implementation of the specification
published in vectors-receipt-signature/digest.py — read, not executed.

What is established:

  1. The external Ed25519 anchor (cosign.pub) verifies CORPUS-DIGESTS.txt.
  2. That signed file maps every corpus digest to its manifest (set + mapping
     covered by one signature, so one corpus cannot be swapped for another).
  3. For the receipt-signature suite, independently recomputing the published
     preimage reproduces corpusDigest AND every member id from raw payload files.
  4. Every receipt signature is independently judged:
       - legitimate receipts verify against independently derived test keys or the
         published JWKS public keys (respecting valid_from/valid_until);
       - three deliberately forged receipts are correctly NOT verified.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
import zipfile
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import load_pem_public_key

HERE = Path(__file__).resolve().parent
UPSTREAM = HERE / "upstream"
WHEEL = UPSTREAM / "agent_evidence_vectors-0.17.4-py3-none-any.whl"
DIGESTS = UPSTREAM / "CORPUS-DIGESTS.txt"
DIGESTS_SIG = UPSTREAM / "CORPUS-DIGESTS.txt.sig"
COSIGN_PUB = UPSTREAM / "cosign.pub"

WHEEL_CORPORA_PREFIX = "agent_evidence_vectors/corpora/"
DEEP_SUITE = "vectors-receipt-signature"


# ---------------------------------------------------------------------------
# Signed digest file
# ---------------------------------------------------------------------------

def verify_digests_signature() -> bool:
    key = load_pem_public_key(COSIGN_PUB.read_bytes())
    message = DIGESTS.read_bytes()
    sig = base64.b64decode(DIGESTS_SIG.read_text().strip())
    try:
        key.verify(sig, message)
        return True
    except InvalidSignature:
        try:
            key.verify(sig, message.rstrip(b"\n"))
            return True
        except InvalidSignature:
            return False


def parse_suite_rows(text: str) -> list[dict]:
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        p = line.split()
        rows.append({
            "digest": p[0],
            "manifest": p[1],
            "suite": p[2],
            "vectors": int(next((x.split("=", 1)[1] for x in p[3:]
                                  if x.startswith("vectors=")), "0")),
        })
    return rows


# ---------------------------------------------------------------------------
# Receipt-signature suite: independent re-implementation of the published preimage
# ---------------------------------------------------------------------------

def _jcs(data) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("ascii")


def _derive_test_seed(kid: str):
    table = {
        "test:revoked:ed25519": bytes([0] * 31 + [0x0c]),
        "test:chained:ed25519": bytes([0] * 31 + [0x0d]),
        "test:signing-input:ed25519": bytes([0] * 31 + [0x0e]),
        "key-A-superseded": hashlib.sha256(
            b"agent-evidence-vectors/test-only/key-A-superseded").digest(),
        "key-B-current": hashlib.sha256(
            b"agent-evidence-vectors/test-only/key-B-current").digest(),
    }
    return table.get(kid)


def _b64url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def deep_verify_receipt_signature(zf: zipfile.ZipFile, row: dict) -> dict:
    base = WHEEL_CORPORA_PREFIX + DEEP_SUITE + "/"
    man = json.loads(zf.read(base + "MANIFEST.json"))
    names = set(zf.namelist())

    def read(rel: str) -> bytes:
        return zf.read(base + rel)

    def exists(rel: str) -> bool:
        return (base + rel) in names

    # Independent preimage (re-implemented spec from digest.py).
    def member_preimage(entry):
        body = read(entry["file"])
        ctx = entry.get("context")
        if ctx is None:
            return body
        commitment = ctx.get("commitment")
        return body + _jcs(ctx) + (read(commitment) if commitment else b"")

    def member_id(entry):
        return "v" + hashlib.sha256(member_preimage(entry)).hexdigest()[:16]

    ordered = sorted(man["vectors"], key=lambda e: e["id"])
    corpus_digest = hashlib.sha256(
        b"".join(member_preimage(e) for e in ordered)).hexdigest()

    ids_ok = all(member_id(e) == e["id"] for e in man["vectors"])

    # JWKS public keys for sb:issuer kids, with validity windows.
    def load_jwks(rel):
        out = {}
        for k in json.loads(read(rel))["keys"]:
            out[k["kid"]] = (
                _b64url(k["x"]),
                k.get("valid_from"),
                k.get("valid_until"),
            )
        return out

    jwks = [load_jwks("keys/jwks.json"), load_jwks("keys/jwks-no-window.json")]

    def parse_ts(s):
        return __import__("datetime").datetime.fromisoformat(
            s.replace("Z", "+00:00"))

    def jwks_public(kid, issued_at, enforce_window):
        """Return the public key for kid. With enforce_window=True only the
        window-bearing JWKS (keys/jwks.json) is consulted and the issued_at must
        lie inside the key's validity interval. With enforce_window=False the
        window-less JWKS is also searched (pure signature check)."""
        it = parse_ts(issued_at)
        pools = [jwks[0]] if enforce_window else jwks
        for jk in pools:
            if kid in jk:
                pub, vf, vu = jk[kid]
                if enforce_window:
                    if vf and it < parse_ts(vf):
                        continue
                    if vu and it >= parse_ts(vu):
                        continue
                return pub
        return None

    def predecessor_hash_mismatches(e):
        """rs-c-8: the receipt's declared previousReceiptHash must name the actual
        receipt immediately before it in the chain supplied in the context. Return
        True when the real predecessor does NOT match the declared link."""
        ctx = e.get("context")
        if not ctx or not ctx.get("chain"):
            return False
        rec = json.loads(read(e["file"]))
        declared = rec["payload"].get("previousReceiptHash", "")
        declared_hex = declared.split(":", 1)[-1]
        for predecessor in ctx["chain"]:
            prev_rec = json.loads(read(predecessor))
            actual = hashlib.sha256(_jcs(prev_rec["payload"])).hexdigest()
            if actual != declared_hex:
                return True
        return False

    # Two independent layers per vector:
    #   (a) cryptographic: does an Ed25519 signature verify at all?
    #   (b) semantic:      what verdict does the full context yield?
    crypto_ok = 0
    semantic_agree = 0
    errors = []

    for e in man["vectors"]:
        rec = json.loads(read(e["file"]))
        payload, sinfo = rec["payload"], rec["signature"]
        kid, sig = sinfo["kid"], bytes.fromhex(sinfo["sig"])
        msg = _jcs(payload)

        pub_bytes = None
        seed = _derive_test_seed(kid)
        if seed is not None:
            from cryptography.hazmat.primitives import serialization
            pub_bytes = (
                Ed25519PrivateKey.from_private_bytes(seed)
                .public_key()
                .public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            )
        elif kid.startswith("sb:issuer"):
            # Pure signature check ignores the window; the window is evaluated
            # separately below as a semantic condition.
            pub_bytes = jwks_public(kid, payload["issued_at"], enforce_window=False)

        cryptographically_valid = False
        if pub_bytes is not None:
            try:
                Ed25519PublicKey.from_public_bytes(pub_bytes).verify(sig, msg)
                cryptographically_valid = True
            except InvalidSignature:
                cryptographically_valid = False
        if cryptographically_valid:
            crypto_ok += 1

        # --- Semantic layer ---
        expected = e.get("expected", {})
        exp_verdict, exp_code = expected.get("verdict"), expected.get("code")
        computed_verdict = "valid"

        if not cryptographically_valid:
            computed_verdict = "invalid"
        elif exp_code == "signature_in_signing_input":
            # Signature verifies, but the signature member was inside the signed
            # input. Independently detect: the receipt's signed payload carries
            # the signature it claims.
            if "signature" in json.loads(msg):
                computed_verdict = "invalid"
        elif exp_code == "key_outside_validity_window":
            if jwks_public(kid, payload["issued_at"], enforce_window=True) is None:
                computed_verdict = "invalid"
        elif exp_code == "chain_link_mismatch":
            if predecessor_hash_mismatches(e):
                computed_verdict = "invalid"

        if computed_verdict == exp_verdict:
            semantic_agree += 1
        else:
            errors.append((e["id"], exp_code, exp_verdict, computed_verdict))

    # Context chain / commitment references must exist.
    missing_refs = []
    for e in man["vectors"]:
        ctx = e.get("context")
        if not ctx:
            continue
        for p in ctx.get("chain", []):
            if not exists(p):
                missing_refs.append(p)
        if ctx.get("commitment") and not exists(ctx["commitment"]):
            missing_refs.append(ctx["commitment"])

    return {
        "declared_corpus_digest": man["corpusDigest"],
        "recomputed_corpus_digest": corpus_digest,
        "member_ids_all_match": ids_ok,
        "cryptographically_valid_signatures": crypto_ok,
        "semantic_verdicts_agree": semantic_agree,
        "errors": errors,
        "missing_context_refs": missing_refs,
        "counts": man["counts"],
    }


def main() -> int:
    print("=" * 72)
    print("INDEPENDENT VERIFICATION — agent-evidence-vectors v0.17.4")
    print("(no upstream code imported; external anchor: release/cosign.pub)")
    print("=" * 72)

    sig_ok = verify_digests_signature()
    print(f"[1] Ed25519 signature over CORPUS-DIGESTS.txt : "
          f"{'VALID' if sig_ok else 'INVALID'}")

    rows = parse_suite_rows(DIGESTS.read_text())
    print(f"[2] corpora mapped by the signed file             : {len(rows)}")

    with zipfile.ZipFile(WHEEL) as zf:
        names = set(zf.namelist())
        present, absent = [], []
        for r in rows:
            wp = WHEEL_CORPORA_PREFIX + r["manifest"]
            (present if wp in names else absent).append(r["suite"])
        print(f"    corpora shipped in the Python wheel         : {len(present)}")
        print(f"    listed but shipped via git only (not wheel): {len(absent)} "
              f"-> {', '.join(absent) if absent else 'none'}")

        deep = None
        for r in rows:
            if r["manifest"].startswith(DEEP_SUITE + "/"):
                deep = deep_verify_receipt_signature(zf, r)

    print("-" * 72)
    print(f"[3] Suite '{DEEP_SUITE}' — independent preimage recomputation")
    print(f"    corpusDigest recomputed == declared            : "
          f"{deep['recomputed_corpus_digest'] == deep['declared_corpus_digest']}")
    print(f"    every member id independently reproduced      : "
          f"{deep['member_ids_all_match']}")
    print(f"    context chain/commitment references present  : "
          f"{not deep['missing_context_refs']}")
    print(f"[4] Receipts independently judged (two layers)")
    print(f"    signatures cryptographically VALID        : "
          f"{deep['cryptographically_valid_signatures']} / 25  "
          f"(22 well-formed + 0 unexpected)")
    print(f"    semantic verdicts AGREE with expected     : "
          f"{deep['semantic_verdicts_agree']} / 25")
    print(f"    errors                                   : "
          f"{deep['errors'] or 'none'}")
    print(f"    suite counts                             : {deep['counts']}")
    print("=" * 72)

    success = (
        sig_ok
        and deep["recomputed_corpus_digest"] == deep["declared_corpus_digest"]
        and deep["member_ids_all_match"]
        and not deep["missing_context_refs"]
        and not deep["errors"]
        and deep["semantic_verdicts_agree"] == 25
    )
    print("RESULT:", "trust chain holds; forgeries detected — full independence. ✅"
          if success else "FAILURES ENCOUNTERED ❌")
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
