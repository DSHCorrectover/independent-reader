# Independent reader for agent-evidence-vectors

An **independent** second implementation of the verifiers for
[`agent-evidence-vectors`](https://pypi.org/project/agent-evidence-vectors/).
It shares **no code** with the reference reader: the reference source is read
only to derive the rules; every check is rewritten from scratch using the
Python standard library and [`cryptography`](https://cryptography.io/).

Purpose: show that the published conformance verdicts are reproducible by an
implementation that does not depend on the reference code (the point raised on
the W3C `public-agent-conformance` list, issue 0089).

## Results against v0.17.6

Wheel total: **951 vectors / 16 corpora — 951/951 agree, zero real
disagreement.**

| Corpus | Vectors | Independent verdict |
|---|---:|---:|
| receipt-signature | 25 | 25/25 |
| adversarial-execution-evidence | 285 | 285/285 |
| w3c-report-v01 | 235 | 235/235 |
| anchored-record-chain | 14 | 14/14 |
| other corpora (structure/binding level) | 382 | 382/382 |

## Usage

Download and unpack the published wheel, then point each script at a corpus:

```sh
pip download agent-evidence-vectors==0.17.6 --no-deps -d /tmp/w
unzip /tmp/w/agent_evidence_vectors-0.17.6-py3-none-any.whl -d /tmp/p

python3 independent_adversarial_full.py \
  --corpus-dir /tmp/p/agent_evidence_vectors/corpora/vectors
python3 independent_w3creport_full.py \
  --corpus-dir /tmp/p/agent_evidence_vectors/corpora/vectors-w3c-report
python3 independent_anchored_full.py \
  --corpus-dir /tmp/p/agent_evidence_vectors/corpora/vectors-anchored-chain
```

Each emits per-vector results and prints an agreement summary. Full per-vector
JSON for v0.17.6 is under [`results/`](results/).

## Independence

- `grep -nE "^import agent_evidence|^from agent_evidence"` over all scripts
  returns nothing.
- No upstream code is imported, executed, or copied into the verifiers.
- Verdicts are derived from the raw test-case bytes; the manifest `expected`
  field is used only for the post-hoc comparison.
- Trust anchor: the published `release/cosign.pub` (Ed25519).

## Dependencies

- Python 3.8+
- [`cryptography`](https://pypi.org/project/cryptography/) (Ed25519)

## License

See [LICENSE](LICENSE).

## Contact

Guigui Wang · Correctover — AI Reliability
