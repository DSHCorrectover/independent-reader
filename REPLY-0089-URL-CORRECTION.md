Subject: [CORRECTION] repository location + evidence mirror for issue 0089

Nicolas, all,

Two small corrections to our earlier messages on issue 0089:

1. The public repository of the independent reader is:

   https://github.com/DSHCorrectover/independent-reader

   (Our earlier messages cited the account "Correctover"; the canonical
   public account is "DSHCorrectover". The repository now contains all four
   independent scripts, the per-vector result JSON files, and the reply
   drafts.)

2. The full verification record is also mirrored as a single static page:

   https://independent-reader-evidence.pages.dev/

It records, for agent-evidence-vectors v0.17.6:

- 951 vectors across 16 corpora, adjudicated independently from raw
  test-case bytes, 951/951 agreeing with the reference verdicts;
- 559 vectors at full semantic depth (receipt-signature 25,
  adversarial-execution-evidence 285 with GATE 0+1+2, w3c-report 235 with
  the full W3C-R/ARM-R/LCD-R rule set, anchored-record-chain 14);
- 392 vectors at the structural/binding layer;
- zero genuine disagreements.

The independent implementation reads the upstream sources and
specifications only to derive the rules: it never imports, execs, evals,
or executes upstream code, and the MANIFEST expectations are used solely
for post-hoc comparison.

Best regards,
Guigui Wang
Correctover - AI Reliability
wangguigui@correctover.com
