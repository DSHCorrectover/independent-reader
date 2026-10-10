Subject: [CORRECTION] Re: An independent v0.1 reader that shares no code with the reference reader

To: public-agent-conformance@w3.org

Apologies - two numerical corrections to my previous message:

(1) The total was 933 vectors across 15 corpora, not 16.  The sixteenth
    corpus (self-reported-record, 11 vectors) is git-only and not present
    in the published wheel.

(2) More importantly, while I was writing, the reference package bumped
    from v0.17.4 (the version I originally verified against) to v0.17.6.
    That release added:
      - 4 new vectors in the adversarial corpus (281 -> 285)
      - a brand-new anchored-record-chain corpus (14 cases)
    bringing the wheel total to **951 vectors across 16 corpora**.

I have now re-run all three independent re-implementations against
v0.17.6 and extended the set with a fourth, independent re-implementation
for the new anchored-record-chain corpus:

  Corpus                    v0.17.4    v0.17.6   agree
  ------------------------  -------    -------   -----
  receipt-signature              25         25    25/25
  adversarial                   281        285   285/285
  w3c-report                    235        235   235/235
  anchored-record-chain  (new)    -         14    14/14
  ------------------------  -------    -------   -----
  semantic deep-verify          541        559   559/559

Plus 382 vectors at structure/binding level across the remaining 12
corpora, giving the wheel total of 951.  No real disagreement on any of
the 951 vectors.

The anchored-record-chain suite is particularly worth flagging because
its design point is exactly that "every signature verifies" is not
enough: only chain links and anchor catch T2/T3/T4/T7/T9/rollback/
reanchored cases.  My implementation catches them all by independent
Ed25519 verification of records, chain-link hash, and anchor-key
signature, and correctly accepts `t2-tail-removal-after-last-anchor`
(the control that must NOT be rejected because deleting records the
latest anchor never covered leaves an honest store).

The corrected full result JSONs and scripts are at the same location
as the original message.

Guigui Wang
Correctover - AI Reliability
