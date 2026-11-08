# RUN0 same-call source readiness

The same-call parent now has independently reviewed host source and private
fixture controls for the pure decoder, capacity and accounting, static input
preparation, host observations, inventory, wire, retained-read identity,
storage, session/runtime and fixed wrapper gate. These source packets follow
base `283d128` through `871b7f5`; they do not establish a native capture. The
public runtime registration guard remains `INCOMPLETE`. The fixed streaming
verifier and its measured copy schedule are independently source-reviewed through
`33dc988`; runtime admission and the actual execution plan remain under review.

A private three-epoch fixture used one original ledger and ordered phase control
reservations with a 384-byte map. Its original recipe committed 25,073,458 bytes.
Explicit, independently reviewed replan 005 replaces the unknown-map frame
reservation with a conservative four-level geometric bound that includes the
root. All original limits, complete translation, read and wire prepayments,
rereads, and permanently charged unused reservations remain binding. The changed
fixture commits 12,084,358 bytes with the same 314 operations and 82 reads.

Real non-VM preparation and both static verifier passes succeeded on Bigman.
At `33dc988`, their one-ledger cost is 12,512,296 bytes, down from 23,440,540
at the earlier recipe. Semantic validators are unchanged; the new recipe pays
for actual parser/projection work before effects instead of charging hash-only
retrievals for repeated parsing. Adding these separately measured components
leaves 7,778,130 regular bytes before Root, actual wire/host and terminal costs.
This is an assessment, not a complete-parent fit or native capture proof.

The earlier [stopped-entry result](run0-c0-result-2026-11-07.md) and 360 Linux
C0 trace controls remain separate prior evidence. Still required are reviewed
runtime admission, complete fixed-candidate Linux CI and an exact independently
reviewed execution plan. Actual one-VM three-stop
capture, ten-child/24-EOF closure, full unfiltered history, current-ledger and
source-execution qualification remain unproved. No new VM run, full CI, push,
PR or A3 approval is claimed by this closeout.

Private source reviews and the shared-ledger experiment are retained in the
workspace evidence directory `evidence/run0-c1-c2-next-20261107/`, including
`runtime-review-resume-001`, `wrapper-gate-review-resume-001`,
`read-identity-review-resume-001`, `storage-review-resume-001` and
`shared-ledger-review-resume-001`, `root-c2-geometric-replan-005.json`,
`geometry-source-review-resume-001`, `verifier-cost-review-resume-002` and
`root-actual-preparation-resume-004`. The first real preparation attempt stopped
before preparation because copied source parents were mode 0755; the corrected
0700 setup and both successful real measurements retain separate records.
