# RUN0 same-call source readiness

The same-call parent now has independently reviewed host source and private
fixture controls for the pure decoder, capacity and accounting, static input
preparation, host observations, inventory, wire, retained-read identity,
storage, session/runtime and fixed wrapper gate. These source packets follow
base `283d128` through `871b7f5`; they do not establish a native capture. The
static runtime readiness checks are implemented. The fixed streaming verifier
and its measured copy schedule are independently source-reviewed through
`33dc988`. Admission source and the sealed one-attempt execution plan are now
reviewed. Hosted Linux run [42507270423](https://github.com/whole-machine-works/RamenOS/actions/runs/42507270423),
at exact head `32a23d39f36919a6adcca1d02b58598eba0a23d7`, passed all nine
checks and received independent qualification review. The hosted merge commit
`286b522cd1e452e529ed7f5c8bcf0a069ce23779` has the same tree as that head; it
is a distinct commit. Static readiness does not issue native origin or reads.

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

The first real, bounded run 005 remained incomplete; its partial capture report recorded primary
`DENY: owned_exe_identity`; cleanup also recorded
`INCOMPLETE: call_drain_timeout`. No guest-memory read
was admitted. QEMU and the one metadata helper were both reaped with return
code zero, and the driver reported no remaining direct children. The private
failure, lifecycle and raw evidence are retained; this attempt is not a
completed C0 observation or a C1/C2 capture.

The retained 005 before-metadata wire is 749,921 bytes. If a completed C0 used
that exact before frame, the current before-side accounting would require at
least 14,991,862 bytes, excluding after metadata, row JSON, fields and other
work. The 7,778,130-byte comparison remainder combines separately observed
static and restricted-session measurements; it is not a measured full-parent
ledger. Future metadata sizes and a complete capture remain unmeasured.

The narrow executable-identity fix is independently reviewed and locally
committed as `57dc43b`; hosted qualification at `32a23d` does not cover that
successor. The separate cleanup repair is independently reviewed and locally committed
as `3d30be4`. All 280 integrated call tests pass on that local source; the old
hosted result does not qualify these repairs. The next budget decision is whether to define a fixed 128 MiB
development profile or redesign to fit the existing 32 MiB cap. The ledger
counts cumulative logical copied, parsed and retained bytes; it is not measured
peak RSS or guest RAM. The 128 MiB profile is prospective and requires an
explicit choice. Neither option is selected: no cap has changed and no retry
is authorized by this record.
Complete successor qualification, integrated accounting, whole history and
one-VM C0/C1/C2 evidence remain open. The earlier
[stopped-entry result](run0-c0-result-2026-11-07.md) and 360 Linux C0 trace
controls remain separate prior evidence. [PR78](https://github.com/whole-machine-works/RamenOS/pull/78)
is a draft stacked on PR77; separate A3 review and merge remain required.

Private source reviews and the shared-ledger experiment are retained in the
workspace evidence directory `evidence/run0-c1-c2-next-20261107/`, including
`runtime-review-resume-001`, `wrapper-gate-review-resume-001`,
`read-identity-review-resume-001`, `storage-review-resume-001` and
`shared-ledger-review-resume-001`, `root-c2-geometric-replan-005.json`,
`geometry-source-review-resume-001`, `verifier-cost-review-resume-002` and
`root-actual-preparation-resume-004`, `hosted-pr78-final-review-001`,
`root-native-capture-005`, `native-host-cost-resume-001`,
`native-host-cost-review-001`, `host-bridge-review-001`,
`native-cleanup-review-001` and `root-repair-integration-001`. Private raw capture
evidence remains in the workspace and is not included in this document. The
first real preparation attempt stopped before preparation because copied source
parents were mode 0755; the corrected
0700 setup and both successful real measurements retain separate records.
