# Fixed-candidate Linux editor delivery qualification — 2026-11-05

This record binds complete hosted validation and retained local failures to the
implementation candidate. Integration requires separate authorized A3 approval.

## Candidate and evidence identity

The implementation candidate is `f412206e914833b072b61872017bf0de51954c3b` on the
existing delivery branch/PR52. Its immutable source archive is
`out/p0-p3-source-f412206`. Both hosted runtime and fresh local stage-batch source
manifests identify 873 regular files with SHA
`4345b3b9a444365ef3246bd6ae0b86b09b34c2f6040756e7ea9f01582ad06039`.
The recorded lockfile SHA is
`8495485fb5d3b0aa5c02a60634d0c05e212650cdc4412af1ff55cea3a7112ad0`.
Source identities bind each result; a diagnostic source overlay is not this fixed
candidate and cannot replace its acceptance result.

## Hosted complete profile — accepted with archival limitation

[Hosted run 42037623174](https://github.com/whole-machine-works/RamenOS/actions/runs/42037623174)
reports PASS for all five required lanes, Foundry and merge-gate on this candidate.
The complete uploaded artifacts are retained under
`out/p0-p3-hosted-f412206/`. The hosted editor runtime result is
`runtime/editor-process/ea065d2ff2c48f59306ba5cc05f2ba2d/result.json`, with status
PASS and source SHA above; it names gate record SHA
`ae2cc5c6da06633b6cea791da064befc39c86e48c3d3d8fa4d247f42024714ea`.
This is actual hosted source-bound execution of the complete thirty-family gate,
not a claim based on authored test counts or a focused diagnostic pass. Independent
review accepted the complete runtime with the binary-byte archival limitation below.
The fresh hosted preservation-stage review is recorded separately.

The f412 runtime archive contains actual Cargo/build receipts and native held/
executed identity hashes, but omits the two selected child ELF files and parent
library. Independent review cannot rehash those binary bytes from that archive.
The delivery successor adds a separate `editor-process-binaries-RUN-ATTEMPT`
artifact containing exactly the normal child, assertion child and selected parent
library, preserving the primary archive layout and gate execution. Complete hosted
CI on that successor and direct comparison of its own three archived byte hashes
to its own gate record/Cargo receipts are required before PR readiness. Local
binaries from a different execution cannot establish that archival result.

The retained mechanical timing audit is
`out/p0-p3-hosted-f412206-timing-audit-txz1cnl3/`. It records all 57 unique canonical
stages across 69 lane-stage executions: quality 13, host 20, agent 6, QEMU 15 and
editor 15. It joins 61 outer timing files plus eight editor inner timings to the
actual command/exit/reap receipts. Twelve additional bootstrap/duplicate executions
do not increase canonical coverage. The separate Linux prerequisite packet proves
only prerequisites. This mechanical inventory is not the final independent review
of implementation correctness, runtime authority or all evidence semantics.

## Fresh local preservation — accepted; additional local editor15 — FAILED

The eight fresh unchanged local editor stages have independent acceptance under
`out/p0-p3-review-f412206-legacy-715bfe8k/audit.json`, SHA
`02eb5bcef3a9f8f21eb8448b79cf495d12a18436288d5bcb88a1af33280311c4`.
Its evidence inventory SHA is
`8ad96e7b29d3ff00469710b89ac1afbaf166177cbb7c83f9b24223a9d19a2ef6`.
That acceptance is limited to those eight source-bound preservation stages; it is
not acceptance of the local complete editor lane.

The separate fixed-source local canonical editor15 attempt FAILED after
552.18 seconds. Its result is `out/p0-p3-editor-f412206/campaign/result.json`:
exit1, fixed source unchanged, and matching before/after lockfile SHA. The failure
was `PrivateAppBehavior4`,
`native::process_assertions::process_d19_newer_draft_keeps_unsaved_after_older_commit`,
in the fourth scenario `D19OlderReceiptThenFreshAuthorizedSave`, during its second
Save. The first three scenarios completed. Actual observation was Unknown at
confirmed revision 2, text generation 23/view 25/body 13; the retained chain targeted
operation 2 in ObserveCommit with no current Flight/lookup. Store counts were
Allocate2/permit2/transition1.

Retained local failure evidence is
`out/p0-p3-editor-f412206/` and the remote original packet
`/tmp/ramen-p0-p3-NerTsUjj/delivery-f412206/out/foundry/editor-process/573ca0a0871af179cf7d90cb6a0ffb30/`.
The actual selection journal still showed operation 2 permitted/revision 2. Its
`selection.next` contained a prepared revision 3 successor, SHA
`2c7ceeb69c09e5a1422a8a825a69cf27e68f3410c1e085db03f7d97d197f4ecb`,
written about 16 ms before the test panic. A prepared successor is not an accepted
Commit, durable selection rename or genuine terminal receipt. The failure remains
unresolved and its cause UNKNOWN.

Diagnostic reruns036/037/038 passed within their recorded diagnostic scopes. They
are unqualified and do not erase or replace the failed unchanged local attempt.
Measured manifest verification was approximately 8 ms per call in the diagnostic
source. That does not identify the rare timeout's cause. The qualified source keeps
its existing signature-validation paths and crypto profiles.

The mandatory complete hosted profile and this additional local editor15 attempt
are distinct results. Report the hosted PASS and local FAIL together. The hosted
profile does not turn the local result into PASS; the additional local failure
does not make the actual hosted job results false. Final acceptance must explicitly
state the retained discrepancy and its remaining uncertainty.

## Archival successor and receipt-readiness correction

Delivery commit `76f7adee5d989ebd2148dbee80ca17ee1c9f635a` added the separate
three-file archive. Its first editor attempt in
[run 42049108755](https://github.com/whole-machine-works/RamenOS/actions/runs/42049108755)
failed at private D17 after 0.62 seconds: one nonblocking `poll_once()` returned
`None` before the actual Commit reply was published. The IO pause had settled,
but `Fixture::join_all()` performs only nonblocking try-joins; the dispatcher can
publish `ExecutionState.ready` afterward. This failure is distinct from the
additional f412 D19 deadline failure and does not explain its unknown cause.

The three binary files from that failed attempt were independently hashed against
that attempt's own Cargo-selected artifacts and gate record. The archival-only
review is `out/p0-p3-review-hosted-76f7ade-eixjkt9g/attempt1-binary-archive-review.json`,
SHA `954501b0a6cb74c6f20815dbce27225163a5f9ee2225b94859c36370fcb374f4`.
It accepts the archive correction, not the failed runtime. The assertion child
execution was not reached; the available normal-child execution identities join
the retained normal binary. Complete passing successor evidence is still required.

The reviewed D17 correction polls only the same staged execution, yields only on
`None`, and checks the already-captured original deadline before each poll. Actual
errors fail, and the genuine reply is staged before any receipt decoding. Full
176-byte receipt, foreign-binding/hash/revision denials, intent identity, Save
counts, reopen and subsequent Save assertions remain unchanged. The full private
D17 target passes on immutable focused candidate `receipt-readiness-040`, retained
under `out/p0-p3-040-receipt-readiness/`; this focused result is separate from
complete successor CI qualification. Its independent focused audit is
`out/p0-p3-review-040-3g8ups99/audit.json`, SHA
`cacf8b44815e7a718dee574f58e5012ca7038bbf4d01e5366709610765b2ea3f`.

A source-only sibling audit found two related one-pass join assumptions, without
claiming new observed runtime failures. Public AppOwner cleanup now drains both
unresolved originals and actual held producer rows under the same already-started
two-second deadline, preserving explicit zero-owner assertions before release.
Private D15 IO-capacity recovery drains the actual StoreIo roster under A's existing
cleanup deadline before the unchanged fresh Save on C. Neither change polls live
filesystem evidence, creates a deadline, replaces an original or relaxes a quota.
The full private D15 target and public D17/D19/D20/D21/D22 targets pass on focused
candidate `producer-readiness-041`, retained in
`out/p0-p3-041-producer-readiness/`. Its independent audit is
`out/p0-p3-review-041-xt8fhn21/audit.json`, SHA
`d7af7e2dbc6c958e9a0c5e2fd28f0b35f7c180ca042a77fa8519545942735214`.
It verifies all six whole targets and genuine receipt/join/fresh-Save outcomes; the
IO-zero admission witness follows the compiled predicate rather than a separately
exported timestamped sample. Complete corrected-successor CI remains required.

Three other jobs in the 76 attempt were delayed in Ubuntu Azure-mirror package
downloads. The reviewed setup correction keeps all repositories, packages,
signature/TLS checks and error handling, with three retries and 30-second HTTP/
HTTPS connection/data inactivity limits per acquisition. It does not impose a
30-second total setup deadline or turn setup failure into acceptance.

## Qualified predecessor and Desktop entry review findings

Commit `0d449c9184bb885dbf528c91a749622ed4f69732` passed all five hosted lanes,
Foundry and merge-gate on [run 42059009291](https://github.com/whole-machine-works/RamenOS/actions/runs/42059009291).
Editor, host Docker, agent task and QEMU completed in attempt 1. Quality was
cancelled during package acquisition in attempt 1 and completed in attempt 2
on the same commit. The independent audit verified 57 canonical stages across
69 actual command receipts, all three of that run's archived binaries, 244
complete Runs and 244 parent joins. The audit is
`out/p0-p3-review-hosted-0d449c9-k465vlgx/complete-qualification-audit.json`, SHA
`9f650b991eb8b68f97a9140095b17cba06883ad3fd8dfe711ef0c5f1a37d2a01`.

A subsequent code review found two failure paths outside the passing test scope.
An app Ctrl+S rejected before Desktop admission by shared producer pressure
could retain a Save chain with no original to reconcile. A startup Read could
install a dispatcher and then fail to spawn its deadline supervisor. The
status-only return left the app with no actual dispatcher identity, allowing
it to report complete cleanup without the join.

The correction lets Desktop close the exact unadmitted Allocate intent while
holding its authority lock. The app releases the chain only on that definitive
disposition. A partially started Read returns its actual installed dispatcher
with its entry owner. The failed-open owner reports Complete only after proving
the join. The D15 regression drives Ctrl+S through the process app with 64
actual Desktop producers held, verifies no new Store work or stranded app
chain, drains the producers, and completes a fresh Save on the same child.
The failed-open regression injects the deadline supervisor failure after
actual dispatcher installation, verifies Pending before release, joins the
dispatcher, and then requires Complete and a fresh authorized Read. Both
focused Linux tests pass. Qualify both tests along with the complete hosted
lanes and the corrected candidate's own binary archive before A3 handoff.

## Implementation, review and delivery boundaries

The reviewed complete P0/private handoff and actual strict Linux missing-API RED
closed the authoring dependencies before concurrent P1/P2 implementation. P1/P2
combined normal Linux acceptance then released P3. The branch now implements the
actual carrier/child and common Store Save/original-recovery pipeline, with retained
focused review and runtime evidence. Statements that these APIs were absent or P0
was incomplete belong to historical preparation source; they are not the current
implementation state. Preparation, focused validation, complete qualification and
integration remain separate claims.

Newcomputer PR3 is ready for review: its tree is clean, all 250 local tests and the
hosted check passed within its recorded recovery/L0 handoff scope. It claims no
compiler adoption and does not qualify RamenOS process runtime.

The independent runtime review accepts the exact hosted candidate with an explicit
binary-byte archival limitation and no blocking runtime finding. Its report is
`out/p0-p3-review-hosted-f412206-cqsiwkbj/audit.json`, SHA
`1cc72205730c07717581f39270ba2ba1e5ab5664e977a3980efac67bc1121695`.
It verified all 52 probes, 44 fresh owned runtime commands, the exact source
closure, strict profiles, public42 plus four captured unwind controls, private10,
genuine Store4, actual Cargo-driven D29, all 244 recording Runs/28,221 controls,
parent raw joins and the hidden budget. Its original downloaded evidence inventory
contains 15,998 files/3,451,491,894 bytes with SHA
`35c9ee89dcf574180a537d0a6f3a0513ac77e6f2e5e3316e7f0d6944855ab525`.
Recording completeness is separate from the actual behavior assertions.

The independent fresh hosted eight-stage review is
`out/p0-p3-review-hosted-f412206-legacy-68dqj76d/audit.json`, SHA
`ffd62221079bf6cdc6d6a7bb2c31de859438e317f12eeb24b702c9674cc361c3`.
Its complete 5,237-file copied-evidence inventory has SHA
`aff3f20f61590b27773e0b3bee98884bf276b6200b2154425c7b6de6bf55cbf5`.
It verifies the fresh hosted eight-stage source/raw/command and semantic joins,
Original18/Reader93, strict native-task profiles and retained legacy binaries.
The source-only forensic rechecks explicitly adapt Linux device-number decoding
and extracted archive permissions; they do not reconstruct original admission
modes or execute a new native campaign. Store's pure decoder retains aggregate
exit/reap and transcript-digest evidence rather than per-call payload exports or
its executable bytes. No local packet substitutes for hosted evidence.

The complete hosted profile satisfies AGENTS.md's complete-CI-lanes OR serial
preflight requirement. The additional failed local editor15 remains a material
reproducibility caveat with unknown cause. Final delivery readiness requires
complete CI on the Desktop entry correction and direct verification of that
run's own three binary files against its gate record and Cargo receipts.

A2 authorship, local execution, CI success and this record grant no A3 merge or
self-approval authority. The reviewed implementation, qualification, archival
successor and authorized integration remain distinct delivery steps.
