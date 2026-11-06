# RUN0 entry inputs and editor timing batch

Base: `02cf36c5100b51e77ad16e6e5716c719f3455436`. This batch follows
PR52's Linux host editor delivery and PR55's failure-only Save diagnostics.
The predecessor's post-merge runtime run
[42158255430](https://github.com/whole-machine-works/RamenOS/actions/runs/42158255430)
passed all nine checks. That result does not explain the retained capacity,
D19 or D09 failures.

## Parallel ownership and acceptance

| Packet | Author / independent reviewer | Scope and acceptance |
|---|---|---|
| Editor timing | `pr52_source_review` / `save_diagnostics_review` | Bounded in-memory D09 reference-render, composition and recorder phase measurements; emission after actual child cleanup. Preserve all corpus steps, both genuine frame streams, exact state/pixel comparisons and the original five-second lifetime. Fresh Linux D09 and capacity controls, strict Clippy and complete affected hosted qualification. |
| RUN0 entry inputs | `run0_oracle_author` / `save_diagnostics_review` | Two new `tools/trace/boot_profile_inputs.py` and `test_boot_profile_inputs.py` files: strict bounded input/PE/relocation and prior-diagnostic admission. Malformed inputs deny; missing prerequisites remain incomplete. Adversarial and CLI tests precede implementation; no collector or guest change. |
| Integration | Coordinator / non-author review | CI tooling invocation, focused recipe, reviewed assertion-pin successors, status/queue/history and final qualification. The existing canonical stage inventory remains intact. |

Authors use `/tmp/wmw-runtime-next-batch` with disjoint file ownership.
Linux builds and fresh evidence use separate `reliability/` and `run0/` children
under `bigman:/tmp/wmw-runtime-next-Z9PN5Mle`; no shared targets or output reuse.
Failed attempts remain retained. Local evidence is indexed by
`out/runtime-next-batch-20261105/batch.json`; large raw artifacts stay compressed
or on the reserved Linux host.

## Boundaries and next inputs

The entry-input tool is one prerequisite of the maintained
[Oracle preparation](boot-profile-oracle-v0.md), not its full profile validator.
Hash-bound opaque records do not verify expanded CPU/invocation semantics,
matching symbols or the ESP-to-EFI relationship. A prior diagnostic supplies
only an address candidate; it cannot supply a fresh C0 stop. All capture,
profile-completion and broader guest-access/ownership/runtime claims stay false.
No usable retained prior diagnostic is currently available in the inspected
project evidence. Actual capture and guest ownership work remain dependent on
the reviewed profile and actual C0/C1/C2 observations.

D09 measurements identify where time is spent in the observed run. They do not
by themselves explain an earlier failure or justify relaxed budgets, fewer
frames, weakened comparisons or synthetic successful evidence. Any optimization
requires source review and measured preservation on the fixed successor.

## Delivery state

Both author packets and the coordinator's CI/pin transitions passed independent
review. RUN0's accepted implementation is committed as `ed167fb`; all 22 controls
and the actual focused recipe pass. The existing EFI smoke is parse-only and has
no verified build provenance. The required tooling stage executes these controls
without adding, dropping or skipping a canonical stage.

The D09 candidate changes only `recording.rs`, `cursor_cases.rs` and its terminal
call in `full_assertions.rs`; the native fixture module is unchanged. Strict Linux
Clippy, focused D09 and the capacity Save control pass. D09 records all 66 rows in
each of nine measured phases with no omissions, both 67-frame streams have equal
application crops, and the child exits and joins. Focused reference rendering
takes about 67.6 ms, both compositions about 1.695 s, nested scans about 150.0 ms,
write/hash/identity work about 228.9 ms and crop hashing about 95.3 ms. Nested
phases must not be added to their enclosing composition totals. These observations
are from the shared Linux host and a smaller corpus, not the historical CI run.

A separate source copy injects a real recorder path collision. The original
assertion still fails with exit 101; one timing sample is incomplete, the child
really exits/joins and no successful scenario summary is produced. Existing
parent-owner retention remains incomplete. The negative copy also materializes
six documentation aliases; it is not claimed byte-identical to the positive tree.
The first unused-helper Clippy failure and control-only compile failure remain
retained separately from the successful candidate checks.

The additional full public-selection campaign is diagnostic only. Genuine bounded
prerequisite probes ran; the command exited 101 and was reaped after 206.025 s:
41 tests passed, D30 alone failed for its eight absent preservation receipts, and
four tests were filtered. No runtime-success result was produced. D09 itself
completed all 66 steps, both 67-frame streams matched, and its child exited/joined
within the original lifetime. The source and actual selected binaries were bound
and independently checked; no missing receipt was fabricated.

With that preceding corpus, observed scan file counts rose to 2371–2633 and nested
scan time to 1.390469626 s, versus 193–455 files and about 0.150 s focused. Both
compositions took 2.881653368 s versus about 1.695 s focused; write/hash and crop
hash costs stayed close. This measures a current corpus-dependent overhead
contribution, not the cause of the historical hosted timeout. The next separate
packet should review combining both complete frame exports under one existing
shared-root reservation/census while preserving path checks, caps and independent
Host assertions. This batch implements no such optimization.

Complete hosted qualification on the combined candidate supplies the full
preservation and recording checks. The final run identity/results are retained
with the batch evidence and PR; the diagnostic campaign does not substitute for it.
