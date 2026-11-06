# Shared frame export and RUN0 probe batch

Status: source and focused evidence independently reviewed; hosted qualification is recorded with the delivery PR.

The fixed starting revision is `8b41a38c4927a327ea69b1fff213699c0ef1caf2`
(PR #57). The coordinator owns integration, source registries, required gate hooks
and this record. Two parallel authors own disjoint frame-recording and RUN0 probe
files; a third, non-author agent reviews both contracts, source and evidence.
The shared worktree is `/tmp/wmw-runtime-next-batch` on
`codex/frame-capture-batch`. Linux resources are reserved under
`bigman:/tmp/wmw-frame-capture-CmEzla0p/{frame,run0}`; timed frame experiments and
VM execution are serialized. Builds and raw evidence stay on that host.

## Baseline

Post-merge [run 42166016429](https://github.com/whole-machine-works/RamenOS/actions/runs/42166016429)
was checked before implementation. Its agent-task lane failed because Docker
container creation exhausted the unchanged validator wall budget. The actual
record reports `created=false`, `failure_phase=create`, `failure_reason=timeout`,
`removed=true` and `reconciliation_required=true`; the public response was `io`.
The success-path test correctly rejected it. This differs from the already
tested, fully reconciled attach-timeout recovery. No relaxed deadline, accepted
`io`, automatic runtime retry or successful validation is inferred. The original
job log is retained under
`out/frame-capture-batch-20261106/baseline/agent-task.log` in the primary checkout.
The other completed lanes passed. Audit verified 877 regular source files,
244 recording runs and all eight preservation stages; among 69 command receipts,
only agent-task failed and every command was actually reaped. All eight original
ZIPs were retained and checked against GitHub's SHA-256 digests. One unchanged
agent-task job rerun passed in attempt 2 (362.572 s), and all nine checks are now
green. Its separate log and timing bundle are retained alongside attempt 1.
The attempt-2 audit combines that fresh agent receipt with the unchanged-head
receipts GitHub reused from attempt 1. It verifies all 57 canonical stages,
six source links and the exact three archived runtime binaries. It is not a
second fresh execution of the other lanes. This success does not establish
the first timeout's cause.

## Frozen outcomes

The frame packet replaces two recursive evidence censuses with one fresh census
and one exclusive reservation for the two genuine frame/chrome exports. Preserve
the first complete export before attempting the second composition, every
independent Host assertion, all 66 D09 iterations and 134 frames, all identity,
freshness, link, mode and path checks, all checked byte/file/record caps, and the
original deadlines. Post-admission failure retains uncertainty and the marker.
Dedicated executable controls must cover refusal of the second target, identity
substitution, combined byte/file/entry cap overflow, partial output and continued
usability of a fresh operation after rejection. Controls join the required
editor gate without altering the original eighteen assertions, Reader93,
thirty process families or preservation stages. Compare actual baseline and
candidate evidence corpora; a speed improvement does not explain a historical
timeout by itself.

The RUN0 packet prepares actual source/tool/firmware/EFI/symbol/init/ESP
provenance and one bounded owned-VM capability/prior-diagnostic probe. It does
not implement or certify C0/C1/C2. The installed Ubuntu OVMF package's release
build must not be assumed to emit EDK II's debug-only image-load diagnostic.
The probe uses the oracle's pinned x86_64 TCG profile, a private VARS clone,
read-only CODE and raw ESP, no network or passthrough, and private sockets.
The sole profile addition is source-derived ISA debugcon port `0x402` for
firmware output. Its evidence uses a separate probe schema and records actual
reset-time CPU expansion, argv, command traffic, resource hashes and teardown.

The closed transport allowlist is QMP capability/status/model queries,
`query-cpus-fast`, exact read-only HMP `info mtree -f` and `info registers`, one
`cont`, and owned `quit`. No RSP request, memory read, write, breakpoint, input
injection, guessed entry address or checkpoint is permitted. Bounds are 60 s
total VM lifetime with 5 s reserved for teardown, 20 s running time, 5 s per
response, 128 total messages, 64 KiB per frame and 32 MiB retained output.
Use an absolute deadline, strict response IDs, bounded asynchronous events and
capped drains. Record actual process reap and initial/final VARS hashes.
All capture/precondition and seven oracle completion claims remain false.
Missing or ambiguous actual diagnostics remain `INCOMPLETE`.

Prefer installed, pinned `qemu-img` to materialize a raw FAT image from staged
EFI/init files, then independently check it with `fsck.fat` and `7z` extraction
and compare extracted hashes. Record actual geometry and format. No bespoke FAT
writer is needed when this route works. No VM launch precedes independent
source, assertion, provenance and exact-invocation review. A DEBUG-firmware
profile, if needed, requires a separate explicit review; it is not an automatic
fallback or an alternative same-run address source.

## Acceptance

Authors run focused denial, lifecycle and real-consumer checks. The independent
reviewer examines their exact source and raw evidence. The coordinator updates
only affected source pins, executes all required CI lanes on the final fixed
candidate and audits source/command/recording/binary provenance. Original failed
attempts remain retained. Full local preflight is not duplicated with full
hosted acceptance. Author handoffs, retained failures and complete hosted
qualification are indexed by the primary checkout's
`out/frame-capture-batch-20261106/batch.json` and the delivery PR. Diagnostic
campaigns are never substituted for required acceptance.

## RUN0 prepared inputs

The reviewed prelaunch packet is retained in the worktree at
`out/run0-capture/prelaunch/` and on the reserved Linux host. Its profile file
SHA-256 is `b5943f7bf15e5034bfdeeceb38ed37512eb42fc92c243907b0fa3f2add3670f5`
and canonical profile digest is
`63ceab5174fc105441a1c3f50168a9339dd6de8d1822ccadca4c88d92f7f76ef`.
It binds an unmodified `8b41a38` guest build from the retained source archive,
using `nightly-2026-02-08`. The EFI is 517,632 bytes and its 7,417,856-byte PDB
matches the actual PE CodeView GUID and age. The 2,949,120-byte FAT12 superfloppy
contains the exact EFI and 4,096-byte default init image; both independent image
checks pass. This establishes prepared inputs, not a boot checkpoint.

The actual installed toolchain includes QEMU 8.2.2, GDB 15.1 and Ubuntu OVMF
`2024.02-2ubuntu0.10`. Retained primary-source hashes trace the firmware's
`RELEASE` build through `MDEPKG_NDEBUG` to disabled `DEBUG` calls, including the
image-loader diagnostic. The initial supervisor has twenty independently rerun
controls, covering closed command authority, bounded transport and storage,
owned-process cleanup, complete log-tail retention, input/image mismatches and
explicitly false capture claims. Concrete VM observations are recorded separately
after independent prelaunch acceptance.

The first authorized run, `probe-001`, exited before the first resume: QEMU
reported `Block node is read-only` for the default disk attachment. Its actual
PID was reaped with return code 1, within the lifetime bound. The sole pending
QMP request was `qmp_capabilities`; no `cont`, boot checkpoint or diagnostic
observation occurred. Input pins and VARS bytes were unchanged. Its report
digest is `f23eff620dbeb239b44b320cbc5a930eb4543b9ccd603495c27d3f62b1473257`.
This is retained as an attachment-capability failure, not evidence of missing
firmware diagnostics. A separately reviewed read-only-capable attachment and
fresh profile/input root were required before the next probe.

The separately reviewed profile
`q35-8.2-tcg-qemu64-virtio-ro-esp-debugcon-v0` binds the read-only virtio device
explicitly. Its canonical digest is
`b883f875cad1ae0f2c538be7df7332c662834e8d0b26f900a2b97514dc68766b`;
all original guest/tool/firmware bytes are unchanged in fresh private input copies.
The original input root, helper and failed report remain intact. `probe-002`
acknowledged the nine allowlisted requests, including one resume and quit, and
actually booted the EFI: retained serial output contains init ping/pong and kernel
idle. QEMU exited 0 and was reaped within 20.125 s; original inputs remained
unchanged and only the disposable VARS changed. The report remains `INCOMPLETE`
because draining encountered an unidentified I/O error before verified EOF.
This is no proof of complete diagnostic absence or any C0/C1/C2 checkpoint.
Report digest: `f89752aef2370dfc574b834daea1659140e3adae0a973c7cd113e15a152d6d37`.
The bounded repair retains stream/errno identity and continues collecting other
streams; any terminal stream error still forbids candidate admission.

The drain repair passes 23 controls on macOS and Linux. It distinguishes bounded
nonblocking retries from terminal errors, records stream and errno, and drains
unaffected streams without falsely marking an errored stream EOF. One fresh run,
`probe-003`, identified QMP read `ECONNRESET` (errno 104). All nine allowlisted
requests were acknowledged, including one resume and quit; 23 messages were
retained. Serial, debug, stdout and stderr each reached actual EOF; firmware debug
output was exactly zero bytes, while the 949-byte serial log again showed actual
guest startup, init checks and kernel idle. The owned child exited 0 and was reaped
in 20.082 s within the original bound. Inputs remained unchanged; disposable VARS
changed. QMP has no EOF witness, so the report remains `INCOMPLETE`, with no
candidate, no C0/C1/C2 and all seven broader claims false. Its digest is
`264e0d8c9751bbbb88c5bad70465440c8312d180b0291a5d315a83a137eac23f`.
The record includes an acknowledged QMP quit followed by an owned SIGTERM; it
does not establish which caused the reset, or the cause of probe-002's error.

The final supervisor adds a default-off acknowledged-quit grace: only an actual
quit acknowledgement enables one wait of at most 0.5 s, clipped to the remaining
original absolute deadline, before the unchanged owned TERM/KILL fallback. It
retains the actual grace outcome separately from EOF. Twenty-five controls pass
on macOS and Linux, including a real cooperative child exiting with no signals
and a real stalled child requiring bounded TERM/KILL and reap. This avoids
interrupting acknowledged shutdown; it does not infer a historical reset cause.

The final authorized `probe-004` exited during that grace with no supervisor
signals and was actually reaped with return 0 in 20.113 s. QMP read errno 104
still occurred; the other four streams reached EOF, with the same genuine
949-byte guest boot log and zero debug bytes. All nine requests were acknowledged,
23 messages were retained and all input pins stayed unchanged. Its report is
`INCOMPLETE`, with all capture/precondition/broader claims false and no candidate
or checkpoint. Digest:
`47aafd6f2e929906cb619ac2584af118bfd405e62a2e46c29503e5b782c4bd94`.
This establishes reset recurrence without supervisor signals in this run; no
cause is assigned to an earlier run and no reset is converted to EOF.

The remaining transport packet must review the concrete acknowledged-quit/QMP
reset and completeness contract; repeating the same probe or adding another
generic validator is not progress. The next firmware prerequisite is a separately reviewed diagnostic-capable
DEBUG profile built from pinned source. The installed RELEASE source removes
the required load-address diagnostic, and probe-003's complete debug stream is
empty. A fresh prior hint still must precede a separately reviewed collector and
actual C0/C1/C2. No firmware fallback, guessed entry, guest patch or guest-access
claim is supplied. Compact evidence is under `out/run0-capture/` in the worktree
and copied into the primary batch evidence; complete inputs and all attempts
remain under `bigman:/tmp/wmw-frame-capture-CmEzla0p/run0/`.

## Matched frame measurements and retained failure

The frozen frame candidate passes strict Linux Clippy and all eight dedicated
controls (7.69 s test time; 9.269 s owned command, actually reaped). The controls
retain 83,169 entries and about 3.10 GB logical sparse/output bytes, using about
286.7 MB allocated file blocks. They remain included in the runtime artifact;
this batch makes no claim that overall CI or upload time is reduced. The initial
control wrapper omitted the existing gate's umask and failed its private-directory
setup. That attempt and the correcting diagnostic are retained separately; the
successor uses the gate's existing `022` umask. The first control also exercised
an already consumed surface and returned `NotReady`; its corrected fixture
renders freshly before every genuine composition. That author error is retained
separately and supplies no optimization evidence. Native arithmetic remains
checked in source; the controls exercise actual bounded cap overflow, not native
integer overflow.

Fresh baseline `8b41a38` and frozen candidate public-corpus campaigns run the same
actual prerequisite probes and public selection. Both D09 scenarios complete all
66 steps, the 134 actual frames and their chrome records, 67 matching crop pairs,
the original five-second child lifetime and actual child exit/join. Independent
raw evidence review verifies all 134 full BGRA frames and all 134 chrome records
are byte-identical between runs, as well as the application crop hashes.

| D09 measurement | Baseline | Shared reservation |
|---|---:|---:|
| Actual recursive census observations | 132 | 66 |
| Sum of census durations | 1.215082460 s | 0.585375709 s |
| Sum of the two composition/export spans | 3.121709954 s | 2.134727333 s |

Those observed sums are 51.8% and 31.6% lower respectively on this shared Linux
host. The first span includes admission/census; the second includes settlement.
They are not end-to-end iteration latency, and nested census time is not added
to the enclosing spans. The unused reference scan has zero observations, never
a manufactured completed measurement. These observations do not identify the
cause of any historical timeout.

Neither campaign supplies complete qualification. Baseline: 41 tests passed,
D30 alone failed for eight missing preservation receipts, four controls filtered,
command exited 101 and was reaped. Candidate: 40 passed, D21 and D30 failed,
four filtered, exited 101 and was reaped. D21's fresh Save after reopen retained
correct `note=next` bytes but remained Unsaved/revision 1 at its original one-second
deadline. Its earlier permit barrier had settled without issuing a permit; the
retained failure has no terminal Store snapshot for the reopened Core (recorder
`epoch_index=1`, service epoch 2). No direct source defect
explains the failure, and its cause remains unresolved. The joint reservation is
used only by D09 and the new controls; shared recording helpers still changed,
so no causal exclusion is claimed. Complete hosted qualification must run D21,
all preservation stages and every other original check on the fixed candidate.

Exact retained frame reports under `bigman:/tmp/wmw-frame-capture-CmEzla0p/frame/`
are `control-002/control-summary.json`, `corpus-baseline-001/campaign-review.json`,
`corpus-candidate-001/campaign-review.json`, `matched-corpus-comparison.json` and
`corpus-candidate-001/d21-failure-review.json`. The compact handoff and copies
also live in the primary checkout's `out/frame-capture-batch-20261106/frame/`.
