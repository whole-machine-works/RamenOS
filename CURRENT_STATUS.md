# Current Status

**Last Updated:** 2026-11-08
**Status:** Active and authoritative for landed state
**Current Slice:** RUN0 target runtime preparation after merged UI1.1d host process delivery
**Physical Lane:** S12.4 HIL appliance observation/actuation awaits setup
**Software Lane:** SW0 foundations through A2.9; full A2 and comparison pending

RamenOS is public pre-alpha, building toward the everyday OS for humans and AI
agents in [Vision](VISION.md). This file owns landed behavior and limitations;
[Next Tasks](NEXT_TASKS.md) owns dispatch and acceptance. Detailed integration
chronology and private evidence digests are retained in the
[historical status snapshot](docs/archive/plans/2026-10-06-status-integration-snapshot.md)
and [Changelog](CHANGELOG.md), outside routine agent intake.

## Execution state

The default-off UI1.1c host task reads an approved artifact, processes logical
keyboard input, edits bounded text, renders offscreen frames, saves through typed
Store authority and reconciles original outcomes through joined-owner reopen.
Its eighteen original assertions and complete 93-scenario recording checks passed
on macOS/Linux. That landed result is a trusted in-process host consumer. Models
are unnecessary for the task. Target execution and target persistence remain
unfinished.

The default-off Linux process implementation merged through
[PR52](https://github.com/whole-machine-works/RamenOS/pull/52) on November 5 as
`c9ed54a5b69a1a279d7014929bf932288aa86ec6`, after separate A3 approval of reviewed
head `59723ffe198019fa847f34777269b4da543758c4`. Complete P0 review,
the private assertion handoff and source-bound Linux missing-API RED closed the
P1/P2 authoring dependencies before their concurrent implementation. P1/P2 then
released P3's common Store Save/original-recovery integration. The workflow uses
genuine approval/Read and enrollment, child-local edit/raster, immutable
publications and one-use captures. The parent retains Core and Store authority.
It exercises Save denial, newer-draft Unsaved, lost-reply recovery without mutation
replay, issued-writer survival after child death/revoke, unrelated-session progress
and a subsequent successful Save.

The reviewed head passed all nine checks in
[hosted run 42098888792](https://github.com/whole-machine-works/RamenOS/actions/runs/42098888792).
Independent audits verified 57 canonical stages, all eight preservation stages,
244 complete recording Runs and parent joins, and that run's own three archived
binaries. The final correction releases an exact unadmitted Save intent when
Desktop producer capacity rejects it, and retains a partially started Read's
actual dispatcher until its join. Linux regressions prove zero Store work on
the rejected Save followed by a fresh Save on the same child, and Pending before
the Read dispatcher's join followed by Complete and a fresh authorized Read.
These are host results; target/runtime, device input, persistent target storage
and physical qualification remain pending.

Post-merge main [run 42151282196, attempt 1](https://github.com/whole-machine-works/RamenOS/actions/runs/42151282196/attempts/1)
failed the unchanged native task before process-runtime qualification. Seventeen
original tests passed; `ui1_1_clock_capacity_and_counter_limits_fail_closed`
failed its first `slots/0` Save: operation 1 returned Unknown (10), with no receipt,
where a successful 176-byte receipt was required. The command exited 101 and was
reaped. Only the scenario's initial Store snapshot survived, so the underlying
permit/publication/reply failure remains unexplained. The retained pre-merge
qualification and actual merge do not establish a green post-merge baseline.

The one unchanged failed-jobs [retry, attempt 2](https://github.com/whole-machine-works/RamenOS/actions/runs/42151282196/attempts/2)
also failed that capacity test: `slots/0` completed, but `native_max/6` returned
Unknown for operation 1 without the required receipt. Again seventeen tests
passed and one failed; the command exited 101 and was reaped. The failed scenario
again retained only its initial Store snapshot. Both main qualification attempts
on `c9ed54a` remain failed, with root cause unknown. Separately, PR53's
[hosted run 42151684699](https://github.com/whole-machine-works/RamenOS/actions/runs/42151684699)
passed all nine checks and its dispatch update merged as `65d45be`; that passing
run does not explain or remediate either main failure.

Failure-only diagnostics now cover the `slots/0` and `native_max` receipt sites.
They retain after-settle timing, actual request/reply bytes, producer join
observations and a bounded Store/IO/permit snapshot before resuming the original
panic. Assertions, deadlines and budgets are unchanged; no successful summary
is manufactured. All eighteen native Linux tests, the focused capacity test and
strict Clippy pass locally. A separate authenticated CandidateBlobWrite failure
control still exits 101 and retains its failure snapshot without a success summary.
These checks validate the diagnostics, not a fix for either original failure.
PR55 merged the Save diagnostics as `1d2c9b1`; all nine checks passed in its
[post-merge run 42158255430](https://github.com/whole-machine-works/RamenOS/actions/runs/42158255430).
That green baseline does not explain the earlier failed attempts.

Use these diagnostics in a bounded fresh source-bound Linux reproduction of both
failed scenarios before proposing a root-cause fix. Preserve every original deadline,
owner and assertion; do not accept Unknown as the expected successful receipt.
Retain every failed attempt. This investigation can proceed alongside independent
RUN0 preparation and does not change the accepted dispatch dependencies.

Post-PR53 main [run 42153799717, attempt 1](https://github.com/whole-machine-works/RamenOS/actions/runs/42153799717/attempts/1)
on `65d45be` failed the separate D09 positive cursor/selection/scroll scenario:
41 public tests passed, one failed and four were filtered out.
`D09FrozenCursorSelectionScrollGolden-123` exhausted its original five-second
child lifetime and returned `Some(Timeout)` instead of `Some(Ok)`. The child was
killed with SIGKILL, actually reaped and its supervisor joined. Why the scenario
overran remains unknown, distinct from the capacity and D19 failures. Reproduce
it in a bounded fresh source-bound Linux snapshot without relaxing budgets or
assertions; this investigation does not block independent RUN0 preparation.
Retained control timestamps place about 4.55 seconds in 66 PublishAck-to-next-Input
gaps that include reference rendering, both compositions and synchronous recording;
they do not isolate the cause. The successor below measures those parent phases
while preserving every step and frame, the original five-second lifetime and
exact pixel comparisons.

D09 now records bounded, preallocated in-memory durations for reference rendering,
both compositions and recorder scan/write/hash phases, then emits a diagnostic
report after actual child exit/join proofs. It preserves every original step,
frame and assertion. The focused Linux run completed all 66 iterations and 67
matching frame pairs within the original lifetime; strict Clippy and the capacity
Save control passed. A separate actual recorder-refusal control retains the
original panic, failed result and incomplete sample. Its child exits and joins,
while the existing failure path retains parent owners as incomplete. These are
separate ownership outcomes, not a successful scenario.

The full public-selection diagnostic completed D09 successfully with its preceding
corpus. Scans grew from about 150 ms to 1.390 s as the observed file counts grew
from 193–455 to 2371–2633; both compositions grew from 1.695 s to 2.882 s. Nested
scan time is part of composition, not additional time. This is measured current
overhead, not proof of the historical hosted cause. The successor now shares one
fresh census and exclusive reservation across both complete frame/chrome exports.
It preserves first-frame evidence before the second composition, every original
path/cap/identity check and independent Host assertion. Errors after admission permanently prevent
that reservation from settling; each write rechecks marker ownership. Eight
separate Linux controls and strict Clippy pass, including actual partial writes,
capacity refusals, replacement and fresh successful operations. Original eighteen
assertions, Reader93, all thirty process families and deadlines remain required.
The [successor batch record](docs/plans/frame-export-run0-probe-batch-2026-11-06.md)
owns the matched measurements, source identity, failed attempts and qualification.

The candidate's diagnostic campaign also failed D21's fresh Save after reopen:
the correct draft remained Unsaved at its unchanged one-second deadline. Its
cause remains unresolved and that run lacks reopened-epoch terminal evidence.
PR #58's reviewed head and its post-merge
[run 42178680168](https://github.com/whole-machine-works/RamenOS/actions/runs/42178680168)
passed all nine checks; the latter audit verifies 57 canonical stages, eight
preservation stages and 244 recording runs. That success does not explain the
earlier failure.

D21 now has failure-only current-epoch Store/IO/permit/reply and pending-owner
diagnostics. It records authentic child exit/join evidence separately from
original-operation cleanup, retains failed roots, and resumes the exact original
panic even if recording or cleanup also fails. Diagnostic work consumes the
existing two-second cleanup budget; the original one-second assertion is
unchanged. Four dedicated Linux controls and strict Clippy pass, including real
execution of the existing simulated IO-fault seam, recording refusal and held
cleanup. A child join with one held producer remains incomplete even when the
pending-original count is zero. The unchanged D21 case also passes. These results
validate diagnostic behavior, not a historical cause or production fix. The
[diagnostic batch](docs/plans/debug-firmware-d21-batch-2026-11-06.md) records exact
evidence and the complete hosted qualification requirement.

The separate earlier local D19 second-Save failure remains unresolved with its
cause unknown; the later hosted PASS does not explain it. The ready queue retains
a bounded reproduction/instrumentation follow-up without renewing deadlines or
discarding failed attempts. The
[qualification record](docs/plans/editor-process-delivery-qualification-2026-11-05.md)
keeps these sources, failures and host evidence distinct from target and physical
qualification.

The four host reliability packets from external review are implemented and
independently reviewed. Store requests retain their actual reply data through
native lease transfer without disabling bounded reclamation. Abandoned rendering
retires its exact acquisition/frozen frame; approved launch assigns focus once,
and background rendering preserves launcher focus. Definitive pre-admission
expiry closes the authentic intent and releases the app Save chain while admitted
uncertainty retains original reconciliation. JournalSync reproduction led to
bounded cleanup of held, verified owner-created pre-rename staging; foreign,
corrupt, symlink and replacement files deny, and post-rename recovery preserves
the original outcome without mutation replay.

`just foundry-editor-reliability-ui1-1` passes thirteen new assertions (Desktop7,
Store5, app-private1) and strict Clippy for all three regression targets on macOS
and Linux on the same source snapshot. The unchanged original eighteen-case task and complete Reader93
pass freshly on macOS, as do volatile13, Store7, Preview codec7, Save codec8,
NativeRead9, NativePreview5 and adapter4 with their strict/feature checks.
[The review resolution](docs/plans/editor-reliability-review-2026-10-13.md)
retains regression, negative-control and integration evidence. Complete Linux56
preflight and fresh five-lane hosted merge qualification now pass. These repairs do
not establish editor-child execution, target persistence, crash-orphan cleanup,
CAS temporary-file recovery or physical durability.

At initial reliability-repair acceptance, CI tooling (71 Python/seven Rust
controls), S11/S12/S13, appliance docs/manifest and org-governance passed on that
source revision. S12 GOP and S13 block each required an unchanged retry after an
initial missing boot marker; those failures and successful runs remain retained.
The streamlining successor below records fresh checks and reviewed registry
successors. Complete Linux56 and the fresh five-lane hosted qualification now pass.

### UI1.1d shared adapter migration — accepted host preservation

The [November 4 Linux prerequisite packet](docs/plans/editor-process-linux-prerequisites-2026-11-04.md)
adds six independently reviewed kernel witnesses and a separate default-off gate:
real shared mappings and sealing, received descriptor ownership, unprivileged
credential rejection and inherited-endpoint sender identity. These are primitive
prerequisites. At that recorded source, the actual editor carrier and full P0/P1–P3
were incomplete; the reviewed working successor above now advances that path. The existing thirteen setup controls and
four missing-process-API consumers retain their separate preparation scope.

Both `EditorClient` and `NativeTextEditor` use `desktop_editor_core` for pure
editing/navigation/scroll/raster. Checked snapshots transfer seven fields;
legacy/native policies and detached-scratch owner admission remain distinct.
The core has no Desktop, Store, Focus or Save authority. Its 26 pure assertions
and four explicit required-feature adapter assertions passed on macOS/Linux;
strict Linux55 preserves original13/18, strict3 and Reader93 requirements.
Protocol384/version1 and the process contracts alone establish no runtime result.
The merged successor above supplies complete bounded Linux host qualification;
historical private smoke and cleanup experiments do not substitute for it. Re-freeze current
source before reusing historical evidence; the old 217-row task closure is not a
permanent count requirement after legitimate dependency additions.

RUN0.0 has a reviewed 17-case allocation-free map/retention admission gate.
The external entry-input prerequisite now has a strict PE/input/prior-diagnostic
admission CLI and 22 independently reviewed synthetic controls, executed by the
existing CI tooling stage. It distinguishes malformed inputs from unavailable
evidence and preserves explicit false capture, profile-completion and guest
claims. The successor prepares a real source-built EFI with matching PDB identity,
tool/firmware provenance and an independently checked read-only boot image. A
separate owned-VM probe has 27 Linux controls in the required tooling stage: bounded
allowlisted observation, actual teardown/EOF, immutable inputs and explicit false
capture claims. Its first run exposed the default IDE attachment's rejection of
read-only media and exited before resume; that failure is retained. The revised
profile explicitly names its read-only virtio-blk attachment and actually boots
the guest through init checks and kernel idle. A source-backed final-quit framing
fix removes only optional trailing CRLF. The final probe exits during bounded quit
grace without supervisor signals, and all five streams reach EOF without errors.
That RELEASE-firmware debug stream is empty. Its actual observations remain in the
[probe batch](docs/plans/frame-export-run0-probe-batch-2026-11-06.md).

A separately reviewed DEBUG OVMF profile now supplies the missing prior hint.
Two clean firmware builds produce identical CODE/VARS/full images on the same
host with pinned BaseTools reused. One bounded probe retains the complete
12,323-byte debug stream, with one matching loader diagnostic. It reaches all
five EOFs and exits without signals or transport errors in 20.096573 seconds;
actual reap and unchanged input pins are recorded. The existing entry-input
helper returns `ADMIT` for the explicitly mapped profile and full diagnostic.
The [DEBUG batch](docs/plans/debug-firmware-d21-batch-2026-11-06.md) owns source,
build, profile and admission identities. No guest or observer code changed.
The prior address is a candidate for a fresh stopped entry; it does not establish
address stability, C0/C1/C2 or guest access. The
[entry preparation](docs/plans/run0-relocated-entry-preparation-v0.md) owns the
remaining capture and guest-access dependencies.

The [reset capability packet](docs/plans/run0-c0-inspection-v0.md) adds a bounded
debugger transport and an independently reviewed reset-only launch. The pinned
QEMU reported one realized CPU with 40 physical address bits, an exact 608-byte
register payload, the matching memory view and successful physical-mode
readback. All six streams reached EOF and the owned VM exited and was reaped.
Fresh C0 still needs a source-bound exclusion or actual witness for hidden
nested translation before it can inspect ordinary RAM.

The [SATA-disabled requalification](docs/plans/run0-sata-off-requalification-2026-11-06.md)
supplies a fresh DEBUG entry hint and admission, a paused CAP1 pass and a separate
paused host CPU witness pass. The diagnostic and CAP1 reset memory views contain
no AHCI region. The offline C0 decoder verifies the unchanged prior CAP1
report and artifacts in a reserved namespace and uses a pure bounded paging
step. Shared C0 replay covers QMP boot transitions and delayed RTC events.
The C0 wire now checks the fixed paused QMP handshake with bounded real socket
fixtures and retains raw slices and operation timing. Its typed debugger
setup shares that wire and ledger through reset register and physical-mode
readback. Existing reset capture controls keep their original limits.
At this stage the live collector still needed its same-stop witness, persistence
source closure and RAM acquisition evidence; the later joins are recorded below.

The [SATA/VAPIC-disabled successor](docs/plans/run0-vapic-off-requalification-2026-11-06.md)
now qualifies a distinct exact profile with 217 Linux trace controls, a fresh
DEBUG hint and independently reproduced admission, CAP1 and host reset evidence.
Its 8/85/42 run files match the remote originals; both observed reset memory
views exclude AHCI and `kvmvapic`. The host retains the unchanged 14-read/104-byte
budget, four actual zero-exit waits and eleven EOFs. Pure prior-profile and CAP1
joins pass. Original profiles and failures remain preserved. This does not
establish global work quiescence or live C0. At that stage, exact RTC policy,
asynchronous entry stop, the same-stop witness and reviewed ordinary-RAM
persistence condition remained prerequisites for guest-memory acquisition.

The later [source follow-up](docs/plans/run0-c0-source-persistence-2026-11-06.md)
conditionally accepts that persistence condition for the exact SATA/VAPIC-off
profile. Its finite callback inventory distinguishes implementation cache
updates from global mapping and architectural-state writers. At that stage,
current C0 launch/stop/state/view/witness joins and actual acquisition remained
pending. The source decision supplies no live-read permit or global-quiescence
claim by itself.

The [entry-stop prefix](docs/plans/run0-c0-entry-prefix-2026-11-06.md) now
implements the checked prior token, sole breakpoint/continue, silent asynchronous
stop, separate acknowledgment and fresh debug-status confirmation. Its
exact-profile RTC policy joins host and C0 replay. All 253 Linux trace controls
and three retained reset replays pass. These are source/socket preparation
results; that packet deferred the owned launch and current-state/witness/RAM joins.

The [acquisition driver](docs/plans/run0-c0-acquisition-driver-2026-11-06.md)
now implements the fixed paging/object/recheck schedule and one-use typed
requests. Eighteen new controls and complete synthetic replay pass independent
review. That packet deferred production current/after issuers, shared-wire
dispatch/accounting and the owned collector; it acquired no live RAM.

The [host-observation receiving adapter](docs/plans/run0-c0-host-observation-2026-11-07.md)
now reuses the 14-read/104-byte body through closed same-wire receipts and one
aggregate lease. Twenty-five new controls and all 296 Linux trace controls pass;
three historical reset replays remain valid. Actual helpers operate only on
private synthetic fixtures in that packet. It deferred production issuers, the
owned collector, shared dispatch/accounting and retained-runtime C0 acceptance.

The [owned C0 collector](docs/plans/run0-c0-owned-collector-2026-11-07.md)
now joins private current/after issuers, shared physical-send accounting and owned
cleanup. Independent source review, all 360 sealed Linux trace controls and three
historical reset replays pass. The runtime policy checks the exact profile, ABI,
prior/persistence inputs and seventeen observer source files.

The [stopped-entry result](docs/plans/run0-c0-result-2026-11-07.md) now accepts
one actual owned C0 inspection after independent retained replay. Its 28 guarded
physical reads returned 26,752 bytes across three distinct table frames and eight
selected objects, with matching rereads and eight reproduced translations. All
129 paired operations, twelve EOFs, four actual zero-exit waits and unchanged
source/input closure are retained. No forced action was needed. The full-capture,
atomic-snapshot and device-quiescence flags remain false. Next, qualify a fresh
same-VM C0/C1/C2 firmware-call history; this completed VM has already shut down.

The [same-call shared primitives](docs/plans/run0-call-map-shared-primitives-2026-11-07.md)
are implemented and independently source-reviewed. They provide fixed parent
deadlines, owned cleanup, complete copy reservations and retained read/assembly
evidence. All57 new integration controls also passed in Linux hosted run
42367071792, but complete qualification failed in frame recording during the
editor runtime stage. The retained run later reported zero MB free disk space;
the original IO errno was not retained, so its cause remains unproved.
[Runner preparation and failure diagnostics](docs/plans/editor-runner-storage-2026-11-07.md)
are now independently qualified at the exact source below, with all checks and
recordings preserved. Native wire
issuance, current-stop authority and whole-history qualification remain open;
these fixtures do not establish another VM capture.

The [same-call source closeout](docs/plans/run0-same-call-source-2026-11-08.md)
records the reviewed successor host source and fixture controls through the fixed
wrapper gate. The public runtime guard remains `INCOMPLETE`; admission and the
actual execution plan are under review. The reviewed static verifier recipe
measures 12,512,296 bytes on real Bigman inputs. Explicit replan 005 reduces the
synthetic three-epoch reservation to 12,084,358 bytes without changing limits or
read/wire checks. Their sum omits integrated costs and proves no new VM capture.
Complete fixed-candidate Linux CI, source-execution and whole-history qualification
remain open.

Changed-candidate run42370785508 subsequently failed the existing agent-backend
success test when Docker creation was not confirmed before its deadline. The
backend correctly returned IO/reconciliation-required. Its environmental cause
is unknown; a cold-daemon explanation is unsupported because real Linux
container controls had just passed. Bounded CI-only failure observations now
preserve all original deadlines, success assertions, freshness checks and cleanup.

[PR76](https://github.com/whole-machine-works/RamenOS/pull/76) has complete,
independently accepted hosted qualification at
`dbbb8e0b3ebe9df58d80ce539b1af96cefe844fe` from
[run 42372873439](https://github.com/whole-machine-works/RamenOS/actions/runs/42372873439),
attempt 1. All nine checks passed, including the complete canonical and
preservation inventories. The agent lane succeeded, so its failure-only journal
and event queries were skipped; no live query history or cause is established.
Both failed runs and all sixteen prior ZIPs remain unchanged. PR76 is open and
ready for separate A3 review, not merged; main remains `2688f245`.
The [qualification record](docs/plans/editor-runner-storage-2026-11-07.md) binds
this result to the tested code, not a new execution on this prose successor.
Full same-VM capture and live I1 remain open. Boot preparation continues through
static verification, integrated accounting and source-execution qualification.
The pending recovery-benefit criterion choice holds further live I1, update and
performance experiments;
it does not block this independent boot preparation.

The IPC diagnostic reproduced two zero-byte timeouts before a later valid
reply on the same VM. The separate single-client run succeeded immediately.
The retained CPU snapshots follow successful replies, so the cause of the
earlier timeouts remains open.
The same-call C1/C2 capture, complete retained-range collection, final firmware
exit map, allocator installation and target application execution remain pending.
Native USB/HID input and device-backed storage also remain pending. Independent
software preparation proceeds without SW0 model trials or physical H0–H3.

### Foundation review successor — merged and hosted-qualified

The October 14 review's seven behavior defects were repaired in PR #38, merged
as `f3fa057`: one live broker grant generation per domain, retained failed-revoke
and rollback owners, actual-frame physical-span checks for the test-protocol
net/block providers, whole-event trace reads and actual per-domain cursors,
empty ring no-ops, and fail-closed explicit runner configuration with node/domain
separation. The README, security status and index now reflect the accepted editor
reliability batch. New assertions include rejection followed by a successful
operation, retained revocation retry, and unrelated-domain/frame progress.

The additive `just foundry-review-boundaries` stage passes fifteen new nonempty
assertions on macOS, including typed grant/trace consumers. Strict Clippy and
kernel/API/broker/supervisor/trace-client suites pass. Fresh original18/Reader93,
regression13, volatile13, Store7, Preview codec7, Save codec8, NativeRead9,
NativePreview5 and adapter4 controls pass. Both bare-metal targets build, and S8
integration, S11/S12/S13, boot admission, broker bridge, execution fabric, IDL lint
and org-governance pass in their named host/QEMU scopes. CI tooling passes on an
unchanged-source serial rerun; the initial concurrent run's two timing-sensitive
boot-observer fixture failures are retained without deadline or assertion changes.
Both reviewed-head hosted runs passed all nine jobs; PR qualification retained
68 passing stage/preparation records. Earlier agent-lane Docker create/attach
timeouts remain retained; retries changed no source, assertions or deadlines.
The [post-merge main run](https://github.com/maxwellsantoro/RamenOS/actions/runs/38591283628)
passed all nine jobs and 68 stage/preparation records on its first attempt.
The separate strict Linux56 `just preflight` result below belongs to the preceding
source snapshot; that wrapper was not repeated for PR #38. General target broker enforcement, arbitrary
fragmented scatter/gather transfer, authenticated target trace transport, editor-child execution,
physical durability and release readiness remain separate.

### Follow-up review — bootstrap and authority repairs

The follow-up replaces unchecked largest-region allocation with a
single held 16 MiB firmware `LOADER_DATA` allocation. Complete supported map
conversion preserves reserved/loader descriptors and keeps active boot-services
and runtime pages unavailable. Numeric admission rejects malformed, incomplete,
unbacked and oversized claims before one-shot installation; denial preserves
live allocations. Failed map capture frees the exact pool or retains it and
halts if release is uncertain. AArch64 labels its bounded synthetic pool as a
QEMU fixture. This is separate from the pending RUN0 firmware-exit, retained-range
collection and physical-access adapter.

Default boot crates no longer enable Oracle protocols implicitly. Every ordinary
IPC envelope, including opt-in net/block fixtures, validates its IPC capability.
Both trace dispatch entrypoints bind creation to that capability's domain before
allocating or resetting state. The comprehensive successor below adds caller-bound read/info/destroy checks;
generic IPC handles still lack protocol-specific rights.

The following preparation record predates complete P0 release and the implemented
process successor above. P0 preparation had nine genuine in-process controls, including Read/reopen,
constructor and Save-chain panic, actual initialization failures and retained
reopen failure/recovery. Four separate parent-owner policy controls cover
quarantine, release, an immutable child cleanup deadline and a deliberately
faulty consuming reopen callback; these do not observe a native child or a
Store-internal panic. Four authored consumers target the frozen process API.
At that source the process APIs were absent: its actual compiler RED established
preparation, not runtime acceptance or completion of the thirty assertion families. Consuming join
must return promptly without unwinding and return the sole child on uncertainty.
The preparation gate serializes recorder access and runs separately in hosted
editor CI, retaining its setup, strict Clippy, compiler and source snapshots.
Opaque Store failures are now staged before assertions/unwind. Reopen retains
its real fence and original operation through a trusted fixture journal repair,
then proves a new Save and durable reopen. Initialization has no public close
proof, so its failure controls intentionally quarantine two parent groups; two
reopen Drop/policy controls also retain their unproved owners. The original
two-second quiescence deadline bounds fence acquisition, not synchronous reopen
IO or a full retry lifetime. Private native negative controls and process-mode
shared app Save ownership were still required before P1/P2 handlers at that source;
the reviewed P0/private handoff subsequently closed those authoring dependencies.
Source and validation scope are tracked in the follow-up
review resolution. Those local results remain source-bound; hosted qualification
must identify its matching revision.

### Comprehensive review successor — bounded enforcement repairs

The D/C, A/F, B and G successors implement the contracts in
[the repair plan](docs/plans/comprehensive-review-repairs-2026-10-14.md).
Strict ordinary host Store ingestion now accepts externally signed manifests,
checks their exact staged bytes and metadata, and enforces the same signature
policy at the common publisher. Recovered older intents precede exact deduplication.
Denied descriptor replies retire the connection; the next explicit operation
reconnects without mutation replay. IPC, Shmem and Trace generations remain
representable on the existing wire and permanently retire slots at exhaustion.

Both kernel dispatchers take an independent kernel-private caller context and
validate IPC and payload ownership against it. Legacy Shmem mapping is self-only;
a versioned IDL offer/accept contract requires recipient consent. Both real MMUs
reject existing leaves and huge/block ancestors and reserve all table frames
before publishing PTEs. Rejection preserves existing mappings and permits retry.
Native trace v3 writes initialized whole events into caller-owned writable Shmem;
an explicit Commit advances the cursor. Completed receipts reconcile their
original outcome after destination retirement. Legacy nonzero metadata-only
reads deny without consuming events.

Ordinary strict host Store operations require an exact durable live grant in
addition to token signature, rights and expiry. Externally signed management
commands grant or permanently revoke IDs. An operation holds its live-authority
lease through consumption; staged ingestion revalidates at publication. A held
root lock excludes a second Store authority owner, and uncertain persistence
disables operations until a verified restart. Strict startup requires explicit
capability-authority keys and valid durable state; development mode remains an
explicit alternative. Artifact publishers do not acquire a Store signing key.

PR #40 merged these controls as `b09e919f66aef3acff0ee2e0d240dece3264e954`.
The [reviewed-head PR run](https://github.com/maxwellsantoro/RamenOS/actions/runs/38660024555)
and [matching push run](https://github.com/maxwellsantoro/RamenOS/actions/runs/38660020341)
passed all nine jobs with 68 verified stage/preparation records each. The push
agent lane needed two unchanged-source retries after enforced LT validation
timeouts; both failures confirmed cleanup and remain retained. Assertions and
production budgets were unchanged. The
[post-merge main run](https://github.com/maxwellsantoro/RamenOS/actions/runs/38662942304)
passed all nine jobs and 68 verified records on its first attempt. Its tree exactly
matches reviewed head `89f1ae3`. These five hosted lanes execute the canonical
56-stage inventory plus preparation; the separate strict Linux preflight wrapper
was not repeated for this batch.

Fresh local integration includes 85 required selected boundary assertion
executions, both-architecture real MMU/Shmem/trace fixtures and affected Store and
editor consumers. Local macOS tooling and short-window boot-observer
fixture failures remain retained; this is not a local all-green claim. Linux
quality passed the complete tooling suite. The
[repair plan](docs/plans/comprehensive-review-repairs-2026-10-14.md#qualification)
records regression and retained-failure scope. Earlier PR #39 qualification
belongs to `23f37445` and is historical evidence.

The caller context still originates only in trusted boot/test fixtures; no
untrusted syscall or authenticated process carrier supplies it. MMU mutation
requires continuous exclusive hierarchy access and does not establish SMP safety
or active userspace translation. `trace_client` still defaults to MockTransport
and has no v3 kernel carrier. The host Store registry does not implement the
Domain Manager's target backend. GetBlob still returns a host path; acknowledged
revocation cannot retract delivered bytes or bypass same-UID filesystem access.
The default POSIX path remains trusted host development with best-effort rlimits.
At that recorded source the real editor child, full P0, RUN0, target storage and
physical graduation were unfinished. The process successor above supplies the
Linux host implementation; the target and physical joins remain separate.

### Updated-review successor — accepted foundation repairs

The updated-review P1/P2/P3 foundation packets are accepted through PR #42.
The user selected these follow-ups before further editor-process
implementation. These packet labels are separate from the process P1/P2/P3
sequence. [The acceptance record](docs/plans/updated-review-repairs-2026-10-14.md)
owns the six bounded findings, assertions and qualification evidence.

Explicit field codecs initialize padding and reject unsupported raw-copy decodes;
domain names truncate only at UTF-8 boundaries and provide checked decoding.
Trace capacity v4 reports the actual 64-event/1536-byte retention independently
of its 24..1536-byte whole-event delivery limit. Legacy v1 size metadata remains
deprecated compatibility behavior. Shmem outcome v3 retains original offer and
acceptance results through unmap, close and slot reuse without remapping. Its
64 receipt slots reclaim only after joint terminal acknowledgement; canonical
close validation preserves pending consent after malformed IDs.

Ordinary host Store uses per-ID operation leases: revoke closes admission and
joins every admitted operation for that ID while unrelated authority management
can progress during held read IO. Actual FIFO-backed service consumers cover
that ordering and health failure after admission. Publication holds authority
health exclusion through durable commit. Offline revoke-all epoch rotation uses
fresh exclusive keys, at most 1024 IDs per epoch, retirement history of at most 64 keys
and an exact external checkpoint pin. See the
[operator contract](docs/STORE_AUTHORITY_EPOCH_V1.md); this is not hardware-backed
rollback protection or online grant preservation.

Assembled kernel/API/Store suites, strict Clippy, the extended boundary gate and
all affected editor consumers pass locally, including original task18/Reader93
and reliability13. Both x86_64/AArch64 S8 target runs pass all prior and new
assertions after a bounded in-place reset removed an oversized AArch64 boot-stack
temporary. S11/S12/S13 and org-governance pass locally.

PR #42's reviewed runtime head `49ea1d4` and merged main `b41c43a` have the same
tree. Its [push run](https://github.com/maxwellsantoro/RamenOS/actions/runs/38674300567),
[PR run](https://github.com/maxwellsantoro/RamenOS/actions/runs/38674334354) and
[post-merge run](https://github.com/maxwellsantoro/RamenOS/actions/runs/38675734768)
each passed all nine jobs and all 68 canonical records on the first attempt.
PR #40/41 remain evidence for preceding source. An additional local tooling run
exposed two fixture-readiness races; test-only repairs pass the complete suite of
149 Python and seven Rust controls. PR #43 carries those test-only repairs;
PR #44 adds bounded timeout evidence and an explicit test recovery scenario;
PR #45 covers aggregate broker timeouts as well. Their separate qualification and retained failure history are tracked in the plan.
Production budgets, containment and public error redaction remain unchanged.
At that recorded source, the authenticated process/trace carrier, full process P0 and real editor child,
RUN0, target grants/storage, SMP page-table synchronization and physical graduation
were unfinished. The Linux editor successor above does not establish the remaining
target/trace joins. Host paths/bytes and same-UID filesystem access are not revoked;
epoch safety depends on external operator pins and exclusive key provisioning.

## Foundry development and CI execution

[The execution profile](docs/FOUNDRY_CI_OPTIMIZATION_V0.md) provides a locked warm
`just dev-check`, content-stable codegen, one canonical 56-stage local inventory
and five isolated CI lanes (quality, host, agent, QEMU and editor). Required Foundry/merge aggregates reject failed,
cancelled, missing or unexpectedly skipped results. Compiler reuse never restores
acceptance results; assertions, source checks and evidence execution remain fresh.
Historical 52/54-stage results apply only to their recorded source snapshots.

PR #34 merged as `d3a95551` after both reviewed-head runs passed all eight jobs.
The [post-merge main run](https://github.com/maxwellsantoro/RamenOS/actions/runs/37730644587)
also passed all eight on October 8. Its host job took 820 seconds, agent 337,
quality 309 and QEMU 292; creation-to-final-update was 845 seconds. These are one
run's job durations, including setup/artifact work, not a before/after speedup.
Host is the measured bottleneck for that run.

CI0 evidence-admission repairs are independently reviewed and validated. Executable
contracts/fixtures and gate-consumed Markdown require Foundry, including deletion;
ordinary prose and governed org packets keep their inexpensive path. NativeRead
and NativePreview retain their old inventories and add conservative transitive
crate/include coverage (351/353 inputs), with pinned helper admission and rejection
of unsupported explicit Cargo target layouts. At CI0 acceptance, the collector,
canonical 55/39 stages, runtime assertions,
real deadlines and cache policies were unchanged. The initial reliability successor added
one host stage (56 full/40 extended), preserving every existing stage and order.
At that acceptance, reviewed registries added three regression sources: task220, NativeRead354
and NativePreview356; the reliability gate closes over 224 paths.

At CI0 acceptance, the Linux candidate passed the CI tooling gate (including seven
Rust codegen controls), policy regressions and actual nine-case NativeRead/five-case
NativePreview gates with strict checks and feature exclusions. Its source remained
unchanged during execution. Gate-first failures and independent review findings
are retained. The affected gates passed; the complete Linux preflight and a new
hosted run were not repeated for this patch. Required S11/S12/S13, appliance docs
mode and org-governance checks pass locally. Final status/queue wording is a
subsequent documentation-only delta outside the two runtime gate closures.

The dev `sha2` optimization and `native_runner` debug stripping have focused
measurements in the execution profile and historical snapshot. Neither establishes
stable whole-CI latency. No model-comparison, metal or release claim follows from
hosted green checks.

The 2026-10-13 streamlining successor adds focused `dev-test`, `dev-compile`
and `dev-lint` modes with shared package/feature compilation state and admitted
1..32 Cargo jobs (default two). Store's WAT parser is agent-feature-only. Task and
reliability acceptance now reuse exact source/configuration compiler targets while
all case lists, assertions, Clippy, recordings and readers execute freshly. The
paired local Cargo measurements were reliability 100.105→1.217 seconds and
Task 88.605→1.451 seconds; original Task runtime still took 83.895/88.444 seconds.
These are fixed-source local preparation measurements with uncontrolled host load,
not hosted or end-to-end performance claims.

The same final source passes thirteen reliability assertions on macOS/Linux;
macOS cold/warm Task runs pass the original eighteen cases and complete Reader93.
All affected editor consumers pass freshly. Selected NativeRunner/Semantic/Projection
gates pass with actual artifact metadata, exact nonempty test unions and eligible
library doctests. Binary-only packages record an explicit no-doctest decision.
Fresh firmware variables and held-parent QEMU cleanup preserve the 30-second
budgets; S11/S12/S13 each booted on their first launch in 2.2–2.5 seconds. Tooling 130
Python/seven Rust controls, formatting and source-registry admission pass. Registry
successors retain all old paths: Task223, reliability227, Read356 and Preview358.

The editor lane moves eleven existing stages onto its own runner; canonical 56/40
coverage, commands, relative order and overrides are preserved, and Foundry now
requires all five lanes. Cross-source CI restores compiler candidates only; inner
exact admission remains required. A measured 1.065-second duplicate NativeRunner
invocation does not justify a cross-gate result broker, so standalone assertions
remain fresh. Explicit cache inspection/retirement denies uncertain ownership.
Five superseded completed entries created during this task were retired,
representing 3,016,239,361 logical bytes, while evidence inventories and retained
binary hashes remained intact. Temporary Linux preparation was removed after
retaining its evidence. [The streamlining resolution](docs/plans/build-streamlining-2026-10-13.md)
records measurements, preserved failures, review and scope. Complete Linux56 passes on the recorded pre-review runtime candidate. The pinned
proof image is installed locally and verified on the native Linux host. Fresh
five-lane hosted qualification passes on the reviewed head. Earlier source-bound PASS reports
remain historical evidence.

The full strict `just preflight` completed all 56 canonical stages on native
Linux `bigman`, with builtin Docker seccomp, the exact pinned image, verified S2
kernel, two Cargo jobs and serialized tests. All stage exits/reaps and the frozen
source/lock checks pass; original18/Reader93, all editor consumers, regression13,
agent evaluator/reconciliation and required QEMU paths execute freshly. The
795-file candidate fingerprint is
`f2fb768a3309a922be4fad73588f2782636d6736a6b7d79156953dc21caa1f04`.
The initial output-permission failure is retained; only qualification-environment
permissions/setup required correction. No product-code change or assertion
waiver was needed. [The qualification](docs/plans/linux56-qualification-2026-10-13.md)
records the complete evidence and separates the subsequent documentation-only
update from the tested runtime snapshot. Fresh five-lane hosted execution passes;
provider/model, process, target and physical scopes remain unchanged.

PR [#36](https://github.com/maxwellsantoro/RamenOS/pull/36) merged on October 14
as `a9e2394314c040c3c5aa692bfdc7b9363a28b57e` after independent exact-head review,
separate bot-author/human-approver identities and required checks. The
[PR run](https://github.com/maxwellsantoro/RamenOS/actions/runs/38511257813)
passed all nine jobs; all 68 isolated-runner preparation/lane records match the
canonical five-lane plans, with exit 0, actual reap and no uncertain cleanup.
The [push run](https://github.com/maxwellsantoro/RamenOS/actions/runs/38511253161)
also passed after a manual failed-job rerun on the unchanged reviewed head. Its
first LT validator attachment timeout and successful cleanup remain retained;
no code, assertion or deadline changed. Editor was the longest PR job at 652
seconds including setup, artifact and cache work; this is one run, not a measured
speedup. Post-merge main execution is a separate workflow, and these results do
not widen the scripted host/Docker/QEMU claim.

## Implemented foundations and their boundaries

| Area | Landed behavior | Evidence and limits |
|------|-----------------|---------------------|
| Kernel / S0–S8 | x86_64 and aarch64 boot, typed IPC, capabilities, shared-memory mappings, tracing and SPSC ring foundations | Selected target/QEMU paths; fixed-size tables. Capability-table use after SMP transition is deliberately blocked; general SMP/IRQ support remains incomplete |
| Boot admission / RUN0.0 prerequisite | Allocation-free full-map validation, seven retention reasons, sticky map-overflow denial and bounded deterministic pool selection | `just foundry-boot-frame-pool-run0-0` · [Contract](docs/BOOT_FRAME_OWNERSHIP_V0.md); 17 pure cases, kernel consumer tests/builds and existing S8 integration pass. No actual firmware-exit/collector/allocator or target-runtime proof |
| Typed interfaces | IDL/codegen, protocol/message IDs, bounded wire contracts | Native contracts are defined in `idl/`; generated syntax alone grants no authority |
| Desktop / UI1.0 | Host permission preview, single-use synthetic confirmation, exact self-observation grants, real pinned child, expiry/revocation/fault/restart and independent watchdog | `just foundry-desktop-host-launch-ui1-0` · [Contract](docs/DESKTOP_SESSION_V1.md); default-off trusted Unix fixture, 17 cases and retained process/wire evidence. No editor, compositor, Store, target or process-containment proof |
| Editor / UI1.1a | Logical keyboard editing, focus and preview approval, offscreen composition, volatile save/receipt and explicit recovery | `just foundry-desktop-editor-host-ui1-1a` · [Contract](docs/DESKTOP_EDITOR_HOST_API_V0.md); default-off trusted in-process fixture, 13 cases and source-bound wire/pixel/receipt evidence on macOS/Linux. Real Store IO, actual editor process, device input and target execution remain separate |
| Editor Store / UI1.1b | Private host CAS, atomic selection/receipt journal, irreversible admission and original-operation recovery through joined-owner reopen | `just foundry-desktop-editor-store-ui1-1b` · [API](docs/DESKTOP_EDITOR_STORE_API_V0.md) · [Recording contract](docs/contracts/editor-store-recording-v0.json); seven behavior and sixteen evidence cases pass on macOS/Linux, with captured bytes decoded by the native Rust codec. Integrated authority is exercised by UI1.1c; actual editor PID, device/target durability and containment remain separate |
| Native Save data / UI1.1c prerequisite | Versioned Save grants and original Commit outcomes, canonical references and complete supplied Binding/receipt correlation | `just foundry-editor-native-save-codec-ui1-1c` · [Contract](docs/contracts/editor-native-save-codec-v0.json); eight pure host cases on macOS/Linux, strict std Clippy and no_std checks and 53-stage strict Linux preflight. Data-only gate; live mutation and the full task are exercised separately by UI1.1c |
| Native Read / UI1.1c prerequisite | Approved editor peer, fresh Store Read, original request deadline, live copy authority and shared owned-producer roster | `just foundry-desktop-editor-native-read-ui1-1c-prerequisite` · [API](docs/DESKTOP_EDITOR_NATIVE_READ_API_V0.md); nine host cases on macOS/Linux, strict Clippy and feature exclusion. Read-only gate; UI1.1c separately exercises Save/task. Optional-export transcript validation, editor PID and device/target execution remain separate |
| Native preview Read / UI1.1c precursor | Actual Store-current pin, one-use input approval, same-row activation/delivery, protected Read-only frames, live Store reads and retained-owner accounting | `just foundry-editor-native-preview-read-ui1-1c` · [Contract](docs/contracts/editor-native-preview-read-v0.json); five default-off trusted host cases on macOS/Linux, identical source/lock inputs, strict Clippy and feature exclusion. Finite source-bound log assertions; no universal exported transcript, editor PID, target/device or containment proof; UI1.1c separately exercises Save/task |
| Native Save/task / UI1.1c | Focused keyboard editing, protected frames, actual Store Save/reopen and original-only failure recovery | `just foundry-desktop-editor-task-ui1-1c` · [Contract](docs/contracts/editor-native-save-task-v0.json); eighteen original host assertions and complete 93-scenario recordings pass on macOS/Linux with strict checks, exact affected consumers and historical full54 and successor full55 Linux preflights. Trusted in-process, default-off scope; editor child, target persistence, device and containment remain separate |
| Native runner / S10 | Host Wasmtime execution, manifests, granted-handle injection and guest deadlines | Host runtime; no complete target userspace loader or Wasmtime environment |
| Semantic State / S10 | Host snapshots, subscriptions/reactor, capability-filtered views; selected QEMU snapshot/IPC paths | Multi-source aggregation and target reactor remain incomplete; default boot/time metadata includes fixtures |
| Store / S1–S10 | Host CAS, signatures, durable ownership, path/tag queries, read-only projections and typed CoW commits | Full user launch/porting flow and target persistence remain incomplete |
| Execution fabric / S10 | Placement, lease, duplicate-observer, launch-plan and trace contracts | Synthetic nodes/load and simulated routing; no distributed transport |
| Driver Foundry / S11 | virtio-net Reference Vault, Linux Oracle capture, replay and typed harness transfers | Embedded Oracle packet vectors in QEMU; device-backed native send/receive unproven |
| Golden machine / S12 | Machine contract, GOP probe, HIL boot/IOMMU gate scaffolds and appliance tooling | First live appliance capture, AMT actuation and physical graduation pending |
| Storage / S13 | Block IDL, virtio-blk Oracle capture/replay and typed harness transfers; NVMe/atomic-update probes | Embedded sector vectors and QEMU scaffolds; native device read/write/flush and physical two-boot rollback remain unproven |
| Compatibility / S2–S9 | Separate Linux capsule VM, host POSIX and GPU quarantine paths with gates | Boundaries differ per runner; default POSIX profile is rlimits-only, not general containment |
| RamenOrg / G0 | Governance schemas, packets, renderers, validators, bounded trials and drift gate | A2-local only; no autonomous merge/release/hardware/public-support authority |

[PLATFORM_OVERVIEW.md](PLATFORM_OVERVIEW.md) explains responsibilities;
[SLICES.md](SLICES.md) defines slice scope. [SECURITY_STATUS.md](SECURITY_STATUS.md)
and [RISKS.md](RISKS.md) record residual risks.

## SW0: runnable evidence, not a completed experiment

The useful task repairs one configuration, runs a pinned WASM validator, commits
an immutable artifact, and denies named unauthorized operations. RT means RamenOS
typed, LT Linux typed, and LS Linux scoped shell. These gates use scripted
consumers and trusted host fixtures, not model trials or target-native task clients.

| Step | Implemented scope | Gate / contract |
|------|-------------------|-----------------|
| A0 | Pure transaction model and deterministic synthetic fixtures; no IO enforcement | `just foundry-agent-task-contract-a0` · [Contract](docs/AGENT_TASK_CONTRACT_V0.md) |
| A1.0 | Generated protocol-14 layouts and allocation-free request preflight | `just foundry-agent-task-protocol-a1-0` · [Protocol](docs/AGENT_TASK_PROTOCOL_V1.md) |
| A1.1 | Useful RT host service task, immutable staging, supervised validator, durable receipts, denials and replay | `just foundry-agent-task-proof-rt` · [Service proof](docs/AGENT_TASK_SERVICE_PROOF_V1.md) |
| A2.1 | Linux scripted repair, inspected Docker containment, pinned worker and named OS probes | `just foundry-agent-task-linux-control` · [Linux control](docs/AGENT_TASK_LINUX_CONTROL_V1.md) |
| A2.2 | Shared strict JSON codec/descriptions and opt-in RT IPC adapter | `just foundry-agent-task-adapter` · [Adapter](docs/AGENT_TASK_ADAPTER_V1.md) |
| A2.3 | Independent LT broker, grants, sealed validation, durable transactions and named RT/LT cases | `just foundry-agent-task-lt` · [LT backend](docs/AGENT_TASK_LT_BACKEND_V1.md) |
| A2.4 | Contained LS commands/launcher, shared Linux transactions, peer checks and original-receipt recovery | `just foundry-agent-task-ls-transactions` · [LS transactions](docs/AGENT_TASK_LS_TRANSACTIONS_V1.md) |
| A2.5 | Shared v2 pull/poll/cancel subscriptions and typed lifecycle comparison | `just foundry-agent-task-subscriptions` · [Subscriptions](docs/AGENT_TASK_SUBSCRIPTIONS_V2.md) |
| A2.6 | Finite canonical inventory, 33 common cases and separate LS OS probes; unknown authority retained | `just foundry-agent-task-authority` · [Authority](docs/AGENT_TASK_AUTHORITY_V1.md) |
| A2.7 | Synthetic bank/release contract, bounded sessions, 45 development attempts and retained failures | `just foundry-agent-task-evaluator-controls` · [Evaluator controls](docs/AGENT_TASK_EVALUATOR_CONTROLS_V1.md) |
| A2.8 | Named acknowledged-ID cleanup, unresolved-create quarantine and explicit interrupted-commit receipt recovery | `just foundry-agent-task-reconciliation` · [Reconciliation](docs/AGENT_TASK_RECONCILIATION_V1.md) |
| A2.9 | 31 issued-right subsets under two policies, single-right effects and named lifetime witnesses | `just foundry-agent-task-requestable-authority` · [Requestable authority](docs/AGENT_TASK_REQUESTABLE_AUTHORITY_V1.md) |

A2.6's frozen suite has zero successful forbidden probes, but does not prove whole
`E_max`, continuous `E(t)`, or narrower authority. A2.9 establishes equality only
for the declared-interface issued-right projection. LS mounted files, retained
observations/descriptors and raw broker access remain broader observations;
typed host clients and transitive deputy authority remain incompletely bounded.
A finite host-file witness now records nine named observations across RT/LT/LS
before expiry, after expiry and after revocation. The trusted Python evaluator/host
consumer in RT/LT reads an unrelated owner-only canary; the contained LS Python
consumer is denied access to that exact unmounted path. Actual PID/UID/GID and
namespace identities identify these actors, separately from adapters or model
interfaces. Read/grant/revocation witnesses bind the same resource, capability
and generation; malformed attribution is rejected. Both authority gates passed
in an isolated Linux/Docker checkout, with 33 common cases per arm and
31 right subsets under two policies per arm. This does not complete whole-authority
inclusion, continuous lifetime coverage or full A2.
Unacknowledged Docker create intents cannot certify cleanup from an empty inventory.

Portable SW-E accounting now freezes bank/release/context/provider/rate identities
and a finite three-arm schedule. Strict reports retain failed, unknown,
over-budget and pending attempts; integer uncached-token estimates cannot certify
the declared ceiling with missing usage. `just foundry-agent-task-provider-accounting`
checks ten unit assertions and a deterministic synthetic consumer. It makes no
provider calls and supplies no billing, attestation or funding authority. Combined
`foundry-agent-task-evaluator-controls` and `foundry-agent-task-reconciliation`
passed in an isolated Linux/Docker checkout with the pinned toolchain/image:
45 retained scripted repair attempts and six interrupted-commit cases, plus
late-create and abrupt-publication recovery assertions. Reports are retained
under `out/roadmap-linux/`; these checks do not complete full A2.

Full A2, real hidden-bank/study releases, actual provider supervision/usage capture, model
comparison, production registration and target task enforcement remain pending.
The [Agent Task Proof plan](docs/plans/2026-09-16-agent-task-proof.md) defines their
acceptance and the three separate contrasts. No comparative agent advantage is claimed.

## Recent boundary fixes

The StoreClient transport follow-up applies socket timeouts on initial and
replacement connections and one absolute deadline across response-frame reads.
Retained clients reconnect when peer closure is observable before dispatch;
transport failures discard the stream for the next explicit operation. Uncertain
requests, including ingestion, are never silently replayed. Real-server idle
expiry and fake-server lost/malformed/truncated reply and withheld/trickled
response regressions cover both ordinary reads and descriptor ingestion. This
is host transport evidence; connect and individual writes are not covered by
the response-frame deadline.

The 2026-10-04 follow-up defines `validation_current` as observation freshness in
RT/LT, independently of commit eligibility. RT direct/poll regressions cover failed
outcomes, truncation, expiry and revocation; portable LT predicate checks pass.
Expanded paired Linux cases run in the required Linux/Docker gates; local macOS
checks establish RT execution and portable LT predicates.
Ordinary Store preparation now has configurable byte/concurrency/deadline bounds,
runs outside the global registry/projection locks, and cancels on disconnect.
A two-client stalled-worker test checks unrelated reads and cleanup; publication
revalidates authority and preserves owner-bound intents. Durable publication IO
still uses the locks; total CAS quota and crash-orphan staging cleanup remain work.
These changes add host evidence, not a model comparison or target/hardware claim.

The 2026-10-03 review changes are implemented and recorded in `CHANGELOG.md`:

- Store reads bind the requested content ID to authenticated metadata and blob bytes;
  native execution hashes the byte snapshot it consumes.
- Host ingestion uses caller-opened regular-file descriptors; pathname-only requests
  fail closed. Native ingestion retains its IDL shared-memory source contract.
- Owner/manifest publication intents precede CAS visibility; restart/retry recovers
  partial publication and unrelated orphans remain denied.
- Native Unix/chardev IPC shares the invocation's absolute deadline through connect
  and partial transfers; uncertain dispatch is not automatically replayed.
- LT duplicate staging preserves capability/validation and counts unique candidates,
  matching RT; portable and executable regressions cover capacity.
- CI and preflight use the same complete implemented SW0 sequence. This does not
  turn that sequence into full A2 conformance or a completed model study.

Earlier memory, tracing, WASM, projection and durability fixes remain in the
changelog and their contract/gate documents. They establish host/QEMU behavior,
not complete SMP, client isolation, physical durability or production assurance.

## Physical inventory and graduation boundary

The x86_64 COM1 console uses 115200 8N1, matching the HIL appliance contract
and capture tools. The S12 GOP gate checks the emulated UART's programmed
parameters in a QEMU trace; first live Pi/ThinkCentre validation remains pending.

The pinned reference is the Lenovo ThinkCentre M900 SFF, machine type 10FH,
Core i7-6700, 8 GiB RAM, with a 240 GB SanDisk SATA SSD. The Raspberry Pi 4
(4 GiB), FTDI USB-to-RS-232 adapter and null-modem chain are physically installed.
Firmware/AMT preflight and the first live serial capture remain pending; a compatible
M.2 2280 PCIe NVMe drive is still required for S13 graduation.

`PASS/QEMU` is not metal evidence. `PASS/HIL-LOG`, `PASS/HIL-LIVE`,
`PASS/HIL-APPLIANCE`, and `PASS/METAL` have separate provenance requirements in
[EVIDENCE_LEVELS.md](EVIDENCE_LEVELS.md). Standalone `operator-golden-machine`
and `appliance-mediated` metal claims must be stamped separately.

S13.8 currently probes A/B metadata. Graduation still requires an implemented
publication/readback/selection verifier, a new-slot boot and a separate rollback
boot with fresh nonces and matching artifact identities. Firmware NVMe detection
and vector-backed block transfers establish neither native NVMe I/O nor that protocol.

## Documentation maintenance

The current roadmap uses a short ready frontier, dependency joins and one
coordinator with disjoint workers and reserved review/validation capacity. The
[workflow](docs/AGENTIC_WORKFLOW.md) owns dispatch mechanics; project skills route
to it rather than copying the queue. Pinned contracts and immutable trial evidence
retain their original paths and bytes. Historical plans do not authorize work.

## Validation entry points

Resolve recipes in [justfile](justfile). Use focused `just dev-check` while editing,
affected consumer gates before handoff and the canonical lanes on a fixed
integration candidate. Roadmap/org/research changes require `just s11`, `just s12`,
`just s13` and `just foundry-org-governance-g0`; appliance docs also require
`just hil-appliance`. Full `just preflight` needs Linux, Python `jsonschema`,
Docker/seccomp and the installed pinned image. macOS host/QEMU results do not
certify the full Linux profile. Physical gates remain separately opt-in.
