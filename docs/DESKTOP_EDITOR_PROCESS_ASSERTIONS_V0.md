# Editor-process private assertion handoff v0

2026-11-04. Independently reviewed and **frozen for P0 assertion authoring**;
handlers still await complete P0 review. The production [API](DESKTOP_EDITOR_PROCESS_API_V0.md)
and [process contract](contracts/editor-process-v0.json) remain frozen. Complete
P0 assertion review releases P1/P2 authoring; actual runtime GREEN follows their
implementation. Missing-API RED is separate from behavior RED and qualification.

## Observable milestone and ownership

The acceptance outcome is a genuine approved Linux editor child that edits and
rasters its own draft, publishes verified immutable mappings, and uses the
parent's genuine Store Save/original-outcome recovery. Denial and child death
must preserve the right original owners; another session and a subsequent Save
must work. Original18/Reader93 and affected consumers remain required. No model,
physical actuation or compiler adoption is a prerequisite.

The critical path is reviewed private handoff → complete thirty-family P0
assertions and original missing-API RED → concurrent P1 carrier/P2 child → their
combined Linux acceptance → P3 common SaveChains/process integration → independent
review, fixed-source validation, branch/PR delivery and authorized integration.
An intermediate packet or PR does not complete this milestone.

Root owns this handoff, shared features/IDL/generated files, mod.rs/host.rs/native.rs
bridges, source registries, gates, status, commits and PRs. Assertion author owns
`apps/artifact_editor/tests/process_task.rs`, `tests/process_support/`,
`services/desktop/src/editor_dev/process_editor/assertions.rs` and
`apps/artifact_editor/src/native/process_assertions.rs`. P1 will own
`services/desktop/src/editor_dev/process_editor.rs` and its `linux.rs` child.
P2 will own `apps/artifact_editor/src/bin/editor-process.rs`. A non-author reviews
each packet. Authors never reset peer edits or change shared branches/commits.

## Three assertion layers

1. Public process consumers use only genuine approval/Read/enrollment, the frozen
   opaque process API and existing app/Store ownership. They cannot submit body,
   image, receipt, PID, FD or caller-supplied publication witnesses.
2. Desktop-private assertions inspect the actual carrier/process/offer/charge
   owner. Desktop never depends on Store or App. Unit-only decoder assertions may
   use cfg(test); integration fault controls need the separate default-off
   `host_editor_process_assertions_v0_dev` feature because a dependency is not
   compiled with its consumer's cfg(test).
3. App-private assertions retain the genuine common SaveChains owner. They use
   existing Store pauses/faults and the frozen Desktop API. They never reproduce
   Save in a test surrogate or move Store IO into Desktop/schema.

## Finite fixture API

Only the supplemental assertion feature exports these diagnostic controls.
Production/default features exclude them. Their implementations are not claimed
by this declaration. All owner and evidence fields remain private and non-Clone.

```rust
pub struct ProcessAssertionRun { /* original enrollment-bound plan/record owner */ }
pub struct ProcessAssertionCheckpoint { /* descriptive copy, no authority */ }
pub struct ProcessAssertionEvidence { /* descriptive native records/ledgers */ }
pub struct ProcessAssertionFinishFailure { /* Status and sole retained run */ }
pub struct ProcessAssertionScenario { /* closed catalog case/subcase only */ }
pub enum ProcessAssertionPoint {
    BeforeSnapshotCopy, HeldVerifiedBeforeExec, ForkOwnedBeforeExecRelease,
    BootstrapBeforeSend, InputReceivedBeforeAck, OfferMappedBeforeSeal,
    PairValidatedBeforeAdopt, CaptureBeforeAdopt, SupervisorBeforeSignal,
    SupervisorBeforeWait, SupervisorTerminalBeforeJoin,
}
impl ProcessAssertionScenario {
    // Only IDs/subcases in the reviewed catalog are admitted. The static case
    // table fully expands grouped controls before complete P0 acceptance.
    // No arbitrary mutation, bytes, paths, identities, counters or errno input.
    pub fn for_case(case: &'static str) -> Result<&'static [Self], Status>;
    pub fn id(&self) -> &'static str;
}
impl FixtureController {
    pub fn arm_process_assertion(
        &self, enrollment: &ProcessEditorEnrollment,
        scenario: &ProcessAssertionScenario,
    ) -> Result<ProcessAssertionRun, Status>;
    pub fn arm_process_pair_assertion(
        &self, enrollment: &ProcessEditorEnrollment, sibling: &OwnedEditorChild,
        scenario: &ProcessAssertionScenario,
    ) -> Result<ProcessAssertionRun, Status>;
    pub fn join_process_assertion_quarantine(
        &self, run: &mut ProcessAssertionRun,
    ) -> Result<OwnedEditorChildExitProof, ProcessStepFailure>;
}
impl ProcessAssertionRun {
    pub fn wait_checkpoint(
        &self, point: ProcessAssertionPoint, timeout_ms: u32,
    ) -> Result<ProcessAssertionCheckpoint, Status>;
    pub fn release(&mut self, point: ProcessAssertionPoint) -> Result<(), Status>;
    pub fn finish_recording(
        self,
    ) -> Result<ProcessAssertionEvidence, ProcessAssertionFinishFailure>;
}
impl ProcessAssertionFinishFailure {
    pub fn into_parts(self) -> (Status, ProcessAssertionRun);
}
```

`ProcessAssertionCheckpoint` has read-only getters `point()`, `reached_at()`
and `sequence()`; they return the declared enum, actual Instant and checked u64.
An armed scenario selects its exact barrier occurrence from the closed plan;
release is one-use for that reached occurrence, not a reusable semaphore.

The evidence getters are `scenario_id() -> &'static str`,
`before()/after() -> &ProcessAssertionSnapshot`,
`syscalls() -> &[ProcessAssertionSyscall]`,
`descriptors() -> &[ProcessAssertionDescriptor]`,
`objects() -> &[ProcessAssertionObject]`,
`controls() -> &[ProcessAssertionControl]`,
`checkpoints() -> &[ProcessAssertionCheckpoint]`,
`native_wait_outcome() -> Option<ProcessWaitOutcome>`,
`supervisor_joined() -> bool` and `quarantined() -> bool`.
`executable() -> Option<&ProcessAssertionExecutable>` supplies a descriptive
identity/action record: `registered_sha256`, `held_sha256`,
`source_before_sha256`, `source_after_sha256` ([u8;32]);
`source_before_device`, `source_before_inode`, `source_after_device`,
`source_after_inode`, `held_device`, `held_inode` (u64);
`executed_device`, `executed_inode` (Option<u64>) and
`executed_sha256: Option<[u8;32]>` from the actual owned child's /proc/exe;
`held_mode`, `held_seals` (u32), `checkpoint_sequence` (u64), and
`action: Option<ProcessAssertionExecutableAction>` (ReplacePath,
MutateOriginalInode, HeldWrite, HeldGrow, HeldShrink). Source mutation must
actually change recorded bytes/inode while held/executed identity stays bound
to registration; a no-op action is not an identity witness.
`source_header: Vec<u8>` retains the actual first at most64 source bytes to
distinguish script/invalid ELF refusals without retaining a whole executable Vec.
The following returned record fields are public descriptive data, never accepted
back by an authority/adoption API:

- Snapshot: `document: Option<NativeEditorObservation>`, complete
  `app_pixels: Vec<u8>` and `composed_pixels: Vec<u8>`,
  `app_sha256: [u8;32]` and `composed_sha256: [u8;32]`,
  `focus_epoch`, `service_epoch`, `channel_generation`,
  `publication_generation`, `delivered_sequence`, `acknowledged_sequence` (u64),
  `request_sequence: u64`, `pending_offer_id: Option<u64>`,
  `syscall_count`, `control_count`, `descriptor_count` (u64 immutable evidence
  prefix lengths at that decision boundary),
  `owners: ProcessAssertionOwners`, `adoption_status: Option<Status>`,
  `admitted_at` and `child_deadline`
  (Option<Instant>), `captured_at` and `save_deadline` (Option<Instant>).
- Owners: `data`, `fixed`, `combined`, `maps`, `children`, `supervisors`,
  `pending_inputs`, `ordinary_queue`, `reset_queue` (u32), `lifetime_objects`
  and `lifetime_bytes` (u64), `lifetime_offers: u32`.
  These count actual Desktop process owners only.
  Existing genuine Store ledgers are captured independently by the app owner.
- Syscall: `operation: ProcessAssertionOperation`,
  `origin: ProcessAssertionOrigin` (Native/InjectedBeforeSyscall/ParserStructural),
  `result: i64`, `errno: Option<i32>`,
  `sender: Option<(u32,u32,u32)>` for kernel PID/UID/GID, `msg_flags: u32`,
  `received_fds: u32`, `descriptor_id: Option<u64>`, `poll_revents: u32`,
  `ancillary: Vec<u8>` (at most256 bytes) and
  `ancillary_descriptor_ids: Vec<u64>`. Ancillary headers/credential bytes are
  actual attempted/received bytes; SCM_RIGHTS FD integer slots are zeroed in
  this explicitly labelled public projection and mapped in order to ledger IDs.
  Full private raw ancillary audit remains owner-private until aliases close.
  For FD-producing syscalls,
  public `result` is zero for success or minus one for failure and is explicitly
  normalized; the actual numeric FD stays owner-private. Count/PID/status returns
  remain actual native values. Mmap pointer returns are also normalized to zero
  on success/minus one on failure; addresses stay owner-private. The operation enum names Open, MemfdCreate, Fstat, Pread,
  Pwrite, Read, Write, Poll, Truncate, GetSeals, AddSeals, Mmap, Munmap, Fork, PidfdOpen, Execveat,
  Sendmsg, Recvmsg, Signal, Waitpid, Close, SupervisorStart and ParseAncillary.
  SupervisorStart labels actual Rust thread start; injected failure uses an
  additional InjectedBeforeOperation origin with no native fork inferred.
  ParseAncillary is
  only a separately labelled owner-private structural parser control, never a
  native receive/close or actual credential record.
- Descriptor: `role: ProcessAssertionDescriptorRole` (Selected/TextState/Surface/Executable/Control/Barrier/
  Pidfd/ExecError/Stdout/Stderr), `descriptor_id`, `device`, `inode`, `byte_len` (u64),
  `owner_process_id: Option<u32>`, `offer_id: Option<u64>`,
  `event: ProcessAssertionDescriptorEvent` (Offered/Returned/Other),
  `mode: u32`, `seals: u32`, `mapping: ProcessAssertionMapping` (None/SharedWritable/ReadOnly/Unmapped),
  `disposition: ProcessAssertionDisposition`
  (Held/Received/Closed/Quarantined). Descriptor IDs are monotonic ledger keys,
  never OS FD numbers. Actual FD numbers remain owner-private and enter the
  post-cleanup raw audit only after closure; they are not exported while held.
  Kernel-discarded aliases have no fabricated FD/Close row.
- Object: `descriptor_id: u64`, `bytes: Vec<u8>`, `sha256: [u8;32]` captures the
  actual attempted selected/text/state/surface or Stdout/Stderr bytes for independent rejection
  predicates. It grants no authority and is never accepted back. Bound a raw
  object capture to FRAME_BYTES+1 and existing scenario/raw-reference caps;
  executable copying remains streamed and is never captured as a 1GiB Vec.
- Control: `direction: ProcessAssertionDirection` (ParentToChild/ChildToParent), `bytes: Vec<u8>`,
  `sender: Option<(u32,u32,u32)>`, `msg_flags: u32`, `received_fds: u32`,
  `sequence: u64` is the consecutive recording row ordinal, distinct from the
  protocol/input sequence encoded in raw bytes. Record each actual wire record
  exactly once, not once at send plus again at receive. Preserve raw data and
  contract caps before append;
  do not sample or truncate a recording and call it complete.

Assertions must compare these observations to independently derived expected
values, public exit proofs and actual raw syscall records. A generic implementation
"case passed" flag is not evidence. Store effects, actual permits/receipts and
producer joins come from existing app-owned recording; the new process recording
has its own run nonce/source/artifact manifest and explicit joined references to
that same run's genuine parent IO records. Reader93 is never relabelled process
evidence. Ancillary normalization/kernel rejection and private parser injection
are separate origins; record actual native behavior when duplicate/unknown CMSG
layouts cannot be delivered unchanged by the kernel.

Before/after snapshots are immutable decision-boundary observations: immediately
before the attempted enforcing action and immediately after its terminal status,
before ordinary cleanup. Later syscall/descriptor/wait/join records describe
actual cleanup separately, so retirement does not erase cap/owner retention
evidence. Post-held source replacement and rejected held-ELF mutation are positive
identity witnesses: the genuine pinned child must still execute afterward.

The [closed case catalog](contracts/editor-process-assertion-handoff-v0.json)
binds every frozen finite control to a stable case ID. Grouped alternatives must
expand into separate actual subcases with exact expected evidence; one successful
group label cannot stand in for unexecuted variants. Gate-only build/graph controls
run in the gate, app/Store controls run in their actual owners, and unsupported
cross-owner arming is Invalid before effects. There is no catch-all mutation.

The controller must match the enrollment's actual Host/document/approval. Arm
is one-use per enrollment; stale/cross-owner/rearm deny without consuming it.
Pair arming additionally requires a distinct currently owned sibling child from
the same Host and its genuine accepted immutable pair. It binds that actual
opaque owner internally; no caller ID/FD/body substitutes it. A sibling which is
not yet ready returns NotReady without consuming enrollment. The runtime checks
the original sibling binding again before any cross-child fault action.
Waiting is bounded to 1..=5000ms and does not change an original child or Save
Instant. Release rejects unreached, wrong or already released checkpoints.
Every checkpoint records actual reach; no no-op hook may pass. Barriers release
enforcing locks before waiting and recheck current authority/deadlines afterward.
Recording finish returns sole ownership on incomplete cleanup; evidence exposes
only descriptive copies. EOF, Drop, a diagnostic PID or joined recording thread
never releases process/Store charges.

The quarantine join is only for the closed actual-Drop scenarios and the
controller's matching Host/enrollment. Production Drop parks the same genuine
inner record, unique supervisor JoinHandle and all charges, requesting retirement
through that supervisor. Reserve parking capacity before spawn; parking failure
must truthfully retain/leak unknown owners rather than claim closure. The fixture
method temporarily takes the unique parked record outside registry locks, uses
the ordinary nonblocking internal join and restores ownership on every failure
or unwind. It preserves the first cleanup Instant and cannot directly signal or
wait. Only the genuine native wait plus actual finished supervisor join yields
the opaque exit proof. Run remains a diagnostic binding, never a PID/FD capability
or a substitute Store producer/fence proof. Production gains no new public API.

Fault actions normally execute automatically at their designated actual point;
recording a checkpoint does not itself block. `wait_checkpoint` exposes only
reached currently armed blocking occurrences; evidence retains all automatic
observations. Explicit rendezvous are post-held path/inode mutation, late/roundtrip
capture, D28 named delays, and D19 pending newer ordinary publication after its
first capture (never bootstrap). The closed plan selects occurrence. Primary
data/fixed/map/queue/lifetime counters are per-child; children/supervisors are
Host-wide (max two). Sibling data does not inflate the primary 12/16/28 budget.
D24NoRegistryLockAcrossSignalWait also blocks SupervisorBeforeSignal and
SupervisorBeforeWait for actual independent B progress at each point.
D29DropIsNotReap blocks SupervisorBeforeSignal, keeping the child live for the
outer controller's identity/pidfd audit before killing its owned parent.

All diagnostic enums derive Debug, Clone, Copy, PartialEq and Eq; records derive
Debug and PartialEq where their contained types support it. `for_case` admits
the grouped catalog DxxCnn and positive DxxP keys and returns exactly the reviewed
expanded order. Scenario `id()` and evidence `scenario_id()` must match the
independent expanded catalog. Unknown keys are Invalid. `adoption_status` is the
actual most recent enforcing decoder/adoption status, never a synthetic success
for a silent stall; no attempt means None.

Default status decisions, where the frozen contract is not more specific:
malformed canonical wire/shape/seals/ELF is Invalid, unauthorized sender/digest/
offered identity is Denied, stale sequence/epoch is Stale, bounded quota overflow
is Exhausted, original deadline expiry is Timeout, nonterminal poll/join is
NotReady and actual child transport death is Disconnected. Unsupported required
Linux primitives report Unsupported and qualify as INCOMPLETE, without fallback.
Injected native signal/wait failures retain owners and report Internal with
explicit injected provenance; their later genuine cleanup has separate records.
Store/receipt failures retain existing StoreStatus/NativeEditorError semantics.

## Artifact, child and syscall agreement

Root first builds the production child with only
`host_editor_process_child_v0_dev`. Its active graph excludes Desktop/Store/App
parent code. Root records artifact/build graph/hash and injects a compile-time
registration into the parent build, using
`RAMEN_EDITOR_PROCESS_ARTIFACT_PATH` and `RAMEN_EDITOR_PROCESS_ARTIFACT_SHA256`.
These are Root build inputs; the public consumer never provides a path/hash/FD.
No registration means closed denial. Actual source open/copy/ELF/hash/seal and
held-FD execveat remain required; compile-time registration is not exec proof.

Fault child behaviors use a separately registered, hashed build with an explicit
`host_editor_process_child_assertions_v0_dev` feature whose graph adds only
child-local assertion controls. Its fixed prepared argv selects one closed case;
environment remains empty. Normal proof scenarios must select the independently
built production artifact. The assertion variant must never silently substitute
for the production child. Every record identifies which artifact actually ran.

Held-source mutation uses an owned, registration-bound fixture copy and real
preexec barrier. It cannot mutate unrelated Cargo outputs or accept a caller path.
Actual wrong-PID helpers have distinct authentic cleanup owners; they cannot
become a second waiter for the editor child. The fixture rendezvous reuses the
prepared preexec barrier descriptor where possible. Any additional fixture-only
descriptor has an explicit remap/close/charge ledger and cannot be hidden inside
the normal fixed16/data12/combined28 footprint claim.

Native errno and deliberate injected failure are separate record origins.

Root's fixed child remap is control FD3, exec-error write FD4 with CLOEXEC,
preexec barrier read FD5, held executable FD6 with CLOEXEC, stdin0 from the
prepared null source and stdout1/stderr2 from supervised pipes. Prepared argv0
is `editor-process`, then `--control-fd 3 --parent-pid PID --parent-uid UID
--parent-gid GID`, all rendered before fork. Child authenticates actual kernel
credentials against these parent observations; payload PID/actor grants nothing.
Normal preexec closes FD5 before exec. The separately registered assertion child
adds `--assertion-case ID --barrier-fd 5`, retaining the same charged barrier
read end. Fixed bounded fixture notifications use its already allocated stdout
pipe, explicitly separate from portal controls/authority. Normal binary rejects
assertion argv; no descriptor is hidden in the footprint.

Start the sole supervisor thread before it forks. Stage unique launch inputs
across thread-start failure, so Unspawned returns actual enrollment/executable
rather than dropping a moved closure's inputs. Only that supervisor owns the
fork-derived wait right. After-fork pidfd/birth/setup failure closes the unreleased
preexec barrier so the prepared child exits; supervisor alone obtains its wait.
Uncertainty retains actual supervised owners/charges, never an invented Unspawned
or parent-side second waiter. Child post-fork code remains only fixed prepared
async-safe remap/close/read/error-write/execveat/_exit operations.
Signal/wait injections occur before the real syscall and retain the unresolved
actual process owner. No injection may fabricate native wait success. A later
real supervisor wait plus actual supervisor join is required to release charges.

## Genuine common Save owner and process wrapper

P3 extracts existing fields and methods once into app-private `SaveChains`:
Desktop, Store, paired launch, request counter, pending SaveChain vector and
registration failure. Existing intent/source/Flight/OriginalNativeSave/binding,
allocation continuation and original deadlines stay in that same owner. Legacy
and process wrappers submit genuine NativeSaveIntent to the same start/progress/
observe_original/validate_receipt logic. There is no alternate process Save path.
Private wrapper field names are `chains: SaveChains` and
`child: Option<OwnedEditorChild>`. SaveChains retains the existing field names
`desktop`, `store`, `launch`, `next_request`, `pending`, `registration_failure`;
SaveChain/Flight field names remain those in the accepted native.rs source.
Private `SaveChains::accept_reply(&mut self, chain: &mut SaveChain, flight: Flight,
reply: store::NativeSaveReply, now: u64) -> Result<bool, NativeEditorError>` is
extracted once from the existing progress function after its actual poll. Both
ordinary progress and private tests consume the same genuine owners through this
method. Tests may retain the actual reply/lease for strict validation counterexamples
then return it through this method; they cannot fabricate a reply or duplicate Save.

`SaveChains::progress_all(&mut self, now: u64) -> Result<(), NativeEditorError>`
extracts exactly the existing ordinary-step pending progress loop, retaining each
chain on error. It does not add automatic original lookup/recovery or continuation.
The explicit reconciliation path remains separate with its original observation
rules. Legacy and process steps delegate after input processing. Private tests
may split actual wrapper chains and
child fields, drive these genuine chains while the child pump is paused, then
resume the same child; no second Save implementation or settlement wait is added.

Freeze these app orchestration entry points for assertion authoring:

```rust
pub struct ProcessArtifactEditor { /* SaveChains and Option<OwnedEditorChild> */ }
pub struct ProcessEditorOpenFailure { /* error and every consumed parent/child owner */ }
pub enum ProcessOpenCleanup { Complete, Pending, Quarantined }
impl ProcessEditorOpenFailure {
    pub fn into_parts(self) -> (NativeEditorError, ProcessArtifactEditor);
}
impl ProcessArtifactEditor {
    pub fn open(
        desktop: desktop::HostDesktop, store: store::StoreHost,
        launch: store::PairedNativeSaveLaunch, budget: desktop::ChildBudget,
        now: u64,
    ) -> Result<Self, ProcessEditorOpenFailure>;
    pub fn step(&mut self, now: u64) -> Result<desktop::ProcessEditorStep, NativeEditorError>;
    pub fn observe(&self, now: u64) -> Result<desktop::NativeEditorObservation, NativeEditorError>;
    pub fn reconcile_originals(&mut self, now: u64) -> Result<(), NativeEditorError>;
    pub fn retire(&mut self, reason: desktop::ProcessRetireReason, now: u64)
        -> Result<(), NativeEditorError>;
    pub fn join_child(&mut self)
        -> Result<desktop::OwnedEditorChildExitProof, NativeEditorError>;
    pub fn cleanup_failed_open(&mut self, now: u64)
        -> Result<ProcessOpenCleanup, NativeEditorError>;
    // Assertion-feature-only read of actual retained pending/startup groups.
    pub fn assertion_pending_originals(&self) -> u32;
}
```

App-private tests use one supplemental constructor on that same implementation:

```rust
// Private to native.rs and its child assertion module, assertion feature only.
impl ProcessArtifactEditor {
fn open_assertion(
    desktop: desktop::HostDesktop, store: store::StoreHost,
    launch: store::PairedNativeSaveLaunch, budget: desktop::ChildBudget, now: u64,
    controller: &desktop::FixtureController,
    scenario: &desktop::ProcessAssertionScenario,
    run_sender: std::sync::mpsc::SyncSender<desktop::ProcessAssertionRun>,
) -> Result<ProcessArtifactEditor, ProcessEditorOpenFailure>;
}
```

This is the ordinary open pipeline with one internal arm immediately after genuine
prepare and before executable registration/spawn. It sends the diagnostic Run to
the test's one-shot channel using nonblocking `try_send` before any rendezvous
can block. A scoped owner thread
can then execute open/step while the independent Run controls the reached barrier;
there is no caller closure or arbitrary raw setter. Closed/dropped diagnostic
channel, including full/zero-capacity without a waiting receiver, returns the
staged failure owner and retains the unsent Run in it. The app-private
`take_assertion_run(&mut self) -> Option<ProcessAssertionRun>` retrieves that
unsent owner; there is no hidden blocking send. No duplicate
Read/Save implementation is permitted. Normal public open uses no scenario.

The wrapper retains the child on every unsuccessful join and retains SaveChains
after a successful child reap. Stage that wrapper and its SaveChains before the
first Read/registration. A failed-open state retains all startup entry/registered
call/reply/editor/enrollment/executable/child owners that actually exist, including
genuine registration failure groups. `into_parts` returns that sole wrapper;
failed-open `step` denies ordinary effects, and `observe` returns NotReady without
an actual still-owned child. Cleanup reports Complete only with genuine known
unspawned/closed or joined proofs; Pending/Quarantined retains every unknown owner.
Drop cannot silently turn failed cleanup into root deletion/charge release.
A child fault is recorded/retired before
processing pending parent originals and never suppresses their continued progress.
After consuming child reap, `observe` returns NotReady; original reconciliation
continues, and a fresh authorized reopen supplies a current document observation.
No legacy NativeEditor alias or fresh authority is reconstructed from diagnostics.
The first retire/failed-open cleanup captures a single retained cleanup Instant;
join/cleanup retries cannot renew it or the child/Save deadline.
No automatic respawn or guessed confirmed base follows Unknown.

### Completed original versus an already pending newer publication

Original Store settlement never waits for the editor child. If it advances the
confirmed base while an ordinary newer-draft pair is already pending with the
old base, terminally reject that pair as nonretiring Stale without adoption.
Preserve the previous accepted output, child-local draft, original owners and
deadlines. Send the authenticated own-capture ReceiptNotice, then issue a fresh
pair/request for unchanged latest acknowledged draft/view generations under
the same child deadline. Spend the stale pair's actual lifetime credit; no
refund, new Commit, capture replay, parent raster or deadline reset occurs.
Repeated CtrlS while the earlier Save remains pending is still denied; this is
an ordinary publication retry. Parent orders a prior notice before the next
ordinary delivery/request and before any later SAVE_CAPTURE, while preserving
input-first dequeue and its original deadline. The first notice binds its
authenticated positive operation ID to the pending capture/channel/input/text
tuple; the child cannot match an operation ID never previously sent to it.

## Actual parent-death assertion

An outer fixture installs Linux subreaper ownership before creating the real
parent. It holds authentic parent/child birth and pidfd observations through an
explicit private test channel. It may wait for the originally owned parent and
only legally adopted child after actual parent death. An adopted native child
wait is not the dead parent's ProcessSupervisor Rust join or Store producer join.
If a genuine supported Store reopen/closure proof is unavailable, retain the
original durable root and unresolved accounting as INCOMPLETE/quarantine. Never
infer noncommit or invent an in-memory SaveChains survival after SIGKILL. Borrower
panic and actual OS parent death are distinct assertions and receipts.

## Review and continuation

Before handlers, review all thirty named executable entries, expanded finite
cases, authorized post-denial witnesses, expected missing-API RED and the explicit
private handoff. Then assign disjoint carrier and child authors. Root integrates
shared bridges/generated outputs and registers exact source/artifact inventories.
Use isolated snapshots and unique outputs for validation while the next eligible
packet is authored. The retained Linux environment audit is the setup baseline;
audit any changed prerequisites before another expensive complete run.

Independent reviewer accepted this handoff for P0 authoring after checking the
thirty-family catalog, ownership return, actual sibling binding, artifact split,
private FD/address boundary, retained deadlines and diagnostic semantics. Root
accepted the reviewed decisions. This acceptance closes the missing internal
handoff; it does not substitute for substantive assertion review or runtime GREEN.

### Save denial and owner closure observations

An ordinary flags-zero Publish without genuine CtrlS may adopt its ordinary
frame. D18OrdinaryPublishSaveClaim must prove capture/deadline remain absent,
Save intent extraction is NotReady, no Store mutation occurs, and protected
chrome does not claim Saved. Publish has no Save flag. An unsolicited child
RequestPublication is an actual parent-only type8 message in the wrong direction
and is Invalid; replay of an actual old capture Publish is Stale. A fault plan
must reach its real attempted operation before retiring the child.

`assertion_pending_originals()` counts the actual common Save chains plus retained
registration-failure and unknown startup groups. An assertion guard may release
the app and Store root only after this count is zero, actual producer closure is
proved, and any child has genuine joined/unspawned proof. Child reap alone cannot
release unresolved parent groups. Otherwise retain the entire owner in quarantine.
D23UnknownCannotChooseOldOrNewBase attempts fresh restart for the same selected
object while its genuine original outcome is UNKNOWN: neither guessed base can
create a child or replay Commit. Reconciliation retains the same original ID and
deadline, then a fresh genuine approval/reopen/Save proves continued usability.

### Known allocation closure bridge

P3 adds the read-only `NativeOriginalReply::allocation_closed() -> bool` to the
existing genuine Store original observation. True means native allocation
**authority closed**, after actual disk allocation/readback; it is not a persisted
noncommit receipt or NoAllocation. Set it only on successful ObserveAllocation
reply type10 for the original Allocate type3, matching the exact retained
allocation, at/after its original native deadline, with `closed`, no Commit
dispatch, JoinedReturned and all installed original producers actually joined.
The successful type9 lookup must have performed disk readback and
`close_late_allocation`: no binding, permit, receipt, successor or runtime dispatch,
then native Gate deadline closure and actual operation closure. Bare `closed`
from timeout/rejection/fence is insufficient. Common SaveChains must also consume
and join that lookup's own producers before retiring an uncommitted original;
otherwise retain it. This adds no mutation/retry or post-Commit recovery rule.
