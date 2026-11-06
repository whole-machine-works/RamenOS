//! Linux-only process carrier. Native authority remains in the genuine parent
//! document and Save owners; copied protocol fields never grant authority.
mod ancillary;
mod diagnostics;
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
mod fixtures;
mod linux;
mod protocol;
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
mod recording;

use super::native_authority::NativeAuthority;
use super::{HostDesktop, NativeEditor, NativeEditorObservation, NativeSaveIntent};
use crate::dev::Status;
use desktop_editor_core::{process_data::TextState, wire::ProcessMessage};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, Weak};
use std::time::Instant;

#[cfg(feature = "host_editor_process_assertions_v0_dev")]
pub use diagnostics::*;
#[cfg(not(feature = "host_editor_process_assertions_v0_dev"))]
use diagnostics::*;

pub(super) struct ProcessSeed {
    pub(super) view: NativeEditorObservation,
    pub(super) object_id: u64,
    pub(super) object_generation: u64,
    pub(super) selected: Vec<u8>,
    pub(super) expires_at_ms: u64,
    pub(super) focus_epoch: u64,
    pub(super) service_epoch: u64,
}
pub(super) struct DeliveredProcessInput {
    pub(super) sequence: u64,
    pub(super) queue_generation: u64,
    pub(super) focus_epoch: u64,
    pub(super) service_epoch: u64,
    pub(super) usage: u32,
    pub(super) phase: u32,
    pub(super) modifiers: u32,
    pub(super) entered: Instant,
    pub(super) capture: Option<ProcessSaveCapture>,
}
pub(super) struct ProcessSaveCapture {
    pub(super) authority: super::native_save::ProcessCaptureAuthority,
    pub(super) entered: Instant,
    pub(super) deadline: Instant,
    pub(super) input_sequence: u64,
}
pub(super) struct VerifiedProcessPublication {
    pub(super) state: TextState,
    pub(super) body: Vec<u8>,
    pub(super) pixels: Vec<u8>,
    pub(super) input_sequence: u64,
    pub(super) publication_sequence: u64,
    pub(super) child_deadline: Instant,
}
pub(super) struct ProcessReceiptNotice {
    pub(super) operation_id: u64,
    pub(super) committed_revision: u64,
    pub(super) capture_input_sequence: u64,
    pub(super) capture_text_generation: u64,
    pub(super) outcome: u32,
    pub(super) phase: u32,
}

#[cfg(feature = "host_editor_process_assertions_v0_dev")]
pub(super) struct ProcessCoreSnapshot {
    pub(super) document: Option<NativeEditorObservation>,
    pub(super) app_pixels: Arc<Vec<u8>>,
    pub(super) composed_pixels: Arc<Vec<u8>>,
    pub(super) focus_epoch: u64,
    pub(super) service_epoch: u64,
    pub(super) ordinary_queue: u32,
    pub(super) reset_queue: u32,
    pub(super) owner_confirm_request: Option<[u8; 88]>,
    pub(super) owner_confirm_status: Option<Status>,
    pub(super) frame_surface_id: Option<u64>,
    pub(super) frame_surface_generation: Option<u64>,
    pub(super) frame_surface_epoch: Option<u64>,
    pub(super) frame_surface_live: Option<bool>,
}

/// One roster per genuine NativeAuthority. Slots include quarantined owners;
/// dropping the public wrapper cannot release a slot or create another waiter.
pub(super) struct ProcessRoster {
    next_channel: u64,
    parent_case: Option<&'static str>,
    prepared: bool,
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    helper_slots: u32,
    descriptor_ids: Arc<std::sync::atomic::AtomicU32>,
    live: BTreeMap<u64, Weak<ProcessRecord>>,
    parked: Vec<OwnedEditorChild>,
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    retired_bootstraps: std::collections::VecDeque<RetiredBootstrapEvidence>,
}
impl ProcessRoster {
    pub(super) fn new() -> Self {
        Self {
            next_channel: 0,
            parent_case: None,
            prepared: false,
            #[cfg(feature = "host_editor_process_assertions_v0_dev")]
            helper_slots: 0,
            descriptor_ids: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            live: BTreeMap::new(),
            parked: Vec::with_capacity(2),
            #[cfg(feature = "host_editor_process_assertions_v0_dev")]
            retired_bootstraps: std::collections::VecDeque::with_capacity(2),
        }
    }
}

pub struct ProcessEditorEnrollment {
    editor: NativeEditor,
    seed: ProcessSeed,
    roster: Arc<Mutex<ProcessRoster>>,
    trace: diagnostics::Trace,
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    fixture: Mutex<fixtures::Plan>,
    channel_admission: Mutex<Option<u64>>,
}
pub struct PinnedProcessExecutable {
    executable: Option<linux::Executable>,
    authority: Arc<NativeAuthority>,
    document: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessWaitOutcome {
    Exited(i32),
    Signaled(i32),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessRetireReason {
    HumanClose,
    Revoked,
    Expired,
    ChildFault,
    InvalidTransport,
    Deadline,
}
pub struct ChildBudget {
    milliseconds: u32,
}
impl ChildBudget {
    pub fn checked(milliseconds: u32) -> Result<Self, Status> {
        if (1..=5000).contains(&milliseconds) {
            Ok(Self { milliseconds })
        } else {
            Err(Status::Invalid)
        }
    }
}
pub struct ProcessPrepareFailure {
    status: Status,
    editor: NativeEditor,
}
impl ProcessPrepareFailure {
    pub fn into_parts(self) -> (Status, NativeEditor) {
        (self.status, self.editor)
    }
}
#[allow(
    clippy::large_enum_variant,
    reason = "The frozen consuming API returns the sole actual owner inline on every launch failure."
)]
pub enum ProcessLaunchRecovery {
    Unspawned {
        enrollment: ProcessEditorEnrollment,
        executable: PinnedProcessExecutable,
    },
    Spawned(OwnedEditorChild),
}
pub struct ProcessLaunchFailure {
    status: Status,
    recovery: ProcessLaunchRecovery,
}
impl ProcessLaunchFailure {
    pub fn into_parts(self) -> (Status, ProcessLaunchRecovery) {
        (self.status, self.recovery)
    }
}
pub struct ProcessJoinFailure {
    status: Status,
    child: OwnedEditorChild,
}
impl ProcessJoinFailure {
    pub fn into_parts(self) -> (Status, OwnedEditorChild) {
        (self.status, self.child)
    }
}
#[derive(Debug)]
pub struct ProcessStepFailure {
    status: Status,
}
impl ProcessStepFailure {
    pub fn status(&self) -> Status {
        self.status
    }
}
impl From<Status> for ProcessStepFailure {
    fn from(status: Status) -> Self {
        Self { status }
    }
}
pub struct ProcessEditorStep {
    consumed: Option<u64>,
    publication: bool,
    intent: bool,
    exited: bool,
}
impl ProcessEditorStep {
    pub fn consumed_sequence(&self) -> Option<u64> {
        self.consumed
    }
    pub fn publication_accepted(&self) -> bool {
        self.publication
    }
    pub fn save_intent_available(&self) -> bool {
        self.intent
    }
    pub fn child_exit_observed(&self) -> bool {
        self.exited
    }
}
pub struct ProcessChildObservation {
    pid: u32,
    birth: u64,
    executable: [u8; 32],
    acknowledged: u64,
    publication: u64,
}
impl ProcessChildObservation {
    pub fn process_id(&self) -> u32 {
        self.pid
    }
    pub fn birth_ticks(&self) -> u64 {
        self.birth
    }
    pub fn executable_sha256(&self) -> [u8; 32] {
        self.executable
    }
    pub fn acknowledged_sequence(&self) -> u64 {
        self.acknowledged
    }
    pub fn publication_generation(&self) -> u64 {
        self.publication
    }
}
pub struct OwnedEditorChildExitProof {
    pid: u32,
    birth: u64,
    executable: [u8; 32],
    outcome: ProcessWaitOutcome,
}
impl OwnedEditorChildExitProof {
    pub fn process_id(&self) -> u32 {
        self.pid
    }
    pub fn birth_ticks(&self) -> u64 {
        self.birth
    }
    pub fn executable_sha256(&self) -> [u8; 32] {
        self.executable
    }
    pub fn wait_outcome(&self) -> ProcessWaitOutcome {
        self.outcome
    }
    pub fn supervisor_joined(&self) -> bool {
        true
    }
}

struct ProcessRecord {
    authority: Arc<NativeAuthority>,
    channel: u64,
    binding: Mutex<ProcessBinding>,
    trace: diagnostics::Trace,
    observed: Mutex<CarrierObserved>,
}
struct ProcessBinding {
    generation: u64,
    retirement: Option<BindingRetirement>,
}
enum BindingRetirement {
    Denied,
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    EpochStale,
}
impl ProcessRecord {
    fn active_generation(&self) -> Result<u64, Status> {
        let binding = self.binding.lock().map_err(|_| Status::Internal)?;
        match binding.retirement {
            Some(BindingRetirement::Denied) => Err(Status::Denied),
            #[cfg(feature = "host_editor_process_assertions_v0_dev")]
            Some(BindingRetirement::EpochStale) => Err(Status::Stale),
            None => Ok(binding.generation),
        }
    }
    fn retire_binding(&self) -> Result<(), Status> {
        self.retire_binding_cause(BindingRetirement::Denied)
    }
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    fn retire_binding_for_epoch(&self) -> Result<(), Status> {
        self.retire_binding_cause(BindingRetirement::EpochStale)
    }
    fn retire_binding_cause(&self, cause: BindingRetirement) -> Result<(), Status> {
        let mut binding = self.binding.lock().map_err(|_| Status::Internal)?;
        if binding.retirement.is_some() {
            return Ok(());
        }
        binding.retirement = Some(cause);
        binding.generation = binding.generation.checked_add(1).ok_or(Status::Exhausted)?;
        Ok(())
    }
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    fn observed_generation(&self) -> u64 {
        self.binding
            .lock()
            .map(|b| b.generation)
            .unwrap_or(u64::MAX)
    }
}
#[derive(Clone, Default)]
struct CarrierObserved {
    request: u64,
    offer_cursor: u64,
    delivered: u64,
    acknowledged: u64,
    publication: u64,
    pending_offer: Option<u64>,
    pending_input: bool,
    ordinary_queue: u32,
    reset_queue: u32,
    captured: Option<Instant>,
    save_deadline: Option<Instant>,
}
pub struct OwnedEditorChild {
    inner: Option<ChildInner>,
}
struct ChildInner {
    enrollment: ProcessEditorEnrollment,
    record: Arc<ProcessRecord>,
    supervisor: linux::Supervisor,
    joined: Option<(linux::Identity, ProcessWaitOutcome)>,
    socket: Option<linux::Fd>,
    gate_peer: Option<linux::Fd>,
    selected: Option<linux::Fd>,
    selected_map: Option<linux::SelectedMap>,
    offer: Option<OfferedPair>,
    accepted: Option<AcceptedPair>,
    pending: Option<DeliveredProcessInput>,
    input_queue: std::collections::VecDeque<DeliveredProcessInput>,
    reset_queue: Option<DeliveredProcessInput>,
    pending_request: Option<u64>,
    capture: Option<ProcessSaveCapture>,
    captured_text_generation: Option<u64>,
    request: u64,
    acknowledged: u64,
    text_generation: u64,
    view_generation: u64,
    publication: u64,
    wire_publication: u64,
    deferred_ack: Option<DeferredAcknowledgment>,
    next_offer: u64,
    deadline: Instant,
    outbound: Option<OutboundFrame>,
    requested_flush: Option<bool>,
    delivered_since_flush: u32,
    downs_since_flush: u32,
    bootstrap: [u8; 88],
    ready: bool,
    retiring: bool,
    receipt: Option<(u64, u64, [u8; 32])>,
}
struct DeferredAcknowledgment {
    request_id: u64,
    publication_sequence: u64,
    input_sequence: u64,
    status: Status,
}

struct OutboundFrame {
    bytes: [u8; 88],
    kind: OutboundKind,
}
#[derive(Clone, Copy)]
enum OutboundKind {
    None,
    Bootstrap,
    Offer,
}

struct OfferedPair {
    id: u64,
    request: u64,
    text: linux::Fd,
    surface: linux::Fd,
    capture: bool,
}
struct AcceptedPair {
    _text: linux::Mapped,
    _surface: linux::Mapped,
}

impl Drop for OwnedEditorChild {
    fn drop(&mut self) {
        let Some(inner) = self.inner.take() else {
            return;
        };
        inner
            .supervisor
            .request_retire(ProcessRetireReason::ChildFault);
        let roster = inner.enrollment.roster.clone();
        match roster.lock() {
            Ok(mut roster) if roster.parked.len() < 2 => {
                roster.parked.push(OwnedEditorChild { inner: Some(inner) })
            }
            _ => {
                std::mem::forget(inner);
                eprintln!("INCOMPLETE: genuine process owner retained; parking unavailable");
            }
        };
    }
}

fn inner<'a>(host: &HostDesktop, child: &'a OwnedEditorChild) -> Result<&'a ChildInner, Status> {
    let inner = child.inner.as_ref().ok_or(Status::Stale)?;
    if !Arc::ptr_eq(&host.process_authority()?, &inner.record.authority) {
        return Err(Status::Denied);
    }
    Ok(inner)
}
fn inner_mut<'a>(
    host: &HostDesktop,
    child: &'a mut OwnedEditorChild,
) -> Result<&'a mut ChildInner, Status> {
    let inner = child.inner.as_mut().ok_or(Status::Stale)?;
    if !Arc::ptr_eq(&host.process_authority()?, &inner.record.authority) {
        return Err(Status::Denied);
    }
    Ok(inner)
}
fn enforce_deadline(inner: &ChildInner) -> Result<(), Status> {
    if Instant::now() >= inner.deadline {
        Err(Status::Timeout)
    } else {
        inner.record.active_generation().map(|_| ())
    }
}
fn validate_bootstrap_binding(
    message: &desktop_editor_core::wire::ProcessMessage,
    enrollment: &ProcessEditorEnrollment,
) -> Result<(), Status> {
    if let desktop_editor_core::wire::ProcessMessage::Bootstrap(bootstrap) = message {
        if bootstrap.document_binding_id != enrollment.seed.view.document_id {
            return Err(Status::Denied);
        }
    }
    Ok(())
}
fn observe_carrier(
    host: &HostDesktop,
    inner: &mut ChildInner,
    status: Option<Status>,
    before: bool,
) -> Result<(), Status> {
    {
        let mut state = inner.record.observed.lock().map_err(|_| Status::Internal)?;
        state.request = inner.request;
        state.offer_cursor = inner.next_offer;
        state.delivered = inner
            .pending
            .as_ref()
            .map(|p| p.sequence)
            .unwrap_or(inner.acknowledged);
        state.acknowledged = inner.acknowledged;
        state.publication = inner.publication;
        state.pending_offer = inner.offer.as_ref().map(|p| p.id);
        state.pending_input = inner.pending.is_some();
        state.ordinary_queue = inner.input_queue.len() as u32;
        state.reset_queue = u32::from(inner.reset_queue.is_some());
        let capture = inner
            .capture
            .as_ref()
            .or_else(|| inner.pending.as_ref().and_then(|p| p.capture.as_ref()));
        state.captured = capture.map(|c| c.entered);
        state.save_deadline = capture.map(|c| c.deadline);
    }
    snapshot_record(
        host,
        &inner.enrollment.editor,
        &inner.record,
        status,
        before,
    )
}
fn snapshot_record(
    host: &HostDesktop,
    editor: &NativeEditor,
    record: &Arc<ProcessRecord>,
    status: Option<Status>,
    before: bool,
) -> Result<(), Status> {
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    {
        if !record.trace.needs_snapshot(before) {
            return Ok(());
        }
        let core = host.process_core_snapshot(editor)?;
        let carrier = record
            .observed
            .lock()
            .map_err(|_| Status::Internal)?
            .clone();
        let roster = host.process_roster()?;
        let (children, supervisors) = {
            let roster = roster.lock().map_err(|_| Status::Internal)?;
            roster
                .live
                .values()
                .filter_map(Weak::upgrade)
                .map(|r| {
                    let o = r.trace.owners();
                    (o.children, o.supervisors)
                })
                .fold((0, 0), |(a, b), (c, d)| (a + c, b + d))
        };
        record.trace.snapshot(
            ProcessAssertionSnapshot {
                document: core.document,
                app_sha256: [0; 32],
                composed_sha256: [0; 32],
                app_pixels: Vec::new(),
                composed_pixels: Vec::new(),
                focus_epoch: core.focus_epoch,
                service_epoch: core.service_epoch,
                channel_generation: record.observed_generation(),
                publication_generation: carrier.publication,
                delivered_sequence: carrier.delivered,
                acknowledged_sequence: carrier.acknowledged,
                request_sequence: carrier.request,
                offer_cursor: carrier.offer_cursor,
                pending_offer_id: carrier.pending_offer,
                syscall_count: 0,
                control_count: 0,
                descriptor_count: 0,
                core_ordinary_queue: core.ordinary_queue,
                core_reset_queue: core.reset_queue,
                owner_confirm_request: core.owner_confirm_request,
                owner_confirm_status: core.owner_confirm_status,
                frame_surface_id: core.frame_surface_id,
                frame_surface_generation: core.frame_surface_generation,
                frame_surface_epoch: core.frame_surface_epoch,
                frame_surface_live: core.frame_surface_live,
                owners: ProcessAssertionOwners {
                    children,
                    supervisors,
                    pending_inputs: u32::from(carrier.pending_input),
                    ordinary_queue: carrier.ordinary_queue,
                    reset_queue: carrier.reset_queue,
                    ..Default::default()
                },
                adoption_status: status,
                admitted_at: None,
                child_deadline: None,
                captured_at: carrier.captured,
                save_deadline: carrier.save_deadline,
            },
            core.app_pixels,
            core.composed_pixels,
            before,
        )?;
    }
    #[cfg(not(feature = "host_editor_process_assertions_v0_dev"))]
    let _ = (host, editor, record, status, before);
    Ok(())
}

impl HostDesktop {
    pub fn prepare_process_editor(
        &self,
        editor: NativeEditor,
    ) -> Result<ProcessEditorEnrollment, ProcessPrepareFailure> {
        let state = (|| {
            if !Arc::ptr_eq(&self.process_authority()?, &editor.authority) {
                return Err(Status::Denied);
            }
            let roster = self.process_roster()?;
            let (ids, parent_case) = {
                let mut r = roster.lock().map_err(|_| Status::Internal)?;
                r.prepared = true;
                (r.descriptor_ids.clone(), r.parent_case)
            };

            let seed = self.process_claim(&editor)?;
            Ok((roster, seed, Trace::new(ids, parent_case)))
        })();
        match state {
            Ok((roster, seed, trace)) => Ok(ProcessEditorEnrollment {
                #[cfg(feature = "host_editor_process_assertions_v0_dev")]
                fixture: Mutex::new(fixtures::Plan::default()),
                editor,
                seed,
                roster,
                trace,
                channel_admission: Mutex::new(None),
            }),
            Err(status) => Err(ProcessPrepareFailure { status, editor }),
        }
    }
    pub fn registered_editor_process_executable(
        &self,
        enrollment: &ProcessEditorEnrollment,
    ) -> Result<PinnedProcessExecutable, Status> {
        if !Arc::ptr_eq(&self.process_authority()?, &enrollment.editor.authority) {
            return Err(Status::Denied);
        }
        self.process_validate(&enrollment.editor, 0)?;
        let diagnostic = Arc::new(ProcessRecord {
            binding: Mutex::new(ProcessBinding {
                generation: 0,
                retirement: None,
            }),
            authority: enrollment.editor.authority.clone(),
            channel: enrollment
                .channel_admission
                .lock()
                .map_err(|_| Status::Internal)?
                .unwrap_or(0),
            trace: enrollment.trace.clone(),
            observed: Mutex::new(CarrierObserved::default()),
        });
        snapshot_record(self, &enrollment.editor, &diagnostic, None, true)?;
        let assertion = enrollment
            .trace
            .scenario()
            .is_some_and(ProcessAssertionScenario::assertion_child);
        match linux::pin(&enrollment.trace, assertion) {
            Ok(executable) => {
                if enrollment.trace.scenario().is_some_and(|s| {
                    matches!(
                        s.id(),
                        "D02PostHeldPathReplacement"
                            | "D02PostHeldInodeMutation"
                            | "D02HeldWriteDenied"
                            | "D02HeldGrowDenied"
                            | "D02HeldShrinkDenied"
                    )
                }) {
                    snapshot_record(
                        self,
                        &enrollment.editor,
                        &diagnostic,
                        Some(Status::Ok),
                        false,
                    )?;
                }
                Ok(PinnedProcessExecutable {
                    executable: Some(executable),
                    authority: enrollment.editor.authority.clone(),
                    document: enrollment.seed.view.document_id,
                })
            }
            Err(status) => {
                snapshot_record(self, &enrollment.editor, &diagnostic, Some(status), false)?;
                Err(status)
            }
        }
    }
    #[allow(
        clippy::result_large_err,
        reason = "The frozen failure type must return the same inline enrollment or sole live child without an extra fallible allocation."
    )]
    pub fn spawn_process_editor(
        &self,
        enrollment: ProcessEditorEnrollment,
        mut executable: PinnedProcessExecutable,
        budget: ChildBudget,
        now_ms: u64,
    ) -> Result<OwnedEditorChild, ProcessLaunchFailure> {
        let admitted = Instant::now();
        let initial = Arc::new(ProcessRecord {
            binding: Mutex::new(ProcessBinding {
                generation: enrollment
                    .channel_admission
                    .lock()
                    .ok()
                    .and_then(|c| *c)
                    .unwrap_or(0),
                retirement: None,
            }),
            authority: enrollment.editor.authority.clone(),
            channel: enrollment
                .channel_admission
                .lock()
                .map(|c| c.unwrap_or(0))
                .unwrap_or(0),
            trace: enrollment.trace.clone(),
            observed: Mutex::new(CarrierObserved::default()),
        });
        let _ = snapshot_record(self, &enrollment.editor, &initial, None, true);
        let validation = (|| {
            if !Arc::ptr_eq(&self.process_authority()?, &enrollment.editor.authority)
                || !Arc::ptr_eq(&executable.authority, &enrollment.editor.authority)
                || executable.document != enrollment.seed.view.document_id
            {
                return Err(Status::Denied);
            }
            self.process_validate(&enrollment.editor, now_ms)?;
            let mut roster = enrollment.roster.lock().map_err(|_| Status::Internal)?;
            roster.live.retain(|_, r| r.strong_count() > 0);
            let reserved = roster.live.len();
            #[cfg(feature = "host_editor_process_assertions_v0_dev")]
            let reserved = reserved + roster.helper_slots as usize;
            if reserved >= 2 {
                return Err(Status::Exhausted);
            }
            let slot = roster
                .next_channel
                .checked_add(1)
                .ok_or(Status::Exhausted)?;
            roster.next_channel = slot;
            let mut admission = enrollment
                .channel_admission
                .lock()
                .map_err(|_| Status::Internal)?;
            let previous = admission.unwrap_or(slot - 1);
            let channel = previous.checked_add(1).ok_or(Status::Exhausted)?;
            *admission = Some(channel);
            drop(admission);
            let record = Arc::new(ProcessRecord {
                binding: Mutex::new(ProcessBinding {
                    generation: channel,
                    retirement: None,
                }),
                authority: enrollment.editor.authority.clone(),
                channel,
                trace: enrollment.trace.clone(),
                observed: Mutex::new(CarrierObserved::default()),
            });
            roster.live.insert(slot, Arc::downgrade(&record));
            let deadline = admitted
                .checked_add(std::time::Duration::from_millis(budget.milliseconds as u64))
                .ok_or(Status::Exhausted)?;
            enrollment.trace.admit(admitted, deadline)?;
            #[cfg(feature = "host_editor_process_assertions_v0_dev")]
            enrollment.trace.record_channel(channel)?;
            Ok((record, deadline))
        })();
        let (record, deadline) = match validation {
            Ok(v) => v,
            Err(status) => {
                let _ = snapshot_record(self, &enrollment.editor, &initial, Some(status), false);
                return Err(ProcessLaunchFailure {
                    status,
                    recovery: ProcessLaunchRecovery::Unspawned {
                        enrollment,
                        executable,
                    },
                });
            }
        };
        // This is a new capture after successful, checked admission. Failed
        // admission retains its genuinely unadmitted snapshot; no old header
        // is backfilled with a later Instant or deadline.
        let _ = snapshot_record(self, &enrollment.editor, &record, None, true);
        let staged = (|| {
            let (parent, child) = linux::sockets(&enrollment.trace)?;
            #[cfg(feature = "host_editor_process_assertions_v0_dev")]
            let gate_peer = if enrollment.trace.scenario().is_some_and(|s| {
                matches!(
                    s.id(),
                    "D04InheritedEndpointForeignPid"
                        | "D04CreationPeercredIsNotSender"
                        | "D04CopiedBootstrapPidActor"
                        | "D05AncillaryTruncation"
                )
            }) {
                Some(child.duplicate()?)
            } else {
                None
            };
            #[cfg(not(feature = "host_editor_process_assertions_v0_dev"))]
            let gate_peer = None;
            let selected = linux::memfd(
                "ramen-selected",
                enrollment.seed.selected.len(),
                ProcessAssertionDescriptorRole::Selected,
                &enrollment.trace,
                true,
            )?;
            selected.write_at(&enrollment.seed.selected, 0)?;
            #[cfg(feature = "host_editor_process_assertions_v0_dev")]
            let skip_seal = fixtures::selected_before_seal(self, &enrollment, &selected, now_ms)?;
            #[cfg(not(feature = "host_editor_process_assertions_v0_dev"))]
            let skip_seal = false;
            if !skip_seal {
                selected.seal()?;
            }
            linux::validate_selected(&selected, &enrollment.seed.selected)?;
            let selected_map = linux::map_selected(&selected, enrollment.seed.selected.len())?;
            Ok((parent, child, selected, selected_map, gate_peer))
        })();
        let (parent, child, selected, selected_map, gate_peer) = match staged {
            Ok(v) => v,
            Err(status) => {
                let _ = snapshot_record(self, &enrollment.editor, &initial, Some(status), false);
                return Err(ProcessLaunchFailure {
                    status,
                    recovery: ProcessLaunchRecovery::Unspawned {
                        enrollment,
                        executable,
                    },
                });
            }
        };
        let Some(image) = executable.executable.take() else {
            return Err(ProcessLaunchFailure {
                status: Status::Stale,
                recovery: ProcessLaunchRecovery::Unspawned {
                    enrollment,
                    executable,
                },
            });
        };
        let assertion = enrollment
            .trace
            .scenario()
            .filter(|s| s.assertion_child())
            .map(ProcessAssertionScenario::id);
        let retirement_editor = NativeEditor {
            authority: enrollment.editor.authority.clone(),
            life: enrollment.editor.life.clone(),
        };
        let retirement_host = self.clone();
        let retirement_record = record.clone();
        let callback = Box::new(
            move |reason: ProcessRetireReason, phase: u8, status: Status| {
                if phase == 0 {
                    let _ = snapshot_record(
                        &retirement_host,
                        &retirement_editor,
                        &retirement_record,
                        None,
                        true,
                    );
                }
                let _ = retirement_host.process_retire_core(&retirement_editor, reason, now_ms);
                let _ = retirement_record.retire_binding();
                if phase == 1 && !retirement_record.trace.retirement_snapshot_deferred() {
                    let _ = snapshot_record(
                        &retirement_host,
                        &retirement_editor,
                        &retirement_record,
                        Some(status),
                        false,
                    );
                }
            },
        );
        let launched = linux::start(
            image,
            child,
            &enrollment.trace,
            deadline,
            assertion,
            callback,
        );
        let (supervisor, start_error) = match launched {
            Ok(s) => (s, None),
            Err(linux::StartFailure::Unspawned(status, image, child)) => {
                drop((selected_map, parent, child, selected));
                executable.executable = Some(image);
                let _ = snapshot_record(self, &enrollment.editor, &record, Some(status), false);
                return Err(ProcessLaunchFailure {
                    status,
                    recovery: ProcessLaunchRecovery::Unspawned {
                        enrollment,
                        executable,
                    },
                });
            }
            Err(linux::StartFailure::Spawned(status, s)) => (s, Some(status)),
        };
        let inner = ChildInner {
            enrollment,
            record,
            supervisor,
            joined: None,
            socket: Some(parent),
            gate_peer,
            selected: Some(selected),
            selected_map: Some(selected_map),
            offer: None,
            accepted: None,
            pending: None,
            input_queue: std::collections::VecDeque::with_capacity(64),
            reset_queue: None,
            pending_request: None,
            capture: None,
            captured_text_generation: None,
            request: 0,
            acknowledged: 0,
            text_generation: 1,
            view_generation: 1,
            publication: 0,
            wire_publication: 0,
            deferred_ack: None,
            next_offer: 0,
            deadline,
            outbound: None,
            requested_flush: None,
            delivered_since_flush: 0,
            downs_since_flush: 0,
            bootstrap: [0; 88],
            ready: false,
            retiring: false,
            receipt: None,
        };
        let mut child = OwnedEditorChild { inner: Some(inner) };
        if let Some(status) = start_error {
            let _ = observe_carrier(self, child.inner.as_mut().unwrap(), Some(status), false);
            return Err(ProcessLaunchFailure {
                status,
                recovery: ProcessLaunchRecovery::Spawned(child),
            });
        }
        if child
            .inner
            .as_ref()
            .unwrap()
            .record
            .trace
            .scenario()
            .is_some_and(|s| s.id().starts_with("D24"))
        {
            // Closed stall control: the real production child remains blocked
            // waiting for its first Bootstrap. Its independent supervisor keeps
            // the original deadline; no registry lock is held and no fake ACK
            // or child checkpoint is emitted.
            return Ok(child);
        }
        match protocol::bootstrap(self, child.inner.as_mut().unwrap(), now_ms) {
            Ok(()) | Err(Status::NotReady) => Ok(child),
            Err(status) => {
                let inner = child.inner.as_mut().unwrap();
                let _ = observe_carrier(self, inner, Some(status), false);
                let _ = self.process_retire_core(
                    &inner.enrollment.editor,
                    ProcessRetireReason::InvalidTransport,
                    now_ms,
                );
                let _ = inner.record.retire_binding();
                inner.retiring = true;
                inner
                    .supervisor
                    .request_retire(ProcessRetireReason::InvalidTransport);
                Err(ProcessLaunchFailure {
                    status,
                    recovery: ProcessLaunchRecovery::Spawned(child),
                })
            }
        }
    }
    pub fn observe_process_child(
        &self,
        child: &OwnedEditorChild,
    ) -> Result<ProcessChildObservation, Status> {
        let inner = inner(self, child)?;
        let actual = inner.supervisor.identity()?;
        if actual.birth == 0 {
            return Err(Status::NotReady);
        }
        Ok(ProcessChildObservation {
            pid: actual.pid,
            birth: actual.birth,
            executable: actual.executable,
            acknowledged: inner.acknowledged,
            publication: inner.publication,
        })
    }
    pub fn observe_process_editor(
        &self,
        child: &OwnedEditorChild,
        now_ms: u64,
    ) -> Result<NativeEditorObservation, Status> {
        let inner = inner(self, child)?;
        enforce_deadline(inner)?;
        if !inner.ready {
            return Err(Status::NotReady);
        }
        if inner.retiring || inner.supervisor.terminal() {
            return Err(Status::Stale);
        }
        self.process_validate(&inner.enrollment.editor, now_ms)
    }
    pub fn take_process_save_intent(
        &self,
        child: &mut OwnedEditorChild,
    ) -> Result<NativeSaveIntent, Status> {
        let inner = inner_mut(self, child)?;
        enforce_deadline(inner)?;
        if inner.retiring {
            return Err(Status::Denied);
        }
        let consumed_probe = inner.record.trace.is("D18CaptureConsumedTwice");
        if consumed_probe {
            let _ = observe_carrier(self, inner, None, true);
        }
        let result = self.process_take_intent(&inner.enrollment.editor);
        if consumed_probe && result.is_err() {
            let _ = observe_carrier(self, inner, result.as_ref().err().copied(), false);
        }
        result
    }
    pub fn retire_process_editor(
        &self,
        child: &mut OwnedEditorChild,
        reason: ProcessRetireReason,
        now_ms: u64,
    ) -> Result<(), ProcessStepFailure> {
        let inner = inner_mut(self, child)?;
        // The first retirement owns the Core fence and supervisor request.
        // A cleanup retry cannot change its cause or send a later graceful
        // Stop that races an already requested fault termination.
        if inner.retiring {
            return Ok(());
        }
        #[cfg(feature = "host_editor_process_assertions_v0_dev")]
        let late_publication = fixtures::before_retire(self, inner, reason, now_ms)?;
        #[cfg(feature = "host_editor_process_assertions_v0_dev")]
        if reason != ProcessRetireReason::HumanClose && !late_publication {
            inner.record.trace.release_candidate();
        }
        observe_carrier(self, inner, None, true)?;
        let retention_probe = inner
            .record
            .trace
            .scenario()
            .is_some_and(|s| s.id().starts_with("D29") && !s.is_positive());
        if reason == ProcessRetireReason::HumanClose
            && !retention_probe
            && !inner.record.trace.has_after()
        {
            let latest = inner.record.trace.latest_status();
            observe_carrier(self, inner, latest, false)?;
        }
        let core = self.process_retire_core(&inner.enrollment.editor, reason, now_ms);
        let _ = inner.record.retire_binding();
        inner.retiring = true;
        if reason == ProcessRetireReason::HumanClose
            && !retention_probe
            && Instant::now() < inner.deadline
        {
            let _ = protocol::stop(inner, reason);
        }
        inner.supervisor.request_retire(reason);
        match core {
            Ok(()) | Err(Status::Stale) => Ok(()),
            Err(status) => Err(status.into()),
        }
    }
    #[allow(
        clippy::result_large_err,
        reason = "A nonblocking failed join must return the same sole inline child and wait owner under the frozen API."
    )]
    pub fn join_process_editor(
        &self,
        mut child: OwnedEditorChild,
    ) -> Result<OwnedEditorChildExitProof, ProcessJoinFailure> {
        let result = (|| {
            let inner = inner_mut(self, &mut child)?;
            let live_probe = inner.record.trace.scenario().is_some_and(|s| {
                matches!(
                    s.id(),
                    "D29LiveJoinNotReadyIsPrompt"
                        | "D29ConsumingJoinReturnsOwnerWithoutUnwind"
                        | "D29ThreadJoinIsNotReap"
                )
            });
            if live_probe {
                observe_carrier(self, inner, None, true)?;
            }
            if inner.retiring
                && inner.record.trace.is("D29EofIsNotReap")
                && !inner.record.trace.has_after()
            {
                observe_carrier(self, inner, None, true)?;
                match linux::receive(inner.socket.as_ref().ok_or(Status::Disconnected)?) {
                    Err(Status::Disconnected) => {
                        observe_carrier(self, inner, Some(Status::NotReady), false)?;
                    }
                    Err(Status::NotReady) | Ok(_) => {}
                    Err(status) => return Err(status),
                }
                return Err(Status::NotReady);
            }
            let (identity, outcome) = match inner
                .joined
                .map(Ok)
                .unwrap_or_else(|| inner.supervisor.try_join())
            {
                Ok(proof) => {
                    // This cache contains only the real sole supervisor's
                    // completed native wait and Rust join, never an inferred
                    // completion. Fallible post-join cleanup can be retried.
                    inner.joined = Some(proof);
                    proof
                }
                Err(status) => {
                    if live_probe {
                        observe_carrier(self, inner, Some(status), false)?;
                    }
                    return Err(status);
                }
            };
            if identity.birth == 0 {
                return Err(Status::Internal);
            }
            #[cfg(feature = "host_editor_process_assertions_v0_dev")]
            fixtures::after_native_wait(self, inner)?;
            drop(inner.accepted.take());
            drop(inner.offer.take());
            drop(inner.pending.take());
            inner.input_queue.clear();
            drop(inner.reset_queue.take());
            drop(inner.capture.take());
            drop(inner.selected_map.take());
            drop(inner.selected.take());
            drop(inner.socket.take());
            drop(inner.gate_peer.take());
            #[cfg(feature = "host_editor_process_assertions_v0_dev")]
            fixtures::cleanup(&inner.enrollment)?;
            if inner.record.trace.quarantined() {
                return Err(Status::Internal);
            }
            Ok((identity, outcome))
        })();
        match result {
            Err(status) => Err(ProcessJoinFailure { status, child }),
            Ok((identity, outcome)) => {
                let inner = child
                    .inner
                    .take()
                    .expect("same actual child after successful join");
                #[cfg(feature = "host_editor_process_assertions_v0_dev")]
                if inner.ready {
                    if let Ok(history) = inner.record.trace.retired_bootstrap() {
                        let mut roster = inner
                            .enrollment
                            .roster
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        if roster.retired_bootstraps.len() == 2 {
                            roster.retired_bootstraps.pop_front();
                        }
                        roster.retired_bootstraps.push_back(history);
                    }
                }
                drop(inner);
                Ok(OwnedEditorChildExitProof {
                    pid: identity.pid,
                    birth: identity.birth,
                    executable: identity.executable,
                    outcome,
                })
            }
        }
    }
}
