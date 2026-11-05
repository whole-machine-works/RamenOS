//! Full process consumers. Each family drives actual owners and independently
//! checks the recorded attempted fault, rejection, and a subsequent authorized
//! operation. No scenario's own success flag is accepted as an oracle.
use super::fixture;
use super::support::*;
use crate::{desktop_owner_assertions as oracle, editor_dev as desktop};
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
#[path = "app_cases.rs"]
mod app_cases;
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
use app_cases::{SaveInterruption, public_interrupted_save, public_save_lifecycle};
#[path = "child_group.rs"]
mod child_group;
#[path = "cursor_cases.rs"]
mod cursor_cases;
#[path = "gate_record.rs"]
mod gate_record;
#[path = "lifecycle_cases.rs"]
mod lifecycle_cases;
#[path = "obligations.rs"]
mod obligations;
use child_group::ChildGroup;
#[allow(
    clippy::duplicate_mod,
    reason = "Each independently staged owner module retains its own three named cleanup controls in the frozen executable inventory."
)]
#[path = "cleanup_owners.rs"]
mod parent_owners;
use desktop_service::dev::Status;
use desktop_service::editor_dev::EditorMessage;
use parent_owners::ParentOwners;
use std::{
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
    time::{Duration, Instant},
};

const POINTS: [desktop::ProcessAssertionPoint; 11] = [
    desktop::ProcessAssertionPoint::BeforeSnapshotCopy,
    desktop::ProcessAssertionPoint::HeldVerifiedBeforeExec,
    desktop::ProcessAssertionPoint::ForkOwnedBeforeExecRelease,
    desktop::ProcessAssertionPoint::BootstrapBeforeSend,
    desktop::ProcessAssertionPoint::InputReceivedBeforeAck,
    desktop::ProcessAssertionPoint::OfferMappedBeforeSeal,
    desktop::ProcessAssertionPoint::PairValidatedBeforeAdopt,
    desktop::ProcessAssertionPoint::CaptureBeforeAdopt,
    desktop::ProcessAssertionPoint::SupervisorBeforeSignal,
    desktop::ProcessAssertionPoint::SupervisorBeforeWait,
    desktop::ProcessAssertionPoint::SupervisorTerminalBeforeJoin,
];

fn release_reached(
    run: &mut desktop::ProcessAssertionRun,
    stopped: &AtomicBool,
    progress: &AtomicU32,
    barrier: &AtomicU32,
    id: &str,
) {
    let mut released = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(8);
    while !stopped.load(Ordering::Acquire) {
        for point in POINTS {
            match run.wait_checkpoint(point, 1) {
                Ok(observed) => {
                    assert_eq!(observed.point(), point);
                    assert!(observed.sequence() > 0);
                    let key = (point, observed.sequence());
                    if released.contains(&key) {
                        continue;
                    }
                    if id == "D24NoRegistryLockAcrossSignalWait"
                        && matches!(
                            point,
                            desktop::ProcessAssertionPoint::SupervisorBeforeSignal
                                | desktop::ProcessAssertionPoint::SupervisorBeforeWait
                        )
                    {
                        let stage =
                            if point == desktop::ProcessAssertionPoint::SupervisorBeforeSignal {
                                1
                            } else {
                                2
                            };
                        barrier.store(stage, Ordering::Release);
                        while progress.load(Ordering::Acquire) < stage {
                            assert!(
                                Instant::now() < deadline,
                                "original unrelated-session barrier budget"
                            );
                            std::thread::yield_now();
                        }
                    }
                    let delay_point = match id {
                        "D28SpawnPauseCannotRenew" => {
                            Some(desktop::ProcessAssertionPoint::ForkOwnedBeforeExecRelease)
                        }
                        "D28BootstrapPauseCannotRenew" => {
                            Some(desktop::ProcessAssertionPoint::BootstrapBeforeSend)
                        }
                        "D28RoundTripCannotRenew" => {
                            Some(desktop::ProcessAssertionPoint::InputReceivedBeforeAck)
                        }
                        "D28IntentRequestCannotRenew" => {
                            Some(desktop::ProcessAssertionPoint::CaptureBeforeAdopt)
                        }
                        "D28BackdatedCoreClock" => {
                            Some(desktop::ProcessAssertionPoint::InputReceivedBeforeAck)
                        }
                        _ => None,
                    };
                    if delay_point == Some(point) {
                        std::thread::sleep(Duration::from_millis(120));
                    }
                    if matches!(
                        id,
                        "D18CaptureAfter1000Ms" | "D18RoundTripCannotRenewCapture"
                    ) && point == desktop::ProcessAssertionPoint::CaptureBeforeAdopt
                    {
                        let held = Instant::now();
                        std::thread::sleep(Duration::from_millis(1100));
                        assert!(held.elapsed() >= Duration::from_millis(1100));
                    }
                    ok(run.release(point));
                    assert!(
                        run.release(point).is_err(),
                        "releasing the same occurrence twice is rejected"
                    );
                    released.push(key);
                }
                Err(Status::NotReady | Status::Timeout | Status::Invalid | Status::Stale) => {}
                Err(error) => panic!("unexpected diagnostic wait: {error:?}"),
            }
        }
        assert!(
            Instant::now() < deadline,
            "original bounded diagnostic barrier control"
        );
        std::thread::yield_now();
    }
}

fn prepare_at(
    group: &mut ChildGroup,
    session: usize,
    object: u64,
    body: &[u8],
    now: u64,
) -> desktop::ProcessEditorEnrollment {
    let (launch, editor) = fixture::initialize_at(group.fixture(), session, object, body, now);
    group.retain_launch(launch);
    match group.fixture().h.prepare_process_editor(editor) {
        Ok(enrollment) => enrollment,
        Err(failure) => {
            let (status, editor) = failure.into_parts();
            drop(editor);
            panic!("genuine prepare {status:?}");
        }
    }
}
fn prepare(
    group: &mut ChildGroup,
    session: usize,
    object: u64,
    body: &[u8],
) -> desktop::ProcessEditorEnrollment {
    prepare_at(group, session, object, body, 1)
}
fn pump_publication(group: &mut ChildGroup, index: usize, now: u64) -> Result<(), Status> {
    pump_publication_with_export(group, index, now, true)
}
fn pump_publication_with_export(
    group: &mut ChildGroup,
    index: usize,
    now: u64,
    export_frame: bool,
) -> Result<(), Status> {
    pump_publication_mode(
        group,
        index,
        now,
        if export_frame {
            PublicationFrame::Export
        } else {
            PublicationFrame::Consume
        },
    )
}
enum PublicationFrame {
    Export,
    Consume,
    CallerComposes,
}
fn pump_publication_mode(
    group: &mut ChildGroup,
    index: usize,
    now: u64,
    mode: PublicationFrame,
) -> Result<(), Status> {
    let end = Instant::now() + Duration::from_millis(1000);
    loop {
        let (f, child) = group.borrow(index);
        let step =
            f.h.pump_process_editor(child, now)
                .map_err(|e| e.status())?;
        if step.publication_accepted() {
            let view = f.h.observe_process_editor(child, now)?;
            let session = f
                .drivers
                .iter()
                .position(|d| d.s.session_id == view.actor.session_id)
                .ok_or(Status::Denied)?;
            if matches!(mode, PublicationFrame::Export) {
                f.compose(session, now)?;
            } else if matches!(mode, PublicationFrame::Consume) {
                // Consume the actual accepted Core frame through the genuine
                // compositor Portal. Present validation still occurs on every
                // pair; only first/final quota frames need full composition.
                use kernel_api::generated::desktop_surface_v1 as surface;
                let endpoint = &f.drivers[session].s.compositor;
                let core = f.dc.evidence()?;
                let present = core
                    .exchanges
                    .iter()
                    .rev()
                    .find_map(|(q, r)| {
                        if q.protocol != surface::DESKTOP_SURFACE_V1_PROTOCOL_ID
                            || q.msg_type != surface::MSG_DESKTOP_SURFACE_V1_PRESENT
                        {
                            return None;
                        }
                        let actual = surface::Present::decode(q).ok()?;
                        let reply = surface::PresentReply::decode(r).ok()?;
                        (reply.status == 0 && reply.sequence == actual.sequence).then_some(actual)
                    })
                    .ok_or(Status::NotReady)?;
                let request_id = 0xd160_0000_u64
                    .checked_add(present.sequence)
                    .ok_or(Status::Exhausted)?;
                let request = surface::Consume {
                    request_id,
                    surface_id: present.surface_id,
                    surface_generation: present.surface_generation,
                    sequence: present.sequence,
                }
                .encode(endpoint.handle)?;
                let prior_chrome = f.dc.save_chrome_observation(endpoint)?;
                let consumed =
                    surface::ConsumeReply::decode(&f.h.dispatch(&endpoint.peer, &request, now))?;
                assert_eq!(consumed.request_id, request_id);
                assert_eq!(consumed.status, Status::Ok as u32);
                assert_eq!(consumed.sequence, present.sequence);
                let chrome =
                    f.dc.save_chrome_observation(&f.drivers[session].s.compositor)?;
                assert_eq!(chrome.current_frame_actor, view.actor);
                assert_eq!(chrome.document_id, Some(view.document_id));
                assert_eq!(chrome.text_generation, Some(view.text_generation));
                assert_eq!(chrome.view_version, Some(view.view_version));
                // Consume acknowledges the latest presented surface; it does
                // not compose a new scene or replace its protected chrome.
                // The getter therefore still describes the last real compose.
                assert_eq!(chrome, prior_chrome);
                assert!(chrome.frame_sequence > 0 && chrome.frame_sequence <= present.sequence);
                assert!(!matches!(chrome.label, desktop::NativeEditorPhase::Saved));
            }
            return Ok(());
        }
        if step.child_exit_observed() {
            return Err(Status::Disconnected);
        }
        if Instant::now() >= end {
            return Err(Status::Timeout);
        }
        std::thread::yield_now();
    }
}
fn deliver(
    group: &mut ChildGroup,
    index: usize,
    driver: usize,
    usage: u32,
    phase: u32,
    now: u64,
) -> Result<(), Status> {
    let (f, child) = group.borrow(index);
    f.drivers[driver].send(&f.h, usage, phase, now);
    let sequence = f.drivers[driver].next - 1;
    let end = Instant::now() + Duration::from_millis(1000);
    loop {
        let step =
            f.h.pump_process_editor(child, now)
                .map_err(|e| e.status())?;
        let observed = f.h.observe_process_child(child)?;
        assert!(observed.acknowledged_sequence() <= sequence);
        if observed.acknowledged_sequence() == sequence {
            return Ok(());
        }
        if step.child_exit_observed() {
            return Err(Status::Disconnected);
        }
        if Instant::now() >= end {
            return Err(Status::Timeout);
        }
        std::thread::yield_now();
    }
}
fn request(group: &mut ChildGroup, index: usize, now: u64) -> Result<(), Status> {
    request_with_export(group, index, now, true)
}
fn request_without_compose(group: &mut ChildGroup, index: usize, now: u64) -> Result<(), Status> {
    let (f, child) = group.borrow(index);
    f.h.request_process_editor_frame(child, now)
        .map_err(|e| e.status())?;
    pump_publication_mode(group, index, now, PublicationFrame::CallerComposes)
}
fn request_with_export(
    group: &mut ChildGroup,
    index: usize,
    now: u64,
    export_frame: bool,
) -> Result<(), Status> {
    let (f, child) = group.borrow(index);
    f.h.request_process_editor_frame(child, now)
        .map_err(|e| e.status())?;
    pump_publication_with_export(group, index, now, export_frame)
}
fn ordinary_edit_at(
    group: &mut ChildGroup,
    index: usize,
    driver: usize,
    now: u64,
) -> Result<(), Status> {
    for (usage, phase) in [(224, 1), (4, 1), (4, 2), (224, 2)] {
        deliver(group, index, driver, usage, phase, now)?;
    }
    for &byte in NEW {
        deliver(group, index, driver, usage(byte), 1, now)?;
        deliver(group, index, driver, usage(byte), 2, now)?;
    }
    request(group, index, now)
}
fn ordinary_edit(group: &mut ChildGroup, index: usize, driver: usize) -> Result<(), Status> {
    ordinary_edit_at(group, index, driver, 2)
}
fn ctrl_s_capture(group: &mut ChildGroup, index: usize, driver: usize) -> Result<(), Status> {
    deliver(group, index, driver, 224, 1, 2)?;
    deliver(group, index, driver, 22, 1, 2)?;
    let end = Instant::now() + Duration::from_millis(1500);
    loop {
        let (f, child) = group.borrow(index);
        let step = f.h.pump_process_editor(child, 2).map_err(|e| e.status())?;
        if step.save_intent_available() {
            let intent = f.h.take_process_save_intent(child)?;
            assert_eq!(
                intent.deadline().duration_since(intent.entered()),
                Duration::from_millis(1000)
            );
            assert!(Instant::now() < intent.deadline());
            assert!(matches!(
                f.h.take_process_save_intent(child),
                Err(Status::NotReady)
            ));
            drop(intent);
            break;
        }
        if Instant::now() >= end {
            return Err(Status::Timeout);
        }
        std::thread::yield_now();
    }
    deliver(group, index, driver, 22, 2, 2)?;
    deliver(group, index, driver, 224, 2, 2)
}

fn fresh_desktop_witness(
    mut fixture: Fixture,
    body: &[u8],
    prior: Option<(u32, u64, desktop::NativeEditorObservation, u64)>,
) {
    fixture.reattach_input(0, 3);
    let mut group = ChildGroup::new(fixture);
    let enrollment = prepare_at(&mut group, 0, 101, body, 4);
    let run = prior.as_ref().map(|_| {
        let scenario = ok(desktop::ProcessAssertionScenario::for_case("D23P"));
        ok(group
            .fixture()
            .dc
            .arm_process_assertion(&enrollment, &scenario[0]))
    });
    let index = ok(group.spawn(enrollment, ok(desktop::ChildBudget::checked(5000)), 4));
    let checked = catch_unwind(AssertUnwindSafe(|| {
        ok(pump_publication(&mut group, index, 4));
        if let Some((pid, birth, old, _)) = &prior {
            let (f, child) = group.borrow(index);
            let actual = ok(f.h.observe_process_child(child));
            let initial = ok(f.h.observe_process_editor(child, 4));
            assert_ne!((actual.process_id(), actual.birth_ticks()), (*pid, *birth));
            assert_ne!(
                (initial.actor.instance_id, initial.actor.instance_generation),
                (old.actor.instance_id, old.actor.instance_generation)
            );
            assert_eq!(initial.confirmed_revision, old.confirmed_revision);
            assert_eq!(initial.confirmed_hash, old.confirmed_hash);
            assert_eq!(initial.bytes, body);
        }
        ok(ordinary_edit_at(&mut group, index, 0, 5));
        let (f, child) = group.borrow(index);
        assert_eq!(ok(f.h.observe_process_editor(child, 5)).bytes, NEW);
        let frame = ok(f.compose(0, 5));
        fixture::expected_crop(&frame, true);
        assert_eq!(f.counts(101), (0, 0, 0));
    }));
    let (fixture, proofs) = match group.finish(6) {
        Ok(done) => done,
        Err(retained) => {
            drop(retained);
            panic!("INCOMPLETE: post-denial witness child retained");
        }
    };
    let fixture = ParentOwners::new(fixture);
    let completed = catch_unwind(AssertUnwindSafe(|| {
        assert_eq!(proofs.len(), 1);
        assert!(proofs[0].supervisor_joined());
        if let Some(run) = run {
            let evidence = match run.finish_recording() {
                Ok(e) => e,
                Err(failure) => {
                    let (status, run) = failure.into_parts();
                    std::mem::forget(run);
                    panic!("INCOMPLETEfreshrecord:{status:?}");
                }
            };
            oracle::assert_integrity(&evidence, "D23FreshPreviewApprovalNewBirth");
            assert_ne!(
                evidence.active_channel_generation(),
                prior.as_ref().unwrap().3
            );
            oracle::assert_positive(&evidence, "D23FreshPreviewApprovalNewBirth");
        }
        if let Err(payload) = checked {
            resume_unwind(payload);
        }
    }));
    match completed {
        Ok(()) => fixture.release_after_join().finish(),
        Err(payload) => {
            drop(fixture);
            resume_unwind(payload);
        }
    }
}

fn sibling_progress(group: &mut ChildGroup, index: usize, usage: u32, expected: &[u8]) {
    let before_frame = ok(group.fixture().compose(1, 2));
    let before_chrome = {
        let f = group.fixture();
        ok(f.dc.save_chrome_observation(&f.drivers[1].s.compositor))
    };
    protected_golden(
        &before_frame,
        match before_chrome.label {
            desktop::NativeEditorPhase::Loaded => "LOADED",
            desktop::NativeEditorPhase::Unsaved => "UNSAVED",
            other => panic!("unexpected independent B chrome {other:?}"),
        },
        "",
    );
    let entered = Instant::now();
    ok(deliver(group, index, 1, usage, 1, 2));
    ok(deliver(group, index, 1, usage, 2, 2));
    ok(request(group, index, 2));
    assert!(entered.elapsed() < Duration::from_millis(1000));
    let (f, child) = group.borrow(index);
    assert_eq!(ok(f.h.observe_process_editor(child, 2)).bytes, expected);
    let after_frame = ok(f.compose(1, 2));
    assert_ne!(
        volatile::hash(&before_frame.bgra[48 * 2560..528 * 2560]),
        volatile::hash(&after_frame.bgra[48 * 2560..528 * 2560])
    );
    assert_eq!(
        volatile::hash(&before_frame.bgra[..48 * 2560]),
        volatile::hash(&after_frame.bgra[..48 * 2560])
    );
    let chrome = ok(f.dc.save_chrome_observation(&f.drivers[1].s.compositor));
    assert_eq!(chrome.label, desktop::NativeEditorPhase::Unsaved);
    assert_eq!(
        chrome.current_document_phase,
        desktop::NativeEditorPhase::Unsaved
    );
    assert_eq!(chrome.outstanding_original_count, 0);
    assert!(chrome.pending_originals.is_empty());
    protected_golden(&after_frame, "UNSAVED", "");
}

fn genuine_alias_denials() {
    let mut parents = ParentOwners::new(fixture::fixture("d07_genuine_alias_denials", 1));
    let (launch, editor) = fixture::initialize(parents.borrow(), 1);
    let (mut reply, _, _) = fixture::read(parents.borrow(), &launch, 401, 1);
    let alias = ok(reply.take_editor());
    let before = ok(parents.borrow().h.editor_observation(&alias, 1));
    let enrollment = match parents.borrow().h.prepare_process_editor(editor) {
        Ok(enrollment) => enrollment,
        Err(failure) => {
            let (_, editor) = failure.into_parts();
            std::mem::forget(editor);
            panic!("genuine process enrollment failed");
        }
    };
    assert!(matches!(
        parents.borrow().h.step_native_editor(&alias, 1),
        Err(Status::Denied)
    ));
    assert!(matches!(
        parents.borrow().h.render_native_editor(&alias, 1),
        Err(Status::Denied)
    ));
    assert_eq!(ok(parents.borrow().h.editor_observation(&alias, 1)), before);
    let mut repeated = fixture::read_reply(parents.borrow(), &launch, 402, 1);
    assert!(repeated.take_editor().is_err());
    drop((repeated, reply, alias));
    let mut group = ChildGroup::new(parents.release_after_join());
    group.retain_launch(launch);
    let index = ok(group.spawn(enrollment, ok(desktop::ChildBudget::checked(5000)), 1));
    let checked = catch_unwind(AssertUnwindSafe(|| {
        ok(pump_publication(&mut group, index, 1));
        ok(ordinary_edit(&mut group, index, 0));
        let (f, child) = group.borrow(index);
        assert_eq!(ok(f.h.observe_process_editor(child, 2)).bytes, NEW);
        fixture::expected_crop(&ok(f.compose(0, 2)), true);
        assert_eq!(f.counts(101), (0, 0, 0));
    }));
    let (fixture, proofs) = match group.finish(3) {
        Ok(done) => done,
        Err(retained) => {
            drop(retained);
            panic!("INCOMPLETE genuine alias witness reap");
        }
    };
    let parents = ParentOwners::new(fixture);
    let checked = catch_unwind(AssertUnwindSafe(|| {
        assert_eq!(proofs.len(), 1);
        assert!(proofs[0].supervisor_joined());
        if let Err(payload) = checked {
            resume_unwind(payload);
        }
    }));
    match checked {
        Ok(()) => parents.release_after_join().finish(),
        Err(payload) => {
            drop(parents);
            resume_unwind(payload);
        }
    }
}

fn fault_previous_bootstrap_owner(fixture: Fixture) -> (Fixture, (u32, u64)) {
    let mut group = ChildGroup::new(fixture);
    let enrollment = prepare(&mut group, 0, 101, OLD);
    let index = ok(group.spawn(enrollment, ok(desktop::ChildBudget::checked(5000)), 1));
    let mut binding = None;
    let checked = catch_unwind(AssertUnwindSafe(|| {
        ok(pump_publication(&mut group, index, 1));
        let (f, child) = group.borrow(index);
        let observed = ok(f.h.observe_process_child(child));
        binding = Some((observed.process_id(), observed.birth_ticks()));
        group.fault(index, 1);
    }));
    let (fixture, proofs) = match group.finish(1) {
        Ok(done) => done,
        Err(retained) => {
            drop(retained);
            panic!("INCOMPLETE originalbootstrapownerreap");
        }
    };
    let parents = ParentOwners::new(fixture);
    let checked = catch_unwind(AssertUnwindSafe(|| {
        if let Err(payload) = checked {
            resume_unwind(payload);
        }
        assert_eq!(proofs.len(), 1);
        assert!(proofs[0].supervisor_joined());
        assert!(
            matches!(proofs[0].wait_outcome(),desktop::ProcessWaitOutcome::Signaled(signal) if signal==libc::SIGKILL)
        );
        assert_eq!(
            (proofs[0].process_id(), proofs[0].birth_ticks()),
            binding.unwrap()
        );
    }));
    match checked {
        Ok(()) => (parents.release_after_join(), binding.unwrap()),
        Err(payload) => {
            drop(parents);
            resume_unwind(payload)
        }
    }
}

fn actual_core_route(f: &mut Fixture, id: &str) {
    lifecycle_cases::assert_core_route(f, id);
    use kernel_api::generated::{desktop_editor_session_v1 as session, input_v1 as input};
    let evidence = ok(f.dc.evidence());
    if id.starts_with("D26") {
        assert!(
            evidence.exchanges.iter().any(|(q, r)| q.protocol
                == session::DESKTOP_EDITOR_SESSION_V1_PROTOCOL_ID
                && q.msg_type == session::MSG_DESKTOP_EDITOR_SESSION_V1_REVOKE_INSTANCE
                && session::RevokeInstance::decode(q)
                    .is_ok_and(|v| v.session_id == f.drivers[0].s.session_id)
                && session::RevokeInstanceReply::decode(r).is_ok_and(|v| v.status == 0)),
            "actual successful Core revoke, not a diagnosticDenied label"
        );
    }
    if id == "D10ProtectedChromeObjectAsSurface" {
        use kernel_api::generated::desktop_surface_v1 as surface;
        assert!(
            evidence.exchanges.iter().any(|(q, r)| q.protocol
                == surface::DESKTOP_SURFACE_V1_PROTOCOL_ID
                && q.msg_type == surface::MSG_DESKTOP_SURFACE_V1_ACQUIRE
                && q.handle == f.drivers[0].s.compositor.handle
                && surface::Acquire::decode(q).is_ok_and(|v| v.request_id == 1901)
                && surface::AcquireReply::decode(r)
                    .is_ok_and(|v| v.status == Status::Denied as u32
                        && v.buffer_shm == 0
                        && v.mapping_generation == 0)),
            "actual typedwrongpeer Coredenial"
        );
    }
    if id == "D10ReservedKeyForwardingReject" {
        assert!(
            evidence
                .exchanges
                .iter()
                .any(|(q, r)| q.protocol == input::INPUT_V1_PROTOCOL_ID
                    && q.msg_type == input::MSG_INPUT_V1_PRODUCE_KEY
                    && input::ProduceKey::decode(q)
                        .is_ok_and(|v| v.usage == 20 && v.phase == 1 && v.modifiers & 1 != 0)
                    && input::ProduceKeyReply::decode(r).is_ok_and(|v| v.status == 0)),
            "actual trusted CtrlQ attempt"
        );
    }
    if id == "D27OrdinaryOverflowReservedReset" {
        assert!(
            evidence
                .exchanges
                .iter()
                .filter(|(q, r)| q.protocol == input::INPUT_V1_PROTOCOL_ID
                    && q.msg_type == input::MSG_INPUT_V1_PRODUCE_KEY
                    && input::ProduceKey::decode(q).is_ok_and(|v| matches!(v.phase, 1 | 2))
                    && input::ProduceKeyReply::decode(r).is_ok_and(|v| v.status == 0))
                .count()
                >= 65,
            "actual overflow attempt after sixtyfour accepted queued keys"
        );
    }
}
fn assert_quota_presents(f: &Fixture, evidence: &desktop::ProcessAssertionEvidence, id: &str) {
    if !id.starts_with("D16") {
        return;
    }
    use kernel_api::generated::desktop_surface_v1 as surface;
    let surface_id = evidence
        .before()
        .frame_surface_id
        .expect("actual accepted quota surface");
    let generation = evidence
        .before()
        .frame_surface_generation
        .expect("actual accepted quota generation");
    let core = ok(f.dc.evidence());
    let sequences: Vec<_> = core
        .exchanges
        .iter()
        .filter_map(|(q, r)| {
            if q.protocol != surface::DESKTOP_SURFACE_V1_PROTOCOL_ID
                || q.msg_type != surface::MSG_DESKTOP_SURFACE_V1_PRESENT
            {
                return None;
            }
            let present = surface::Present::decode(q).ok()?;
            let reply = surface::PresentReply::decode(r).ok()?;
            (present.surface_id == surface_id
                && present.surface_generation == generation
                && reply.status == 0
                && reply.sequence == present.sequence)
                .then_some(present.sequence)
        })
        .collect();
    assert_eq!(
        sequences,
        (1..=128).collect::<Vec<u64>>(),
        "all128 real Core Presents remain validated, independently of composition/export frequency"
    );
}

fn run_native(
    scenario: &desktop::ProcessAssertionScenario,
    positive: bool,
) -> desktop::ProcessAssertionEvidence {
    let id = scenario.id();
    let case_name: &'static str = Box::leak(id.to_ascii_lowercase().into_boxed_str());
    let sibling_needed = id.starts_with("D12")
        || id == "D14ForeignDocumentBinding"
        || id.starts_with("D24")
        || id == "D26OtherOwnerAndOriginalReceiptProgress"
        || matches!(id, "D15LiveEditorThree" | "D15SupervisorThree");
    let maximum_selected = id.starts_with("D16");
    let third_attempt = matches!(id, "D15LiveEditorThree" | "D15SupervisorThree");
    let cursor_golden = id == "D09FrozenCursorSelectionScrollGolden";
    let lines = b"abcd\nx\nabcdef\n".repeat(20);
    let capacity = id == "D08EmptyBase4096PressReleaseAndCtrlS";
    let large = vec![b'a'; 4096];
    let body = if maximum_selected {
        large.as_slice()
    } else if capacity {
        b""
    } else if cursor_golden {
        lines.as_slice()
    } else {
        OLD
    };
    let fixture = if cursor_golden {
        fixture::fixture_with_contents(case_name, &[body])
    } else if third_attempt {
        fixture::fixture(case_name, 3)
    } else if sibling_needed {
        fixture::fixture_with_contents(case_name, &[body, B, C])
    } else {
        fixture::fixture_with_contents(case_name, &[body])
    };
    let (fixture, prior_bootstrap) = if id == "D23OldBootstrapDenied" {
        let (f, binding) = fault_previous_bootstrap_owner(fixture);
        (f, Some(binding))
    } else {
        (fixture, None)
    };
    let admission_now = if prior_bootstrap.is_some() { 2 } else { 1 };
    let mut group = Some(ChildGroup::new(fixture));
    let mut reference = if cursor_golden {
        Some(cursor_cases::ReferenceFixture::new(body))
    } else {
        None
    };
    let mut sibling = None;
    if sibling_needed {
        let enrollment = prepare(group.as_mut().unwrap(), 1, 102, B);
        let index = ok(group.as_mut().unwrap().spawn(
            enrollment,
            ok(desktop::ChildBudget::checked(5000)),
            1,
        ));
        ok(pump_publication(group.as_mut().unwrap(), index, 1));
        sibling = Some(index);
    }
    if third_attempt {
        let enrollment = prepare(group.as_mut().unwrap(), 0, 101, body);
        let index = ok(group.as_mut().unwrap().spawn(
            enrollment,
            ok(desktop::ChildBudget::checked(5000)),
            1,
        ));
        ok(pump_publication(group.as_mut().unwrap(), index, 1));
    }
    let enrollment = if third_attempt {
        // Core intentionally has two sessions. A new genuine approval on the
        // existing session yields a distinct document while both old native
        // child/supervisor owners remain retained for cap admission.
        prepare(group.as_mut().unwrap(), 0, 101, OLD)
    } else {
        prepare_at(group.as_mut().unwrap(), 0, 101, body, admission_now)
    };
    let mut run = {
        let group = group.as_mut().unwrap();
        match sibling {
            Some(index) => {
                let (f, child) = group.borrow(index);
                ok(f.dc.arm_process_pair_assertion(&enrollment, child, scenario))
            }
            None => ok(group
                .fixture()
                .dc
                .arm_process_assertion(&enrollment, scenario)),
        }
    };
    let stopped = AtomicBool::new(false);
    let unrelated_progress = AtomicU32::new(0);
    let unrelated_barrier = AtomicU32::new(0);
    let mut primary_observation = None;
    let mut primary_spawn_instant = None;
    let (asserted, (mut fixture, proofs)) = std::thread::scope(|scope| {
        let controller = scope.spawn(|| {
            release_reached(
                &mut run,
                &stopped,
                &unrelated_progress,
                &unrelated_barrier,
                id,
            )
        });
        let asserted = catch_unwind(AssertUnwindSafe(|| {
            let budget = if let Some(budget) = lifecycle_cases::budget(id, positive) {
                budget
            } else if id == "D24NoRegistryLockAcrossSignalWait" {
                200
            } else if id.starts_with("D24") || id == "D28WithinOriginalBudgetAndActualExpiry" {
                1000
            } else if id.starts_with("D28") && !positive {
                80
            } else {
                5000
            };
            let spawn_entered = Instant::now();
            primary_spawn_instant = Some(spawn_entered);
            let index = match group.as_mut().unwrap().spawn(
                enrollment,
                ok(desktop::ChildBudget::checked(budget)),
                admission_now,
            ) {
                Ok(index) => {
                    assert!(
                        !third_attempt,
                        "third actual child/supervisor must be refused before spawn"
                    );
                    index
                }
                Err(status) => {
                    if third_attempt {
                        assert_eq!(status, Status::Exhausted);
                    }
                    assert!(!positive, "positive actual launch failed: {status:?}");
                    return;
                }
            };
            {
                let (f, child) = group.as_mut().unwrap().borrow(index);
                primary_observation = Some(ok(f.h.observe_process_child(child)));
                if let Some(old) = prior_bootstrap {
                    let fresh = primary_observation.as_ref().unwrap();
                    assert_ne!((fresh.process_id(), fresh.birth_ticks()), old);
                }
            }
            if id.starts_with("D24") {
                if id == "D24NoRegistryLockAcrossReceive" {
                    let (f, child) = group.as_mut().unwrap().borrow(index);
                    match f.h.pump_process_editor(child, 1) {
                        Ok(step) => {
                            assert!(!step.publication_accepted());
                            assert!(!step.child_exit_observed());
                        }
                        Err(error) => {
                            assert!(matches!(error.status(), Status::NotReady | Status::Timeout))
                        }
                    }
                }
                // No further pump, retire, signal or wait on A. Its genuine supervisor
                // watchdog must enforce the original budget while B stays usable.
                return;
            }
            let first = pump_publication(group.as_mut().unwrap(), index, admission_now);
            if let Err(error) = first {
                assert!(
                    !positive || id == "D24IndependentChildBWithinOneSecond",
                    "positive first publication: {error:?}"
                );
                return;
            }
            if id == "D23NoAutomaticRespawn" {
                // Explicit actual fault while this owner is live. HumanClose
                // cleanup below cannot manufacture this scenario's trigger.
                group.as_mut().unwrap().fault(index, 2);
                let end = Instant::now() + Duration::from_millis(1000);
                loop {
                    let (f, child) = group.as_mut().unwrap().borrow(index);
                    match f.h.pump_process_editor(child, 2) {
                        Ok(step) if step.child_exit_observed() => break,
                        Err(error) if error.status() == Status::Disconnected => break,
                        Ok(_) => {}
                        Err(error)
                            if matches!(error.status(), Status::NotReady | Status::Stale) => {}
                        Err(error) => {
                            panic!("actual no-respawn fault observation {:?}", error.status())
                        }
                    }
                    assert!(
                        Instant::now() < end,
                        "actual terminal/EOF before ordinary cleanup"
                    );
                    std::thread::yield_now();
                }
                return;
            }
            if id == "D10ProtectedChromeObjectAsSurface" {
                use kernel_api::generated::desktop_surface_v1 as surface;
                let f = group.as_mut().unwrap().fixture();
                let protected = ok(f.compose(0, 2));
                assert_eq!(protected.bgra.len(), 640 * 568 * 4);
                let actual: surface::CreateReply = volatile::latest(&ok(f.dc.evidence()));
                let request = ok(surface::Acquire {
                    request_id: 1901,
                    surface_id: actual.surface_id,
                    surface_generation: actual.surface_generation,
                    buffer_index: 0,
                    reserved: 0,
                }
                .encode(f.drivers[0].s.compositor.handle));
                // The genuine Input peer cannot act through the genuine
                // compositor handle. Using the compositor peer itself would
                // test its current buffer state, not cross-peer authority.
                let reply = ok(surface::AcquireReply::decode(&f.h.dispatch(
                    &f.drivers[0].s.input.peer,
                    &request,
                    2,
                )));
                assert_eq!(reply.status, Status::Denied as u32);
                assert_eq!(
                    (reply.mapping_generation, reply.buffer_shm, reply.byte_len),
                    (0, 0, 0)
                );
                // This is a genuine wrong-peer Core access refusal. Protected
                // chrome is an internal composed Vec and has no Unix FD export.
                return;
            }
            if id == "D10ReservedKeyForwardingReject" {
                let f = group.as_mut().unwrap().fixture();
                for (usage, phase) in [(224, 1), (20, 1), (20, 2), (224, 2)] {
                    f.drivers[0].send(&f.h, usage, phase, 2);
                }
                let (f, child) = group.as_mut().unwrap().borrow(index);
                let _ = f.h.pump_process_editor(child, 2);
                return;
            }
            if matches!(
                id,
                "D29LiveJoinNotReadyIsPrompt"
                    | "D29ConsumingJoinReturnsOwnerWithoutUnwind"
                    | "D29ThreadJoinIsNotReap"
            ) {
                if id == "D29ThreadJoinIsNotReap" {
                    std::thread::spawn(|| ()).join().unwrap();
                }
                for _ in 0..3 {
                    group
                        .as_mut()
                        .unwrap()
                        .assert_live_join_returns_owner(index);
                }
            }
            if lifecycle_cases::drive(
                group.as_mut().unwrap(),
                index,
                id,
                positive,
                admission_now,
                spawn_entered,
            ) {
                // Actions only; all independent oracles, cleanup, Store counts
                // and the fresh authorized recovery witness still run below.
            } else if cursor_golden {
                reference
                    .as_mut()
                    .unwrap()
                    .drive(group.as_mut().unwrap(), index);
            } else if capacity {
                for _ in 0..4096 {
                    ok(deliver(group.as_mut().unwrap(), index, 0, 4, 1, 2));
                    ok(deliver(group.as_mut().unwrap(), index, 0, 4, 2, 2));
                }
                ok(ctrl_s_capture(group.as_mut().unwrap(), index, 0));
            } else if maximum_selected {
                for offer in 1..128 {
                    ok(request_with_export(
                        group.as_mut().unwrap(),
                        index,
                        2,
                        offer == 127,
                    ));
                }
                if !positive {
                    let _ = request(group.as_mut().unwrap(), index, 2);
                }
            } else {
                let _ = if id == "D28BackdatedCoreClock" {
                    ordinary_edit_at(group.as_mut().unwrap(), index, 0, 0)
                } else {
                    ordinary_edit(group.as_mut().unwrap(), index, 0)
                };
                if id == "D18OrdinaryPublishSaveClaim" {
                    let (f, child) = group.as_mut().unwrap().borrow(index);
                    for _ in 0..3 {
                        assert!(matches!(
                            f.h.take_process_save_intent(child),
                            Err(Status::NotReady)
                        ));
                    }
                } else if matches!(&id[..3], "D18" | "D27" | "D28") {
                    let _ = ctrl_s_capture(group.as_mut().unwrap(), index, 0);
                }
                let _ = request(group.as_mut().unwrap(), index, 2);
            }
            if id == "D28WithinOriginalBudgetAndActualExpiry" {
                let end = Instant::now() + Duration::from_millis(1500);
                loop {
                    let (f, child) = group.as_mut().unwrap().borrow(index);
                    match f.h.pump_process_editor(child, 2) {
                        Err(error) if error.status() == Status::Timeout => break,
                        Ok(step) if step.child_exit_observed() => break,
                        Err(error) => panic!("positive deadline transition {:?}", error.status()),
                        Ok(_) => {}
                    }
                    assert!(
                        Instant::now() < end,
                        "watchdog enforces original one-second budget"
                    );
                    std::thread::yield_now();
                }
                assert!(
                    spawn_entered.elapsed() >= Duration::from_millis(1000),
                    "actual original budget, not early transport failure"
                );
            }
            if id == "D07ActualChildEditAndRasterGolden" {
                let (f, child) = group.as_mut().unwrap().borrow(index);
                assert_eq!(ok(f.h.observe_process_editor(child, 2)).bytes, NEW);
                fixture::expected_crop(&ok(f.compose(0, 2)), true);
            }
            assert_eq!(
                group.as_mut().unwrap().fixture().counts(101),
                (0, 0, 0),
                "Desktop scenario never allocates/commits Save"
            );
        }));
        // This witness runs even if the primary failed before bootstrap; an
        // early negative must not accidentally omit unrelated-session progress.
        let sibling_checked = catch_unwind(AssertUnwindSafe(|| {
            actual_core_route(group.as_mut().unwrap().fixture(), id);
            if let Some(other) = sibling {
                if id == "D24NoRegistryLockAcrossSignalWait" {
                    for stage in 1..=2 {
                        let end = Instant::now() + Duration::from_millis(1000);
                        while unrelated_barrier.load(Ordering::Acquire) != stage {
                            assert!(
                                Instant::now() < end,
                                "actual selected supervisor checkpoint reached"
                            );
                            std::thread::yield_now();
                        }
                        sibling_progress(
                            group.as_mut().unwrap(),
                            other,
                            if stage == 1 { 4 } else { 5 },
                            if stage == 1 {
                                b"other=live\na"
                            } else {
                                b"other=live\nab"
                            },
                        );
                        unrelated_progress.store(stage, Ordering::Release);
                    }
                } else {
                    if id.starts_with("D24") {
                        assert!(
                            Instant::now()
                                < primary_spawn_instant.unwrap() + Duration::from_millis(1000),
                            "B starts while A has originalbudget"
                        );
                    }
                    sibling_progress(group.as_mut().unwrap(), other, 4, b"other=live\na");
                    if id.starts_with("D24") {
                        let admitted_before = primary_spawn_instant.unwrap();
                        assert!(
                            Instant::now() < admitted_before + Duration::from_millis(1000),
                            "B completes while A remains stalled beforebudget"
                        );
                        let after_expiry = admitted_before + Duration::from_millis(1050);
                        if let Some(wait) = after_expiry.checked_duration_since(Instant::now()) {
                            std::thread::sleep(wait);
                        }
                    }
                }
            }
        }));
        unrelated_progress.store(u32::MAX, Ordering::Release);
        let mut cleanup = group.take().unwrap().finish(2);
        if matches!(
            id,
            "D29WaitFailureRetainsOwner" | "D29SignalFailureRetainsOwner"
        ) {
            while let Err(mut retained) = cleanup {
                let deadline = retained.cleanup_deadline();
                if Instant::now() >= deadline {
                    cleanup = Err(retained);
                    break;
                }
                if let Some(before) = &primary_observation {
                    let (f, child) = retained.borrow(0);
                    let after = ok(f.h.observe_process_child(child));
                    assert_eq!(before.process_id(), after.process_id());
                    assert_eq!(before.birth_ticks(), after.birth_ticks());
                }
                std::thread::yield_now();
                cleanup = retained.finish(2);
            }
        }
        let (parents, proofs) = match cleanup {
            Ok((fixture, proofs)) => (ParentOwners::new(fixture), proofs),
            Err(retained) => {
                stopped.store(true, Ordering::Release);
                let _ = controller.join();
                drop(retained);
                panic!("INCOMPLETE: genuine children and parents quarantined; reap unproved");
            }
        };
        stopped.store(true, Ordering::Release);
        controller.join().unwrap();
        let checked = if asserted.is_err() {
            asserted
        } else {
            sibling_checked
        };
        (checked, (parents, proofs))
    });
    let checked = catch_unwind(AssertUnwindSafe(|| {
        let evidence = match run.finish_recording() {
            Ok(evidence) => evidence,
            Err(failure) => {
                let (status, run) = failure.into_parts();
                std::mem::forget(run);
                panic!("INCOMPLETE: recording retains original owner: {status:?}");
            }
        };
        lifecycle_cases::assert_owner_confirm(fixture.borrow(), &evidence, id);
        assert_quota_presents(fixture.borrow(), &evidence, id);
        for proof in &proofs {
            assert!(proof.supervisor_joined());
        }
        if let Some(executable) = evidence.executable() {
            // Registration and the actual held ELF are joined to Root's
            // separately built production artifact on the same source snapshot.
            gate_record::assert_registered_executable(
                if id == "D02WrongRegisteredDigest" {
                    executable.source_before_sha256
                } else {
                    executable.registered_sha256
                },
                positive && !id.starts_with("D24"),
            );
        }
        if let Some(observed) = &primary_observation {
            let proof = proofs
                .iter()
                .find(|p| p.process_id() == observed.process_id())
                .expect("actual primary child proof");
            assert_eq!(proof.birth_ticks(), observed.birth_ticks());
            assert_eq!(proof.executable_sha256(), observed.executable_sha256());
            if id.starts_with("D04") {
                oracle::assert_sender_binding(&evidence, id, observed.process_id());
            }
            if id.starts_with("D12") {
                oracle::assert_offered_binding(&evidence, id, observed.process_id());
            }
        }
        if let Err(payload) = asserted {
            resume_unwind(payload);
        }
        if positive {
            oracle::assert_positive(&evidence, id);
        } else if id == "D07ObserverOnlyChildOracleReject" {
            oracle::assert_integrity(&evidence, id);
            assert_eq!(evidence.after().document.as_ref().unwrap().bytes, OLD);
            assert_ne!(
                evidence.after().document.as_ref().unwrap().bytes,
                NEW,
                "independent edit oracle rejects observer-only child"
            );
            assert!(
                evidence
                    .controls()
                    .iter()
                    .filter(|r| r.bytes.len() == 88
                        && u32::from_le_bytes(r.bytes[4..8].try_into().unwrap()) == 2)
                    .count()
                    >= 22
            );
        } else {
            oracle::assert_negative(&evidence, id);
        }
        evidence
    }));
    match checked {
        Ok(evidence) => {
            let prior = if id.starts_with("D23") {
                let observed = primary_observation.as_ref().expect("actual oldnativebirth");
                Some((
                    observed.process_id(),
                    observed.birth_ticks(),
                    evidence
                        .before()
                        .document
                        .as_ref()
                        .expect("actual olddocument")
                        .clone(),
                    evidence.active_channel_generation(),
                ))
            } else {
                None
            };
            if let Some(reference) = reference.take() {
                reference.finish();
            }
            let fixture = fixture.release_after_join();
            if !positive
                || matches!(
                    id,
                    "D16LifetimeOffer128ThenFreshReapedChild" | "D23FreshPreviewApprovalNewBirth"
                )
            {
                fresh_desktop_witness(fixture, body, prior);
            } else {
                fixture.finish();
            }
            evidence
        }
        Err(payload) => {
            drop(fixture);
            resume_unwind(payload)
        }
    }
}

fn native_family(id: &str) {
    let family = obligations::family(id);
    for control in &family.controls {
        let actual = ok(desktop::ProcessAssertionScenario::for_case(control.group));
        assert_eq!(actual.len(), control.scenarios.len());
        for (scenario, expected) in actual.iter().zip(&control.scenarios) {
            assert_eq!(scenario.id(), *expected);
            if matches!(
                *expected,
                "D07ParentEditedDraftSourceReject" | "D07ParentRasterWithReportedPidSourceReject"
            ) {
                gate_record::source_substitute_rejected(expected);
                continue;
            }
            if *expected == "D25ScenarioControlRow32769" {
                gate_record::scenario_recording_cap();
                continue;
            }
            if *expected == "D25AggregateControlRow131073" {
                gate_record::aggregate_recording_cap();
                continue;
            }
            if *expected == "D29ForeignNumericPidIsNotOwner" {
                gate_record::assert_api_absent(
                    "D29ForeignNumericPidCannotConstructOwner",
                    "from_pid",
                    "OwnedEditorChild",
                );
                continue;
            }
            if (expected.starts_with("D15Store") || *expected == "D15InflightSaveTwo")
                || *expected == "D26IssuedPermitCannotCancel"
                || *expected == "D25AggregateControlRow131073"
                || *expected == "D29DropIsNotReap"
                || *expected == "D23UnknownCannotChooseOldOrNewBase"
            {
                continue;
            }
            if matches!(*expected, "D28BudgetZero" | "D28Budget5001") {
                let budget = if *expected == "D28BudgetZero" {
                    0
                } else {
                    5001
                };
                assert!(matches!(
                    desktop::ChildBudget::checked(budget),
                    Err(Status::Invalid)
                ));
                continue;
            }
            let evidence = run_native(scenario, false);
            assert_eq!(evidence.scenario_id(), *expected);
        }
    }
    if id != "D03" {
        let positive = ok(desktop::ProcessAssertionScenario::for_case(Box::leak(
            format!("{id}P").into_boxed_str(),
        )));
        assert_eq!(positive.len(), 1);
        assert_eq!(positive[0].id(), family.positive);
        assert_eq!(
            run_native(&positive[0], true).scenario_id(),
            family.positive
        );
    }
}

#[test]
fn process_d01_default_off_build_and_exports() {
    gate_record::default_off_and_child_graph();
}
#[test]
fn process_d02_pinned_actual_editor_and_private_channel() {
    native_family("D02");
}
#[test]
fn process_d03_canonical_wire_exact_closed_inventory() {
    native_family("D03");
}
#[test]
fn process_d04_actual_sender_credentials_not_bootstrap_pid() {
    native_family("D04");
}
#[test]
fn process_d05_ancillary_inventory_truncation_and_cleanup() {
    native_family("D05");
}
#[test]
fn process_d06_genuine_selected_init_and_first_child_frame() {
    native_family("D06");
}
#[test]
fn process_d07_child_local_keyboard_edit_raster_task() {
    genuine_alias_denials();
    native_family("D07");
}
#[test]
fn process_d08_ascii_and_4096_bounds_preserve_prior_draft() {
    native_family("D08");
}
#[test]
fn process_d09_cursor_selection_scroll_exact_state_pixels() {
    native_family("D09");
}
#[test]
fn process_d10_protected_chrome_and_reserved_input_routes() {
    gate_record::assert_api_absent(
        "D10ProtectedChromeFdNotExported",
        "export_process_chrome_fd",
        "HostDesktop",
    );
    native_family("D10");
}
#[test]
fn process_d11_actual_write_seals_and_retained_alias_ebusy() {
    native_family("D11");
}
#[test]
fn process_d12_offered_inode_pair_and_cross_child_denials() {
    native_family("D12");
}
#[test]
fn process_d13_complete_mapping_shape_hash_and_base() {
    native_family("D13");
}
#[test]
fn process_d14_sequence_epoch_ownership_and_single_use() {
    native_family("D14");
}
#[test]
fn process_d15_live_owner_pending_queue_and_save_caps() {
    native_family("D15");
}
#[test]
fn process_d16_lifetime_offer_ledger_bytes_and_no_alias_reuse() {
    native_family("D16");
}
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
#[test]
fn process_d17_genuine_ctrl_s_full_receipt_and_reopen() {
    public_save_lifecycle("process_d17_genuine_ctrl_s_full_receipt_and_reopen");
}
#[test]
fn process_d18_no_save_without_genuine_single_use_capture() {
    native_family("D18");
}
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
#[test]
fn process_d19_newer_draft_keeps_unsaved_after_older_commit() {
    public_interrupted_save(
        "process_d19_newer_draft_keeps_unsaved_after_older_commit",
        SaveInterruption::NewerDraft,
    );
}
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
#[test]
fn process_d20_lost_reply_original_only_recovery_no_replay() {
    public_interrupted_save(
        "process_d20_lost_reply_original_only_recovery_no_replay",
        SaveInterruption::LostCommitReply,
    );
}
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
#[test]
fn process_d21_child_death_before_permit_retains_known_allocation() {
    public_interrupted_save(
        "process_d21_child_death_before_permit_retains_known_allocation",
        SaveInterruption::DeathBeforePermit,
    );
}
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
#[test]
fn process_d22_child_death_after_permit_original_writer_survives() {
    public_interrupted_save(
        "process_d22_child_death_after_permit_original_writer_survives",
        SaveInterruption::DeathAfterPermit,
    );
}
#[test]
fn process_d23_actual_fault_fresh_restart_approval() {
    native_family("D23");
}
#[test]
fn process_d24_stalled_child_unrelated_session_one_second() {
    native_family("D24");
}
#[test]
fn process_d25_flood_eof_short_io_and_backpressure() {
    native_family("D25");
}
#[test]
fn process_d26_revoke_fences_unpermitted_publication_preserves_permit() {
    native_family("D26");
}
#[test]
fn process_d27_focus_compositor_service_reset_and_reserved_reset() {
    native_family("D27");
}
#[test]
fn process_d28_absolute_expiry_death_deadline_no_reset() {
    native_family("D28");
}
#[test]
fn process_d29_real_reap_uncertainty_and_charge_retention() {
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    gate_record::parent_death_and_drop();
    native_family("D29");
}
#[test]
fn process_d30_unchanged_c_consumers_and_integration() {
    gate_record::unchanged_consumers();
}
