//! Gate-first P0 assertions over the real common SaveChains and process wrapper.
//! Deliberately RED until the reviewed process/P3 declarations exist. No Save
//! implementation, lease constructor, receipt setter or result flag lives here.
#![cfg(all(test, feature = "host_editor_process_assertions_v0_dev"))]

use super::*;
use crate::support::{self, *};
use desktop_service::editor_dev::{
    ChildBudget, OwnedEditorChildExitProof, ProcessAssertionEvidence, ProcessAssertionPoint,
    ProcessAssertionRun, ProcessAssertionScenario, ProcessRetireReason,
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

#[path = "../../tests/process_support/fixture.rs"]
#[allow(dead_code)]
mod fixture;
#[path = "../../tests/process_support/gate_record.rs"]
#[allow(dead_code)]
mod gate_record;

struct OwnedApp {
    fixture: Option<Fixture>,
    app: Option<ProcessArtifactEditor>,
    other: Option<ProcessArtifactEditor>,
    third: Option<ProcessArtifactEditor>,
    intercepted: Option<InterceptedReply>,
    unexpected_intent: Option<desktop::NativeSaveIntent>,
    run: Option<ProcessAssertionRun>,
    proofs: Vec<OwnedEditorChildExitProof>,
    cleanup_deadline: Option<Instant>,
}

struct PanicOwners<T>(Option<T>);
impl<T> PanicOwners<T> {
    fn new(value: T) -> Self {
        Self(Some(value))
    }
}
impl<T> std::ops::Deref for PanicOwners<T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.0.as_ref().unwrap()
    }
}
impl<T> std::ops::DerefMut for PanicOwners<T> {
    fn deref_mut(&mut self) -> &mut T {
        self.0.as_mut().unwrap()
    }
}
impl<T> Drop for PanicOwners<T> {
    fn drop(&mut self) {
        if thread::panicking() {
            std::mem::forget(self.0.take());
        }
    }
}

struct InterceptedReply {
    chain: SaveChain,
    flight: Option<Flight>,
    reply: Option<store::NativeSaveReply>,
}

struct ReleaseCheckpoint<'a> {
    run: &'a mut ProcessAssertionRun,
    point: ProcessAssertionPoint,
    stop: Arc<AtomicBool>,
}
impl Drop for ReleaseCheckpoint<'_> {
    fn drop(&mut self) {
        // Installed before waiting for actual reach. Releasing the borrower is not reap.
        let _ = self.run.release(self.point);
        self.stop.store(true, Ordering::Release);
    }
}

impl Drop for OwnedApp {
    fn drop(&mut self) {
        if self.fixture.is_some() {
            // An assertion/constructor panic is not an absence, reap or Store
            // producer join. Keep the complete parents alongside actual child
            // and recording owners rather than deleting their durable root.
            eprintln!("INCOMPLETE: quarantining actual process app and Store parents");
            std::mem::forget(self.app.take());
            std::mem::forget(self.other.take());
            std::mem::forget(self.third.take());
            std::mem::forget(self.intercepted.take());
            std::mem::forget(self.unexpected_intent.take());
            std::mem::forget(self.run.take());
            std::mem::forget(self.fixture.take());
        }
    }
}

impl OwnedApp {
    fn open(case: &'static str, scenario: &ProcessAssertionScenario) -> Self {
        let mut owner = Self {
            fixture: Some(fixture::fixture(
                Box::leak(format!("app_{}", case.to_ascii_lowercase()).into_boxed_str()),
                if case == "D15StoreIoThree" { 3 } else { 2 },
            )),
            app: None,
            other: None,
            third: None,
            intercepted: None,
            unexpected_intent: None,
            run: None,
            proofs: Vec::new(),
            cleanup_deadline: None,
        };
        let f = owner.fixture.as_mut().unwrap();
        let launch = f.launch(0, 101, 1);
        let desktop = f.h.clone();
        let store = f.host();
        let controller = f.dc.clone();
        let (sender, receiver) = mpsc::sync_channel(1);
        // Only the actual common open path performs Read/prepare/registration.
        // Run is sent before a child rendezvous can block this scoped owner.
        let opened = thread::scope(|scope| {
            let pending = scope.spawn(move || {
                ProcessArtifactEditor::open_assertion(
                    desktop,
                    store,
                    launch,
                    ok(ChildBudget::checked(5000)),
                    1,
                    &controller,
                    scenario,
                    sender,
                )
            });
            owner.run = Some(
                receiver
                    .recv_timeout(Duration::from_millis(1000))
                    .expect("actual one-shot assertion Run before spawn rendezvous"),
            );
            pending
                .join()
                .expect("open must return every owner rather than unwind")
        });
        match opened {
            Ok(app) => owner.app = Some(app),
            Err(failure) => {
                let (_, app) = failure.into_parts();
                owner.app = Some(app);
                panic!("genuine approved process open failed; owners retained");
            }
        }
        owner.until(1, |observation| observation.bytes == OLD);
        owner.fixture.as_mut().unwrap().join_all();
        let app = owner.app.as_ref().unwrap();
        let native = ok(app
            .chains
            .desktop
            .observe_process_child(app.child.as_ref().unwrap()));
        assert!(native.process_id() > 0 && native.birth_ticks() > 0);
        assert!(native.publication_generation() > 0);
        owner
    }

    fn parts(&mut self) -> (&mut Fixture, &mut ProcessArtifactEditor) {
        (self.fixture.as_mut().unwrap(), self.app.as_mut().unwrap())
    }

    fn open_other(&mut self, now: u64) {
        let f = self.fixture.as_mut().unwrap();
        let launch = f.launch(1, 102, now);
        self.other = Some(
            match ProcessArtifactEditor::open(
                f.h.clone(),
                f.host(),
                launch,
                ok(ChildBudget::checked(5000)),
                now,
            ) {
                Ok(app) => app,
                Err(failure) => {
                    let (_, app) = failure.into_parts();
                    self.other = Some(app);
                    panic!("other genuine process open failed; retain both actual parents");
                }
            },
        );
        if let Some(run) = self.run.as_mut() {
            let f = self.fixture.as_ref().unwrap();
            let sibling = self.other.as_ref().unwrap().child.as_ref().unwrap();
            ok(f.dc.reference_process_assertion(run, sibling));
        }
        let compositor = self.fixture.as_ref().unwrap().drivers[1]
            .s
            .compositor
            .clone();
        let end = Instant::now() + Duration::from_millis(1000);
        loop {
            let app = self.other.as_mut().unwrap();
            ok(step_composed(app, &compositor, now));
            match app.observe(now) {
                Ok(observation) if observation.bytes == B => break,
                Ok(_) | Err(NativeEditorError::Desktop(Status::NotReady | Status::Stale)) => {}
                Err(error) => panic!("independent process observation denied:{error:?}"),
            }
            assert!(
                Instant::now() < end,
                "independent genuine child first publication"
            );
        }
    }

    fn other_chord(&mut self, key: u32, now: u64) {
        let f = self.fixture.as_mut().unwrap();
        let app = self.other.as_mut().unwrap();
        for (usage, phase) in [(224, 1), (key, 1), (key, 2), (224, 2)] {
            delivered(f, app, 1, usage, phase, now);
        }
    }

    fn replace_other(&mut self, body: &[u8], now: u64) {
        self.other_chord(4, now);
        let f = self.fixture.as_mut().unwrap();
        let app = self.other.as_mut().unwrap();
        for &byte in body {
            delivered(f, app, 1, usage(byte), 1, now);
            delivered(f, app, 1, usage(byte), 2, now);
        }
        ok(app
            .chains
            .desktop
            .request_process_editor_frame(app.child.as_mut().unwrap(), now));
        let end = Instant::now() + Duration::from_millis(1000);
        loop {
            ok(step_composed(app, &f.drivers[1].s.compositor, now));
            if ok(app.observe(now)).bytes == body {
                break;
            }
            assert!(
                Instant::now() < end,
                "other session publishes without waiting for held writer"
            );
        }
        let frame = ok(f.h.compose_native_save(&f.drivers[1].s.compositor, now));
        assert_eq!(frame.bgra.len(), 640 * 568 * 4);
    }

    fn save_other(&mut self, revision: u64, now: u64) {
        self.other_chord(22, now);
        let compositor = self.fixture.as_ref().unwrap().drivers[1]
            .s
            .compositor
            .clone();
        let end = Instant::now() + Duration::from_millis(1000);
        loop {
            let app = self.other.as_mut().unwrap();
            ok(step_composed(app, &compositor, now));
            if ok(app.observe(now)).confirmed_revision == revision {
                break;
            }
            assert!(Instant::now() < end, "unrelated genuine Save settles");
        }
        assert_eq!(self.fixture.as_ref().unwrap().counts(102), (1, 1, 1));
    }

    fn until(&mut self, now: u64, predicate: impl Fn(&desktop::NativeEditorObservation) -> bool) {
        let end = Instant::now() + Duration::from_millis(1000);
        loop {
            let (f, app) = self.parts();
            match step_composed(app, &f.drivers[0].s.compositor, now) {
                Ok(_) | Err(NativeEditorError::Desktop(Status::Stale | Status::NotReady)) => {}
                Err(error) => panic!("current process progress denied:{error:?}"),
            }
            match app.observe(now) {
                Ok(observation) if predicate(&observation) => return,
                Ok(_) | Err(NativeEditorError::Desktop(Status::NotReady | Status::Stale)) => {}
                Err(error) => panic!("current process observation denied:{error:?}"),
            }
            if Instant::now() >= end {
                let current = app.observe(now).map(|view| {
                    (
                        view.phase,
                        view.confirmed_revision,
                        view.text_generation,
                        view.view_version,
                        view.bytes.len(),
                    )
                });
                let pending: Vec<_> = app
                    .chains
                    .pending
                    .iter()
                    .map(|chain| {
                        (
                            match chain.stage {
                                Stage::Allocate => "Allocate",
                                Stage::Commit => "Commit",
                                Stage::ObserveAllocation => "ObserveAllocation",
                                Stage::ObserveCommit => "ObserveCommit",
                            },
                            chain.binding.as_ref().map(|b| b.allocation.operation_id),
                            chain.flight.is_some(),
                            chain.lookup.is_some(),
                            chain.continuation_allowed,
                        )
                    })
                    .collect();
                panic!(
                    "original bounded process observation: current_phase_revision_text_view_len={current:?} pending_stage_operation_flight_lookup_continuation={pending:?} actual_store_counts={:?}",
                    f.counts(101)
                );
            }
            thread::yield_now();
        }
    }

    fn event(&mut self, usage: u32, phase: u32, now: u64) {
        let (f, app) = self.parts();
        delivered(f, app, 0, usage, phase, now);
    }

    fn chord(&mut self, usage: u32, now: u64) {
        for (key, phase) in [(224, 1), (usage, 1), (usage, 2), (224, 2)] {
            self.event(key, phase, now);
        }
    }

    fn replace(&mut self, body: &[u8], now: u64) {
        self.edit_without_frame(body, now);
        let (_, app) = self.parts();
        ok(app
            .chains
            .desktop
            .request_process_editor_frame(app.child.as_mut().unwrap(), now));
        self.until(now, |observation| observation.bytes == body);
    }

    fn edit_without_frame(&mut self, body: &[u8], now: u64) {
        self.chord(4, now);
        for &byte in body {
            self.event(usage(byte), 1, now);
            self.event(usage(byte), 2, now);
        }
    }

    fn race_old_receipt_with_pending_pair(&mut self, pause: &store::PauseToken, now: u64) {
        self.edit_without_frame(C, now);
        let app = self.app.as_mut().unwrap();
        let desktop = app.chains.desktop.clone();
        ok(desktop.request_process_editor_frame(app.child.as_mut().unwrap(), now));
        let child = app.child.as_mut().unwrap();
        let chains = &mut app.chains;
        let f = self.fixture.as_mut().unwrap();
        let run = self.run.as_mut().unwrap();
        let compositor = f.drivers[0].s.compositor.clone();
        let stop = Arc::new(AtomicBool::new(false));
        thread::scope(|scope| {
            let finished = stop.clone();
            let borrower = scope.spawn(move || {
                let end = Instant::now() + Duration::from_millis(5000);
                while !finished.load(Ordering::Acquire) {
                    match desktop.pump_process_editor(child, now) {
                        Ok(step) => {
                            if step.publication_accepted() {
                                ok(desktop.compose_native_save(&compositor, now));
                            }
                        }
                        Err(error) => return Some(error.status()),
                    }
                    assert!(Instant::now() < end);
                }
                None
            });
            let point = ProcessAssertionPoint::PairValidatedBeforeAdopt;
            let release = ReleaseCheckpoint { run, point, stop };
            let checkpoint = ok(release.run.wait_checkpoint(point, 1000));
            assert_eq!(checkpoint.point(), point);
            assert_eq!(f.counts(101), (1, 1, 0));
            ok(f.prepared().controller().release(pause));
            assert!(ok(pause.wait_until_settled(1000)).settled);
            f.join_all();
            let end = Instant::now() + Duration::from_millis(1000);
            while !chains.pending.is_empty() {
                ok(chains.progress_all(now));
                assert!(
                    Instant::now() < end,
                    "same original common owner settles while child pump is held"
                );
            }
            assert_eq!(f.counts(101), (1, 1, 1));
            assert_eq!(object(f, 101).selected.revision, 2);
            let still_old_pixels = ok(f.h.compose_native_save(&f.drivers[0].s.compositor, now));
            let chrome = ok(f.dc.save_chrome_observation(&f.drivers[0].s.compositor));
            assert_ne!(
                chrome.label,
                desktop::NativeEditorPhase::Saved,
                "an ACKed newer text generation cannot flash Saved before pair adoption"
            );
            support::protected_golden(&still_old_pixels, "UNSAVED", "");
            fixture::expected_crop(&still_old_pixels, true);
            drop(release);
            assert!(matches!(
                borrower.join().unwrap(),
                None | Some(Status::Stale)
            ));
        });
    }

    fn pause(&mut self, point: store::PausePoint) -> Arc<store::PauseToken> {
        let (f, app) = self.parts();
        let owner = f.prepared.as_ref().unwrap().clone();
        let pause = Arc::new(ok(owner
            .controller()
            .pause_native_save(app.chains.launch.endpoint(), point)));
        f.store_pauses.push((owner, pause.clone()));
        pause
    }

    fn reach_pause(&mut self, pause: &store::PauseToken, now: u64) -> store::BarrierSnapshot {
        let end = Instant::now() + Duration::from_millis(1000);
        loop {
            match pause.wait_until_entered(1) {
                Ok(actual) => {
                    assert!(actual.entered);
                    return actual;
                }
                Err(error) => assert_eq!(error.status, StoreStatus::Timeout),
            }
            ok(step_composed(
                self.app.as_mut().unwrap(),
                &self.fixture.as_ref().unwrap().drivers[0].s.compositor,
                now,
            ));
            assert!(
                Instant::now() < end,
                "real Store writer reaches exact pause"
            );
        }
    }

    fn reach_other_pause(&mut self, pause: &store::PauseToken, now: u64) {
        let end = Instant::now() + Duration::from_millis(1000);
        loop {
            match pause.wait_until_entered(1) {
                Ok(actual) => {
                    assert!(actual.entered);
                    break;
                }
                Err(error) => assert_eq!(error.status, StoreStatus::Timeout),
            }
            ok(step_composed(
                self.other.as_mut().unwrap(),
                &self.fixture.as_ref().unwrap().drivers[1].s.compositor,
                now,
            ));
            assert!(Instant::now() < end);
        }
    }

    fn release_pause(&mut self, pause: &store::PauseToken) {
        let f = self.fixture.as_mut().unwrap();
        ok(f.prepared().controller().release(pause));
        assert!(ok(pause.wait_until_settled(1000)).settled);
        f.join_all();
    }

    fn save(&mut self, revision: u64, now: u64) {
        self.chord(22, now);
        self.until(now, |observation| {
            observation.confirmed_revision == revision
        });
        let (f, app) = self.parts();
        let frame = ok(f.h.compose_native_save(&f.drivers[0].s.compositor, now));
        assert_eq!(
            ok(app.observe(now)).phase,
            desktop::NativeEditorPhase::Saved
        );
        let chrome = ok(f.dc.save_chrome_observation(&f.drivers[0].s.compositor));
        assert_eq!(chrome.label, desktop::NativeEditorPhase::Saved);
        assert_eq!(frame.bgra.len(), 640 * 568 * 4);
        f.join_all();
    }

    fn queue_chord(&mut self, usage: u32, now: u64) {
        let f = self.fixture.as_mut().unwrap();
        for (key, phase) in [(224, 1), (usage, 1), (usage, 2), (224, 2)] {
            f.drivers[0].send(&f.h, key, phase, now);
        }
    }

    fn at_checkpoint(
        &mut self,
        point: ProcessAssertionPoint,
        now: u64,
        inspect: impl FnOnce(&mut Fixture, &desktop::ProcessAssertionCheckpoint),
    ) {
        let app = self.app.as_mut().unwrap();
        let f = self.fixture.as_mut().unwrap();
        let run = self.run.as_mut().unwrap();
        let compositor = f.drivers[0].s.compositor.clone();
        let stop = Arc::new(AtomicBool::new(false));
        thread::scope(|scope| {
            let finished = stop.clone();
            let borrower = scope.spawn(move || {
                let end = Instant::now() + Duration::from_millis(5000);
                while !finished.load(Ordering::Acquire) {
                    if let Err(error) = step_composed(app, &compositor, now) {
                        return Some(error);
                    }
                    assert!(
                        Instant::now() < end,
                        "original child lifetime bounds borrower work"
                    );
                    thread::yield_now();
                }
                None
            });
            let release = ReleaseCheckpoint { run, point, stop };
            let checkpoint = ok(release.run.wait_checkpoint(point, 1000));
            assert_eq!(checkpoint.point(), point);
            assert!(checkpoint.sequence() > 0);
            inspect(f, &checkpoint);
            drop(release);
            let _actual_terminal_error = borrower.join().expect("borrower returns owners on error");
        });
    }

    fn retire_and_join(&mut self, reason: ProcessRetireReason, now: u64) {
        let deadline = *self
            .cleanup_deadline
            .get_or_insert_with(|| Instant::now() + Duration::from_millis(2000));
        let app = self.app.as_mut().unwrap();
        if app.child.is_none() {
            return;
        }
        match app.retire(reason, now) {
            Ok(()) | Err(NativeEditorError::Desktop(Status::Disconnected | Status::Stale)) => {}
            Err(error) => panic!("INCOMPLETE: retire failed with genuine owner retained:{error:?}"),
        }
        loop {
            match app.join_child() {
                Ok(proof) => {
                    assert!(proof.process_id() > 0 && proof.birth_ticks() > 0);
                    assert!(proof.supervisor_joined());
                    self.proofs.push(proof);
                    break;
                }
                Err(NativeEditorError::Desktop(Status::NotReady)) => {
                    assert!(app.child.is_some(), "nonterminal join returns sole child");
                    assert!(Instant::now() < deadline, "cleanup deadline never renewed");
                    thread::yield_now();
                }
                Err(error) => panic!("INCOMPLETE: actual child cleanup unproved: {error:?}"),
            }
        }
    }

    fn reopen_child(&mut self, expected: &[u8], now: u64) {
        self.retire_and_join(ProcessRetireReason::HumanClose, now);
        let (_, app) = self.parts();
        ok(app.reconcile_originals(now));
        assert!(
            app.chains.pending.is_empty(),
            "no original owner silently discarded on reopen"
        );
        self.app.take();
        let f = self.fixture.as_mut().unwrap();
        let launch = f.launch(0, 101, now);
        self.app = Some(
            match ProcessArtifactEditor::open(
                f.h.clone(),
                f.host(),
                launch,
                ok(ChildBudget::checked(5000)),
                now,
            ) {
                Ok(app) => app,
                Err(failure) => {
                    let (_, app) = failure.into_parts();
                    self.app = Some(app);
                    panic!("fresh approved child reopen failed");
                }
            },
        );
        self.cleanup_deadline = None; // New actual child, not a retry of old cleanup.
        self.until(now, |observation| observation.bytes == expected);
    }

    fn finish(mut self, now: u64) -> ProcessAssertionEvidence {
        self.retire_and_join(ProcessRetireReason::HumanClose, now);
        for slot in [&mut self.other, &mut self.third] {
            if let Some(other) = slot.as_mut() {
                ok(other.retire(ProcessRetireReason::HumanClose, now));
                let end = Instant::now() + Duration::from_millis(2000);
                loop {
                    match other.join_child() {
                        Ok(proof) => {
                            assert!(proof.supervisor_joined());
                            self.proofs.push(proof);
                            break;
                        }
                        Err(NativeEditorError::Desktop(Status::NotReady)) => {
                            assert!(Instant::now() < end)
                        }
                        Err(error) => panic!("other genuine child cleanup incomplete:{error:?}"),
                    }
                }
                ok(other.reconcile_originals(now));
                assert!(other.chains.pending.is_empty());
                slot.take();
            }
        }
        let (f, app) = self.parts();
        ok(app.reconcile_originals(now));
        assert!(
            app.chains.pending.is_empty(),
            "genuine originals settled before parent teardown"
        );
        f.join_all();
        let run = self.run.take().unwrap();
        let evidence = match run.finish_recording() {
            Ok(evidence) => evidence,
            Err(failure) => {
                let (_, run) = failure.into_parts();
                self.run = Some(run);
                panic!("INCOMPLETE: recording retains genuine native owner");
            }
        };
        assert!(!evidence.quarantined());
        assert!(evidence.supervisor_joined());
        self.app.take();
        self.fixture.take().unwrap().finish();
        evidence
    }
}

fn step_composed(
    app: &mut ProcessArtifactEditor,
    compositor: &desktop::Endpoint,
    now: u64,
) -> Result<desktop::ProcessEditorStep, NativeEditorError> {
    let step = app.step(now)?;
    if step.publication_accepted() {
        app.chains.desktop.compose_native_save(compositor, now)?;
    }
    Ok(step)
}

fn delivered(
    f: &mut Fixture,
    app: &mut ProcessArtifactEditor,
    session: usize,
    usage: u32,
    phase: u32,
    now: u64,
) {
    f.drivers[session].send(&f.h, usage, phase, now);
    let sequence = f.drivers[session].next - 1;
    let end = Instant::now() + Duration::from_millis(1000);
    loop {
        match step_composed(app, &f.drivers[session].s.compositor, now) {
            Ok(step) if step.consumed_sequence() == Some(sequence) => break,
            Ok(_) => {}
            Err(NativeEditorError::Desktop(Status::Stale)) if app.observe(now).is_ok() => {}
            Err(error) => panic!(
                "actual input progress denied: session={session} usage={usage} phase={phase} sequence={sequence} error={error:?} current_observation={:?}",
                app.observe(now)
                    .map(|view| (view.phase, view.confirmed_revision))
            ),
        }
        assert!(
            Instant::now() < end,
            "each actual Focus delivery is acknowledged"
        );
        thread::yield_now();
    }
}

fn actual_original(owner: &mut OwnedApp) -> (u64, Instant, Instant, EditorSaveBindingV0) {
    let app = owner.app.as_ref().unwrap();
    assert_eq!(app.chains.pending.len(), 1);
    let chain = &app.chains.pending[0];
    let binding = chain
        .binding
        .clone()
        .expect("actual parent source/operation binding");
    assert_eq!(chain.intent.snapshot().body(), NEW);
    assert_eq!(
        binding.source.content_hash,
        chain.intent.snapshot().view().source_content_hash
    );
    (
        binding.allocation.operation_id,
        chain.intent.entered(),
        chain.intent.deadline(),
        binding,
    )
}

fn assert_receipt(owner: &OwnedApp, operation: u64, body: &[u8]) {
    let f = owner.fixture.as_ref().unwrap();
    let app = owner.app.as_ref().unwrap();
    let record = object(f, 101);
    let row = record
        .operations
        .iter()
        .find(|row| row.allocation.operation_id == operation)
        .unwrap();
    let binding = row.binding.as_ref().unwrap();
    let receipt = row.receipt.as_ref().unwrap();
    let bytes = ok(receipt.encode_le());
    assert_eq!(bytes.len(), 176);
    ok(receipt.validate_binding(binding));
    assert_eq!(
        receipt.backend_service_epoch,
        row.submitted_service_epoch.unwrap()
    );
    app_chain_artifacts(
        f,
        101,
        body,
        operation,
        &binding.allocation.actor,
        app.chains.launch.endpoint().handle,
    );
    assert_eq!(selected_blob(f, 101), body);
}

fn assert_original_held(owner: &OwnedApp, operation: u64, entered: Instant, deadline: Instant) {
    let app = owner.app.as_ref().unwrap();
    assert_eq!(app.chains.pending.len(), 1);
    let chain = &app.chains.pending[0];
    assert_eq!(
        (chain.intent.entered(), chain.intent.deadline()),
        (entered, deadline)
    );
    assert_eq!(
        chain.binding.as_ref().unwrap().allocation.operation_id,
        operation
    );
    assert!(chain.original.is_some() || chain.flight.is_some());
}

fn settle_original(owner: &mut OwnedApp, revision: u64, now: u64) {
    let end = Instant::now() + Duration::from_millis(1000);
    loop {
        let app = owner.app.as_mut().unwrap();
        if let Err(error) = app.reconcile_originals(now) {
            let retained: Vec<_> = app
                .chains
                .pending
                .iter()
                .map(|chain| {
                    (
                        match chain.stage {
                            Stage::Allocate => "Allocate",
                            Stage::Commit => "Commit",
                            Stage::ObserveAllocation => "ObserveAllocation",
                            Stage::ObserveCommit => "ObserveCommit",
                        },
                        chain.flight.is_some(),
                        chain.flight.as_ref().is_some_and(|f| f.execution.is_some()),
                        chain.lookup.is_some(),
                        chain.original.is_some(),
                    )
                })
                .collect();
            panic!(
                "actual original reconciliation denied: error={error:?} retained_stage_flight_execution_lookup_original={retained:?} child_retained={}",
                app.child.is_some()
            );
        }
        if owner.app.as_ref().unwrap().chains.pending.is_empty() {
            break;
        }
        assert!(
            Instant::now() < end,
            "original-only reconciliation remains bounded"
        );
        thread::yield_now();
    }
    assert_eq!(
        object(owner.fixture.as_ref().unwrap(), 101)
            .selected
            .revision,
        revision
    );
}

#[test]
fn process_d17_genuine_ctrl_s_full_receipt_and_reopen() {
    gate_record::assert_api_absent(
        "D17ChildReceiptSetterApiAbsent",
        "set_receipt",
        "desktop_service::editor_dev::OwnedEditorChild",
    );
    gate_record::assert_api_absent(
        "D17CopiedAllocationCannotMintIntent",
        "from_allocation",
        "desktop_service::editor_dev::NativeSaveIntent",
    );
    for case in ["D17C01", "D17C02", "D17P"] {
        for scenario in ok(ProcessAssertionScenario::for_case(case)) {
            let mut owner = OwnedApp::open(scenario.id(), scenario);
            owner.replace(NEW, 2);
            let pause = owner.pause(store::PausePoint::AfterCommitPermit);
            owner.chord(22, 2);
            assert!(owner.reach_pause(&pause, 2).permit_issued);
            let (operation, entered, deadline, binding) = actual_original(&mut owner);
            assert_eq!(owner.fixture.as_ref().unwrap().counts(101), (1, 1, 0));
            owner.release_pause(&pause);
            // Retain the actual chain, Flight and genuine reply. The normal
            // common progress path delegates this same ownership to accept_reply.
            let app = owner.app.as_mut().unwrap();
            owner.intercepted = Some(InterceptedReply {
                chain: app.chains.pending.remove(0),
                flight: None,
                reply: None,
            });
            let held = owner.intercepted.as_mut().unwrap();
            held.flight = held.chain.flight.take();
            assert!(matches!(held.chain.stage, Stage::Commit));
            // The IO worker can settle the pause before the dispatcher has
            // constructed/transferred its reply. join_all is nonblocking too.
            // Poll only this retained execution under its original deadline.
            loop {
                assert!(
                    Instant::now() < deadline,
                    "original Commit reply readiness deadline: operation={operation} elapsed={:?}",
                    entered.elapsed()
                );
                let reply = ok(held
                    .flight
                    .as_ref()
                    .unwrap()
                    .execution
                    .as_ref()
                    .unwrap()
                    .poll_once());
                if let Some(reply) = reply {
                    held.reply = Some(reply);
                    break;
                }
                thread::yield_now();
            }
            let chain = &mut held.chain;
            let reply = held.reply.as_ref().unwrap();
            let response = ok(artifact::CommitReply::decode(reply.wire()));
            let lease = reply.receipt().expect("genuine immutable receipt lease");
            let original_binding = chain.binding.clone();
            let expected_error = match scenario.id() {
                "D17ShortReceipt" => app.chains.validate_receipt(
                    &chain,
                    lease,
                    operation,
                    response.revision,
                    response.receipt_shm,
                    175,
                ),
                "D17ForeignReceiptBinding" => {
                    chain
                        .binding
                        .as_mut()
                        .unwrap()
                        .allocation
                        .actor
                        .instance_generation += 1;
                    app.chains.validate_receipt(
                        &chain,
                        lease,
                        operation,
                        response.revision,
                        response.receipt_shm,
                        176,
                    )
                }
                "D17ReceiptHashMismatch" => {
                    chain.binding.as_mut().unwrap().source.content_hash[31] ^= 1;
                    app.chains.validate_receipt(
                        &chain,
                        lease,
                        operation,
                        response.revision,
                        response.receipt_shm,
                        176,
                    )
                }
                "D17ReceiptRevisionMismatch" => app.chains.validate_receipt(
                    &chain,
                    lease,
                    operation,
                    response.revision.checked_add(1).unwrap(),
                    response.receipt_shm,
                    176,
                ),
                "D17OneGenuineSaveReceiptAndFreshChildReopen" => Ok(()),
                other => panic!("unreviewed app receipt case {other}"),
            };
            chain.binding = original_binding;
            if scenario.id() != "D17OneGenuineSaveReceiptAndFreshChildReopen" {
                assert_eq!(expected_error, Err(NativeEditorError::InvalidReceipt));
            }
            assert_eq!(
                (chain.intent.entered(), chain.intent.deadline()),
                (entered, deadline)
            );
            assert_eq!(chain.binding.as_ref(), Some(&binding));
            assert_eq!(owner.fixture.as_ref().unwrap().counts(101), (1, 1, 1));
            let held = owner.intercepted.as_mut().unwrap();
            let accepted = app.chains.accept_reply(
                &mut held.chain,
                held.flight.take().unwrap(),
                held.reply.take().unwrap(),
                3,
            );
            match accepted {
                Ok(true) => app
                    .chains
                    .pending
                    .push(owner.intercepted.take().unwrap().chain),
                Ok(false) => {
                    owner.intercepted.take();
                }
                Err(error) => {
                    panic!("actual reply acceptance failed; genuine chain remains staged:{error:?}")
                }
            }
            owner.until(3, |observation| observation.confirmed_revision == 2);
            assert_receipt(&owner, operation, NEW);
            owner.reopen_child(NEW, 3);
            owner.replace(OLD, 4);
            owner.save(3, 4);
            assert_eq!(owner.fixture.as_ref().unwrap().counts(101), (2, 2, 2));
            let evidence = owner.finish(4);
            assert_eq!(evidence.scenario_id(), scenario.id());
        }
    }
}

#[test]
fn process_d19_newer_draft_keeps_unsaved_after_older_commit() {
    for case in ["D19C01", "D19C02", "D19C03", "D19P"] {
        for scenario in ok(ProcessAssertionScenario::for_case(case)) {
            let mut owner = OwnedApp::open(scenario.id(), scenario);
            owner.replace(NEW, 2);
            let pause = owner.pause(store::PausePoint::AfterCommitPermit);
            owner.chord(22, 2);
            assert!(owner.reach_pause(&pause, 2).permit_issued);
            let (operation, entered, deadline, _) = actual_original(&mut owner);
            let raced = scenario.id() == "D19OlderReceiptThenFreshAuthorizedSave";
            if raced {
                owner.race_old_receipt_with_pending_pair(&pause, 2);
            } else {
                owner.replace(C, 2);
            }
            if scenario.id() == "D19RepeatSaveWhileUnknown" {
                // The actual original deadline expires while its permitted
                // Store writer remains held. No synthetic phase setter.
                owner.until(2, |view| view.phase == desktop::NativeEditorPhase::Unknown);
            }
            if !raced {
                let before = owner.fixture.as_ref().unwrap().counts(101);
                owner.chord(22, 2);
                assert_eq!(owner.fixture.as_ref().unwrap().counts(101), before);
                assert_eq!(before, (1, 1, 0));
                assert_original_held(&owner, operation, entered, deadline);
                owner.release_pause(&pause);
            }
            settle_original(&mut owner, 2, 3);
            owner.until(3, |view| view.confirmed_revision == 2 && view.bytes == C);
            assert_eq!(
                ok(owner.app.as_ref().unwrap().observe(3)).phase,
                desktop::NativeEditorPhase::Unsaved
            );
            assert_receipt(&owner, operation, NEW);
            assert_eq!(owner.fixture.as_ref().unwrap().counts(101), (1, 1, 1));
            owner.save(3, 4);
            assert_eq!(owner.fixture.as_ref().unwrap().counts(101), (2, 2, 2));
            assert_eq!(selected_blob(owner.fixture.as_ref().unwrap(), 101), C);
            let evidence = owner.finish(4);
            if raced {
                assert_eq!(evidence.after().adoption_status, Some(Status::Stale));
                assert_eq!(evidence.before().app_pixels, evidence.after().app_pixels);
                assert_eq!(
                    evidence.before().publication_generation,
                    evidence.after().publication_generation
                );
                assert_eq!(
                    evidence.before().owners.lifetime_objects,
                    evidence.after().owners.lifetime_objects,
                    "obsolete pair denial does not refund object credits"
                );
                if let (Some(before), Some(after)) = (
                    evidence.before().save_deadline,
                    evidence.after().save_deadline,
                ) {
                    assert_eq!(before, after);
                }
            }
        }
    }
}

#[test]
fn process_d20_lost_reply_original_only_recovery_no_replay() {
    for case in ["D20C01", "D20C02", "D20C03", "D20C04", "D20P"] {
        for scenario in ok(ProcessAssertionScenario::for_case(case)) {
            let mut owner = OwnedApp::open(scenario.id(), scenario);
            owner.replace(NEW, 2);
            let pause = owner.pause(store::PausePoint::AfterCommitPermit);
            owner.chord(22, 2);
            assert!(owner.reach_pause(&pause, 2).permit_issued);
            let (operation, entered, deadline, binding) = actual_original(&mut owner);
            {
                let (f, app) = owner.parts();
                ok(f.prepared()
                    .controller()
                    .drop_next_native_reply(app.chains.launch.endpoint()));
            }
            owner.retire_and_join(ProcessRetireReason::ChildFault, 2);
            assert_original_held(&owner, operation, entered, deadline);
            assert_eq!(owner.fixture.as_ref().unwrap().counts(101), (1, 1, 0));
            let other_pause = if matches!(
                scenario.id(),
                "D20ForeignOriginalOwnerDenied" | "D20NewIntentCannotReconcileOld"
            ) {
                owner.open_other(3);
                owner.replace_other(C, 3);
                let f = owner.fixture.as_mut().unwrap();
                let app = owner.other.as_ref().unwrap();
                let p = Arc::new(ok(f.prepared().controller().pause_native_save(
                    app.chains.launch.endpoint(),
                    store::PausePoint::AfterCommitPermit,
                )));
                f.store_pauses
                    .push((f.prepared.as_ref().unwrap().clone(), p.clone()));
                owner.other_chord(22, 3);
                owner.reach_other_pause(&p, 3);
                Some(p)
            } else {
                None
            };
            {
                let app = owner.app.as_ref().unwrap();
                let chain = &app.chains.pending[0];
                let original = chain
                    .flight
                    .as_ref()
                    .map(|flight| flight.registered.original())
                    .or(chain.original.as_ref())
                    .unwrap();
                let mut valid = super::canonical(
                    artifact::SaveStatus {
                        request_id: 800,
                        session_id: binding.allocation.actor.session_id,
                        session_generation: binding.allocation.actor.session_generation,
                        operation_id: operation,
                    }
                    .encode(app.chains.launch.endpoint().handle)
                    .unwrap(),
                )
                .unwrap();
                match scenario.id() {
                    "D20ForeignOriginalOwnerDenied" => {
                        let foreign = owner.other.as_ref().unwrap().chains.pending[0]
                            .flight
                            .as_ref()
                            .unwrap()
                            .registered
                            .original();
                        assert!(
                            matches!(
                                app.chains.desktop.begin_save_recovery(
                                    foreign.observation_origin(),
                                    &valid,
                                    3
                                ),
                                Err(Status::Denied)
                            ),
                            "actual independently issued original B cannot observe original A"
                        );
                    }
                    "D20NewIntentCannotReconcileOld" => {
                        let newer = &owner.other.as_ref().unwrap().chains.pending[0].intent;
                        let actor = newer.snapshot().view().actor;
                        assert_ne!(actor, binding.allocation.actor);
                        valid.payload[8..16].copy_from_slice(&actor.session_id.to_le_bytes());
                        valid.payload[16..24]
                            .copy_from_slice(&actor.session_generation.to_le_bytes());
                        assert!(
                            matches!(
                                app.chains.desktop.begin_save_recovery(
                                    original.observation_origin(),
                                    &valid,
                                    3
                                ),
                                Err(Status::Denied)
                            ),
                            "genuine newer intent identity cannot rebind old original recovery"
                        );
                    }
                    "D20OriginalAllocationCountPreserved" => {
                        assert!(
                            matches!(
                                app.chains.desktop.begin_save_allocate(
                                    app.chains.launch.desktop().bindings().artifact_origin(),
                                    &chain.intent,
                                    ok(chain.allocation_request()),
                                    3
                                ),
                                Err(Status::Denied | Status::Stale | Status::NotReady)
                            ),
                            "actual old allocation request and consumed genuine intent cannot reset allocation count"
                        );
                        assert_eq!(owner.fixture.as_ref().unwrap().counts(101), (1, 1, 0));
                        assert_eq!(
                            object(owner.fixture.as_ref().unwrap(), 101)
                                .operations
                                .len(),
                            1
                        );
                    }
                    "D20OrdinaryRetiredLookupDenied" | "D20OriginalLookupThenFreshRestart" => {
                        assert!(matches!(
                            app.chains.desktop.begin_save_status(
                                app.chains.launch.desktop().bindings().artifact_origin(),
                                &valid,
                                3
                            ),
                            Err(Status::Denied | Status::Stale)
                        ));
                    }
                    other => panic!("unreviewed original recovery case {other}"),
                }
                assert_eq!(
                    chain.intent.snapshot().view().actor,
                    binding.allocation.actor
                );
            }
            if let Some(p) = &other_pause {
                ok(owner
                    .fixture
                    .as_ref()
                    .unwrap()
                    .prepared()
                    .controller()
                    .release(p));
            }
            owner.release_pause(&pause);
            settle_original(&mut owner, 2, 3);
            assert_receipt(&owner, operation, NEW);
            assert_eq!(owner.fixture.as_ref().unwrap().counts(101), (1, 1, 1));
            if other_pause.is_some() {
                let app = owner.other.as_mut().unwrap();
                let end = Instant::now() + Duration::from_millis(1000);
                while !app.chains.pending.is_empty() {
                    ok(app.chains.progress_all(3));
                    assert!(Instant::now() < end);
                }
            }
            // Actual child reap did not invent a current observation or recreate
            // authority. A fresh approved child obtains the actual confirmed base.
            assert!(matches!(
                owner.app.as_ref().unwrap().observe(3),
                Err(NativeEditorError::Desktop(Status::NotReady))
            ));
            owner.reopen_child(NEW, 4);
            let fresh = ok(owner.app.as_ref().unwrap().observe(4));
            assert_ne!(
                fresh.actor.instance_id,
                binding.allocation.actor.instance_id
            );
            owner.replace(OLD, 4);
            owner.save(3, 4);
            assert_eq!(owner.fixture.as_ref().unwrap().counts(101), (2, 2, 2));
            owner.finish(4);
        }
    }
}

#[test]
fn process_d22_child_death_after_permit_original_writer_survives() {
    for case in ["D22C01", "D22C02", "D22C03", "D22C04", "D22P"] {
        for scenario in ok(ProcessAssertionScenario::for_case(case)) {
            let mut owner = OwnedApp::open(scenario.id(), scenario);
            owner.replace(NEW, 2);
            let pause = owner.pause(store::PausePoint::AfterCommitPermit);
            owner.chord(22, 2);
            assert!(owner.reach_pause(&pause, 2).permit_issued);
            let (operation, entered, deadline, binding) = actual_original(&mut owner);
            let before_counts = owner.fixture.as_ref().unwrap().counts(101);
            let store_workers = ok(owner
                .fixture
                .as_ref()
                .unwrap()
                .prepared()
                .controller()
                .evidence())
            .ledger
            .active_io_workers;
            assert_eq!(store_workers, 1);
            owner.open_other(2);
            let progress_started = Instant::now();
            owner.replace_other(C, 2);
            assert!(progress_started.elapsed() < Duration::from_millis(1000));
            owner.save_other(2, 2);
            if scenario.id() == "D22DropChildDoesNotDropWriter" {
                let end = ok(owner.app.as_mut().unwrap().drop_child_for_assertion());
                assert_original_held(&owner, operation, entered, deadline);
                // A genuine unrelated child's proof cannot close A's wrapper.
                // Keep B and its actual proof staged outside assertion unwinds.
                ok(owner
                    .other
                    .as_mut()
                    .unwrap()
                    .retire(ProcessRetireReason::HumanClose, 2));
                loop {
                    match owner.other.as_mut().unwrap().join_child() {
                        Ok(proof) => {
                            owner.proofs.push(proof);
                            break;
                        }
                        Err(NativeEditorError::Desktop(Status::NotReady)) => {
                            assert!(Instant::now() < end);
                            thread::yield_now();
                        }
                        Err(error) => panic!("INCOMPLETE: genuine sibling join failed: {error:?}"),
                    }
                }
                assert!(matches!(
                    owner
                        .app
                        .as_mut()
                        .unwrap()
                        .accept_dropped_child_exit_for_assertion(owner.proofs.last().unwrap()),
                    Err(NativeEditorError::Desktop(Status::Denied))
                ));
                loop {
                    owner.fixture.as_mut().unwrap().join_all();
                    let other = owner.other.as_mut().unwrap();
                    match other.reconcile_originals(2) {
                        Ok(()) => {}
                        Err(NativeEditorError::Desktop(Status::NotReady))
                        | Err(NativeEditorError::Store(store::StoreStatus::NotReady)) => {}
                        Err(error) => {
                            panic!("INCOMPLETE: genuine sibling reconciliation failed: {error:?}")
                        }
                    }
                    if other.assertion_pending_originals() == 0 {
                        break;
                    }
                    assert!(Instant::now() < end);
                    thread::yield_now();
                }
                assert_eq!(
                    owner.other.as_ref().unwrap().assertion_pending_originals(),
                    0
                );
                owner.other.take();
                loop {
                    match owner
                        .fixture
                        .as_ref()
                        .unwrap()
                        .dc
                        .join_process_assertion_quarantine(owner.run.as_mut().unwrap())
                    {
                        Ok(proof) => {
                            assert!(proof.supervisor_joined());
                            owner.proofs.push(proof);
                            let proof = owner.proofs.last().unwrap();
                            let app = owner.app.as_mut().unwrap();
                            ok(app.accept_dropped_child_exit_for_assertion(proof));
                            assert!(matches!(
                                app.accept_dropped_child_exit_for_assertion(proof),
                                Err(NativeEditorError::Desktop(Status::Denied))
                            ));
                            break;
                        }
                        Err(error) if error.status() == Status::NotReady => {
                            assert!(Instant::now() < end)
                        }
                        Err(_) => panic!("INCOMPLETE: actual dropped child remains quarantined"),
                    }
                }
            } else {
                ok(owner
                    .app
                    .as_mut()
                    .unwrap()
                    .retire(ProcessRetireReason::ChildFault, 2));
                assert!(
                    owner.app.as_ref().unwrap().child.is_some(),
                    "signal request is not consuming reap"
                );
                assert_original_held(&owner, operation, entered, deadline);
                owner.retire_and_join(ProcessRetireReason::ChildFault, 2);
            }
            assert_original_held(&owner, operation, entered, deadline);
            if scenario.id() == "D22NoOrdinaryGrantRevival" {
                let app = owner.app.as_ref().unwrap();
                let chain = &app.chains.pending[0];
                let before = ok(owner
                    .fixture
                    .as_ref()
                    .unwrap()
                    .prepared()
                    .controller()
                    .evidence())
                .exchanges
                .len();
                let query = ok(super::canonical(ok(artifact::SaveStatus {
                    request_id: 810,
                    session_id: binding.allocation.actor.session_id,
                    session_generation: binding.allocation.actor.session_generation,
                    operation_id: operation,
                }
                .encode(app.chains.launch.endpoint().handle))));
                assert!(
                    matches!(
                        app.chains.desktop.begin_save_status(
                            app.chains.launch.desktop().bindings().artifact_origin(),
                            &query,
                            2
                        ),
                        Err(Status::Denied | Status::Stale)
                    ),
                    "true child reap does not revive old ordinary lookup authority"
                );
                assert!(
                    matches!(
                        app.chains.desktop.begin_save_allocate(
                            app.chains.launch.desktop().bindings().artifact_origin(),
                            &chain.intent,
                            ok(chain.allocation_request()),
                            2
                        ),
                        Err(Status::Denied | Status::Stale | Status::NotReady)
                    ),
                    "true child reap does not revive consumed allocation authority"
                );
                assert_eq!(
                    ok(owner
                        .fixture
                        .as_ref()
                        .unwrap()
                        .prepared()
                        .controller()
                        .evidence())
                    .exchanges
                    .len(),
                    before
                );
                assert_eq!(owner.fixture.as_ref().unwrap().counts(101), before_counts);
            }
            let f = owner.fixture.as_ref().unwrap();
            assert_eq!(f.counts(101), before_counts);
            assert_eq!(
                ok(f.prepared().controller().evidence())
                    .ledger
                    .active_io_workers,
                1,
                "native child reap is not a genuine Store IO join"
            );
            assert_eq!(selected_blob(f, 101), OLD);
            assert!(object(f, 101).operations[0].receipt.is_none());
            owner.release_pause(&pause);
            settle_original(&mut owner, 2, 3);
            assert_receipt(&owner, operation, NEW);
            assert_eq!(owner.fixture.as_ref().unwrap().counts(101), (1, 1, 1));
            assert!(matches!(
                owner.app.as_ref().unwrap().observe(3),
                Err(NativeEditorError::Desktop(Status::NotReady))
            ));
            owner.reopen_child(NEW, 4);
            assert_ne!(
                ok(owner.app.as_ref().unwrap().observe(4)).actor.instance_id,
                binding.allocation.actor.instance_id
            );
            owner.replace(OLD, 4);
            owner.save(3, 4);
            assert_eq!(owner.fixture.as_ref().unwrap().counts(101), (2, 2, 2));
            owner.finish(4);
        }
    }
}

fn assert_no_capture_intent(owner: &mut OwnedApp, retired: bool) {
    let app = owner.app.as_mut().unwrap();
    match app
        .chains
        .desktop
        .take_process_save_intent(app.child.as_mut().unwrap())
    {
        Err(status) => assert_eq!(
            status,
            if retired {
                Status::Denied
            } else {
                Status::NotReady
            }
        ),
        Ok(intent) => {
            owner.unexpected_intent = Some(intent);
            panic!("unexpected genuine capture owner retained, never discarded or submitted");
        }
    }
}

fn pump_capture_attempt(owner: &mut OwnedApp, now: u64) -> Option<Status> {
    let compositor = owner.fixture.as_ref().unwrap().drivers[0]
        .s
        .compositor
        .clone();
    let end = Instant::now() + Duration::from_millis(1000);
    loop {
        let app = owner.app.as_mut().unwrap();
        match step_composed(app, &compositor, now) {
            Ok(step) if step.publication_accepted() => return None,
            Ok(_) => {}
            Err(NativeEditorError::Desktop(status)) => return Some(status),
            Err(error) => panic!("unexpected capture carrier failure:{error:?}"),
        }
        assert!(
            Instant::now() < end,
            "actual armed capture attempt reaches terminal native handling"
        );
        thread::yield_now();
    }
}

#[test]
fn process_d18_no_save_without_genuine_single_use_capture() {
    for case in [
        "D18C01", "D18C02", "D18C03", "D18C04", "D18C05", "D18C06", "D18P",
    ] {
        for scenario in ok(ProcessAssertionScenario::for_case(case)) {
            let mut owner = OwnedApp::open(scenario.id(), scenario);
            owner.edit_without_frame(NEW, 2);
            let replay = matches!(
                scenario.id(),
                "D18CopiedOldCaptureRequest" | "D18CaptureConsumedTwice"
            );
            match scenario.id() {
                "D18OrdinaryPublishSaveClaim" | "D18UnsolicitedCapture" => {
                    let app = owner.app.as_mut().unwrap();
                    ok(app
                        .chains
                        .desktop
                        .request_process_editor_frame(app.child.as_mut().unwrap(), 2));
                    let status = pump_capture_attempt(&mut owner, 2);
                    if scenario.id() == "D18OrdinaryPublishSaveClaim" {
                        assert_eq!(status, None);
                        assert_eq!(ok(owner.app.as_ref().unwrap().observe(2)).bytes, NEW);
                        assert_no_capture_intent(&mut owner, false);
                    } else {
                        assert_eq!(status, Some(Status::Invalid));
                        assert_no_capture_intent(&mut owner, true);
                    }
                    assert_eq!(owner.fixture.as_ref().unwrap().counts(101), (0, 0, 0));
                    let f = owner.fixture.as_ref().unwrap();
                    ok(f.h.compose_native_save(&f.drivers[0].s.compositor, 2));
                    assert_ne!(
                        ok(f.dc.save_chrome_observation(&f.drivers[0].s.compositor)).label,
                        desktop::NativeEditorPhase::Saved
                    );
                }
                "D18CopiedOldCaptureRequest" | "D18CaptureConsumedTwice" => {
                    // Only the real original CtrlS may create Save1. Replay is
                    // driven on this same armed child, never on a fresh child.
                    owner.queue_chord(22, 2);
                    let end = Instant::now() + Duration::from_millis(1000);
                    // Store evidence walks live filesystem components; it is
                    // not a polling authority during the writer's publication.
                    // Wait on the same genuine Core receipt-confirmed revision,
                    // then check exact Store effects and receipt after joining.
                    while ok(owner.app.as_ref().unwrap().observe(2)).confirmed_revision != 2 {
                        match step_composed(
                            owner.app.as_mut().unwrap(),
                            &owner.fixture.as_ref().unwrap().drivers[0].s.compositor,
                            2,
                        ) {
                            Ok(_)
                            | Err(NativeEditorError::Desktop(
                                Status::Stale | Status::NotReady | Status::Disconnected,
                            )) => {}
                            Err(error) => panic!("first real capture:{error:?}"),
                        }
                        ok(owner.app.as_mut().unwrap().chains.progress_all(2));
                        assert!(
                            Instant::now() < end,
                            "first genuine captured Save must commit"
                        );
                    }
                    let end = Instant::now() + Duration::from_millis(1000);
                    while !owner.app.as_ref().unwrap().chains.pending.is_empty() {
                        ok(owner.app.as_mut().unwrap().chains.progress_all(2));
                        assert!(Instant::now() < end);
                    }
                    owner.fixture.as_mut().unwrap().join_all();
                    assert_eq!(owner.fixture.as_ref().unwrap().counts(101), (1, 1, 1));
                    let op = object(owner.fixture.as_ref().unwrap(), 101).operations[0]
                        .allocation
                        .operation_id;
                    assert_receipt(&owner, op, NEW);
                    if scenario.id() == "D18CopiedOldCaptureRequest" {
                        let app = owner.app.as_mut().unwrap();
                        let requested = app
                            .chains
                            .desktop
                            .request_process_editor_frame(app.child.as_mut().unwrap(), 2);
                        if requested.is_ok() {
                            let _actual_terminal = pump_capture_attempt(&mut owner, 2);
                        } else {
                            assert!(
                                matches!(requested,Err(ref e) if matches!(e.status(),Status::Denied|Status::Stale|Status::NotReady|Status::Disconnected))
                            );
                        }
                    }
                    let app = owner.app.as_mut().unwrap();
                    match app
                        .chains
                        .desktop
                        .take_process_save_intent(app.child.as_mut().unwrap())
                    {
                        Err(status) if scenario.id() == "D18CaptureConsumedTwice" => assert_eq!(
                            status,
                            Status::NotReady,
                            "second actual take after the common chain consumed the genuine intent"
                        ),
                        Err(Status::NotReady | Status::Denied) => {}
                        Err(other) => panic!("unexpected replay intent status:{other:?}"),
                        Ok(intent) => {
                            owner.unexpected_intent = Some(intent);
                            panic!("replay minted second capture; retaining unexpected owner");
                        }
                    }
                    assert_eq!(owner.fixture.as_ref().unwrap().counts(101), (1, 1, 1));
                }
                "D18CaptureAfter1000Ms" | "D18RoundTripCannotRenewCapture" => {
                    owner.queue_chord(22, 2);
                    owner.at_checkpoint(
                        ProcessAssertionPoint::CaptureBeforeAdopt,
                        2,
                        |f, checkpoint| {
                            assert_eq!(f.counts(101), (0, 0, 0));
                            thread::sleep(Duration::from_millis(1050));
                            assert!(
                                checkpoint.reached_at().elapsed() >= Duration::from_millis(1000)
                            );
                        },
                    );
                    assert_eq!(owner.fixture.as_ref().unwrap().counts(101), (0, 0, 0));
                }
                "D18FreshSingleUseCtrlSCapture" => {
                    owner.save(2, 2);
                }
                other => panic!("unreviewed capture scenario {other}"),
            }
            if scenario.id() != "D18FreshSingleUseCtrlSCapture" {
                owner.reopen_child(if replay { NEW } else { OLD }, 3);
                owner.replace(if replay { OLD } else { NEW }, 3);
                owner.save(if replay { 3 } else { 2 }, 3);
            }
            let evidence = owner.finish(3);
            if scenario.id() == "D18FreshSingleUseCtrlSCapture" {
                continue;
            }
            let start = usize::try_from(evidence.before().control_count).unwrap();
            let end = usize::try_from(evidence.after().control_count).unwrap();
            assert!(start <= end && end <= evidence.controls().len());
            if scenario.id() != "D18CaptureConsumedTwice" {
                assert!(
                    start < end,
                    "wire-driven capture attempt must have actual raw control evidence"
                );
            }
            let rows = &evidence.controls()[start..end];
            let word = |bytes: &[u8], offset: usize| {
                u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
            };
            match scenario.id() {
                "D18OrdinaryPublishSaveClaim" => {
                    assert!(rows.iter().any(|r| r.bytes.len() == 88
                        && word(&r.bytes, 4) == 8
                        && word(&r.bytes, 68) == 0));
                    assert!(
                        rows.iter()
                            .any(|r| r.bytes.len() == 88 && word(&r.bytes, 4) == 5)
                    );
                    assert!(matches!(
                        evidence.after().adoption_status,
                        Some(Status::Ok | Status::NotReady)
                    ));
                    assert_eq!(
                        (evidence.before().captured_at, evidence.after().captured_at),
                        (None, None)
                    );
                    assert_eq!(
                        (
                            evidence.before().save_deadline,
                            evidence.after().save_deadline
                        ),
                        (None, None)
                    );
                    assert!(
                        !evidence.controls()[..end]
                            .iter()
                            .any(|r| r.bytes.len() == 88
                                && word(&r.bytes, 4) == 2
                                && word(&r.bytes, 68) == 22
                                && word(&r.bytes, 72) == 1
                                && word(&r.bytes, 76) & 1 != 0)
                    );
                }
                "D18UnsolicitedCapture" => {
                    assert!(rows.iter().any(|r| r.bytes.len() == 88
                        && word(&r.bytes, 4) == 8
                        && word(&r.bytes, 68) == 2
                        && r.direction == desktop::ProcessAssertionDirection::ChildToParent));
                    assert_eq!(evidence.after().adoption_status, Some(Status::Invalid));
                    assert_eq!(evidence.after().captured_at, None);
                    assert_eq!(evidence.after().save_deadline, None);
                    assert_eq!(evidence.before().app_pixels, evidence.after().app_pixels);
                }
                "D18CopiedOldCaptureRequest" => {
                    assert!(rows.iter().any(|r| {
                        r.bytes.len() == 88
                            && word(&r.bytes, 4) == 5
                            && evidence.controls()[..start]
                                .iter()
                                .any(|old| old.bytes == r.bytes)
                    }));
                    assert_eq!(evidence.after().adoption_status, Some(Status::Stale));
                    assert_eq!(evidence.before().app_pixels, evidence.after().app_pixels);
                }
                "D18CaptureConsumedTwice" => {
                    assert_eq!(evidence.after().adoption_status, Some(Status::NotReady));
                }
                "D18CaptureAfter1000Ms" | "D18RoundTripCannotRenewCapture" => {
                    let capture = evidence
                        .before()
                        .captured_at
                        .expect("genuine CtrlS original Instant");
                    let deadline = evidence
                        .before()
                        .save_deadline
                        .expect("genuine original capture deadline");
                    assert_eq!(
                        deadline.duration_since(capture),
                        Duration::from_millis(1000)
                    );
                    assert_eq!(evidence.after().save_deadline, Some(deadline));
                    assert_eq!(evidence.after().adoption_status, Some(Status::Timeout));
                    assert_eq!(evidence.before().app_pixels, evidence.after().app_pixels);
                }
                _ => unreachable!(),
            }
        }
    }
}

#[test]
fn process_d21_child_death_before_permit_retains_known_allocation() {
    for case in ["D21C01", "D21C02", "D21C03", "D21P"] {
        for scenario in ok(ProcessAssertionScenario::for_case(case)) {
            let mut owner = OwnedApp::open(scenario.id(), scenario);
            owner.replace(NEW, 2);
            let before_capture = scenario.id() == "D21DeathBeforeCapture";
            let pause = if before_capture {
                None
            } else {
                Some(owner.pause(store::PausePoint::BeforeCommitPermit))
            };
            if let Some(pause) = &pause {
                owner.chord(22, 2);
                let barrier = owner.reach_pause(pause, 2);
                assert!(!barrier.permit_issued);
                assert_eq!(owner.fixture.as_ref().unwrap().counts(101), (1, 0, 0));
            }
            let prior = object(owner.fixture.as_ref().unwrap(), 101);
            owner.retire_and_join(ProcessRetireReason::ChildFault, 2);
            if let Some(pause) = &pause {
                owner.release_pause(pause);
            }
            settle_original(&mut owner, 1, 3);
            let after = object(owner.fixture.as_ref().unwrap(), 101);
            assert_eq!(after.permit_count, 0);
            assert_eq!(after.transition_count, 0);
            assert_eq!(after.selected.content_hash, prior.selected.content_hash);
            assert_eq!(selected_blob(owner.fixture.as_ref().unwrap(), 101), OLD);
            if before_capture {
                assert_eq!(after.mutation_dispatch_count, 0);
                assert!(after.operations.is_empty());
            } else {
                assert_eq!(
                    after.operations.len(),
                    1,
                    "retain known allocation, never NoAllocation"
                );
                assert_eq!(
                    after.operations[0].allocation.operation_id,
                    prior.operations[0].allocation.operation_id
                );
                if let Some(receipt) = &after.operations[0].receipt {
                    assert_eq!(receipt.outcome,artifact_store_schema::editor_save::EditorReceiptOutcomeV0::DefinitiveNoncommit);
                    assert_eq!((receipt.result_revision, receipt.committed_at_ms), (0, 0));
                }
            }
            let retired_pid = owner.proofs[0].process_id();
            owner.reopen_child(OLD, 4);
            owner.replace(NEW, 4);
            owner.save(2, 4);
            let evidence = owner.finish(4);
            if scenario.id() == "D21PublicationAfterDeath" {
                let start = usize::try_from(evidence.before().control_count).unwrap();
                let end = usize::try_from(evidence.after().control_count).unwrap();
                assert!(
                    start < end && end <= evidence.controls().len(),
                    "late queued native publication must actually reach denial"
                );
                assert!(
                    evidence.controls()[start..end]
                        .iter()
                        .any(|control| control.bytes.len() == 88
                            && u32::from_le_bytes(control.bytes[4..8].try_into().unwrap()) == 5
                            && control.received_fds == 2
                            && control.direction
                                == desktop::ProcessAssertionDirection::ChildToParent
                            && control.sender.is_some_and(|(pid, _, _)| pid == retired_pid)),
                    "actual retired child queued Publish with two real FD aliases, not a fabricated decision flag"
                );
                assert!(matches!(
                    evidence.after().adoption_status,
                    Some(Status::Denied | Status::Stale | Status::Disconnected)
                ));
                assert_eq!(evidence.before().app_pixels, evidence.after().app_pixels);
                assert_eq!(
                    evidence.before().publication_generation,
                    evidence.after().publication_generation
                );
                assert!(evidence.after().owners.maps <= evidence.before().owners.maps);
                assert!(evidence.after().owners.combined <= evidence.before().owners.combined);
            }
            assert!(evidence.native_wait_outcome().is_some());
            assert!(evidence.supervisor_joined());
            assert_eq!(evidence.scenario_id(), scenario.id());
        }
    }
}

#[test]
fn process_d26_revoke_preserves_genuine_issued_permit() {
    for case in ["D26C04", "D26P"] {
        for scenario in ok(ProcessAssertionScenario::for_case(case)) {
            let mut owner = OwnedApp::open(scenario.id(), scenario);
            owner.replace(NEW, 2);
            let pause = owner.pause(store::PausePoint::AfterCommitPermit);
            owner.chord(22, 2);
            assert!(owner.reach_pause(&pause, 2).permit_issued);
            let (operation, entered, deadline, binding) = actual_original(&mut owner);
            revoke(
                owner.fixture.as_ref().unwrap(),
                0,
                &binding.allocation.actor,
                3,
            );
            owner.retire_and_join(ProcessRetireReason::Revoked, 3);
            assert_original_held(&owner, operation, entered, deadline);
            assert_eq!(owner.fixture.as_ref().unwrap().counts(101), (1, 1, 0));
            if scenario.id() == "D26OtherOwnerAndOriginalReceiptProgress" {
                owner.open_other(3);
                owner.replace_other(C, 3);
                owner.save_other(2, 3);
                let f = owner.fixture.as_ref().unwrap();
                ok(f.h.compose_native_save(&f.drivers[1].s.compositor, 3));
                let other = ok(owner.other.as_ref().unwrap().observe(3));
                assert_eq!(other.bytes, C);
                assert_eq!(other.phase, desktop::NativeEditorPhase::Saved);
                assert_eq!(f.counts(102), (1, 1, 1));
                assert_eq!(f.counts(101), (1, 1, 0));
                assert_original_held(&owner, operation, entered, deadline);
            }
            owner.release_pause(&pause);
            settle_original(&mut owner, 2, 3);
            assert_receipt(&owner, operation, NEW);
            assert_eq!(owner.fixture.as_ref().unwrap().counts(101), (1, 1, 1));
            owner.reopen_child(NEW, 4);
            owner.replace(OLD, 4);
            owner.save(3, 4);
            assert_eq!(owner.fixture.as_ref().unwrap().counts(101), (2, 2, 2));
            owner.finish(4);
        }
    }
}

#[test]
fn process_d03_receipt_notice_genuine_parent() {
    let scenarios = ok(ProcessAssertionScenario::for_case("D03P"));
    assert_eq!(scenarios.len(), 1);
    let scenario = &scenarios[0];
    let mut owner = OwnedApp::open(scenario.id(), scenario);
    owner.replace(NEW, 2);
    owner.save(2, 2);
    let row = object(owner.fixture.as_ref().unwrap(), 101)
        .operations
        .remove(0);
    let operation = row.allocation.operation_id;
    assert_receipt(&owner, operation, NEW);
    let current = ok(owner.app.as_ref().unwrap().observe(2));
    let actor = current.actor.clone();
    // Store progress follows the carrier pump. Drive the next actual control
    // turn so the genuine receipt notice precedes this fresh ordinary pair.
    // No new input, Save, source, operation, or capture authority is created.
    let (f, app) = owner.parts();
    let previous_publication =
        ok(f.h.observe_process_child(app.child.as_ref().unwrap())).publication_generation();
    ok(f.h.request_process_editor_frame(app.child.as_mut().unwrap(), 2));
    let end = Instant::now() + Duration::from_millis(1000);
    loop {
        let step = step_composed(app, &f.drivers[0].s.compositor, 2)
            .expect("actual postreceipt pair must publish under its original child budget");
        if step.publication_accepted() {
            break;
        }
        assert!(
            Instant::now() < end,
            "bounded genuine postreceipt publication"
        );
        thread::yield_now();
    }
    let after = ok(app.observe(2));
    assert_eq!(after.bytes, current.bytes);
    assert_eq!(after.text_generation, current.text_generation);
    assert_eq!(after.view_version, current.view_version);
    assert_eq!(after.confirmed_revision, 2);
    assert_eq!(after.phase, desktop::NativeEditorPhase::Saved);
    assert!(
        ok(f.h.observe_process_child(app.child.as_ref().unwrap())).publication_generation()
            > previous_publication
    );
    assert_eq!(f.counts(101), (1, 1, 1));
    let evidence = owner.finish(2);
    let mut messages = std::collections::BTreeSet::new();
    let mut notices = 0;
    for (index, control) in evidence.controls().iter().enumerate() {
        assert_eq!(control.sequence, index as u64 + 1);
        assert_eq!(control.bytes.len(), 88);
        assert_eq!(&control.bytes[0..4], &384u32.to_le_bytes());
        assert_eq!(&control.bytes[16..20], &64u32.to_le_bytes());
        assert_eq!(&control.bytes[84..88], &[0; 4]);
        let ty = u32::from_le_bytes(control.bytes[4..8].try_into().unwrap());
        assert!((1..=8).contains(&ty));
        messages.insert(ty);
        let from_child = matches!(ty, 3 | 5);
        assert_eq!(
            control.direction,
            if from_child {
                desktop::ProcessAssertionDirection::ChildToParent
            } else {
                desktop::ProcessAssertionDirection::ParentToChild
            }
        );
        assert_eq!(
            control.received_fds,
            match ty {
                1 => 3,
                5 | 8 => 2,
                _ => 0,
            }
        );
        if from_child {
            assert!(control.sender.is_some_and(|(pid, _, _)| pid > 0));
        }
        if ty == 7 {
            notices += 1;
            let payload = &control.bytes[20..84];
            assert_eq!(
                u64::from_le_bytes(payload[24..32].try_into().unwrap()),
                operation
            );
            assert_eq!(u64::from_le_bytes(payload[32..40].try_into().unwrap()), 2);
            assert_eq!(u32::from_le_bytes(payload[48..52].try_into().unwrap()), 0);
            assert_eq!(u32::from_le_bytes(payload[52..56].try_into().unwrap()), 0);
            assert_eq!(&payload[56..64], &[0; 8]);
            assert!(u64::from_le_bytes(payload[16..24].try_into().unwrap()) > 0);
            assert!(u64::from_le_bytes(payload[40..48].try_into().unwrap()) > 0);
        }
    }
    assert_eq!(messages, (1u32..=8).collect());
    assert_eq!(
        notices, 1,
        "one original receipt produces one parent-only notice"
    );
    assert_eq!(row.allocation.actor, actor);
}

fn read_from_launch(
    f: &mut Fixture,
    launch: &store::PairedNativeSaveLaunch,
    id: u64,
) -> (
    desktop::NativeSaveEntry,
    store::RegisteredNativeSave,
    store::NativeSaveReply,
) {
    let request = selected_request(launch, id);
    let entry =
        ok(f.h.begin_save_read(launch.desktop().bindings().artifact_origin(), &request, 2));
    let registered = ok(f
        .host()
        .register_native_save(launch.endpoint(), ok(entry.wait_once())));
    let reply = ok(f.host().execute_native_save(&registered));
    for producer in entry.producer_ids() {
        join_core(f, &producer);
    }
    for producer in reply.producers() {
        join_core(f, producer);
    }
    (entry, registered, reply)
}

fn store_data_cap(owner: &mut OwnedApp) {
    let f = owner.fixture.as_mut().unwrap();
    // This independently approved Read context has not been consumed into
    // process enrollment. Re-extracting A's ProcessOwned Read is denied.
    let launch = PanicOwners::new(f.launch(1, 102, 2));
    // The consumed A Read can leave an unowned registry row until the next
    // real allocation collects it. Retain one genuine B Read first, so quota
    // increments are measured from an actually owned, post-collection baseline.
    let mut held = PanicOwners::new(vec![read_from_launch(f, &launch, 1000)]);
    assert!(held[0].2.selected().is_some());
    let mut identities = std::collections::BTreeSet::new();
    identities.insert(held[0].2.selected().unwrap().descriptor().handle.pack());
    while ok(f.prepared().controller().evidence())
        .ledger
        .shared_objects
        < 32
    {
        let before = ok(f.prepared().controller().evidence())
            .ledger
            .shared_objects;
        let id = 1000 + held.len() as u64;
        let triple = read_from_launch(f, &launch, id);
        assert!(
            triple.2.selected().is_some(),
            "genuine data fill request{id} denied before actual cap32: reply_status={} shared_before={before} shared_after={}",
            ok(artifact::ReadSelectedReply::decode(triple.2.wire())).status,
            ok(f.prepared().controller().evidence())
                .ledger
                .shared_objects
        );
        assert!(
            identities.insert(triple.2.selected().unwrap().descriptor().handle.pack()),
            "each retained selected Read owns a genuinely distinct data descriptor"
        );
        assert_eq!(
            ok(f.prepared().controller().evidence())
                .ledger
                .shared_objects,
            before + 1
        );
        held.push(triple);
    }
    assert_eq!(
        ok(f.prepared().controller().evidence())
            .ledger
            .shared_objects,
        32
    );
    let id = 1000 + held.len() as u64;
    let denied = read_from_launch(f, &launch, id);
    assert_eq!(
        ok(artifact::ReadSelectedReply::decode(denied.2.wire())).status,
        StoreStatus::Exhausted as u32
    );
    assert!(denied.2.selected().is_none());
    assert_eq!(
        ok(f.prepared().controller().evidence())
            .ledger
            .shared_objects,
        32
    );
    assert!(!held.is_empty());
    let released = held.pop().unwrap();
    let released_descriptor = released.2.selected().unwrap().descriptor().handle.pack();
    drop(released);
    assert!(held.iter().all(|triple| {
        triple.2.selected().unwrap().descriptor().handle.pack() != released_descriptor
    }));
    // The readonly registry ledger may still include the unowned row. This
    // genuine admission performs normal lazy collection and allocates a new
    // distinct data object; no test-only collection or count mutation occurs.
    let fresh = read_from_launch(f, &launch, id + 1);
    assert!(fresh.2.selected().is_some());
    let fresh_descriptor = fresh.2.selected().unwrap().descriptor().handle.pack();
    assert_ne!(fresh_descriptor, released_descriptor);
    assert!(identities.insert(fresh_descriptor));
    assert_eq!(
        ok(f.prepared().controller().evidence())
            .ledger
            .shared_objects,
        32
    );
    drop((fresh, denied, held));
}

fn store_query_cap(owner: &mut OwnedApp) {
    let f = owner.fixture.as_mut().unwrap();
    // This independently approved Read context has not been consumed into
    // process enrollment. Re-extracting A's ProcessOwned Read is denied.
    let launch = PanicOwners::new(f.launch(1, 102, 2));
    let mut held = PanicOwners::new(Vec::new());
    while ok(f.h.preview_counts()).query_slots < 64 {
        let query = selected_request(&launch, 1100 + held.len() as u64);
        let entry =
            ok(f.h.begin_save_read(launch.desktop().bindings().artifact_origin(), &query, 2));
        let registered = ok(f
            .host()
            .register_native_save(launch.endpoint(), ok(entry.wait_once())));
        for id in entry.producer_ids() {
            join_core(f, &id);
        }
        held.push((entry, registered));
    }
    assert_eq!(ok(f.h.preview_counts()).query_slots, 64);
    let query = selected_request(&launch, 1200);
    assert!(matches!(
        f.h.begin_save_read(launch.desktop().bindings().artifact_origin(), &query, 2),
        Err(Status::Exhausted)
    ));
    assert_eq!(ok(f.h.preview_counts()).query_slots, 64);
    drop(held.pop());
    let entry =
        ok(f.h.begin_save_read(launch.desktop().bindings().artifact_origin(), &query, 2));
    let call = ok(entry.wait_once());
    for id in entry.producer_ids() {
        f.join(&id);
    }
    drop((entry, call, held));
}

fn store_producer_cap(owner: &mut OwnedApp) {
    owner.replace(NEW, 2);
    let f = owner.fixture.as_mut().unwrap();
    // This independently approved Read context has not been consumed into
    // process enrollment. Re-extracting A's ProcessOwned Read is denied.
    let launch = PanicOwners::new(f.launch(1, 102, 2));
    let mut held = PanicOwners::new(Vec::new());
    while f.h.native_producer_counts().held < 64 {
        let id = 1300 + held.len() as u64;
        let pause = desktop_pause(f, 1, desktop::NativeSavePausePoint::BeforeEntryAdmission);
        let query = selected_request(&launch, id);
        let entry =
            ok(f.h.begin_save_read(launch.desktop().bindings().artifact_origin(), &query, 2));
        assert!(ok(pause.wait_until_entered(1000)).entered);
        held.push((entry, pause));
    }
    assert_eq!(f.h.native_producer_counts().held, 64);
    let query = selected_request(&launch, 1332);
    assert!(matches!(
        f.h.begin_save_read(launch.desktop().bindings().artifact_origin(), &query, 2),
        Err(Status::Exhausted)
    ));
    assert_eq!(f.h.native_producer_counts().held, 64);
    // Exercise the consumed process intent against the same live Desktop
    // pressure. Every input still traverses genuine Focus and child ACKs.
    let app = owner.app.as_mut().unwrap();
    for (usage, phase) in [(224, 1), (22, 1), (22, 2), (224, 2)] {
        f.drivers[0].send(&f.h, usage, phase, 2);
    }
    let last = f.drivers[0].next - 1;
    let end = Instant::now() + Duration::from_millis(1000);
    loop {
        match step_composed(app, &f.drivers[0].s.compositor, 2) {
            Err(NativeEditorError::Desktop(Status::Exhausted)) => break,
            Ok(_) => {}
            Err(error) => panic!("actual pressure Save admission failed: {error:?}"),
        }
        assert!(
            Instant::now() < end,
            "real process Save reaches Desktop pressure"
        );
        thread::yield_now();
    }
    assert_eq!(app.assertion_pending_originals(), 0);
    assert_eq!(f.counts(101), (0, 0, 0));
    assert_eq!(f.h.native_producer_counts().held, 64);
    let view = ok(app.observe(2));
    assert_eq!(view.bytes, NEW);
    assert_eq!(view.phase, desktop::NativeEditorPhase::Unsaved);
    // The app returned the entry refusal after adopting the capture frame.
    // Compose that actual frame before continuing the remaining releases.
    ok(f.h.compose_native_save(&f.drivers[0].s.compositor, 2));
    while ok(f.h.observe_process_child(app.child.as_ref().unwrap())).acknowledged_sequence() != last
    {
        assert!(
            Instant::now() < end,
            "actual refused Save chord releases are acknowledged"
        );
        ok(step_composed(app, &f.drivers[0].s.compositor, 2));
        thread::yield_now();
    }
    for (_, pause) in held.iter() {
        ok(f.dc.release_native_save(pause));
    }
    for (entry, _) in held.iter() {
        for id in entry.producer_ids() {
            f.join(&id);
        }
    }
    assert_eq!(f.h.native_producer_counts().held, 0);
    drop(held);
    let entry =
        ok(f.h.begin_save_read(launch.desktop().bindings().artifact_origin(), &query, 2));
    let call = ok(entry.wait_once());
    for id in entry.producer_ids() {
        f.join(&id);
    }
    drop((entry, call));
}

fn store_pin_cap(owner: &mut OwnedApp) {
    let f = owner.fixture.as_mut().unwrap();
    let mut held = PanicOwners::new(Vec::new());
    while ok(f.h.preview_counts()).pin_rows < 16 {
        held.push(ok(f.prepared().pin_selection(
            &f.drivers[0].s.chrome.peer,
            101,
            30000,
        )));
    }
    assert_eq!(ok(f.h.preview_counts()).pin_rows, 16);
    assert!(matches!(
        f.prepared()
            .pin_selection(&f.drivers[0].s.chrome.peer, 101, 30000),
        Err(StoreStatus::Exhausted)
    ));
    drop(held.pop());
    let fresh = ok(f
        .prepared()
        .pin_selection(&f.drivers[0].s.chrome.peer, 101, 30000));
    drop((fresh, held));
}

fn store_pending_cap(owner: &mut OwnedApp) {
    let retained_child = {
        let (f, app) = owner.parts();
        ok(f.h.observe_process_child(app.child.as_ref().unwrap()))
    };
    let f = owner.fixture.as_mut().unwrap();
    let mut held = PanicOwners::new(Vec::new());
    while ok(f.h.preview_counts()).read_contexts < 16 {
        let launch = f.launch(1, 102, 2);
        let actor = boot(&launch);
        let read = read_from_launch(f, &launch, 1600 + held.len() as u64);
        assert!(read.2.selected().is_some());
        revoke(
            f,
            1,
            &artifact_store_schema::editor_save::EditorActorV0 {
                owner_id: 2,
                session_id: actor.session_id,
                session_generation: actor.session_generation,
                instance_id: actor.instance_id,
                instance_generation: actor.instance_generation,
            },
            2,
        );
        held.push((launch, read));
    }
    let (selector, pin, _) = f.prepare(1, 102, 2);
    let mut approval = f.approval(1, 2);
    assert!(matches!(
        f.h.confirm_save_preview(&f.drivers[1].s.chrome.peer, &mut approval, 2),
        Err(Status::Exhausted)
    ));
    assert_eq!(ok(f.h.preview_counts()).read_contexts, 16);
    drop((selector, pin, approval, held));
    let app = owner.app.as_ref().unwrap();
    let after_child = ok(f.h.observe_process_child(app.child.as_ref().unwrap()));
    assert_eq!(after_child.process_id(), retained_child.process_id());
    assert_eq!(after_child.birth_ticks(), retained_child.birth_ticks());
    assert_eq!(
        after_child.executable_sha256(),
        retained_child.executable_sha256()
    );
}

fn store_io_cap(owner: &mut OwnedApp) {
    owner.replace(NEW, 2);
    let a = owner.pause(store::PausePoint::AfterCommitPermit);
    owner.chord(22, 2);
    assert!(owner.reach_pause(&a, 2).permit_issued);
    owner.open_other(2);
    owner.replace_other(NEW, 2);
    let b = {
        let f = owner.fixture.as_mut().unwrap();
        let app = owner.other.as_ref().unwrap();
        let p = Arc::new(ok(f.prepared().controller().pause_native_save(
            app.chains.launch.endpoint(),
            store::PausePoint::AfterCommitPermit,
        )));
        f.store_pauses
            .push((f.prepared.as_ref().unwrap().clone(), p.clone()));
        p
    };
    owner.other_chord(22, 2);
    owner.reach_other_pause(&b, 2);
    assert_eq!(
        ok(owner
            .fixture
            .as_ref()
            .unwrap()
            .prepared()
            .controller()
            .evidence())
        .ledger
        .active_io_workers,
        2
    );
    // Hold both genuine permitted writers; retire A's child before a fresh
    // approval launches actual child C on object103. The original A owner stays.
    let (_, _, _, binding) = actual_original(owner);
    revoke(
        owner.fixture.as_ref().unwrap(),
        0,
        &binding.allocation.actor,
        2,
    );
    owner.retire_and_join(ProcessRetireReason::Revoked, 2);
    let cleanup_deadline = owner
        .cleanup_deadline
        .expect("A retirement already owns the original cleanup deadline");
    let f = owner.fixture.as_mut().unwrap();
    let c = f.launch(0, 103, 2);
    owner.third = Some(
        match ProcessArtifactEditor::open(
            f.h.clone(),
            f.host(),
            c,
            ok(ChildBudget::checked(5000)),
            2,
        ) {
            Ok(app) => app,
            Err(failure) => {
                let (_, app) = failure.into_parts();
                owner.third = Some(app);
                panic!("third genuine child failed; all owners retained");
            }
        },
    );
    let app = owner.third.as_mut().unwrap();
    let end = Instant::now() + Duration::from_millis(1000);
    loop {
        ok(step_composed(app, &f.drivers[0].s.compositor, 2));
        match app.observe(2) {
            Ok(view) if view.bytes == C => break,
            Ok(_) | Err(NativeEditorError::Desktop(Status::NotReady)) => {}
            Err(error) => panic!("third child observation:{error:?}"),
        };
        assert!(Instant::now() < end);
    }
    for (usage, phase) in [(224, 1), (4, 1), (4, 2), (224, 2)] {
        delivered(f, app, 0, usage, phase, 2);
    }
    for &byte in NEW {
        delivered(f, app, 0, usage(byte), 1, 2);
        delivered(f, app, 0, usage(byte), 2, 2);
    }
    ok(app
        .chains
        .desktop
        .request_process_editor_frame(app.child.as_mut().unwrap(), 2));
    let end = Instant::now() + Duration::from_millis(1000);
    while ok(app.observe(2)).bytes != NEW {
        ok(step_composed(app, &f.drivers[0].s.compositor, 2));
        assert!(Instant::now() < end);
    }
    for (usage, phase) in [(224, 1), (22, 1), (22, 2), (224, 2)] {
        delivered(f, app, 0, usage, phase, 2);
    }
    let end = Instant::now() + Duration::from_millis(1000);
    while !app.chains.pending.is_empty() {
        ok(app.chains.progress_all(2));
        assert!(Instant::now() < end);
    }
    let exhausted = ok(f.prepared().controller().evidence());
    assert!(
        exhausted
            .exchanges
            .iter()
            .filter(|e| e.selected_object_id == 103)
            .any(|e| {
                let q = ok(desktop::decode_envelope_wire(&e.request_wire));
                q.msg_type == 3
                    && e.actual_reply_wire.as_ref().is_some_and(|wire| {
                        let r = ok(desktop::decode_envelope_wire(wire));
                        ok(artifact::AllocateSaveIdReply::decode(&r)).status
                            == StoreStatus::Exhausted as u32
                    })
            }),
        "third actual common Save allocation must hit global IO2"
    );
    assert_eq!(exhausted.ledger.active_io_workers, 2);
    assert_eq!(f.counts(103), (0, 0, 0));
    ok(f.prepared().controller().release(&a));
    ok(f.prepared().controller().release(&b));
    assert!(ok(a.wait_until_settled(1000)).settled && ok(b.wait_until_settled(1000)).settled);
    // Settled IO can still own its native producer row. Those same rows must
    // actually join before the unchanged global IO cap admits C's fresh Save.
    while f.h.native_producer_counts().io != 0 {
        assert!(
            Instant::now() < cleanup_deadline,
            "original A cleanup deadline bounds actual IO producer joins"
        );
        f.join_all();
        thread::yield_now();
    }
    // Capacity release permits a fresh real CtrlS on the same current C draft.
    let app = owner.third.as_mut().unwrap();
    for (usage, phase) in [(224, 1), (22, 1), (22, 2), (224, 2)] {
        delivered(f, app, 0, usage, phase, 3);
    }
    let end = Instant::now() + Duration::from_millis(1000);
    while ok(app.observe(3)).confirmed_revision != 2 {
        ok(step_composed(app, &f.drivers[0].s.compositor, 3));
        assert!(Instant::now() < end);
    }
    assert_eq!(f.counts(103), (1, 1, 1));
    settle_original(owner, 2, 3);
    let app = owner.other.as_mut().unwrap();
    let end = Instant::now() + Duration::from_millis(1000);
    while !app.chains.pending.is_empty() {
        ok(app.chains.progress_all(3));
        assert!(Instant::now() < end);
    }
}

#[test]
fn process_failed_open_joins_partial_read_entry() {
    let mut retained = PanicOwners::new((fixture::fixture("app_partial_read_entry", 1), None));
    let (f, slot) = &mut *retained;
    let launch = f.launch(0, 101, 1);
    let before = f.h.native_producer_counts();
    assert_eq!(before.held, 0);
    let fault = ok(f
        .dc
        .fail_next_native_save_deadline_spawn(launch.desktop().bindings().artifact_origin()));
    let error = match ProcessArtifactEditor::open(
        f.h.clone(),
        f.host(),
        launch,
        ok(ChildBudget::checked(5000)),
        1,
    ) {
        Ok(app) => {
            *slot = Some(app);
            panic!("partial Read entry must return the failed open owner");
        }
        Err(failure) => {
            let (error, app) = failure.into_parts();
            *slot = Some(app);
            error
        }
    };
    assert_eq!(error, NativeEditorError::Desktop(Status::Internal));
    let failed = slot.as_mut().unwrap();
    assert!(failed.child.is_none());
    let stage = failed.chains.startup.as_ref().unwrap();
    let Some(desktop::NativeSaveEntryRecovery::Partial(cleanup)) = &stage.entry_failure else {
        panic!("failed open retains the actual installed Read dispatcher");
    };
    assert!(stage.entry.is_none() && stage.registered.is_none());
    let [dispatcher] = cleanup.producer_ids() else {
        panic!("only the real dispatcher installed before supervisor failure");
    };
    assert!(dispatcher.producer_id() > 0);
    assert!(!ok(f.host().native_save_producer_joined(dispatcher)));
    assert_eq!(f.h.native_producer_counts().held, before.held + 1);
    assert_eq!(
        ok(failed.cleanup_failed_open(2)),
        ProcessOpenCleanup::Pending
    );
    assert_eq!(
        f.h.native_producer_counts().joined_total,
        before.joined_total
    );
    drop(fault);
    loop {
        match ok(failed.cleanup_failed_open(2)) {
            ProcessOpenCleanup::Complete => break,
            ProcessOpenCleanup::Pending => thread::yield_now(),
            ProcessOpenCleanup::Quarantined => panic!("actual partial Read join did not complete"),
        }
    }
    assert_eq!(failed.assertion_pending_originals(), 0);
    let after = f.h.native_producer_counts();
    assert_eq!(after.held, before.held);
    assert_eq!(after.joined_total, before.joined_total + 1);
    drop(slot.take());

    let launch = f.launch(0, 101, 3);
    let (reply, revision, body) = fixture::read(f, &launch, 1400, 3);
    assert_eq!((revision, body.as_slice()), (1, OLD));
    assert_eq!(f.counts(101), (0, 0, 0));
    drop((reply, launch));
    let (fixture, slot) = retained.0.take().unwrap();
    assert!(slot.is_none());
    fixture.finish();
}

#[test]
fn process_d15_genuine_store_resource_boundaries() {
    for case in ["D15C08", "D15C11"] {
        for scenario in ok(ProcessAssertionScenario::for_case(case)) {
            let mut owner = OwnedApp::open(scenario.id(), scenario);
            let before = owner.fixture.as_ref().unwrap().counts(101);
            match scenario.id() {
                "D15InflightSaveTwo" => {
                    owner.replace(NEW, 2);
                    let p = owner.pause(store::PausePoint::AfterCommitPermit);
                    owner.chord(22, 2);
                    assert!(owner.reach_pause(&p, 2).permit_issued);
                    let (op, entered, deadline, _) = actual_original(&mut owner);
                    owner.chord(22, 2);
                    assert_original_held(&owner, op, entered, deadline);
                    assert_eq!(owner.fixture.as_ref().unwrap().counts(101), (1, 1, 0));
                    owner.release_pause(&p);
                    settle_original(&mut owner, 2, 3);
                    owner.replace(OLD, 3);
                    owner.save(3, 3);
                }
                "D15StoreDataThirtyThree" => store_data_cap(&mut owner),
                "D15StorePinSeventeen" => store_pin_cap(&mut owner),
                "D15StorePendingSeventeen" => store_pending_cap(&mut owner),
                "D15StoreQuerySixtyFive" => store_query_cap(&mut owner),
                "D15StoreProducerSixtyFive" => store_producer_cap(&mut owner),
                "D15StoreIoThree" => store_io_cap(&mut owner),
                other => panic!("unreviewed genuine Store cap {other}"),
            }
            if !matches!(scenario.id(), "D15InflightSaveTwo" | "D15StoreIoThree") {
                assert_eq!(owner.fixture.as_ref().unwrap().counts(101), before);
                if !matches!(
                    scenario.id(),
                    "D15StorePendingSeventeen" | "D15StoreProducerSixtyFive"
                ) {
                    owner.reopen_child(OLD, 3);
                }
                // Pending17 kept this same genuine A process/approval valid
                // while B filled the context cap. Its actual input and Save
                // demonstrate progress without a 34th diagnostic grant row.
                if scenario.id() != "D15StoreProducerSixtyFive" {
                    owner.replace(NEW, 3);
                }
                owner.save(2, 3);
                if scenario.id() == "D15StoreProducerSixtyFive" {
                    assert_eq!(owner.fixture.as_ref().unwrap().counts(101), (1, 1, 1));
                    assert_receipt(&owner, 1, NEW);
                }
            }
            owner.finish(3);
        }
    }
}

#[cfg(target_os = "linux")]
struct OwnedTestProcess {
    child: Option<std::process::Child>,
}
#[cfg(target_os = "linux")]
impl OwnedTestProcess {
    fn new(child: std::process::Child) -> Self {
        Self { child: Some(child) }
    }
}
#[cfg(target_os = "linux")]
impl Drop for OwnedTestProcess {
    fn drop(&mut self) {
        let Some(child) = self.child.as_mut() else {
            return;
        };
        let _ = child.kill();
        let end = Instant::now() + Duration::from_millis(2000);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if Instant::now() < end => thread::sleep(Duration::from_millis(1)),
                _ => break,
            }
        }
        eprintln!("INCOMPLETE: retained sole owned direct subprocess after cleanup deadline");
        std::mem::forget(self.child.take());
    }
}

#[cfg(target_os = "linux")]
fn isolated_command(entry: &str) -> std::process::Command {
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command.args([
        "--exact",
        entry,
        "--ignored",
        "--nocapture",
        "--test-threads=1",
    ]);
    command
}

#[test]
#[cfg(target_os = "linux")]
fn process_d29_actual_parent_death_retains_uncertain_store_quarantine() {
    for mode in ["parent_death", "drop_child"] {
        let mut outer = OwnedTestProcess::new(
            isolated_command("native::process_assertions::owned_parent_death_outer_worker")
                .env("RAMEN_PROCESS_PARENT_DEATH_MODE", mode)
                .spawn()
                .expect("actual owned outer"),
        );
        let end = Instant::now() + Duration::from_millis(15000);
        let status = loop {
            if let Some(status) = outer.child.as_mut().unwrap().try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= end {
                let _ = outer.child.as_mut().unwrap().kill();
                eprintln!("INCOMPLETE: actual outer deadline; all quarantine remains");
                panic!("owned outer did not finish by original deadline");
            }
            thread::sleep(Duration::from_millis(1));
        };
        assert!(
            status.success(),
            "actual subreaper evidence failed for {mode}"
        );
    }
}

#[test]
#[ignore = "private reexec helper; selected only by the actual D29 outer test"]
#[cfg(target_os = "linux")]
fn owned_parent_death_outer_worker() {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        io::{AsRawFd, FromRawFd},
        net::UnixListener,
    };
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
        0
    );
    let mode = std::env::var("RAMEN_PROCESS_PARENT_DEATH_MODE").unwrap();
    assert!(matches!(mode.as_str(), "parent_death" | "drop_child"));
    let channel = tempfile::Builder::new()
        .prefix("ramen-d29-private-")
        .tempdir()
        .unwrap();
    std::fs::set_permissions(channel.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = channel.path().join("control");
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let nonce = format!(
        "{}-{}",
        std::process::id(),
        Instant::now().elapsed().as_nanos()
    );
    let parent = isolated_command("native::process_assertions::owned_parent_death_worker")
        .env("RAMEN_PROCESS_PARENT_DEATH_MODE", &mode)
        .env("RAMEN_PROCESS_PARENT_DEATH_SOCKET", &socket)
        .env("RAMEN_PROCESS_PARENT_DEATH_NONCE", &nonce)
        .spawn()
        .unwrap();
    let mut guard = OwnedTestProcess::new(parent);
    let end = Instant::now() + Duration::from_millis(5000);
    let (mut stream, _) = loop {
        match listener.accept() {
            Ok(v) => break v,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < end);
                thread::yield_now();
            }
            Err(e) => panic!("private accept:{e}"),
        }
    };
    stream
        .set_read_timeout(Some(Duration::from_millis(3000)))
        .unwrap();
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    assert_eq!(
        unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut _,
                &mut len,
            )
        },
        0
    );
    assert_eq!(
        cred.pid as u32,
        guard.child.as_ref().unwrap().id(),
        "kernel authenticates the actual owned parent"
    );
    let mut line = String::new();
    BufReader::new(stream.try_clone().unwrap())
        .read_line(&mut line)
        .unwrap();
    let record: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(record["nonce"], nonce);
    assert_eq!(record["mode"], mode);
    let parent_birth = proc_identity(guard.child.as_ref().unwrap().id() as i32).1;
    let child = record["child_pid"].as_u64().unwrap() as i32;
    let birth = record["child_birth_ticks"].as_u64().unwrap();
    let mut descendants = Vec::new();
    for task in
        std::fs::read_dir(format!("/proc/{}/task", guard.child.as_ref().unwrap().id())).unwrap()
    {
        let task = task.unwrap();
        if let Ok(children) = std::fs::read_to_string(task.path().join("children")) {
            descendants.extend(
                children
                    .split_whitespace()
                    .map(|p| p.parse::<i32>().unwrap()),
            );
        }
    }
    assert!(
        descendants.contains(&child),
        "actual supervisor may fork from any owned parent thread"
    );
    assert_eq!(proc_identity(child).1, birth);
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, child, 0) } as i32;
    assert!(raw >= 0);
    let pidfd = unsafe { std::fs::File::from_raw_fd(raw) };
    let parent_raw =
        unsafe { libc::syscall(libc::SYS_pidfd_open, guard.child.as_ref().unwrap().id(), 0) }
            as i32;
    assert!(parent_raw >= 0);
    let mut descendant = AdoptedCleanup {
        pid: child,
        birth,
        pidfd: Some(pidfd.try_clone().unwrap()),
        parent: unsafe { std::fs::File::from_raw_fd(parent_raw) },
        armed: true,
    };
    assert_eq!(
        proc_identity(child).1,
        birth,
        "birth recheck after held pidfd"
    );
    let executable = std::fs::read(format!("/proc/{child}/exe")).unwrap();
    let actual_executable_sha256: [u8; 32] = {
        use sha2::Digest;
        sha2::Sha256::digest(&executable).into()
    };
    assert_eq!(
        serde_json::json!(actual_executable_sha256),
        record["executable_sha256"]
    );
    let root = std::path::PathBuf::from(record["root"].as_str().unwrap());
    let held_root = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(&root)
        .unwrap();
    let metadata = held_root.metadata().unwrap();
    assert_eq!(metadata.dev(), record["root_dev"].as_u64().unwrap());
    assert_eq!(metadata.ino(), record["root_ino"].as_u64().unwrap());
    assert!(record["operation_id"].as_u64().unwrap() > 0);
    assert_eq!(record["permit_count"], 1);
    assert_eq!(record["transition_count"], 0);
    stream.write_all(b"metadata-verified\n").unwrap();
    guard.child.as_mut().unwrap().kill().unwrap();
    let end = Instant::now() + Duration::from_millis(2000);
    let parent_status = loop {
        if let Some(status) = guard.child.as_mut().unwrap().try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < end);
        thread::yield_now();
    };
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(parent_status.signal(), Some(libc::SIGKILL));
    let end = Instant::now() + Duration::from_millis(2000);
    loop {
        let (ppid, current_birth) = proc_identity(child);
        assert_eq!(current_birth, birth);
        if ppid == std::process::id() as i32 {
            break;
        }
        assert!(
            Instant::now() < end,
            "child must be legally adopted before outer signal/wait"
        );
        thread::yield_now();
    }
    let signal_result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    let signal_errno = if signal_result < 0 {
        std::io::Error::last_os_error().raw_os_error()
    } else {
        None
    };
    assert!(
        signal_result == 0
            || (mode == "drop_child" && signal_result == -1 && signal_errno == Some(libc::ESRCH)),
        "actual drop may already terminate child while sole supervisor is held before wait"
    );
    let mut status = 0;
    let mut wait_records = Vec::new();
    let end = Instant::now() + Duration::from_millis(2000);
    loop {
        let waited = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
        let errno = if waited < 0 {
            std::io::Error::last_os_error().raw_os_error()
        } else {
            None
        };
        wait_records
            .push(serde_json::json!({"returned_pid":waited,"raw_status":status,"errno":errno}));
        if waited == child {
            break;
        }
        assert_eq!(waited, 0);
        assert!(Instant::now() < end);
        thread::sleep(Duration::from_millis(1));
    }
    assert!(libc::WIFSIGNALED(status) || libc::WIFEXITED(status));
    descendant.armed = false;
    let decoded_wait = if libc::WIFSIGNALED(status) {
        serde_json::json!({"Signaled":libc::WTERMSIG(status)})
    } else {
        serde_json::json!({"Exited":libc::WEXITSTATUS(status)})
    };
    let evidence = serde_json::json!({"actual_waitpid_records":wait_records,"actual_terminal_wait":decoded_wait,"pidfd_signal_result":signal_result,"pidfd_signal_errno":signal_errno,"parent_birth_ticks":parent_birth,"parent_peercred":{"pid":cred.pid,"uid":cred.uid,"gid":cred.gid},"parent_exit_raw":parent_status.into_raw(),"scenario":"D29ActualParentDeathSubreaperQuarantine","mode":mode,"actual_parent_pid":guard.child.as_ref().unwrap().id(),"native_child_pid":child,"native_child_birth_ticks":birth,"outer_adopted_and_waited":true,"dead_parent_supervisor_joined":false,"store_producers_joined":false,"store_outcome":"unknown","quarantined":true,"original":record});
    // Root is intentionally retained. Kernel terminal wait does not prove a
    // dead Rust supervisor join, Store fence, absence, or original Save outcome.
    std::fs::write(
        root.join(format!("d29-{mode}-quarantine.json")),
        serde_json::to_vec_pretty(&evidence).unwrap(),
    )
    .unwrap();
    assert!(root.is_dir());
    std::mem::forget(held_root);
    println!("\nD29_ACTUAL_QUARANTINE {}", evidence);
}

#[cfg(target_os = "linux")]
struct AdoptedCleanup {
    pid: i32,
    birth: u64,
    pidfd: Option<std::fs::File>,
    parent: std::fs::File,
    armed: bool,
}
#[cfg(target_os = "linux")]
impl Drop for AdoptedCleanup {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        if !self.armed {
            return;
        }
        // Both descriptors were held only after verifying the owned parent and
        // its actual descendant. Kill the genuine parent to obtain legal adoption.
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.parent.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            );
        }
        let end = Instant::now() + Duration::from_millis(2000);
        while Instant::now() < end {
            let stat = std::fs::read_to_string(format!("/proc/{}/stat", self.pid));
            let Ok(stat) = stat else {
                eprintln!(
                    "INCOMPLETE: verified descendant vanished; no dead-parent Rust join claim"
                );
                break;
            };
            let Some(close) = stat.rfind(')') else {
                break;
            };
            let Some(rest) = stat.get(close + 2..) else {
                break;
            };
            let fields: Vec<_> = rest.split_whitespace().collect();
            if fields.get(19).and_then(|v| v.parse::<u64>().ok()) != Some(self.birth) {
                eprintln!("INCOMPLETE: held descendant birth changed");
                break;
            }
            if fields.get(1).and_then(|v| v.parse::<u32>().ok()) == Some(std::process::id()) {
                unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        self.pidfd.as_ref().unwrap().as_raw_fd(),
                        libc::SIGKILL,
                        std::ptr::null::<libc::siginfo_t>(),
                        0,
                    );
                }
                let mut status = 0;
                let waited = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
                if waited == self.pid {
                    eprintln!(
                        "INCOMPLETE: actual adopted descendant reaped; Store/root remains quarantined"
                    );
                    return;
                }
                if waited < 0 {
                    eprintln!("INCOMPLETE: adopted wait failed; held pidfd remains quarantined");
                    break;
                }
            }
            thread::yield_now();
        }
        std::mem::forget(self.pidfd.take());
        eprintln!(
            "INCOMPLETE: retained descendant descriptor; cleanup uncertainty, no release claim"
        );
    }
}

#[cfg(target_os = "linux")]
fn proc_identity(pid: i32) -> (i32, u64) {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let fields: Vec<_> = stat[stat.rfind(')').unwrap() + 2..]
        .split_whitespace()
        .collect();
    (fields[1].parse().unwrap(), fields[19].parse().unwrap())
}

#[test]
#[ignore = "private actual parent; SIGKILL prevents Rust parent cleanup by design"]
#[cfg(target_os = "linux")]
fn owned_parent_death_worker() {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::{fs::MetadataExt, net::UnixStream};
    let mode = std::env::var("RAMEN_PROCESS_PARENT_DEATH_MODE").unwrap();
    let group = if mode == "drop_child" {
        "D29C05"
    } else {
        "D29P"
    };
    let scenarios = ok(ProcessAssertionScenario::for_case(group));
    assert_eq!(scenarios.len(), 1);
    let mut owner = OwnedApp::open(scenarios[0].id(), &scenarios[0]);
    owner.replace(NEW, 2);
    let pause = owner.pause(store::PausePoint::AfterCommitPermit);
    owner.chord(22, 2);
    assert!(owner.reach_pause(&pause, 2).permit_issued);
    let (operation, entered, deadline, binding) = actual_original(&mut owner);
    owner.open_other(2);
    owner.replace_other(C, 2);
    owner.save_other(2, 2);
    let b = owner.other.as_mut().unwrap();
    ok(b.retire(ProcessRetireReason::HumanClose, 2));
    let end = Instant::now() + Duration::from_millis(2000);
    let bproof = loop {
        match b.join_child() {
            Ok(proof) => break proof,
            Err(NativeEditorError::Desktop(Status::NotReady)) => assert!(Instant::now() < end),
            Err(error) => panic!("B actual child join:{error:?}"),
        }
    };
    assert!(bproof.supervisor_joined());
    assert!(b.chains.pending.is_empty());
    owner.proofs.push(bproof);
    owner.other.take();
    assert_original_held(&owner, operation, entered, deadline);
    let app = owner.app.as_ref().unwrap();
    let child = ok(app
        .chains
        .desktop
        .observe_process_child(app.child.as_ref().unwrap()));
    let pid = child.process_id();
    let birth = child.birth_ticks();
    let executable_sha256 = child.executable_sha256();
    if mode == "drop_child" {
        drop(owner.app.as_mut().unwrap().child.take().unwrap());
        let checkpoint = ok(owner
            .run
            .as_ref()
            .unwrap()
            .wait_checkpoint(ProcessAssertionPoint::SupervisorBeforeSignal, 1000));
        assert_eq!(
            checkpoint.point(),
            ProcessAssertionPoint::SupervisorBeforeSignal
        );
        assert_original_held(&owner, operation, entered, deadline);
    }
    let f = owner.fixture.as_ref().unwrap();
    let metadata = std::fs::metadata(&f.path).unwrap();
    let record = serde_json::json!({"nonce":std::env::var("RAMEN_PROCESS_PARENT_DEATH_NONCE").unwrap(),"mode":mode,"child_pid":pid,"child_birth_ticks":birth,"executable_sha256":executable_sha256,"root":f.path,"root_dev":metadata.dev(),"root_ino":metadata.ino(),"operation_id":operation,"original_binding":binding,"original_entered_age_ns":entered.elapsed().as_nanos().to_string(),"original_deadline_remaining_ns":deadline.saturating_duration_since(Instant::now()).as_nanos().to_string(),"actor_session":binding.allocation.actor.session_id,"actor_instance":binding.allocation.actor.instance_id,"permit_count":f.counts(101).1,"transition_count":f.counts(101).2,"actual_child_dropped":mode=="drop_child","rust_supervisor_joined":false,"store_producers_joined":false});
    let mut stream =
        UnixStream::connect(std::env::var("RAMEN_PROCESS_PARENT_DEATH_SOCKET").unwrap()).unwrap();
    writeln!(stream, "{record}").unwrap();
    let mut ack = String::new();
    BufReader::new(stream.try_clone().unwrap())
        .read_line(&mut ack)
        .unwrap();
    assert_eq!(ack, "metadata-verified\n");
    // Parent remains alive with its actual Store writer held. Only the outer
    // legally owned std::process::Child controller terminates this process.
    loop {
        thread::park_timeout(Duration::from_millis(100));
    }
}

fn refuse_unresolved_restart(owner: &mut OwnedApp, expected_selected: &[u8], now: u64) {
    let f = owner.fixture.as_mut().unwrap();
    assert_eq!(selected_blob(f, 101), expected_selected);
    let launch = f.launch(0, 101, now);
    let candidate = boot(&launch);
    let actual_old = owner.app.as_ref().unwrap().chains.pending[0]
        .intent
        .snapshot()
        .view()
        .actor;
    assert_ne!(
        candidate.instance_id, actual_old.instance_id,
        "restart has a real fresh approval, not reconstructed authority"
    );
    let before = f.counts(101);
    let failure = match ProcessArtifactEditor::open(
        f.h.clone(),
        f.host(),
        launch,
        ok(ChildBudget::checked(5000)),
        now,
    ) {
        Ok(app) => {
            owner.other = Some(app);
            panic!(
                "unresolved original improperly admitted a guessed-base child; retain actual child"
            );
        }
        Err(failure) => failure,
    };
    let (error, retained) = failure.into_parts();
    owner.other = Some(retained);
    assert!(
        matches!(error, NativeEditorError::Desktop(Status::NotReady)),
        "unresolved original has an explicit pending restart denial"
    );
    let refused = owner.other.as_mut().unwrap();
    assert!(
        refused.child.is_none(),
        "no spawn or current observation from guessed disk base"
    );
    assert!(matches!(
        refused.observe(now),
        Err(NativeEditorError::Desktop(Status::NotReady))
    ));
    assert_eq!(
        f.counts(101),
        before,
        "restart Read never allocates/commits or replays original Save"
    );
    assert!(refused.chains.pending.is_empty());
    let cleanup_deadline = Instant::now() + Duration::from_millis(2000);
    loop {
        match ok(refused.cleanup_failed_open(now)) {
            ProcessOpenCleanup::Complete => break,
            ProcessOpenCleanup::Pending => assert!(
                Instant::now() < cleanup_deadline,
                "retain failed restart owners across original bounded cleanup"
            ),
            ProcessOpenCleanup::Quarantined => {
                panic!("INCOMPLETE: failed restart stays quarantined with original owners")
            }
        }
    }
    owner.other.take();
}

#[test]
fn process_d23_unknown_cannot_choose_old_or_new_base() {
    let scenarios = ok(ProcessAssertionScenario::for_case("D23C04"));
    assert_eq!(scenarios.len(), 1);
    let scenario = &scenarios[0];
    let mut owner = OwnedApp::open(scenario.id(), scenario);
    owner.replace(NEW, 2);
    let pause = owner.pause(store::PausePoint::AfterCommitPermit);
    owner.chord(22, 2);
    assert!(owner.reach_pause(&pause, 2).permit_issued);
    let (operation, entered, deadline, binding) = actual_original(&mut owner);
    {
        let (f, app) = owner.parts();
        ok(f.prepared()
            .controller()
            .drop_next_native_reply(app.chains.launch.endpoint()));
    }
    // Actual monotonic capture/stage expiry while the same permitted writer is
    // held produces Unknown. No phase/receipt/base setter participates.
    owner.until(2, |view| view.phase == desktop::NativeEditorPhase::Unknown);
    owner.retire_and_join(ProcessRetireReason::ChildFault, 2);
    assert_original_held(&owner, operation, entered, deadline);
    assert_eq!(owner.fixture.as_ref().unwrap().counts(101), (1, 1, 0));
    refuse_unresolved_restart(&mut owner, OLD, 3);
    assert_original_held(&owner, operation, entered, deadline);
    // Let the genuine issued writer finish, suppressing its caller reply.
    // Do not pump/reconcile the original before trying the now-NEW disk base.
    owner.release_pause(&pause);
    assert_eq!(owner.fixture.as_ref().unwrap().counts(101), (1, 1, 1));
    assert_eq!(selected_blob(owner.fixture.as_ref().unwrap(), 101), NEW);
    assert_original_held(&owner, operation, entered, deadline);
    refuse_unresolved_restart(&mut owner, NEW, 3);
    assert_original_held(&owner, operation, entered, deadline);
    assert_eq!(owner.fixture.as_ref().unwrap().counts(101), (1, 1, 1));
    // Only the actual original observation path may settle uncertainty, after
    // which a new approved actor can read the confirmed base and Save again.
    settle_original(&mut owner, 2, 4);
    assert_receipt(&owner, operation, NEW);
    owner.reopen_child(NEW, 4);
    assert_ne!(
        ok(owner.app.as_ref().unwrap().observe(4)).actor.instance_id,
        binding.allocation.actor.instance_id
    );
    owner.replace(OLD, 4);
    owner.save(3, 4);
    assert_eq!(owner.fixture.as_ref().unwrap().counts(101), (2, 2, 2));
    let evidence = owner.finish(4);
    assert_eq!(evidence.scenario_id(), scenario.id());
}
