//! Existing genuine app Save consumers, shared by full P3 acceptance.
use super::*;
#[path = "app_owner.rs"]
mod app_owner;

struct ReleasePauseOnce {
    owner: std::sync::Arc<store_service::editor_store::PreparedNativeSaveStore>,
    pause: std::sync::Arc<store_service::editor_store::PauseToken>,
    armed: bool,
}
impl ReleasePauseOnce {
    fn request_release(&mut self) {
        assert!(self.armed, "same pause release is requested only once");
        ok(self.owner.controller().release(&self.pause));
        // The Fixture still retains this exact token and actual Store owner.
        // Only successful real release disarms the unwind fallback.
        self.armed = false;
    }
}
impl Drop for ReleasePauseOnce {
    fn drop(&mut self) {
        if self.armed && self.owner.controller().release(&self.pause).is_err() {
            eprintln!("INCOMPLETE: actual Store pause release failed; fixture retains owners");
        }
    }
}

fn app_until_at(
    f: &Fixture,
    app: &mut artifact_editor::ProcessArtifactEditor,
    expected: &[u8],
    saved: bool,
    now: u64,
) {
    let end = Instant::now() + Duration::from_millis(1000);
    let mut composed_tuple = None;
    loop {
        let publication = match app.step(now) {
            Ok(step) => step.publication_accepted(),
            Err(artifact_editor::NativeEditorError::Desktop(Status::NotReady | Status::Stale)) => {
                false
            }
            Err(error) => panic!("genuine process progress failed: {error:?}"),
        };
        if let Ok(view) = app.observe(now) {
            let tuple = (
                view.text_generation,
                view.view_version,
                view.confirmed_revision,
            );
            if publication || composed_tuple != Some(tuple) {
                match f.compose(0, now) {
                    Ok(_) => composed_tuple = Some(tuple),
                    Err(Status::NotReady | Status::Stale) => {}
                    Err(error) => panic!("genuine protected composition failed: {error:?}"),
                }
            }
            let current = ok(app.observe(now));
            if current.bytes == expected
                && (!saved || current.phase == desktop::NativeEditorPhase::Saved)
            {
                return;
            }
        }
        assert!(
            Instant::now() < end,
            "original one-second public process task: expected={expected:?} saved={saved} now={now} current={:?} store_counts={:?}",
            app.observe(now).map(|view| (
                view.phase,
                view.confirmed_revision,
                view.text_generation,
                view.view_version,
                view.bytes,
            )),
            f.counts(101),
        );
        std::thread::yield_now();
    }
}
fn app_until(
    f: &Fixture,
    app: &mut artifact_editor::ProcessArtifactEditor,
    expected: &[u8],
    saved: bool,
) {
    app_until_at(f, app, expected, saved, 2)
}
fn app_event_at(
    f: &mut Fixture,
    app: &mut artifact_editor::ProcessArtifactEditor,
    usage: u32,
    phase: u32,
    now: u64,
) {
    f.drivers[0].send(&f.h, usage, phase, now);
    let sequence = f.drivers[0].next - 1;
    let end = Instant::now() + Duration::from_millis(1000);
    loop {
        match app.step(now) {
            Ok(step) => {
                if step.publication_accepted() {
                    match f.compose(0, now) {
                        Ok(_) => {}
                        Err(Status::Stale) if app.observe(now).is_ok() => {}
                        Err(error) => {
                            panic!("actual input publication composition failed: {error:?}")
                        }
                    }
                }
                if let Some(consumed) = step.consumed_sequence() {
                    assert!(
                        consumed <= sequence,
                        "actual input ACK cannot skip this delivery"
                    );
                    if consumed == sequence {
                        return;
                    }
                }
            }
            Err(artifact_editor::NativeEditorError::Desktop(Status::Stale))
                if app.observe(now).is_ok() => {}
            Err(error) => panic!(
                "actual public input progress denied: usage={usage} phase={phase} sequence={sequence} error={error:?} current={:?}",
                app.observe(now)
                    .map(|view| (view.phase, view.confirmed_revision)),
            ),
        }
        assert!(
            Instant::now() < end,
            "original one-second input acknowledgement: usage={usage} phase={phase} sequence={sequence} current={:?}",
            app.observe(now)
                .map(|view| (view.phase, view.confirmed_revision)),
        );
        std::thread::yield_now();
    }
}

fn app_replace_at(
    f: &mut Fixture,
    app: &mut artifact_editor::ProcessArtifactEditor,
    body: &[u8],
    now: u64,
) {
    for (u, p) in [(224, 1), (4, 1), (4, 2), (224, 2)] {
        app_event_at(f, app, u, p, now);
    }
    for &byte in body {
        app_event_at(f, app, usage(byte), 1, now);
        app_event_at(f, app, usage(byte), 2, now);
    }
    // Small edits need not reach the normal 16-down/64-delivery batch
    // boundary. Flush through the genuine wrapper-owned ordinary request.
    ok(app.request_frame(now));
    app_until_at(f, app, body, false, now);
}
fn app_replace(f: &mut Fixture, app: &mut artifact_editor::ProcessArtifactEditor, body: &[u8]) {
    app_replace_at(f, app, body, 2)
}
fn app_chord_at(f: &mut Fixture, app: &mut artifact_editor::ProcessArtifactEditor, now: u64) {
    for (u, p) in [(224, 1), (22, 1), (22, 2), (224, 2)] {
        app_event_at(f, app, u, p, now);
    }
}
fn app_chord(f: &mut Fixture, app: &mut artifact_editor::ProcessArtifactEditor) {
    app_chord_at(f, app, 2)
}
fn app_save_at(
    f: &mut Fixture,
    app: &mut artifact_editor::ProcessArtifactEditor,
    body: &[u8],
    now: u64,
) {
    app_chord_at(f, app, now);
    app_until_at(f, app, body, true, now);
}
fn app_save(f: &mut Fixture, app: &mut artifact_editor::ProcessArtifactEditor, body: &[u8]) {
    app_save_at(f, app, body, 2)
}
fn finish_app_at(mut owner: app_owner::AppOwner, now: u64) -> Fixture {
    ok(owner.join(now));
    owner.release(now)
}
fn finish_app(owner: app_owner::AppOwner) -> Fixture {
    finish_app_at(owner, 3)
}
fn fresh_save_after_reopen(mut f: Fixture, body: &[u8]) {
    f.reopen();
    let mut owner = app_owner::AppOwner::new(f);
    ok(owner.open(0, 101, 4));
    let result = catch_unwind(AssertUnwindSafe(|| {
        let (f, app) = owner.borrow();
        app_until_at(f, app, body, false, 5);
        let before = ok(app.observe(5)).confirmed_revision;
        app_replace_at(f, app, b"note=next\n", 5);
        app_save_at(f, app, b"note=next\n", 5);
        assert_eq!(ok(app.observe(5)).confirmed_revision, before + 1);
        assert_eq!(selected_blob(f, 101), b"note=next\n");
    }));
    let f = finish_app_at(owner, 6);
    if let Err(payload) = result {
        std::mem::forget(f);
        resume_unwind(payload);
    }
    f.finish();
}
pub(super) fn public_save_lifecycle(name: &'static str) {
    let mut owner = app_owner::AppOwner::new(fixture::fixture(name, 1));
    ok(owner.open(0, 101, 1));
    let result = catch_unwind(AssertUnwindSafe(|| {
        let (f, app) = owner.borrow();
        app_until(f, app, OLD, false);
        app_replace(f, app, NEW);
        app_save(f, app, NEW);
        assert_eq!(f.counts(101), (1, 1, 1));
        assert_eq!(ok(app.observe(2)).confirmed_revision, 2);
        assert_eq!(selected_blob(f, 101), NEW);
    }));
    let f = finish_app(owner);
    if let Err(payload) = result {
        std::mem::forget(f);
        resume_unwind(payload);
    }
    fresh_save_after_reopen(f, NEW);
}
#[derive(Clone, Copy)]
pub(super) enum SaveInterruption {
    NewerDraft,
    LostCommitReply,
    DeathBeforePermit,
    DeathAfterPermit,
}
pub(super) fn public_interrupted_save(name: &'static str, mode: SaveInterruption) {
    use store_service::editor_store::{PausePoint, StoreStatus};
    let mut owner = app_owner::AppOwner::new(fixture::fixture(name, 1));
    ok(owner.open(0, 101, 1));
    let endpoint = store_service::editor_store::EditorEndpoint {
        peer: owner.endpoint().peer.clone(),
        handle: owner.endpoint().handle,
    };
    let store = owner.fixture().prepared.as_ref().unwrap().clone();
    let point = if matches!(mode, SaveInterruption::DeathBeforePermit) {
        PausePoint::BeforeCommitPermit
    } else {
        PausePoint::AfterCommitPermit
    };
    let pause = std::sync::Arc::new(ok(store.controller().pause_native_save(&endpoint, point)));
    owner
        .fixture()
        .store_pauses
        .push((store.clone(), pause.clone()));
    // Both release guard and actual app/Store/root owners outlive every borrower assertion.
    let mut release = ReleasePauseOnce {
        owner: store.clone(),
        pause: pause.clone(),
        armed: true,
    };
    let result = catch_unwind(AssertUnwindSafe(|| {
        {
            let (f, app) = owner.borrow();
            app_until(f, app, OLD, false);
            app_replace(f, app, NEW);
            app_chord(f, app);
        }
        let end = Instant::now() + Duration::from_millis(1000);
        loop {
            {
                let (_, app) = owner.borrow();
                let _ = app.step(2);
            }
            match pause.wait_until_entered(1) {
                Ok(snapshot) => {
                    assert!(snapshot.entered);
                    break;
                }
                Err(error) if error.status == StoreStatus::Timeout => {}
                Err(error) => panic!("actual Store pause: {:?}", error.status),
            }
            assert!(Instant::now() < end);
        }
        let original = object(owner.fixture(), 101).operations[0]
            .allocation
            .operation_id;
        let before = owner.fixture().counts(101);
        match mode {
            SaveInterruption::NewerDraft => {
                let (f, app) = owner.borrow();
                app_replace(f, app, b"note=later\n");
                app_chord(f, app);
                assert_eq!(
                    f.counts(101),
                    before,
                    "Saving cannot mint a second mutation"
                );
            }
            SaveInterruption::LostCommitReply => {
                ok(store.controller().drop_next_native_reply(&endpoint))
            }
            SaveInterruption::DeathBeforePermit | SaveInterruption::DeathAfterPermit => {
                ok(owner.retire(desktop::ProcessRetireReason::ChildFault, 2));
                ok(owner.join(2));
                let (f, app) = owner.borrow();
                assert!(app.observe(2).is_err());
                assert!(
                    f.h.native_producer_counts().held > 0,
                    "child reap is not a Rust Store producer join"
                );
                assert_eq!(f.counts(101), before);
            }
        }
        release.request_release();
        assert!(ok(pause.wait_until_settled(1000)).settled);
        // The same post-release deadline covers producer completion, the
        // Unknown/no-replay check and explicit original reconciliation.
        let end = Instant::now() + Duration::from_millis(1000);
        if matches!(mode, SaveInterruption::LostCommitReply) {
            loop {
                let (_, app) = owner.borrow();
                let _ = app.step(2);
                if ok(app.observe(2)).phase == desktop::NativeEditorPhase::Unknown {
                    break;
                }
                assert!(
                    Instant::now() < end,
                    "lost post-dispatch reply must remain Unknown before original lookup"
                );
                std::thread::yield_now();
            }
            // Unknown and a released pause do not prove that the real Store
            // writer has finished. Join its producers before inspecting the
            // filesystem, without resolving the retained original yet.
            loop {
                let (f, _) = owner.borrow();
                f.join_all();
                if f.h.native_producer_counts().held == 0 {
                    break;
                }
                assert!(Instant::now() < end, "actual lost-reply producer joins");
                std::thread::yield_now();
            }
            assert_eq!(
                ok(owner.borrow().1.observe(2)).phase,
                desktop::NativeEditorPhase::Unknown
            );
            let counts = owner.fixture().counts(101);
            {
                let (f, app) = owner.borrow();
                app_chord(f, app);
            }
            assert_eq!(
                owner.fixture().counts(101),
                counts,
                "Unknown cannot replay Allocate/Commit"
            );
        }
        loop {
            let (f, app) = owner.borrow();
            f.join_all();
            match app.reconcile_originals(3) {
                Ok(()) => {}
                Err(artifact_editor::NativeEditorError::Desktop(Status::NotReady))
                | Err(artifact_editor::NativeEditorError::Store(StoreStatus::NotReady)) => {}
                Err(error) => panic!("same original reconciliation failed: {error:?}"),
            }
            if app.assertion_pending_originals() == 0 && f.h.native_producer_counts().held == 0 {
                break;
            }
            assert!(
                Instant::now() < end,
                "actual original and producer completion before filesystem evidence"
            );
            std::thread::yield_now();
        }
        assert_eq!(
            object(owner.fixture(), 101).operations[0]
                .allocation
                .operation_id,
            original
        );
        if matches!(mode, SaveInterruption::DeathBeforePermit) {
            assert_eq!(
                owner.fixture().counts(101).1,
                0,
                "no private permit after death"
            );
            assert_eq!(selected_blob(owner.fixture(), 101), OLD);
        } else {
            assert_eq!(owner.fixture().counts(101), (1, 1, 1));
            assert_eq!(selected_blob(owner.fixture(), 101), NEW);
        }
        if matches!(mode, SaveInterruption::NewerDraft) {
            let (f, app) = owner.borrow();
            app_until(f, app, b"note=later\n", false);
            assert_eq!(
                ok(app.observe(3)).phase,
                desktop::NativeEditorPhase::Unsaved
            );
            assert_eq!(ok(app.observe(3)).confirmed_revision, 2);
            app_save(f, app, b"note=later\n");
            assert_eq!(f.counts(101), (2, 2, 2));
        }
    }));
    drop(release);
    let f = if matches!(
        mode,
        SaveInterruption::DeathBeforePermit | SaveInterruption::DeathAfterPermit
    ) {
        {
            let (f, app) = owner.borrow();
            f.join_all();
            ok(app.reconcile_originals(3));
        }
        owner.release(3)
    } else {
        finish_app(owner)
    };
    if let Err(payload) = result {
        std::mem::forget(f);
        resume_unwind(payload);
    }
    fresh_save_after_reopen(
        f,
        if matches!(mode, SaveInterruption::DeathBeforePermit) {
            OLD
        } else if matches!(mode, SaveInterruption::NewerDraft) {
            b"note=later\n"
        } else {
            NEW
        },
    );
}
