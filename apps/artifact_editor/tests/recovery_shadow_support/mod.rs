//! Existing genuine app Save consumers, shared by full P3 acceptance.
use super::*;
#[path = "../process_support/app_owner.rs"]
pub(super) mod app_owner;

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

pub(super) fn app_until_at(
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
pub(super) fn app_until(
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

pub(super) fn app_replace_at(
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
pub(super) fn app_replace(
    f: &mut Fixture,
    app: &mut artifact_editor::ProcessArtifactEditor,
    body: &[u8],
) {
    app_replace_at(f, app, body, 2)
}
fn app_chord_at(f: &mut Fixture, app: &mut artifact_editor::ProcessArtifactEditor, now: u64) {
    for (u, p) in [(224, 1), (22, 1), (22, 2), (224, 2)] {
        app_event_at(f, app, u, p, now);
    }
}
pub(super) fn app_chord(f: &mut Fixture, app: &mut artifact_editor::ProcessArtifactEditor) {
    app_chord_at(f, app, 2)
}
pub(super) fn app_save_at(
    f: &mut Fixture,
    app: &mut artifact_editor::ProcessArtifactEditor,
    body: &[u8],
    now: u64,
) {
    app_chord_at(f, app, now);
    app_until_at(f, app, body, true, now);
}
pub(super) fn app_save(
    f: &mut Fixture,
    app: &mut artifact_editor::ProcessArtifactEditor,
    body: &[u8],
) {
    app_save_at(f, app, body, 2)
}
pub(super) fn finish_app_at(mut owner: app_owner::AppOwner, now: u64) -> Fixture {
    ok(owner.join(now));
    owner.release(now)
}
pub(super) fn finish_app(owner: app_owner::AppOwner) -> Fixture {
    finish_app_at(owner, 3)
}
