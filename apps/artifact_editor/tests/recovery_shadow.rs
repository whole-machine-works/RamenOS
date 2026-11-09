//! Receiving assertions for actual process-owned post-Commit lookup.
#![cfg(all(target_os = "linux", feature = "host_editor_recovery_shadow_v0_dev"))]
#[allow(dead_code)]
#[path = "process_support/fixture.rs"]
mod fixture;
#[allow(dead_code)]
#[path = "recovery_shadow_support/mod.rs"]
mod shadow_support;
#[allow(dead_code)]
#[path = "native_task_support/mod.rs"]
mod support;
use desktop_service::{dev::Status, editor_dev as desktop};
use shadow_support::{app_chord, app_owner::AppOwner, app_replace, app_until};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use store_service::editor_store::{self as store, StoreStatus};
use support::*;

fn prepared_c1() -> store::PreparedStoreShadowModule {
    let bytes = include_bytes!("../../../services/store_service/tests/fixtures/recovery-c1.wasm");
    let identity = store::RecoveryArtifactV0 {
        abi_sha256: [
            0x49, 0xda, 0xf5, 0x2d, 0xd6, 0x69, 0x41, 0x13, 0x76, 0x77, 0x0b, 0x3b, 0xc2, 0xa0,
            0x07, 0xd7, 0xc6, 0xa8, 0xb3, 0x46, 0x84, 0x3b, 0xcd, 0x12, 0x3a, 0x45, 0xda, 0x81,
            0x39, 0xb0, 0xda, 0x60,
        ],
        module_sha256: [
            0x64, 0x58, 0xa1, 0x73, 0xcd, 0x09, 0xe7, 0x3f, 0xe0, 0xbe, 0x59, 0xb1, 0xa2, 0xd3,
            0x39, 0xc2, 0x07, 0x0c, 0x33, 0xac, 0x05, 0x62, 0x8b, 0x3d, 0x2d, 0xd5, 0xfb, 0x26,
            0x4c, 0xb2, 0xe0, 0x79,
        ],
    };
    store::PreparedStoreShadowModule::prepare(bytes, identity).expect("fixed C1 preloaded")
}

#[test]
fn genuine_lost_reply_terminal_and_fresh_save() {
    let mut owner = AppOwner::new(fixture::fixture("i1_shadow_lost_reply", 1));
    ok(owner.open(0, 101, 1));
    owner
        .borrow()
        .1
        .install_recovery_shadow(prepared_c1())
        .expect("install prepared C1");
    let endpoint = store::EditorEndpoint {
        peer: owner.endpoint().peer.clone(),
        handle: owner.endpoint().handle,
    };
    let service = owner.fixture().prepared.as_ref().unwrap().clone();
    let pause = Arc::new(ok(service
        .controller()
        .pause_native_save(&endpoint, store::PausePoint::AfterCommitPermit)));
    owner
        .fixture()
        .store_pauses
        .push((service.clone(), pause.clone()));
    let release = fixture::ReleaseStorePause {
        owner: service.clone(),
        pause: pause.clone(),
    };
    {
        let (f, app) = owner.borrow();
        app_until(f, app, OLD, false);
        app_replace(f, app, NEW);
        app_chord(f, app);
    }
    let end = Instant::now() + Duration::from_secs(1);
    loop {
        let _ = owner.borrow().1.step(2);
        match pause.wait_until_entered(1) {
            Ok(state) => {
                assert!(state.entered && state.permit_issued);
                break;
            }
            Err(error) if error.status == StoreStatus::Timeout => {}
            Err(error) => panic!("actual pause: {:?}", error.status),
        }
        assert!(Instant::now() < end);
    }
    assert_eq!(owner.fixture().counts(101), (1, 1, 0));
    assert_eq!(selected_blob(owner.fixture(), 101), OLD);
    let original = object(owner.fixture(), 101).operations[0]
        .allocation
        .operation_id;
    ok(service.controller().drop_next_native_reply(&endpoint));
    drop(release);
    assert!(ok(pause.wait_until_settled(1000)).settled);
    let end = Instant::now() + Duration::from_secs(1);
    loop {
        let (_, app) = owner.borrow();
        let _ = app.step(2);
        if ok(app.observe(2)).phase == desktop::NativeEditorPhase::Unknown {
            break;
        }
        assert!(
            Instant::now() < end,
            "actual lost reply must produce Unknown"
        );
    }
    let before = owner.fixture().counts(101);
    let end = Instant::now() + Duration::from_secs(1);
    loop {
        let (f, app) = owner.borrow();
        f.join_all();
        match app.reconcile_originals(3) {
            Ok(())
            | Err(artifact_editor::NativeEditorError::Store(StoreStatus::NotReady))
            | Err(artifact_editor::NativeEditorError::Desktop(Status::NotReady)) => {}
            Err(e) => panic!("terminal original recovery: {e:?}"),
        }
        if app.assertion_pending_originals() == 0 && f.h.native_producer_counts().held == 0 {
            break;
        }
        assert!(Instant::now() < end);
    }
    assert_eq!(before, (1, 1, 1));
    assert_eq!(
        object(owner.fixture(), 101).operations[0]
            .allocation
            .operation_id,
        original
    );
    assert_eq!(owner.fixture().counts(101), (1, 1, 1));
    assert_eq!(selected_blob(owner.fixture(), 101), NEW);
    assert!(
        owner.borrow().1.recovery_shadow_record_count() > 0,
        "terminal q7 passed through shadow"
    );
    let records: Vec<_> = owner.borrow().1.drain_recovery_shadow_records().collect();
    assert_eq!(records.len(), 1, "one genuine terminal q7 comparison");
    assert_eq!(records[0].result(), store::ShadowResultTag::Committed);
    assert!(
        records[0].receipt().is_some(),
        "actual terminal receipt retained"
    );
    assert_eq!(owner.borrow().1.recovery_shadow_record_count(), 0);
    let fresh_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let (f, app) = owner.borrow();
        shadow_support::app_until_at(f, app, NEW, true, 3);
        shadow_support::app_replace_at(f, app, b"note=next\n", 4);
        shadow_support::app_save_at(f, app, b"note=next\n", 4);
        assert_eq!(f.counts(101), (2, 2, 2));
        assert_eq!(selected_blob(f, 101), b"note=next\n");
    }));
    if let Err(payload) = fresh_result {
        drop(pause);
        drop(service);
        owner.retain_failure_diagnostics(4, 5, payload);
    }
    drop(pause);
    drop(service);
    shadow_support::finish_app_at(owner, 5).finish();
}
