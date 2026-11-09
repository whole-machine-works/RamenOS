//! Real process-owned q7 pins survive approved module update and rollback.
#![cfg(all(
    target_os = "linux",
    feature = "host_editor_recovery_shadow_update_assertions_v0_dev"
))]
#[allow(dead_code)]
#[path = "process_support/fixture.rs"]
mod fixture;
#[allow(dead_code)]
#[path = "recovery_shadow_support/mod.rs"]
mod shadow_support;
#[allow(dead_code)]
#[path = "native_task_support/mod.rs"]
mod support;
use artifact_editor::{ShadowArmError, ShadowArmOutcome};
use desktop_service::{dev::Status, editor_dev as desktop};
use sha2::{Digest, Sha256};
use shadow_support::{app_chord, app_owner::AppOwner, app_replace_at, app_until_at};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    sync::Arc,
    time::{Duration, Instant},
};
use store_service::editor_store::{self as store, StoreStatus};
use support::*;

const C1: &[u8] = include_bytes!("../../../services/store_service/tests/fixtures/recovery-c1.wasm");
const C2: &[u8] = include_bytes!("../../../services/native_runner/tests/fixtures/recovery-c2.wasm");
fn c1() -> store::PreparedStoreShadowModule {
    store::PreparedStoreShadowModule::prepare(
        C1,
        store::RecoveryArtifactV0 {
            abi_sha256: [
                0x49, 0xda, 0xf5, 0x2d, 0xd6, 0x69, 0x41, 0x13, 0x76, 0x77, 0x0b, 0x3b, 0xc2, 0xa0,
                0x07, 0xd7, 0xc6, 0xa8, 0xb3, 0x46, 0x84, 0x3b, 0xcd, 0x12, 0x3a, 0x45, 0xda, 0x81,
                0x39, 0xb0, 0xda, 0x60,
            ],
            module_sha256: Sha256::digest(C1).into(),
        },
    )
    .unwrap()
}
fn hash_file(path: &std::path::Path) -> [u8; 32] {
    Sha256::digest(fs::read(path).unwrap()).into()
}

#[test]
fn real_inflight_q7_pins_c1_then_c2_across_update_and_rollback() {
    let dir = tempfile::tempdir().unwrap();
    let (c1_path, c2_path, bad_path) = (
        dir.path().join("c1"),
        dir.path().join("c2"),
        dir.path().join("bad"),
    );
    for (path, bytes) in [
        (&c1_path, C1),
        (&c2_path, C2),
        (&bad_path, b"bad".as_slice()),
    ] {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let selector = store::RecoveryShadowSelector::new(c1());
    let mut owner = AppOwner::new(fixture::fixture("update_shadow_real", 1));
    ok(owner.open(0, 101, 1));
    owner
        .borrow()
        .1
        .install_recovery_shadow_selector(selector.clone())
        .unwrap();
    {
        let (fixture, app) = owner.borrow();
        app_until_at(fixture, app, OLD, false, 2);
    }
    let service = owner.fixture().prepared.as_ref().unwrap().clone();
    let endpoint = store::EditorEndpoint {
        peer: owner.endpoint().peer.clone(),
        handle: owner.endpoint().handle,
    };
    let before_child = owner.borrow().1.assertion_child_observation().unwrap();
    let before_host_hash = hash_file(std::path::Path::new("/proc/self/exe"));
    let before_child_hash = hash_file(std::path::Path::new(&format!(
        "/proc/{}/exe",
        before_child.process_id()
    )));
    assert_eq!(before_child_hash, before_child.executable_sha256());
    let wrong = fixture::fixture("update_wrong_store", 1);
    let wrong_service = wrong.prepared.as_ref().unwrap().clone();
    assert!(selector.replace_from_file(&bad_path).is_err());
    fs::write(&bad_path, vec![0u8; C2.len()]).unwrap();
    assert_eq!(
        selector.replace_from_file(&bad_path),
        Err(store::RecoveryShadowUpdateError::Identity)
    );
    fs::set_permissions(&c2_path, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        selector.replace_from_file(&c2_path),
        Err(store::RecoveryShadowUpdateError::Path)
    );
    fs::set_permissions(&c2_path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        selector.pin().unwrap().identity().module_sha256,
        <[u8; 32]>::from(Sha256::digest(C1))
    );
    for (round, text, initial, replacement) in [
        (0, b"note=one\n".as_slice(), C1, &c2_path),
        (1, b"note=two\n".as_slice(), C2, &c1_path),
        (2, b"note=three\n".as_slice(), C1, &c1_path),
    ] {
        let before = owner.fixture().counts(101);
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
            app_replace_at(f, app, text, 2);
            app_chord(f, app);
        }
        let end = Instant::now() + Duration::from_secs(1);
        loop {
            let _ = owner.borrow().1.step(2);
            match pause.wait_until_entered(1) {
                Ok(s) => {
                    assert!(s.entered && s.permit_issued);
                    break;
                }
                Err(e) if e.status == StoreStatus::Timeout => {}
                Err(e) => panic!("permit pause: {:?}", e.status),
            }
            assert!(Instant::now() < end);
        }
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
            assert!(Instant::now() < end);
        }
        let counts = owner.fixture().counts(101);
        assert_eq!(counts, (before.0 + 1, before.1 + 1, before.2 + 1));
        let terminal_object = object(owner.fixture(), 101);
        let terminal_operation = terminal_object.operations.last().unwrap().clone();
        let expected_receipt = terminal_operation
            .receipt
            .clone()
            .expect("committed operation receipt");
        assert_eq!(
            expected_receipt.operation_id,
            terminal_operation.allocation.operation_id
        );
        assert_eq!(
            expected_receipt.backend_service_epoch,
            terminal_operation.allocated_service_epoch
        );
        let end = Instant::now() + Duration::from_secs(1);
        let mut wrong_arm_exchange_count = None;
        let (snapshot, identity) = loop {
            let (f, app) = owner.borrow();
            f.join_all();
            if round == 0 {
                match app.assertion_arm_next_terminal_shadow(wrong_service.controller(), 3) {
                    Err(ShadowArmError::Fixture(_)) => {
                        wrong_arm_exchange_count =
                            Some(ok(service.controller().evidence()).exchanges.len());
                    }
                    Ok(ShadowArmOutcome::NotReady) => {
                        assert!(Instant::now() < end);
                        continue;
                    }
                    _ => panic!("foreign controller must refuse"),
                }
            }
            match app.assertion_arm_next_terminal_shadow(service.controller(), 3) {
                Ok(ShadowArmOutcome::Armed { pause, identity }) => {
                    if let Some(count) = wrong_arm_exchange_count {
                        assert_eq!(
                            ok(service.controller().evidence()).exchanges.len(),
                            count,
                            "correct arm retained the same q7"
                        );
                    }
                    break (pause, identity);
                }
                Ok(ShadowArmOutcome::NotReady) => {
                    assert!(Instant::now() < end);
                }
                Err(e) => panic!("genuine arm failed: {e:?}"),
            }
        };
        assert_eq!(
            identity.module_sha256,
            <[u8; 32]>::from(Sha256::digest(initial))
        );
        std::thread::scope(|scope| {
            let (_, app) = owner.borrow();
            let worker = scope.spawn(move || app.reconcile_originals(3));
            ok(snapshot.wait_until_entered());
            if round < 2 {
                let replacement_identity = selector.replace_from_file(replacement).unwrap();
                assert_eq!(replacement_identity, selector.pin().unwrap().identity());
                assert_ne!(replacement_identity, identity);
                assert_eq!(
                    replacement_identity.module_sha256,
                    <[u8; 32]>::from(Sha256::digest(if round == 0 { C2 } else { C1 }))
                );
            } else {
                assert_eq!(selector.pin().unwrap().identity(), identity);
            }
            let mut snapshot = snapshot;
            ok(snapshot.release());
            ok(snapshot.wait_until_exited());
            worker.join().unwrap().unwrap();
        });
        assert_eq!(owner.fixture().counts(101), counts);
        let records: Vec<_> = owner.borrow().1.drain_recovery_shadow_records().collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].module_identity(), Some(identity));
        assert_eq!(records[0].result(), store::ShadowResultTag::Committed);
        let actual_receipt = artifact_store_schema::editor_save::EditorSaveReceiptV0::decode_le(
            records[0].receipt().expect("actual terminal receipt"),
        )
        .unwrap();
        assert_eq!(actual_receipt, expected_receipt);
        assert_eq!(selected_blob(owner.fixture(), 101), text);
        {
            let (f, app) = owner.borrow();
            app_until_at(f, app, text, true, 3);
        }
        let after_child = owner.borrow().1.assertion_child_observation().unwrap();
        assert_eq!(
            (
                after_child.process_id(),
                after_child.birth_ticks(),
                after_child.executable_sha256()
            ),
            (
                before_child.process_id(),
                before_child.birth_ticks(),
                before_child.executable_sha256()
            )
        );
        assert_eq!(
            hash_file(std::path::Path::new("/proc/self/exe")),
            before_host_hash
        );
        assert_eq!(
            hash_file(std::path::Path::new(&format!(
                "/proc/{}/exe",
                after_child.process_id()
            ))),
            before_child_hash
        );
    }
    {
        let (f, app) = owner.borrow();
        app_replace_at(f, app, b"note=fresh\n", 4);
        shadow_support::app_save_at(f, app, b"note=fresh\n", 4);
    }
    drop(wrong_service);
    wrong.finish();
    drop(service);
    shadow_support::finish_app_at(owner, 5).finish();
}
