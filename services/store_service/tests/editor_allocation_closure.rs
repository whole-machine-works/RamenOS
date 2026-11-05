//! Genuine Store allocation-closure and issuer-backed producer completion controls.
#![cfg(feature = "editor_native_save_v0_dev")]
#[allow(dead_code)]
#[path = "../../desktop/tests/support/editor_host_assertions.rs"]
mod ui_a;
use ui_a as ui;
#[allow(dead_code)]
#[path = "support/editor_store.rs"]
mod legacy;
use desktop_service::editor_dev::{self as desktop, EditorMessage};
use kernel_api::generated::desktop_artifact_v1 as a;
use std::time::{Duration, Instant};
use store_service::editor_store::{self as store, StoreStatus};

struct NativeRig {
    _root: tempfile::TempDir,
    desktop: desktop::HostDesktop,
    _controller: desktop::FixtureController,
    drivers: Vec<ui::Driver>,
    store: store::PreparedNativeSaveStore,
}
impl NativeRig {
    fn new() -> Self {
        let (desktop, controller, witness, enrollment) = store_ok(
            desktop::HostDesktop::new_store_save(ui::config(30000, 600000)),
        );
        let mut drivers = Vec::new();
        for i in 0..2 {
            let session = store_ok(controller.register_store_session(
                i + 1,
                ui::APP,
                ui::MANIFEST,
                101 + i,
                1,
                1,
            ));
            let mut driver = ui::Driver {
                s: session,
                queue: 0,
                next: 1,
                mods: 0,
            };
            driver.attach(&desktop, 1);
            drivers.push(driver);
        }
        #[cfg(target_os = "macos")]
        let root = store_ok(tempfile::tempdir_in("/System/Volumes/Data/private/tmp"));
        #[cfg(not(target_os = "macos"))]
        let root = store_ok(tempfile::tempdir());
        let store = store_ok(store::StoreFixture::prepare_native_save(
            &root.path().join("owner"),
            store::NativeSaveFixtureProfile {
                origin_ms: 1,
                initial_objects: (0..2)
                    .map(|i| store::InitialObject {
                        owner_id: i + 1,
                        object_id: 101 + i,
                        generation: 1,
                        revision: 1,
                        bytes: if i == 0 {
                            b"first\n".to_vec()
                        } else {
                            b"second\n".to_vec()
                        },
                    })
                    .collect(),
                fixture_signing_seed: [0x53; 32],
                fixture_key_id: "reliability-fixture".into(),
            },
            witness,
            enrollment,
        ));
        Self {
            _root: root,
            desktop,
            _controller: controller,
            drivers,
            store,
        }
    }
    fn launch(&mut self, i: usize) -> store::PairedNativeSaveLaunch {
        let driver = &mut self.drivers[i];
        driver.launcher(&self.desktop, 1);
        driver.send(&self.desktop, 40, 1, 1);
        let mut selector = store_ok(self.desktop.take_save_preview_action(&driver.s.chrome.peer));
        let pin = store_ok(
            self.store
                .pin_selection(&driver.s.chrome.peer, 101 + i as u64, 30000),
        );
        store_ok(
            self.desktop
                .prepare_save_preview(&driver.s.chrome.peer, &mut selector, &pin, 1),
        );
        driver.send(&self.desktop, 40, 2, 1);
        driver.send(&self.desktop, 40, 1, 1);
        let mut approval = store_ok(self.desktop.take_save_preview_action(&driver.s.chrome.peer));
        driver.send(&self.desktop, 40, 2, 1);
        let pending = store_ok(self.desktop.confirm_save_preview(
            &driver.s.chrome.peer,
            &mut approval,
            1,
        ));
        let active = store_ok(self.store.activate_save(&pending));
        let mut launch = None;
        store_ok(
            self.desktop
                .take_save_launch(&driver.s.chrome.peer, &mut launch, 1),
        );
        store_ok(active.pair_launch(&mut launch))
    }
    fn read(
        &self,
        launch: &store::PairedNativeSaveLaunch,
        id: u64,
    ) -> (desktop::NativeSaveEntry, store::RegisteredNativeSave) {
        let bootstrap = store_ok(
            kernel_api::generated::desktop_editor_session_v1::InstanceBootstrap::decode(
                launch.desktop().bindings().bootstrap(),
            ),
        );
        let request = store_ok(
            a::ReadSelected {
                request_id: id,
                session_id: bootstrap.session_id,
                session_generation: bootstrap.session_generation,
                instance_id: bootstrap.instance_id,
                instance_generation: bootstrap.instance_generation,
            }
            .encode(launch.endpoint().handle),
        );
        let entry = store_ok(self.desktop.begin_save_read(
            launch.desktop().bindings().artifact_origin(),
            &request,
            1,
        ));
        let registered = store_ok(
            self.store
                .host()
                .register_native_save(launch.endpoint(), store_ok(entry.wait_once())),
        );
        (entry, registered)
    }
    fn join(&self, entry: &desktop::NativeSaveEntry, reply: &store::NativeSaveReply) {
        for id in entry.producer_ids().into_iter().chain(reply.producers()) {
            let end = Instant::now() + Duration::from_secs(2);
            loop {
                match self.store.host().join_native_save_finished(id) {
                    Ok(joined) => {
                        assert_eq!(joined.outcome(), desktop::JoinOutcome::Returned);
                        break;
                    }
                    Err(StoreStatus::NotReady) => {
                        assert!(Instant::now() < end);
                        std::thread::yield_now();
                    }
                    Err(error) => panic!("join failed: {error:?}"),
                }
            }
        }
    }
}
fn store_ok<T, E>(r: Result<T, E>) -> T {
    r.unwrap_or_else(|_| panic!("required positive failed"))
}
fn selected(reply: &store::NativeSaveReply, expected: &[u8]) {
    let wire = store_ok(a::ReadSelectedReply::decode(reply.wire()));
    assert_eq!(wire.status, 0, "approved concurrent Read must succeed");
    let mut bytes = vec![0; wire.byte_len as usize];
    store_ok(
        reply
            .selected()
            .expect("actual owned selected lease")
            .copy_into(0, &mut bytes),
    );
    assert_eq!(&bytes[64..], expected);
}

fn joined(rig: &NativeRig, id: &desktop::ProducerId) {
    let end = Instant::now() + Duration::from_secs(2);
    loop {
        match rig.store.host().join_native_save_finished(id) {
            Ok(proof) => {
                assert_eq!(proof.outcome(), desktop::JoinOutcome::Returned);
                break;
            }
            Err(StoreStatus::NotReady) => {
                assert!(Instant::now() < end);
                std::thread::yield_now();
            }
            Err(error) => panic!("actual producer join failed: {error:?}"),
        }
    }
}
#[test]
fn lookup_completion_memo_authenticates_actual_join_beyond_sixtyfour_origins() {
    let mut rig = NativeRig::new();
    let launch = rig.launch(0);
    let (entry, call) = rig.read(&launch, 100);
    let producer = entry.producer_ids().into_iter().next().unwrap();
    assert!(!store_ok(
        rig.store.host().native_save_producer_joined(&producer)
    ));
    let reply = store_ok(rig.store.host().execute_native_save(&call));
    selected(&reply, b"first\n");
    rig.join(&entry, &reply);
    assert!(store_ok(
        rig.store.host().native_save_producer_joined(&producer)
    ));
    // Retain the authentic first entry/origin while later completed origins pass
    // the old global64-history boundary. No live-row absence is used as proof.
    for request in 101..170 {
        let (next, registered) = rig.read(&launch, request);
        let reply = store_ok(rig.store.host().execute_native_save(&registered));
        rig.join(&next, &reply);
        assert!(store_ok(
            rig.store.host().native_save_producer_joined(&producer)
        ));
    }
    let mut foreign = NativeRig::new();
    let foreign_launch = foreign.launch(0);
    let (foreign_entry, foreign_call) = foreign.read(&foreign_launch, 900);
    assert_eq!(
        rig.store
            .host()
            .native_save_producer_joined(&foreign_entry.producer_ids()[0]),
        Err(StoreStatus::Denied)
    );
    let foreign_reply = store_ok(foreign.store.host().execute_native_save(&foreign_call));
    foreign.join(&foreign_entry, &foreign_reply);
    drop((reply, call, entry));
}

#[test]
fn known_allocation_requires_deadline_readback_and_all_original_joins() {
    let mut rig = NativeRig::new();
    let launch = rig.launch(0);
    let (read, registered) = rig.read(&launch, 1000);
    let mut selected = store_ok(rig.store.host().execute_native_save(&registered));
    let editor = store_ok(selected.take_editor());
    rig.join(&read, &selected);
    store_ok(rig.desktop.render_native_editor(&editor, 1));
    for (usage, phase) in [(224, 1), (22, 1)] {
        rig.drivers[0].send(&rig.desktop, usage, phase, 1);
        store_ok(rig.desktop.step_native_editor(&editor, 1));
    }
    let intent = store_ok(rig.desktop.take_save_intent(&editor));
    let view = intent.snapshot().view();
    let request = store_ok(
        a::AllocateSaveId {
            request_id: 1001,
            session_id: view.actor.session_id,
            session_generation: view.actor.session_generation,
            expected_revision: view.expected_revision,
        }
        .encode(launch.endpoint().handle),
    );
    let allocate = store_ok(rig.desktop.begin_save_allocate(
        launch.desktop().bindings().artifact_origin(),
        &intent,
        &request,
        1,
    ));
    let call = store_ok(
        rig.store
            .host()
            .register_native_save(launch.endpoint(), store_ok(allocate.wait_once())),
    );
    let allocated = store_ok(rig.store.host().execute_native_save(&call));
    let allocation = store_ok(a::AllocateSaveIdReply::decode(allocated.wire()));
    assert_eq!(allocation.status, 0);
    assert!(allocation.operation_id > 0);
    let original = allocated.original();
    let observe = |id| {
        store_ok(
            a::ObserveAllocation {
                request_id: id,
                session_id: view.actor.session_id,
                session_generation: view.actor.session_generation,
                original_allocate_request_id: 1001,
            }
            .encode(launch.endpoint().handle),
        )
    };
    if let Some(delay) = intent.deadline().checked_duration_since(Instant::now()) {
        std::thread::sleep(delay + Duration::from_millis(2));
    }
    let early = store_ok(rig.desktop.begin_save_recovery(
        original.observation_origin(),
        &observe(1002),
        2,
    ));
    let early_reply = store_ok(
        rig.store
            .host()
            .observe_original(store_ok(early.wait_once()), original),
    );
    assert!(
        !early_reply.allocation_closed(),
        "elapsed deadline/dispatcher return cannot replace actual joins"
    );
    for id in early
        .producer_ids()
        .into_iter()
        .chain(early_reply.producers())
    {
        joined(&rig, id);
    }
    rig.join(&allocate, &allocated);
    let lookup = store_ok(rig.desktop.begin_save_recovery(
        original.observation_origin(),
        &observe(1003),
        2,
    ));
    let reply = store_ok(
        rig.store
            .host()
            .observe_original(store_ok(lookup.wait_once()), original),
    );
    assert!(
        reply.allocation_closed(),
        "actual disk readback + native deadline closure + authentic complete original join set"
    );
    assert!(
        matches!(reply.observation(),store::NativeOriginalObservation::AllocationRetained{allocation:a,commit_dispatched:false}if a.operation_id==allocation.operation_id)
    );
    // A target closure witness cannot stand in for the lookup's own joins.
    assert!(
        lookup
            .producer_ids()
            .iter()
            .any(|id| !store_ok(rig.store.host().native_save_producer_joined(id)))
    );
    for id in lookup.producer_ids().into_iter().chain(reply.producers()) {
        joined(&rig, id);
    }
    assert!(
        lookup
            .producer_ids()
            .iter()
            .all(|id| store_ok(rig.store.host().native_save_producer_joined(id)))
    );
}
