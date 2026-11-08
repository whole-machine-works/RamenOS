//! Authentic two-original unpermitted Commit closure; no forged receipt/absence/join.
#![cfg(feature = "editor_recovery_shadow_v0_dev")]
#[allow(dead_code)]
#[path = "../../desktop/tests/support/editor_host_assertions.rs"]
mod ui_a;
use desktop_service::editor_dev::{self as desktop, EditorMessage};
use kernel_api::generated::desktop_artifact_v1 as a;
use std::time::{Duration, Instant};
use store_service::editor_store::{self as store, StoreStatus};
use ui_a as ui;

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
#[track_caller]
fn store_ok<T, E>(r: Result<T, E>) -> T {
    match r {
        Ok(v) => v,
        Err(_) => panic!("required positive failed"),
    }
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

/// An incomplete/panicking test retains the actual owners and private root.
/// Only the explicit settled path below permits their ordinary destruction.
struct Held<T>(Option<T>);
impl<T> Held<T> {
    fn new(value: T) -> Self {
        Self(Some(value))
    }
    fn get(&self) -> &T {
        self.0.as_ref().unwrap()
    }
    fn get_mut(&mut self) -> &mut T {
        self.0.as_mut().unwrap()
    }
    fn settled(mut self) -> T {
        self.0.take().unwrap()
    }
}
impl<T> Drop for Held<T> {
    fn drop(&mut self) {
        if let Some(actual) = self.0.take() {
            std::mem::forget(actual);
            eprintln!("INCOMPLETE: authentic Store/original owners retained; cleanup unproved");
        }
    }
}
#[derive(Default)]
struct Attempt {
    intent: Option<desktop::NativeSaveIntent>,
    allocate_entry: Option<desktop::NativeSaveEntry>,
    allocate_call: Option<store::RegisteredNativeSave>,
    allocated: Option<store::NativeSaveReply>,
    source: Option<store::NativeDraftSource>,
    commit_entry: Option<desktop::NativeSaveEntry>,
    commit_call: Option<store::RegisteredNativeSave>,
    running: Option<store::NativeSaveExecution>,
    committed: Option<store::NativeSaveReply>,
    pause: Option<store::PauseToken>,
}
fn join_lookup(
    rig: &NativeRig,
    entry: &desktop::NativeSaveEntry,
    reply: &store::NativeOriginalReply,
) {
    for id in entry.producer_ids().into_iter().chain(reply.producers()) {
        joined(rig, id);
    }
}
fn commit_lookup(
    rig: &NativeRig,
    launch: &store::PairedNativeSaveLaunch,
    attempt: &Attempt,
    id: u64,
    op: u64,
) -> (desktop::NativeSaveEntry, store::NativeOriginalReply) {
    let view = attempt.intent.as_ref().unwrap().snapshot().view();
    let request = store_ok(
        a::SaveStatus {
            request_id: id,
            session_id: view.actor.session_id,
            session_generation: view.actor.session_generation,
            operation_id: op,
        }
        .encode(launch.endpoint().handle),
    );
    let original = attempt.commit_call.as_ref().unwrap().original();
    let entry = store_ok(rig.desktop.begin_save_recovery(
        original.observation_origin(),
        &request,
        2,
    ));
    let reply = store_ok(
        rig.store
            .host()
            .observe_original(store_ok(entry.wait_once()), original),
    );
    (entry, reply)
}
#[test]
fn real_commit_pending_then_terminal_replay_refused_and_fresh_owner_remains_usable() {
    let module = store_ok(store::PreparedStoreShadowModule::prepare(
        include_bytes!("fixtures/recovery-c1.wasm"),
        store::RecoveryArtifactV0 {
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
        },
    ));
    let mut rig = Held::new(NativeRig::new());
    let launch = rig.get_mut().launch(0);
    let (entry, registered) = rig.get().read(&launch, 1000);
    let mut read = store_ok(rig.get().store.host().execute_native_save(&registered));
    let editor = store_ok(read.take_editor());
    rig.get().join(&entry, &read);
    let frame = store_ok(rig.get().desktop.render_native_editor(&editor, 1));
    store_ok(
        rig.get()
            .desktop
            .compose_native_save(&rig.get().drivers[0].s.compositor, 1),
    );
    let actor = store_ok(rig.get().desktop.editor_observation(&editor, 1)).actor;
    let assigned: kernel_api::generated::desktop_focus_v1::AssignReply = ui::call(
        &rig.get().desktop,
        &rig.get().drivers[0].s.chrome,
        kernel_api::generated::desktop_focus_v1::Assign {
            request_id: 201,
            session_id: actor.session_id,
            session_generation: actor.session_generation,
            instance_id: actor.instance_id,
            instance_generation: actor.instance_generation,
            surface_id: frame.surface_id,
            surface_generation: frame.surface_generation,
        },
        1,
    );
    assert_eq!(assigned.status, 0);
    for (usage, phase) in [(224, 1), (22, 1), (22, 2), (224, 2)] {
        let actual = rig.get_mut();
        actual.drivers[0].send(&actual.desktop, usage, phase, 1);
        store_ok(actual.desktop.step_native_editor(&editor, 1));
    }
    let mut attempt = Held::new(Attempt::default());
    attempt.get_mut().intent = Some(store_ok(rig.get().desktop.take_save_intent(&editor)));
    let intent = attempt.get().intent.as_ref().unwrap();
    let view = intent.snapshot().view();
    let allocate_request = store_ok(
        a::AllocateSaveId {
            request_id: 1001,
            session_id: view.actor.session_id,
            session_generation: view.actor.session_generation,
            expected_revision: view.expected_revision,
        }
        .encode(launch.endpoint().handle),
    );
    attempt.get_mut().allocate_entry = Some(store_ok(rig.get().desktop.begin_save_allocate(
        launch.desktop().bindings().artifact_origin(),
        attempt.get().intent.as_ref().unwrap(),
        &allocate_request,
        1,
    )));
    attempt.get_mut().allocate_call = Some(store_ok(rig.get().store.host().register_native_save(
        launch.endpoint(),
        store_ok(attempt.get().allocate_entry.as_ref().unwrap().wait_once()),
    )));
    attempt.get_mut().allocated =
        Some(store_ok(rig.get().store.host().execute_native_save(
            attempt.get().allocate_call.as_ref().unwrap(),
        )));
    let allocation = store_ok(a::AllocateSaveIdReply::decode(
        attempt.get().allocated.as_ref().unwrap().wire(),
    ));
    assert_eq!(allocation.status, 0);
    assert!(allocation.operation_id > 0);
    attempt.get_mut().source = Some(store_ok(
        rig.get().store.host().source_for_intent(
            launch.endpoint(),
            attempt
                .get()
                .allocated
                .as_ref()
                .unwrap()
                .allocation()
                .unwrap(),
            attempt.get().intent.as_ref().unwrap(),
        ),
    ));
    let intent = attempt.get().intent.as_ref().unwrap();
    let header = store_ok(
        artifact_store_schema::editor_save::EditorTextHeaderV0::try_new(
            intent.snapshot().view().object_id,
            intent.snapshot().view().expected_revision,
            intent.snapshot().body(),
        ),
    );
    let mut bytes = store_ok(header.encode_le()).to_vec();
    bytes.extend_from_slice(intent.snapshot().body());
    store_ok(store_ok(attempt.get().source.as_ref().unwrap().write_lease()).copy_from(0, &bytes));
    let descriptor = attempt.get().source.as_ref().unwrap().descriptor();
    let view = attempt.get().intent.as_ref().unwrap().snapshot().view();
    let commit_request = store_ok(
        a::Commit {
            request_id: 1002,
            session_id: view.actor.session_id,
            session_generation: view.actor.session_generation,
            expected_revision: view.expected_revision,
            operation_id: allocation.operation_id,
            source_shm: descriptor.handle.pack(),
            byte_len: descriptor.byte_len,
            reserved: 0,
        }
        .encode(launch.endpoint().handle),
    );
    attempt.get_mut().commit_entry = Some(store_ok(rig.get().desktop.begin_save_commit(
        launch.desktop().bindings().artifact_origin(),
        attempt.get().source.as_ref().unwrap().bound(),
        &commit_request,
        1,
    )));
    attempt.get_mut().commit_call = Some(store_ok(rig.get().store.host().register_native_save(
        launch.endpoint(),
        store_ok(attempt.get().commit_entry.as_ref().unwrap().wait_once()),
    )));
    attempt.get_mut().pause =
        Some(store_ok(rig.get().store.controller().pause_native_save(
            launch.endpoint(),
            store::PausePoint::BeforeCommitPermit,
        )));
    attempt.get_mut().running =
        Some(store_ok(rig.get().store.host().start_native_save(
            attempt.get().commit_call.as_ref().unwrap(),
        )));
    let barrier = store_ok(
        attempt
            .get()
            .pause
            .as_ref()
            .unwrap()
            .wait_until_entered(2000),
    );
    assert!(!barrier.permit_issued);
    assert!(
        Instant::now() < attempt.get().intent.as_ref().unwrap().deadline(),
        "early probe is genuinely before original deadline"
    );

    let mut records = store::PostCommitShadowRecords::new();
    let original = attempt.get().commit_call.as_ref().unwrap().original();
    let (first_entry, mut first_reply) = commit_lookup(
        rig.get(),
        &launch,
        attempt.get(),
        1100,
        allocation.operation_id,
    );
    join_lookup(rig.get(), &first_entry, &first_reply);
    let (other_query, other_query_reply) = commit_lookup(
        rig.get(),
        &launch,
        attempt.get(),
        1109,
        allocation.operation_id,
    );
    join_lookup(rig.get(), &other_query, &other_query_reply);
    let foreign = rig
        .get()
        .store
        .host()
        .compare_post_commit_shadow(
            original,
            &other_query,
            &mut first_reply,
            &[],
            &module,
            &mut records,
        )
        .err()
        .expect("another genuine query must not identify this reply");
    assert_eq!(foreign.phase(), store::PostCommitShadowPhase::Preclaim);
    assert_eq!(foreign.status(), StoreStatus::Denied);
    assert!(records.is_empty());
    drop((other_query, other_query_reply));
    let wrong_original = attempt.get().allocated.as_ref().unwrap().original();
    let foreign_original = rig
        .get()
        .store
        .host()
        .compare_post_commit_shadow(
            wrong_original,
            &first_entry,
            &mut first_reply,
            &[],
            &module,
            &mut records,
        )
        .err()
        .expect("the genuine allocation original is not this Commit owner");
    assert_eq!(
        foreign_original.phase(),
        store::PostCommitShadowPhase::Preclaim
    );
    assert_eq!(foreign_original.status(), StoreStatus::Denied);
    assert!(records.is_empty());
    let receipt_copies_before = store_ok(rig.get().store.controller().native_save_artifacts())
        .iter()
        .filter(|r| matches!(r.kind, store::NativeSaveArtifactKind::ReceiptCopy))
        .count();
    let first = rig
        .get()
        .store
        .host()
        .compare_post_commit_shadow(
            original,
            &first_entry,
            &mut first_reply,
            &[],
            &module,
            &mut records,
        )
        .unwrap_or_else(|e| panic!("first compare: {e:?}"));
    assert!(matches!(
        first.into_native(),
        store::PostCommitLookupResult::RetainOriginal
    ));
    let replay = rig
        .get()
        .store
        .host()
        .compare_post_commit_shadow(
            original,
            &first_entry,
            &mut first_reply,
            &[],
            &module,
            &mut records,
        )
        .err()
        .expect("claimed reply is single use");
    assert_eq!(replay.phase(), store::PostCommitShadowPhase::Preclaim);
    // Fill with genuine independent q7 observations, then retry an unclaimed
    // seventeenth reply after draining. The first claimed reply stays spent.
    for index in 0..15 {
        let (entry, mut reply) = commit_lookup(
            rig.get(),
            &launch,
            attempt.get(),
            1110 + index,
            allocation.operation_id,
        );
        join_lookup(rig.get(), &entry, &reply);
        let observed = store_ok(rig.get().store.host().compare_post_commit_shadow(
            original,
            &entry,
            &mut reply,
            &[],
            &module,
            &mut records,
        ));
        assert!(matches!(
            observed.into_native(),
            store::PostCommitLookupResult::RetainOriginal
        ));
    }
    let (retry_entry, mut retry_reply) = commit_lookup(
        rig.get(),
        &launch,
        attempt.get(),
        1130,
        allocation.operation_id,
    );
    join_lookup(rig.get(), &retry_entry, &retry_reply);
    let full = rig
        .get()
        .store
        .host()
        .compare_post_commit_shadow(
            original,
            &retry_entry,
            &mut retry_reply,
            &[],
            &module,
            &mut records,
        )
        .err()
        .expect("record capacity must refuse before claiming reply");
    assert_eq!(full.phase(), store::PostCommitShadowPhase::Preclaim);
    assert_eq!(full.status(), StoreStatus::Exhausted);
    let full_records: Vec<_> = records.drain().collect();
    assert_eq!(full_records.len(), 16);
    assert!(
        full_records
            .iter()
            .all(|r| r.result() == store::ShadowResultTag::Pending && r.receipt().is_none())
    );
    assert_eq!(
        store_ok(rig.get().store.controller().native_save_artifacts())
            .iter()
            .filter(|r| matches!(r.kind, store::NativeSaveArtifactKind::ReceiptCopy))
            .count(),
        receipt_copies_before
    );
    let retried = store_ok(rig.get().store.host().compare_post_commit_shadow(
        original,
        &retry_entry,
        &mut retry_reply,
        &[],
        &module,
        &mut records,
    ));
    assert!(matches!(
        retried.into_native(),
        store::PostCommitLookupResult::RetainOriginal
    ));
    let still_spent = rig
        .get()
        .store
        .host()
        .compare_post_commit_shadow(
            original,
            &first_entry,
            &mut first_reply,
            &[],
            &module,
            &mut records,
        )
        .err()
        .expect("draining never resets claimed reply");
    assert_eq!(still_spent.phase(), store::PostCommitShadowPhase::Preclaim);
    store_ok(
        rig.get()
            .store
            .controller()
            .release(attempt.get().pause.as_ref().unwrap()),
    );
    let end = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(reply) = store_ok(attempt.get().running.as_ref().unwrap().poll_once()) {
            attempt.get_mut().committed = Some(reply);
            break;
        }
        assert!(Instant::now() < end);
        std::thread::yield_now();
    }
    rig.get().join(
        attempt.get().allocate_entry.as_ref().unwrap(),
        attempt.get().allocated.as_ref().unwrap(),
    );
    rig.get().join(
        attempt.get().commit_entry.as_ref().unwrap(),
        attempt.get().committed.as_ref().unwrap(),
    );
    let original = attempt.get().commit_call.as_ref().unwrap().original();
    let (terminal_entry, mut terminal_reply) = commit_lookup(
        rig.get(),
        &launch,
        attempt.get(),
        1101,
        allocation.operation_id,
    );
    join_lookup(rig.get(), &terminal_entry, &terminal_reply);
    let terminal = store_ok(rig.get().store.host().compare_post_commit_shadow(
        original,
        &terminal_entry,
        &mut terminal_reply,
        &[],
        &module,
        &mut records,
    ));
    assert!(matches!(
        terminal.into_native(),
        store::PostCommitLookupResult::ReceiptValidated
    ));
    assert_eq!(records.len(), 2);
    let observed: Vec<_> = records.drain().collect();
    assert_eq!(observed[0].result(), store::ShadowResultTag::Pending);
    assert_eq!(observed[1].result(), store::ShadowResultTag::Committed);
    assert!(observed[1].receipt().is_some());
    assert!(observed.iter().all(|r| r.encode().len() <= 4096));
    assert_eq!(
        store_ok(rig.get().store.controller().native_save_artifacts())
            .iter()
            .filter(|r| matches!(r.kind, store::NativeSaveArtifactKind::ReceiptCopy))
            .count(),
        receipt_copies_before + 1
    );
    let evidence = store_ok(rig.get().store.controller().evidence());
    let object = evidence
        .objects
        .iter()
        .find(|o| o.selected.selected_object_id == 101)
        .unwrap();
    assert_eq!(object.permit_count, 1);
    assert_eq!(object.transition_count, 1);
    assert_eq!(object.selected.revision, 2);
    let other = rig.get_mut().launch(1);
    let (other_entry, other_call) = rig.get().read(&other, 1200);
    let other_reply = store_ok(rig.get().store.host().execute_native_save(&other_call));
    selected(&other_reply, b"second\n");
    rig.get().join(&other_entry, &other_reply);
    drop((
        first_entry,
        first_reply,
        terminal_entry,
        terminal_reply,
        other_entry,
        other_reply,
        other_call,
    ));
    drop(attempt.settled());
    drop(store_ok(
        rig.get().store.controller().quiesce_native_save(2000),
    ));
    drop(rig.settled());
}
