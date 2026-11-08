//! Authentic two-original unpermitted Commit closure; no forged receipt/absence/join.
#![cfg(feature = "editor_recovery_shadow_assertions_v0_dev")]
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
struct CommitAttempt {
    entry: desktop::NativeSaveEntry,
    call: store::RegisteredNativeSave,
    operation: u64,
    _intent: desktop::NativeSaveIntent,
    _source: store::NativeDraftSource,
}
impl NativeRig {
    fn editor(&self, launch: &store::PairedNativeSaveLaunch, i: usize) -> desktop::NativeEditor {
        let (entry, call) = self.read(launch, 200);
        let mut reply = store_ok(self.store.host().execute_native_save(&call));
        let editor = store_ok(reply.take_editor());
        self.join(&entry, &reply);
        let frame = store_ok(self.desktop.render_native_editor(&editor, 1));
        store_ok(
            self.desktop
                .compose_native_save(&self.drivers[i].s.compositor, 1),
        );
        let actor = store_ok(self.desktop.editor_observation(&editor, 1)).actor;
        let assigned: kernel_api::generated::desktop_focus_v1::AssignReply = ui::call(
            &self.desktop,
            &self.drivers[i].s.chrome,
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
        editor
    }
    fn unchanged_save(
        &mut self,
        launch: &store::PairedNativeSaveLaunch,
        editor: &desktop::NativeEditor,
        i: usize,
    ) -> CommitAttempt {
        for (usage, phase) in [(224, 1), (22, 1), (22, 2), (224, 2)] {
            self.drivers[i].send(&self.desktop, usage, phase, 1);
            store_ok(self.desktop.step_native_editor(editor, 1));
        }
        let intent = store_ok(self.desktop.take_save_intent(editor));
        let view = intent.snapshot().view();
        let request = store_ok(
            a::AllocateSaveId {
                request_id: 300,
                session_id: view.actor.session_id,
                session_generation: view.actor.session_generation,
                expected_revision: view.expected_revision,
            }
            .encode(launch.endpoint().handle),
        );
        let entry = store_ok(self.desktop.begin_save_allocate(
            launch.desktop().bindings().artifact_origin(),
            &intent,
            &request,
            1,
        ));
        let call = store_ok(
            self.store
                .host()
                .register_native_save(launch.endpoint(), store_ok(entry.wait_once())),
        );
        let reply = store_ok(self.store.host().execute_native_save(&call));
        let allocation = store_ok(a::AllocateSaveIdReply::decode(reply.wire()));
        assert_eq!(allocation.status, 0);
        let source = store_ok(self.store.host().source_for_intent(
            launch.endpoint(),
            reply.allocation().unwrap(),
            &intent,
        ));
        let header = store_ok(
            artifact_store_schema::editor_save::EditorTextHeaderV0::try_new(
                view.object_id,
                view.expected_revision,
                intent.snapshot().body(),
            ),
        );
        let mut bytes = store_ok(header.encode_le()).to_vec();
        bytes.extend_from_slice(intent.snapshot().body());
        store_ok(store_ok(source.write_lease()).copy_from(0, &bytes));
        self.join(&entry, &reply);
        let descriptor = source.descriptor();
        let request = store_ok(
            a::Commit {
                request_id: 301,
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
        let entry = store_ok(self.desktop.begin_save_commit(
            launch.desktop().bindings().artifact_origin(),
            source.bound(),
            &request,
            1,
        ));
        let call = store_ok(
            self.store
                .host()
                .register_native_save(launch.endpoint(), store_ok(entry.wait_once())),
        );
        CommitAttempt {
            entry,
            call,
            operation: allocation.operation_id,
            _intent: intent,
            _source: source,
        }
    }
}

fn commit_lookup_deadline(
    rig: &NativeRig,
    launch: &store::PairedNativeSaveLaunch,
    attempt: &Attempt,
    id: u64,
    op: u64,
) -> (
    desktop::NativeSaveEntry,
    store::NativeOriginalReply,
    Instant,
) {
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
    let call = store_ok(entry.wait_once());
    let deadline = call.deadline();
    let reply = store_ok(rig.store.host().observe_original(call, original));
    (entry, reply, deadline)
}
fn commit_lookup(
    rig: &NativeRig,
    launch: &store::PairedNativeSaveLaunch,
    attempt: &Attempt,
    id: u64,
    op: u64,
) -> (desktop::NativeSaveEntry, store::NativeOriginalReply) {
    let (entry, reply, _) = commit_lookup_deadline(rig, launch, attempt, id, op);
    (entry, reply)
}

fn run_terminal_snapshot_barrier(mode: &str) {
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
        .filter(|r| {
            r.object_id == 101 && matches!(r.kind, store::NativeSaveArtifactKind::ReceiptCopy)
        })
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
            .filter(|r| r.object_id == 101
                && matches!(r.kind, store::NativeSaveArtifactKind::ReceiptCopy))
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
    let other = rig.get_mut().launch(1);
    let sibling_editor = rig.get().editor(&other, 1);
    let sibling_attempt = rig.get_mut().unchanged_save(&other, &sibling_editor, 1);
    let original = attempt.get().commit_call.as_ref().unwrap().original();
    let (terminal_entry, mut terminal_reply, query_deadline) = commit_lookup_deadline(
        rig.get(),
        &launch,
        attempt.get(),
        1101,
        allocation.operation_id,
    );
    join_lookup(rig.get(), &terminal_entry, &terminal_reply);
    let (wrong_entry, wrong_reply) = commit_lookup(
        rig.get(),
        &launch,
        attempt.get(),
        1108,
        allocation.operation_id,
    );
    join_lookup(rig.get(), &wrong_entry, &wrong_reply);
    assert!(
        rig.get()
            .store
            .controller()
            .arm_shadow_after_snapshot(original, &wrong_entry, &mut terminal_reply)
            .is_err()
    );
    drop((wrong_entry, wrong_reply));
    assert!(
        rig.get()
            .store
            .controller()
            .arm_shadow_after_snapshot(
                attempt.get().allocated.as_ref().unwrap().original(),
                &terminal_entry,
                &mut terminal_reply,
            )
            .is_err()
    );
    let mut snapshot_pause = store_ok(rig.get().store.controller().arm_shadow_after_snapshot(
        original,
        &terminal_entry,
        &mut terminal_reply,
    ));
    let terminal = std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            rig.get().store.host().compare_post_commit_shadow(
                original,
                &terminal_entry,
                &mut terminal_reply,
                &[],
                &module,
                &mut records,
            )
        });
        store_ok(snapshot_pause.wait_until_entered());
        assert_eq!(
            store_ok(rig.get().store.controller().native_save_artifacts())
                .iter()
                .filter(|r| r.object_id == 101
                    && matches!(r.kind, store::NativeSaveArtifactKind::ReceiptCopy))
                .count(),
            receipt_copies_before
        );
        let sibling_reply = store_ok(
            rig.get()
                .store
                .host()
                .execute_native_save(&sibling_attempt.call),
        );
        let sibling_wire = store_ok(a::CommitReply::decode(sibling_reply.wire()));
        assert_eq!(
            (sibling_wire.status, sibling_wire.operation_id),
            (0, sibling_attempt.operation)
        );
        let mut sibling_bytes = [0; 176];
        store_ok(
            sibling_reply
                .receipt()
                .expect("actual sibling receipt")
                .copy_into(0, &mut sibling_bytes),
        );
        let sibling_receipt = store_ok(
            artifact_store_schema::editor_save::EditorSaveReceiptV0::decode_le(&sibling_bytes),
        );
        assert_eq!(sibling_receipt.operation_id, sibling_attempt.operation);
        assert_eq!(sibling_receipt.result_revision, 2);
        rig.get().join(&sibling_attempt.entry, &sibling_reply);
        let evidence = store_ok(rig.get().store.controller().evidence());
        let sibling = evidence
            .objects
            .iter()
            .find(|row| row.selected.selected_object_id == 102)
            .unwrap();
        assert_eq!(
            (
                sibling.mutation_dispatch_count,
                sibling.permit_count,
                sibling.transition_count,
                sibling.selected.revision
            ),
            (1, 1, 1, 2)
        );
        drop(sibling_reply);
        if mode == "revoke" {
            let bootstrap = store_ok(
                kernel_api::generated::desktop_editor_session_v1::InstanceBootstrap::decode(
                    launch.desktop().bindings().bootstrap(),
                ),
            );
            ui::revoke(&rig.get().desktop, &rig.get().drivers[0].s, &bootstrap, 3);
            assert!(
                !matches!(rig.get().desktop.editor_observation(&editor, 3), Ok(v) if v.phase == desktop::NativeEditorPhase::Saved)
            );
        }
        if mode == "drop" {
            drop(snapshot_pause);
            let failure = worker
                .join()
                .expect("comparison worker actually joined")
                .err()
                .expect("drop must abort");
            assert_eq!(
                failure.phase(),
                store::PostCommitShadowPhase::ClaimedNoPublication
            );
            return None;
        }
        if mode == "watchdog" {
            std::thread::sleep(Duration::from_millis(2050));
            store_ok(snapshot_pause.wait_until_exited());
            assert!(snapshot_pause.release().is_err());
            let failure = worker
                .join()
                .expect("comparison worker actually joined")
                .err()
                .expect("watchdog must abort before C1");
            assert_eq!(
                failure.phase(),
                store::PostCommitShadowPhase::ClaimedNoPublication
            );
            return None;
        }
        if mode == "expiry" {
            while Instant::now() < query_deadline {
                std::thread::yield_now();
            }
        }
        store_ok(snapshot_pause.release());
        store_ok(snapshot_pause.wait_until_exited());
        let result = worker.join().expect("comparison worker actually joined");
        if mode == "expiry" {
            let failure = result.err().expect("expired real query must refuse");
            assert_eq!(
                failure.phase(),
                store::PostCommitShadowPhase::ClaimedNoPublication
            );
            assert_eq!(failure.status(), StoreStatus::Timeout);
            None
        } else {
            Some(store_ok(result))
        }
    });
    let terminal = match terminal {
        Some(terminal) => terminal,
        None => {
            assert_eq!(
                store_ok(rig.get().store.controller().native_save_artifacts())
                    .iter()
                    .filter(|r| r.object_id == 101
                        && matches!(r.kind, store::NativeSaveArtifactKind::ReceiptCopy))
                    .count(),
                receipt_copies_before
            );
            assert_eq!(records.len(), if mode == "expiry" { 2 } else { 1 });
            let (entry, mut reply) = commit_lookup(
                rig.get(),
                &launch,
                attempt.get(),
                1107,
                allocation.operation_id,
            );
            join_lookup(rig.get(), &entry, &reply);
            let completion = store_ok(rig.get().store.host().compare_post_commit_shadow(
                original,
                &entry,
                &mut reply,
                &[],
                &module,
                &mut records,
            ));
            drop((entry, reply));
            completion
        }
    };
    assert!(matches!(
        terminal.into_native(),
        store::PostCommitLookupResult::ReceiptValidated
    ));
    assert_eq!(records.len(), if mode == "expiry" { 3 } else { 2 });
    let observed: Vec<_> = records.drain().collect();
    assert_eq!(observed[0].result(), store::ShadowResultTag::Pending);
    assert_eq!(observed[1].result(), store::ShadowResultTag::Committed);
    assert!(observed[1].receipt().is_some());
    assert!(observed.iter().all(|r| r.encode().len() <= 4096));
    assert_eq!(
        store_ok(rig.get().store.controller().native_save_artifacts())
            .iter()
            .filter(|r| r.object_id == 101
                && matches!(r.kind, store::NativeSaveArtifactKind::ReceiptCopy))
            .count(),
        receipt_copies_before + 1
    );
    let evidence = store_ok(rig.get().store.controller().evidence());
    let object = evidence
        .objects
        .iter()
        .find(|o| o.selected.selected_object_id == 101)
        .unwrap();
    assert_eq!(object.mutation_dispatch_count, 1);
    assert_eq!(object.permit_count, 1);
    assert_eq!(object.transition_count, 1);
    assert_eq!(object.selected.revision, 2);
    store_ok(rig.get().desktop.render_native_editor(&sibling_editor, 4));
    store_ok(
        rig.get()
            .desktop
            .compose_native_save(&rig.get().drivers[1].s.compositor, 4),
    );
    let fresh_sibling = rig.get_mut().unchanged_save(&other, &sibling_editor, 1);
    assert!(fresh_sibling.operation > sibling_attempt.operation);
    let fresh_reply = store_ok(
        rig.get()
            .store
            .host()
            .execute_native_save(&fresh_sibling.call),
    );
    assert_eq!(
        store_ok(a::CommitReply::decode(fresh_reply.wire())).status,
        0
    );
    rig.get().join(&fresh_sibling.entry, &fresh_reply);
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
    drop((fresh_reply, fresh_sibling, sibling_attempt));
    drop(sibling_editor);
    drop(attempt.settled());
    drop(store_ok(
        rig.get().store.controller().quiesce_native_save(2000),
    ));
    drop(rig.settled());
}

#[test]
fn actual_terminal_snapshot_barrier_checks_query_and_unrelated_progress() {
    run_terminal_snapshot_barrier("release");
}
#[test]
fn actual_expired_query_rejects_native_publication_after_c1_then_fresh_query_succeeds() {
    run_terminal_snapshot_barrier("expiry");
}
#[test]
fn actual_token_drop_aborts_before_c1_then_fresh_query_succeeds() {
    run_terminal_snapshot_barrier("drop");
}
#[test]
fn actual_watchdog_aborts_before_c1_then_fresh_query_succeeds() {
    run_terminal_snapshot_barrier("watchdog");
}

#[test]
fn actual_revocation_keeps_original_scope_and_never_grants_saved() {
    run_terminal_snapshot_barrier("revoke");
}

#[test]
fn actual_reopened_store_compares_original_epoch_and_fresh_save() {
    for (point, pause_point, committed) in [
        (
            store::IoPoint::JournalSync,
            store::PausePoint::AfterCommitPermit,
            false,
        ),
        (
            store::IoPoint::JournalDirectorySync,
            store::PausePoint::BeforeSelectionRename,
            true,
        ),
    ] {
        let module = store_ok(store::PreparedStoreShadowModule::prepare(
            include_bytes!("fixtures/recovery-c1.wasm"),
            store::RecoveryArtifactV0 {
                abi_sha256: [
                    0x49, 0xda, 0xf5, 0x2d, 0xd6, 0x69, 0x41, 0x13, 0x76, 0x77, 0x0b, 0x3b, 0xc2,
                    0xa0, 0x07, 0xd7, 0xc6, 0xa8, 0xb3, 0x46, 0x84, 0x3b, 0xcd, 0x12, 0x3a, 0x45,
                    0xda, 0x81, 0x39, 0xb0, 0xda, 0x60,
                ],
                module_sha256: [
                    0x64, 0x58, 0xa1, 0x73, 0xcd, 0x09, 0xe7, 0x3f, 0xe0, 0xbe, 0x59, 0xb1, 0xa2,
                    0xd3, 0x39, 0xc2, 0x07, 0x0c, 0x33, 0xac, 0x05, 0x62, 0x8b, 0x3d, 0x2d, 0xd5,
                    0xfb, 0x26, 0x4c, 0xb2, 0xe0, 0x79,
                ],
            },
        ));
        let mut rig = NativeRig::new();
        let first = rig.launch(0);
        let editor = rig.editor(&first, 0);
        for (usage, phase) in [(224, 1), (4, 1), (4, 2), (224, 2), (5, 1), (5, 2)] {
            rig.drivers[0].send(&rig.desktop, usage, phase, 1);
            store_ok(rig.desktop.step_native_editor(&editor, 1));
        }
        let attempt = rig.unchanged_save(&first, &editor, 0);
        assert_eq!(attempt._intent.snapshot().body(), b"b");
        let original_epoch = attempt._intent.snapshot().view().original_store_epoch;
        let recovery = store_ok(
            rig.store
                .controller()
                .recovery_for_original(&rig.drivers[0].s.chrome.peer, attempt.call.original()),
        );
        let pause = store_ok(
            rig.store
                .controller()
                .pause_native_save(first.endpoint(), pause_point),
        );
        let running = store_ok(rig.store.host().start_native_save(&attempt.call));
        assert!(store_ok(pause.wait_until_entered(2000)).permit_issued);
        store_ok(rig.store.controller().fail_next_io(first.endpoint(), point));
        store_ok(rig.store.controller().release(&pause));
        let deadline = Instant::now() + Duration::from_secs(2);
        let reply = loop {
            if let Some(reply) = store_ok(running.poll_once()) {
                break reply;
            }
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        };
        let wire = store_ok(a::CommitReply::decode(reply.wire()));
        assert_eq!(
            (wire.status, wire.operation_id),
            (StoreStatus::Unknown as u32, attempt.operation)
        );
        assert!(reply.receipt().is_none());
        let before = store_ok(rig.store.controller().evidence());
        assert!(
            before
                .io_events
                .iter()
                .any(|event| event.selected_object_id == 101
                    && event.point == point
                    && matches!(event.outcome, store::IoOutcome::SimulatedFailure))
        );
        rig.join(&attempt.entry, &reply);
        let fence = store_ok(rig.store.controller().quiesce_native_save(2000));
        assert_eq!(fence.fence_snapshot().base.live_ownership_after_join, 0);
        rig.store = store_ok(store::StoreFixture::reopen_native_save(fence));
        let after = store_ok(rig.store.controller().evidence());
        let object = after
            .objects
            .iter()
            .find(|row| row.selected.selected_object_id == 101)
            .unwrap();
        assert!(object.service_epoch > original_epoch);
        let actor = attempt._intent.snapshot().view().actor;
        let status = store_ok(
            a::SaveStatus {
                request_id: 600,
                session_id: actor.session_id,
                session_generation: actor.session_generation,
                operation_id: attempt.operation,
            }
            .encode(first.endpoint().handle),
        );
        let entry = store_ok(
            rig.desktop
                .begin_save_recovery(recovery.origin(), &status, 1),
        );
        let mut observed = store_ok(
            rig.store
                .host()
                .recover_original(store_ok(entry.wait_once()), &recovery),
        );
        join_lookup(&rig, &entry, &observed);
        let mut records = store::PostCommitShadowRecords::new();
        let completion = store_ok(rig.store.host().compare_post_commit_shadow(
            attempt.call.original(),
            &entry,
            &mut observed,
            &[],
            &module,
            &mut records,
        ));
        assert!(matches!(
            completion.into_native(),
            store::PostCommitLookupResult::ReceiptValidated
        ));
        let records: Vec<_> = records.drain().collect();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].result(),
            if committed {
                store::ShadowResultTag::Committed
            } else {
                store::ShadowResultTag::DefinitiveNoncommit
            }
        );
        let receipt = store_ok(
            artifact_store_schema::editor_save::EditorSaveReceiptV0::decode_le(
                records[0].receipt().unwrap(),
            ),
        );
        assert_eq!(receipt.backend_service_epoch, original_epoch);
        assert_eq!(receipt.operation_id, attempt.operation);
        let after_compare = store_ok(rig.store.controller().evidence());
        let object = after_compare
            .objects
            .iter()
            .find(|row| row.selected.selected_object_id == 101)
            .unwrap();
        assert_eq!(
            (
                object.mutation_dispatch_count,
                object.permit_count,
                object.transition_count
            ),
            (1, 1, u32::from(committed))
        );
        let next = rig.launch(0);
        let (read_entry, read_call) = rig.read(&next, 599);
        let read = store_ok(rig.store.host().execute_native_save(&read_call));
        let read_wire = store_ok(a::ReadSelectedReply::decode(read.wire()));
        assert_eq!(read_wire.revision, if committed { 2 } else { 1 });
        selected(&read, if committed { b"b" } else { b"first\n" });
        rig.join(&read_entry, &read);
        drop((read, read_entry, read_call));
        let next_editor = rig.editor(&next, 0);
        for (usage, phase) in [(224, 1), (4, 1), (4, 2), (224, 2), (6, 1), (6, 2)] {
            rig.drivers[0].send(&rig.desktop, usage, phase, 1);
            store_ok(rig.desktop.step_native_editor(&next_editor, 1));
        }
        let fresh = rig.unchanged_save(&next, &next_editor, 0);
        assert_eq!(fresh._intent.snapshot().body(), b"c");
        assert!(fresh.operation > attempt.operation);
        assert!(fresh._intent.snapshot().view().original_store_epoch > original_epoch);
        let saved = store_ok(rig.store.host().execute_native_save(&fresh.call));
        assert_eq!(store_ok(a::CommitReply::decode(saved.wire())).status, 0);
        rig.join(&fresh.entry, &saved);
        let (fresh_read_entry, fresh_read_call) = rig.read(&next, 601);
        let fresh_read = store_ok(rig.store.host().execute_native_save(&fresh_read_call));
        let fresh_wire = store_ok(a::ReadSelectedReply::decode(fresh_read.wire()));
        assert_eq!(fresh_wire.revision, if committed { 3 } else { 2 });
        selected(&fresh_read, b"c");
        rig.join(&fresh_read_entry, &fresh_read);
        drop((fresh_read, fresh_read_entry, fresh_read_call));
        let final_evidence = store_ok(rig.store.controller().evidence());
        let object = final_evidence
            .objects
            .iter()
            .find(|row| row.selected.selected_object_id == 101)
            .unwrap();
        assert_eq!(
            (
                object.mutation_dispatch_count,
                object.permit_count,
                object.transition_count
            ),
            (2, 2, u32::from(committed) + 1)
        );
        drop((saved, fresh, observed, entry, reply, running, attempt));
        assert_eq!(rig.desktop.native_producer_counts().held, 0);
        drop(store_ok(rig.store.controller().quiesce_native_save(2000)));
    }
}
