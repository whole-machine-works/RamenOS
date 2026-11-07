//! Private identity/outcome unit fixtures, not a Save workflow or frame permit.
use super::super::native_preview::AttachmentLife;
use super::super::native_save::{
    CallLife, NativeJoinObservation, NativeSaveCallView, NativeSaveEntry, SaveEntryResult,
    SaveEntryState,
};
use super::*;
use kernel_api::cap::Handle;
use std::thread;

fn attachment() -> Arc<AttachmentLife> {
    Arc::new(AttachmentLife {
        id: 1,
        pin: 1,
        pin_identity: Weak::new(),
    })
}

fn origin(id: u64) -> Arc<OriginLifetime> {
    NativeAuthority::save_origin(id, attachment(), 7)
}

fn entry(authority: &Arc<NativeAuthority>, origin: &Arc<OriginLifetime>) -> NativeSaveEntry {
    let reservations = authority
        .reserve_save_pair(
            origin,
            [
                ProducerKind::DesktopDispatch,
                ProducerKind::DesktopSupervisor,
            ],
        )
        .unwrap();
    let [dispatch, supervisor] = reservations;
    let producers = [
        dispatch.install(thread::spawn(|| {})),
        supervisor.install(thread::spawn(|| {})),
    ];
    let entered = Instant::now();
    let life = Arc::new(CallLife {
        origin: origin.clone(),
        attachment: attachment(),
        view: NativeSaveCallView {
            actor: EditorActorV0 {
                owner_id: 1,
                session_id: 2,
                session_generation: 3,
                instance_id: 4,
                instance_generation: 5,
            },
            object_id: 7,
            object_generation: 1,
            store_epoch: 1,
            origin_id: origin.id,
            intent_id: None,
            entered,
            deadline: entered + Duration::from_secs(1),
            request: Envelope {
                protocol: 368,
                msg_type: 7,
                handle: Handle::INVALID,
                payload_len: 0,
                payload: [0; 64],
            },
        },
        intent: None,
        source: None,
        recovery: None,
        producers: [producers[0].id, producers[1].id],
    });
    NativeSaveEntry {
        authority: authority.clone(),
        life,
        result: Arc::new(SaveEntryResult {
            state: Mutex::new(SaveEntryState {
                started: true,
                completed: true,
                consumed: false,
                outcome: Some(Ok(())),
            }),
            changed: Condvar::new(),
        }),
        producers,
    }
}

fn join(witness: &RegistryWitness, id: &ProducerId) -> JoinedProducerProof {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match witness.join_finished(id) {
            Ok(proof) => return proof,
            Err(Status::NotReady) if Instant::now() < deadline => thread::yield_now(),
            _ => panic!("actual producer did not join within test bound"),
        }
    }
}

fn finish_entry(witness: &RegistryWitness, entry: &NativeSaveEntry) {
    for id in entry.producer_ids() {
        assert_eq!(join(witness, id).outcome(), JoinOutcome::Returned);
    }
}

fn installed(
    authority: &Arc<NativeAuthority>,
    original: &Arc<OriginLifetime>,
    panics: bool,
) -> ProducerId {
    let reservation = authority
        .reserve_save_one(original, ProducerKind::StoreDispatch)
        .unwrap();
    reservation.install(thread::spawn(move || {
        assert!(!panics, "intentional outcome fixture");
    }))
}

#[test]
fn shadow_identity_exact_call_rejects_second_same_actor_query_and_recovers() {
    let authority = NativeAuthority::new();
    let witness = authority.witness();
    let original = origin(1);
    let first = entry(&authority, &original);
    let call = first.wait_once().unwrap();
    // Deliberately equal diagnostic actor/object/origin/request fields do not
    // make a second actual call the same owner.
    let second = entry(&authority, &original);
    assert_eq!(first.life.view.actor, second.life.view.actor);
    assert_eq!(call.validate_entry(&witness, &second), Err(Status::Denied));
    assert_eq!(call.validate_entry(&witness, &first), Ok(()));
    assert!(matches!(first.wait_once(), Err(Status::NotReady)));
    finish_entry(&witness, &first);
    finish_entry(&witness, &second);
}

#[test]
fn shadow_identity_foreign_witness_and_entry_authority_are_denied() {
    let authority = NativeAuthority::new();
    let witness = authority.witness();
    let other = NativeAuthority::new();
    let foreign = other.witness();
    let original = origin(1);
    let mut actual = entry(&authority, &original);
    let call = actual.wait_once().unwrap();
    assert_eq!(call.validate_entry(&foreign, &actual), Err(Status::Denied));
    actual.authority = other;
    assert_eq!(call.validate_entry(&witness, &actual), Err(Status::Denied));
    actual.authority = authority;
    assert_eq!(call.validate_entry(&witness, &actual), Ok(()));
    finish_entry(&witness, &actual);
}

#[test]
fn shadow_identity_missing_and_reserved_join_are_none_without_consumption() {
    let authority = NativeAuthority::new();
    let witness = authority.witness();
    let original = origin(2);
    let id = installed(&authority, &original, false);
    let before = witness.producer_counts();
    assert_eq!(witness.save_join_observation_for(&id).unwrap(), None);
    original.save_joined.lock().unwrap().insert(id.id, None);
    assert_eq!(witness.save_join_observation_for(&id).unwrap(), None);
    assert_eq!(witness.producer_counts(), before);
    assert!(!witness.save_producer_joined(&id).unwrap());
    original.save_joined.lock().unwrap().remove(&id.id);
    assert_eq!(join(&witness, &id).outcome(), JoinOutcome::Returned);
    assert_eq!(
        witness
            .save_join_observation_for(&id)
            .unwrap()
            .unwrap()
            .outcome,
        JoinOutcome::Returned
    );
}

#[test]
fn shadow_identity_actual_returned_join_is_read_only_and_matches_proof() {
    let authority = NativeAuthority::new();
    let witness = authority.witness();
    let original = origin(3);
    let id = installed(&authority, &original, false);
    let proof = join(&witness, &id);
    let before = witness.producer_counts();
    let actual = witness.save_join_observation_for(&id).unwrap().unwrap();
    assert_eq!(actual, witness.verify_join_for(&id, &proof).unwrap());
    assert_eq!(actual.outcome, JoinOutcome::Returned);
    assert_eq!(actual.native_pid, std::process::id());
    assert!(!actual.rust_thread_id.is_empty());
    assert!(witness.save_producer_joined(&id).unwrap());
    assert_eq!(
        witness.save_join_observation_for(&id).unwrap(),
        Some(actual)
    );
    assert_eq!(witness.producer_counts(), before);
    assert!(matches!(witness.join_finished(&id), Err(Status::NotReady)));
}

#[test]
fn shadow_identity_actual_panicked_join_is_not_promoted_to_returned() {
    let authority = NativeAuthority::new();
    let witness = authority.witness();
    let original = origin(4);
    let id = installed(&authority, &original, true);
    let proof = join(&witness, &id);
    assert_eq!(proof.outcome(), JoinOutcome::Panicked);
    assert_eq!(
        witness
            .save_join_observation_for(&id)
            .unwrap()
            .unwrap()
            .outcome,
        JoinOutcome::Panicked
    );
    assert!(witness.save_producer_joined(&id).unwrap()); // legacy semantics retained
    let fresh = installed(&authority, &original, false);
    assert_eq!(join(&witness, &fresh).outcome(), JoinOutcome::Returned);
    assert_eq!(
        witness
            .save_join_observation_for(&fresh)
            .unwrap()
            .unwrap()
            .outcome,
        JoinOutcome::Returned
    );
}

#[test]
fn shadow_identity_foreign_authority_origin_kind_and_proof_are_denied() {
    let authority = NativeAuthority::new();
    let witness = authority.witness();
    let original = origin(5);
    let id = installed(&authority, &original, false);
    let mut token = witness.duplicate_producer(&id).unwrap();
    let proof = join(&witness, &id);
    let foreign = NativeAuthority::new().witness();
    assert_eq!(foreign.save_join_observation_for(&id), Err(Status::Denied));
    let wrong_origin = origin(5);
    token.origin = Arc::downgrade(&wrong_origin);
    assert_eq!(
        witness.save_join_observation_for(&token),
        Err(Status::Denied)
    );
    assert!(matches!(
        witness.verify_join_for(&token, &proof),
        Err(Status::Denied)
    ));
    token.origin = id.origin.clone();
    token.kind = ProducerKind::StoreSupervisor;
    assert_eq!(
        witness.save_join_observation_for(&token),
        Err(Status::Denied)
    );
    assert!(matches!(
        witness.verify_join_for(&token, &proof),
        Err(Status::Denied)
    ));
    assert_eq!(
        witness
            .save_join_observation_for(&id)
            .unwrap()
            .unwrap()
            .outcome,
        JoinOutcome::Returned
    );
}

#[test]
fn shadow_identity_generation_and_memo_identity_corruption_are_denied() {
    let authority = NativeAuthority::new();
    let witness = authority.witness();
    let original = origin(6);
    let id = installed(&authority, &original, false);
    let proof = join(&witness, &id);
    let actual = witness.verify_join_for(&id, &proof).unwrap();
    original
        .save_installed
        .lock()
        .unwrap()
        .insert(id.id, (id.kind, 2));
    assert_eq!(witness.save_join_observation_for(&id), Err(Status::Denied));
    original
        .save_installed
        .lock()
        .unwrap()
        .insert(id.id, (id.kind, 1));
    let mut variants: Vec<NativeJoinObservation> = Vec::new();
    let mut changed = actual.clone();
    changed.producer_id += 1;
    variants.push(changed);
    let mut changed = actual.clone();
    changed.producer_generation += 1;
    variants.push(changed);
    let mut changed = actual.clone();
    changed.origin_id += 1;
    variants.push(changed);
    let mut changed = actual.clone();
    changed.kind = ProducerKind::StoreSupervisor;
    variants.push(changed);
    for changed in variants {
        original
            .save_joined
            .lock()
            .unwrap()
            .insert(id.id, Some(changed));
        assert_eq!(witness.save_join_observation_for(&id), Err(Status::Denied));
    }
    original
        .save_joined
        .lock()
        .unwrap()
        .insert(id.id, Some(actual.clone()));
    assert_eq!(
        witness.save_join_observation_for(&id).unwrap(),
        Some(actual)
    );
}

#[test]
fn shadow_identity_retired_origin_and_non_save_origin_never_imply_join() {
    let authority = NativeAuthority::new();
    let witness = authority.witness();
    let original = origin(7);
    let id = installed(&authority, &original, false);
    let _proof = join(&witness, &id);
    drop(original);
    assert_eq!(witness.save_join_observation_for(&id).unwrap(), None);
    assert!(!witness.save_producer_joined(&id).unwrap());
    let non_save = Arc::new(OriginLifetime {
        id: 8,
        save_object: None,
        save_installed: Mutex::new(BTreeMap::new()),
        save_joined: Mutex::new(BTreeMap::new()),
        _preview_attachment: None,
    });
    let token = ProducerId {
        authority,
        id: 99,
        origin: Arc::downgrade(&non_save),
        kind: ProducerKind::StoreDispatch,
    };
    assert_eq!(
        witness.save_join_observation_for(&token),
        Err(Status::Denied)
    );
}
