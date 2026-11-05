//! Named lifecycle attempts over genuine public owners. The independent raw
//! control/Core/pixel oracles remain in the family runner after these actions.
use super::*;

pub(super) fn budget(id: &str, positive: bool) -> Option<u32> {
    id.starts_with("D28")
        .then_some(if positive { 1000 } else { 100 })
}

fn rejected_attempt(id: &str, result: Result<(), Status>, expected: Status) {
    assert_eq!(result, Err(expected), "actual named lifecycle attempt {id}");
}

/// Return true only when this module drove the named attempt. This is routing,
/// never an attestation: every caller still runs the independent family oracle.
pub(super) fn drive(
    group: &mut ChildGroup,
    index: usize,
    id: &str,
    positive: bool,
    admission_now: u64,
    spawn_entered: Instant,
) -> bool {
    match id {
        "D23OldPreviewEnterDenied" => {
            // No extra key may be queued after the genuine consumed-confirm
            // replay has fenced the old owner.
            let (f, child) = group.borrow(index);
            let result =
                f.h.pump_process_editor(child, admission_now)
                    .map(|_| ())
                    .map_err(|e| e.status());
            rejected_attempt(id, result, Status::Stale);
        }
        "D26FrameAfterRevoke" | "D26OldGenerationCannotRevive" => {
            rejected_attempt(id, ordinary_edit(group, index, 0), Status::Denied);
        }
        "D26CaptureAfterRevoke" => {
            // Establish a real current draft first. The backend revokes only
            // when the subsequent genuine Ctrl+S requests its capture pair.
            ok(ordinary_edit(group, index, 0));
            rejected_attempt(id, ctrl_s_capture(group, index, 0), Status::Denied);
        }
        "D26OtherOwnerAndOriginalReceiptProgress" => {
            assert!(positive);
            ok(ordinary_edit(group, index, 0));
            let (f, child) = group.borrow(index);
            let actor = ok(f.h.observe_process_editor(child, 2)).actor;
            revoke(f, 0, &actor, 3);
            // The runner drives the separately owned genuine sibling after
            // this revoke; the app-owned packet supplies the issued receipt.
        }
        "D27OrdinaryOverflowReservedReset" => {
            // The closed backend must start from an empty Core input queue,
            // then produce64 accepted keys and the real65th overflow attempt.
            let (f, child) = group.borrow(index);
            let result =
                f.h.pump_process_editor(child, 2)
                    .map(|_| ())
                    .map_err(|e| e.status());
            rejected_attempt(id, result, Status::NotReady);
        }
        "D27OldKeyPressRelease" => {
            rejected_attempt(id, deliver(group, index, 0, 4, 1, 2), Status::Stale);
        }
        "D27OldResetServiceEpoch" => {
            rejected_attempt(id, deliver(group, index, 0, 0, 3, 2), Status::Stale);
        }
        "D27OldSurfaceGeneration" => {
            rejected_attempt(id, request(group, index, 2), Status::Stale);
        }
        "D27StaleResetCapture" => {
            rejected_attempt(id, ctrl_s_capture(group, index, 0), Status::Stale);
        }
        "D27FreshResetApprovalAndSurface" => {
            assert!(positive);
            ok(deliver(group, index, 0, 0, 3, 2));
            ok(ordinary_edit(group, index, 0));
        }
        "D28RoundTripCannotRenew" | "D28BackdatedCoreClock" | "D28IntentRequestCannotRenew" => {
            assert!(!positive);
            let result = if id == "D28IntentRequestCannotRenew" {
                ctrl_s_capture(group, index, 0)
            } else {
                deliver(
                    group,
                    index,
                    0,
                    224,
                    1,
                    if id == "D28BackdatedCoreClock" { 0 } else { 2 },
                )
            };
            assert!(
                matches!(result, Err(Status::Timeout | Status::Disconnected)),
                "actual named deadline interruption {id}: {result:?}"
            );
            assert!(spawn_entered.elapsed() >= Duration::from_millis(100));
        }
        _ => return false,
    }
    assert_eq!(group.fixture().counts(101), (0, 0, 0));
    true
}

pub(super) fn assert_core_route(f: &mut Fixture, id: &str) {
    use kernel_api::generated::{desktop_editor_session_v1 as session, input_v1 as input};
    let evidence = ok(f.dc.evidence());
    if id.starts_with("D26") {
        assert!(
            evidence.exchanges.iter().any(|(q, r)| {
                q.protocol == session::DESKTOP_EDITOR_SESSION_V1_PROTOCOL_ID
                    && q.msg_type == session::MSG_DESKTOP_EDITOR_SESSION_V1_REVOKE_INSTANCE
                    && q.handle == f.drivers[0].s.chrome.handle
                    && session::RevokeInstance::decode(q).is_ok_and(|v| {
                        v.session_id == f.drivers[0].s.session_id
                            && v.instance_id > 0
                            && v.instance_generation > 0
                    })
                    && session::RevokeInstanceReply::decode(r).is_ok_and(|v| v.status == 0)
            }),
            "actual successful authorized Core revoke for {id}"
        );
    }
    if id == "D27OrdinaryOverflowReservedReset" {
        assert!(
            evidence
                .exchanges
                .iter()
                .filter(|(q, r)| {
                    q.protocol == input::INPUT_V1_PROTOCOL_ID
                        && q.msg_type == input::MSG_INPUT_V1_PRODUCE_KEY
                        && input::ProduceKey::decode(q).is_ok_and(|v| matches!(v.phase, 1 | 2))
                        && input::ProduceKeyReply::decode(r).is_ok_and(|v| v.status == 0)
                })
                .count()
                >= 65,
            "real accepted Core65th overflow attempt"
        );
    }
}

/// The owner-confirm operation is distinct from the unsupported wire dispatch.
/// Join its actual recorded request to the genuinely consumed original request.
pub(super) fn assert_owner_confirm(
    f: &Fixture,
    evidence: &desktop::ProcessAssertionEvidence,
    id: &str,
) {
    if id != "D23OldPreviewEnterDenied" {
        return;
    }
    use kernel_api::generated::desktop_editor_session_v1 as session;
    let raw = evidence
        .after()
        .owner_confirm_request
        .expect("actual owner-confirm request bytes");
    let request = ok(desktop::decode_envelope_wire(&raw));
    let decoded = ok(session::ConfirmLaunch::decode(&request));
    assert_eq!(request.handle, f.drivers[0].s.chrome.handle);
    assert_eq!(decoded.session_id, f.drivers[0].s.session_id);
    assert_eq!(
        decoded.session_generation,
        f.drivers[0].s.session_generation
    );
    assert!(decoded.request_id > 0 && decoded.plan_id > 0 && decoded.preview_revision > 0);
    assert_eq!(evidence.after().owner_confirm_status, Some(Status::Stale));
    assert!(
        ok(f.dc.evidence()).exchanges.iter().any(|(q, r)| {
            q.protocol == session::DESKTOP_EDITOR_SESSION_V1_PROTOCOL_ID
                && q.msg_type == session::MSG_DESKTOP_EDITOR_SESSION_V1_CONFIRM_LAUNCH
                && desktop::encode_envelope_wire(q)
                    .is_ok_and(|bytes| bytes.as_slice() == raw.as_slice())
                && session::ConfirmLaunchReply::decode(r).is_ok_and(|v| v.status == 0)
        }),
        "owner replay used the exact genuine previously consumed confirmation"
    );
}
