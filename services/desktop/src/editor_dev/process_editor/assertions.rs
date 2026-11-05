//! Independent P0 predicates over actual owner recordings. This file never
//! constructs enrollment, a process, a verified publication, a capture or a reap
//! proof. The controller's closed scenario merely selects the attempted action;
//! these predicates decide whether the recorded native behavior satisfies it.
#![cfg(all(target_os = "linux", feature = "host_editor_process_assertions_v0_dev"))]

use crate::dev::Status;
use crate::editor_dev::{
    ProcessAssertionDescriptorEvent as DescriptorEvent, ProcessAssertionDescriptorRole as Role,
    ProcessAssertionDirection as Direction, ProcessAssertionDisposition as Disposition,
    ProcessAssertionEvidence as Evidence, ProcessAssertionExecutableAction as ExecutableAction,
    ProcessAssertionMapping as Mapping, ProcessAssertionOperation as Operation,
    ProcessAssertionOrigin as Origin, ProcessAssertionSnapshot as Snapshot,
};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, time::Duration};

const SURFACE_BYTES: usize = 640 * 480 * 4;
const COMPOSED_BYTES: usize = 640 * 568 * 4;
const ALL_SEALS: u32 =
    (libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL) as u32;

fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

pub(crate) fn assert_snapshot_bounds(snapshot: &Snapshot) {
    let owners = &snapshot.owners;
    assert!(owners.data <= 12);
    assert!(owners.fixed <= 16);
    assert!(owners.combined <= 28);
    assert_eq!(owners.combined, owners.data + owners.fixed);
    assert!(owners.maps <= 12);
    assert!(owners.children <= 2 && owners.supervisors <= 2);
    assert!(owners.pending_inputs <= 1);
    assert!(owners.ordinary_queue <= 64 && owners.reset_queue <= 1);
    assert!(owners.ordinary_queue + owners.reset_queue <= 65);
    assert!(owners.lifetime_offers <= 128);
    assert!(owners.lifetime_objects <= 257);
    assert!(owners.lifetime_bytes <= 157_831_232);
    assert!(snapshot.app_pixels.is_empty() || snapshot.app_pixels.len() == SURFACE_BYTES);
    assert!(
        snapshot.composed_pixels.is_empty() || snapshot.composed_pixels.len() == COMPOSED_BYTES
    );
    assert_eq!(snapshot.app_sha256, hash(&snapshot.app_pixels));
    assert_eq!(snapshot.composed_sha256, hash(&snapshot.composed_pixels));
    if let Some(view) = &snapshot.document {
        assert!(view.bytes.len() <= 4096);
        assert!(view.cursor as usize <= view.bytes.len());
        if let Some((start, end)) = view.selection {
            assert!(start <= end && end as usize <= view.bytes.len());
        }
    }
    if let (Some(entered), Some(deadline)) = (snapshot.admitted_at, snapshot.child_deadline) {
        assert!(deadline > entered);
        assert!(deadline.duration_since(entered) <= Duration::from_millis(5000));
    }
    if let (Some(entered), Some(deadline)) = (snapshot.captured_at, snapshot.save_deadline) {
        assert_eq!(
            deadline.duration_since(entered),
            Duration::from_millis(1000)
        );
    }
}

pub(crate) fn assert_integrity(e: &Evidence, expected_id: &str) {
    assert_eq!(e.scenario_id(), expected_id);
    assert_snapshot_bounds(e.before());
    assert_snapshot_bounds(e.after());
    if e.before().admitted_at.is_some() {
        assert_eq!(e.before().admitted_at, e.after().admitted_at);
        assert_eq!(e.before().child_deadline, e.after().child_deadline);
    }
    if e.before().captured_at.is_some() {
        assert_eq!(e.before().captured_at, e.after().captured_at);
        assert_eq!(e.before().save_deadline, e.after().save_deadline);
    }
    assert!(e.controls().len() <= 32768);
    let mut previous = 0;
    for row in e.controls() {
        assert_eq!(
            row.sequence,
            previous + 1,
            "complete consecutive control inventory"
        );
        previous = row.sequence;
        assert!(
            row.received_fds <= 4,
            "bounded malformed arity includes Bootstrap four"
        );
    }
    let mut descriptor_ids = BTreeSet::new();
    for row in e.descriptors() {
        assert!(row.descriptor_id > 0);
        descriptor_ids.insert(row.descriptor_id);
        if row.disposition == Disposition::Closed {
            assert!(
                e.syscalls()
                    .iter()
                    .any(|call| call.operation == Operation::Close
                        && call.origin == Origin::Native
                        && call.result == 0
                        && call.descriptor_id == Some(row.descriptor_id))
            );
        }
    }
    for call in e.syscalls() {
        let mut rights = 0;
        for (level, kind, payload) in ancillary_messages(&call.ancillary) {
            if level == libc::SOL_SOCKET && kind == libc::SCM_RIGHTS {
                assert_eq!(payload.len() % 4, 0);
                assert!(
                    payload.iter().all(|v| *v == 0),
                    "public SCM_RIGHTS integer projection zeroed"
                );
                rights += payload.len() / 4;
            }
        }
        assert_eq!(rights, call.ancillary_descriptor_ids.len());
        for id in &call.ancillary_descriptor_ids {
            assert!(descriptor_ids.contains(id));
        }
        if let Some(id) = call.descriptor_id {
            assert!(descriptor_ids.contains(&id));
        }
        if call.result < 0 {
            assert!(call.errno.is_some());
        }
        if call.operation == Operation::Waitpid && call.result > 0 {
            assert_eq!(
                call.origin,
                Origin::Native,
                "injected reap success is forbidden"
            );
        }
    }
    assert!(e.before().syscall_count <= e.after().syscall_count);
    assert!(e.after().syscall_count as usize <= e.syscalls().len());
    assert!(e.before().control_count <= e.after().control_count);
    assert!(e.after().control_count as usize <= e.controls().len());
    assert!(e.before().descriptor_count <= e.after().descriptor_count);
    assert!(e.after().descriptor_count as usize <= e.descriptors().len());
    for object in e.objects() {
        assert!(object.bytes.len() <= SURFACE_BYTES + 1);
        assert_eq!(object.sha256, hash(&object.bytes));
        assert!(descriptor_ids.contains(&object.descriptor_id));
    }
    if e.supervisor_joined() {
        assert!(e.native_wait_outcome().is_some());
        assert!(
            e.syscalls()
                .iter()
                .any(|call| call.operation == Operation::Waitpid
                    && call.origin == Origin::Native
                    && call.result > 0)
        );
    }
}

fn attempt_syscalls(e: &Evidence) -> &[crate::editor_dev::ProcessAssertionSyscall] {
    &e.syscalls()[e.before().syscall_count as usize..e.after().syscall_count as usize]
}

fn assert_held_identity(e: &Evidence, action: ExecutableAction) {
    let executable = e.executable().expect("actual held executable/action audit");
    assert_eq!(executable.action, Some(action));
    assert_eq!(executable.registered_sha256, executable.held_sha256);
    assert_eq!(
        executable.executed_sha256,
        Some(executable.registered_sha256)
    );
    assert_eq!(
        (executable.executed_device, executable.executed_inode),
        (Some(executable.held_device), Some(executable.held_inode))
    );
    assert_eq!(executable.held_mode & 0o777, 0o500);
    assert_eq!(executable.held_seals & ALL_SEALS, ALL_SEALS);
    assert!(executable.checkpoint_sequence > 0);
    assert!(e.checkpoints().iter().any(|point| point.point()
        == crate::editor_dev::ProcessAssertionPoint::HeldVerifiedBeforeExec
        && point.sequence() == executable.checkpoint_sequence));
    match action {
        ExecutableAction::ReplacePath => assert_ne!(
            (
                executable.source_before_device,
                executable.source_before_inode
            ),
            (
                executable.source_after_device,
                executable.source_after_inode
            )
        ),
        ExecutableAction::MutateOriginalInode => {
            assert_eq!(
                (
                    executable.source_before_device,
                    executable.source_before_inode
                ),
                (
                    executable.source_after_device,
                    executable.source_after_inode
                )
            );
            assert_ne!(
                executable.source_before_sha256,
                executable.source_after_sha256
            );
        }
        ExecutableAction::HeldWrite | ExecutableAction::HeldGrow | ExecutableAction::HeldShrink => {
        }
    }
}

pub(crate) fn assert_prior_draft_and_frame(e: &Evidence) {
    let before = e.before();
    let after = e.after();
    if let (Some(a), Some(b)) = (&before.document, &after.document) {
        assert_eq!(a.actor, b.actor);
        assert_eq!(a.document_id, b.document_id);
        assert_eq!(a.bytes, b.bytes);
        assert_eq!(a.cursor, b.cursor);
        assert_eq!(a.selection, b.selection);
        assert_eq!(a.first_visible_line, b.first_visible_line);
        assert_eq!(a.text_generation, b.text_generation);
        assert_eq!(a.view_version, b.view_version);
        assert_eq!(a.confirmed_revision, b.confirmed_revision);
        assert_eq!(a.confirmed_hash, b.confirmed_hash);
    } else {
        assert_eq!(before.document, after.document);
    }
    assert_eq!(before.app_pixels, after.app_pixels);
    assert_eq!(before.app_sha256, after.app_sha256);
    assert_eq!(before.publication_generation, after.publication_generation);
}

fn rejected(e: &Evidence, status: Status) {
    assert_eq!(e.after().adoption_status, Some(status));
    assert_prior_draft_and_frame(e);
}
fn native_error(e: &Evidence, operation: Operation, errno: i32) {
    assert!(
        e.syscalls().iter().any(|r| r.operation == operation
            && r.origin == Origin::Native
            && r.result == -1
            && r.errno == Some(errno)),
        "missing actual native {operation:?}/{errno}"
    );
}
fn received_aliases_closed(e: &Evidence) {
    let received: BTreeSet<_> = e
        .descriptors()
        .iter()
        .filter(|r| r.disposition == Disposition::Received)
        .map(|r| r.descriptor_id)
        .collect();
    let closed: BTreeSet<_> = e
        .descriptors()
        .iter()
        .filter(|r| r.disposition == Disposition::Closed)
        .map(|r| r.descriptor_id)
        .collect();
    assert!(
        received.is_subset(&closed),
        "every actually received temporary alias closed"
    );
    let observed = e
        .syscalls()
        .iter()
        .filter(|r| r.operation == Operation::Recvmsg && r.origin == Origin::Native)
        .map(|r| r.received_fds as usize)
        .sum::<usize>();
    assert_eq!(
        received.len(),
        observed,
        "no closure invented for kernel-discarded aliases"
    );
}
fn canonical_controls(e: &Evidence) {
    for row in e.controls() {
        assert_eq!(row.bytes.len(), 88);
        assert_eq!(u32_at(&row.bytes, 0), 384);
        let kind = u32_at(&row.bytes, 4);
        assert!((1..=8).contains(&kind));
        assert_eq!(u32_at(&row.bytes, 16), 64);
        assert_eq!(&row.bytes[84..88], &[0; 4]);
        assert_eq!(
            row.direction,
            if matches!(kind, 3 | 5) {
                Direction::ChildToParent
            } else {
                Direction::ParentToChild
            }
        );
        let expected_fds = match kind {
            1 => 3,
            5 | 8 => 2,
            _ => 0,
        };
        assert_eq!(row.received_fds, expected_fds);
    }
}
fn immutable_pair(e: &Evidence) {
    for role in [Role::TextState, Role::Surface] {
        assert!(e.descriptors().iter().any(|r| r.role == role
            && r.seals & ALL_SEALS == ALL_SEALS
            && r.mapping == Mapping::ReadOnly));
    }
}

fn ancillary_messages(bytes: &[u8]) -> Vec<(i32, i32, &[u8])> {
    assert!(bytes.len() <= 256);
    let width = std::mem::size_of::<usize>();
    let header = width + 8;
    let mut offset = 0;
    let mut rows = Vec::new();
    while offset + header <= bytes.len() {
        let length = if width == 8 {
            u64_at(bytes, offset) as usize
        } else {
            u32_at(bytes, offset) as usize
        };
        assert!(
            length >= header && offset + length <= bytes.len(),
            "actual complete cmsghdr projection"
        );
        let level = i32::from_le_bytes(
            bytes[offset + width..offset + width + 4]
                .try_into()
                .unwrap(),
        );
        let kind = i32::from_le_bytes(
            bytes[offset + width + 4..offset + header]
                .try_into()
                .unwrap(),
        );
        rows.push((level, kind, &bytes[offset + header..offset + length]));
        offset += (length + width - 1) & !(width - 1);
    }
    rows
}

fn credential_fault_was_attempted(e: &Evidence, id: &str) {
    let calls = attempt_syscalls(e);
    if matches!(id, "D04MissingCredentials" | "D04DuplicateCredentials") {
        assert!(
            calls
                .iter()
                .filter(|r| r.operation == Operation::ParseAncillary
                    && r.origin == Origin::ParserStructural)
                .any(|r| ancillary_messages(&r.ancillary)
                    .iter()
                    .filter(|(level, kind, _)| *level == libc::SOL_SOCKET
                        && *kind == libc::SCM_CREDENTIALS)
                    .count()
                    == if id == "D04MissingCredentials" { 0 } else { 2 })
        );
    } else if matches!(
        id,
        "D04ForgedPidKernelReject" | "D04ForgedUidKernelReject" | "D04ForgedGidKernelReject"
    ) {
        assert!(
            calls
                .iter()
                .filter(|r| r.operation == Operation::Sendmsg
                    && r.origin == Origin::Native
                    && r.errno == Some(libc::EPERM))
                .any(|r| {
                    let actual = r.sender.expect("actual native sending process credentials");
                    ancillary_messages(&r.ancillary)
                        .iter()
                        .any(|(level, kind, payload)| {
                            if *level != libc::SOL_SOCKET
                                || *kind != libc::SCM_CREDENTIALS
                                || payload.len() != 12
                            {
                                return false;
                            }
                            let requested =
                                (u32_at(payload, 0), u32_at(payload, 4), u32_at(payload, 8));
                            match id {
                                "D04ForgedPidKernelReject" => {
                                    requested.0 != actual.0
                                        && requested.1 == actual.1
                                        && requested.2 == actual.2
                                }
                                "D04ForgedUidKernelReject" => {
                                    requested.0 == actual.0
                                        && requested.1 != actual.1
                                        && requested.2 == actual.2
                                }
                                "D04ForgedGidKernelReject" => {
                                    requested.0 == actual.0
                                        && requested.1 == actual.1
                                        && requested.2 != actual.2
                                }
                                _ => unreachable!(),
                            }
                        })
                }),
            "actual distinct forged credential tuple rejected by kernel"
        );
    }
}

pub(crate) fn assert_offered_binding(e: &Evidence, id: &str, approved_pid: u32) {
    let pending = e
        .before()
        .pending_offer_id
        .expect("actual current pending offer");
    let offered = |role| {
        e.descriptors()
            .iter()
            .find(|r| {
                r.role == role
                    && r.event == DescriptorEvent::Offered
                    && r.offer_id == Some(pending)
                    && r.owner_process_id == Some(approved_pid)
            })
            .expect("actual primary offered role")
    };
    let returned = |role| {
        e.descriptors()[e.before().descriptor_count as usize..e.after().descriptor_count as usize]
            .iter()
            .find(|r| r.role == role && r.event == DescriptorEvent::Returned)
            .expect("actual returned protocol slot")
    };
    let identity = |r: &crate::editor_dev::ProcessAssertionDescriptor| (r.device, r.inode);
    let text = offered(Role::TextState);
    let surface = offered(Role::Surface);
    let returned_text = returned(Role::TextState);
    let returned_surface = returned(Role::Surface);
    match id {
        "D12ExactPendingOfferedPair" => {
            assert_eq!(identity(text), identity(returned_text));
            assert_eq!(identity(surface), identity(returned_surface));
        }
        "D12ForeignChildText" | "D12ForeignChildSurface" => {
            let role = if id == "D12ForeignChildText" {
                Role::TextState
            } else {
                Role::Surface
            };
            let foreign = returned(role);
            assert_ne!(foreign.owner_process_id, Some(approved_pid));
            assert!(foreign.owner_process_id.is_some());
            assert!(e.descriptors().iter().any(|r| r.role == role
                && r.event == DescriptorEvent::Offered
                && r.owner_process_id == foreign.owner_process_id
                && identity(r) == identity(foreign)));
            assert_ne!(identity(foreign), identity(offered(role)));
        }
        "D12SwappedOfferedRoles" => {
            assert_eq!(identity(text), identity(returned_surface));
            assert_eq!(identity(surface), identity(returned_text));
        }
        "D12DuplicateOfferedFdRoles" => {
            assert_eq!(identity(returned_text), identity(returned_surface))
        }
        "D12EqualBytesForeignInode" => {
            let (expected, foreign) = if identity(text) != identity(returned_text) {
                (text, returned_text)
            } else {
                (surface, returned_surface)
            };
            assert_ne!(identity(expected), identity(foreign));
            let object = |id| {
                e.objects()
                    .iter()
                    .find(|o| o.descriptor_id == id)
                    .expect("actual complete equal-byte objects")
            };
            assert_eq!(
                object(expected.descriptor_id).bytes,
                object(foreign.descriptor_id).bytes
            );
        }
        "D12StaleOfferId" => assert!(
            e.controls()[e.before().control_count as usize..e.after().control_count as usize]
                .iter()
                .any(|r| r.bytes.len() == 88
                    && u32_at(&r.bytes, 4) == 5
                    && u64_at(&r.bytes, 68) != pending)
        ),
        _ => panic!("unreviewed actual offered identity case"),
    }
}

pub(crate) fn assert_sender_binding(e: &Evidence, id: &str, approved_pid: u32) {
    if matches!(id, "D04MissingCredentials" | "D04DuplicateCredentials") {
        assert!(
            attempt_syscalls(e)
                .iter()
                .any(|r| r.operation == Operation::ParseAncillary
                    && r.origin == Origin::ParserStructural
                    && r.result == -1)
        );
    } else if matches!(
        id,
        "D04InheritedEndpointForeignPid"
            | "D04CreationPeercredIsNotSender"
            | "D04CopiedBootstrapPidActor"
    ) {
        let foreign: BTreeSet<_> = attempt_syscalls(e)
            .iter()
            .filter(|r| r.operation == Operation::Recvmsg && r.origin == Origin::Native)
            .filter_map(|r| r.sender.map(|(pid, _, _)| pid))
            .filter(|pid| *pid != approved_pid)
            .collect();
        assert!(
            !foreign.is_empty(),
            "actual sender differs from enrolled child"
        );
        for pid in foreign {
            assert!(
                e.syscalls().iter().any(|r| r.operation == Operation::Fork
                    && r.origin == Origin::Native
                    && r.result == i64::from(pid)),
                "foreign helper actually forked"
            );
            assert!(
                e.syscalls()
                    .iter()
                    .any(|r| r.operation == Operation::Waitpid
                        && r.origin == Origin::Native
                        && r.result == i64::from(pid)),
                "foreign helper actually reaped"
            );
        }
    } else if id == "D04GenuineOwnedSender" {
        let rows: Vec<_> = e
            .controls()
            .iter()
            .filter(|r| r.direction == Direction::ChildToParent)
            .collect();
        assert!(!rows.is_empty());
        for row in rows {
            let (pid, uid, gid) = row.sender.expect("kernel sender on each child record");
            assert_eq!(pid, approved_pid);
            assert_eq!(uid, unsafe { libc::getuid() });
            assert_eq!(gid, unsafe { libc::getgid() });
        }
    }
}

fn child_saved_imitation_was_attempted(e: &Evidence) {
    let surface = attempted_object(e, Role::Surface);
    assert_eq!(surface.bytes.len(), SURFACE_BYTES);
    let font = include_bytes!("../../../tests/fixtures/ascii8x16_v0.bin");
    assert_eq!(
        format!("{:x}", Sha256::digest(font)),
        "50ab6522c495f06a69590ccb6958458be15e02a2ca4c6b1024b052e826d21c64"
    );
    for (column, byte) in b"Saved".iter().enumerate() {
        for y in 0..16 {
            for x in 0..8 {
                let set = font[(*byte as usize - 32) * 16 + y] & (128 >> x) != 0;
                let offset = (y * 640 + column * 8 + x) * 4;
                assert_eq!(
                    &surface.bytes[offset..offset + 4],
                    if set { &[0, 0, 0, 255] } else { &[255; 4] },
                    "actual child attempts Saved glyphs in its Surface"
                );
            }
        }
    }
    assert_eq!(e.after().app_pixels, surface.bytes);
}

fn malformed_fd_arity_was_attempted(e: &Evidence, id: &str) {
    let expected = match id {
        "D05BootstrapFdZero" => (1, 0),
        "D05BootstrapFdOne" => (1, 1),
        "D05BootstrapFdTwo" => (1, 2),
        "D05BootstrapFdFour" => (1, 4),
        "D05DeliverInputFdOne" => (2, 1),
        "D05RequestPublicationFdZero" => (8, 0),
        "D05RequestPublicationFdOne" => (8, 1),
        "D05RequestPublicationFdThree" => (8, 3),
        "D05PublishFdZero" => (5, 0),
        "D05PublishFdOne" => (5, 1),
        "D05PublishFdThree" => (5, 3),
        "D05InputAckFdOne" => (3, 1),
        "D05StopFdOne" => (4, 1),
        "D05PublishAckFdOne" => (6, 1),
        "D05ReceiptNoticeFdOne" => (7, 1),
        "D05UnknownAncillary"
        | "D05DuplicateRights"
        | "D05AncillaryTruncation"
        | "D05RecordTruncation" => return,
        _ => panic!("unknown descriptor-arity case {id}"),
    };
    assert!(
        e.controls()[e.before().control_count as usize..e.after().control_count as usize]
            .iter()
            .any(|r| r.bytes.len() == 88
                && u32_at(&r.bytes, 4) == expected.0
                && r.received_fds == expected.1),
        "distinct actual record/FD arity {id}"
    );
}

fn malformed_selected_was_attempted(e: &Evidence, id: &str) {
    match id {
        "D06FocusBeforeFirstFrame" => {
            assert_eq!(e.before().publication_generation, 0);
            assert_eq!(e.after().publication_generation, 0);
            assert!(e.after().app_pixels.is_empty());
        }
        "D06SelectedInputUnsealed" => assert!(
            e.descriptors()
                .iter()
                .any(|r| r.role == Role::Selected && r.seals & ALL_SEALS != ALL_SEALS)
        ),
        _ => {
            let object = attempted_object(e, Role::Selected);
            assert!(object.bytes.len() >= 64);
            match id {
                "D06SelectedHashMismatch" => {
                    assert_ne!(&object.bytes[24..56], hash(&object.bytes[64..]).as_slice())
                }
                "D06SelectedRevisionMismatch" => assert_ne!(u64_at(&object.bytes, 16), 1),
                "D06SelectedObjectMismatch" => assert_ne!(u64_at(&object.bytes, 8), 101),
                _ => panic!("unreviewed selected mutation {id}"),
            }
        }
    }
}

fn malformed_text_or_key_was_attempted(e: &Evidence, id: &str) {
    if matches!(
        id,
        "D08UnsupportedKeyUsage" | "D08ContradictoryModifiers" | "D08InvalidKeyPhase"
    ) {
        let rows =
            &e.controls()[e.before().control_count as usize..e.after().control_count as usize];
        assert!(
            rows.iter().any(|r| r.bytes.len() == 88
                && u32_at(&r.bytes, 4) == 2
                && match id {
                    "D08UnsupportedKeyUsage" =>
                        !matches!(u32_at(&r.bytes,68), 4..=56 | 74 | 77 | 79..=82 | 224 | 225),
                    "D08ContradictoryModifiers" => u32_at(&r.bytes, 76) & !3 != 0,
                    "D08InvalidKeyPhase" => !matches!(u32_at(&r.bytes, 72), 1..=3),
                    _ => unreachable!(),
                }),
            "distinct attempted malformed input {id}"
        );
        return;
    }
    let text = attempted_object(e, Role::TextState);
    let b = &text.bytes;
    assert!(b.len() >= 128);
    let len = b.len() - 128;
    match id {
        "D08Body4097" => assert_eq!(len, 4097),
        "D08BodyNonAscii" => assert!(b[128..].iter().any(|v| !v.is_ascii())),
        "D08BodyNul" => assert!(b[128..].contains(&0)),
        "D09CursorBeyondBody" => assert!(u32_at(b, 64) as usize > len),
        "D09HalfSelectionSentinel" => {
            assert_ne!(u32_at(b, 68) == u32::MAX, u32_at(b, 72) == u32::MAX)
        }
        "D09SelectionReversed" => assert!(u32_at(b, 68) > u32_at(b, 72)),
        "D09SelectionBeyondBody" => {
            assert!(u32_at(b, 68) as usize > len || u32_at(b, 72) as usize > len)
        }
        "D09FirstLineBeyondInventory" => {
            assert!(u32_at(b, 76) as usize >= 1 + b[128..].iter().filter(|v| **v == b'\n').count())
        }
        "D09WrongViewGeneration" => assert!(e.controls().iter().any(|r| r.bytes.len() == 88
            && u32_at(&r.bytes, 4) == 5
            && u64_at(&r.bytes, 60) != u64_at(b, 88))),
        _ => panic!("unreviewed text/key mutation {id}"),
    }
}

fn malformed_wire_was_attempted(e: &Evidence, id: &str) {
    let rows = &e.controls()[e.before().control_count as usize..e.after().control_count as usize];
    assert!(
        rows.iter().any(|row| {
            let b = &row.bytes;
            match id {
                "D03Frame87Bytes" => b.len() == 87,
                "D03Frame89Bytes" => b.len() == 89,
                "D03ProtocolZero" => b.len() >= 4 && u32_at(b, 0) == 0,
                "D03ForeignProtocolVersion" => b.len() >= 4 && !matches!(u32_at(b, 0), 0 | 384),
                "D03MessageTypeZero" => b.len() >= 8 && u32_at(b, 4) == 0,
                "D03MessageTypeNine" => b.len() >= 8 && u32_at(b, 4) == 9,
                "D03NonzeroTail84" => b.len() == 88 && b[84] != 0,
                "D03NonzeroTail85" => b.len() == 88 && b[85] != 0,
                "D03NonzeroTail86" => b.len() == 88 && b[86] != 0,
                "D03NonzeroTail87" => b.len() == 88 && b[87] != 0,
                "D03WrongPayloadLength" => b.len() == 88 && u32_at(b, 16) != 64,
                "D03NonzeroReservedField" => {
                    b.len() == 88
                        && match u32_at(b, 4) {
                            1 | 3 => b[68..84].iter().any(|v| *v != 0),
                            4 => b[40..84].iter().any(|v| *v != 0),
                            6 => b[56..84].iter().any(|v| *v != 0),
                            7 => b[76..84].iter().any(|v| *v != 0),
                            8 => b[72..84].iter().any(|v| *v != 0),
                            _ => false,
                        }
                }
                "D03UnknownFlags" => {
                    b.len() == 88
                        && match u32_at(b, 4) {
                            2 => !matches!(u32_at(b, 80), 0..=2),
                            3 => !matches!(u32_at(b, 60), 0 | 1),
                            8 => !matches!(u32_at(b, 68), 0 | 2),
                            _ => false,
                        }
                }
                "D03WrongMessageDirection" => {
                    b.len() == 88
                        && row.direction
                            != if matches!(u32_at(b, 4), 3 | 5) {
                                Direction::ChildToParent
                            } else {
                                Direction::ParentToChild
                            }
                }
                _ => panic!("unreviewed wire mutation {id}"),
            }
        }),
        "case {id} never actually attempted its distinct malformed record"
    );
}

fn attempted_object<'a>(
    e: &'a Evidence,
    role: Role,
) -> &'a crate::editor_dev::ProcessAssertionObject {
    let ids: BTreeSet<_> = e.descriptors()
        [e.before().descriptor_count as usize..e.after().descriptor_count as usize]
        .iter()
        .filter(|r| r.role == role)
        .map(|r| r.descriptor_id)
        .collect();
    e.objects()
        .iter()
        .find(|r| ids.contains(&r.descriptor_id))
        .expect("actual rejected offered-object capture")
}

fn malformed_pair_was_attempted(e: &Evidence, id: &str) {
    if id == "D13SurfaceFormatMismatch" {
        assert!(
            e.controls().iter().any(|r| r.bytes.len() == 88
                && u32_at(&r.bytes, 4) == 1
                && (u32_at(&r.bytes, 56) != 640
                    || u32_at(&r.bytes, 60) != 480
                    || u32_at(&r.bytes, 64) != 2560)),
            "actual pre-bootstrap width/height/stride violation; Surface has no format field"
        );
        return;
    }
    let text = attempted_object(e, Role::TextState);
    let surface = attempted_object(e, Role::Surface);
    match id {
        "D13TextLength127" => assert_eq!(text.bytes.len(), 127),
        "D13TextLength4225" => assert_eq!(text.bytes.len(), 4225),
        "D13ControlLengthVsFstat" => assert!(e.controls().iter().any(|r| r.bytes.len() == 88
            && u32_at(&r.bytes, 4) == 5
            && u32_at(&r.bytes, 76) as usize != text.bytes.len())),
        "D13SurfaceLength1228799" => assert_eq!(surface.bytes.len(), 1_228_799),
        "D13SurfaceLength1228801" => assert_eq!(surface.bytes.len(), 1_228_801),
        "D13TextHeaderVersion" => assert_ne!(u32_at(&text.bytes, 0), 1),
        "D13TextHeaderReserved" => assert_ne!(u32_at(&text.bytes, 60), 0),
        "D13TextBodyHash" => assert_ne!(&text.bytes[24..56], hash(&text.bytes[128..]).as_slice()),
        "D13BaseRevisionMismatch" => assert_ne!(
            u64_at(&text.bytes, 16),
            e.before().document.as_ref().unwrap().confirmed_revision
        ),
        "D13TextObjectMismatch" => assert_ne!(u64_at(&text.bytes, 8), 101),
        "D13StateControlGenerationMismatch" => assert!(e.controls().iter().any(|r| r.bytes.len()
            == 88
            && u32_at(&r.bytes, 4) == 5
            && (u64_at(&r.bytes, 52) != u64_at(&text.bytes, 80)
                || u64_at(&r.bytes, 60) != u64_at(&text.bytes, 88)))),
        "D13SurfaceCompanionHashMismatch" => {
            assert_ne!(&text.bytes[96..128], hash(&surface.bytes).as_slice())
        }
        "D13SurfaceAlphaMismatch" => assert!(surface.bytes.chunks_exact(4).any(|p| p[3] != 255)),
        "D13SurfaceFormatMismatch" => assert!(
            e.descriptors()
                .iter()
                .any(|r| r.role == Role::Surface && r.byte_len != SURFACE_BYTES as u64)
                || surface.bytes.chunks_exact(4).any(|p| p[3] != 255)
        ),
        _ => panic!("unreviewed mapping mutation {id}"),
    }
}

/// A finite negative's exact identifier selects its predicate. It never selects
/// an effect. Fault injection and native observations remain distinct records.
pub(crate) fn assert_negative(e: &Evidence, id: &str) {
    assert_integrity(e, id);
    let family = &id[..3];
    match family {
        "D02" => match id {
            "D02PostHeldPathReplacement" | "D02PostHeldInodeMutation" => {
                assert_held_identity(
                    e,
                    if id == "D02PostHeldPathReplacement" {
                        ExecutableAction::ReplacePath
                    } else {
                        ExecutableAction::MutateOriginalInode
                    },
                );
                assert_eq!(e.after().adoption_status, Some(Status::Ok));
                assert!(
                    e.syscalls()
                        .iter()
                        .any(|r| r.operation == Operation::Execveat && r.origin == Origin::Native)
                );
                assert!(
                    e.descriptors()
                        .iter()
                        .any(|r| r.role == Role::Executable && r.seals & ALL_SEALS == ALL_SEALS)
                );
                assert!(e.supervisor_joined() && e.native_wait_outcome().is_some());
            }
            "D02HeldWriteDenied" => {
                assert_held_identity(e, ExecutableAction::HeldWrite);
                native_error(e, Operation::Pwrite, libc::EPERM);
            }
            "D02HeldGrowDenied" | "D02HeldShrinkDenied" => {
                assert_held_identity(
                    e,
                    if id == "D02HeldGrowDenied" {
                        ExecutableAction::HeldGrow
                    } else {
                        ExecutableAction::HeldShrink
                    },
                );
                native_error(e, Operation::Truncate, libc::EPERM);
            }
            "D02WrongRegisteredDigest" | "D02PreSnapshotSourceReplacement" => {
                let executable = e
                    .executable()
                    .expect("actual rejected registration/source identity");
                if id == "D02WrongRegisteredDigest" {
                    assert_ne!(
                        executable.source_before_sha256,
                        executable.registered_sha256
                    );
                } else {
                    assert_ne!(
                        (
                            executable.source_before_device,
                            executable.source_before_inode
                        ),
                        (
                            executable.source_after_device,
                            executable.source_after_inode
                        )
                    );
                    assert_ne!(executable.source_after_sha256, executable.registered_sha256);
                }
                assert!(
                    !e.syscalls()
                        .iter()
                        .any(|r| r.operation == Operation::Execveat && r.origin == Origin::Native)
                );
                rejected(e, Status::Denied)
            }
            "D02SourceSymlink" => {
                native_error(e, Operation::Open, libc::ELOOP);
                rejected(e, Status::Invalid);
            }
            "D02SourceNonregular" => {
                assert!(
                    e.descriptors()
                        .iter()
                        .any(|r| r.role == Role::Executable
                            && r.mode & libc::S_IFMT != libc::S_IFREG)
                );
                rejected(e, Status::Invalid);
            }
            "D02ScriptExecutable" | "D02InvalidElf" => {
                let header = &e
                    .executable()
                    .expect("actual bounded source ELF header")
                    .source_header;
                assert!(header.len() <= 64);
                if id == "D02ScriptExecutable" {
                    assert!(header.starts_with(b"#!"));
                } else {
                    assert!(!header.starts_with(b"#!"));
                    assert!(
                        header.len() < 64
                            || !header.starts_with(b"\x7fELF")
                            || header[4] != 2
                            || header[5] != 1
                            || u16::from_le_bytes([header[18], header[19]]) != 62
                    );
                }
                assert!(
                    !e.syscalls()
                        .iter()
                        .any(|r| r.operation == Operation::Execveat && r.result >= 0)
                );
                rejected(e, Status::Invalid);
            }
            "D02MemfdUnavailable" | "D02ExecveatUnavailable" => {
                rejected(e, Status::Unsupported);
                assert!(
                    e.syscalls()
                        .iter()
                        .any(|r| r.origin == Origin::InjectedBeforeSyscall
                            && r.operation
                                == if id == "D02MemfdUnavailable" {
                                    Operation::MemfdCreate
                                } else {
                                    Operation::Execveat
                                }
                            && r.result == -1
                            && r.errno == Some(libc::ENOSYS))
                );
            }
            "D02BirthInstallFailure" | "D02PidfdInstallFailure" | "D02SupervisorInstallFailure" => {
                rejected(e, Status::Internal);
                assert!(e.syscalls().iter().any(|r| r.origin
                    == if id == "D02SupervisorInstallFailure" {
                        Origin::InjectedBeforeOperation
                    } else {
                        Origin::InjectedBeforeSyscall
                    }
                    && r.result == -1
                    && r.operation
                        == match id {
                            "D02BirthInstallFailure" => Operation::Open,
                            "D02PidfdInstallFailure" => Operation::PidfdOpen,
                            _ => Operation::SupervisorStart,
                        }));
                if id == "D02SupervisorInstallFailure" {
                    assert!(!e.syscalls().iter().any(|r| r.operation == Operation::Fork
                        && r.origin == Origin::Native
                        && r.result > 0));
                }
            }
            _ => panic!("unreviewed D02 case {id}"),
        },
        "D03" => {
            malformed_wire_was_attempted(e, id);
            rejected(e, Status::Invalid);
        }
        "D04" => {
            credential_fault_was_attempted(e, id);
            if matches!(
                id,
                "D04ForgedPidKernelReject"
                    | "D04ForgedUidKernelReject"
                    | "D04ForgedGidKernelReject"
            ) {
                native_error(e, Operation::Sendmsg, libc::EPERM);
                assert_prior_draft_and_frame(e);
            } else if matches!(id, "D04MissingCredentials" | "D04DuplicateCredentials") {
                rejected(e, Status::Invalid);
                assert!(
                    e.syscalls()
                        .iter()
                        .any(|r| r.operation == Operation::ParseAncillary
                            && r.origin == Origin::ParserStructural
                            && r.result == -1)
                );
            } else {
                rejected(e, Status::Denied);
                assert!(
                    e.syscalls()
                        .iter()
                        .any(|r| r.operation == Operation::Recvmsg
                            && r.origin == Origin::Native
                            && r.sender.is_some())
                );
            }
        }
        "D05" => {
            malformed_fd_arity_was_attempted(e, id);
            if matches!(id, "D05UnknownAncillary" | "D05DuplicateRights") {
                assert!(attempt_syscalls(e).iter().any(|r| r.operation
                    == Operation::ParseAncillary
                    && r.origin == Origin::ParserStructural
                    && if id == "D05UnknownAncillary" {
                        ancillary_messages(&r.ancillary)
                            .iter()
                            .any(|(level, kind, _)| {
                                *level != libc::SOL_SOCKET
                                    || !matches!(*kind, libc::SCM_RIGHTS | libc::SCM_CREDENTIALS)
                            })
                    } else {
                        ancillary_messages(&r.ancillary)
                            .iter()
                            .filter(|(level, kind, _)| {
                                *level == libc::SOL_SOCKET && *kind == libc::SCM_RIGHTS
                            })
                            .count()
                            == 2
                    }));
            }
            rejected(e, Status::Invalid);
            received_aliases_closed(e);
            if id == "D05AncillaryTruncation" {
                assert!(
                    e.syscalls()
                        .iter()
                        .any(|r| r.operation == Operation::Recvmsg
                            && r.msg_flags & libc::MSG_CTRUNC as u32 != 0)
                );
            }
            if id == "D05RecordTruncation" {
                assert!(
                    e.syscalls()
                        .iter()
                        .any(|r| r.operation == Operation::Recvmsg
                            && r.msg_flags & libc::MSG_TRUNC as u32 != 0)
                );
            }
        }
        "D06" => {
            malformed_selected_was_attempted(e, id);
            rejected(
                e,
                if id == "D06FocusBeforeFirstFrame" {
                    Status::NotReady
                } else if id == "D06SelectedInputUnsealed" {
                    Status::Invalid
                } else {
                    Status::Denied
                },
            );
            assert!(e.after().app_pixels.is_empty());
        }
        "D08" | "D09" => {
            malformed_text_or_key_was_attempted(e, id);
            rejected(e, Status::Invalid);
        }
        "D10" => {
            if id == "D10ChildSavedImitationClipped" {
                child_saved_imitation_was_attempted(e);
                assert_eq!(e.before().composed_pixels.len(), COMPOSED_BYTES);
                assert_eq!(
                    &e.before().composed_pixels[..640 * 88 * 4],
                    &e.after().composed_pixels[..640 * 88 * 4]
                );
            } else if id == "D10ReservedKeyForwardingReject" {
                assert_eq!(e.before().delivered_sequence, e.after().delivered_sequence);
                assert!(!e.controls().iter().any(|r| r.bytes.len() == 88
                    && u32_at(&r.bytes, 4) == 2
                    && u32_at(&r.bytes, 68) == 20
                    && u32_at(&r.bytes, 76) & 1 != 0));
            } else if id == "D10ProtectedChromeObjectAsSurface" {
                // Public consumer checks the actual typed wrong-peer Core
                // denial and Root's missing-FD-export compiler probe. No Unix
                // FD can denote the internal protected chrome Vec.
                assert_prior_draft_and_frame(e);
            } else {
                if id == "D10OversizedSurface" {
                    assert!(attempted_object(e, Role::Surface).bytes.len() > SURFACE_BYTES);
                }
                rejected(
                    e,
                    if id == "D10ProtectedChromeObjectAsSurface" {
                        Status::Denied
                    } else {
                        Status::Invalid
                    },
                );
            }
        }
        "D11" => {
            match id {
                "D11RetainedWritableMapping" | "D11MprotectOnly" => {
                    native_error(e, Operation::AddSeals, libc::EBUSY);
                    assert!(e.descriptors().iter().any(|r| matches!(
                        r.role,
                        Role::TextState | Role::Surface
                    ) && r.mapping
                        == if id == "D11MprotectOnly" {
                            Mapping::ReadOnly
                        } else {
                            Mapping::SharedWritable
                        }));
                }
                "D11WriteAfterSeal" => native_error(e, Operation::Pwrite, libc::EPERM),
                "D11GrowAfterSeal" | "D11ShrinkAfterSeal" => {
                    native_error(e, Operation::Truncate, libc::EPERM)
                }
                "D11FutureWriteOnly" => {
                    assert!(
                        e.descriptors()
                            .iter()
                            .any(|r| r.seals & libc::F_SEAL_FUTURE_WRITE as u32 != 0
                                && r.seals & libc::F_SEAL_WRITE as u32 == 0)
                    );
                    rejected(e, Status::Invalid);
                }
                "D11MissingGrowSeal" | "D11MissingShrinkSeal" | "D11MissingFinalSeal" => {
                    let missing = match id {
                        "D11MissingGrowSeal" => libc::F_SEAL_GROW,
                        "D11MissingShrinkSeal" => libc::F_SEAL_SHRINK,
                        _ => libc::F_SEAL_SEAL,
                    } as u32;
                    assert!(e.descriptors().iter().any(|r| matches!(
                        r.role,
                        Role::TextState | Role::Surface
                    ) && r.seals & ALL_SEALS
                        == ALL_SEALS & !missing));
                    rejected(e, Status::Invalid);
                }
                _ => panic!("unreviewed D11 case {id}"),
            }
            assert_prior_draft_and_frame(e);
        }
        "D12" => {
            rejected(
                e,
                if id == "D12StaleOfferId" {
                    Status::Stale
                } else {
                    Status::Denied
                },
            );
            received_aliases_closed(e);
            assert_eq!(
                e.before().owners.lifetime_objects,
                e.after().owners.lifetime_objects
            );
            assert_eq!(
                e.before().owners.lifetime_bytes,
                e.after().owners.lifetime_bytes
            );
        }
        "D13" => {
            malformed_pair_was_attempted(e, id);
            rejected(
                e,
                match id {
                    "D13BaseRevisionMismatch" => Status::Stale,
                    "D13TextObjectMismatch" => Status::Denied,
                    _ => Status::Invalid,
                },
            );
        }
        "D14" => {
            let before = e.before();
            let after = e.after();
            let rows = &e.controls()[before.control_count as usize..after.control_count as usize];
            if id.ends_with("CounterMax") {
                let counter = match id {
                    "D14RequestCounterMax" => before.request_sequence,
                    "D14PublicationCounterMax" => before.publication_generation,
                    "D14TextCounterMax" => before.document.as_ref().unwrap().text_generation,
                    "D14ViewCounterMax" => before.document.as_ref().unwrap().view_version,
                    "D14ChannelCounterMax" => before.channel_generation,
                    _ => panic!("unreviewed counter"),
                };
                assert_eq!(counter, u64::MAX);
                assert_eq!(before.request_sequence, after.request_sequence);
                assert_eq!(before.channel_generation, after.channel_generation);
                assert_eq!(
                    before.control_count, after.control_count,
                    "overflow refuses before encoding another record"
                );
                assert!(!attempt_syscalls(e).iter().any(|r| r.result >= 0
                    && matches!(
                        r.operation,
                        Operation::MemfdCreate | Operation::Mmap | Operation::Fork
                    )));
                rejected(e, Status::Exhausted);
            } else {
                assert!(
                    rows.iter().any(|r| r.bytes.len() == 88
                        && match id {
                            "D14OldRequest" => u64_at(&r.bytes, 20) < before.request_sequence,
                            "D14FutureInput" =>
                                matches!(u32_at(&r.bytes, 4), 3 | 5)
                                    && u64_at(&r.bytes, 36) > before.delivered_sequence,
                            "D14DuplicatePublish" | "D14DuplicateAck" =>
                                u32_at(&r.bytes, 4)
                                    == if id == "D14DuplicatePublish" { 5 } else { 3 }
                                    && e.controls()[..before.control_count as usize]
                                        .iter()
                                        .any(|prior| prior.bytes == r.bytes),
                            "D14WrongChannelGeneration" =>
                                u64_at(&r.bytes, 28) != before.channel_generation,
                            "D14OldFocusEpoch" =>
                                u32_at(&r.bytes, 4) == 2
                                    && u64_at(&r.bytes, 44) < before.focus_epoch,
                            "D14OldServiceEpoch" =>
                                u32_at(&r.bytes, 4) == 2
                                    && u64_at(&r.bytes, 52) < before.service_epoch,
                            "D14ForeignDocumentBinding" =>
                                u32_at(&r.bytes, 4) == 1
                                    && e.controls()[..before.control_count as usize].iter().any(
                                        |prior| prior.bytes.len() == 88
                                            && u32_at(&prior.bytes, 4) == 1
                                            && u64_at(&prior.bytes, 36) != u64_at(&r.bytes, 36)
                                    ),
                            _ => panic!("unreviewed ordering control {id}"),
                        }),
                    "actual distinct ordering/epoch attempt {id}"
                );
                rejected(
                    e,
                    if id == "D14ForeignDocumentBinding" {
                        Status::Denied
                    } else {
                        Status::Stale
                    },
                );
            }
        }
        "D15" => {
            rejected(e, Status::Exhausted);
            let a = &e.before().owners;
            let b = &e.after().owners;
            match id {
                "D15DataOwnerThirteen" => {
                    assert_eq!(a.data, 12);
                    assert_eq!(b.data, 12);
                }
                "D15FixedOwnerSeventeen" => {
                    assert_eq!(a.fixed, 16);
                    assert_eq!(b.fixed, 16);
                }
                "D15CombinedOwnerTwentyNine" => {
                    assert_eq!(a.combined, 28);
                    assert_eq!(b.combined, 28);
                }
                "D15PendingInputTwo" => {
                    assert_eq!(a.pending_inputs, 1);
                    assert_eq!(b.pending_inputs, 1);
                }
                "D15OrdinaryQueueSixtyFive" => {
                    assert_eq!(a.ordinary_queue, 64);
                    assert_eq!(b.ordinary_queue, 64);
                }
                "D15ReservedResetTwo" => {
                    assert_eq!(a.reset_queue, 1);
                    assert_eq!(b.reset_queue, 1);
                }
                "D15TotalQueueSixtySix" => {
                    assert_eq!(a.ordinary_queue + a.reset_queue, 65);
                    assert_eq!(b.ordinary_queue + b.reset_queue, 65);
                }
                "D15LiveEditorThree" => {
                    assert_eq!(a.children, 2);
                    assert_eq!(b.children, 2);
                }
                "D15SupervisorThree" => {
                    assert_eq!(a.supervisors, 2);
                    assert_eq!(b.supervisors, 2);
                }
                "D15InflightSaveTwo" => panic!("actual app Store/intent owners required"),
                _ => panic!("Store quota {id} requires genuine app-owned Store checks"),
            }
            assert_eq!(
                (a.data, a.fixed, a.combined, a.maps),
                (b.data, b.fixed, b.combined, b.maps)
            );
            assert!(
                !attempt_syscalls(e)
                    .iter()
                    .any(|r| r.origin == Origin::Native
                        && r.result >= 0
                        && matches!(
                            r.operation,
                            Operation::MemfdCreate
                                | Operation::Mmap
                                | Operation::Fork
                                | Operation::PidfdOpen
                        ))
            );
            assert_eq!(
                e.before().owners.lifetime_objects,
                e.after().owners.lifetime_objects
            );
            assert_eq!(
                e.before().owners.lifetime_bytes,
                e.after().owners.lifetime_bytes
            );
            if id == "D15OrdinaryQueueSixtyFive" {
                assert_eq!(e.after().owners.ordinary_queue, 64);
            }
            if id == "D15ReservedResetTwo" {
                assert_eq!(e.after().owners.reset_queue, 1);
            }
        }
        "D16" => {
            rejected(
                e,
                if id == "D16ExistingInodeAsNewCredit" {
                    Status::Denied
                } else {
                    Status::Exhausted
                },
            );
            assert_eq!(e.before().owners.lifetime_offers, 128);
            assert_eq!(e.after().owners.lifetime_offers, 128);
            assert_eq!(e.before().owners.lifetime_objects, 257);
            assert_eq!(e.before().owners.lifetime_bytes, 157_831_232);
            if id == "D16ExistingInodeAsNewCredit" {
                let old = &e.descriptors()[..e.before().descriptor_count as usize];
                let attempted = &e.descriptors()
                    [e.before().descriptor_count as usize..e.after().descriptor_count as usize];
                assert!(
                    attempted
                        .iter()
                        .any(|r| r.event == DescriptorEvent::Returned
                            && old.iter().any(|prior| prior.role == r.role
                                && prior.device == r.device
                                && prior.inode == r.inode
                                && prior.offer_id != r.offer_id)),
                    "actual existing offeredinode wrongly presented as fresh credit"
                );
            }
            assert_eq!(
                e.before().owners.lifetime_objects,
                e.after().owners.lifetime_objects
            );
            assert_eq!(
                e.before().owners.lifetime_bytes,
                e.after().owners.lifetime_bytes
            );
            assert!(
                !attempt_syscalls(e)
                    .iter()
                    .any(|r| r.operation == Operation::MemfdCreate
                        && r.origin == Origin::Native
                        && r.result == 0)
            );
        }
        "D18" => {
            let rows =
                &e.controls()[e.before().control_count as usize..e.after().control_count as usize];
            match id {
                "D18OrdinaryPublishSaveClaim" => {
                    assert_eq!(e.before().captured_at, None);
                    assert_eq!(e.after().captured_at, None);
                    assert_eq!(e.before().save_deadline, None);
                    assert_eq!(e.after().save_deadline, None);
                    assert!(matches!(
                        e.after().adoption_status,
                        Some(Status::Ok | Status::NotReady)
                    ));
                    assert!(rows.iter().any(|r| r.bytes.len() == 88
                        && u32_at(&r.bytes, 4) == 8
                        && u32_at(&r.bytes, 68) == 0));
                    assert!(
                        rows.iter()
                            .any(|r| r.bytes.len() == 88 && u32_at(&r.bytes, 4) == 5)
                    );
                    assert!(
                        !e.controls()[..e.after().control_count as usize]
                            .iter()
                            .any(|r| r.bytes.len() == 88
                                && u32_at(&r.bytes, 4) == 2
                                && u32_at(&r.bytes, 68) == 22
                                && u32_at(&r.bytes, 72) == 1
                                && u32_at(&r.bytes, 76) & 1 != 0)
                    );
                }
                "D18UnsolicitedCapture" => {
                    assert!(rows.iter().any(|r| r.bytes.len() == 88
                        && r.direction == Direction::ChildToParent
                        && u32_at(&r.bytes, 4) == 8
                        && u32_at(&r.bytes, 68) == 2));
                    assert_eq!(e.after().captured_at, None);
                    assert_eq!(e.after().save_deadline, None);
                    rejected(e, Status::Invalid);
                }
                "D18CopiedOldCaptureRequest" => {
                    assert!(rows.iter().any(|r| {
                        r.bytes.len() == 88
                            && u32_at(&r.bytes, 4) == 5
                            && e.controls()[..e.before().control_count as usize]
                                .iter()
                                .any(|old| old.bytes == r.bytes)
                    }));
                    rejected(e, Status::Stale);
                }
                "D18CaptureConsumedTwice" => rejected(e, Status::NotReady),
                "D18CaptureAfter1000Ms" | "D18RoundTripCannotRenewCapture" => {
                    let captured = e
                        .before()
                        .captured_at
                        .expect("actual delivered CtrlS capturedAt");
                    let deadline = e.before().save_deadline.expect("original capture deadline");
                    assert_eq!(
                        deadline.duration_since(captured),
                        Duration::from_millis(1000)
                    );
                    assert_eq!(e.after().save_deadline, Some(deadline));
                    let point = e
                        .checkpoints()
                        .iter()
                        .find(|c| {
                            c.point()
                                == crate::editor_dev::ProcessAssertionPoint::CaptureBeforeAdopt
                        })
                        .expect("actual held capturepoint");
                    assert!(point.reached_at() >= captured);
                    assert!(
                        deadline.duration_since(point.reached_at()) <= Duration::from_millis(1000)
                    );
                    assert!(std::time::Instant::now() >= deadline);
                    rejected(e, Status::Timeout);
                }
                _ => panic!("unreviewed capture control {id}"),
            }
        }
        "D23" => match id {
            "D23OldPreviewEnterDenied" => rejected(e, Status::Stale),
            "D23OldBootstrapDenied" => {
                let earlier = &e.controls()[..e.before().control_count as usize];
                let attempted = &e.controls()
                    [e.before().control_count as usize..e.after().control_count as usize];
                assert!(
                    attempted.iter().any(|r| r.bytes.len() == 88
                        && u32_at(&r.bytes, 4) == 1
                        && u64_at(&r.bytes, 28) != e.before().channel_generation
                        && r.received_fds == 3
                        && earlier.iter().any(|old| old.bytes == r.bytes)),
                    "actual byteidentical oldBootstrap replay to freshregistered child"
                );
                assert!(
                    attempt_syscalls(e)
                        .iter()
                        .any(|r| r.operation == Operation::Sendmsg
                            && r.origin == Origin::Native
                            && r.result == 88)
                );
                assert!(
                    attempt_syscalls(e)
                        .iter()
                        .any(|r| r.operation == Operation::Recvmsg
                            && r.origin == Origin::Native
                            && r.result == 88)
                );
                received_aliases_closed(e);
                rejected(e, Status::Stale);
            }
            "D23NoAutomaticRespawn" => {
                let attempted = attempt_syscalls(e);
                assert!(
                    attempted.iter().any(|r| r.operation == Operation::Signal
                        && r.origin == Origin::Native
                        && r.result == 0),
                    "actual ChildFault signal before ordinary cleanup"
                );
                assert!(
                    attempted.iter().any(|r| r.origin == Origin::Native
                        && ((r.operation == Operation::Waitpid && r.result > 0)
                            || (r.operation == Operation::Recvmsg && r.result == 0))),
                    "actual native terminal wait or EOF before decision boundary"
                );
                assert_eq!(e.after().owners.children, e.before().owners.children);
                assert_eq!(e.after().owners.supervisors, e.before().owners.supervisors);
                assert!(
                    !attempt_syscalls(e)
                        .iter()
                        .any(|r| r.operation == Operation::Fork && r.result > 0)
                );
                assert_prior_draft_and_frame(e);
            }
            _ => panic!("Unknown base requires actual app SaveChain owner"),
        },
        "D24" => {
            match id {
                "D24NoRegistryLockAcrossReceive" => {
                    native_error(e, Operation::Recvmsg, libc::EAGAIN)
                }
                "D24NoRegistryLockAcrossSignalWait" => {
                    for point in [
                        crate::editor_dev::ProcessAssertionPoint::SupervisorBeforeSignal,
                        crate::editor_dev::ProcessAssertionPoint::SupervisorBeforeWait,
                    ] {
                        assert!(
                            e.checkpoints().iter().any(|c| c.point() == point),
                            "actual supervisor point while genuine B progressed"
                        );
                    }
                }
                "D24WatchdogWithoutPump" | "D24OtherSessionCannotRenewDeadline" => {}
                _ => panic!("unreviewed stall control"),
            }
            let before = e
                .before()
                .child_deadline
                .expect("actual admitted child deadline");
            assert_eq!(e.after().child_deadline, Some(before));
            assert!(e.native_wait_outcome().is_some() && e.supervisor_joined());
        }
        "D25" => {
            match id {
                "D25ActualSendBackpressure" => native_error(e, Operation::Sendmsg, libc::EAGAIN),
                "D25ReceiveInterrupted" | "D25SendInterrupted" => {
                    let op = if id == "D25ReceiveInterrupted" {
                        Operation::Recvmsg
                    } else {
                        Operation::Sendmsg
                    };
                    assert!(e.syscalls().iter().any(|r| r.operation == op
                        && r.result == -1
                        && r.errno == Some(libc::EINTR)));
                }
                "D25EofWithPendingOffer" => assert!(
                    e.syscalls()
                        .iter()
                        .any(|r| r.operation == Operation::Recvmsg
                            && r.origin == Origin::Native
                            && r.result == 0)
                ),
                "D25ScenarioControlRow32769" => {
                    assert_eq!(e.before().control_count, 32768);
                    assert_eq!(e.after().control_count, 32768);
                    assert_eq!(e.controls().len(), 32768);
                    assert_eq!(e.after().adoption_status, Some(Status::Exhausted));
                }
                "D25AggregateControlRow131073" => {
                    panic!("aggregate cap is Root-owned actual recorder probe")
                }
                "D25StdoutCapPlusOne" | "D25StderrCapPlusOne" => {
                    let role = if id == "D25StdoutCapPlusOne" {
                        Role::Stdout
                    } else {
                        Role::Stderr
                    };
                    let ids: BTreeSet<_> = e
                        .descriptors()
                        .iter()
                        .filter(|r| r.role == role)
                        .map(|r| r.descriptor_id)
                        .collect();
                    let attempted = e
                        .objects()
                        .iter()
                        .find(|o| ids.contains(&o.descriptor_id) && o.bytes.len() == 16385)
                        .expect("actual stream cap+1 bytes");
                    let retained = e
                        .objects()
                        .iter()
                        .find(|o| {
                            o.descriptor_id == attempted.descriptor_id && o.bytes.len() == 16384
                        })
                        .expect("actual retained16384 prefix, not sampled complete log");
                    assert_eq!(&attempted.bytes[..16384], retained.bytes);
                    assert_eq!(e.after().adoption_status, Some(Status::Exhausted));
                }
                "D25ShortRecord" => rejected(e, Status::Invalid),
                _ => panic!("unreviewed D25 case {id}"),
            }
            assert_prior_draft_and_frame(e);
        }
        "D26" => {
            let rows =
                &e.controls()[e.before().control_count as usize..e.after().control_count as usize];
            assert!(
                rows.iter().any(|r| r.bytes.len() == 88
                    && match id {
                        "D26FrameAfterRevoke" => u32_at(&r.bytes, 4) == 5,
                        "D26CaptureAfterRevoke" =>
                            u32_at(&r.bytes, 4) == 8 && u32_at(&r.bytes, 68) == 2,
                        "D26OldGenerationCannotRevive" =>
                            u64_at(&r.bytes, 28) < e.before().channel_generation,
                        _ => panic!("issuedpermit is genuine appowner case"),
                    }),
                "actual late frame/capture/old binding after genuine Core revoke"
            );
            assert!(e.checkpoints().iter().any(|c| c.point()
                == if id == "D26CaptureAfterRevoke" {
                    crate::editor_dev::ProcessAssertionPoint::CaptureBeforeAdopt
                } else {
                    crate::editor_dev::ProcessAssertionPoint::PairValidatedBeforeAdopt
                }));
            rejected(e, Status::Denied);
        }
        "D27" => {
            let rows =
                &e.controls()[e.before().control_count as usize..e.after().control_count as usize];
            if id == "D27OrdinaryOverflowReservedReset" {
                assert_eq!(e.before().owners.ordinary_queue, 64);
                assert_eq!(e.after().owners.reset_queue, 1);
                assert!(e.after().owners.ordinary_queue <= 64);
            } else {
                assert!(
                    rows.iter().any(|r| r.bytes.len() == 88
                        && match id {
                            "D27OldKeyPressRelease" =>
                                u32_at(&r.bytes, 4) == 2
                                    && matches!(u32_at(&r.bytes, 72), 1 | 2)
                                    && u64_at(&r.bytes, 44) < e.before().focus_epoch,
                            "D27OldResetServiceEpoch" =>
                                u32_at(&r.bytes, 4) == 2
                                    && u32_at(&r.bytes, 80) == 1
                                    && u32_at(&r.bytes, 72) == 3
                                    && u64_at(&r.bytes, 52) < e.before().service_epoch,
                            "D27OldSurfaceGeneration" =>
                                u32_at(&r.bytes, 4) == 5
                                    && e.descriptors()[e.before().descriptor_count as usize
                                        ..e.after().descriptor_count as usize]
                                        .iter()
                                        .any(|d| d.role == Role::Surface
                                            && d.event == DescriptorEvent::Returned
                                            && d.offer_id != e.before().pending_offer_id),
                            "D27StaleResetCapture" =>
                                u32_at(&r.bytes, 4) == 8
                                    && u32_at(&r.bytes, 68) == 2
                                    && u64_at(&r.bytes, 28) != e.before().channel_generation,
                            _ => panic!("unreviewed reset control"),
                        }),
                    "actual stale key/reset/surface/capture tuple"
                );
                rejected(e, Status::Stale);
            }
        }
        "D28" => {
            rejected(
                e,
                if matches!(id, "D28BudgetZero" | "D28Budget5001") {
                    Status::Invalid
                } else {
                    Status::Timeout
                },
            );
            assert_eq!(e.before().child_deadline, e.after().child_deadline);
            let point = match id {
                "D28SpawnPauseCannotRenew" => {
                    crate::editor_dev::ProcessAssertionPoint::ForkOwnedBeforeExecRelease
                }
                "D28BootstrapPauseCannotRenew" => {
                    crate::editor_dev::ProcessAssertionPoint::BootstrapBeforeSend
                }
                "D28RoundTripCannotRenew" | "D28BackdatedCoreClock" => {
                    crate::editor_dev::ProcessAssertionPoint::InputReceivedBeforeAck
                }
                "D28IntentRequestCannotRenew" => {
                    crate::editor_dev::ProcessAssertionPoint::CaptureBeforeAdopt
                }
                _ => panic!("budget constructor controls are public-only"),
            };
            assert!(
                e.checkpoints().iter().any(|c| c.point() == point),
                "actual named expiry point"
            );
        }
        "D29" => {
            assert!(
                !e.syscalls()[..e.after().syscall_count as usize]
                    .iter()
                    .any(|r| r.operation == Operation::Waitpid && r.result > 0),
                "decision remains pre-reap"
            );
            if id == "D29PidfdReadyIsNotReap" {
                assert!(
                    attempt_syscalls(e)
                        .iter()
                        .any(|r| r.operation == Operation::Poll
                            && r.origin == Origin::Native
                            && r.result > 0
                            && r.poll_revents & libc::POLLIN as u32 != 0)
                );
            }
            if id == "D29EofIsNotReap" {
                assert!(
                    attempt_syscalls(e)
                        .iter()
                        .any(|r| r.operation == Operation::Recvmsg
                            && r.origin == Origin::Native
                            && r.result == 0)
                );
            }
            assert!(e.after().owners.children > 0 && e.after().owners.supervisors > 0);
            assert!(e.after().owners.combined >= e.before().owners.combined);
            if matches!(
                id,
                "D29WaitFailureRetainsOwner" | "D29SignalFailureRetainsOwner"
            ) {
                assert_eq!(e.after().adoption_status, Some(Status::Internal));
                let op = if id == "D29WaitFailureRetainsOwner" {
                    Operation::Waitpid
                } else {
                    Operation::Signal
                };
                assert!(e.syscalls().iter().any(|r| r.operation == op
                    && r.origin == Origin::InjectedBeforeSyscall
                    && r.result == -1));
            }
        }
        _ => {
            panic!("case {id} requires app-owned/build/source assertions, not a Desktop surrogate")
        }
    }
}

pub(crate) fn assert_positive(e: &Evidence, id: &str) {
    assert_integrity(e, id);
    canonical_controls(e);
    if id == "D24IndependentChildBWithinOneSecond" {
        assert!(e.native_wait_outcome().is_some() && e.supervisor_joined());
        assert_eq!(e.before().child_deadline, e.after().child_deadline);
        // Real sibling state/pixels/one-second progress are asserted while its
        // actual owner remains live in the public consumer.
        return;
    }
    immutable_pair(e);
    assert_eq!(
        e.after().adoption_status,
        Some(if id == "D28WithinOriginalBudgetAndActualExpiry" {
            Status::Timeout
        } else {
            Status::Ok
        })
    );
    if id == "D28WithinOriginalBudgetAndActualExpiry" {
        assert!(e.native_wait_outcome().is_some() && e.supervisor_joined());
        assert_eq!(e.before().child_deadline, e.after().child_deadline);
    }
    assert!(e.after().acknowledged_sequence <= e.after().delivered_sequence);
    if id == "D07ActualChildEditAndRasterGolden" {
        assert_eq!(e.after().document.as_ref().unwrap().bytes, b"note=new\n");
    }
    if id == "D03AllEightCanonicalMessages" {
        let kinds: BTreeSet<_> = e.controls().iter().map(|r| u32_at(&r.bytes, 4)).collect();
        assert_eq!(kinds, (1..=8).collect());
    }
    if id == "D08EmptyBase4096PressReleaseAndCtrlS" {
        let document = e
            .after()
            .document
            .as_ref()
            .expect("actual accepted child publication");
        assert_eq!(document.bytes, vec![b'a'; 4096]);
        let deliveries = e
            .controls()
            .iter()
            .filter(|r| r.direction == Direction::ParentToChild && u32_at(&r.bytes, 4) == 2)
            .count();
        let acknowledgments = e
            .controls()
            .iter()
            .filter(|r| r.direction == Direction::ChildToParent && u32_at(&r.bytes, 4) == 3)
            .count();
        assert_eq!(
            deliveries, 8196,
            "8192 a press/releases plus genuine Ctrl-down/S-down/S-up/Ctrl-up"
        );
        assert_eq!(acknowledgments, deliveries);
        let pairs = e
            .controls()
            .iter()
            .filter(|r| r.direction == Direction::ChildToParent && u32_at(&r.bytes, 4) == 5)
            .count();
        assert!((66..=67).contains(&pairs));
        let mut previous = 0;
        for row in e
            .controls()
            .iter()
            .filter(|r| r.direction == Direction::ParentToChild && u32_at(&r.bytes, 4) == 2)
        {
            let sequence = u64_at(&row.bytes, 36);
            assert!(sequence > previous);
            previous = sequence;
        }
    }
    if id == "D16LifetimeOffer128ThenFreshReapedChild" {
        assert_eq!(e.after().owners.lifetime_offers, 128);
        assert_eq!(e.after().owners.lifetime_objects, 257);
        assert_eq!(e.after().owners.lifetime_bytes, 157_831_232);
    }
}
