//! Closed assertion plans. These paths retain actual enrolled owners and make
//! actual native attempts; their descriptive records grant no authority.
use super::*;
use std::time::Duration;

#[derive(Default)]
pub(super) struct Plan {
    foreign: Option<Foreign>,
    foreign_bootstrap: Option<[u8; 88]>,
    retained: Vec<linux::Fd>,
    operation_started: bool,
    helper: Option<linux::ForkHelper>,
    helper_slot: bool,
    core_action_done: bool,
    late_deadline: Option<Instant>,
    late_now: Option<u64>,
    late_ready: bool,
    late_done: bool,
}
pub(super) fn before_retire(
    host: &HostDesktop,
    inner: &mut ChildInner,
    reason: ProcessRetireReason,
    now: u64,
) -> Result<bool, Status> {
    if !inner.record.trace.is("D21PublicationAfterDeath")
        || reason != ProcessRetireReason::ChildFault
    {
        return Ok(false);
    }
    let mut plan = take_plan(inner)?;
    if plan.late_ready {
        restore_plan(inner, plan)?;
        return Ok(true);
    }
    let first = plan.late_deadline.is_none();
    let deadline = *plan
        .late_deadline
        .get_or_insert_with(|| Instant::now() + Duration::from_millis(2000));
    plan.late_now.get_or_insert(now);
    restore_plan(inner, plan)?;
    if first {
        inner.record.trace.release_candidate();
        observe_carrier(host, inner, None, true)?;
        inner.record.trace.hold_candidate(8)?;
    }
    loop {
        if Instant::now() >= deadline || Instant::now() >= inner.deadline {
            return Err(Status::Timeout);
        }
        match super::protocol::queue_assertion_publication(host, inner, now) {
            Ok(()) => break,
            Err(Status::NotReady) => std::thread::yield_now(),
            Err(status) => return Err(status),
        }
    }
    loop {
        if Instant::now() >= deadline || Instant::now() >= inner.deadline {
            return Err(Status::Timeout);
        }
        match linux::readable(inner.socket.as_ref().ok_or(Status::Disconnected)?) {
            Ok(true) => break,
            Ok(false) | Err(Status::NotReady) => std::thread::yield_now(),
            Err(status) => return Err(status),
        }
    }
    // Only an actual queued native record defers the decision snapshot; the
    // supervisor still owns the real fence/signal/wait and its full ledger.
    inner.record.trace.defer_late_publication_snapshot()?;
    let mut plan = take_plan(inner)?;
    plan.late_ready = true;
    restore_plan(inner, plan)?;
    Ok(true)
}
pub(super) fn after_native_wait(host: &HostDesktop, inner: &mut ChildInner) -> Result<(), Status> {
    if !inner.record.trace.is("D21PublicationAfterDeath") {
        return Ok(());
    }
    let plan = take_plan(inner)?;
    let (ready, done, deadline, now) = (
        plan.late_ready,
        plan.late_done,
        plan.late_deadline,
        plan.late_now,
    );
    restore_plan(inner, plan)?;
    if done {
        return Ok(());
    }
    if !ready {
        return Err(Status::NotReady);
    }
    let deadline = deadline.ok_or(Status::Internal)?;
    let now = now.ok_or(Status::Internal)?;
    let (identity, _) = inner.joined.ok_or(Status::NotReady)?;
    let mut received = loop {
        if Instant::now() >= deadline {
            return Err(Status::Timeout);
        }
        match linux::receive(inner.socket.as_ref().ok_or(Status::Disconnected)?) {
            Ok(record) => break record,
            Err(Status::NotReady) => std::thread::yield_now(),
            Err(status) => return Err(status),
        }
    };
    if received.credentials
        != (identity.pid, unsafe { libc::getuid() }, unsafe {
            libc::getgid()
        })
    {
        inner.record.trace.quarantine();
        return Err(Status::Denied);
    }
    let offer = inner.offer.as_ref().ok_or(Status::NotReady)?;
    linux::capture_received(&mut received, Some(identity.pid), Some(offer.id))?;
    let (channel, message) =
        desktop_editor_core::wire::decode_frame(&received.bytes).map_err(|_| Status::Invalid)?;
    desktop_editor_core::wire::validate_delivery(
        &message,
        desktop_editor_core::wire::Direction::ChildToParent,
        received.fds.len(),
    )
    .map_err(|_| Status::Invalid)?;
    if channel != inner.record.channel {
        return Err(Status::Stale);
    }
    let ProcessMessage::Publish(publish) = message else {
        return Err(Status::Invalid);
    };
    let (verified, accepted) = super::protocol::verify_pair(inner, &publish, received)?;
    inner
        .record
        .trace
        .point(ProcessAssertionPoint::PairValidatedBeforeAdopt)?;
    let result = host.process_adopt_verified(&inner.enrollment.editor, &verified, None, now);
    drop(accepted);
    let status = match result {
        Err(status @ (Status::Denied | Status::Stale)) => status,
        _ => {
            inner.record.trace.quarantine();
            return Err(Status::Internal);
        }
    };
    // Release actual temporary owners only after the real enforcing denial.
    drop(inner.offer.take());
    inner.record.trace.finish_late_publication_snapshot()?;
    inner.record.trace.release_candidate();
    observe_carrier(host, inner, Some(status), false)?;
    let mut plan = take_plan(inner)?;
    plan.late_done = true;
    restore_plan(inner, plan)?;
    Ok(())
}
pub(super) fn cleanup(enrollment: &ProcessEditorEnrollment) -> Result<(), Status> {
    let plan = std::mem::take(&mut *enrollment.fixture.lock().map_err(|_| Status::Internal)?);
    if plan.helper_slot {
        enrollment.trace.quarantine();
        std::mem::forget(plan);
        return Err(Status::Internal);
    }
    drop(plan);
    if enrollment.trace.quarantined() {
        Err(Status::Internal)
    } else {
        Ok(())
    }
}

pub(super) fn before_operation(
    host: &HostDesktop,
    inner: &mut ChildInner,
    now: u64,
) -> Result<(), Status> {
    if !inner.ready {
        return Ok(());
    }
    let Some(scenario) = inner.record.trace.scenario() else {
        return Ok(());
    };
    if scenario.id() == "D15PendingInputTwo" && inner.pending.is_none() {
        return Ok(());
    }
    let mut plan = take_plan(inner)?;
    let result = (|| {
        if plan.operation_started {
            return Ok(());
        }
        plan.operation_started = true;
        if matches!(
            scenario.id(),
            "D14RequestCounterMax"
                | "D14PublicationCounterMax"
                | "D14TextCounterMax"
                | "D14ViewCounterMax"
                | "D15DataOwnerThirteen"
                | "D15FixedOwnerSeventeen"
                | "D15CombinedOwnerTwentyNine"
                | "D25ActualSendBackpressure"
        ) {
            inner.record.trace.release_candidate();
        }
        match scenario.id() {
            "D14RequestCounterMax" => inner.request = u64::MAX,
            "D14PublicationCounterMax" => inner.publication = u64::MAX,
            "D14TextCounterMax" | "D14ViewCounterMax" => {
                host.process_fixture_counter_seed(&inner.enrollment.editor, scenario)?;
                if scenario.id() == "D14TextCounterMax" {
                    inner.text_generation = u64::MAX;
                } else {
                    inner.view_generation = u64::MAX;
                }
            }
            "D04MissingCredentials"
            | "D04DuplicateCredentials"
            | "D05UnknownAncillary"
            | "D05DuplicateRights" => {
                inner.record.trace.release_candidate();
                observe_carrier(host, inner, None, true)?;
                return super::ancillary::closed_attempt(&inner.record.trace);
            }
            "D04ForgedPidKernelReject"
            | "D04ForgedUidKernelReject"
            | "D04ForgedGidKernelReject" => {
                inner.record.trace.release_candidate();
                observe_carrier(host, inner, None, true)?;
                return linux::forged_credentials(
                    inner.socket.as_ref().ok_or(Status::Disconnected)?,
                    &inner.bootstrap,
                );
            }
            "D04InheritedEndpointForeignPid"
            | "D04CreationPeercredIsNotSender"
            | "D04CopiedBootstrapPidActor" => {
                return foreign_sender_attempt(host, inner, &mut plan, scenario, now);
            }
            "D05AncillaryTruncation" => {
                inner.record.trace.release_candidate();
                observe_carrier(host, inner, None, true)?;
                let peer = inner.gate_peer.take().ok_or(Status::NotReady)?;
                loop {
                    if Instant::now() >= inner.deadline {
                        return Err(Status::Timeout);
                    }
                    match linux::send_ancillary_truncation(
                        &peer,
                        &inner.bootstrap,
                        inner.selected.as_ref().ok_or(Status::Internal)?,
                    ) {
                        Err(Status::NotReady) => std::thread::yield_now(),
                        result => {
                            result?;
                            break;
                        }
                    }
                }
                drop(peer);
                loop {
                    if Instant::now() >= inner.deadline {
                        return Err(Status::Timeout);
                    }
                    match linux::receive(inner.socket.as_ref().ok_or(Status::Disconnected)?) {
                        Err(Status::NotReady) => std::thread::yield_now(),
                        Err(status) => return Err(status),
                        Ok(_) => return Err(Status::Internal),
                    }
                }
            }
            "D14ForeignDocumentBinding" => {
                let other = plan.foreign_bootstrap.ok_or(Status::NotReady)?;
                let mut raw = inner.bootstrap;
                raw[36..44].copy_from_slice(&other[36..44]);
                inner.record.trace.release_candidate();
                observe_carrier(host, inner, None, true)?;
                let accepted = inner.accepted.as_ref().ok_or(Status::NotReady)?;
                let socket = inner.socket.as_ref().ok_or(Status::Disconnected)?;
                let fds = [
                    inner.selected.as_ref().ok_or(Status::NotReady)?,
                    accepted._text.fd(),
                    accepted._surface.fd(),
                ];
                loop {
                    if Instant::now() >= inner.deadline {
                        return Err(Status::Timeout);
                    }
                    match linux::send(socket, &raw, &fds) {
                        Err(Status::NotReady) => std::thread::yield_now(),
                        result => {
                            result?;
                            break;
                        }
                    }
                }
                let (_, message) =
                    desktop_editor_core::wire::decode_frame(&raw).map_err(|_| Status::Invalid)?;
                return validate_bootstrap_binding(&message, &inner.enrollment);
            }
            "D23OldPreviewEnterDenied" => {
                inner.record.trace.release_candidate();
                observe_carrier(host, inner, None, true)?;
                // The finite bridge replays the genuinely consumed Core
                // ConfirmLaunch bytes and verifies the actual Stale reply.
                host.process_fixture_core_action(&inner.enrollment.editor, scenario, now)?;
                return Err(Status::Stale);
            }
            "D15PendingInputTwo"
            | "D15OrdinaryQueueSixtyFive"
            | "D15ReservedResetTwo"
            | "D15TotalQueueSixtySix" => {
                return queue_cap_attempt(host, inner, scenario, now);
            }
            "D27OrdinaryOverflowReservedReset" => {
                host.process_fixture_core_action(&inner.enrollment.editor, scenario, now)?;
                inner.record.trace.release_candidate();
                observe_carrier(host, inner, None, true)?;
                host.process_fixture_core_action(&inner.enrollment.editor, scenario, now)?;
                observe_carrier(host, inner, Some(Status::Ok), false)?;
                return Err(Status::NotReady);
            }
            // Root-owned generation counters require the reviewed finite
            // Core bridge before their carrier counterpart can be seeded.
            "D15DataOwnerThirteen" | "D15FixedOwnerSeventeen" | "D15CombinedOwnerTwentyNine" => {
                let trace = &inner.record.trace;
                let combined = scenario.id() == "D15CombinedOwnerTwentyNine";
                if combined || scenario.id() == "D15DataOwnerThirteen" {
                    while trace.owners().data < 12 {
                        plan.retained.push(
                            inner
                                .selected
                                .as_ref()
                                .ok_or(Status::Internal)?
                                .duplicate()?,
                        );
                    }
                }
                if combined || scenario.id() == "D15FixedOwnerSeventeen" {
                    while trace.owners().fixed < 16 {
                        plan.retained
                            .push(inner.socket.as_ref().ok_or(Status::Internal)?.duplicate()?);
                    }
                }
                observe_carrier(host, inner, None, true)?;
                // Duplicate performs the genuine owner's pre-native quota
                // check. Denial occurs before F_DUPFD creates another alias.
                let result = if scenario.id() == "D15DataOwnerThirteen" {
                    inner.selected.as_ref().ok_or(Status::Internal)?.duplicate()
                } else {
                    inner.socket.as_ref().ok_or(Status::Internal)?.duplicate()
                };
                return match result {
                    Err(error) => Err(error),
                    Ok(fd) => {
                        plan.retained.push(fd);
                        Err(Status::Internal)
                    }
                };
            }
            "D25ActualSendBackpressure" => {
                observe_carrier(host, inner, None, true)?;
                let socket = inner.socket.as_ref().ok_or(Status::Disconnected)?;
                // Closed same-channel fill probe, explicitly outside ordinary
                // input delivery. The stopped receiver is the actual child;
                // every accepted packet and the native EAGAIN are recorded.
                for _ in 0..1024 {
                    match linux::send(socket, &inner.bootstrap, &[]) {
                        Ok(()) => {}
                        Err(Status::NotReady) => return Err(Status::NotReady),
                        Err(status) => return Err(status),
                    }
                }
                return Err(Status::Internal);
            }
            "D05StopFdOne" | "D05ReceiptNoticeFdOne" => {
                use kernel_api::generated::desktop_editor_process_v1 as p;
                let request = inner.request.checked_add(1).ok_or(Status::Exhausted)?;
                let message = if scenario.id() == "D05StopFdOne" {
                    ProcessMessage::Stop(p::Stop {
                        request_id: request,
                        channel_generation: inner.record.channel,
                        reason: 1,
                        reserved: [0; 44],
                    })
                } else {
                    // Closed malformed transport record only. Its extra FD is
                    // rejected by the same production delivery validator;
                    // these numbers are never a genuine receipt or Core fact.
                    ProcessMessage::ReceiptNotice(p::ReceiptNotice {
                        request_id: request,
                        channel_generation: inner.record.channel,
                        capture_input_sequence: inner.acknowledged.max(1),
                        operation_id: 1,
                        committed_revision: 0,
                        capture_text_generation: inner.text_generation,
                        outcome: 1,
                        phase: 2,
                        reserved: [0; 8],
                    })
                };
                let raw = desktop_editor_core::wire::encode_frame(&message, inner.record.channel)
                    .map_err(|_| Status::Invalid)?;
                inner.record.trace.release_candidate();
                observe_carrier(host, inner, None, true)?;
                return send_control(
                    inner,
                    inner.socket.as_ref().ok_or(Status::Disconnected)?,
                    &raw,
                    &[],
                );
            }
            _ => return Ok(()),
        }
        observe_carrier(host, inner, None, true)?;
        Ok(())
    })();
    restore_plan(inner, plan)?;
    let _ = now;
    result
}
fn foreign_sender_attempt(
    host: &HostDesktop,
    inner: &mut ChildInner,
    plan: &mut Plan,
    scenario: &ProcessAssertionScenario,
    _now: u64,
) -> Result<(), Status> {
    inner.record.trace.release_candidate();
    observe_carrier(host, inner, None, true)?;
    let (creation, peer_index) =
        linux::peer_credentials(inner.socket.as_ref().ok_or(Status::Disconnected)?)?;
    if inner.gate_peer.is_none() {
        return Err(Status::NotReady);
    }
    {
        let mut roster = inner
            .enrollment
            .roster
            .lock()
            .map_err(|_| Status::Internal)?;
        roster.live.retain(|_, r| r.strong_count() > 0);
        if roster.live.len() + roster.helper_slots as usize >= 2 {
            return Err(Status::Exhausted);
        }
        roster.helper_slots += 1;
        plan.helper_slot = true;
    }
    let endpoint = inner.gate_peer.take().ok_or(Status::NotReady)?;
    let helper = match linux::start_fork_helper(endpoint, inner.bootstrap, &inner.record.trace) {
        Ok(helper) => helper,
        Err((status, endpoint)) => {
            inner.gate_peer = Some(endpoint);
            inner
                .enrollment
                .roster
                .lock()
                .map_err(|_| Status::Internal)?
                .helper_slots -= 1;
            plan.helper_slot = false;
            return Err(status);
        }
    };
    plan.helper = Some(helper);
    let mut report = loop {
        match plan.helper.as_mut().ok_or(Status::Internal)?.try_join() {
            Ok(report) => break report,
            Err(Status::NotReady) if Instant::now() < inner.deadline => std::thread::yield_now(),
            Err(status) => {
                inner.record.trace.quarantine();
                return Err(status);
            }
        }
    };
    // Only actual helper wait + Rust join + successful native C-close release
    // its admission slot. A's separate supervisor/wait owner is untouched.
    inner
        .enrollment
        .roster
        .lock()
        .map_err(|_| Status::Internal)?
        .helper_slots -= 1;
    plan.helper_slot = false;
    drop(plan.helper.take());
    let received = loop {
        if Instant::now() >= inner.deadline {
            return Err(Status::Timeout);
        }
        match linux::receive(inner.socket.as_ref().ok_or(Status::Disconnected)?) {
            Ok(packet) => break packet,
            Err(Status::NotReady) => std::thread::yield_now(),
            Err(status) => return Err(status),
        }
    };
    let helper_pid = report.process.child_pid.ok_or(Status::Internal)?;
    let approved = inner.supervisor.identity()?.pid;
    if received.credentials.0 != helper_pid
        || helper_pid == approved
        || received.credentials.1 != unsafe { libc::getuid() }
        || received.credentials.2 != unsafe { libc::getgid() }
        || received.bytes.as_slice() != inner.bootstrap.as_slice()
    {
        return Err(Status::Internal);
    }
    if scenario.id() == "D04CreationPeercredIsNotSender"
        && (creation.0 != unsafe { libc::getpid() } as u32 || creation.0 == helper_pid)
    {
        return Err(Status::Internal);
    }
    report.syscall_indices.insert(0, peer_index);
    inner
        .record
        .trace
        .save_helper(AssertionForkHelperEvidence {
            parent_case: inner.record.trace.parent_case().ok_or(Status::Invalid)?,
            scenario_id: scenario.id(),
            channel_generation: inner.record.channel,
            process: report.process,
            syscall_indices: report.syscall_indices,
            received_syscall_index: received.syscall_index,
            descriptors: vec![report.descriptor],
            creation_peer_credentials: Some(creation),
            received_credentials: received.credentials,
            endpoint_aliases_after_cleanup: 0,
            helper_slots_after_cleanup: 0,
        })?;
    // Kernel credentials, not the copied Bootstrap or creation-time peercred,
    // select the ordinary admission decision before any decoder/adoption.
    Err(Status::Denied)
}
fn queue_cap_attempt(
    host: &HostDesktop,
    inner: &mut ChildInner,
    scenario: &ProcessAssertionScenario,
    now: u64,
) -> Result<(), Status> {
    let id = scenario.id();
    if matches!(id, "D15OrdinaryQueueSixtyFive" | "D15TotalQueueSixtySix") {
        for _ in 0..64 {
            host.process_fixture_queue_produce(&inner.enrollment.editor, scenario, false, now)?;
            super::protocol::prefetch(host, inner, now)?;
        }
        if inner.input_queue.len() != 64 {
            return Err(Status::Internal);
        }
    }
    if matches!(id, "D15ReservedResetTwo" | "D15TotalQueueSixtySix") {
        host.process_fixture_queue_produce(&inner.enrollment.editor, scenario, true, now)?;
        super::protocol::prefetch(host, inner, now)?;
        if inner.reset_queue.is_none() {
            return Err(Status::Internal);
        }
    }
    if id == "D15PendingInputTwo" {
        if inner.pending.is_none() {
            return Err(Status::Internal);
        }
        host.process_fixture_queue_produce(&inner.enrollment.editor, scenario, false, now)?;
        super::protocol::prefetch(host, inner, now)?;
        if inner.input_queue.is_empty() {
            return Err(Status::Internal);
        }
    }
    inner.record.trace.release_candidate();
    observe_carrier(host, inner, None, true)?;
    if id == "D15PendingInputTwo" {
        return super::protocol::admit_pending(inner);
    }
    host.process_fixture_queue_produce(
        &inner.enrollment.editor,
        scenario,
        id == "D15ReservedResetTwo",
        now,
    )?;
    match host.process_dequeue_for_queue(
        &inner.enrollment.editor,
        now,
        inner.input_queue.len() < 64,
        inner.reset_queue.is_none(),
    ) {
        Err(status) => Err(status),
        Ok(_) => Err(Status::Internal),
    }
    // The genuine Core event stays queued when the actual parent queue has no
    // matching slot. The bridge checks those real free flags before PollKeys;
    // neither the token nor any encoded record is consumed on refusal.
}
struct Foreign {
    record: Weak<ProcessRecord>,
    trace: Trace,
    owner_pid: u32,
    offer_id: u64,
    text: Option<linux::Fd>,
    surface: Option<linux::Fd>,
    prepared_offer: Option<u64>,
}

pub(super) fn bind_pair(
    enrollment: &ProcessEditorEnrollment,
    sibling: &ChildInner,
) -> Result<(), Status> {
    let accepted = sibling.accepted.as_ref().ok_or(Status::NotReady)?;
    let id = enrollment.trace.scenario().ok_or(Status::Invalid)?.id();
    let foreign = Foreign {
        record: Arc::downgrade(&sibling.record),
        trace: sibling.record.trace.clone(),
        owner_pid: sibling.supervisor.identity()?.pid,
        offer_id: sibling.next_offer,
        text: (id == "D12ForeignChildText")
            .then(|| accepted._text.fd().duplicate())
            .transpose()?,
        surface: (id == "D12ForeignChildSurface")
            .then(|| accepted._surface.fd().duplicate())
            .transpose()?,
        prepared_offer: None,
    };
    let mut plan = enrollment.fixture.lock().map_err(|_| Status::Internal)?;
    if plan.foreign.is_some() {
        return Err(Status::Stale);
    }
    plan.foreign = Some(foreign);
    Ok(())
}
pub(super) fn bind_document(
    enrollment: &ProcessEditorEnrollment,
    sibling: &ChildInner,
) -> Result<(), Status> {
    let mut plan = enrollment.fixture.lock().map_err(|_| Status::Internal)?;
    if plan.foreign_bootstrap.is_some() {
        return Err(Status::Stale);
    }
    plan.foreign_bootstrap = Some(sibling.bootstrap);
    Ok(())
}

pub(super) fn selected_before_seal(
    host: &HostDesktop,
    enrollment: &ProcessEditorEnrollment,
    selected: &linux::Fd,
    now: u64,
) -> Result<bool, Status> {
    let Some(scenario) = enrollment.trace.scenario() else {
        return Ok(false);
    };
    let mut bytes = enrollment.seed.selected.clone();
    match scenario.id() {
        "D06SelectedHashMismatch" => {
            bytes[32] ^= 1;
        }
        "D06SelectedRevisionMismatch" => {
            bytes[16..24].copy_from_slice(&u64::MAX.to_le_bytes());
        }
        "D06SelectedObjectMismatch" => {
            bytes[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        }
        "D06SelectedInputUnsealed" => {
            enrollment.trace.object(selected.id, &bytes)?;
            return Ok(true);
        }
        "D06FocusBeforeFirstFrame" => {
            return match host.process_dequeue(&enrollment.editor, now) {
                Err(Status::NotReady) => Err(Status::NotReady),
                Err(other) => Err(other),
                Ok(_) => Err(Status::Internal),
            };
        }
        _ => return Ok(false),
    }
    selected.write_at(&bytes, 0)?;
    enrollment.trace.object(selected.id, &bytes)?;
    Ok(false)
}

// Take the fixture owner out before native I/O; this mutex is never held across
// socket, filesystem, Core, mapping, or descriptor operations.
fn take_plan(inner: &ChildInner) -> Result<Plan, Status> {
    Ok(std::mem::take(
        &mut *inner
            .enrollment
            .fixture
            .lock()
            .map_err(|_| Status::Internal)?,
    ))
}
fn restore_plan(inner: &ChildInner, plan: Plan) -> Result<(), Status> {
    *inner
        .enrollment
        .fixture
        .lock()
        .map_err(|_| Status::Internal)? = plan;
    Ok(())
}

pub(super) fn before_offer(
    host: &HostDesktop,
    inner: &mut ChildInner,
    now: u64,
) -> Result<(), Status> {
    if inner.record.trace.scenario().is_some_and(|s| {
        matches!(
            s.id(),
            "D26FrameAfterRevoke" | "D26OldGenerationCannotRevive" | "D27OldSurfaceGeneration"
        ) || s.id() == "D26CaptureAfterRevoke" && inner.offer.as_ref().is_some_and(|o| o.capture)
    }) {
        return revoked_attempt(host, inner, now);
    }
    let mut plan = take_plan(inner)?;
    let result = (|| {
        let Some(foreign) = &mut plan.foreign else {
            return Ok(());
        };
        if foreign.record.upgrade().is_none() {
            return Err(Status::Stale);
        }
        let offer = inner.offer.as_ref().ok_or(Status::NotReady)?;
        if foreign.prepared_offer == Some(offer.id) {
            return Ok(());
        }
        let accepted = inner.accepted.as_ref().ok_or(Status::NotReady)?;
        // The child must return an authentic sealed foreign inode. Own A
        // offers remain the enforcing expected identities. Even the equal-byte
        // control creates its full normal high-water offer before shrinking.
        let text = accepted._text.bytes();
        let pixels = accepted._surface.bytes();
        for (fd, bytes) in [(&offer.text, text), (&offer.surface, pixels)] {
            fd.write_at(bytes, 0)?;
            fd.truncate(bytes.len())?;
            fd.seal()?;
            inner.record.trace.object(fd.id, bytes)?;
        }
        if inner.record.trace.is("D12EqualBytesForeignInode") {
            for (slot, bytes, role) in [
                (
                    &mut foreign.text,
                    text,
                    ProcessAssertionDescriptorRole::TextState,
                ),
                (
                    &mut foreign.surface,
                    pixels,
                    ProcessAssertionDescriptorRole::Surface,
                ),
            ] {
                let fd = linux::memfd(
                    "ramen-foreign-equal",
                    bytes.len(),
                    role,
                    &foreign.trace,
                    true,
                )?;
                fd.write_at(bytes, 0)?;
                fd.seal()?;
                *slot = Some(fd);
            }
        }
        for fd in [&foreign.text, &foreign.surface].into_iter().flatten() {
            fd.project(
                &inner.record.trace,
                Some(foreign.owner_pid),
                Some(foreign.offer_id),
            )?;
        }
        foreign.prepared_offer = Some(offer.id);
        Ok(())
    })();
    restore_plan(inner, plan)?;
    result
}

pub(super) fn before_offer_credit(
    host: &HostDesktop,
    inner: &mut ChildInner,
) -> Result<(), Status> {
    let Some(scenario) = inner.record.trace.scenario() else {
        return Ok(());
    };
    if !scenario.id().starts_with("D16") || inner.record.trace.owners().lifetime_offers != 128 {
        return Ok(());
    }
    inner.record.trace.release_candidate();
    observe_carrier(host, inner, None, true)?;
    match scenario.id() {
        "D16DropDoesNotRefund" => {
            // Core retains the accepted immutable frame. Releasing these
            // actual transport owners cannot restore lifetime creation credit.
            drop(inner.accepted.take());
            return Ok(());
        }
        "D16ReseedDoesNotRefund" => {
            let selected = inner.selected.as_ref().ok_or(Status::NotReady)?;
            let mut bytes = vec![0; inner.enrollment.seed.selected.len()];
            selected.read_at(&mut bytes, 0)?;
            if bytes != inner.enrollment.seed.selected {
                return Err(Status::Invalid);
            }
            return match linux::memfd(
                "ramen-selected",
                bytes.len(),
                ProcessAssertionDescriptorRole::Selected,
                &inner.record.trace,
                true,
            ) {
                Err(status) => Err(status),
                Ok(fd) => {
                    drop(fd);
                    Err(Status::Internal)
                }
            };
        }
        "D16CounterResetDoesNotRefund" => {
            // Closed fixture changes the actual per-owner offer cursor, not
            // its independent lifetime ledger or any Core/native authority.
            inner.next_offer = 0;
            return Ok(());
        }
        "D16ExistingInodeAsNewCredit" => {}
        _ => return Ok(()),
    }
    use desktop_editor_core::wire::{self, Direction};
    use kernel_api::generated::desktop_editor_process_v1 as p;
    let accepted = inner.accepted.as_ref().ok_or(Status::NotReady)?;
    let text = accepted._text.fd().duplicate()?;
    let surface = accepted._surface.fd().duplicate()?;
    let proposed = inner.next_offer.checked_add(1).ok_or(Status::Exhausted)?;
    let frame = wire::encode_frame(
        &ProcessMessage::RequestPublication(p::RequestPublication {
            request_id: inner.request.checked_add(1).ok_or(Status::Exhausted)?,
            channel_generation: inner.record.channel,
            last_input_sequence: inner.acknowledged,
            offer_id: proposed,
            expected_text_generation: inner.text_generation,
            expected_view_generation: inner.view_generation,
            flags: 0,
            reserved: [0; 12],
        }),
        inner.record.channel,
    )
    .map_err(|_| Status::Invalid)?;
    let socket = inner.socket.as_ref().ok_or(Status::Disconnected)?;
    loop {
        if Instant::now() >= inner.deadline {
            return Err(Status::Timeout);
        }
        match linux::send(socket, &frame, &[&text, &surface]) {
            Ok(()) => break,
            Err(Status::NotReady) => std::thread::yield_now(),
            Err(status) => return Err(status),
        }
    }
    // No object, offer, byte or deadline credit was minted. These are merely
    // actual native aliases of the already accepted immutable old objects.
    drop((text, surface));
    let mut received = loop {
        if Instant::now() >= inner.deadline {
            return Err(Status::Timeout);
        }
        match linux::receive(socket) {
            Ok(packet) => break packet,
            Err(Status::NotReady) => std::thread::yield_now(),
            Err(status) => return Err(status),
        }
    };
    let identity = inner.supervisor.identity()?;
    if received.credentials
        != (identity.pid, unsafe { libc::getuid() }, unsafe {
            libc::getgid()
        })
    {
        return Err(Status::Denied);
    }
    linux::capture_received(&mut received, Some(identity.pid), Some(proposed))?;
    let (_, message) = wire::decode_frame(&received.bytes).map_err(|_| Status::Invalid)?;
    wire::validate_delivery(&message, Direction::ChildToParent, received.fds.len())
        .map_err(|_| Status::Invalid)?;
    let ProcessMessage::Publish(publish) = message else {
        return Err(Status::Invalid);
    };
    if publish.offer_id != proposed || received.fds.len() != 2 {
        return Err(Status::Invalid);
    }
    let old_text = accepted._text.fd().identity()?;
    let old_surface = accepted._surface.fd().identity()?;
    let reused = received.fds[0].identity()? == old_text
        && received.fds[1].identity()? == old_surface
        && proposed != inner.next_offer;
    drop(received);
    if reused {
        Err(Status::Denied)
    } else {
        Err(Status::Internal)
    }
}

fn revoked_attempt(host: &HostDesktop, inner: &mut ChildInner, now: u64) -> Result<(), Status> {
    use desktop_editor_core::wire::{self, Direction};
    use kernel_api::generated::desktop_editor_process_v1 as p;
    let scenario = inner.record.trace.scenario().ok_or(Status::Invalid)?;
    if scenario.id() == "D27OldSurfaceGeneration" {
        // Preserve the genuine currently-live frame and own pending pair at
        // this boundary, then retire its actual compositor epoch. No FD or
        // offer identity is substituted to manufacture a stale frame.
        inner.record.trace.release_candidate();
        observe_carrier(host, inner, None, true)?;
        inner.record.trace.hold_candidate(8)?;
    } else {
        host.process_fixture_core_action(&inner.enrollment.editor, scenario, now)?;
        host.process_retire_core(&inner.enrollment.editor, ProcessRetireReason::Revoked, now)?;
        inner.record.retire_binding()?;
        inner.record.trace.release_candidate();
        observe_carrier(host, inner, None, true)?;
    }
    let offer = inner.offer.as_ref().ok_or(Status::NotReady)?;
    let frame = wire::encode_frame(
        &ProcessMessage::RequestPublication(p::RequestPublication {
            request_id: offer.request,
            channel_generation: inner.record.channel,
            last_input_sequence: inner.acknowledged,
            offer_id: offer.id,
            expected_text_generation: inner.text_generation,
            expected_view_generation: inner.view_generation,
            flags: if offer.capture { 2 } else { 0 },
            reserved: [0; 12],
        }),
        inner.record.channel,
    )
    .map_err(|_| Status::Invalid)?;
    let socket = inner.socket.as_ref().ok_or(Status::Disconnected)?;
    loop {
        if Instant::now() >= inner.deadline {
            return Err(Status::Timeout);
        }
        match linux::send(socket, &frame, &[&offer.text, &offer.surface]) {
            Ok(()) => break,
            Err(Status::NotReady) => std::thread::yield_now(),
            Err(status) => return Err(status),
        }
    }
    let mut received = loop {
        if Instant::now() >= inner.deadline {
            return Err(Status::Timeout);
        }
        match linux::receive(socket) {
            Ok(packet) => break packet,
            Err(Status::NotReady) => std::thread::yield_now(),
            Err(status) => return Err(status),
        }
    };
    let identity = inner.supervisor.identity()?;
    if received.credentials
        != (identity.pid, unsafe { libc::getuid() }, unsafe {
            libc::getgid()
        })
    {
        return Err(Status::Denied);
    }
    linux::capture_received(&mut received, Some(identity.pid), Some(offer.id))?;
    let (channel, message) = wire::decode_frame(&received.bytes).map_err(|_| Status::Invalid)?;
    wire::validate_delivery(&message, Direction::ChildToParent, received.fds.len())
        .map_err(|_| Status::Invalid)?;
    if channel != inner.record.channel {
        return Err(Status::Stale);
    }
    let ProcessMessage::Publish(publish) = message else {
        return Err(Status::Invalid);
    };
    let (verified, accepted) = super::protocol::verify_pair(inner, &publish, received)?;
    let capturing = offer.capture;
    inner.record.trace.point(if capturing {
        ProcessAssertionPoint::CaptureBeforeAdopt
    } else {
        ProcessAssertionPoint::PairValidatedBeforeAdopt
    })?;
    if scenario.id() == "D27OldSurfaceGeneration" {
        // The same real own offered/returned pair has passed every normal
        // credential, inode, seal, size and hash check. Only now does the
        // actual compositor restart retire its genuine Core frame binding.
        host.process_fixture_core_action(&inner.enrollment.editor, scenario, now)?;
        inner.record.retire_binding_for_epoch()?;
    }
    let capture = if capturing {
        Some(inner.capture.as_ref().ok_or(Status::Denied)?)
    } else {
        None
    };
    let result = host.process_adopt_verified(&inner.enrollment.editor, &verified, capture, now);
    drop(accepted);
    match (inner.record.active_generation(), result) {
        (Err(Status::Denied), Err(Status::Denied | Status::Stale)) => Err(Status::Denied),
        (_, Err(other)) => Err(other),
        _ => Err(Status::Internal),
    }
}

pub(super) fn send_offer(
    inner: &ChildInner,
    socket: &linux::Fd,
    bytes: &[u8; 88],
) -> Result<(), Status> {
    let mut plan = take_plan(inner)?;
    let result = (|| {
        let offer = inner.offer.as_ref().ok_or(Status::NotReady)?;
        let text = plan
            .foreign
            .as_ref()
            .and_then(|f| f.text.as_ref())
            .unwrap_or(&offer.text);
        let surface = plan
            .foreign
            .as_ref()
            .and_then(|f| f.surface.as_ref())
            .unwrap_or(&offer.surface);
        send_control(inner, socket, bytes, &[text, surface])
    })();
    if result.is_ok() {
        if let Some(foreign) = &mut plan.foreign {
            // Native sendmsg owns the in-flight aliases now. Close these
            // parent aliases before B makes its next independent progress.
            foreign.text = None;
            foreign.surface = None;
        }
    }
    restore_plan(inner, plan)?;
    result
}

/// Native transport-negative controls use the exact bytes and aliases passed
/// to sendmsg. Validation afterward invokes the same structural decoder used
/// by the production receiver; it never infers a decoder outcome from EOF.
pub(super) fn send_control(
    inner: &ChildInner,
    socket: &linux::Fd,
    bytes: &[u8; 88],
    fds: &[&linux::Fd],
) -> Result<(), Status> {
    use desktop_editor_core::wire::{self, Direction};
    let Some(scenario) = inner.record.trace.scenario() else {
        return linux::send(socket, bytes, fds);
    };
    let kind = u32::from_le_bytes(bytes[4..8].try_into().map_err(|_| Status::Invalid)?);
    let mut raw = *bytes;
    if scenario.id() == "D13SurfaceFormatMismatch" && kind == 1 {
        // Surface has no wire format field. This finite control exercises
        // the actual Bootstrap geometry decoder before any first frame.
        raw[64..68].copy_from_slice(&0u32.to_le_bytes());
    }
    if scenario.id() == "D23OldBootstrapDenied" && kind == 1 {
        raw = inner
            .record
            .trace
            .old_bootstrap_bytes()
            .ok_or(Status::NotReady)?;
    }
    let mut aliases = fds.to_vec();
    let selected = || inner.selected.as_ref().ok_or(Status::Internal);
    let arity = match (scenario.id(), kind) {
        ("D05BootstrapFdZero", 1) => Some(0),
        ("D05BootstrapFdOne", 1) => Some(1),
        ("D05BootstrapFdTwo", 1) => Some(2),
        ("D05BootstrapFdFour", 1) => Some(4),
        ("D05DeliverInputFdOne", 2) => Some(1),
        ("D05RequestPublicationFdZero", 8) => Some(0),
        ("D05RequestPublicationFdOne", 8) => Some(1),
        ("D05RequestPublicationFdThree", 8) => Some(3),
        ("D05PublishAckFdOne", 6) if inner.publication > 1 => Some(1),
        ("D05StopFdOne", 4) => Some(1),
        ("D05ReceiptNoticeFdOne", 7) => Some(1),
        _ => None,
    };
    if let Some(count) = arity {
        aliases.truncate(count);
        while aliases.len() < count {
            aliases.push(selected()?);
        }
    }
    if kind == 2 {
        match scenario.id() {
            "D08UnsupportedKeyUsage"
                if u32::from_le_bytes(raw[72..76].try_into().map_err(|_| Status::Invalid)?)
                    == 1 =>
            {
                raw[68..72].copy_from_slice(&0u32.to_le_bytes())
            }
            "D08InvalidKeyPhase" => raw[72..76].copy_from_slice(&4u32.to_le_bytes()),
            "D08ContradictoryModifiers" => raw[76..80].copy_from_slice(&4u32.to_le_bytes()),
            _ => {}
        }
    }
    linux::send(socket, &raw, &aliases)?;
    let (_, message) = wire::decode_frame(&raw).map_err(|_| Status::Invalid)?;
    wire::validate_delivery(&message, Direction::ParentToChild, aliases.len())
        .map_err(|_| Status::Invalid)?;
    if let ProcessMessage::DeliverInput(input) = &message {
        // Protocol validation only: this never applies a key, edits a draft,
        // rasterizes pixels or derives capture authority in the parent.
        if input.phase == 1
            && input.flags == 0
            && !matches!(input.usage,4..=49 | 51..=56 | 74 | 77 | 79..=82 | 224 | 225)
        {
            return Err(Status::Invalid);
        }
    }
    Ok(())
}

pub(super) fn before_send(
    host: &HostDesktop,
    inner: &mut ChildInner,
    bytes: &[u8; 88],
    now: u64,
) -> Result<(), Status> {
    let kind = u32::from_le_bytes(bytes[4..8].try_into().map_err(|_| Status::Invalid)?);
    if matches!(kind, 1 | 2 | 8) && inner.record.trace.candidate_kind() != Some(kind) {
        inner.record.trace.release_candidate();
        observe_carrier(host, inner, None, true)?;
        inner.record.trace.hold_candidate(kind)?;
    } else if inner.record.trace.is("D05PublishAckFdOne") && inner.publication > 1 && kind == 6 {
        // This valid publication was already adopted before its ACK. The
        // transport fault must preserve that actual preceding state/frame.
        inner.record.trace.release_candidate();
        observe_carrier(host, inner, None, true)?;
        inner.record.trace.hold_candidate(kind)?;
    }
    let Some(scenario) = inner.record.trace.scenario() else {
        return Ok(());
    };
    let phase = u32::from_le_bytes(bytes[72..76].try_into().map_err(|_| Status::Invalid)?);
    let flags = u32::from_le_bytes(bytes[68..72].try_into().map_err(|_| Status::Invalid)?);
    let selected = match scenario.id() {
        "D14OldFocusEpoch" | "D14OldServiceEpoch" => kind == 2,
        "D27OldKeyPressRelease" => kind == 2 && matches!(phase, 1 | 2),
        "D27OldResetServiceEpoch" => kind == 2 && phase == 3,
        "D27StaleResetCapture" => kind == 8 && flags == 2,
        _ => false,
    };
    if selected {
        let mut plan = take_plan(inner)?;
        let performed = !plan.core_action_done;
        plan.core_action_done = true;
        restore_plan(inner, plan)?;
        if performed {
            host.process_fixture_core_action(&inner.enrollment.editor, scenario, now)?;
            inner.record.retire_binding_for_epoch()?;
            inner.record.trace.release_candidate();
            observe_carrier(host, inner, None, true)?;
            inner.record.trace.hold_candidate(kind)?;
            if Instant::now() >= inner.deadline {
                return Err(Status::Timeout);
            }
        }
    }
    Ok(())
}

pub(super) fn decision_complete(host: &HostDesktop, inner: &mut ChildInner) -> Result<(), Status> {
    let kind = inner.record.trace.release_candidate();
    if (inner.record.trace.is("D18OrdinaryPublishSaveClaim")
        || inner.record.trace.is("D12ExactPendingOfferedPair")
        || (inner.record.trace.is("D10ChildSavedImitationClipped") && inner.publication == 3))
        && kind == Some(8)
    {
        // D10's first ordinary pair establishes genuine Unsaved chrome;
        // the second contains the actual child Saved imitation. Preserve
        // its RequestPublication-to-adoption interval before cleanup can
        // replace the before snapshot with the already accepted frame.
        observe_carrier(host, inner, Some(Status::Ok), false)?;
    }
    Ok(())
}

pub(super) fn after_authenticated_receive(
    inner: &ChildInner,
    received: &mut linux::Received,
) -> Result<(), Status> {
    let Some(scenario) = inner.record.trace.scenario() else {
        return Ok(());
    };
    if scenario.id().starts_with("D11") && !inner.ready {
        return Ok(());
    }
    if received.bytes.len() != 88
        || u32::from_le_bytes(
            received.bytes[4..8]
                .try_into()
                .map_err(|_| Status::Invalid)?,
        ) != 5
    {
        return Ok(());
    }
    let Some(fd) = received.fds.first() else {
        return Ok(());
    };
    match scenario.id() {
        "D11RetainedWritableMapping" | "D11MprotectOnly" => {
            let mapping = linux::child_mapping(inner.supervisor.identity()?.pid, fd)?;
            let expected = if scenario.id() == "D11MprotectOnly" {
                ProcessAssertionMapping::ReadOnly
            } else {
                ProcessAssertionMapping::SharedWritable
            };
            if mapping != expected {
                return Err(Status::Internal);
            }
            inner.record.trace.disposition(
                fd.id,
                ProcessAssertionDisposition::Received,
                Some(mapping),
            );
            // This actual F_ADD_SEALS executes while the child still owns the
            // returned shared mapping, before any terminal ACK can stop it.
            if fd.seal().is_ok() {
                return Err(Status::Internal);
            }
        }
        "D11WriteAfterSeal" => {
            if !inner.ready {
                return Ok(());
            }
            return match fd.write_at(&[0x5a], 0) {
                Err(status) => Err(status),
                Ok(()) => Err(Status::Internal),
            };
        }
        "D11GrowAfterSeal" | "D11ShrinkAfterSeal" => {
            if !inner.ready {
                return Ok(());
            }
            let size = fd.stat()?.st_size as usize;
            return match fd.truncate(if scenario.id() == "D11GrowAfterSeal" {
                size + 1
            } else {
                size - 1
            }) {
                Err(status) => Err(status),
                Ok(()) => Err(Status::Internal),
            };
        }
        _ => {}
    }
    Ok(())
}
