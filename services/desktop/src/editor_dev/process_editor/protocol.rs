//! Parent-owned nonblocking protocol. The Core bridge alone admits document
//! changes and captures; peer fields and mapped bytes carry no authority.
use super::*;
use desktop_editor_core::{
    FRAME_BYTES,
    process_data::TextState,
    wire::{self, Direction},
};
use kernel_api::generated::desktop_editor_process_v1 as p;

const SEALS: i32 = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
fn checked(value: u64) -> Result<u64, Status> {
    value.checked_add(1).ok_or(Status::Exhausted)
}
fn require(value: bool, status: Status) -> Result<(), Status> {
    if value { Ok(()) } else { Err(status) }
}
fn step() -> ProcessEditorStep {
    ProcessEditorStep {
        consumed: None,
        publication: false,
        intent: false,
        exited: false,
    }
}
fn encode(inner: &ChildInner, message: ProcessMessage) -> Result<[u8; 88], Status> {
    super::validate_bootstrap_binding(&message, &inner.enrollment)?;
    wire::encode_frame(&message, inner.record.channel).map_err(|_| Status::Invalid)
}

/// Capacity is checked before moving the genuine Core-issued input. A closed
/// fixture can retain a refused token; no caller data reconstructs that token.
pub(super) fn enqueue(
    inner: &mut ChildInner,
    input: &mut Option<DeliveredProcessInput>,
) -> Result<(), Status> {
    let value = input.as_ref().ok_or(Status::Invalid)?;
    if value.phase == 3 {
        require(inner.reset_queue.is_none(), Status::Exhausted)?;
        inner.reset_queue = input.take();
    } else {
        require(inner.input_queue.len() < 64, Status::Exhausted)?;
        inner
            .input_queue
            .push_back(input.take().ok_or(Status::Internal)?);
    }
    Ok(())
}

/// Prefetch only bounded, genuine Focus deliveries. Capture authority remains
/// on its original token/Instant and stops later dequeue until its own pair.
pub(super) fn prefetch(host: &HostDesktop, inner: &mut ChildInner, now: u64) -> Result<(), Status> {
    enforce_deadline(inner)?;
    host.process_validate(&inner.enrollment.editor, now)?;
    if !inner.ready
        || inner.retiring
        || inner.pending.as_ref().is_some_and(|i| i.capture.is_some())
        || inner.input_queue.iter().any(|i| i.capture.is_some())
        || inner
            .reset_queue
            .as_ref()
            .is_some_and(|i| i.capture.is_some())
        || inner.offer.as_ref().is_some_and(|o| o.capture)
        || inner.requested_flush == Some(true)
    {
        return Ok(());
    }
    checked(inner.text_generation)?;
    checked(inner.view_generation)?;
    for _ in 0..65 {
        let ordinary_free = inner.input_queue.len() < 64;
        let reset_free = inner.reset_queue.is_none();
        if !ordinary_free && !reset_free {
            break;
        }
        let mut input = match host.process_dequeue_for_queue(
            &inner.enrollment.editor,
            now,
            ordinary_free,
            reset_free,
        ) {
            Ok(input) => input,
            // The genuine Core front may need the locally full class. Leave
            // it there and progress the already owned FIFO; this is no new
            // admission. A refusal with both classes free remains an error.
            Err(Status::Exhausted) if !ordinary_free || !reset_free => break,
            Err(status) => return Err(status),
        };
        let Some(value) = input.as_ref() else {
            break;
        };
        let capturing = value.capture.is_some();
        enqueue(inner, &mut input)?;
        if capturing {
            break;
        }
    }
    Ok(())
}

fn pop_input(inner: &mut ChildInner) -> Option<DeliveredProcessInput> {
    let ordinary = inner.input_queue.front().map(|i| i.sequence);
    let reset = inner.reset_queue.as_ref().map(|i| i.sequence);
    if reset.is_some_and(|r| ordinary.is_none_or(|o| r < o)) {
        inner.reset_queue.take()
    } else {
        inner.input_queue.pop_front()
    }
}

pub(super) fn admit_pending(inner: &mut ChildInner) -> Result<(), Status> {
    require(
        inner.pending.is_none() && inner.pending_request.is_none(),
        Status::Exhausted,
    )?;
    inner.pending = pop_input(inner);
    Ok(())
}

fn allocate_offer(inner: &mut ChildInner, request: u64, capture: bool) -> Result<(), Status> {
    require(inner.offer.is_none(), Status::NotReady)?;
    let id = checked(inner.next_offer)?;
    inner.record.trace.offer()?;
    let text = linux::memfd(
        "ramen-editor-state",
        4224,
        ProcessAssertionDescriptorRole::TextState,
        &inner.record.trace,
        true,
    )?;
    let surface = linux::memfd(
        "ramen-editor-surface",
        FRAME_BYTES,
        ProcessAssertionDescriptorRole::Surface,
        &inner.record.trace,
        true,
    )?;
    let pid = inner.supervisor.identity()?.pid;
    for fd in [&text, &surface] {
        fd.mark(
            Some(pid),
            Some(id),
            ProcessAssertionDescriptorEvent::Offered,
            ProcessAssertionDisposition::Held,
        )?;
    }
    inner.offer = Some(OfferedPair {
        id,
        request,
        text,
        surface,
        capture,
    });
    inner.next_offer = id;
    Ok(())
}
fn queue_offer(
    host: &HostDesktop,
    inner: &mut ChildInner,
    now: u64,
    capture: bool,
) -> Result<(), Status> {
    enforce_deadline(inner)?;
    host.process_validate(&inner.enrollment.editor, now)?;
    require(
        inner.pending.is_none() && inner.outbound.is_none() && inner.ready,
        Status::NotReady,
    )?;
    if capture {
        let c = inner.capture.as_ref().ok_or(Status::Denied)?;
        require(Instant::now() < c.deadline, Status::Timeout)?;
    }
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    fixtures::before_offer_credit(host, inner)?;
    let request = checked(inner.request)?;
    checked(inner.publication)?;
    checked(inner.wire_publication)?;
    checked(inner.text_generation)?;
    checked(inner.view_generation)?;
    allocate_offer(inner, request, capture)?;
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    super::fixtures::before_offer(host, inner, now)?;
    let offer = inner.offer.as_ref().ok_or(Status::Internal)?;
    let bytes = encode(
        inner,
        ProcessMessage::RequestPublication(p::RequestPublication {
            request_id: request,
            channel_generation: inner.record.channel,
            last_input_sequence: inner.acknowledged,
            offer_id: offer.id,
            expected_text_generation: inner.text_generation,
            expected_view_generation: inner.view_generation,
            flags: if capture { 2 } else { 0 },
            reserved: [0; 12],
        }),
    )?;
    inner.request = request;
    inner.outbound = Some(OutboundFrame {
        bytes,
        kind: OutboundKind::Offer,
    });
    Ok(())
}

// EAGAIN retains the original frame and all actual source aliases. No counter,
// capture Instant, offered object or deadline is recreated for a retry.
fn flush(host: &HostDesktop, inner: &mut ChildInner, now: u64) -> Result<bool, Status> {
    let Some(frame) = inner.outbound.take() else {
        return Ok(true);
    };
    enforce_deadline(inner)?;
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    fixtures::before_send(host, inner, &frame.bytes, now)?;
    let socket = inner.socket.as_ref().ok_or(Status::Disconnected)?;
    let send = match frame.kind {
        OutboundKind::None => {
            #[cfg(feature = "host_editor_process_assertions_v0_dev")]
            {
                fixtures::send_control(inner, socket, &frame.bytes, &[])
            }
            #[cfg(not(feature = "host_editor_process_assertions_v0_dev"))]
            {
                linux::send(socket, &frame.bytes, &[])
            }
        }
        OutboundKind::Bootstrap => {
            let offer = inner.offer.as_ref().ok_or(Status::Internal)?;
            let fds = [
                inner.selected.as_ref().ok_or(Status::Internal)?,
                &offer.text,
                &offer.surface,
            ];
            #[cfg(feature = "host_editor_process_assertions_v0_dev")]
            {
                fixtures::send_control(inner, socket, &frame.bytes, &fds)
            }
            #[cfg(not(feature = "host_editor_process_assertions_v0_dev"))]
            {
                linux::send(socket, &frame.bytes, &fds)
            }
        }
        OutboundKind::Offer => {
            #[cfg(feature = "host_editor_process_assertions_v0_dev")]
            {
                super::fixtures::send_offer(inner, socket, &frame.bytes)
            }
            #[cfg(not(feature = "host_editor_process_assertions_v0_dev"))]
            {
                let offer = inner.offer.as_ref().ok_or(Status::Internal)?;
                linux::send(socket, &frame.bytes, &[&offer.text, &offer.surface])
            }
        }
    };
    match send {
        Err(Status::NotReady) => {
            inner.outbound = Some(frame);
            return Ok(false);
        }
        Err(status) => {
            inner.outbound = Some(frame);
            return Err(status);
        }
        Ok(()) => {}
    }
    // A terminal obsolete ordinary pair spends its old credit. Only after the
    // real Stale ACK is sent may a fresh pair be issued for the same ACK tuple.
    if let Ok((_, ProcessMessage::PublishAck(ack))) = wire::decode_frame(&frame.bytes) {
        if ack.status == Status::Stale as u32
            && !inner.retiring
            && inner.offer.is_none()
            && inner.requested_flush == Some(false)
        {
            queue_offer(host, inner, now, false)?;
            inner.requested_flush = None;
        }
    }
    if inner.outbound.is_none() {
        if let Some(ack) = inner.deferred_ack.take() {
            install_ack(inner, ack)?;
        }
    }
    Ok(true)
}
fn drain_outbound(host: &HostDesktop, inner: &mut ChildInner, now: u64) -> Result<bool, Status> {
    for _ in 0..3 {
        if inner.outbound.is_none() {
            return Ok(true);
        }
        if !flush(host, inner, now)? {
            return Ok(false);
        }
    }
    Ok(inner.outbound.is_none())
}
pub(super) fn bootstrap(
    host: &HostDesktop,
    inner: &mut ChildInner,
    now: u64,
) -> Result<(), Status> {
    enforce_deadline(inner)?;
    host.process_validate(&inner.enrollment.editor, now)?;
    require(inner.request == 0 && inner.next_offer == 0, Status::Stale)?;
    allocate_offer(inner, 1, false)?;
    let seed = &inner.enrollment.seed;
    let bytes = encode(
        inner,
        ProcessMessage::Bootstrap(p::Bootstrap {
            request_id: 1,
            channel_generation: inner.record.channel,
            document_binding_id: seed.view.document_id,
            offer_id: 1,
            selected_text_len: seed.selected.len() as u32,
            width: 640,
            height: 480,
            stride: 2560,
            reserved: [0; 16],
        }),
    )?;
    inner.request = 1;
    inner.bootstrap = bytes;
    inner.outbound = Some(OutboundFrame {
        bytes,
        kind: OutboundKind::Bootstrap,
    });
    inner
        .record
        .trace
        .point(ProcessAssertionPoint::BootstrapBeforeSend)?;
    let _sent = drain_outbound(host, inner, now)?;
    Ok(())
}

fn queue_receipt(host: &HostDesktop, inner: &mut ChildInner, now: u64) -> Result<(), Status> {
    if !inner.ready
        || inner.pending_request.is_some()
        || inner.outbound.is_some()
        || inner.offer.as_ref().is_some_and(|o| o.capture)
    {
        return Ok(());
    }
    let Some(notice) = host.process_receipt_notice(&inner.enrollment.editor, now)? else {
        return Ok(());
    };
    if inner.receipt.as_ref().is_some_and(|(op, revision, _)| {
        *op == notice.operation_id && *revision == notice.committed_revision
    }) {
        return Ok(());
    }
    let capture = inner.capture.as_ref().ok_or(Status::Denied)?;
    require(
        capture.input_sequence == notice.capture_input_sequence
            && inner.captured_text_generation == Some(notice.capture_text_generation)
            && notice.operation_id > 0,
        Status::Denied,
    )?;
    let request = checked(inner.request)?;
    let bytes = encode(
        inner,
        ProcessMessage::ReceiptNotice(p::ReceiptNotice {
            request_id: request,
            channel_generation: inner.record.channel,
            capture_input_sequence: notice.capture_input_sequence,
            operation_id: notice.operation_id,
            committed_revision: notice.committed_revision,
            capture_text_generation: notice.capture_text_generation,
            outcome: notice.outcome,
            phase: notice.phase,
            reserved: [0; 8],
        }),
    )?;
    let current = host.process_validate(&inner.enrollment.editor, now)?;
    inner.receipt = Some((
        notice.operation_id,
        notice.committed_revision,
        current.confirmed_hash,
    ));
    inner.request = request;
    inner.outbound = Some(OutboundFrame {
        bytes,
        kind: OutboundKind::None,
    });
    Ok(())
}
fn service_flush(host: &HostDesktop, inner: &mut ChildInner, now: u64) -> Result<bool, Status> {
    let Some(capturing) = inner.requested_flush else {
        return Ok(true);
    };
    require(
        inner.pending.is_none() && inner.offer.is_none(),
        Status::NotReady,
    )?;
    queue_receipt(host, inner, now)?;
    if !drain_outbound(host, inner, now)? {
        return Ok(false);
    }
    queue_offer(host, inner, now, capturing)?;
    inner.requested_flush = None;
    drain_outbound(host, inner, now)
}
/// The finite retirement fixture sends through the same ordinary offer path.
/// An EAGAIN retry drains the existing outbound record and retains its pair;
/// it cannot allocate another offer or renew the original child deadline.
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
pub(super) fn queue_assertion_publication(
    host: &HostDesktop,
    inner: &mut ChildInner,
    now: u64,
) -> Result<(), Status> {
    require(inner.ready && !inner.retiring, Status::NotReady)?;
    if inner.offer.is_none() {
        queue_offer(host, inner, now, false)?;
    }
    require(
        inner.offer.as_ref().is_some_and(|offer| !offer.capture) && inner.pending.is_none(),
        Status::NotReady,
    )?;
    if drain_outbound(host, inner, now)? {
        Ok(())
    } else {
        Err(Status::NotReady)
    }
}

fn receive_ack(
    host: &HostDesktop,
    inner: &mut ChildInner,
    ack: p::InputAck,
    now: u64,
) -> Result<ProcessEditorStep, Status> {
    let input = inner.pending.as_ref().ok_or(Status::Stale)?;
    require(Some(ack.request_id) == inner.pending_request, Status::Stale)?;
    if ack.status != 0 {
        return Err(status_code(ack.status)?);
    }
    require(
        ack.channel_generation == inner.record.channel && ack.input_sequence == input.sequence,
        Status::Stale,
    )?;
    for (previous, next) in [
        (inner.text_generation, ack.text_generation),
        (inner.view_generation, ack.view_generation),
    ] {
        require(
            next == previous || previous.checked_add(1) == Some(next),
            Status::Invalid,
        )?;
    }
    require(
        ack.text_generation == inner.text_generation
            || ack.view_generation != inner.view_generation,
        Status::Invalid,
    )?;
    if ack.flags == 0 {
        require(
            ack.text_generation == inner.text_generation
                && ack.view_generation == inner.view_generation,
            Status::Invalid,
        )?;
    }
    host.process_acknowledge(
        &inner.enrollment.editor,
        input,
        ack.text_generation,
        ack.view_generation,
        now,
    )?;
    let mut input = inner.pending.take().ok_or(Status::Internal)?;
    inner.pending_request = None;
    inner.acknowledged = input.sequence;
    inner.text_generation = ack.text_generation;
    inner.view_generation = ack.view_generation;
    inner.delivered_since_flush = inner
        .delivered_since_flush
        .checked_add(1)
        .ok_or(Status::Exhausted)?;
    if input.phase == 1 {
        inner.downs_since_flush = inner
            .downs_since_flush
            .checked_add(1)
            .ok_or(Status::Exhausted)?;
    }
    let capturing = input.capture.is_some();
    if let Some(capture) = input.capture.take() {
        inner.capture = Some(capture);
    }
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    inner.record.trace.release_candidate();
    if capturing || inner.delivered_since_flush >= 128 || inner.downs_since_flush >= 64 {
        inner.requested_flush = Some(capturing);
        let _sent = service_flush(host, inner, now)?;
    }
    let mut result = step();
    result.consumed = Some(input.sequence);
    Ok(result)
}
fn status_code(code: u32) -> Result<Status, Status> {
    Ok(match code {
        0 => Status::Ok,
        1 => Status::Denied,
        2 => Status::Invalid,
        3 => Status::Unsupported,
        4 => Status::Stale,
        5 => Status::Exhausted,
        6 => Status::NotReady,
        7 => Status::Conflict,
        8 => Status::Timeout,
        9 => Status::Disconnected,
        10 => Status::Unknown,
        11 => Status::Internal,
        _ => return Err(Status::Invalid),
    })
}

pub(super) fn verify_pair(
    inner: &ChildInner,
    publish: &p::Publish,
    mut received: linux::Received,
) -> Result<(VerifiedProcessPublication, AcceptedPair), Status> {
    let offer = inner.offer.as_ref().ok_or(Status::Stale)?;
    require(
        publish.request_id == offer.request
            && publish.channel_generation == inner.record.channel
            && publish.input_sequence == inner.acknowledged
            && publish.publication_sequence == checked(inner.wire_publication)?
            && publish.offer_id == offer.id,
        Status::Stale,
    )?;
    require(
        inner.pending.is_none()
            && publish.text_generation == inner.text_generation
            && publish.view_generation == inner.view_generation,
        Status::Invalid,
    )?;
    require(received.fds.len() == 2, Status::Invalid)?;
    let mut surface = received.fds.pop().ok_or(Status::Invalid)?;
    let mut text = received.fds.pop().ok_or(Status::Invalid)?;
    text.role = ProcessAssertionDescriptorRole::TextState;
    surface.role = ProcessAssertionDescriptorRole::Surface;
    let pid = inner.supervisor.identity()?.pid;
    for fd in [&text, &surface] {
        fd.mark(
            Some(pid),
            Some(offer.id),
            ProcessAssertionDescriptorEvent::Returned,
            ProcessAssertionDisposition::Received,
        )?;
    }
    require(
        text.identity()? == offer.text.identity()?
            && surface.identity()? == offer.surface.identity()?,
        Status::Denied,
    )?;
    require(text.identity()? != surface.identity()?, Status::Denied)?;
    for (fd, size) in [
        (&text, publish.text_state_len as usize),
        (&surface, publish.surface_len as usize),
    ] {
        let stat = fd.stat()?;
        require(
            stat.st_mode & libc::S_IFMT == libc::S_IFREG
                && stat.st_size == size as i64
                && fd.seals()? & SEALS == SEALS,
            Status::Invalid,
        )?;
    }
    require(
        (128..=4224).contains(&publish.text_state_len) && publish.surface_len == FRAME_BYTES as u32,
        Status::Invalid,
    )?;
    let text = linux::map_read_only(text, publish.text_state_len as usize)?;
    let surface = linux::map_read_only(surface, FRAME_BYTES)?;
    inner.record.trace.object(text.fd().id, text.bytes())?;
    inner
        .record
        .trace
        .object(surface.fd().id, surface.bytes())?;
    let (state, body) = TextState::decode(text.bytes()).map_err(|_| Status::Invalid)?;
    state
        .validate_surface(surface.bytes())
        .map_err(|_| Status::Invalid)?;
    require(
        state.text_generation == publish.text_generation
            && state.view_generation == publish.view_generation,
        Status::Invalid,
    )?;
    // Immutable seals prevent content/size changes; repeat held identity and
    // seal checks immediately before handing the verified bytes to Core.
    require(
        text.fd().identity()? == offer.text.identity()?
            && surface.fd().identity()? == offer.surface.identity()?,
        Status::Denied,
    )?;
    for fd in [text.fd(), surface.fd()] {
        require(fd.seals()? & SEALS == SEALS, Status::Invalid)?;
    }
    let verified = VerifiedProcessPublication {
        state,
        body: body.to_vec(),
        pixels: surface.bytes().to_vec(),
        input_sequence: publish.input_sequence,
        publication_sequence: publish.publication_sequence,
        child_deadline: inner.deadline,
    };
    Ok((
        verified,
        AcceptedPair {
            _text: text,
            _surface: surface,
        },
    ))
}
fn install_ack(inner: &mut ChildInner, ack: DeferredAcknowledgment) -> Result<(), Status> {
    require(inner.outbound.is_none(), Status::NotReady)?;
    let success = ack.status == Status::Ok;
    let bytes = encode(
        inner,
        ProcessMessage::PublishAck(p::PublishAck {
            request_id: ack.request_id,
            channel_generation: if success { inner.record.channel } else { 0 },
            publication_sequence: if success { ack.publication_sequence } else { 0 },
            input_sequence: if success { ack.input_sequence } else { 0 },
            status: ack.status as u32,
            reserved: [0; 28],
        }),
    )?;
    inner.outbound = Some(OutboundFrame {
        bytes,
        kind: OutboundKind::None,
    });
    Ok(())
}
fn queue_publish_ack(
    inner: &mut ChildInner,
    publish: &p::Publish,
    status: Status,
) -> Result<(), Status> {
    let ack = DeferredAcknowledgment {
        request_id: publish.request_id,
        publication_sequence: publish.publication_sequence,
        input_sequence: publish.input_sequence,
        status,
    };
    if inner.outbound.is_some() {
        require(inner.deferred_ack.is_none(), Status::NotReady)?;
        inner.deferred_ack = Some(ack);
        Ok(())
    } else {
        install_ack(inner, ack)
    }
}
enum PublicationResult {
    Accepted(ProcessEditorStep),
    Obsolete,
}
fn receive_publication(
    host: &HostDesktop,
    inner: &mut ChildInner,
    publish: p::Publish,
    received: linux::Received,
    now: u64,
) -> Result<PublicationResult, Status> {
    let (verified, accepted) = verify_pair(inner, &publish, received)?;
    let capturing = inner.offer.as_ref().ok_or(Status::Stale)?.capture;
    if inner.ready
        && !capturing
        && inner.receipt.is_none()
        && inner
            .captured_text_generation
            .is_some_and(|old| old != inner.text_generation)
    {
        inner
            .record
            .trace
            .point(ProcessAssertionPoint::PairValidatedBeforeAdopt)?;
    }
    if capturing {
        inner
            .record
            .trace
            .point(ProcessAssertionPoint::CaptureBeforeAdopt)?;
    }
    enforce_deadline(inner)?;
    let capture = if capturing {
        Some(inner.capture.as_ref().ok_or(Status::Denied)?)
    } else {
        None
    };
    let accepted_generation = checked(inner.publication)?;
    let admitted = host.process_adopt_verified(&inner.enrollment.editor, &verified, capture, now);
    match admitted {
        Ok(intent) => {
            if capturing {
                inner.captured_text_generation = Some(verified.state.text_generation);
            }
            inner.accepted = Some(accepted);
            inner.offer = None;
            inner.publication = accepted_generation;
            inner.wire_publication = publish.publication_sequence;
            inner.ready = true;
            inner.delivered_since_flush = 0;
            inner.downs_since_flush = 0;
            queue_publish_ack(inner, &publish, Status::Ok)?;
            let _sent = drain_outbound(host, inner, now)?;
            #[cfg(feature = "host_editor_process_assertions_v0_dev")]
            fixtures::decision_complete(host, inner)?;
            inner.record.trace.note_status(Status::Ok);
            let mut result = step();
            result.publication = true;
            result.intent = intent;
            Ok(PublicationResult::Accepted(result))
        }
        Err(Status::Stale)
            if !capturing
                && verified.state.header.revision
                    < host
                        .process_validate(&inner.enrollment.editor, now)?
                        .confirmed_revision =>
        {
            // The original may settle while PairValidatedBeforeAdopt is held.
            // Fetch its genuine Core notice now, preserving its delivery order.
            queue_receipt(host, inner, now)?;
            require(inner.receipt.is_some(), Status::Stale)?;
            drop(accepted);
            inner.offer = None;
            inner.wire_publication = publish.publication_sequence;
            observe_carrier(host, inner, Some(Status::Stale), false)?;
            inner.requested_flush = Some(false);
            queue_publish_ack(inner, &publish, Status::Stale)?;
            let _sent = drain_outbound(host, inner, now)?;
            Ok(PublicationResult::Obsolete)
        }
        Err(status) => Err(status),
    }
}
fn retire_failure(host: &HostDesktop, inner: &mut ChildInner, status: Status, now: u64) {
    let _ = observe_carrier(host, inner, Some(status), false);
    let reason = if status == Status::Timeout {
        ProcessRetireReason::Deadline
    } else {
        ProcessRetireReason::InvalidTransport
    };
    inner.retiring = true;
    let _ = host.process_retire_core(&inner.enrollment.editor, reason, now);
    inner.supervisor.request_retire(reason);
}

impl HostDesktop {
    pub fn pump_process_editor(
        &self,
        child: &mut OwnedEditorChild,
        now: u64,
    ) -> Result<ProcessEditorStep, ProcessStepFailure> {
        let inner = inner_mut(self, child)?;
        let result = pump(self, inner, now);
        match result {
            Ok(PublicationResult::Accepted(step)) => Ok(step),
            Ok(PublicationResult::Obsolete) => Err(Status::Stale.into()),
            Err(status) => {
                retire_failure(self, inner, status, now);
                Err(status.into())
            }
        }
    }
    pub fn request_process_editor_frame(
        &self,
        child: &mut OwnedEditorChild,
        now: u64,
    ) -> Result<(), ProcessStepFailure> {
        let inner = inner_mut(self, child)?;
        let result = (|| {
            #[cfg(feature = "host_editor_process_assertions_v0_dev")]
            fixtures::before_operation(self, inner, now)?;
            require(!inner.retiring, Status::Denied)?;
            require(inner.requested_flush.is_none(), Status::NotReady)?;
            queue_receipt(self, inner, now)?;
            if !drain_outbound(self, inner, now)? {
                return Err(Status::NotReady);
            }
            queue_offer(self, inner, now, false)?;
            let _sent = drain_outbound(self, inner, now)?;
            Ok(())
        })();
        if let Err(status) = result {
            if status != Status::NotReady {
                retire_failure(self, inner, status, now);
            }
            return Err(status.into());
        }
        Ok(())
    }
}
fn send_pending(host: &HostDesktop, inner: &mut ChildInner, now: u64) -> Result<(), Status> {
    if inner.pending_request.is_some() || inner.outbound.is_some() {
        return Ok(());
    }
    let Some(input) = inner.pending.as_ref() else {
        return Ok(());
    };
    enforce_deadline(inner)?;
    host.process_validate(&inner.enrollment.editor, now)?;
    if let Some(capture) = input.capture.as_ref() {
        require(Instant::now() < capture.deadline, Status::Timeout)?;
    }
    let request = checked(inner.request)?;
    checked(inner.publication)?;
    checked(inner.wire_publication)?;
    checked(inner.text_generation)?;
    checked(inner.view_generation)?;
    let flags = if input.capture.is_some() {
        2
    } else if input.phase == 3 {
        1
    } else {
        0
    };
    let bytes = encode(
        inner,
        ProcessMessage::DeliverInput(p::DeliverInput {
            request_id: request,
            channel_generation: inner.record.channel,
            input_sequence: input.sequence,
            focus_epoch: input.focus_epoch,
            focus_service_epoch: input.service_epoch,
            offer_id: 0,
            usage: input.usage,
            phase: input.phase,
            modifiers: input.modifiers,
            flags,
        }),
    )?;
    inner.request = request;
    inner.pending_request = Some(request);
    inner.outbound = Some(OutboundFrame {
        bytes,
        kind: OutboundKind::None,
    });
    let _sent = drain_outbound(host, inner, now)?;
    Ok(())
}
fn pump(host: &HostDesktop, inner: &mut ChildInner, now: u64) -> Result<PublicationResult, Status> {
    if inner.supervisor.terminal() {
        let mut ended = step();
        ended.exited = true;
        return Ok(PublicationResult::Accepted(ended));
    }
    if inner.retiring {
        return Ok(PublicationResult::Obsolete);
    }
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    fixtures::before_operation(host, inner, now)?;
    enforce_deadline(inner)?;
    host.process_validate(&inner.enrollment.editor, now)?;
    if !drain_outbound(host, inner, now)? {
        return Ok(PublicationResult::Accepted(step()));
    }
    queue_receipt(host, inner, now)?;
    if !drain_outbound(host, inner, now)? {
        return Ok(PublicationResult::Accepted(step()));
    }
    if !service_flush(host, inner, now)? {
        return Ok(PublicationResult::Accepted(step()));
    }
    prefetch(host, inner, now)?;
    if inner.pending.is_some() && inner.pending_request.is_none() {
        send_pending(host, inner, now)?;
        if inner.outbound.is_some() {
            return Ok(PublicationResult::Accepted(step()));
        }
    }
    observe_carrier(host, inner, None, true)?;
    match linux::receive(inner.socket.as_ref().ok_or(Status::Disconnected)?) {
        Ok(received) => {
            #[cfg(feature = "host_editor_process_assertions_v0_dev")]
            let mut received = received;
            let identity = inner.supervisor.identity()?;
            require(
                received.credentials
                    == (identity.pid, unsafe { libc::getuid() }, unsafe {
                        libc::getgid()
                    }),
                Status::Denied,
            )?;
            #[cfg(feature = "host_editor_process_assertions_v0_dev")]
            linux::capture_received(
                &mut received,
                Some(identity.pid),
                inner.offer.as_ref().map(|o| o.id),
            )?;
            #[cfg(feature = "host_editor_process_assertions_v0_dev")]
            fixtures::after_authenticated_receive(inner, &mut received)?;
            let (handle, message) =
                wire::decode_frame(&received.bytes).map_err(|_| Status::Invalid)?;
            require(handle == inner.record.channel, Status::Stale)?;
            wire::validate_delivery(&message, Direction::ChildToParent, received.fds.len())
                .map_err(|_| Status::Invalid)?;
            return match message {
                ProcessMessage::InputAck(ack) => Ok(PublicationResult::Accepted(receive_ack(
                    host, inner, ack, now,
                )?)),
                ProcessMessage::Publish(publish) => {
                    let result = receive_publication(host, inner, publish, received, now);
                    if let Err(status) = &result {
                        // A known publication receives only the canonical
                        // correlated error shape, with no data/authority fields.
                        if queue_publish_ack(inner, &publish, *status).is_ok() {
                            let _ = drain_outbound(host, inner, now);
                        }
                    }
                    result
                }
                _ => Err(Status::Invalid),
            };
        }
        Err(Status::NotReady) => {}
        Err(status) => return Err(status),
    }
    if inner.ready
        && inner.offer.is_none()
        && inner.pending.is_none()
        && inner.requested_flush.is_none()
    {
        admit_pending(inner)?;
    }
    if inner.pending.is_some() && inner.pending_request.is_none() {
        queue_receipt(host, inner, now)?;
        if drain_outbound(host, inner, now)? {
            send_pending(host, inner, now)?;
        }
    }
    Ok(PublicationResult::Accepted(step()))
}

/// Advisory shutdown follows the Core retirement fence. The sole supervisor
/// still owns signaling/wait/reap even when this nonblocking send cannot finish.
pub(super) fn stop(inner: &mut ChildInner, reason: ProcessRetireReason) -> Result<(), Status> {
    require(inner.retiring, Status::Denied)?;
    let request = checked(inner.request)?;
    let reason = match reason {
        ProcessRetireReason::HumanClose => 1,
        ProcessRetireReason::Revoked => 2,
        ProcessRetireReason::Expired => 3,
        ProcessRetireReason::ChildFault => 4,
        ProcessRetireReason::InvalidTransport => 5,
        ProcessRetireReason::Deadline => 6,
    };
    // These are copied control bytes/metadata, not the held input, offered FDs,
    // accepted mappings, capture ticket or original Save owners.
    inner.outbound = None;
    inner.deferred_ack = None;
    inner.requested_flush = None;
    let bytes = encode(
        inner,
        ProcessMessage::Stop(p::Stop {
            request_id: request,
            channel_generation: inner.record.channel,
            reason,
            reserved: [0; 44],
        }),
    )?;
    inner.request = request;
    let socket = inner.socket.as_ref().ok_or(Status::Disconnected)?;
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    let sent = fixtures::send_control(inner, socket, &bytes, &[]);
    #[cfg(not(feature = "host_editor_process_assertions_v0_dev"))]
    let sent = linux::send(socket, &bytes, &[]);
    match sent {
        Ok(()) => Ok(()),
        Err(status) => {
            inner.outbound = Some(OutboundFrame {
                bytes,
                kind: OutboundKind::None,
            });
            Err(status)
        }
    }
}
