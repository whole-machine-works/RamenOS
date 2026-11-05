//! Trusted bridge from actual process delivery/publication to existing Core.
//! No public data setter and no parent editor/raster implementation.
use super::*;
use crate::editor_dev::native_authority::NativeAuthority;
use crate::editor_dev::native_save::*;
use crate::editor_dev::process_editor::*;
use desktop_editor_core::process_data;
use kernel_api::generated::{desktop_focus_v1 as focus, desktop_surface_v1 as surface};
use std::sync::Weak;
use std::sync::atomic::AtomicBool;

// Only this module can construct this authority. The carrier carries it opaquely.
pub(in crate::editor_dev) struct ProcessCaptureAuthority {
    authority: Arc<NativeAuthority>,
    document: Arc<DocumentLife>,
    attachment: Arc<crate::editor_dev::native_preview::AttachmentLife>,
    input_sequence: u64,
    focus_epoch: u64,
    entered: Instant,
    deadline: Instant,
    consumed: AtomicBool,
}

impl HostDesktop {
    pub(in crate::editor_dev) fn process_authority(&self) -> Result<Arc<NativeAuthority>, Status> {
        self.save_authority()
    }
    pub(in crate::editor_dev) fn process_roster(
        &self,
    ) -> Result<Arc<Mutex<ProcessRoster>>, Status> {
        Ok(self.save_authority()?.process.clone())
    }
    pub(in crate::editor_dev) fn process_claim(
        &self,
        editor: &NativeEditor,
    ) -> Result<ProcessSeed, Status> {
        let authority = self.save_authority()?;
        if !same(&authority, &editor.authority) {
            return Err(Status::Denied);
        }
        let (mut seed, attachment) = {
            let mut state = self.state.lock().map_err(|_| Status::Internal)?;
            state.expire(self.clock.load(Ordering::SeqCst));
            if state.config.font_rows != process_data::frozen_font() {
                return Err(Status::Unsupported);
            }
            let gate = authority.gate.lock().map_err(|_| Status::Internal)?;
            let save = gate.save.as_ref().ok_or(Status::Denied)?;
            let document = save.documents.get(&editor.life.id).ok_or(Status::Stale)?;
            claimable(save, document, editor)?;
            let preview = gate.preview.as_ref().ok_or(Status::Denied)?;
            preview.admit_instance(document.attachment.id)?;
            let approved = preview.row(&document.attachment)?;
            let session = state
                .sessions
                .get(&document.view.actor.session_id)
                .ok_or(Status::Stale)?;
            (
                ProcessSeed {
                    view: document.view.clone(),
                    object_id: document.object_id,
                    object_generation: approved.view.pin.current.object_generation,
                    selected: Vec::new(),
                    expires_at_ms: approved.view.instance_expires_at_ms,
                    focus_epoch: session.focus,
                    service_epoch: state.service_epoch,
                },
                document.attachment.clone(),
            )
        };
        // Hash/encode outside enforcing locks, then revalidate the same owner and
        // complete document tuple before the one-way ProcessOwned transition.
        seed.selected = process_data::encode_text64(
            seed.object_id,
            seed.view.confirmed_revision,
            &seed.view.bytes,
        )
        .map_err(|_| Status::Invalid)?;
        if process_data::sha256(&seed.view.bytes) != seed.view.confirmed_hash {
            return Err(Status::Denied);
        }
        let mut state = self.state.lock().map_err(|_| Status::Internal)?;
        state.expire(self.clock.load(Ordering::SeqCst));
        let mut gate = authority.gate.lock().map_err(|_| Status::Internal)?;
        let save = gate.save.as_ref().ok_or(Status::Denied)?;
        let document = save.documents.get(&editor.life.id).ok_or(Status::Stale)?;
        claimable(save, document, editor)?;
        let preview = gate.preview.as_ref().ok_or(Status::Denied)?;
        preview.admit_instance(document.attachment.id)?;
        let approved = preview.row(&document.attachment)?;
        let session = state
            .sessions
            .get(&seed.view.actor.session_id)
            .ok_or(Status::Stale)?;
        if document.view != seed.view
            || !Arc::ptr_eq(&document.attachment, &attachment)
            || approved.view.pin.current.object_generation != seed.object_generation
            || approved.view.instance_expires_at_ms != seed.expires_at_ms
            || state.service_epoch != seed.service_epoch
            || session.focus != seed.focus_epoch
            || state.config.font_rows != process_data::frozen_font()
        {
            return Err(Status::Stale);
        }
        gate.save
            .as_mut()
            .ok_or(Status::Denied)?
            .documents
            .get_mut(&editor.life.id)
            .ok_or(Status::Stale)?
            .process
            .owned = true;
        let session = state
            .sessions
            .get_mut(&seed.view.actor.session_id)
            .ok_or(Status::Stale)?;
        session.focused = None;
        session.keys.clear();
        Ok(seed)
    }
    pub(in crate::editor_dev) fn process_validate(
        &self,
        editor: &NativeEditor,
        now: u64,
    ) -> Result<NativeEditorObservation, Status> {
        let authority = self.save_authority()?;
        if !same(&authority, &editor.authority) {
            return Err(Status::Denied);
        }
        let mut state = self.state.lock().map_err(|_| Status::Internal)?;
        state.expire(self.clock.fetch_max(now, Ordering::SeqCst).max(now));
        let gate = authority.gate.lock().map_err(|_| Status::Internal)?;
        let document = gate
            .save
            .as_ref()
            .ok_or(Status::Denied)?
            .documents
            .get(&editor.life.id)
            .ok_or(Status::Stale)?;
        if !Arc::ptr_eq(&document.life, &editor.life) || !document.process.owned {
            return Err(Status::Denied);
        }
        if document.process.retired {
            return Err(Status::Stale);
        }
        gate.preview
            .as_ref()
            .ok_or(Status::Denied)?
            .admit_instance(document.attachment.id)?;
        if document.frame.is_some()
            && state
                .sessions
                .get(&document.view.actor.session_id)
                .is_none_or(|s| s.focused != Some(document.view.actor.instance_id))
        {
            return Err(Status::Stale);
        }
        Ok(document.view.clone())
    }
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    pub(in crate::editor_dev) fn process_dequeue(
        &self,
        editor: &NativeEditor,
        now: u64,
    ) -> Result<Option<DeliveredProcessInput>, Status> {
        self.process_dequeue_for_queue(editor, now, true, true)
    }
    pub(in crate::editor_dev) fn process_dequeue_for_queue(
        &self,
        editor: &NativeEditor,
        now: u64,
        ordinary_free: bool,
        reset_free: bool,
    ) -> Result<Option<DeliveredProcessInput>, Status> {
        let authority = self.save_authority()?;
        if !same(&authority, &editor.authority) {
            return Err(Status::Denied);
        }
        let (status_endpoint, focus_endpoint, actor, ids, queued, queue_generation) = {
            let mut state = self.state.lock().map_err(|_| Status::Internal)?;
            state.expire(self.clock.fetch_max(now, Ordering::SeqCst).max(now));
            let mut gate = authority.gate.lock().map_err(|_| Status::Internal)?;
            let document = gate
                .save
                .as_ref()
                .ok_or(Status::Denied)?
                .documents
                .get(&editor.life.id)
                .ok_or(Status::Stale)?;
            if !Arc::ptr_eq(&document.life, &editor.life)
                || !document.process.owned
                || document.process.retired
            {
                return Err(Status::Denied);
            }
            // Focus delivery starts only after genuine immutable child pixels
            // have been admitted. Enrollment alone cannot activate input.
            if document.frame.is_none() || document.process.app_pixels.is_none() {
                return Err(Status::NotReady);
            }
            let actor = document.view.actor.clone();
            let preview = gate.preview.as_ref().ok_or(Status::Denied)?;
            preview.admit_instance(actor.instance_id)?;
            let endpoints = preview.row(&document.attachment)?.endpoints;
            let queued = state
                .sessions
                .get(&actor.session_id)
                .ok_or(Status::Stale)?
                .keys
                .front()
                .copied();
            if queued.is_none() {
                return Ok(None);
            }
            // Parent typed-input storage is separate from Core's existing
            // overflow-reset queue. Refuse before a genuine PollKeys dequeue.
            if document.process.issued_inputs.len() >= 66
                || if queued.unwrap().phase == 3 {
                    !reset_free
                } else {
                    !ordinary_free
                }
            {
                return Err(Status::Exhausted);
            }
            let document = gate
                .save
                .as_mut()
                .ok_or(Status::Denied)?
                .documents
                .get_mut(&editor.life.id)
                .ok_or(Status::Stale)?;
            document
                .process
                .issued_inputs
                .try_reserve(1)
                .map_err(|_| Status::Exhausted)?;
            let last = document
                .request_id
                .checked_add(2)
                .ok_or(Status::Exhausted)?;
            document.request_id = last;
            (
                self.endpoint_locked(&state, endpoints[0])?,
                self.endpoint_locked(&state, endpoints[1])?,
                actor,
                [last - 1, last],
                queued.unwrap(),
                state
                    .sessions
                    .get(&document.view.actor.session_id)
                    .ok_or(Status::Stale)?
                    .queue_generation,
            )
        };
        let q = editor::ObserveFocus {
            request_id: ids[0],
            session_id: actor.session_id,
            session_generation: actor.session_generation,
            instance_id: actor.instance_id,
            instance_generation: actor.instance_generation,
        }
        .encode(status_endpoint.handle)?;
        let observed =
            editor::ObserveFocusReply::decode(&self.dispatch(&status_endpoint.peer, &q, now))?;
        if observed.status != 0 {
            return Err(status_from_u32(observed.status));
        }
        let q = focus::PollKeys {
            request_id: ids[1],
            session_id: actor.session_id,
            session_generation: actor.session_generation,
            instance_id: actor.instance_id,
            instance_generation: actor.instance_generation,
            focus_epoch: observed.focus_epoch,
        }
        .encode(focus_endpoint.handle)?;
        let key = focus::PollKeysReply::decode(&self.dispatch(&focus_endpoint.peer, &q, now))?;
        if key.status == Status::NotReady as u32 {
            return Ok(None);
        }
        if key.status != 0 {
            return Err(status_from_u32(key.status));
        }
        let mut state = self.state.lock().map_err(|_| Status::Internal)?;
        state.expire(self.clock.fetch_max(now, Ordering::SeqCst).max(now));
        let mut gate = authority.gate.lock().map_err(|_| Status::Internal)?;
        gate.preview
            .as_ref()
            .ok_or(Status::Denied)?
            .admit_instance(actor.instance_id)?;
        let session = state.sessions.get(&actor.session_id).ok_or(Status::Stale)?;
        if session.focused != Some(actor.instance_id)
            || session.focus != key.focus_epoch
            || session.queue_generation != queue_generation
            || queued.sequence != key.sequence
            || queued.usage != key.usage
            || queued.phase != key.phase
            || queued.modifiers != key.modifiers
        {
            return Err(Status::Stale);
        }
        let save = gate.save.as_ref().ok_or(Status::Denied)?;
        let document = save.documents.get(&editor.life.id).ok_or(Status::Stale)?;
        if document.process.retired
            || key.sequence <= document.key_sequence && key.focus_epoch == document.focus_epoch
        {
            return Err(Status::Stale);
        }
        let capturing = key.phase == 1
            && key.usage == 22
            && key.modifiers & 1 != 0
            && !save.unresolved_document(editor.life.id)?
            && !matches!(
                document.view.phase,
                NativeEditorPhase::AllocationPending
                    | NativeEditorPhase::AllocationUnknown
                    | NativeEditorPhase::Saving
                    | NativeEditorPhase::Unknown
            );
        let capture = if capturing {
            let deadline = queued
                .entered
                .checked_add(Duration::from_millis(1000))
                .ok_or(Status::Exhausted)?;
            if Instant::now() >= deadline {
                return Err(Status::Timeout);
            }
            Some(ProcessSaveCapture {
                authority: ProcessCaptureAuthority {
                    authority: authority.clone(),
                    document: document.life.clone(),
                    attachment: document.attachment.clone(),
                    input_sequence: key.sequence,
                    focus_epoch: key.focus_epoch,
                    entered: queued.entered,
                    deadline,
                    consumed: AtomicBool::new(false),
                },
                entered: queued.entered,
                deadline,
                input_sequence: key.sequence,
            })
        } else {
            None
        };
        let service_epoch = state.service_epoch;
        let document = gate
            .save
            .as_mut()
            .ok_or(Status::Denied)?
            .documents
            .get_mut(&editor.life.id)
            .ok_or(Status::Stale)?;
        if document.process.issued_inputs.len() >= 66 {
            return Err(Status::Exhausted);
        }
        document.process.issued_inputs.push_back((
            key.sequence,
            key.focus_epoch,
            state.service_epoch,
            queue_generation,
        ));
        document.key_sequence = key.sequence;
        document.focus_epoch = key.focus_epoch;
        Ok(Some(DeliveredProcessInput {
            sequence: key.sequence,
            queue_generation,
            focus_epoch: key.focus_epoch,
            service_epoch,
            usage: key.usage,
            phase: key.phase,
            modifiers: key.modifiers,
            entered: queued.entered,
            capture,
        }))
    }
    pub(in crate::editor_dev) fn process_acknowledge(
        &self,
        editor: &NativeEditor,
        input: &DeliveredProcessInput,
        text_generation: u64,
        view_version: u64,
        now: u64,
    ) -> Result<(), Status> {
        self.process_validate(editor, now)?;
        if input.entered > Instant::now() {
            return Err(Status::Invalid);
        }
        let authority = self.save_authority()?;
        let mut state = self.state.lock().map_err(|_| Status::Internal)?;
        state.expire(self.clock.fetch_max(now, Ordering::SeqCst).max(now));
        let mut gate = authority.gate.lock().map_err(|_| Status::Internal)?;
        let document = gate
            .save
            .as_ref()
            .ok_or(Status::Denied)?
            .documents
            .get(&editor.life.id)
            .ok_or(Status::Stale)?;
        if !same(&authority, &editor.authority) || !Arc::ptr_eq(&document.life, &editor.life) {
            return Err(Status::Denied);
        }
        gate.preview
            .as_ref()
            .ok_or(Status::Denied)?
            .admit_instance(document.attachment.id)?;
        let session = state
            .sessions
            .get(&document.view.actor.session_id)
            .ok_or(Status::Stale)?;
        if session.focused != Some(document.view.actor.instance_id)
            || session.focus != input.focus_epoch
            || state.service_epoch != input.service_epoch
            || session.queue_generation != input.queue_generation
        {
            return Err(Status::Stale);
        }
        let document = gate
            .save
            .as_mut()
            .ok_or(Status::Denied)?
            .documents
            .get_mut(&editor.life.id)
            .ok_or(Status::Stale)?;
        if document.process.retired
            || document.process.issued_inputs.front()
                != Some(&(
                    input.sequence,
                    input.focus_epoch,
                    input.service_epoch,
                    input.queue_generation,
                ))
            || input.focus_epoch != document.focus_epoch
            || input.sequence <= document.process.acknowledged_sequence
        {
            return Err(Status::Stale);
        }
        for (before, after) in [
            (document.process.acknowledged_text, text_generation),
            (document.process.acknowledged_view, view_version),
        ] {
            if after != before && before.checked_add(1) != Some(after) {
                return Err(Status::Invalid);
            }
        }
        if text_generation != document.process.acknowledged_text
            && view_version == document.process.acknowledged_view
        {
            return Err(Status::Invalid);
        }
        document.process.issued_inputs.pop_front();
        document.process.acknowledged_sequence = input.sequence;
        document.process.acknowledged_text = text_generation;
        document.process.acknowledged_view = view_version;
        if text_generation != document.view.text_generation
            && document.view.phase == NativeEditorPhase::Saved
        {
            document.view.phase = NativeEditorPhase::Unsaved;
        }
        Ok(())
    }
    pub(in crate::editor_dev) fn process_take_intent(
        &self,
        editor: &NativeEditor,
    ) -> Result<NativeSaveIntent, Status> {
        let authority = self.save_authority()?;
        if !same(&authority, &editor.authority) {
            return Err(Status::Denied);
        }
        let mut state = self.state.lock().map_err(|_| Status::Internal)?;
        state.expire(self.clock.load(Ordering::SeqCst));
        let mut gate = authority.gate.lock().map_err(|_| Status::Internal)?;
        let document = gate
            .save
            .as_ref()
            .ok_or(Status::Denied)?
            .documents
            .get(&editor.life.id)
            .ok_or(Status::Stale)?;
        if !Arc::ptr_eq(&document.life, &editor.life) || !document.process.owned {
            return Err(Status::Denied);
        }
        gate.preview
            .as_ref()
            .ok_or(Status::Denied)?
            .admit_instance(document.attachment.id)?;
        if document.process.retired {
            return Err(Status::Stale);
        }
        let document = gate
            .save
            .as_mut()
            .ok_or(Status::Denied)?
            .documents
            .get_mut(&editor.life.id)
            .ok_or(Status::Stale)?;
        let life = document.queued_intent.take().ok_or(Status::NotReady)?;
        life.exposed.store(true, Ordering::Release);
        Ok(NativeSaveIntent {
            authority: authority.clone(),
            life,
        })
    }
    pub(in crate::editor_dev) fn process_retire_core(
        &self,
        editor: &NativeEditor,
        reason: ProcessRetireReason,
        now: u64,
    ) -> Result<(), Status> {
        let authority = self.save_authority()?;
        if !same(&authority, &editor.authority) {
            return Err(Status::Denied);
        }
        let mut state = self.state.lock().map_err(|_| Status::Internal)?;
        state.expire(self.clock.fetch_max(now, Ordering::SeqCst).max(now));
        let instance = {
            let mut gate = authority.gate.lock().map_err(|_| Status::Internal)?;
            let document = gate
                .save
                .as_mut()
                .ok_or(Status::Denied)?
                .documents
                .get_mut(&editor.life.id)
                .ok_or(Status::Stale)?;
            if !Arc::ptr_eq(&document.life, &editor.life) || !document.process.owned {
                return Err(Status::Denied);
            }
            document.process.retired = true;
            document.process.issued_inputs.clear();
            document.queued_intent = None;
            document.view.actor.instance_id
        };
        state.retire(
            instance,
            match reason {
                ProcessRetireReason::HumanClose => InstanceState::Exited,
                ProcessRetireReason::Revoked => InstanceState::Revoked,
                ProcessRetireReason::Expired | ProcessRetireReason::Deadline => {
                    InstanceState::Expired
                }
                ProcessRetireReason::ChildFault | ProcessRetireReason::InvalidTransport => {
                    InstanceState::Faulted
                }
            },
        );
        Ok(())
    }
}

#[cfg(feature = "host_editor_process_assertions_v0_dev")]
impl FixtureController {
    pub(in crate::editor_dev) fn process_host(&self) -> &HostDesktop {
        &self.host
    }
}

impl HostDesktop {
    pub(in crate::editor_dev) fn process_adopt_verified(
        &self,
        editor: &NativeEditor,
        publication: &VerifiedProcessPublication,
        capture: Option<&ProcessSaveCapture>,
        now: u64,
    ) -> Result<bool, Status> {
        // Full hashes and buffer copies occur outside both enforcing locks.
        publication
            .state
            .validate_body(&publication.body)
            .map_err(|_| Status::Invalid)?;
        publication
            .state
            .validate_surface(&publication.pixels)
            .map_err(|_| Status::Invalid)?;
        let pixels = Arc::new(publication.pixels.clone());
        let authority = self.save_authority()?;
        if !same(&authority, &editor.authority) {
            return Err(Status::Denied);
        }
        if capture.is_some_and(|capture| !same(&authority, &capture.authority.authority)) {
            return Err(Status::Denied);
        }
        self.process_validate(editor, now)?;
        // A genuine preceding Present is consumed through the existing typed
        // compositor before acquiring the next buffer. No inspection side effect.
        let prior_compositor = {
            let state = self.state.lock().map_err(|_| Status::Internal)?;
            let gate = authority.gate.lock().map_err(|_| Status::Internal)?;
            let document = gate
                .save
                .as_ref()
                .ok_or(Status::Denied)?
                .documents
                .get(&editor.life.id)
                .ok_or(Status::Stale)?;
            let instance = state
                .instances
                .get(&document.view.actor.instance_id)
                .ok_or(Status::Stale)?;
            if instance.surface.frozen.is_some()
                && !document.process.staged_adoption
                && document.frame.is_some()
            {
                Some(
                    self.endpoint_locked(
                        &state,
                        state
                            .sessions
                            .get(&document.view.actor.session_id)
                            .ok_or(Status::Stale)?
                            .compositor,
                    )?,
                )
            } else {
                None
            }
        };
        if let Some(compositor) = prior_compositor {
            self.compose_native_save(&compositor, now)?;
        }
        let (
            view,
            endpoint,
            chrome_endpoint,
            created,
            surface_id,
            surface_generation,
            buffer_index,
            sequence,
            requests,
            initial_focus,
        ) = {
            let mut state = self.state.lock().map_err(|_| Status::Internal)?;
            state.expire(self.clock.fetch_max(now, Ordering::SeqCst).max(now));
            if state.frame_limit_hit() {
                return Err(Status::Exhausted);
            }
            let mut gate = authority.gate.lock().map_err(|_| Status::Internal)?;
            let save = gate.save.as_ref().ok_or(Status::Denied)?;
            let document = save.documents.get(&editor.life.id).ok_or(Status::Stale)?;
            validate_publication(document, publication, capture)?;
            let preview = gate.preview.as_ref().ok_or(Status::Denied)?;
            preview.admit_instance(document.attachment.id)?;
            let endpoints = preview.row(&document.attachment)?.endpoints;
            let actor = &document.view.actor;
            let instance = state
                .instances
                .get(&actor.instance_id)
                .ok_or(Status::Stale)?;
            if instance.surface.frozen.is_some() || document.process.staged_adoption {
                return Err(Status::NotReady);
            }
            let sequence = instance
                .surface
                .sequence
                .checked_add(1)
                .ok_or(Status::Exhausted)?;
            let surface_id = instance.surface.id;
            let surface_generation = instance.surface.generation;
            let created = instance.surface.created;
            let view = document.view.clone();
            let session = state.sessions.get(&actor.session_id).ok_or(Status::Stale)?;
            let initial_focus = session.focus;
            let chrome = self.endpoint_locked(&state, session.chrome)?;
            let endpoint = self.endpoint_locked(&state, endpoints[2])?;
            let save = gate.save.as_mut().ok_or(Status::Denied)?;
            let next_frame = save.next_frame.checked_add(1).ok_or(Status::Exhausted)?;
            let document = save
                .documents
                .get_mut(&editor.life.id)
                .ok_or(Status::Stale)?;
            let last = document
                .request_id
                .checked_add(4)
                .ok_or(Status::Exhausted)?;
            document.request_id = last;
            document.process.staged_adoption = true;
            save.next_frame = next_frame;
            state.pending_frames += 1;
            (
                view,
                endpoint,
                chrome,
                created,
                surface_id,
                surface_generation,
                ((sequence - 1) % 2) as u32,
                sequence,
                [last - 3, last - 2, last - 1, last],
                initial_focus,
            )
        };
        let mut staged = ProcessAdoptionReservation {
            authority: authority.clone(),
            document: editor.life.clone(),
            finished: false,
        };
        let mut reservation = FrameReservation {
            state: self.state.clone(),
            finished: false,
        };
        let actor = &view.actor;
        if !created {
            let q = surface::Create {
                request_id: requests[0],
                session_id: actor.session_id,
                session_generation: actor.session_generation,
                instance_id: actor.instance_id,
                instance_generation: actor.instance_generation,
                width: 640,
                height: 480,
                format: 1,
                reserved: 0,
            }
            .encode(endpoint.handle)?;
            let reply = surface::CreateReply::decode(&self.dispatch(&endpoint.peer, &q, now))?;
            if reply.status != 0 {
                return Err(status_from_u32(reply.status));
            }
            if (reply.surface_id, reply.surface_generation) != (surface_id, surface_generation) {
                return Err(Status::Denied);
            }
        }
        let needs_focus = {
            let state = self.state.lock().map_err(|_| Status::Internal)?;
            state
                .sessions
                .get(&actor.session_id)
                .ok_or(Status::Stale)?
                .focused
                != Some(actor.instance_id)
        };
        let focus_epoch = if needs_focus && publication.input_sequence == 0 {
            let q = focus::Assign {
                request_id: requests[1],
                session_id: actor.session_id,
                session_generation: actor.session_generation,
                instance_id: actor.instance_id,
                instance_generation: actor.instance_generation,
                surface_id,
                surface_generation,
            }
            .encode(chrome_endpoint.handle)?;
            let reply = focus::AssignReply::decode(&self.dispatch(&chrome_endpoint.peer, &q, now))?;
            if reply.status != 0 {
                return Err(status_from_u32(reply.status));
            }
            reply.focus_epoch
        } else {
            initial_focus
        };
        let q = surface::Acquire {
            request_id: requests[2],
            surface_id,
            surface_generation,
            buffer_index,
            reserved: 0,
        }
        .encode(endpoint.handle)?;
        let acquired = surface::AcquireReply::decode(&self.dispatch(&endpoint.peer, &q, now))?;
        if acquired.status != 0 {
            return Err(status_from_u32(acquired.status));
        }
        let mut acquisition = NativeFrameAcquisition {
            state: self.state.clone(),
            instance: actor.instance_id,
            instance_generation: actor.instance_generation,
            surface: surface_id,
            surface_generation,
            buffer_index,
            buffer: acquired.buffer_shm,
            mapping: acquired.mapping_generation,
            sequence,
            published: false,
        };
        if acquired.mapping_generation == 0 || acquired.byte_len != FRAME_BYTES as u32 {
            return Err(Status::Invalid);
        }
        let handle = Handle::unpack(acquired.buffer_shm);
        let descriptor = ObjectDescriptor {
            handle,
            kind: ObjectKind::SurfaceBuffer,
            byte_len: acquired.byte_len,
            object_generation: handle.generation,
        };
        let lease = self.write_lease(
            &endpoint.peer,
            &descriptor,
            acquired.mapping_generation,
            now,
        )?;
        lease.copy_from(0, &pixels, now)?;
        self.process_validate(editor, now)?;
        let q = surface::Present {
            request_id: requests[3],
            surface_id,
            surface_generation,
            mapping_generation: acquired.mapping_generation,
            sequence,
            buffer_index,
            reserved: 0,
        }
        .encode(endpoint.handle)?;
        let presented = surface::PresentReply::decode(&self.dispatch(&endpoint.peer, &q, now))?;
        if presented.status != 0 {
            return Err(status_from_u32(presented.status));
        }
        if presented.sequence != sequence {
            return Err(Status::Invalid);
        }
        let mut state = self.state.lock().map_err(|_| Status::Internal)?;
        state.expire(self.clock.fetch_max(now, Ordering::SeqCst).max(now));
        let mut gate = authority.gate.lock().map_err(|_| Status::Internal)?;
        gate.preview
            .as_ref()
            .ok_or(Status::Denied)?
            .admit_instance(actor.instance_id)?;
        let session = state.sessions.get(&actor.session_id).ok_or(Status::Stale)?;
        let frozen = state
            .instances
            .get(&actor.instance_id)
            .ok_or(Status::Stale)?
            .surface
            .frozen
            .as_ref()
            .ok_or(Status::Stale)?;
        if session.focus != focus_epoch
            || session.focused != Some(actor.instance_id)
            || frozen.1 != sequence
            || frozen.2.as_slice() != pixels.as_slice()
        {
            return Err(Status::Stale);
        }
        let accepted_surface = frozen.2.clone();
        let save = gate.save.as_mut().ok_or(Status::Denied)?;
        let document = save.documents.get(&editor.life.id).ok_or(Status::Stale)?;
        validate_publication(document, publication, capture)?;
        let intent = if let Some(capture) = capture {
            if save.unresolved_document(editor.life.id)? {
                return Err(Status::NotReady);
            }
            let live = save.live_intents(&authority)?;
            if live.len() >= 48
                || live
                    .iter()
                    .filter(|i| i.snapshot.data.view.object_id == document.object_id)
                    .count()
                    >= 16
            {
                return Err(Status::Exhausted);
            }
            let id = save.next_intent.checked_add(1).ok_or(Status::Exhausted)?;
            let current = save
                .current
                .get(&document.object_id)
                .ok_or(Status::Denied)?;
            Some(Arc::new(IntentLife {
                capture_input_sequence: capture.authority.input_sequence,
                id,
                exposed: AtomicBool::new(false),
                closed_before_admission: AtomicBool::new(false),
                entry_admitted: AtomicBool::new(false),
                snapshot: NativeDraftSnapshot {
                    data: Arc::new(SnapshotData {
                        body: publication.body.clone(),
                        view: DraftSnapshotView {
                            actor: actor.clone(),
                            object_id: current.object_id,
                            object_generation: current.object_generation,
                            original_store_epoch: current.store_epoch,
                            document_id: view.document_id,
                            text_generation: publication.state.text_generation,
                            expected_revision: view.confirmed_revision,
                            expected_content_hash: view.confirmed_hash,
                            byte_len: publication.body.len() as u32,
                            source_content_hash: publication.state.header.content_hash,
                        },
                    }),
                },
                entered: capture.authority.entered,
                deadline: capture.authority.deadline,
                attachment: document.attachment.clone(),
            }))
        } else {
            None
        };
        if let Some(capture) = capture {
            if capture
                .authority
                .consumed
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return Err(Status::NotReady);
            }
        }
        if let Some(intent) = &intent {
            save.next_intent = intent.id;
            save.intents.insert(intent.id, Arc::downgrade(intent));
        }
        let document = save
            .documents
            .get_mut(&editor.life.id)
            .ok_or(Status::Stale)?;
        let changed = document.view.bytes != publication.body;
        document.view.bytes = publication.body.clone();
        document.view.cursor = publication.state.cursor;
        document.view.selection = publication.state.selection;
        document.view.first_visible_line = publication.state.first_visible_line;
        document.view.text_generation = publication.state.text_generation;
        document.view.view_version = publication.state.view_generation;
        if changed
            && !matches!(
                document.view.phase,
                NativeEditorPhase::Saving
                    | NativeEditorPhase::Unknown
                    | NativeEditorPhase::AllocationPending
                    | NativeEditorPhase::AllocationUnknown
            )
        {
            document.view.phase = NativeEditorPhase::Unsaved;
        }
        document.frame = Some(NativeFrameObservation {
            actor: actor.clone(),
            document_id: view.document_id,
            text_generation: publication.state.text_generation,
            view_version: publication.state.view_generation,
            surface_id,
            surface_generation,
            mapping_generation: acquired.mapping_generation,
            focus_epoch,
            sequence,
            app_crop_sha256: publication.state.surface_sha256,
        });
        document.process.app_pixels = Some(accepted_surface);
        document.process.publication_sequence = publication.publication_sequence;
        if let Some(intent) = intent {
            document.last_intent_id = Some(intent.id);
            document.queued_intent = Some(intent);
            document.view.phase = NativeEditorPhase::AllocationPending;
        }
        document.process.staged_adoption = false;
        staged.finished = true;
        state.pending_frames -= 1;
        reservation.finished = true;
        acquisition.published = true;
        Ok(capture.is_some())
    }
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    pub(in crate::editor_dev) fn process_core_snapshot(
        &self,
        editor: &NativeEditor,
    ) -> Result<ProcessCoreSnapshot, Status> {
        let authority = self.save_authority()?;
        if !same(&authority, &editor.authority) {
            return Err(Status::Denied);
        }
        let state = self.state.lock().map_err(|_| Status::Internal)?;
        let gate = authority.gate.lock().map_err(|_| Status::Internal)?;
        let document = gate
            .save
            .as_ref()
            .ok_or(Status::Denied)?
            .documents
            .get(&editor.life.id)
            .ok_or(Status::Stale)?;
        if !Arc::ptr_eq(&document.life, &editor.life) {
            return Err(Status::Denied);
        }
        let session = state
            .sessions
            .get(&document.view.actor.session_id)
            .ok_or(Status::Stale)?;
        let frame_surface = document.frame.as_ref().and_then(|frame| {
            state
                .instances
                .get(&document.view.actor.instance_id)
                .filter(|instance| {
                    frame.actor == document.view.actor
                        && frame.document_id == document.view.document_id
                        && instance.surface.id == frame.surface_id
                        && instance.surface.generation == frame.surface_generation
                })
                .map(|instance| {
                    (
                        frame.surface_id,
                        frame.surface_generation,
                        instance.surface.epoch,
                        instance.state == InstanceState::Running
                            && instance.surface.created
                            && !instance.surface.destroyed,
                    )
                })
        });
        Ok(ProcessCoreSnapshot {
            document: Some(document.view.clone()),
            app_pixels: document.process.app_pixels.clone().unwrap_or_default(),
            composed_pixels: document.process.composed_pixels.clone().unwrap_or_default(),
            focus_epoch: session.focus,
            service_epoch: state.service_epoch,
            ordinary_queue: session.keys.iter().filter(|k| k.phase != 3).count() as u32,
            reset_queue: session.keys.iter().filter(|k| k.phase == 3).count() as u32,
            owner_confirm_request: document.process.owner_confirm_request,
            owner_confirm_status: document.process.owner_confirm_status,
            frame_surface_id: frame_surface.map(|s| s.0),
            frame_surface_generation: frame_surface.map(|s| s.1),
            frame_surface_epoch: frame_surface.map(|s| s.2),
            frame_surface_live: frame_surface.map(|s| s.3),
        })
    }
}

fn validate_publication(
    document: &DocumentRow,
    publication: &VerifiedProcessPublication,
    capture: Option<&ProcessSaveCapture>,
) -> Result<(), Status> {
    if !document.process.owned || document.process.retired {
        return Err(Status::Denied);
    }
    if Instant::now() >= publication.child_deadline {
        return Err(Status::Timeout);
    }
    if publication.state.header.selected_object_id != document.object_id {
        return Err(Status::Denied);
    }
    if publication.state.header.revision != document.view.confirmed_revision {
        return Err(Status::Stale);
    }
    if publication.publication_sequence <= document.process.publication_sequence {
        return Err(Status::Stale);
    }
    if publication.input_sequence != document.process.acknowledged_sequence
        || publication.state.text_generation != document.process.acknowledged_text
        || publication.state.view_generation != document.process.acknowledged_view
    {
        return Err(Status::Stale);
    }
    if let Some(capture) = capture {
        let actual = &capture.authority;
        if !Arc::ptr_eq(&actual.document, &document.life)
            || !Arc::ptr_eq(&actual.attachment, &document.attachment)
        {
            return Err(Status::Denied);
        }
        if actual.consumed.load(Ordering::Acquire) {
            return Err(Status::NotReady);
        }
        if actual.input_sequence != publication.input_sequence
            || actual.focus_epoch != document.focus_epoch
            || actual.entered != capture.entered
            || actual.deadline != capture.deadline
            || capture.input_sequence != actual.input_sequence
        {
            return Err(Status::Stale);
        }
        if Instant::now() >= actual.deadline {
            return Err(Status::Timeout);
        }
    }
    Ok(())
}

fn claimable(save: &SaveGate, document: &DocumentRow, editor: &NativeEditor) -> Result<(), Status> {
    if !Arc::ptr_eq(&document.life, &editor.life) || document.process.owned {
        return Err(Status::Denied);
    }
    if document.view.phase != NativeEditorPhase::Loaded {
        return Err(Status::NotReady);
    }
    for intent in save.intents.values().filter_map(Weak::upgrade) {
        if intent.snapshot.data.view.object_id == document.object_id
            && save.unresolved_document(intent.snapshot.data.view.document_id)?
        {
            return Err(Status::NotReady);
        }
    }
    Ok(())
}

struct ProcessAdoptionReservation {
    authority: Arc<NativeAuthority>,
    document: Arc<DocumentLife>,
    finished: bool,
}
impl Drop for ProcessAdoptionReservation {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let mut gate = self
            .authority
            .gate
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if let Some(document) = gate
            .save
            .as_mut()
            .and_then(|save| save.documents.get_mut(&self.document.id))
        {
            if Arc::ptr_eq(&document.life, &self.document) {
                document.process.staged_adoption = false;
            }
        }
    }
}

#[cfg(feature = "host_editor_process_assertions_v0_dev")]
impl HostDesktop {
    pub(in crate::editor_dev) fn process_fixture_queue_produce(
        &self,
        editor: &NativeEditor,
        scenario: &ProcessAssertionScenario,
        reset: bool,
        now: u64,
    ) -> Result<(), Status> {
        use kernel_api::generated::input_v1 as input;
        if !matches!(
            scenario.id(),
            "D15PendingInputTwo"
                | "D15OrdinaryQueueSixtyFive"
                | "D15ReservedResetTwo"
                | "D15TotalQueueSixtySix"
        ) {
            return Err(Status::Invalid);
        }
        self.process_validate(editor, now)?;
        let authority = self.save_authority()?;
        if !same(&authority, &editor.authority) {
            return Err(Status::Denied);
        }
        let (endpoint, request) = {
            let state = self.state.lock().map_err(|_| Status::Internal)?;
            let gate = authority.gate.lock().map_err(|_| Status::Internal)?;
            let document = gate
                .save
                .as_ref()
                .ok_or(Status::Denied)?
                .documents
                .get(&editor.life.id)
                .ok_or(Status::Stale)?;
            if !Arc::ptr_eq(&document.life, &editor.life)
                || !document.process.owned
                || document.process.retired
                || document.frame.is_none()
            {
                return Err(Status::Denied);
            }
            let actor = &document.view.actor;
            let session = state.sessions.get(&actor.session_id).ok_or(Status::Stale)?;
            let endpoint = self.endpoint_locked(&state, session.input)?;
            let request = input::ProduceKey {
                session_id: actor.session_id,
                session_generation: actor.session_generation,
                queue_generation: session.queue_generation,
                sequence: session.next_sequence,
                usage: if reset { 0 } else { 4 },
                phase: if reset {
                    3
                } else if session.pressed.contains(&4) {
                    2
                } else {
                    1
                },
                modifiers: if reset { 0 } else { session.modifiers },
                reserved: 0,
            }
            .encode(endpoint.handle)?;
            (endpoint, request)
        };
        let reply = input::ProduceKeyReply::decode(&self.dispatch(&endpoint.peer, &request, now))?;
        if reply.status == 0 {
            Ok(())
        } else {
            Err(status_from_u32(reply.status))
        }
    }

    pub(in crate::editor_dev) fn process_fixture_counter_seed(
        &self,
        editor: &NativeEditor,
        scenario: &ProcessAssertionScenario,
    ) -> Result<(), Status> {
        let authority = self.save_authority()?;
        if !same(&authority, &editor.authority) {
            return Err(Status::Denied);
        }
        let mut gate = authority.gate.lock().map_err(|_| Status::Internal)?;
        let document = gate
            .save
            .as_mut()
            .ok_or(Status::Denied)?
            .documents
            .get_mut(&editor.life.id)
            .ok_or(Status::Stale)?;
        if !Arc::ptr_eq(&document.life, &editor.life)
            || !document.process.owned
            || document.process.retired
        {
            return Err(Status::Denied);
        }
        match scenario.id() {
            "D14TextCounterMax" => {
                document.view.text_generation = u64::MAX;
                document.process.acknowledged_text = u64::MAX;
            }
            "D14ViewCounterMax" => {
                document.view.view_version = u64::MAX;
                document.process.acknowledged_view = u64::MAX;
            }
            _ => return Err(Status::Invalid),
        }
        Ok(())
    }

    pub(in crate::editor_dev) fn process_fixture_core_action(
        &self,
        editor: &NativeEditor,
        scenario: &ProcessAssertionScenario,
        now: u64,
    ) -> Result<(), Status> {
        use kernel_api::generated::{desktop_editor_session_v1 as session, input_v1 as input};
        let authority = self.save_authority()?;
        if !same(&authority, &editor.authority) {
            return Err(Status::Denied);
        }
        let (actor, chrome, compositor, surface_id, surface_generation, old_confirm) = {
            let state = self.state.lock().map_err(|_| Status::Internal)?;
            let gate = authority.gate.lock().map_err(|_| Status::Internal)?;
            let document = gate
                .save
                .as_ref()
                .ok_or(Status::Denied)?
                .documents
                .get(&editor.life.id)
                .ok_or(Status::Stale)?;
            if !Arc::ptr_eq(&document.life, &editor.life) {
                return Err(Status::Denied);
            }
            let actor = document.view.actor.clone();
            let selected = state.sessions.get(&actor.session_id).ok_or(Status::Stale)?;
            let instance = state
                .instances
                .get(&actor.instance_id)
                .ok_or(Status::Stale)?;
            let row = gate
                .preview
                .as_ref()
                .ok_or(Status::Denied)?
                .row(&document.attachment)?;
            (
                actor,
                self.endpoint_locked(&state, selected.chrome)?,
                self.endpoint_locked(&state, selected.compositor)?,
                instance.surface.id,
                instance.surface.generation,
                row.confirm_request,
            )
        };
        let controller = FixtureController { host: self.clone() };
        match scenario.id() {
            "D26FrameAfterRevoke"
            | "D26CaptureAfterRevoke"
            | "D26OldGenerationCannotRevive"
            | "D26OtherOwnerAndOriginalReceiptProgress" => {
                let q = session::RevokeInstance {
                    request_id: 1902,
                    session_id: actor.session_id,
                    session_generation: actor.session_generation,
                    instance_id: actor.instance_id,
                    instance_generation: actor.instance_generation,
                }
                .encode(chrome.handle)?;
                let reply =
                    session::RevokeInstanceReply::decode(&self.dispatch(&chrome.peer, &q, now))?;
                if reply.status != 0 {
                    return Err(status_from_u32(reply.status));
                }
                Ok(())
            }
            "D23OldPreviewEnterDenied" => {
                // Exercise the actual owner operation. The public native
                // preview wire dispatcher intentionally does not support raw
                // ConfirmLaunch; preserve that boundary without relabeling it.
                let entered = Instant::now();
                let life = RequestLife {
                    ticket: Arc::new(()),
                    entered,
                    deadline: entered + std::time::Duration::from_millis(1000),
                    closed: AtomicBool::new(false),
                };
                let result = self.confirm(&chrome.peer, &old_confirm, now, &life);
                let status = match result {
                    Ok(ref reply) => {
                        status_from_u32(session::ConfirmLaunchReply::decode(reply)?.status)
                    }
                    Err(status) => status,
                };
                let request = encode_envelope_wire(&old_confirm)?;
                let mut gate = authority.gate.lock().map_err(|_| Status::Internal)?;
                let document = gate
                    .save
                    .as_mut()
                    .ok_or(Status::Denied)?
                    .documents
                    .get_mut(&editor.life.id)
                    .ok_or(Status::Stale)?;
                document.process.owner_confirm_request = Some(request);
                document.process.owner_confirm_status = Some(status);
                Err(status)
            }
            "D10ProtectedChromeObjectAsSurface" => {
                let input = {
                    let state = self.state.lock().map_err(|_| Status::Internal)?;
                    let selected = state.sessions.get(&actor.session_id).ok_or(Status::Stale)?;
                    self.endpoint_locked(&state, selected.input)?
                };
                let q = surface::Acquire {
                    request_id: 1901,
                    surface_id,
                    surface_generation,
                    buffer_index: 0,
                    reserved: 0,
                }
                .encode(compositor.handle)?;
                let reply = surface::AcquireReply::decode(&self.dispatch(&input.peer, &q, now))?;
                if reply.status != Status::Denied as u32
                    || reply.buffer_shm != 0
                    || reply.mapping_generation != 0
                {
                    return Err(Status::Invalid);
                }
                Err(Status::Denied)
            }
            "D14OldFocusEpoch" | "D27OldKeyPressRelease" => {
                let mut state = self.state.lock().map_err(|_| Status::Internal)?;
                state.shift_focus(actor.session_id, Route::App, Some(actor.instance_id))
            }
            "D14OldServiceEpoch" | "D27OldResetServiceEpoch" | "D27StaleResetCapture" => {
                controller.restart_service(ServiceKind::Focus, now)
            }
            "D27OldSurfaceGeneration" => controller.restart_service(ServiceKind::Compositor, now),
            "D27OrdinaryOverflowReservedReset" => {
                // First call queues64 genuine accepted presses. The carrier
                // records its before checkpoint, then a second call makes the
                // actual65th attempt which forces Core's reserved RESET path.
                let count = {
                    let state = self.state.lock().map_err(|_| Status::Internal)?;
                    state
                        .sessions
                        .get(&actor.session_id)
                        .ok_or(Status::Stale)?
                        .keys
                        .len()
                };
                let number = if count == 64 {
                    1
                } else if count == 0 {
                    64
                } else {
                    return Err(Status::NotReady);
                };
                for _ in 0..number {
                    let (endpoint, q) = {
                        let state = self.state.lock().map_err(|_| Status::Internal)?;
                        let selected =
                            state.sessions.get(&actor.session_id).ok_or(Status::Stale)?;
                        // The queue bounds ordinary events, including releases.
                        // Toggle one genuine supported key so every attempt is
                        // valid without inventing65 simultaneously held keys.
                        let usage = 4;
                        let phase = if selected.pressed.contains(&usage) {
                            2
                        } else {
                            1
                        };
                        let endpoint = self.endpoint_locked(&state, selected.input)?;
                        let q = input::ProduceKey {
                            session_id: actor.session_id,
                            session_generation: actor.session_generation,
                            queue_generation: selected.queue_generation,
                            sequence: selected.next_sequence,
                            usage,
                            phase,
                            modifiers: selected.modifiers,
                            reserved: 0,
                        }
                        .encode(endpoint.handle)?;
                        (endpoint, q)
                    };
                    let reply =
                        input::ProduceKeyReply::decode(&self.dispatch(&endpoint.peer, &q, now))?;
                    if reply.status != 0 {
                        return Err(status_from_u32(reply.status));
                    }
                }
                Ok(())
            }
            // Human reserved keys are already sent through the actual public
            // consumer's genuine driver; this hook never forwards them to child.
            "D10ReservedKeyForwardingReject" => Ok(()),
            _ => Err(Status::Invalid),
        }
    }
}

impl HostDesktop {
    pub(in crate::editor_dev) fn process_receipt_notice(
        &self,
        editor: &NativeEditor,
        now: u64,
    ) -> Result<Option<ProcessReceiptNotice>, Status> {
        self.process_validate(editor, now)?;
        let authority = self.save_authority()?;
        if !same(&authority, &editor.authority) {
            return Err(Status::Denied);
        }
        let gate = authority.gate.lock().map_err(|_| Status::Internal)?;
        let save = gate.save.as_ref().ok_or(Status::Denied)?;
        let document = save.documents.get(&editor.life.id).ok_or(Status::Stale)?;
        if !Arc::ptr_eq(&document.life, &editor.life) || !document.process.owned {
            return Err(Status::Denied);
        }
        let mut selected = None;
        for original in save.originals.values().filter_map(Weak::upgrade) {
            let Some(source) = &original.source else {
                continue;
            };
            let intent = &source.intent;
            if original.view.request.msg_type != 5
                || intent.capture_input_sequence == 0
                || intent.snapshot.data.view.document_id != editor.life.id
                || !Arc::ptr_eq(&intent.attachment, &document.attachment)
                || !original
                    .intent
                    .as_ref()
                    .is_some_and(|actual| Arc::ptr_eq(actual, intent))
            {
                continue;
            }
            let state = original.state.lock().map_err(|_| Status::Internal)?;
            let (Some(receipt), Some(_full176)) = (&state.receipt, &state.receipt_bytes) else {
                continue;
            };
            if receipt.operation_id != source.binding.allocation.operation_id
                || receipt.operation_id == 0
                || receipt.selected_object_id != document.object_id
                || receipt.original_instance_id != document.view.actor.instance_id
                || receipt.original_instance_generation != document.view.actor.instance_generation
            {
                return Err(Status::Invalid);
            }
            let committed = receipt.outcome
                == artifact_store_schema::editor_save::EditorReceiptOutcomeV0::Committed;
            let notice = ProcessReceiptNotice {
                operation_id: receipt.operation_id,
                committed_revision: if committed {
                    receipt.result_revision
                } else {
                    0
                },
                capture_input_sequence: intent.capture_input_sequence,
                capture_text_generation: intent.snapshot.data.view.text_generation,
                outcome: if committed { 0 } else { 1 },
                phase: if !committed {
                    2
                } else if document.process.acknowledged_text
                    == intent.snapshot.data.view.text_generation
                    && document.view.text_generation == intent.snapshot.data.view.text_generation
                {
                    0
                } else {
                    1
                },
            };
            if selected.as_ref().is_none_or(|(id, _)| intent.id > *id) {
                selected = Some((intent.id, notice));
            }
        }
        Ok(selected.map(|(_, notice)| notice))
    }
}
