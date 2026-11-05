//! Concrete default-off consumer. All authority and publication stay in services.
use artifact_store_schema::editor_save::{
    EditorSaveBindingV0, EditorSaveReceiptV0, EditorTextHeaderV0,
};
use desktop_service::dev::Status;
use desktop_service::editor_dev::{self as desktop, EditorMessage};
use kernel_api::generated::{
    desktop_artifact_v1 as artifact, desktop_editor_session_v1 as session,
};
use kernel_api::ipc::Envelope;
use std::time::Instant;
use store_service::editor_store::{self as store, StoreStatus};

const ORIGINALS_PER_DOCUMENT: usize = 16;

#[derive(Debug, PartialEq, Eq)]
pub enum NativeEditorError {
    Desktop(Status),
    Store(StoreStatus),
    InvalidReceipt,
    Exhausted,
}
impl From<Status> for NativeEditorError {
    fn from(value: Status) -> Self {
        Self::Desktop(value)
    }
}
impl From<StoreStatus> for NativeEditorError {
    fn from(value: StoreStatus) -> Self {
        Self::Store(value)
    }
}

pub struct NativeArtifactEditor {
    chains: SaveChains,
    editor: desktop::NativeEditor,
}
struct SaveChains {
    desktop: desktop::HostDesktop,
    store: store::StoreHost,
    launch: store::PairedNativeSaveLaunch,
    next_request: u64,
    pending: Vec<SaveChain>,
    registration_failure: Option<store::NativeSaveRegistrationFailure>,
    startup: Option<ReadStartup>,
    registration_failures: Vec<store::NativeSaveRegistrationFailure>,
    lookup_cleanup: LookupCleanup,
}

#[derive(Clone, Copy)]
enum LookupCleanup {
    CoreOwned,
    ProcessOwned,
}

struct ReadStartup {
    request: Envelope,
    entry: Option<desktop::NativeSaveEntry>,
    registered: Option<store::RegisteredNativeSave>,
    reply: Option<store::NativeSaveReply>,
    producers: Vec<desktop::ProducerId>,
    joined: Vec<desktop::JoinedProducerProof>,
    execution: Option<store::NativeSaveExecution>,
    deadline: Option<Instant>,
}

struct Flight {
    _entry: desktop::NativeSaveEntry,
    registered: store::RegisteredNativeSave,
    execution: Option<store::NativeSaveExecution>,
    request: Envelope,
}
#[derive(Clone, Copy)]
enum Stage {
    Allocate,
    Commit,
    ObserveAllocation,
    ObserveCommit,
}
struct SaveChain {
    intent: desktop::NativeSaveIntent,
    allocation_request: Envelope,
    original: Option<store::OriginalNativeSave>,
    // The genuine Allocate original remains distinct after Commit admission.
    // A rejected Commit without a receipt cannot prove that allocation closed.
    allocation_original: Option<store::OriginalNativeSave>,
    recover_rejected_commit: bool,
    flight: Option<Flight>,
    source: Option<store::NativeDraftSource>,
    binding: Option<EditorSaveBindingV0>,
    stage: Stage,
    continuation_allowed: bool,
    allocation_admitted: bool,
    lookup: Option<LookupFlight>,
    staged: Option<EntryStartup>,
}

struct EntryStartup {
    entry: Option<desktop::NativeSaveEntry>,
    registered: Option<store::RegisteredNativeSave>,
    request: Envelope,
}

struct LookupFlight {
    request_id: u64,
    entry: desktop::NativeSaveEntry,
    reply: Option<store::NativeOriginalReply>,
    joined: Vec<desktop::JoinedProducerProof>,
}

impl NativeArtifactEditor {
    pub fn open(
        desktop: desktop::HostDesktop,
        store: store::StoreHost,
        launch: store::PairedNativeSaveLaunch,
        now: u64,
    ) -> Result<Self, NativeEditorError> {
        let mut chains = SaveChains::new(desktop, store, launch);
        let editor = match chains.read_editor(now, false) {
            Ok(editor) => editor,
            Err(error) => {
                if chains.startup.is_some() || chains.registration_failure.is_some() {
                    eprintln!("INCOMPLETE: retained failed legacy Read parents");
                    std::mem::forget(chains);
                }
                return Err(error);
            }
        };
        Ok(Self { chains, editor })
    }
    pub fn step(&mut self, now: u64) -> Result<desktop::NativeEditorStep, NativeEditorError> {
        let step = self.chains.desktop.step_native_editor(&self.editor, now)?;
        self.chains.progress_all(now)?;
        if step.save_intent_available {
            if self.chains.pending.len() >= ORIGINALS_PER_DOCUMENT {
                return Err(NativeEditorError::Exhausted);
            }
            let intent = self.chains.desktop.take_save_intent(&self.editor)?;
            self.chains.start_intent(intent, now)?;
        }
        Ok(step)
    }
    pub fn render(
        &mut self,
        now: u64,
    ) -> Result<desktop::NativeFrameObservation, NativeEditorError> {
        self.chains
            .desktop
            .render_native_editor(&self.editor, now)
            .map_err(Into::into)
    }
    pub fn observe(&self, now: u64) -> Result<desktop::NativeEditorObservation, NativeEditorError> {
        self.chains
            .desktop
            .editor_observation(&self.editor, now)
            .map_err(Into::into)
    }
    pub fn reconcile(&mut self, now: u64) -> Result<(), NativeEditorError> {
        self.chains.reconcile_originals(now)
    }
}
impl SaveChains {
    fn new(
        desktop: desktop::HostDesktop,
        store: store::StoreHost,
        launch: store::PairedNativeSaveLaunch,
    ) -> Self {
        Self {
            desktop,
            store,
            launch,
            next_request: 2,
            pending: Vec::new(),
            registration_failure: None,
            startup: None,
            registration_failures: Vec::new(),
            lookup_cleanup: LookupCleanup::CoreOwned,
        }
    }
    fn read_editor(
        &mut self,
        now: u64,
        retain_read: bool,
    ) -> Result<desktop::NativeEditor, NativeEditorError> {
        // This private, one-time open choice changes only which genuine owner
        // collects completed lookup producers. It does not change admission,
        // registration, receipt validation or target allocation closure.
        self.lookup_cleanup = if retain_read {
            LookupCleanup::ProcessOwned
        } else {
            LookupCleanup::CoreOwned
        };
        let boot =
            session::InstanceBootstrap::decode(self.launch.desktop().bindings().bootstrap())?;
        let request = canonical(
            artifact::ReadSelected {
                request_id: 1,
                session_id: boot.session_id,
                session_generation: boot.session_generation,
                instance_id: boot.instance_id,
                instance_generation: boot.instance_generation,
            }
            .encode(self.launch.endpoint().handle)?,
        )?;
        if self.startup.is_some() || self.registration_failure.is_some() {
            return Err(NativeEditorError::Exhausted);
        }
        self.startup = Some(ReadStartup {
            request,
            entry: None,
            registered: None,
            reply: None,
            producers: Vec::new(),
            joined: Vec::new(),
            execution: None,
            deadline: None,
        });
        let entry = self.desktop.begin_save_read(
            self.launch.desktop().bindings().artifact_origin(),
            &request,
            now,
        )?;
        self.startup.as_mut().unwrap().entry = Some(entry);
        let call = self
            .startup
            .as_ref()
            .unwrap()
            .entry
            .as_ref()
            .unwrap()
            .wait_once()?;
        self.startup.as_mut().unwrap().deadline = Some(call.deadline());
        match self
            .store
            .register_native_save(self.launch.endpoint(), call)
        {
            Ok(registered) => self.startup.as_mut().unwrap().registered = Some(registered),
            Err(failure) => {
                let status = failure.status();
                self.retain_registration_failure(failure);
                return Err(status.into());
            }
        }
        let execution = self
            .store
            .start_native_save(self.startup.as_ref().unwrap().registered.as_ref().unwrap())?;
        self.startup.as_mut().unwrap().execution = Some(execution);
        let reply = loop {
            if let Some(reply) = self
                .startup
                .as_ref()
                .unwrap()
                .execution
                .as_ref()
                .unwrap()
                .poll_once()?
            {
                break reply;
            }
            if Instant::now() >= self.startup.as_ref().unwrap().deadline.unwrap() {
                return Err(StoreStatus::Timeout.into());
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        };
        self.startup.as_mut().unwrap().reply = Some(reply);
        let reply = self.startup.as_ref().unwrap().reply.as_ref().unwrap();
        let response = artifact::ReadSelectedReply::decode(reply.wire())?;
        if response.request_id
            != artifact::ReadSelected::decode(&self.startup.as_ref().unwrap().request)?.request_id
        {
            return Err(NativeEditorError::InvalidReceipt);
        }
        successful(response.status)?;
        let lease = reply.selected().ok_or(NativeEditorError::InvalidReceipt)?;
        let descriptor = lease.descriptor();
        if descriptor.byte_len != response.byte_len
            || descriptor.handle.pack() != response.data_shm
            || descriptor.object_generation != response.object_generation
            || !(64..=4160).contains(&descriptor.byte_len)
        {
            return Err(NativeEditorError::InvalidReceipt);
        }
        // This is a genuine full lease copy, never document initialization authority.
        let mut bytes = vec![0; descriptor.byte_len as usize];
        lease.copy_into(0, &mut bytes)?;
        let header = EditorTextHeaderV0::decode_le(&bytes[..64])
            .map_err(|_| NativeEditorError::InvalidReceipt)?;
        header
            .validate_bytes(&bytes[64..])
            .map_err(|_| NativeEditorError::InvalidReceipt)?;
        if header.revision != response.revision {
            return Err(NativeEditorError::InvalidReceipt);
        }
        let editor = self
            .startup
            .as_mut()
            .unwrap()
            .reply
            .as_mut()
            .unwrap()
            .take_editor()?;
        if retain_read {
            let stage = self.startup.as_mut().unwrap();
            let parts = stage.reply.take().unwrap().into_parts();
            stage.producers = parts.producers;
            // Release data leases; actual entry/registration/producers retain
            // the successful Read scope until genuine nonblocking joins.
            drop((
                parts.original,
                parts.selected,
                parts.receipt,
                parts.editor,
                parts.allocation,
            ));
        } else {
            self.startup.take();
        }
        Ok(editor)
    }
    fn cleanup_startup(&mut self) -> Result<bool, NativeEditorError> {
        let Some(stage) = self.startup.as_mut() else {
            return Ok(true);
        };
        if stage.registered.is_some() && stage.execution.is_none() && stage.reply.is_none() {
            return Ok(false);
        }
        if stage.reply.is_none() && stage.producers.is_empty() {
            if let Some(execution) = stage.execution.as_ref() {
                match execution.poll_once() {
                    Ok(Some(reply)) => stage.reply = Some(reply),
                    Ok(None) | Err(StoreStatus::NotReady) => return Ok(false),
                    Err(_) => return Ok(false),
                }
            }
        }
        let ids = stage
            .entry
            .as_ref()
            .into_iter()
            .flat_map(|e| e.producer_ids().into_iter())
            .chain(stage.producers.iter())
            .chain(
                stage
                    .reply
                    .as_ref()
                    .into_iter()
                    .flat_map(|r| r.producers().iter()),
            );
        let mut complete = true;
        for id in ids {
            if stage
                .joined
                .iter()
                .any(|p| p.producer_id() == id.producer_id())
                || self.store.native_save_producer_joined(id)?
            {
                continue;
            }
            match self.store.join_native_save_finished(id) {
                Ok(proof) => stage.joined.push(proof),
                Err(StoreStatus::NotReady) => complete = false,
                Err(StoreStatus::Denied) => match self.desktop.join_native_finished(id) {
                    Ok(proof) => stage.joined.push(proof),
                    Err(Status::NotReady) => complete = false,
                    Err(status) => return Err(status.into()),
                },
                Err(status) => return Err(status.into()),
            }
        }
        if self.registration_failure.is_some() || !self.registration_failures.is_empty() {
            return Ok(false);
        }
        if complete {
            self.startup.take();
        }
        Ok(complete)
    }
    fn pending_groups(&self) -> usize {
        self.pending.len()
            + usize::from(self.registration_failure.is_some())
            + self.registration_failures.len()
            + usize::from(self.startup.is_some())
    }
    fn start_intent(
        &mut self,
        intent: desktop::NativeSaveIntent,
        now: u64,
    ) -> Result<(), NativeEditorError> {
        let view = intent.snapshot().view();
        let request = canonical(
            artifact::AllocateSaveId {
                request_id: self.request_id()?,
                session_id: view.actor.session_id,
                session_generation: view.actor.session_generation,
                expected_revision: view.expected_revision,
            }
            .encode(self.launch.endpoint().handle)?,
        )?;
        let mut chain = SaveChain {
            intent,
            allocation_request: request,
            original: None,
            allocation_original: None,
            recover_rejected_commit: false,
            flight: None,
            source: None,
            binding: None,
            stage: Stage::Allocate,
            continuation_allowed: true,
            allocation_admitted: false,
            lookup: None,
            staged: None,
        };
        let start = self.start_allocate(&mut chain, now);
        // Only a failure before Desktop entry admission can be definitive here.
        // Once admitted, retain the original chain for owner reconciliation.
        if !matches!(start, Err(NativeEditorError::Desktop(Status::Timeout)))
            || chain.allocation_admitted
        {
            self.pending.push(chain);
        }
        start
    }

    fn progress_all(&mut self, now: u64) -> Result<(), NativeEditorError> {
        let mut index = 0;
        while index < self.pending.len() {
            let mut chain = self.pending.remove(index);
            match self.progress(&mut chain, now) {
                Ok(true) => {
                    self.pending.insert(index, chain);
                    index += 1;
                }
                Ok(false) => {}
                Err(error) => {
                    self.pending.insert(index, chain);
                    return Err(error);
                }
            }
        }
        Ok(())
    }
    fn reconcile_originals(&mut self, now: u64) -> Result<(), NativeEditorError> {
        let mut index = 0;
        while index < self.pending.len() {
            let mut chain = self.pending.remove(index);
            let outcome = match self.progress(&mut chain, now) {
                Ok(false) => Ok(false),
                Ok(true) if chain.flight.as_ref().is_some_and(|f| f.execution.is_some()) => {
                    Ok(true)
                }
                Ok(true) => self.observe_original(&mut chain, now),
                Err(NativeEditorError::Store(StoreStatus::Stale))
                    if matches!(self.lookup_cleanup, LookupCleanup::ProcessOwned)
                        && matches!(chain.stage, Stage::ObserveCommit)
                        && chain.flight.is_none()
                        && chain.original.is_some() =>
                {
                    // A consumed ordinary Commit reply can carry a receipt
                    // lease whose ordinary grant was retired with the child.
                    // Keep the same actual original and validate its receipt
                    // through recovery authority; never replay the Commit.
                    self.observe_original(&mut chain, now)
                }
                Err(error) => Err(error),
            };
            match outcome {
                Ok(true) => {
                    self.pending.insert(index, chain);
                    index += 1;
                }
                Ok(false) => {}
                Err(error) => {
                    self.pending.insert(index, chain);
                    return Err(error);
                }
            }
        }
        Ok(())
    }
    fn request_id(&mut self) -> Result<u64, NativeEditorError> {
        let next = self
            .next_request
            .checked_add(1)
            .ok_or(NativeEditorError::Exhausted)?;
        let id = self.next_request;
        self.next_request = next;
        Ok(id)
    }
    fn retain_registration_failure(&mut self, failure: store::NativeSaveRegistrationFailure) {
        if self.registration_failure.is_none() {
            self.registration_failure = Some(failure);
        } else {
            self.registration_failures.push(failure);
        }
    }
    fn register_staged(&mut self, stage: &mut EntryStartup) -> Result<(), NativeEditorError> {
        if self.registration_failure.is_some() || !self.registration_failures.is_empty() {
            return Err(NativeEditorError::Exhausted);
        }
        let call = stage
            .entry
            .as_ref()
            .ok_or(NativeEditorError::InvalidReceipt)?
            .wait_once()?;
        match self
            .store
            .register_native_save(self.launch.endpoint(), call)
        {
            Ok(registered) => stage.registered = Some(registered),
            Err(failure) => {
                let status = failure.status();
                self.retain_registration_failure(failure);
                return Err(status.into());
            }
        }
        Ok(())
    }
    fn start_allocate(&mut self, chain: &mut SaveChain, now: u64) -> Result<(), NativeEditorError> {
        if self.registration_failure.is_some() {
            return Err(NativeEditorError::Exhausted);
        }
        let entry = self.desktop.begin_save_allocate(
            self.launch.desktop().bindings().artifact_origin(),
            &chain.intent,
            &chain.allocation_request,
            now,
        )?;
        chain.allocation_admitted = true;
        self.start_flight(chain, entry, chain.allocation_request)
    }
    fn start_flight(
        &mut self,
        chain: &mut SaveChain,
        entry: desktop::NativeSaveEntry,
        request: Envelope,
    ) -> Result<(), NativeEditorError> {
        chain.staged = Some(EntryStartup {
            entry: Some(entry),
            registered: None,
            request,
        });
        if let Err(error) = self.register_staged(chain.staged.as_mut().unwrap()) {
            chain.stage = match chain.stage {
                Stage::Allocate => Stage::ObserveAllocation,
                _ => Stage::ObserveCommit,
            };
            return Err(error);
        }
        let mut staged = chain.staged.take().unwrap();
        chain.flight = Some(Flight {
            _entry: staged.entry.take().unwrap(),
            registered: staged.registered.take().unwrap(),
            execution: None,
            request: staged.request,
        });
        let flight = chain.flight.as_mut().expect("actual registered flight");
        match self.store.start_native_save(&flight.registered) {
            Ok(execution) => {
                flight.execution = Some(execution);
                Ok(())
            }
            Err(error) => {
                chain.stage = match chain.stage {
                    Stage::Allocate => Stage::ObserveAllocation,
                    _ => Stage::ObserveCommit,
                };
                Err(error.into())
            }
        }
    }
    fn start_commit(
        &mut self,
        chain: &mut SaveChain,
        allocation: &store::NativeAllocatedOperation,
        now: u64,
    ) -> Result<(), NativeEditorError> {
        if self.registration_failure.is_some() || !self.registration_failures.is_empty() {
            return Err(NativeEditorError::Exhausted);
        }
        // An observation never renews the original explicit CtrlS deadline.
        if !chain.continuation_allowed || Instant::now() >= chain.intent.deadline() {
            chain.continuation_allowed = false;
            chain.stage = Stage::ObserveAllocation;
            return Ok(());
        }
        // Even a source-construction error must never cause an automatic retry.
        chain.continuation_allowed = false;
        let source =
            self.store
                .source_for_intent(self.launch.endpoint(), allocation, &chain.intent)?;
        let view = chain.intent.snapshot().view();
        let body = chain.intent.snapshot().body();
        let header = EditorTextHeaderV0 {
            schema_version: 1,
            total_len: 64 + view.byte_len,
            selected_object_id: view.object_id,
            revision: view.expected_revision,
            content_hash: view.source_content_hash,
            byte_len: view.byte_len,
            reserved: 0,
        };
        let mut bytes = header
            .encode_le()
            .map_err(|_| NativeEditorError::InvalidReceipt)?
            .to_vec();
        bytes.extend_from_slice(body);
        let descriptor = source.descriptor();
        if bytes.len() != descriptor.byte_len as usize {
            return Err(NativeEditorError::InvalidReceipt);
        }
        source.write_lease()?.copy_from(0, &bytes)?;
        let request = canonical(
            artifact::Commit {
                request_id: self.request_id()?,
                session_id: view.actor.session_id,
                session_generation: view.actor.session_generation,
                expected_revision: view.expected_revision,
                operation_id: allocation.observation().operation_id,
                source_shm: descriptor.handle.pack(),
                byte_len: descriptor.byte_len,
                reserved: 0,
            }
            .encode(self.launch.endpoint().handle)?,
        )?;
        let entry = self.desktop.begin_save_commit(
            self.launch.desktop().bindings().artifact_origin(),
            source.bound(),
            &request,
            now,
        )?;
        // Move the opaque Allocate owner before the Commit flight can replace
        // the current original. Never reconstruct recovery authority from IDs.
        if chain.allocation_original.is_none() {
            chain.allocation_original = chain.original.take();
        }
        chain.binding = Some(source.bound().binding().clone());
        chain.source = Some(source);
        chain.stage = Stage::Commit;
        self.start_flight(chain, entry, request)
    }

    /// Returns false only after an actual terminal response or original observation.
    fn progress(&mut self, chain: &mut SaveChain, now: u64) -> Result<bool, NativeEditorError> {
        let reply = match chain.flight.as_ref() {
            Some(flight) => match &flight.execution {
                Some(execution) => match execution.poll_once()? {
                    Some(reply) => reply,
                    None => return Ok(true),
                },
                None => return Ok(true),
            },
            None => return Ok(true),
        };
        let flight = chain.flight.take().expect("actual ready flight");
        self.accept_reply(chain, flight, reply, now)
    }
    fn accept_reply(
        &mut self,
        chain: &mut SaveChain,
        flight: Flight,
        reply: store::NativeSaveReply,
        now: u64,
    ) -> Result<bool, NativeEditorError> {
        let prior = chain.stage;
        let mut parts = reply.into_parts();
        chain.original = Some(parts.original);
        chain.stage = match prior {
            Stage::Allocate => Stage::ObserveAllocation,
            Stage::Commit => Stage::ObserveCommit,
            _ => return Err(NativeEditorError::InvalidReceipt),
        };
        let request = match prior {
            Stage::Allocate => {
                artifact::AllocateSaveId::decode(&chain.allocation_request)?.request_id
            }
            Stage::Commit => artifact::Commit::decode(&flight.request)?.request_id,
            _ => return Err(NativeEditorError::InvalidReceipt),
        };
        match prior {
            Stage::Allocate => {
                let response = artifact::AllocateSaveIdReply::decode(&parts.wire)?;
                if response.request_id != request {
                    return Err(NativeEditorError::InvalidReceipt);
                }
                chain.stage = Stage::ObserveAllocation;
                if response.status == StoreStatus::Ok as u32 {
                    let allocation = parts
                        .allocation
                        .take()
                        .ok_or(NativeEditorError::InvalidReceipt)?;
                    if allocation.observation().operation_id != response.operation_id {
                        return Err(NativeEditorError::InvalidReceipt);
                    }
                    self.start_commit(chain, &allocation, now)?;
                } else if !uncertain(response.status)? {
                    return Ok(false);
                }
            }
            Stage::Commit => {
                let response = artifact::CommitReply::decode(&parts.wire)?;
                if response.request_id != request {
                    return Err(NativeEditorError::InvalidReceipt);
                }
                chain.stage = Stage::ObserveCommit;
                if response.status == StoreStatus::Ok as u32 {
                    let lease = parts
                        .receipt
                        .as_ref()
                        .ok_or(NativeEditorError::InvalidReceipt)?;
                    self.validate_receipt(
                        chain,
                        lease,
                        response.operation_id,
                        response.revision,
                        response.receipt_shm,
                        response.receipt_len,
                    )?;
                    return Ok(false);
                }
                if !uncertain(response.status)? {
                    if matches!(self.lookup_cleanup, LookupCleanup::CoreOwned) {
                        return Ok(false);
                    }
                    // A definitive rejection is not a terminal allocation
                    // proof. First ask this same Commit original for a receipt,
                    // then alternate with the retained Allocate original until
                    // an authenticated closure or strict receipt resolves it.
                    if parts.receipt.is_some() || chain.allocation_original.is_none() {
                        return Err(NativeEditorError::InvalidReceipt);
                    }
                    chain.recover_rejected_commit = true;
                    chain.continuation_allowed = false;
                }
            }
            _ => return Err(NativeEditorError::InvalidReceipt),
        }
        // Caller aliases are released; genuine installed handles remain in Core until actual join.
        drop((
            flight,
            parts.selected,
            parts.receipt,
            parts.editor,
            parts.producers,
        ));
        // Allocate processing may have just started Commit: retain its genuine data
        // owner until that Commit produces its own caller response.
        if matches!(chain.stage, Stage::ObserveCommit) && !chain.recover_rejected_commit {
            chain.source.take();
        }
        Ok(true)
    }

    fn validate_receipt(
        &self,
        chain: &SaveChain,
        lease: &store::NativeReceiptRead,
        operation: u64,
        revision: u64,
        shm: u64,
        len: u32,
    ) -> Result<(), NativeEditorError> {
        let descriptor = lease.descriptor();
        if len != 176 || descriptor.byte_len != 176 || descriptor.handle.pack() != shm {
            return Err(NativeEditorError::InvalidReceipt);
        }
        let mut bytes = [0; 176];
        lease.copy_into(0, &mut bytes)?;
        let receipt = EditorSaveReceiptV0::decode_le(&bytes)
            .map_err(|_| NativeEditorError::InvalidReceipt)?;
        let binding = chain
            .binding
            .as_ref()
            .ok_or(NativeEditorError::InvalidReceipt)?;
        receipt
            .validate_binding(binding)
            .map_err(|_| NativeEditorError::InvalidReceipt)?;
        if receipt.operation_id != operation
            || receipt.result_revision != revision
            || receipt.backend_service_epoch != chain.intent.snapshot().view().original_store_epoch
        {
            return Err(NativeEditorError::InvalidReceipt);
        }
        // Receipt is an observation. Only service-private original/current-frame joins admit Saved.
        Ok(())
    }

    fn observe_original(
        &mut self,
        chain: &mut SaveChain,
        now: u64,
    ) -> Result<bool, NativeEditorError> {
        if chain.lookup.is_none() {
            // No new registration/admission can accumulate behind an unknown
            // registration owner. Existing lookup completion may still progress.
            if self.registration_failure.is_some() || !self.registration_failures.is_empty() {
                return Ok(true);
            }
            let original = if chain.recover_rejected_commit
                && matches!(chain.stage, Stage::ObserveAllocation)
            {
                match &chain.allocation_original {
                    Some(value) => value,
                    None => return Err(NativeEditorError::InvalidReceipt),
                }
            } else {
                match &chain.flight {
                    Some(flight) => flight.registered.original(),
                    None => match &chain.original {
                        Some(value) => value,
                        None => return Ok(true),
                    },
                }
            };
            let snapshot = chain.intent.snapshot().view();
            let id = self.request_id()?;
            let request = match chain.stage {
                Stage::ObserveAllocation => artifact::ObserveAllocation {
                    request_id: id,
                    session_id: snapshot.actor.session_id,
                    session_generation: snapshot.actor.session_generation,
                    original_allocate_request_id: artifact::AllocateSaveId::decode(
                        &chain.allocation_request,
                    )?
                    .request_id,
                }
                .encode(self.launch.endpoint().handle)?,
                Stage::ObserveCommit => artifact::SaveStatus {
                    request_id: id,
                    session_id: snapshot.actor.session_id,
                    session_generation: snapshot.actor.session_generation,
                    operation_id: chain
                        .binding
                        .as_ref()
                        .ok_or(NativeEditorError::InvalidReceipt)?
                        .allocation
                        .operation_id,
                }
                .encode(self.launch.endpoint().handle)?,
                _ => return Ok(true),
            };
            let request = canonical(request)?;
            let entry =
                self.desktop
                    .begin_save_recovery(original.observation_origin(), &request, now)?;
            chain.lookup = Some(LookupFlight {
                request_id: id,
                entry,
                reply: None,
                joined: Vec::new(),
            });
            let call = chain.lookup.as_ref().unwrap().entry.wait_once()?;
            match self.store.observe_original(call, original) {
                Ok(reply) => chain.lookup.as_mut().unwrap().reply = Some(reply),
                Err(failure) => {
                    let status = failure.status();
                    self.retain_registration_failure(failure);
                    return Err(status.into());
                }
            }
        }
        let ready = {
            let lookup = chain.lookup.as_mut().unwrap();
            self.join_lookup(lookup)?
        };
        if !ready {
            return Ok(true);
        }
        let mut lookup = chain.lookup.take().unwrap();
        match self.finish_lookup(chain, &mut lookup, now) {
            Ok(retain) => Ok(retain),
            Err(error) => {
                chain.lookup = Some(lookup);
                Err(error)
            }
        }
    }
    fn join_lookup(&self, lookup: &mut LookupFlight) -> Result<bool, NativeEditorError> {
        // A failed/partial registration has not supplied a completed query.
        // Both modes retain its exact entry and any registration-failure group.
        if lookup.reply.is_none() {
            return Ok(false);
        }
        if matches!(self.lookup_cleanup, LookupCleanup::CoreOwned) {
            // Legacy callers already collect these actual Core-installed
            // handles through their native quiesce owner. Do not consume their
            // unique join proofs privately: dropping caller aliases leaves
            // Core's real registered group and its handles intact. Process
            // mode instead retains the entry/reply until its own joins below.
            return Ok(true);
        }
        if lookup
            .joined
            .iter()
            .any(|proof| !matches!(proof.outcome(), desktop::JoinOutcome::Returned))
        {
            return Err(NativeEditorError::Desktop(Status::Internal));
        }
        let mut complete = true;
        for id in lookup.entry.producer_ids().into_iter().chain(
            lookup
                .reply
                .as_ref()
                .into_iter()
                .flat_map(|r| r.producers().iter()),
        ) {
            if lookup
                .joined
                .iter()
                .any(|proof| proof.producer_id() == id.producer_id())
                || self.store.native_save_producer_joined(id)?
            {
                continue;
            }
            match self.store.join_native_save_finished(id) {
                Ok(proof) => {
                    let returned = matches!(proof.outcome(), desktop::JoinOutcome::Returned);
                    lookup.joined.push(proof);
                    if !returned {
                        return Err(NativeEditorError::Desktop(Status::Internal));
                    }
                }
                Err(StoreStatus::NotReady) => complete = false,
                Err(error) => return Err(error.into()),
            }
        }
        Ok(complete)
    }
    fn finish_lookup(
        &mut self,
        chain: &mut SaveChain,
        lookup: &mut LookupFlight,
        now: u64,
    ) -> Result<bool, NativeEditorError> {
        let id = lookup.request_id;
        let Some(reply) = lookup.reply.as_mut() else {
            return Ok(true);
        };
        match reply.observation() {
            store::NativeOriginalObservation::AllocationPending
            | store::NativeOriginalObservation::CommitPending { .. } => {
                if chain.recover_rejected_commit {
                    chain.stage = match chain.stage {
                        Stage::ObserveCommit => Stage::ObserveAllocation,
                        Stage::ObserveAllocation => Stage::ObserveCommit,
                        _ => return Err(NativeEditorError::InvalidReceipt),
                    };
                }
                Ok(true)
            }
            store::NativeOriginalObservation::NoAllocation => {
                if chain.recover_rejected_commit {
                    // We own the actual successful Allocate original. A
                    // contradictory no-allocation observation is not closure.
                    Err(NativeEditorError::InvalidReceipt)
                } else {
                    Ok(false)
                }
            }
            store::NativeOriginalObservation::AllocationRetained {
                commit_dispatched, ..
            } => {
                if !commit_dispatched
                    && chain.continuation_allowed
                    && Instant::now() < chain.intent.deadline()
                {
                    if let Some(allocation) = reply.take_allocation() {
                        self.start_commit(chain, &allocation, now)?;
                        return Ok(true);
                    }
                }
                // This distinct Store witness is valid only for the genuine
                // Allocate-original q9 branch. join_lookup has already joined
                // this query's own producers before this method is called.
                let closed = reply.allocation_closed()
                    || (chain.recover_rejected_commit
                        && matches!(chain.stage, Stage::ObserveAllocation)
                        && reply.unpermitted_commit_closed());
                if chain.recover_rejected_commit && !closed {
                    chain.stage = Stage::ObserveCommit;
                }
                Ok(!closed)
            }
            store::NativeOriginalObservation::Receipt { binding, receipt } => {
                if chain.binding.as_ref() != Some(binding) {
                    return Err(NativeEditorError::InvalidReceipt);
                }
                let response = artifact::SaveStatusReply::decode(reply.wire())?;
                if response.request_id != id || response.status != 0 {
                    return Err(NativeEditorError::InvalidReceipt);
                }
                self.validate_receipt(
                    chain,
                    receipt,
                    response.operation_id,
                    response.revision,
                    response.receipt_shm,
                    response.receipt_len,
                )?;
                Ok(false)
            }
        }
    }
}

fn canonical(request: Envelope) -> Result<Envelope, NativeEditorError> {
    Ok(desktop::decode_envelope_wire(
        &desktop::encode_envelope_wire(&request)?,
    )?)
}
fn successful(value: u32) -> Result<(), NativeEditorError> {
    if value == 0 {
        Ok(())
    } else {
        Err(NativeEditorError::Store(status(value)?))
    }
}
fn uncertain(value: u32) -> Result<bool, NativeEditorError> {
    Ok(matches!(
        status(value)?,
        StoreStatus::Unknown
            | StoreStatus::Timeout
            | StoreStatus::Disconnected
            | StoreStatus::NotReady
    ))
}
fn status(value: u32) -> Result<StoreStatus, NativeEditorError> {
    Ok(match value {
        0 => StoreStatus::Ok,
        1 => StoreStatus::Denied,
        2 => StoreStatus::Invalid,
        3 => StoreStatus::Unsupported,
        4 => StoreStatus::Stale,
        5 => StoreStatus::Exhausted,
        6 => StoreStatus::NotReady,
        7 => StoreStatus::Conflict,
        8 => StoreStatus::Timeout,
        9 => StoreStatus::Disconnected,
        10 => StoreStatus::Unknown,
        11 => StoreStatus::Internal,
        _ => return Err(NativeEditorError::InvalidReceipt),
    })
}

#[cfg(all(target_os = "linux", feature = "host_editor_process_v0_dev"))]
#[path = "native/process.rs"]
mod process;
#[cfg(all(target_os = "linux", feature = "host_editor_process_v0_dev"))]
pub use process::{ProcessArtifactEditor, ProcessEditorOpenFailure, ProcessOpenCleanup};

#[cfg(test)]
#[path = "native_tests.rs"]
mod tests;

#[cfg(all(
    test,
    target_os = "linux",
    feature = "host_editor_process_assertions_v0_dev"
))]
#[path = "native/process_assertions.rs"]
mod process_assertions;
