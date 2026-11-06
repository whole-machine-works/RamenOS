//! Process lifecycle around the same SaveChains used by the legacy editor.
use super::*;
use std::mem::ManuallyDrop;
use std::time::Duration;

pub struct ProcessArtifactEditor {
    pub(super) chains: ManuallyDrop<SaveChains>,
    pub(super) child: Option<desktop::OwnedEditorChild>,
    editor: Option<desktop::NativeEditor>,
    enrollment: Option<desktop::ProcessEditorEnrollment>,
    executable: Option<desktop::PinnedProcessExecutable>,
    failed: bool,
    spawned: bool,
    joined: bool,
    cleanup_complete: bool,
    cleanup_deadline: Option<Instant>,
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    assertion_run: Option<desktop::ProcessAssertionRun>,
    #[cfg(all(test, feature = "host_editor_process_assertions_v0_dev"))]
    assertion_dropped_child: Option<desktop::ProcessChildObservation>,
}
pub struct ProcessEditorOpenFailure {
    error: NativeEditorError,
    owner: ProcessArtifactEditor,
}
impl ProcessEditorOpenFailure {
    pub fn into_parts(self) -> (NativeEditorError, ProcessArtifactEditor) {
        (self.error, self.owner)
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum ProcessOpenCleanup {
    Complete,
    Pending,
    Quarantined,
}

impl Drop for ProcessArtifactEditor {
    fn drop(&mut self) {
        let safe = self.cleanup_complete
            || self.child.is_none()
                && (!self.spawned || self.joined)
                && self.chains.pending_groups() == 0;
        if safe {
            // No live/unknown Save or startup owner, and authentic child join
            // (or known unspawned pipeline). This drops parents exactly once.
            unsafe {
                ManuallyDrop::drop(&mut self.chains);
            }
        } else {
            eprintln!("INCOMPLETE: retaining process editor parents and original Save owners");
            // Opaque child Drop parks the sole real supervisor and requests
            // retirement; it does not claim wait/reap or release its charges.
            drop(self.child.take());
            std::mem::forget(self.editor.take());
            std::mem::forget(self.enrollment.take());
            std::mem::forget(self.executable.take());
            #[cfg(feature = "host_editor_process_assertions_v0_dev")]
            std::mem::forget(self.assertion_run.take());
            // ManuallyDrop preserves the entire genuine parent group.
        }
    }
}
impl ProcessArtifactEditor {
    fn staged(
        desktop: desktop::HostDesktop,
        store: store::StoreHost,
        launch: store::PairedNativeSaveLaunch,
    ) -> Self {
        Self {
            chains: ManuallyDrop::new(SaveChains::new(desktop, store, launch)),
            child: None,
            editor: None,
            enrollment: None,
            executable: None,
            failed: true,
            spawned: false,
            joined: false,
            cleanup_complete: false,
            cleanup_deadline: None,
            #[cfg(feature = "host_editor_process_assertions_v0_dev")]
            assertion_run: None,
            #[cfg(all(test, feature = "host_editor_process_assertions_v0_dev"))]
            assertion_dropped_child: None,
        }
    }
    #[allow(
        clippy::result_large_err,
        reason = "The frozen failure contract returns the same inline staged app, launch and original owners without another fallible allocation."
    )]
    pub fn open(
        desktop: desktop::HostDesktop,
        store: store::StoreHost,
        launch: store::PairedNativeSaveLaunch,
        budget: desktop::ChildBudget,
        now: u64,
    ) -> Result<Self, ProcessEditorOpenFailure> {
        let mut owner = Self::staged(desktop, store, launch);
        let result = owner.initialize(
            budget,
            now,
            #[cfg(feature = "host_editor_process_assertions_v0_dev")]
            None,
        );
        match result {
            Ok(()) => {
                owner.failed = false;
                Ok(owner)
            }
            Err(error) => Err(ProcessEditorOpenFailure { error, owner }),
        }
    }
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    #[cfg_attr(not(test), allow(dead_code))]
    #[allow(
        clippy::result_large_err,
        clippy::too_many_arguments,
        reason = "The frozen private constructor keeps every staged owner and the explicit one-shot assertion channel in its owner-returning handoff."
    )]
    pub(super) fn open_assertion(
        desktop: desktop::HostDesktop,
        store: store::StoreHost,
        launch: store::PairedNativeSaveLaunch,
        budget: desktop::ChildBudget,
        now: u64,
        controller: &desktop::FixtureController,
        scenario: &desktop::ProcessAssertionScenario,
        run_sender: std::sync::mpsc::SyncSender<desktop::ProcessAssertionRun>,
    ) -> Result<Self, ProcessEditorOpenFailure> {
        let mut owner = Self::staged(desktop, store, launch);
        let result = owner.initialize(budget, now, Some((controller, scenario, run_sender)));
        match result {
            Ok(()) => {
                owner.failed = false;
                Ok(owner)
            }
            Err(error) => Err(ProcessEditorOpenFailure { error, owner }),
        }
    }
    fn initialize(
        &mut self,
        budget: desktop::ChildBudget,
        now: u64,
        #[cfg(feature = "host_editor_process_assertions_v0_dev")] assertion: Option<(
            &desktop::FixtureController,
            &desktop::ProcessAssertionScenario,
            std::sync::mpsc::SyncSender<desktop::ProcessAssertionRun>,
        )>,
    ) -> Result<(), NativeEditorError> {
        self.editor = Some(self.chains.read_editor(now, true)?);
        let editor = self
            .editor
            .take()
            .ok_or(NativeEditorError::InvalidReceipt)?;
        match self.chains.desktop.prepare_process_editor(editor) {
            Ok(enrollment) => self.enrollment = Some(enrollment),
            Err(failure) => {
                let (status, editor) = failure.into_parts();
                self.editor = Some(editor);
                return Err(status.into());
            }
        }
        #[cfg(feature = "host_editor_process_assertions_v0_dev")]
        if let Some((controller, scenario, sender)) = assertion {
            self.assertion_run = Some(
                controller.arm_process_assertion(self.enrollment.as_ref().unwrap(), scenario)?,
            );
            match sender.try_send(self.assertion_run.take().unwrap()) {
                Ok(()) => {}
                Err(std::sync::mpsc::TrySendError::Full(run)) => {
                    self.assertion_run = Some(run);
                    return Err(Status::NotReady.into());
                }
                Err(std::sync::mpsc::TrySendError::Disconnected(run)) => {
                    self.assertion_run = Some(run);
                    return Err(Status::Disconnected.into());
                }
            }
        }
        self.executable = Some(
            self.chains
                .desktop
                .registered_editor_process_executable(self.enrollment.as_ref().unwrap())?,
        );
        let enrollment = self.enrollment.take().unwrap();
        let executable = self.executable.take().unwrap();
        match self
            .chains
            .desktop
            .spawn_process_editor(enrollment, executable, budget, now)
        {
            Ok(child) => {
                self.child = Some(child);
                self.spawned = true;
                Ok(())
            }
            Err(failure) => {
                let (status, recovery) = failure.into_parts();
                match recovery {
                    desktop::ProcessLaunchRecovery::Unspawned {
                        enrollment,
                        executable,
                    } => {
                        self.enrollment = Some(enrollment);
                        self.executable = Some(executable);
                    }
                    desktop::ProcessLaunchRecovery::Spawned(child) => {
                        self.child = Some(child);
                        self.spawned = true;
                    }
                }
                Err(status.into())
            }
        }
    }
    pub fn step(&mut self, now: u64) -> Result<desktop::ProcessEditorStep, NativeEditorError> {
        if self.failed {
            return Err(Status::Denied.into());
        }
        let child = self
            .child
            .as_mut()
            .ok_or(NativeEditorError::Desktop(Status::NotReady))?;
        // Input/fault handling always precedes independent original progress.
        let result = self.chains.desktop.pump_process_editor(child, now);
        let obsolete_retry = result
            .as_ref()
            .is_err_and(|error| error.status() == Status::Stale)
            && self
                .chains
                .desktop
                .observe_process_editor(child, now)
                .is_ok();
        if result.as_ref().is_err() && !obsolete_retry
            || result.as_ref().is_ok_and(|s| s.child_exit_observed())
        {
            let _ = self.chains.desktop.retire_process_editor(
                child,
                desktop::ProcessRetireReason::ChildFault,
                now,
            );
        }
        if result.as_ref().is_err() && !obsolete_retry
            || result.as_ref().is_ok_and(|s| s.child_exit_observed())
        {
            for chain in &mut self.chains.pending {
                chain.continuation_allowed = false;
            }
        }
        self.chains.progress_all(now)?;
        let _read_closed = self.chains.cleanup_startup()?;
        let step = result.map_err(|error| NativeEditorError::Desktop(error.status()))?;
        if step.save_intent_available() {
            if self.chains.pending.len() >= ORIGINALS_PER_DOCUMENT {
                return Err(NativeEditorError::Exhausted);
            }
            let intent = self
                .chains
                .desktop
                .take_process_save_intent(self.child.as_mut().unwrap())?;
            self.chains.start_intent(intent, now)?;
        }
        Ok(step)
    }
    /// Request an ordinary publication of the child's acknowledged draft.
    /// This forwards the existing owner-bound request without admitting Save.
    pub fn request_frame(&mut self, now: u64) -> Result<(), NativeEditorError> {
        if self.failed {
            return Err(Status::Denied.into());
        }
        let child = self
            .child
            .as_mut()
            .ok_or(NativeEditorError::Desktop(Status::NotReady))?;
        self.chains
            .desktop
            .request_process_editor_frame(child, now)
            .map_err(|error| NativeEditorError::Desktop(error.status()))
    }
    pub fn observe(&self, now: u64) -> Result<desktop::NativeEditorObservation, NativeEditorError> {
        let child = self
            .child
            .as_ref()
            .ok_or(NativeEditorError::Desktop(Status::NotReady))?;
        self.chains
            .desktop
            .observe_process_editor(child, now)
            .map_err(Into::into)
    }
    pub fn reconcile_originals(&mut self, now: u64) -> Result<(), NativeEditorError> {
        let _read_closed = self.chains.cleanup_startup()?;
        self.chains.reconcile_originals(now)
    }
    pub fn retire(
        &mut self,
        reason: desktop::ProcessRetireReason,
        now: u64,
    ) -> Result<(), NativeEditorError> {
        self.cleanup_deadline
            .get_or_insert_with(|| Instant::now() + Duration::from_millis(2000));
        for chain in &mut self.chains.pending {
            chain.continuation_allowed = false;
        }
        let Some(child) = self.child.as_mut() else {
            return Ok(());
        };
        self.chains
            .desktop
            .retire_process_editor(child, reason, now)
            .map_err(|error| NativeEditorError::Desktop(error.status()))
    }
    pub fn join_child(&mut self) -> Result<desktop::OwnedEditorChildExitProof, NativeEditorError> {
        let child = self
            .child
            .take()
            .ok_or(NativeEditorError::Desktop(Status::NotReady))?;
        match self.chains.desktop.join_process_editor(child) {
            Ok(proof) => {
                self.joined = true;
                // Separate real startup Read joins; this never joins original
                // Save IO or derives its completion from the child proof.
                let _read_cleanup = self.chains.cleanup_startup();
                Ok(proof)
            }
            Err(failure) => {
                let (status, child) = failure.into_parts();
                self.child = Some(child);
                Err(status.into())
            }
        }
    }
    #[cfg(all(test, feature = "host_editor_process_assertions_v0_dev"))]
    pub(super) fn drop_child_for_assertion(&mut self) -> Result<Instant, NativeEditorError> {
        if !self.spawned || self.joined || self.assertion_dropped_child.is_some() {
            return Err(Status::Denied.into());
        }
        let child = self.child.as_ref().ok_or(Status::Denied)?;
        // The same Host authenticates this opaque owner before its actual Drop
        // parks the supervisor. Numeric caller-supplied identity is never used.
        let observed = self.chains.desktop.observe_process_child(child)?;
        if observed.process_id() == 0 || observed.birth_ticks() == 0 {
            return Err(Status::Denied.into());
        }
        let deadline = *self
            .cleanup_deadline
            .get_or_insert_with(|| Instant::now() + Duration::from_millis(2000));
        self.assertion_dropped_child = Some(observed);
        drop(self.child.take());
        Ok(deadline)
    }
    #[cfg(all(test, feature = "host_editor_process_assertions_v0_dev"))]
    pub(super) fn accept_dropped_child_exit_for_assertion(
        &mut self,
        proof: &desktop::OwnedEditorChildExitProof,
    ) -> Result<(), NativeEditorError> {
        let expected = self
            .assertion_dropped_child
            .as_ref()
            .ok_or(Status::Denied)?;
        if !self.spawned
            || self.joined
            || self.child.is_some()
            || !proof.supervisor_joined()
            || proof.process_id() == 0
            || proof.birth_ticks() == 0
            || proof.process_id() != expected.process_id()
            || proof.birth_ticks() != expected.birth_ticks()
            || proof.executable_sha256() != expected.executable_sha256()
        {
            return Err(Status::Denied.into());
        }
        // Only the genuine same-child native wait/supervisor proof changes this
        // state. A foreign or repeated proof cannot consume the staged binding.
        self.joined = true;
        self.assertion_dropped_child.take();
        // As with join_child, Read cleanup may still be pending. Its real owners
        // and every original Save group remain for ordinary reconciliation.
        let _read_cleanup = self.chains.cleanup_startup();
        Ok(())
    }
    pub fn cleanup_failed_open(
        &mut self,
        now: u64,
    ) -> Result<ProcessOpenCleanup, NativeEditorError> {
        let deadline = *self
            .cleanup_deadline
            .get_or_insert_with(|| Instant::now() + Duration::from_millis(2000));
        if self.child.is_some() {
            let _ = self.retire(desktop::ProcessRetireReason::ChildFault, now);
            match self.join_child() {
                Ok(_actual_child_proof) => {}
                Err(NativeEditorError::Desktop(Status::NotReady)) => {
                    return Ok(if Instant::now() < deadline {
                        ProcessOpenCleanup::Pending
                    } else {
                        ProcessOpenCleanup::Quarantined
                    });
                }
                Err(_) => return Ok(ProcessOpenCleanup::Quarantined),
            }
        }
        if self.spawned && !self.joined {
            return Ok(ProcessOpenCleanup::Quarantined);
        }
        self.chains.progress_all(now)?;
        if !self.chains.cleanup_startup()? || self.chains.pending_groups() != 0 {
            return Ok(if Instant::now() < deadline {
                ProcessOpenCleanup::Pending
            } else {
                ProcessOpenCleanup::Quarantined
            });
        }
        // These actual owners are known unspawned, or the original child has
        // genuine terminal+supervisor proof. No Store original is inferred away.
        self.editor.take();
        self.enrollment.take();
        self.executable.take();
        self.cleanup_complete = true;
        Ok(ProcessOpenCleanup::Complete)
    }
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    pub fn assertion_pending_originals(&self) -> u32 {
        u32::try_from(self.chains.pending_groups()).unwrap_or(u32::MAX)
    }
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    #[allow(dead_code)]
    pub(super) fn take_assertion_run(&mut self) -> Option<desktop::ProcessAssertionRun> {
        self.assertion_run.take()
    }
}
