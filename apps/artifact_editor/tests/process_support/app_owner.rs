//! Actual process app and durable-root ownership across assertion failure.
use crate::support::Fixture;
#[path = "cleanup_owners.rs"]
#[allow(
    clippy::duplicate_mod,
    reason = "The frozen helper inventory exercises each independently staged owner module; sharing one module would remove named cleanup controls."
)]
mod cleanup_owners;
use artifact_editor::{NativeEditorError, ProcessArtifactEditor};
use cleanup_owners::ParentOwners;
use desktop_service::{dev::Status, editor_dev as desktop};
use std::{
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    time::Instant,
};

pub struct AppOwner {
    parents: Option<ParentOwners<Fixture>>,
    app: Option<ProcessArtifactEditor>,
    child_joined: bool,
    child_exit: Option<desktop::OwnedEditorChildExitProof>,
    failure_retire_pending: bool,
    endpoint: Option<store_service::editor_store::EditorEndpoint>,
}
impl AppOwner {
    pub fn new(fixture: Fixture) -> Self {
        Self {
            parents: Some(ParentOwners::new(fixture)),
            app: None,
            child_joined: false,
            child_exit: None,
            failure_retire_pending: false,
            endpoint: None,
        }
    }
    pub fn fixture(&mut self) -> &mut Fixture {
        self.parents.as_mut().unwrap().borrow()
    }
    pub fn open(&mut self, session: usize, object: u64, now: u64) -> Result<(), NativeEditorError> {
        let f = self.fixture();
        let launch = f.launch(session, object, now);
        let endpoint = store_service::editor_store::EditorEndpoint {
            peer: launch.endpoint().peer.clone(),
            handle: launch.endpoint().handle,
        };
        let result = ProcessArtifactEditor::open(
            f.h.clone(),
            f.host(),
            launch,
            crate::support::ok(desktop::ChildBudget::checked(5000)),
            now,
        );
        self.endpoint = Some(endpoint);
        match result {
            Ok(app) => {
                self.app = Some(app);
                Ok(())
            }
            Err(failure) => {
                let (error, app) = failure.into_parts();
                self.app = Some(app);
                Err(error)
            }
        }
    }
    pub fn endpoint(&self) -> &store_service::editor_store::EditorEndpoint {
        self.endpoint.as_ref().unwrap()
    }
    pub fn retire(
        &mut self,
        reason: desktop::ProcessRetireReason,
        now: u64,
    ) -> Result<(), NativeEditorError> {
        self.parents.as_mut().unwrap().begin_cleanup();
        self.app.as_mut().unwrap().retire(reason, now)
    }
    pub fn borrow(&mut self) -> (&mut Fixture, &mut ProcessArtifactEditor) {
        (
            self.parents.as_mut().unwrap().borrow(),
            self.app.as_mut().unwrap(),
        )
    }
    pub fn borrow_with_endpoint(
        &mut self,
    ) -> (
        &mut Fixture,
        &mut ProcessArtifactEditor,
        &store_service::editor_store::EditorEndpoint,
    ) {
        (
            self.parents.as_mut().unwrap().borrow(),
            self.app.as_mut().unwrap(),
            self.endpoint.as_ref().unwrap(),
        )
    }
    pub fn join(&mut self, now: u64) -> Result<(), NativeEditorError> {
        let (end, first) = self.parents.as_mut().unwrap().begin_cleanup();
        let app = self.app.as_mut().unwrap();
        if first || std::mem::take(&mut self.failure_retire_pending) {
            app.retire(desktop::ProcessRetireReason::HumanClose, now)?;
        }
        loop {
            match app.join_child() {
                Ok(proof) => {
                    assert!(proof.supervisor_joined());
                    self.child_joined = true;
                    self.child_exit = Some(proof);
                    return Ok(());
                }
                Err(NativeEditorError::Desktop(Status::NotReady)) => {
                    if Instant::now() >= end {
                        return Err(NativeEditorError::Desktop(Status::Timeout));
                    }
                    std::thread::yield_now();
                }
                Err(error) => return Err(error),
            }
        }
    }
    fn settle_originals(&mut self, now: u64) -> Result<(), NativeEditorError> {
        let (end, first) = self.parents.as_mut().unwrap().begin_cleanup();
        assert!(
            !first,
            "retire/join must already own the original cleanup deadline"
        );
        loop {
            let (fixture, app) = self.borrow();
            if app.assertion_pending_originals() == 0
                && fixture.h.native_producer_counts().held == 0
            {
                return Ok(());
            }
            if Instant::now() >= end {
                return Err(NativeEditorError::Desktop(Status::Timeout));
            }
            // These are actual nonblocking producer joins and observations of
            // the same retained originals. Neither call replays a Save.
            fixture.join_all();
            match app.reconcile_originals(now) {
                Ok(()) => {}
                Err(NativeEditorError::Desktop(Status::NotReady))
                | Err(NativeEditorError::Store(
                    store_service::editor_store::StoreStatus::NotReady,
                )) => {}
                Err(error) => return Err(error),
            }
            std::thread::yield_now();
        }
    }
    fn check_release(&mut self, now: u64) {
        assert!(
            self.child_joined,
            "actual child proof required before releasing parent root"
        );
        if let Err(error) = self.settle_originals(now) {
            panic!(
                "INCOMPLETE: same original reconciliation failed; app and parent owners retained: {error:?}; pending={}",
                self.app.as_ref().unwrap().assertion_pending_originals(),
            );
        }
        assert_eq!(
            self.app.as_ref().unwrap().assertion_pending_originals(),
            0,
            "child reap/producer joins do not close unresolved original Save owners"
        );
        assert_eq!(
            self.fixture().h.native_producer_counts().held,
            0,
            "actual producer joins complete before releasing parent root"
        );
        assert!(matches!(
            self.app.as_ref().unwrap().observe(now),
            Err(NativeEditorError::Desktop(Status::NotReady))
        ));
    }
    fn transfer_checked(&mut self) -> Fixture {
        drop(self.app.take().unwrap());
        self.parents.take().unwrap().release_after_join()
    }
    pub fn release(mut self, now: u64) -> Fixture {
        self.check_release(now);
        self.transfer_checked()
    }
    fn panic_detail(payload: &(dyn std::any::Any + Send)) -> serde_json::Value {
        let message = if let Some(s) = payload.downcast_ref::<String>() {
            s.as_str()
        } else if let Some(s) = payload.downcast_ref::<&str>() {
            s
        } else {
            "non-string secondary panic payload"
        };
        serde_json::json!({"result":"panic", "panic":message.chars().take(4096).collect::<String>(), "truncated":message.chars().count()>4096})
    }
    fn diagnostic_incomplete(stage: &str, detail: &serde_json::Value) {
        if let Ok(bytes) = serde_json::to_vec(
            &serde_json::json!({"stage":stage,"detail":detail,"acceptance":false}),
        ) {
            let mut stderr = std::io::stderr().lock();
            let _ = std::io::Write::write_all(&mut stderr, b"D21_FAILURE_DIAGNOSTIC_ERROR ");
            let _ = std::io::Write::write_all(&mut stderr, &bytes);
            let _ = std::io::Write::write_all(&mut stderr, b"\n");
        }
    }
    fn failure_value(
        &mut self,
        phase: &str,
        now: u64,
        original: &str,
        started: Instant,
        deadline: Instant,
        outcome: &str,
    ) -> Option<serde_json::Value> {
        match catch_unwind(AssertUnwindSafe(|| {
            let mut value = self
                .parents
                .as_mut()
                .unwrap()
                .borrow()
                .process_failure_observation(
                    self.app.as_ref().unwrap(),
                    self.child_exit.as_ref(),
                    now,
                );
            value["phase"] = phase.into();
            value["original_panic"] = original.into();
            value["cleanup_outcome"] = outcome.into();
            value["elapsed_since_failure_handler_ns"] =
                serde_json::json!(started.elapsed().as_nanos());
            value["cleanup_deadline_offset_from_handler_start_ns"] =
                serde_json::json!(deadline.saturating_duration_since(started).as_nanos());
            value["original_cleanup_budget_ms"] = 2000.into();
            value["cleanup_deadline_elapsed"] = (Instant::now() >= deadline).into();
            value
        })) {
            Ok(value) => Some(value),
            Err(payload) => {
                Self::diagnostic_incomplete(phase, &Self::panic_detail(&*payload));
                None
            }
        }
    }
    fn emit_with_fixture(fixture: &Fixture, phase: &str, value: &serde_json::Value) {
        match catch_unwind(AssertUnwindSafe(|| {
            fixture.emit_process_failure_observation(phase, value)
        })) {
            Ok(Ok(())) => {}
            Ok(Err(error)) => Self::diagnostic_incomplete(
                phase,
                &serde_json::json!({"result":"Err","error":format!("{error:?}")}),
            ),
            Err(payload) => Self::diagnostic_incomplete(phase, &Self::panic_detail(&*payload)),
        }
    }
    fn emit_failure_value(&mut self, phase: &str, value: &serde_json::Value) {
        if let Some(parents) = self.parents.as_mut() {
            Self::emit_with_fixture(parents.borrow(), phase, value);
        } else {
            Self::diagnostic_incomplete(
                phase,
                &serde_json::json!({"result":"unavailable","reason":"parent owner consumed during failed transfer"}),
            );
        }
    }
    pub fn retain_failure_diagnostics(
        mut self,
        observed_now: u64,
        cleanup_now: u64,
        original: Box<dyn std::any::Any + Send>,
    ) -> ! {
        let started = Instant::now();
        // Charge diagnostic work to the same original two-second cleanup
        // budget. Starting the budget does not retire or reconcile the app.
        let (deadline, first) = self.parents.as_mut().unwrap().begin_cleanup();
        self.failure_retire_pending |= first;
        let text = if let Some(text) = original.downcast_ref::<String>() {
            text.as_str()
        } else if let Some(text) = original.downcast_ref::<&str>() {
            text
        } else {
            "non-string original panic payload"
        };
        if let Some(value) = self.failure_value(
            "before_cleanup",
            observed_now,
            text,
            started,
            deadline,
            "not_started",
        ) {
            self.emit_failure_value("before_cleanup", &value);
        }
        // Reuse the bounded actual Store export, without a fence or summary.
        if let Err(payload) = catch_unwind(AssertUnwindSafe(|| {
            self.parents.as_mut().unwrap().borrow().store_snapshot(
                "final",
                "final_before_cleanup",
                None,
                None,
            );
        })) {
            Self::diagnostic_incomplete("current_store_snapshot", &Self::panic_detail(&*payload));
        }
        let joined = catch_unwind(AssertUnwindSafe(|| self.join(cleanup_now)));
        let (joined_ok, join_detail) = match joined {
            Ok(Ok(())) => (true, serde_json::json!({"result":"Ok"})),
            Ok(Err(error)) => (
                false,
                serde_json::json!({"result":"Err","error":format!("{error:?}")}),
            ),
            Err(payload) => (false, Self::panic_detail(&*payload)),
        };
        if let Some(mut value) = self.failure_value(
            "after_child_join",
            cleanup_now,
            text,
            started,
            deadline,
            if joined_ok {
                "complete"
            } else {
                "failed_or_panicked"
            },
        ) {
            // Retain the authentic proof before a consuming release can panic.
            value["child_cleanup"] = join_detail.clone();
            self.emit_failure_value("after_child_join", &value);
        }
        let (checked, check_detail) = if joined_ok {
            match catch_unwind(AssertUnwindSafe(|| self.check_release(cleanup_now))) {
                Ok(()) => (true, serde_json::json!({"result":"Ok"})),
                Err(payload) => (false, Self::panic_detail(&*payload)),
            }
        } else {
            (
                false,
                serde_json::json!({"result":"not_attempted","reason":"child join did not complete"}),
            )
        };
        let mut terminal = self.failure_value(
            "after_original_cleanup",
            cleanup_now,
            text,
            started,
            deadline,
            if checked {
                "complete"
            } else {
                "failed_or_panicked"
            },
        );
        if let Some(value) = terminal.as_mut() {
            value["child_cleanup"] = join_detail;
            value["original_cleanup"] = check_detail;
        }
        if checked {
            match catch_unwind(AssertUnwindSafe(|| self.transfer_checked())) {
                Ok(fixture) => {
                    if let Some(value) = terminal.as_mut() {
                        value["parent_transfer"] =
                            serde_json::json!({"result":"Ok","fixture_retained":true});
                        value["observation_precedes_parent_transfer"] = true.into();
                        Self::emit_with_fixture(&fixture, "after_original_cleanup", value);
                    }
                    std::mem::forget(fixture);
                }
                Err(payload) => {
                    if let Some(value) = terminal.as_mut() {
                        value["cleanup_outcome"] = "failed_or_panicked".into();
                        value["parent_transfer"] = Self::panic_detail(&*payload);
                        self.emit_failure_value("after_original_cleanup", value);
                    }
                }
            }
        } else if let Some(value) = terminal.as_mut() {
            value["parent_transfer"] =
                serde_json::json!({"result":"not_attempted","owners_retained":true});
            self.emit_failure_value("after_original_cleanup", value);
        }
        // Avoid fallible uncertainty-printing destructors during original unwind.
        std::mem::forget(self);
        resume_unwind(original)
    }
}
impl Drop for AppOwner {
    fn drop(&mut self) {
        if let Some(app) = self.app.take() {
            std::mem::forget(app);
        }
        // ParentOwners retains the root/Core even when a faulty open consumed
        // authority then unwound without returning its staged wrapper.
    }
}
