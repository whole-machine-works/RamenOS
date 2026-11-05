//! Actual process app and durable-root ownership across assertion failure.
use crate::support::Fixture;
#[path = "cleanup_owners.rs"]
mod cleanup_owners;
use artifact_editor::{NativeEditorError, ProcessArtifactEditor};
use cleanup_owners::ParentOwners;
use desktop_service::{dev::Status, editor_dev as desktop};
use std::time::Instant;

pub struct AppOwner {
    parents: Option<ParentOwners<Fixture>>,
    app: Option<ProcessArtifactEditor>,
    child_joined: bool,
    endpoint: Option<store_service::editor_store::EditorEndpoint>,
}
impl AppOwner {
    pub fn new(fixture: Fixture) -> Self {
        Self {
            parents: Some(ParentOwners::new(fixture)),
            app: None,
            child_joined: false,
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
    pub fn join(&mut self, now: u64) -> Result<(), NativeEditorError> {
        let (end, first) = self.parents.as_mut().unwrap().begin_cleanup();
        let app = self.app.as_mut().unwrap();
        if first {
            app.retire(desktop::ProcessRetireReason::HumanClose, now)?;
        }
        loop {
            match app.join_child() {
                Ok(proof) => {
                    assert!(proof.supervisor_joined());
                    self.child_joined = true;
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
    pub fn release(mut self, now: u64) -> Fixture {
        assert!(
            self.child_joined,
            "actual child proof required before releasing parent root"
        );
        assert_eq!(
            self.app.as_ref().unwrap().assertion_pending_originals(),
            0,
            "child reap/producer joins do not close unresolved original Save owners"
        );
        assert!(matches!(
            self.app.as_ref().unwrap().observe(now),
            Err(NativeEditorError::Desktop(Status::NotReady))
        ));
        drop(self.app.take().unwrap());
        self.parents.take().unwrap().release_after_join()
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
