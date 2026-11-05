//! Test ownership of one or two genuine children. A failed consuming call never
//! becomes an empty-slot cleanup proof. Parent Store/root owners are released
//! only after every actual child proof and its supervisor join are retained.
use crate::support::Fixture;
#[allow(
    clippy::duplicate_mod,
    reason = "Each independently staged owner module retains its own three named cleanup controls in the frozen executable inventory."
)]
#[path = "cleanup_owners.rs"]
mod cleanup_owners;
use cleanup_owners::ParentOwners;
use desktop_service::dev::Status;
use desktop_service::editor_dev::{
    ChildBudget, OwnedEditorChild, OwnedEditorChildExitProof, ProcessEditorEnrollment,
    ProcessLaunchRecovery, ProcessRetireReason,
};
use store_service::editor_store::PairedNativeSaveLaunch;

pub struct ChildGroup {
    parents: Option<ParentOwners<(Fixture, Vec<PairedNativeSaveLaunch>)>>,
    children: Vec<Option<OwnedEditorChild>>,
    proofs: Vec<OwnedEditorChildExitProof>,
    consuming_owner_unreturned: bool,
}
impl ChildGroup {
    pub fn new(fixture: Fixture) -> Self {
        Self {
            parents: Some(ParentOwners::new((fixture, Vec::new()))),
            children: Vec::new(),
            proofs: Vec::new(),
            consuming_owner_unreturned: false,
        }
    }
    pub fn fixture(&mut self) -> &mut Fixture {
        &mut self.parents.as_mut().unwrap().borrow().0
    }
    pub fn retain_launch(&mut self, launch: PairedNativeSaveLaunch) {
        self.parents.as_mut().unwrap().borrow().1.push(launch);
    }
    pub fn cleanup_deadline(&mut self) -> std::time::Instant {
        self.parents.as_mut().unwrap().begin_cleanup().0
    }
    pub fn child(&self, index: usize) -> &OwnedEditorChild {
        self.children[index].as_ref().unwrap()
    }
    pub fn borrow(&mut self, index: usize) -> (&mut Fixture, &mut OwnedEditorChild) {
        let fixture = &mut self.parents.as_mut().unwrap().borrow().0;
        (fixture, self.children[index].as_mut().unwrap())
    }
    pub fn fault(&mut self, index: usize, now: u64) {
        let (f, child) = self.borrow(index);
        crate::support::ok(f.h.retire_process_editor(child, ProcessRetireReason::ChildFault, now));
    }
    pub fn assert_live_join_returns_owner(&mut self, index: usize) {
        let host = self.fixture().h.clone();
        let before = crate::support::ok(host.observe_process_child(self.child(index)));
        let child = self.children[index].take().unwrap();
        self.consuming_owner_unreturned = true;
        let entered = std::time::Instant::now();
        match host.join_process_editor(child) {
            Ok(_) => panic!("live child cannot have a terminal reap before fault/retire"),
            Err(failure) => {
                let (status, child) = failure.into_parts();
                self.children[index] = Some(child);
                self.consuming_owner_unreturned = false;
                assert_eq!(status, Status::NotReady);
            }
        }
        assert!(entered.elapsed() < std::time::Duration::from_millis(100));
        let after = crate::support::ok(host.observe_process_child(self.child(index)));
        assert_eq!(before.process_id(), after.process_id());
        assert_eq!(before.birth_ticks(), after.birth_ticks());
        assert_eq!(before.executable_sha256(), after.executable_sha256());
    }
    pub fn spawn(
        &mut self,
        enrollment: ProcessEditorEnrollment,
        budget: ChildBudget,
        now: u64,
    ) -> Result<usize, Status> {
        let host = self.fixture().h.clone();
        let executable = host.registered_editor_process_executable(&enrollment)?;
        self.consuming_owner_unreturned = true;
        match host.spawn_process_editor(enrollment, executable, budget, now) {
            Ok(child) => {
                self.children.push(Some(child));
                self.consuming_owner_unreturned = false;
                Ok(self.children.len() - 1)
            }
            Err(failure) => {
                let (status, recovery) = failure.into_parts();
                match recovery {
                    ProcessLaunchRecovery::Unspawned {
                        enrollment,
                        executable,
                    } => drop((enrollment, executable)),
                    ProcessLaunchRecovery::Spawned(child) => self.children.push(Some(child)),
                }
                self.consuming_owner_unreturned = false;
                Err(status)
            }
        }
    }
    #[allow(
        clippy::result_large_err,
        reason = "Failed cleanup must return this same inline sole owner, preserving its original deadline, children and parent roots for retry or quarantine."
    )]
    pub fn finish(mut self, now: u64) -> Result<(Fixture, Vec<OwnedEditorChildExitProof>), Self> {
        if self.consuming_owner_unreturned {
            return Err(self);
        }
        let (end, first) = self.parents.as_mut().unwrap().begin_cleanup();
        if first {
            let host = self.fixture().h.clone();
            for child in self.children.iter_mut().flatten() {
                let _ = host.retire_process_editor(child, ProcessRetireReason::HumanClose, now);
            }
        }
        for index in 0..self.children.len() {
            loop {
                if self.children[index].is_none() {
                    break;
                }
                if !self.parents.as_ref().unwrap().join_permitted() {
                    return Err(self);
                }
                let child = self.children[index].take().unwrap();
                self.consuming_owner_unreturned = true;
                let host = self.fixture().h.clone();
                match host.join_process_editor(child) {
                    Ok(proof) => {
                        self.proofs.push(proof);
                        self.consuming_owner_unreturned = false;
                        break;
                    }
                    Err(failure) => {
                        let (status, child) = failure.into_parts();
                        self.children[index] = Some(child);
                        self.consuming_owner_unreturned = false;
                        if status != Status::NotReady || std::time::Instant::now() >= end {
                            return Err(self);
                        }
                        std::thread::yield_now();
                    }
                }
            }
        }
        assert_eq!(self.proofs.len(), self.children.len());
        let (fixture, launches) = self.parents.take().unwrap().release_after_join();
        drop(launches);
        Ok((fixture, std::mem::take(&mut self.proofs)))
    }
}
impl Drop for ChildGroup {
    fn drop(&mut self) {
        for child in self.children.iter_mut().filter_map(Option::take) {
            std::mem::forget(child);
        }
        // ParentOwners conservatively quarantines even if a faulty consuming
        // API unwound after taking the actual opaque child out of its slot.
    }
}
