//! Fixed, private C1/C2 selection. A pin is advisory, never native authority.
use super::{PreparedStoreShadowModule, RecoveryArtifactV0, RecoveryDecisionAdapter};
use std::{
    fs::{self, Metadata, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    sync::{Arc, Mutex},
};

const ABI: [u8; 32] = [
    0x49, 0xda, 0xf5, 0x2d, 0xd6, 0x69, 0x41, 0x13, 0x76, 0x77, 0x0b, 0x3b, 0xc2, 0xa0, 0x07, 0xd7,
    0xc6, 0xa8, 0xb3, 0x46, 0x84, 0x3b, 0xcd, 0x12, 0x3a, 0x45, 0xda, 0x81, 0x39, 0xb0, 0xda, 0x60,
];
const C1: [u8; 32] = [
    0x64, 0x58, 0xa1, 0x73, 0xcd, 0x09, 0xe7, 0x3f, 0xe0, 0xbe, 0x59, 0xb1, 0xa2, 0xd3, 0x39, 0xc2,
    0x07, 0x0c, 0x33, 0xac, 0x05, 0x62, 0x8b, 0x3d, 0x2d, 0xd5, 0xfb, 0x26, 0x4c, 0xb2, 0xe0, 0x79,
];
const C2: [u8; 32] = [
    0xfb, 0xcc, 0xea, 0xe4, 0x41, 0x1b, 0x17, 0xf2, 0xe5, 0x17, 0xa8, 0x53, 0x99, 0x91, 0xbf, 0xb4,
    0x1b, 0x09, 0x7b, 0x2a, 0xa2, 0xb0, 0x37, 0xca, 0x58, 0xa8, 0x28, 0x97, 0x2a, 0x3b, 0x3c, 0xe4,
];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryShadowIdentity {
    pub module_sha256: [u8; 32],
    pub abi_sha256: [u8; 32],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryShadowUpdateError {
    Path,
    Read,
    Identity,
    Prepare,
    Unavailable,
}
#[derive(Clone)]
pub struct RecoveryShadowSelector(Arc<Mutex<Arc<PreparedStoreShadowModule>>>);
pub struct PinnedRecoveryShadowModule(Arc<PreparedStoreShadowModule>);
impl PinnedRecoveryShadowModule {
    pub fn module(&self) -> &PreparedStoreShadowModule {
        &self.0
    }
    pub fn identity(&self) -> RecoveryShadowIdentity {
        self.0.1
    }
}
impl RecoveryShadowSelector {
    pub fn new(initial: PreparedStoreShadowModule) -> Self {
        Self(Arc::new(Mutex::new(Arc::new(initial))))
    }
    pub fn pin(&self) -> Result<PinnedRecoveryShadowModule, RecoveryShadowUpdateError> {
        Ok(PinnedRecoveryShadowModule(
            self.0
                .lock()
                .map_err(|_| RecoveryShadowUpdateError::Unavailable)?
                .clone(),
        ))
    }
    pub fn replace_from_file(
        &self,
        path: &Path,
    ) -> Result<RecoveryShadowIdentity, RecoveryShadowUpdateError> {
        let (bytes, identity) = load(path)?;
        let artifact = RecoveryArtifactV0 {
            module_sha256: identity.module_sha256,
            abi_sha256: identity.abi_sha256,
        };
        let prepared = Arc::new(PreparedStoreShadowModule(
            RecoveryDecisionAdapter::new(&bytes, artifact)
                .map_err(|_| RecoveryShadowUpdateError::Prepare)?,
            identity,
        ));
        let old = {
            let mut guard = self
                .0
                .lock()
                .map_err(|_| RecoveryShadowUpdateError::Unavailable)?;
            std::mem::replace(&mut *guard, prepared)
        };
        drop(old);
        Ok(identity)
    }
}
fn safe(m: &Metadata) -> bool {
    m.is_file()
        && m.uid() == unsafe { libc::geteuid() }
        && m.mode() & 0o077 == 0
        && m.nlink() == 1
        && matches!(m.len(), 1347 | 1349)
}
fn same(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.mode() == b.mode()
        && a.uid() == b.uid()
        && a.nlink() == b.nlink()
        && a.len() == b.len()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}
fn load(path: &Path) -> Result<(Vec<u8>, RecoveryShadowIdentity), RecoveryShadowUpdateError> {
    use RecoveryShadowUpdateError::{Identity, Path as PathError, Read as ReadError};
    let before = fs::symlink_metadata(path).map_err(|_| PathError)?;
    if !safe(&before) {
        return Err(PathError);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| PathError)?;
    let opened = file.metadata().map_err(|_| ReadError)?;
    if !safe(&opened) || !same(&before, &opened) {
        return Err(PathError);
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(1350)
        .read_to_end(&mut bytes)
        .map_err(|_| ReadError)?;
    let after = file.metadata().map_err(|_| ReadError)?;
    let path_after = fs::symlink_metadata(path).map_err(|_| PathError)?;
    if !safe(&after)
        || !safe(&path_after)
        || !same(&opened, &after)
        || !same(&opened, &path_after)
        || bytes.len() as u64 != opened.len()
    {
        return Err(ReadError);
    }
    let digest = super::super::storage::hash(&bytes);
    if !((bytes.len() == 1349 && digest == C1) || (bytes.len() == 1347 && digest == C2)) {
        return Err(Identity);
    }
    Ok((
        bytes,
        RecoveryShadowIdentity {
            module_sha256: digest,
            abi_sha256: ABI,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    const ONE: &[u8] = include_bytes!("../../tests/fixtures/recovery-c1.wasm");
    const TWO: &[u8] = include_bytes!("../../../native_runner/tests/fixtures/recovery-c2.wasm");
    fn initial() -> RecoveryShadowSelector {
        RecoveryShadowSelector::new(
            PreparedStoreShadowModule::prepare(
                ONE,
                RecoveryArtifactV0 {
                    module_sha256: C1,
                    abi_sha256: ABI,
                },
            )
            .unwrap(),
        )
    }
    fn put(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    #[test]
    fn refuses_unsafe_or_wrong_files_then_updates_and_retains_pins() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("candidate");
        let selector = initial();
        let held = selector.pin().unwrap();
        assert_eq!(
            selector.replace_from_file(dir.path()),
            Err(RecoveryShadowUpdateError::Path)
        );
        assert_eq!(
            selector.replace_from_file(&file),
            Err(RecoveryShadowUpdateError::Path)
        );
        put(&file, &[0; 8]);
        assert_eq!(
            selector.replace_from_file(&file),
            Err(RecoveryShadowUpdateError::Path)
        );
        assert_eq!(selector.pin().unwrap().identity(), held.identity());
        put(&file, &[0; 1347]);
        assert_eq!(
            selector.replace_from_file(&file),
            Err(RecoveryShadowUpdateError::Identity)
        );
        assert_eq!(selector.pin().unwrap().identity(), held.identity());
        put(&file, TWO);
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            selector.replace_from_file(&file),
            Err(RecoveryShadowUpdateError::Path)
        );
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.path().join("link");
        symlink(&file, &link).unwrap();
        assert_eq!(
            selector.replace_from_file(&link),
            Err(RecoveryShadowUpdateError::Path)
        );
        let hard = dir.path().join("hard");
        fs::hard_link(&file, &hard).unwrap();
        assert_eq!(
            selector.replace_from_file(&file),
            Err(RecoveryShadowUpdateError::Path)
        );
        fs::remove_file(hard).unwrap();
        assert_eq!(selector.replace_from_file(&file).unwrap().module_sha256, C2);
        let second = selector.pin().unwrap();
        assert_eq!(second.identity().module_sha256, C2);
        assert_eq!(held.identity().module_sha256, C1);
        put(&file, ONE);
        assert_eq!(selector.replace_from_file(&file).unwrap().module_sha256, C1);
        assert_eq!(second.identity().module_sha256, C2);
        assert_eq!(selector.pin().unwrap().identity().module_sha256, C1);
    }
    #[test]
    fn poison_refuses_new_pins_and_swaps_but_held_pin_survives() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("candidate");
        put(&file, TWO);
        let selector = initial();
        let held = selector.pin().unwrap();
        let clone = selector.clone();
        let _ = std::thread::spawn(move || {
            let _guard = clone.0.lock().unwrap();
            panic!("poison");
        })
        .join();
        assert!(matches!(
            selector.pin(),
            Err(RecoveryShadowUpdateError::Unavailable)
        ));
        assert_eq!(
            selector.replace_from_file(&file),
            Err(RecoveryShadowUpdateError::Unavailable)
        );
        assert_eq!(held.identity().module_sha256, C1);
    }
}
