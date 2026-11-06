//! Default-off host composition consumer for the native artifact editor task.
//!
//! The gate-first task assertions precede its implementation. The concrete
//! Desktop and Store owners retain authority; this crate adds no public text,
//! receipt, or Save-state setter. A separate editor process remains UI1.1d.

#[cfg(all(test, feature = "host_native_save_v0_dev"))]
extern crate self as artifact_editor;

#[cfg(all(test, feature = "host_editor_process_assertions_v0_dev"))]
#[path = "../tests/native_task_support/mod.rs"]
mod support;

#[cfg(all(test, feature = "host_editor_process_assertions_v0_dev"))]
mod dev {
    pub use desktop_service::dev::*;
}
#[cfg(all(test, feature = "host_editor_process_assertions_v0_dev"))]
mod editor_dev {
    pub use desktop_service::editor_dev::*;
}

#[cfg(feature = "host_native_save_v0_dev")]
mod native;
#[cfg(feature = "host_native_save_v0_dev")]
pub use native::{NativeArtifactEditor, NativeEditorError};

#[cfg(all(target_os = "linux", feature = "host_editor_process_v0_dev"))]
pub use native::{ProcessArtifactEditor, ProcessEditorOpenFailure, ProcessOpenCleanup};
