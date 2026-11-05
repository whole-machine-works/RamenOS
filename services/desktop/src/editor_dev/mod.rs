//! Default-off typed editor host fixture. Volatile, in-process enforcement only.
mod client;
mod codec;
mod host;
#[cfg(all(test, target_os = "linux", feature = "host_editor_process_assertions_v0_dev"))]
#[path = "process_editor/assertions.rs"]
#[allow(dead_code)]
mod process_assertions;
#[cfg(feature = "editor_native_read_v0_dev")]
mod native_authority;
#[cfg(feature = "editor_native_preview_v0_dev")]
mod native_preview;
#[cfg(feature = "editor_native_save_v0_dev")]
mod native_save;
pub use client::*;
pub use codec::{EditorMessage, decode_envelope_wire, encode_envelope_wire};
pub use host::*;
#[cfg(feature = "editor_native_read_v0_dev")]
pub use native_authority::*;
#[cfg(feature = "editor_native_preview_v0_dev")]
pub use native_preview::*;
#[cfg(feature = "editor_native_save_v0_dev")]
pub use native_save::*;
