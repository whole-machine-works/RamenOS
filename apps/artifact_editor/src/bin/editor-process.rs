//! The default-off Linux editor process. Authority stays in its parent.
#[cfg(all(
    target_os = "linux",
    feature = "host_editor_process_child_assertions_v0_dev"
))]
#[path = "editor_process_child/assertions.rs"]
mod assertions;
#[cfg(target_os = "linux")]
#[path = "editor_process_child/linux.rs"]
mod linux;

#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = linux::run() {
        eprintln!("editor-process: {error}");
        std::process::exit(2);
    }
}
#[cfg(not(target_os = "linux"))]
fn main() {
    std::process::exit(3);
}
