//! Executable recording controls; these do not claim native task qualification.
#![cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "../native_task_support/mod.rs"]
mod support;

use desktop_service::{dev::Status, editor_dev as desktop};
use std::{
    fs::{self, File},
    os::unix::fs::{DirBuilderExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use support::recording::{CaseRecorder, ScenarioRecorder, SharedFrameReservation};

type Capture = (desktop::ComposedFrame, desktop::NativeSaveChromeObservation);
const FRAME_BYTES: usize = 640 * 568 * 4;
const MAX_FILE: u64 = 32 * 1024 * 1024;

fn directory(path: &Path) {
    fs::DirBuilder::new().mode(0o700).create(path).unwrap();
}
fn root(name: &str) -> PathBuf {
    let path =
        PathBuf::from(std::env::var_os("RAMEN_SHARED_FRAME_CONTROL_ROOT").unwrap()).join(name);
    assert!(path.is_absolute());
    directory(&path);
    path
}
fn nonce() -> String {
    std::env::var("RAMEN_NATIVE_TASK_RUN_NONCE").unwrap()
}
fn recorder(path: &Path, name: &'static str) -> ScenarioRecorder {
    CaseRecorder::open_at(path, &nonce(), name)
        .unwrap()
        .scenario(support::recording::ScenarioSpec {
            case: name,
            scenario: "frames",
            leg: 0,
            scope: support::recording::ScenarioScope::DirectNative,
            checkpoints: &[],
            requirements: &["shared_frame_control"],
        })
        .unwrap()
}
fn recorders(path: &Path) -> (ScenarioRecorder, ScenarioRecorder) {
    (recorder(path, "left"), recorder(path, "right"))
}
fn leaf(path: &Path, side: &str, name: &str) -> PathBuf {
    path.join(side).join("frames/0").join(name)
}
fn seed(
    path: &Path,
    name: &'static str,
) -> (support::Fixture, artifact_editor::NativeArtifactEditor) {
    let case = CaseRecorder::open_at(path, &nonce(), name).unwrap();
    let mut spec = support::scenario(
        "ui1_1_clock_capacity_and_counter_limits_fail_closed",
        "process_preparation",
        0,
        support::recording::ScenarioScope::DirectNative,
    );
    spec.case = name;
    spec.requirements = &["shared_frame_control"];
    let mut fixture = support::Fixture::recorded(&case, spec, 1);
    let mut app = fixture.app(0, 101, 1);
    support::ok(app.render(2));
    (fixture, app)
}
fn captures(path: &Path) -> [Capture; 2] {
    let p = path.join("seeds");
    directory(&p);
    let (left, la) = seed(&p, "seed_left");
    let (right, ra) = seed(&p, "seed_right");
    let a = support::ok(left.capture_composed_frame(0, 2));
    let b = support::ok(right.capture_composed_frame(0, 2));
    assert_eq!(a.0.bgra.len(), FRAME_BYTES);
    assert_eq!(b.0.bgra.len(), FRAME_BYTES);
    assert!(a.1.record248.is_some() && b.1.record248.is_some());
    drop((la, ra));
    left.finish();
    right.finish();
    [a, b]
}
fn pair(left: &mut ScenarioRecorder, right: &mut ScenarioRecorder, frames: &[Capture; 2]) {
    let mut pending = SharedFrameReservation::prepare(left, right).unwrap();
    pending.record_next(&frames[0].0, &frames[0].1).unwrap();
    pending.record_next(&frames[1].0, &frames[1].1).unwrap();
    pending.finish().unwrap();
}
fn exact_files(path: &Path, frames: &[Capture; 2], ordinal: usize) {
    for (side, frame) in ["left", "right"].into_iter().zip(frames) {
        assert_eq!(
            fs::read(leaf(path, side, &format!("frame-{ordinal}.bgra"))).unwrap(),
            frame.0.bgra
        );
        assert_eq!(
            fs::read(leaf(path, side, &format!("chrome-{ordinal}.bin"))).unwrap(),
            frame.1.record248.unwrap()
        );
    }
}
fn fresh_success(path: &Path, frames: &[Capture; 2]) {
    directory(path);
    let (mut left, mut right) = recorders(path);
    pair(&mut left, &mut right, frames);
    exact_files(path, frames, 0);
    assert!(!path.join(".recording-reservation").exists());
}
fn clean_progress(left: &ScenarioRecorder, right: &ScenarioRecorder) {
    for r in [left, right] {
        let (raw, frames) = r.frame_export_progress();
        assert!(raw.is_empty() && frames.is_empty());
    }
}

#[test]
fn shared_frame_success_and_single_census() {
    let root = root("success");
    let frames = captures(&root);
    let destination = root.join("paired");
    directory(&destination);
    let (mut left, mut right) = recorders(&destination);
    let lt = support::recording::PhaseTimingLog::new(["scan", "write", "crop"]);
    let rt = support::recording::PhaseTimingLog::new(["scan", "write", "crop"]);
    left.enable_frame_timings(lt.clone());
    right.enable_frame_timings(rt.clone());
    pair(&mut left, &mut right, &frames);
    exact_files(&destination, &frames, 0);
    assert_eq!(
        lt.observation()["phases"][0]["observations"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(
        rt.observation()["phases"][0]["observations"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    for r in [&left, &right] {
        let (raw, rows) = r.frame_export_progress();
        assert_eq!((raw.len(), rows.len()), (2, 1));
        assert_eq!(rows[0]["raw"]["sha256"], raw[0]["sha256"]);
    }
    // A second genuine operation uses fresh paths under the same owners.
    pair(&mut left, &mut right, &frames);
    exact_files(&destination, &frames, 1);
    assert!(!destination.join(".recording-reservation").exists());
}

#[test]
fn shared_frame_second_target_refusal_then_fresh_success() {
    let root = root("second_target");
    let frames = captures(&root);
    let destination = root.join("paired");
    directory(&destination);
    let (mut left, mut right) = recorders(&destination);
    let target = leaf(&destination, "right", "frame-0.bgra");
    fs::write(&target, b"existing independently owned target").unwrap();
    assert!(SharedFrameReservation::prepare(&mut left, &mut right).is_err());
    clean_progress(&left, &right);
    assert!(!leaf(&destination, "left", "frame-0.bgra").exists());
    assert!(!destination.join(".recording-reservation").exists());
    assert_eq!(
        fs::read(&target).unwrap(),
        b"existing independently owned target"
    );
    fs::remove_file(target).unwrap();
    pair(&mut left, &mut right, &frames);
    exact_files(&destination, &frames, 0);
}

#[test]
fn shared_frame_root_case_and_mode_substitution_then_recovery() {
    let root = root("substitution");
    let frames = captures(&root);
    for (index, relative) in ["", "right", "right/frames", "right/frames/0"]
        .into_iter()
        .enumerate()
    {
        let destination = root.join(format!("pair{index}"));
        directory(&destination);
        let (mut left, mut right) = recorders(&destination);
        let original = if relative.is_empty() {
            destination.clone()
        } else {
            destination.join(relative)
        };
        let moved = root.join(format!("held{index}"));
        fs::rename(&original, &moved).unwrap();
        directory(&original);
        assert!(SharedFrameReservation::prepare(&mut left, &mut right).is_err());
        clean_progress(&left, &right);
        assert!(!destination.join(".recording-reservation").exists());
        fs::remove_dir(&original).unwrap();
        fs::rename(moved, original).unwrap();
        pair(&mut left, &mut right, &frames);
        exact_files(&destination, &frames, 0);
    }
    let destination = root.join("mode");
    directory(&destination);
    let (mut left, mut right) = recorders(&destination);
    fs::set_permissions(destination.join("right"), fs::Permissions::from_mode(0o777)).unwrap();
    assert!(SharedFrameReservation::prepare(&mut left, &mut right).is_err());
    clean_progress(&left, &right);
    fs::set_permissions(destination.join("right"), fs::Permissions::from_mode(0o700)).unwrap();
    pair(&mut left, &mut right, &frames);
    let destination = root.join("nonce_mismatch");
    directory(&destination);
    let mut left = recorder(&destination, "left");
    let other_nonce = if nonce() == "0".repeat(32) {
        "1".repeat(32)
    } else {
        "0".repeat(32)
    };
    let mut right = CaseRecorder::open_at(&destination, &other_nonce, "right")
        .unwrap()
        .scenario(support::recording::ScenarioSpec {
            case: "right",
            scenario: "frames",
            leg: 0,
            scope: support::recording::ScenarioScope::DirectNative,
            checkpoints: &[],
            requirements: &["shared_frame_control"],
        })
        .unwrap();
    assert!(SharedFrameReservation::prepare(&mut left, &mut right).is_err());
    clean_progress(&left, &right);
    assert!(!destination.join(".recording-reservation").exists());
    let other_root = root.join("other_root");
    directory(&other_root);
    let mut other = recorder(&other_root, "right");
    assert!(SharedFrameReservation::prepare(&mut left, &mut other).is_err());
    clean_progress(&left, &other);
    assert!(!destination.join(".recording-reservation").exists());
    assert!(!other_root.join(".recording-reservation").exists());
    fresh_success(&root.join("fresh-after-owner-mismatch"), &frames);
}

#[test]
fn shared_frame_symlink_hardlink_and_foreign_reservation_refusal() {
    let root = root("links");
    let frames = captures(&root);
    for kind in ["symlink", "hardlink", "reservation"] {
        let destination = root.join(kind);
        directory(&destination);
        let (mut left, mut right) = recorders(&destination);
        let original = root.join(format!("owner-{kind}"));
        fs::write(&original, b"retain original bytes").unwrap();
        let target = if kind == "reservation" {
            destination.join(".recording-reservation")
        } else {
            leaf(&destination, "right", "chrome-0.bin")
        };
        if kind == "symlink" {
            symlink(&original, &target).unwrap();
        } else if kind == "hardlink" {
            fs::hard_link(&original, &target).unwrap();
        } else {
            fs::write(&target, b"another reservation owner").unwrap();
        }
        assert!(SharedFrameReservation::prepare(&mut left, &mut right).is_err());
        clean_progress(&left, &right);
        assert_eq!(fs::read(&original).unwrap(), b"retain original bytes");
        if kind == "reservation" {
            assert_eq!(fs::read(&target).unwrap(), b"another reservation owner");
        }
        fs::remove_file(target).unwrap();
        pair(&mut left, &mut right, &frames);
        exact_files(&destination, &frames, 0);
    }
    let destination = root.join("replaced_marker");
    directory(&destination);
    let (mut left, mut right) = recorders(&destination);
    let mut pending = SharedFrameReservation::prepare(&mut left, &mut right).unwrap();
    pending.record_next(&frames[0].0, &frames[0].1).unwrap();
    let marker = destination.join(".recording-reservation");
    fs::rename(&marker, destination.join("retained-original-marker")).unwrap();
    fs::write(&marker, b"foreign replacement owner").unwrap();
    assert!(pending.record_next(&frames[1].0, &frames[1].1).is_err());
    assert!(!leaf(&destination, "right", "frame-0.bgra").exists());
    assert!(pending.finish().is_err());
    assert_eq!(fs::read(&marker).unwrap(), b"foreign replacement owner");
    assert_eq!(
        (
            left.frame_export_progress().0.len(),
            left.frame_export_progress().1.len()
        ),
        (2, 1)
    );
    assert!(right.frame_export_progress().0.is_empty());
    fresh_success(&root.join("fresh-after-replacement"), &frames);
}

#[test]
fn shared_frame_combined_file_byte_and_case_json_caps() {
    let root = root("caps");
    let frames = captures(&root);
    for kind in [
        "files",
        "entries",
        "bytes",
        "case_json",
        "global_json",
        "frame_count",
    ] {
        let destination = root.join(kind);
        directory(&destination);
        let (mut left, mut right) = recorders(&destination);
        if kind == "files" {
            for n in 0..40957 {
                File::create(destination.join(format!("f{n}"))).unwrap();
            }
        } else if kind == "entries" {
            for n in 0..41106 {
                directory(&destination.join(format!("d{n}")));
            }
        } else if kind == "bytes" {
            let mut remaining = 2 * 1024 * 1024 * 1024 - 2_000_000;
            for n in 0..64 {
                let len = remaining.min(MAX_FILE);
                File::create(destination.join(format!("b{n}")))
                    .unwrap()
                    .set_len(len)
                    .unwrap();
                remaining -= len;
            }
            assert_eq!(remaining, 0);
        } else if kind == "case_json" || kind == "global_json" {
            let (parent, count) = if kind == "case_json" {
                (destination.join("right"), 4)
            } else {
                (destination.clone(), 16)
            };
            for n in 0..=count {
                File::create(parent.join(format!("j{n}.json")))
                    .unwrap()
                    .set_len(if n == count { 1 } else { MAX_FILE })
                    .unwrap();
            }
        } else {
            for _ in 0..128 {
                left.frame(&frames[0].0, None, None, Some(&frames[0].1))
                    .unwrap();
            }
        }
        let before_left = left.frame_export_progress().0.len();
        assert!(SharedFrameReservation::prepare(&mut left, &mut right).is_err());
        assert_eq!(left.frame_export_progress().0.len(), before_left);
        assert!(right.frame_export_progress().0.is_empty());
        if kind == "frame_count" {
            assert!(!destination.join(".recording-reservation").exists());
        } else {
            assert!(destination.join(".recording-reservation").is_file());
        }
        // Failed admission evidence is never cleared to manufacture recovery.
        fresh_success(&root.join(format!("fresh-{kind}")), &frames);
    }
}

fn partial_child() {
    let root = root("partial_child");
    let frames = captures(&root);
    let destination = root.join("paired");
    directory(&destination);
    let (mut left, mut right) = recorders(&destination);
    let mut pending = SharedFrameReservation::prepare(&mut left, &mut right).unwrap();
    let mut previous = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, &mut previous) },
        0
    );
    let handler = unsafe { libc::signal(libc::SIGXFSZ, libc::SIG_IGN) };
    assert_ne!(handler, libc::SIG_ERR);
    let limited = libc::rlimit {
        rlim_cur: 524288,
        rlim_max: previous.rlim_max,
    };
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &limited) }, 0);
    let refused = pending.record_next(&frames[0].0, &frames[0].1);
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &previous) }, 0);
    assert_ne!(
        unsafe { libc::signal(libc::SIGXFSZ, handler) },
        libc::SIG_ERR
    );
    assert!(refused.is_err());
    drop(pending);
    let bytes = fs::metadata(leaf(&destination, "left", "frame-0.bgra"))
        .unwrap()
        .len();
    assert!(bytes > 0 && bytes < FRAME_BYTES as u64);
    clean_progress(&left, &right);
    assert!(destination.join(".recording-reservation").is_file());
    assert!(SharedFrameReservation::prepare(&mut left, &mut right).is_err());
    fresh_success(&root.join("fresh"), &frames);
}

#[test]
fn shared_frame_partial_write_retains_owner_and_fresh_root_succeeds() {
    if std::env::var_os("RAMEN_SHARED_FRAME_PARTIAL_CHILD").is_some() {
        partial_child();
        return;
    }
    let root = root("partial_parent");
    let stdout = File::create(root.join("child.stdout")).unwrap();
    let stderr = File::create(root.join("child.stderr")).unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "shared_frame_partial_write_retains_owner_and_fresh_root_succeeds",
            "--test-threads=1",
            "--nocapture",
        ])
        .env("RAMEN_SHARED_FRAME_PARTIAL_CHILD", "1")
        .env("RAMEN_SHARED_FRAME_CONTROL_ROOT", &root)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .unwrap();
    let pid = child.id();
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let actual = child.wait().unwrap();
            panic!("owned partial-write child timed out; actual wait {actual}");
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    assert!(
        status.success(),
        "retained child log describes actual failure"
    );
    let destination = root.join("partial_child/paired");
    let bytes = fs::metadata(leaf(&destination, "left", "frame-0.bgra"))
        .unwrap()
        .len();
    assert!(bytes > 0 && bytes < FRAME_BYTES as u64);
    assert!(destination.join(".recording-reservation").is_file());
    assert!(!leaf(&destination, "right", "frame-0.bgra").exists());
    assert!(
        root.join("partial_child/fresh/left/frames/0/frame-0.bgra")
            .is_file()
    );
    fs::write(root.join("child-wait.json"), serde_json::to_vec(&serde_json::json!({"pid":pid,"exit_code":status.code(),"reaped":true,"partial_bytes":bytes})).unwrap()).unwrap();
}

#[test]
fn shared_frame_second_write_refusal_retains_first_rows() {
    let root = root("second_write");
    let frames = captures(&root);
    let destination = root.join("paired");
    directory(&destination);
    let (mut left, mut right) = recorders(&destination);
    let mut pending = SharedFrameReservation::prepare(&mut left, &mut right).unwrap();
    pending.record_next(&frames[0].0, &frames[0].1).unwrap();
    directory(&leaf(&destination, "right", "frame-0.bgra"));
    assert!(pending.record_next(&frames[1].0, &frames[1].1).is_err());
    fs::rename(
        leaf(&destination, "right", "frame-0.bgra"),
        destination.join("retained-refused-directory"),
    )
    .unwrap();
    assert!(pending.record_next(&frames[1].0, &frames[1].1).is_err());
    assert!(pending.finish().is_err());
    assert_eq!(
        (
            left.frame_export_progress().0.len(),
            left.frame_export_progress().1.len()
        ),
        (2, 1)
    );
    assert!(right.frame_export_progress().0.is_empty());
    assert_eq!(
        fs::read(leaf(&destination, "left", "frame-0.bgra")).unwrap(),
        frames[0].0.bgra
    );
    assert!(destination.join(".recording-reservation").is_file());
    assert!(SharedFrameReservation::prepare(&mut left, &mut right).is_err());
    fresh_success(&root.join("fresh"), &frames);
    let mut malformed = frames;
    let destination = root.join("malformed_first");
    directory(&destination);
    let (mut left, mut right) = recorders(&destination);
    let mut pending = SharedFrameReservation::prepare(&mut left, &mut right).unwrap();
    let chrome = malformed[0].1.record248.take();
    assert!(
        pending
            .record_next(&malformed[0].0, &malformed[0].1)
            .is_err()
    );
    malformed[0].1.record248 = chrome;
    assert!(
        pending
            .record_next(&malformed[0].0, &malformed[0].1)
            .is_err()
    );
    assert!(pending.finish().is_err());
    clean_progress(&left, &right);
    assert!(destination.join(".recording-reservation").is_file());
    let destination = root.join("malformed_frame");
    directory(&destination);
    let (mut left, mut right) = recorders(&destination);
    let mut pending = SharedFrameReservation::prepare(&mut left, &mut right).unwrap();
    let last = malformed[0].0.bgra.pop().unwrap();
    assert!(
        pending
            .record_next(&malformed[0].0, &malformed[0].1)
            .is_err()
    );
    malformed[0].0.bgra.push(last);
    assert!(
        pending
            .record_next(&malformed[0].0, &malformed[0].1)
            .is_err()
    );
    assert!(pending.finish().is_err());
    clean_progress(&left, &right);
    assert!(destination.join(".recording-reservation").is_file());
    let destination = root.join("extra_third");
    directory(&destination);
    let (mut left, mut right) = recorders(&destination);
    let mut pending = SharedFrameReservation::prepare(&mut left, &mut right).unwrap();
    pending
        .record_next(&malformed[0].0, &malformed[0].1)
        .unwrap();
    pending
        .record_next(&malformed[1].0, &malformed[1].1)
        .unwrap();
    assert!(
        pending
            .record_next(&malformed[0].0, &malformed[0].1)
            .is_err()
    );
    assert!(pending.finish().is_err());
    assert!(destination.join(".recording-reservation").is_file());
    exact_files(&destination, &malformed, 0);
    fresh_success(&root.join("fresh-after-sticky-errors"), &malformed);
}

#[test]
fn shared_frame_second_composition_failure_retains_first_export() {
    let root = root("second_compose");
    let seeds = root.join("seeds");
    directory(&seeds);
    let (first, first_app) = seed(&seeds, "first");
    let (second, mut second_app) = seed(&seeds, "second");
    let fallback = support::ok(second.capture_composed_frame(0, 2));
    // app() composed once and fallback composed once. Each remaining genuine
    // composition consumes a fresh genuine render until the original 128 cap.
    for _ in 0..126 {
        support::ok(second_app.render(2));
        support::ok(second.capture_composed_frame(0, 2));
    }
    let destination = root.join("paired");
    directory(&destination);
    let (mut left, mut right) = recorders(&destination);
    let mut pending = SharedFrameReservation::prepare(&mut left, &mut right).unwrap();
    let first_frame = support::ok(first.capture_composed_frame(0, 2));
    pending.record_next(&first_frame.0, &first_frame.1).unwrap();
    assert!(matches!(
        second.capture_composed_frame(0, 2),
        Err(Status::Exhausted)
    ));
    drop(pending);
    assert_eq!(
        (
            left.frame_export_progress().0.len(),
            left.frame_export_progress().1.len()
        ),
        (2, 1)
    );
    assert!(right.frame_export_progress().0.is_empty());
    assert_eq!(
        fs::read(leaf(&destination, "left", "frame-0.bgra")).unwrap(),
        first_frame.0.bgra
    );
    assert!(destination.join(".recording-reservation").is_file());
    assert!(SharedFrameReservation::prepare(&mut left, &mut right).is_err());
    drop((first_app, second_app));
    first.finish();
    second.finish();
    fresh_success(&root.join("fresh"), &[first_frame, fallback]);
}
