//! Real failure controls for the test-private reopened-Save diagnostic path.
#![cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "app_cases.rs"]
mod app_cases;
#[allow(dead_code)]
#[path = "fixture.rs"]
mod fixture;
#[allow(dead_code)]
#[path = "../native_task_support/mod.rs"]
mod support;
use desktop_service::{dev::Status, editor_dev as desktop};
use std::{
    fs::{self, File},
    os::unix::fs::DirBuilderExt,
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};
use support::*;

const CASE: &str = "d21_diagnostic_control";
fn directory(path: &Path) {
    fs::DirBuilder::new().mode(0o700).create(path).unwrap();
}
fn panic_text(payload: &(dyn std::any::Any + Send)) -> &str {
    if let Some(text) = payload.downcast_ref::<String>() {
        text
    } else if let Some(text) = payload.downcast_ref::<&str>() {
        text
    } else {
        panic!("actual original assertion must retain its string payload")
    }
}
fn child_case(mode: &str) {
    assert!(matches!(mode, "success" | "io" | "refusal" | "cleanup"));
    let fixture = fixture::fixture(CASE, 1);
    let result = catch_unwind(AssertUnwindSafe(|| {
        app_cases::fresh_save_after_reopen_with_control(fixture, OLD, |f, endpoint| {
            if matches!(mode, "io" | "refusal") {
                ok(f.prepared().controller().fail_next_io(
                    endpoint,
                    store_service::editor_store::IoPoint::JournalDirectorySync,
                ));
            } else if mode == "cleanup" {
                let store = f.prepared.as_ref().unwrap().clone();
                let pause = std::sync::Arc::new(ok(store.controller().pause_native_save(
                    endpoint,
                    store_service::editor_store::PausePoint::BeforeCommitPermit,
                )));
                // This actual pause deliberately remains held during cleanup.
                // Neither diagnostics nor the control manufactures its release.
                f.store_pauses.push((store, pause));
            }
            if mode == "refusal" {
                let parent = PathBuf::from(std::env::var_os("RAMEN_NATIVE_TASK_EVIDENCE").unwrap());
                directory(
                    &parent
                        .join(CASE)
                        .join("process_preparation/0/failure-before_cleanup.json"),
                );
            }
        });
    }));
    if let Err(payload) = result {
        let path = PathBuf::from(std::env::var_os("RAMEN_D21_CONTROL_CHILD_ROOT").unwrap());
        fs::write(path.join("observed-panic.txt"), panic_text(&*payload)).unwrap();
        resume_unwind(payload);
    }
}
struct OwnedControlChild(Option<Child>);
impl OwnedControlChild {
    fn wait(&mut self) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = self.0.as_mut().unwrap().try_wait().unwrap() {
                self.0.take();
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "actual diagnostic control child deadline"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
impl Drop for OwnedControlChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            if child.wait().is_err() {
                let _ = std::io::Write::write_all(
                    &mut std::io::stderr().lock(),
                    b"INCOMPLETE: diagnostic control child wait failed\n",
                );
            }
        }
    }
}
fn run_child(test: &str, mode: &str, root: &Path) -> serde_json::Value {
    directory(root);
    for name in ["parent-io", "process-io", "fixtures"] {
        directory(&root.join(name));
    }
    let stdout = File::create(root.join("child.stdout")).unwrap();
    let stderr = File::create(root.join("child.stderr")).unwrap();
    let nonce = std::env::var("RAMEN_NATIVE_TASK_RUN_NONCE").unwrap();
    let mut child = OwnedControlChild(Some(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--test-threads=1", "--nocapture"])
            .env("RAMEN_D21_CONTROL_CHILD", mode)
            .env("RAMEN_D21_CONTROL_CHILD_ROOT", root)
            .env("RAMEN_NATIVE_TASK_EVIDENCE", root.join("parent-io"))
            .env("RAMEN_PROCESS_EVIDENCE", root.join("process-io"))
            .env("RAMEN_NATIVE_TASK_RUN_NONCE", &nonce)
            .env("RAMEN_PROCESS_RUN_NONCE", &nonce)
            .env("TMPDIR", root.join("fixtures"))
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .unwrap(),
    ));
    let pid = child.0.as_ref().unwrap().id();
    let started = Instant::now();
    let status = child.wait();
    let observed = serde_json::json!({"pid":pid,"exit_code":status.code(),"reaped":true,"elapsed_ns":started.elapsed().as_nanos(),"mode":mode});
    fs::write(
        root.join("child-wait.json"),
        serde_json::to_vec(&observed).unwrap(),
    )
    .unwrap();
    assert_eq!(status.code(), Some(if mode == "success" { 0 } else { 101 }));
    let scenario = root
        .join("parent-io")
        .join(CASE)
        .join("process_preparation/0");
    let stderr = fs::read_to_string(root.join("child.stderr")).unwrap();
    if mode == "success" {
        assert!(!stderr.contains("D21_FAILURE_DIAGNOSTIC"));
        assert!(!stderr.contains("INCOMPLETE"));
        assert!(scenario.join("summary.json").is_file());
        assert!(!scenario.join("failure-before_cleanup.json").exists());
        return observed;
    }
    let rows: Vec<serde_json::Value> = stderr
        .lines()
        .filter_map(|line| line.strip_prefix("D21_FAILURE_DIAGNOSTIC "))
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        rows.len(),
        3,
        "compact evidence survives any recorder failure"
    );
    assert!(rows.iter().all(|row| row["acceptance"] == false));
    let before = &rows[0];
    assert_eq!(before["phase"], "before_cleanup");
    assert_eq!(before["core_epoch_index"], 1);
    let panic = fs::read_to_string(root.join("observed-panic.txt")).unwrap();
    assert!(panic.starts_with("original one-second public process task:"));
    assert_eq!(
        panic,
        before["original_panic"].as_str().unwrap(),
        "exact original payload must survive diagnostic and cleanup failures"
    );
    let retained = PathBuf::from(before["root"]["path"].as_str().unwrap());
    assert!(retained.starts_with(root.join("fixtures")) && retained.is_dir());
    assert!(before["pending_originals"].is_number());
    assert!(!scenario.join("summary.json").exists());
    assert!(!scenario.join("cleanup.json").exists());
    let proof = &rows[1]["child_exit_proof"];
    assert_eq!(rows[1]["phase"], "after_child_join");
    assert!(proof["process_id"].as_u64().unwrap() > 0);
    assert!(proof["birth_ticks"].as_u64().unwrap() > 0);
    assert_eq!(proof["supervisor_joined"], true);
    assert!(proof["wait_outcome"].is_string());
    assert_eq!(rows[2]["phase"], "after_original_cleanup");
    if mode == "refusal" {
        assert!(scenario.join("failure-before_cleanup.json").is_dir());
        assert!(root.join("parent-io/.recording-reservation").is_file());
        let errors: Vec<serde_json::Value> = stderr
            .lines()
            .filter_map(|line| line.strip_prefix("D21_FAILURE_DIAGNOSTIC_ERROR "))
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert!(errors.iter().any(|row| {
            row["stage"] == "before_cleanup"
                && row["detail"]["result"] == "Err"
                && row["detail"]["error"]
                    .as_str()
                    .unwrap()
                    .contains("fresh export file")
        }));
    } else {
        let snapshot = scenario.join(format!(
            "store-epoch-1-snapshot-{}.json",
            before["next_store_snapshot"].as_u64().unwrap()
        ));
        let snapshot: serde_json::Value =
            serde_json::from_slice(&fs::read(snapshot).unwrap()).unwrap();
        assert_eq!(snapshot["binding"]["epoch_index"], 1);
        assert!(
            snapshot["native_fence"].is_null(),
            "pre-cleanup observation is not quiescence proof"
        );
        assert_eq!(snapshot["objects"][0]["service_epoch"], 2);
        if mode == "io" {
            assert!(
                snapshot["io_events"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|row| row["point"] == "JournalDirectorySync"
                        && row["outcome"] == "SimulatedFailure")
            );
        } else {
            assert_eq!(rows[2]["cleanup_outcome"], "failed_or_panicked");
            assert_eq!(rows[2]["original_cleanup"]["result"], "panic");
            let secondary = rows[2]["original_cleanup"]["panic"].as_str().unwrap();
            assert!(
                secondary.starts_with("INCOMPLETE: same original reconciliation failed")
                    && secondary.contains("Timeout")
            );
            assert_eq!(rows[2]["parent_transfer"]["result"], "not_attempted");
            assert!(
                snapshot["barriers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|row| row["entered"] == true && row["released"] == false)
            );
            assert!(
                rows[2]["pending_originals"].as_u64().unwrap() > 0
                    || rows[2]["producer_counts"]["held"].as_u64().unwrap() > 0
            );
        }
    }
    observed
}
fn control(test: &str, mode: &str) {
    if let Some(mode) = std::env::var_os("RAMEN_D21_CONTROL_CHILD") {
        child_case(mode.to_str().unwrap());
        return;
    }
    let root =
        PathBuf::from(std::env::var_os("RAMEN_D21_DIAGNOSTIC_CONTROL_ROOT").unwrap()).join(test);
    directory(&root);
    run_child(test, mode, &root.join("original"));
    if mode != "success" {
        run_child(test, "success", &root.join("fresh_authorized"));
        assert!(root.join("original/observed-panic.txt").is_file());
    }
}
#[test]
fn d21_diagnostic_success_has_no_failure_records() {
    control("d21_diagnostic_success_has_no_failure_records", "success");
}
#[test]
fn d21_diagnostic_io_failure_preserves_original_panic() {
    control("d21_diagnostic_io_failure_preserves_original_panic", "io");
}
#[test]
fn d21_diagnostic_recording_refusal_preserves_original_panic() {
    control(
        "d21_diagnostic_recording_refusal_preserves_original_panic",
        "refusal",
    );
}
#[test]
fn d21_diagnostic_cleanup_failure_preserves_original_panic() {
    control(
        "d21_diagnostic_cleanup_failure_preserves_original_panic",
        "cleanup",
    );
}
