//! Consume Root's actual build/unchanged-consumer receipts. No recursive gate,
//! cached PASS token, fixture-generated success flag or production authority.
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    io::{BufReader, Read},
    path::{Path, PathBuf},
    sync::OnceLock,
};
fn digest(path: &Path) -> String {
    let metadata = fs::symlink_metadata(path).expect("actual retained file");
    assert!(metadata.is_file() && !metadata.file_type().is_symlink());
    assert!(metadata.len() <= 1_073_741_824);
    let mut file = BufReader::new(fs::File::open(path).unwrap());
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let count = file.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    hash.finalize().iter().map(|b| format!("{b:02x}")).collect()
}
fn retained(row: &Value) -> PathBuf {
    let path = PathBuf::from(row["path"].as_str().expect("literal recorded path"));
    assert!(path.is_absolute());
    assert_eq!(digest(&path), row["sha256"].as_str().unwrap());
    path
}
fn source_manifest(row: &Value, repo: &Path) -> BTreeSet<String> {
    let path = retained(row);
    assert!(fs::metadata(&path).unwrap().len() <= 524288);
    let rows: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let mut names = BTreeSet::new();
    for source in rows.as_array().unwrap() {
        let name = source
            .get("path")
            .or_else(|| source.get("relative_path"))
            .unwrap()
            .as_str()
            .unwrap();
        let path = Path::new(name);
        assert!(
            !path.is_absolute()
                && !path
                    .components()
                    .any(|p| matches!(p, std::path::Component::ParentDir))
        );
        assert!(names.insert(name.to_owned()));
        let path = repo.join(path);
        assert_eq!(
            fs::metadata(&path).unwrap().len(),
            source
                .get("bytes")
                .or_else(|| source.get("byte_len"))
                .unwrap()
                .as_u64()
                .unwrap()
        );
        assert_eq!(digest(&path), source["sha256"].as_str().unwrap());
    }
    assert!(!names.is_empty() && names.len() <= 1024);
    names
}
fn report() -> &'static Value {
    static RECORD: OnceLock<Value> = OnceLock::new();
    RECORD.get_or_init(|| {
        let path = PathBuf::from(
            std::env::var_os("RAMEN_PROCESS_GATE_RECORD")
                .expect("fresh Root gate record is required"),
        );
        assert!(path.is_absolute());
        assert!(fs::metadata(&path).unwrap().len() <= 33_554_432);
        let value: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(value["schema_version"], 1);
        assert_eq!(
            value["phase"], "runtime",
            "preparation cannot satisfy runtime acceptance"
        );
        let nonce = value["run_nonce"].as_str().unwrap();
        assert!(
            nonce.len() == 32
                && nonce
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        let repo = PathBuf::from(value["repo"].as_str().unwrap());
        assert_eq!(
            repo.canonicalize().unwrap(),
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .canonicalize()
                .unwrap()
        );
        let names = source_manifest(&value["source_manifest"], &repo);
        for required in [
            "Cargo.lock",
            "apps/artifact_editor/src/native.rs",
            "apps/artifact_editor/tests/process_task.rs",
            "services/desktop/src/editor_dev/process_editor.rs",
            "services/desktop/src/editor_dev/process_editor/linux.rs",
            "apps/artifact_editor/src/bin/editor-process.rs",
        ] {
            assert!(names.contains(required));
        }
        assert_eq!(value["lockfile"]["before"], value["lockfile"]["after"]);
        assert_eq!(
            digest(&repo.join("Cargo.lock")),
            value["lockfile"]["after"].as_str().unwrap()
        );
        let mut ids = BTreeSet::new();
        for probe in value["probes"].as_array().unwrap() {
            assert!(ids.insert(probe["id"].as_str().unwrap()));
            assert_eq!(probe["wait_reaped"], true);
            assert_eq!(probe["cleanup_uncertain"], false);
            assert!(!probe["argv"].as_array().unwrap().is_empty());
            retained(&probe["stdout"]);
            retained(&probe["stderr"]);
            for artifact in probe["artifacts"].as_array().unwrap() {
                retained(artifact);
            }
            for gate in probe["gate_reports"].as_array().unwrap() {
                let path = retained(gate);
                let actual: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                {
                    let child_names = source_manifest(&gate["source_manifest"], &repo);
                    assert_eq!(
                        gate["source_manifest"]["sha256"],
                        gate["source_manifest_sha256"]
                    );
                    if actual.get("source_manifest_sha256").is_some() {
                        assert_eq!(
                            actual["source_manifest_sha256"],
                            gate["source_manifest_sha256"]
                        );
                    } else {
                        let embedded = actual["source_sha256"]
                            .as_object()
                            .expect("legacy gate's actual source inventory");
                        assert_eq!(child_names, embedded.keys().cloned().collect());
                        for (name, expected) in embedded {
                            assert_eq!(digest(&repo.join(name)), expected.as_str().unwrap());
                        }
                    }
                    let actual_nonce = actual
                        .get("run_nonce")
                        .or_else(|| actual.get("provenance").and_then(|p| p.get("nonce")));
                    assert_eq!(
                        gate.get("child_run_nonce").is_some(),
                        actual_nonce.is_some(),
                        "actual nested nonce must be explicitly joined iff present"
                    );
                    if let Some(actual_nonce) = actual_nonce {
                        assert_eq!(gate["child_run_nonce"], *actual_nonce);
                    }
                    assert!(
                        actual
                            .get("status")
                            .or_else(|| actual.get("outcome"))
                            .and_then(Value::as_str)
                            == Some("PASS"),
                        "actual unchanged semantic reader must accept"
                    );
                    if let Some(raw) = actual.get("artifact_sha256") {
                        for (name, expected) in raw.as_object().unwrap() {
                            assert_eq!(
                                digest(&path.parent().unwrap().join(name)),
                                expected.as_str().unwrap()
                            );
                        }
                    }
                }
            }
        }
        value
    })
}
pub fn assert_probe(id: &str, exit: i64) -> &'static Value {
    let probe = report()["probes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"].as_str() == Some(id))
        .expect("exact actual Root probe");
    assert_eq!(probe["exit_code"].as_i64(), Some(exit));
    probe
}
fn cargo_errors(probe: &Value) -> Vec<Value> {
    fs::read_to_string(retained(&probe["stdout"]))
        .unwrap()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|row| row["reason"] == "compiler-message" && row["message"]["level"] == "error")
        .map(|row| row["message"].clone())
        .collect()
}
pub fn assert_api_absent(id: &str, symbol: &str, receiver: &str) {
    let probe = assert_probe(id, 101);
    let errors = cargo_errors(probe);
    assert_eq!(
        errors.len(),
        1,
        "absence requires one exact diagnostic, not an unrelated build failure"
    );
    let error = &errors[0];
    assert_eq!(error["code"]["code"], "E0599");
    let text = error["message"].as_str().unwrap();
    assert!(text.contains(symbol) && text.contains(receiver));
}
pub fn default_off_and_child_graph() {
    let binary = assert_probe("D01DefaultBinaryAbsent", 101);
    let error = fs::read_to_string(retained(&binary["stderr"])).unwrap();
    assert!(error.contains("error: target `editor-process` in package `artifact_editor` requires the features: `host_editor_process_child_v0_dev`"));
    let api = assert_probe("D01DefaultParentApiAbsent", 101);
    let errors = cargo_errors(api);
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0]["code"]["code"], "E0432");
    assert!(
        errors[0]["message"]
            .as_str()
            .unwrap()
            .contains("desktop_service::editor_dev")
    );
    let graph = assert_probe("D01ChildGraphExcludesDesktopStore", 0);
    let output = fs::read_to_string(retained(&graph["stdout"])).unwrap();
    assert!(!output.trim().is_empty());
    let graph_args: Vec<_> = graph["argv"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(graph_args.contains(&"tree") && graph_args.contains(&"--no-default-features"));
    assert!(
        graph_args.contains(&"host_editor_process_child_v0_dev")
            && !graph_args.contains(&"--all-features")
    );
    assert!(
        graph_args
            .windows(2)
            .any(|w| matches!(w[0], "-p" | "--package") && w[1] == "artifact_editor")
    );
    assert!(
        graph_args
            .windows(2)
            .any(|w| matches!(w[0], "-e" | "--edges") && w[1] == "normal")
    );
    let graph_names: BTreeSet<_> = output
        .lines()
        .filter_map(|line| {
            let words: Vec<_> = line.split_whitespace().collect();
            words.windows(2).find_map(|w| {
                if w[1]
                    .strip_prefix('v')
                    .is_some_and(|v| v.as_bytes().first().is_some_and(u8::is_ascii_digit))
                {
                    Some(w[0].to_owned())
                } else {
                    None
                }
            })
        })
        .collect();
    assert!(
        !graph_names.is_empty(),
        "actual Cargo tree package/version records"
    );
    for name in [
        "artifact_editor",
        "desktop_editor_core",
        "kernel_api",
        "libc",
    ] {
        assert!(
            output
                .lines()
                .any(|line| line.split_whitespace().any(|word| word == name)),
            "actual child normal graph missing {name}"
        );
    }
    assert!(
        !output
            .lines()
            .any(|line| line.split_whitespace().any(|word| matches!(
                word,
                "desktop_service" | "store_service" | "artifact_store_core"
            )))
    );
    for id in ["D01ExplicitChildBuild", "D01ExplicitParentBuild"] {
        let probe = assert_probe(id, 0);
        let kind = if id == "D01ExplicitChildBuild" {
            "production_child"
        } else {
            "parent"
        };
        let artifacts = probe["artifacts"].as_array().unwrap();
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0]["kind"], kind);
        let cargo_rows = fs::read_to_string(retained(&probe["stdout"]))
            .unwrap()
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .collect::<Vec<_>>();
        assert!(
            cargo_rows
                .iter()
                .any(|r| r["reason"] == "build-finished" && r["success"] == true)
        );
        for artifact in probe["artifacts"].as_array().unwrap() {
            let native = cargo_rows
                .iter()
                .find(|row| {
                    row["reason"] == "compiler-artifact"
                        && (row["executable"] == artifact["path"]
                            || row["filenames"]
                                .as_array()
                                .is_some_and(|files| files.contains(&artifact["path"])))
                })
                .expect("actual Cargo-selected artifact, not a declared arbitrary path");
            assert_eq!(native["features"], artifact["features"]);
            assert_eq!(
                native["target"]["name"],
                if kind == "production_child" {
                    "editor-process"
                } else {
                    "artifact_editor"
                }
            );
            if artifact["kind"] == "production_child" {
                let declared_packages: BTreeSet<_> = artifact["package_names"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_str().unwrap().to_owned())
                    .collect();
                assert_eq!(
                    declared_packages, graph_names,
                    "actual selected child normal graph identity"
                );
                let features: BTreeSet<_> = artifact["features"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_str().unwrap())
                    .filter(|s| *s != "default")
                    .collect();
                assert_eq!(
                    features,
                    BTreeSet::from(["host_editor_process_child_v0_dev"])
                );
                assert!(
                    !artifact["package_names"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|v| matches!(
                            v.as_str(),
                            Some("desktop_service" | "store_service" | "artifact_store_core")
                        ))
                );
                let mut magic = [0; 4];
                fs::File::open(retained(artifact))
                    .unwrap()
                    .read_exact(&mut magic)
                    .unwrap();
                assert_eq!(&magic, b"\x7fELF");
            }
        }
    }
}
pub fn assert_registered_executable(actual: [u8; 32], production_required: bool) {
    let expected = actual
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let artifacts: Vec<_> = report()["probes"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|probe| probe["artifacts"].as_array().unwrap())
        .filter(|a| a["sha256"].as_str() == Some(expected.as_str()))
        .collect();
    assert!(
        !artifacts.is_empty(),
        "held executable must match actual Root registered artifact"
    );
    for artifact in artifacts {
        assert!(matches!(
            artifact["kind"].as_str(),
            Some("production_child" | "assertion_child")
        ));
        if production_required {
            assert_eq!(
                artifact["kind"], "production_child",
                "normal proof runs production child"
            );
        }
        retained(artifact);
    }
}

fn exact_python_probe(probe: &Value, script: &str, option: &str, input: &Path) {
    let args: Vec<_> = probe["argv"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(args.len(), 4);
    assert_eq!(args[0], "python3");
    let root = Path::new(report()["repo"].as_str().unwrap());
    let path = Path::new(args[1]);
    assert_eq!(
        if path.is_absolute() {
            path.to_owned()
        } else {
            root.join(path)
        },
        root.join(script)
    );
    assert_eq!(args[2], option);
    assert_eq!(Path::new(args[3]), input);
}

pub fn source_substitute_rejected(id: &str) {
    let probe = assert_probe(id, 1);
    let marker = if id == "D07ParentEditedDraftSourceReject" {
        "PROCESS_SOURCE_FORBIDDEN_PARENT_EDIT"
    } else {
        "PROCESS_SOURCE_FORBIDDEN_PARENT_RASTER"
    };
    let stderr = fs::read_to_string(retained(&probe["stderr"])).unwrap();
    assert!(
        stderr.lines().any(|line| line == marker),
        "exact source policy rejection"
    );
    let artifacts: Vec<_> = probe["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|a| a["kind"] == "source_mutant")
        .collect();
    assert_eq!(artifacts.len(), 1);
    let path = retained(artifacts[0]);
    assert!(fs::metadata(&path).unwrap().len() <= 4_194_304);
    let source = fs::read_to_string(&path).unwrap();
    assert!(
        source.contains(if id == "D07ParentEditedDraftSourceReject" {
            "step_native_editor("
        } else {
            "render_native_editor("
        })
    );
    exact_python_probe(
        probe,
        "tools/ci/editor_process_source_policy.py",
        "--source",
        &path,
    );
}

pub fn aggregate_recording_cap() {
    let probe = assert_probe("D25Aggregate131073RecordingCap", 0);
    let output = fs::read_to_string(retained(&probe["stdout"])).unwrap();
    let rows: Vec<_> = output
        .lines()
        .filter_map(|line| line.strip_prefix("PROCESS_RECORDER_BOUNDARY "))
        .collect();
    assert_eq!(rows.len(), 1);
    let row: Value = serde_json::from_str(rows[0]).unwrap();
    assert_eq!(row["scope"], "recorder-boundary-not-native");
    assert_eq!(row["before"]["count"], 131072);
    assert_eq!(row["attempt_index"], 131073);
    assert_eq!(row["before"], row["after"]);
    assert_eq!(row["error"], "aggregate control capacity");
    let leaves: Vec<_> = probe["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|a| a["kind"] == "control_leaf")
        .collect();
    assert_eq!(leaves.len(), 4);
    let parent = retained(leaves[0]).parent().unwrap().to_owned();
    exact_python_probe(
        probe,
        "tools/ci/editor_process_recording.py",
        "--boundary-output",
        &parent,
    );
    let mut hash = Sha256::new();
    let mut bytes = 0usize;
    for (index, leaf) in leaves.into_iter().enumerate() {
        let path = retained(leaf);
        assert_eq!(path, parent.join(format!("controls-{index}.jsonl")));
        assert!(fs::metadata(&path).unwrap().len() <= 33_554_432);
        let raw = fs::read(path).unwrap();
        bytes += raw.len();
        hash.update(&raw);
        assert!(raw.ends_with(b"\n"));
        let lines: Vec<_> = raw
            .split(|b| *b == b'\n')
            .filter(|b| !b.is_empty())
            .collect();
        assert_eq!(lines.len(), 32768);
        for (index, line) in lines.iter().enumerate() {
            let value: Value = serde_json::from_slice(line).unwrap();
            assert_eq!(value["i"].as_u64(), Some(index as u64 + 1));
        }
    }
    assert_eq!(row["before"]["bytes"].as_u64(), Some(bytes as u64));
    assert_eq!(row["before"]["sha256"], format!("{:x}", hash.finalize()));
}

pub fn parent_death_and_drop() {
    let probe = assert_probe("D29ActualParentDeathSubreaperQuarantine", 0);
    let name = "native::process_assertions::process_d29_actual_parent_death_retains_uncertain_store_quarantine";
    assert_eq!(probe["selected"], serde_json::json!([name]));
    assert_eq!(probe["passed"], probe["selected"]);
    let args: Vec<_> = probe["argv"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(
        args.contains(&"test")
            && args.contains(&"--lib")
            && args.contains(&"--exact")
            && args.contains(&"--nocapture")
            && args.contains(&name)
    );
    let output = fs::read_to_string(retained(&probe["stdout"])).unwrap();
    let rows: Vec<Value> = output
        .lines()
        .filter_map(|line| line.strip_prefix("D29_ACTUAL_QUARANTINE "))
        .map(|raw| serde_json::from_str(raw).unwrap())
        .collect();
    assert_eq!(rows.len(), 2);
    let modes: BTreeSet<_> = rows.iter().map(|r| r["mode"].as_str().unwrap()).collect();
    assert_eq!(modes, BTreeSet::from(["parent_death", "drop_child"]));
    for row in rows {
        assert_eq!(row["scenario"], "D29ActualParentDeathSubreaperQuarantine");
        assert_eq!(row["outer_adopted_and_waited"], true);
        assert_eq!(row["dead_parent_supervisor_joined"], false);
        assert_eq!(row["store_producers_joined"], false);
        assert_eq!(row["quarantined"], true);
        assert_eq!(row["store_outcome"], "unknown");
        assert!(row["native_child_pid"].as_u64().unwrap() > 0);
        assert!(row["native_child_birth_ticks"].as_u64().unwrap() > 0);
        let records = row["actual_waitpid_records"].as_array().unwrap();
        assert!(!records.is_empty());
        assert_eq!(
            records.last().unwrap()["returned_pid"],
            row["native_child_pid"]
        );
        assert!(
            records[..records.len() - 1]
                .iter()
                .all(|r| r["returned_pid"] == 0)
        );
        assert!(row["actual_terminal_wait"].is_object());
        assert_eq!(row["parent_peercred"]["pid"], row["actual_parent_pid"]);
        assert!(
            row["original"].is_object(),
            "actual retained original Save owners"
        );
    }
}

pub fn unchanged_consumers() {
    for (id, count) in [
        ("D30Launch17", 17),
        ("D30Volatile13", 13),
        ("D30Store7Reader16", 7),
        ("D30NativeRead9", 9),
        ("D30NativePreview5", 5),
        ("D30Original18Reader93", 18),
        ("D30Adapter4", 4),
        ("D30Reliability13", 13),
    ] {
        let probe = assert_probe(id, 0);
        exact_gate_command(probe, id);
        let expected = required_cases(id, Path::new(report()["repo"].as_str().unwrap()));
        let actual: BTreeSet<_> = probe["selected"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            actual, expected,
            "exact source-owned test inventory, not a selectedcount token"
        );
        verify_semantic_report(id, probe);
        let selected = probe["selected"].as_array().unwrap();
        let passed = probe["passed"].as_array().unwrap();
        assert_eq!(selected, passed);
        assert_eq!(selected.len(), count);
        assert!(
            !probe["gate_reports"].as_array().unwrap().is_empty(),
            "actual semantic reader receipts required"
        );
    }
}

fn rust_cases(path: &Path) -> BTreeSet<String> {
    let mut waiting = false;
    let mut result = BTreeSet::new();
    for line in fs::read_to_string(path).unwrap().lines() {
        let line = line.trim();
        if line == "#[test]" {
            waiting = true;
            continue;
        }
        if waiting && line.starts_with("fn ") {
            result.insert(line[3..].split('(').next().unwrap().to_owned());
            waiting = false;
        }
    }
    result
}
fn required_cases(id: &str, repo: &Path) -> BTreeSet<String> {
    let path = match id {
        "D30Launch17" => Some("services/desktop/tests/launch_lifetime.rs"),
        "D30Volatile13" => Some("services/desktop/tests/editor_host.rs"),
        "D30Store7Reader16" => Some("services/store_service/tests/editor_store.rs"),
        "D30NativeRead9" => Some("services/store_service/tests/editor_native_read.rs"),
        "D30NativePreview5" => Some("services/store_service/tests/editor_native_preview_read.rs"),
        "D30Original18Reader93" => Some("apps/artifact_editor/tests/native_task.rs"),
        _ => None,
    };
    if let Some(path) = path {
        return rust_cases(&repo.join(path));
    }
    if id == "D30Adapter4" {
        return [
            "services/desktop/tests/editor_adapter_migration.rs",
            "apps/artifact_editor/tests/editor_adapter_migration.rs",
        ]
        .iter()
        .flat_map(|p| rust_cases(&repo.join(p)))
        .collect();
    }
    let registry: Value = serde_json::from_slice(
        &fs::read(repo.join("tools/ci/editor_reliability_sources_v0.json")).unwrap(),
    )
    .unwrap();
    registry["targets"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|r| {
            r["cases"]
                .as_array()
                .unwrap()
                .iter()
                .map(|n| n.as_str().unwrap().to_owned())
        })
        .collect()
}
fn exact_gate_command(probe: &Value, id: &str) {
    let expected = match id {
        "D30Launch17" => ["bash", "tools/ci/foundry_desktop_host_launch_ui1_0.sh"],
        "D30Volatile13" => ["bash", "tools/ci/foundry_desktop_editor_host_ui1_1a.sh"],
        "D30Store7Reader16" => ["bash", "tools/ci/foundry_desktop_editor_store_ui1_1b.sh"],
        "D30NativeRead9" => [
            "python3",
            "tools/foundry/desktop_editor_native_read_gate.py",
        ],
        "D30NativePreview5" => [
            "python3",
            "tools/foundry/desktop_editor_native_preview_read_gate.py",
        ],
        "D30Original18Reader93" => ["bash", "tools/ci/foundry_desktop_editor_task_ui1_1c.sh"],
        "D30Adapter4" => [
            "bash",
            "tools/ci/foundry_editor_adapter_migration_ui1_1d.sh",
        ],
        "D30Reliability13" => ["bash", "tools/ci/foundry_editor_reliability_ui1_1.sh"],
        _ => panic!("unknown gate"),
    };
    let argv = probe["argv"].as_array().unwrap();
    assert_eq!(argv.len(), 2);
    assert_eq!(argv[0], expected[0]);
    assert_eq!(argv[1], expected[1]);
}
fn exact_names(left: &Value, right: &Value) {
    let names = |v: &Value| {
        let rows = v.as_array().expect("exact name inventory");
        let set: BTreeSet<_> = rows
            .iter()
            .map(|n| n.as_str().unwrap().to_owned())
            .collect();
        assert_eq!(set.len(), rows.len(), "duplicate selected name");
        set
    };
    assert_eq!(names(left), names(right));
}
fn verify_semantic_report(id: &str, probe: &Value) {
    let mut found = false;
    for record in probe["gate_reports"].as_array().unwrap() {
        let path = retained(record);
        let value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        match id {
            "D30Launch17" | "D30Volatile13" => {
                if value.get("required_cases").is_none() {
                    continue;
                }
                exact_names(&value["required_cases"], &value["executed_cases"]);
                exact_names(&value["required_cases"], &probe["selected"]);
                assert_eq!(value["default_runtime_exposed"], false);
                assert!(
                    value["artifact_sha256"]
                        .as_object()
                        .is_some_and(|m| !m.is_empty())
                );
                found = true;
            }
            "D30Store7Reader16" => {
                if value["gate"] != "foundry-desktop-editor-store-ui1-1b" {
                    continue;
                }
                assert_eq!(value["behavior_case_count"], 7);
                assert_eq!(value["semantic_case_count"], 16);
                exact_names(&value["behavior_cases"], &probe["selected"]);
                found = true;
            }
            "D30NativeRead9" | "D30NativePreview5" => {
                if value.get("cases").is_none() {
                    continue;
                }
                exact_names(&value["cases"], &probe["selected"]);
                assert!(
                    value["commands"]
                        .as_array()
                        .is_some_and(|rows| !rows.is_empty())
                );
                assert!(value["test_process"].is_object());
                found = true;
            }
            "D30Original18Reader93" => {
                if value
                    .get("actual_eighteen_unfiltered_runtime_outcomes")
                    .is_none()
                {
                    continue;
                }
                assert_eq!(value["actual_eighteen_unfiltered_runtime_outcomes"], true);
                let consistency = &value["provenance"]["case_data_consistency"];
                assert_eq!(consistency["cases"], 18);
                assert_eq!(consistency["runtime_acceptance_claim"], false);
                let repo = Path::new(report()["repo"].as_str().unwrap());
                let source: Value = serde_json::from_slice(
                    &fs::read(
                        repo.join("docs/contracts/editor-native-save-source-inventory-v0.json"),
                    )
                    .unwrap(),
                )
                .unwrap();
                let expected: BTreeSet<_> = source["cases"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .flat_map(|case| {
                        case["scenarios"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(move |scenario| {
                                (
                                    case["case"].as_str().unwrap().to_owned(),
                                    format!(
                                        "{}/{}",
                                        scenario["scenario"].as_str().unwrap(),
                                        scenario["source_leg"].as_u64().unwrap()
                                    ),
                                )
                            })
                    })
                    .collect();
                let actual: BTreeSet<_> = consistency["scenarios"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|r| {
                        (
                            r["case"].as_str().unwrap().to_owned(),
                            r["scenario"].as_str().unwrap().to_owned(),
                        )
                    })
                    .collect();
                assert_eq!(actual.len(), 93);
                assert_eq!(actual, expected);
                found = true;
            }
            "D30Reliability13" => {
                if value["gate"] != "editor-reliability" {
                    continue;
                }
                let cases: BTreeSet<_> = value["targets"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .flat_map(|t| {
                        t["cases"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|v| v.as_str().unwrap())
                    })
                    .collect();
                let selected: BTreeSet<_> = probe["selected"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_str().unwrap())
                    .collect();
                assert_eq!(cases, selected);
                found = true;
            }
            "D30Adapter4" => {
                let stdout = fs::read_to_string(retained(&probe["stdout"])).unwrap();
                let stderr = fs::read_to_string(retained(&probe["stderr"])).unwrap();
                let both = stdout + &stderr;
                for name in probe["selected"].as_array().unwrap() {
                    assert!(both.contains(&format!("test {} ... ok", name.as_str().unwrap())));
                }
                for marker in [
                    "ADAPTER_ASSERT actual-text-max hidden-owner-atomic PASS",
                    "ADAPTER_ASSERT actual-view-max hidden-owner-atomic PASS",
                    "EDITOR_ADAPTER_MIGRATION: PASS tests=4 scope=adapter-preservation",
                ] {
                    assert!(both.contains(marker));
                }
                found = true;
            }
            _ => unreachable!(),
        }
    }
    assert!(
        found,
        "required actual semantic reader/raw inventory absent for {id}"
    );
}
