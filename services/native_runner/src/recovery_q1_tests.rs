mod controls {
    use super::*;
    // Independent Q1 raw-engine evidence and synthetic controls.

    #[test]
    fn q1_bridge_synthetic_observes_actual_bytes_and_retains_failures_in_order() {
        let module = wat::parse_str(
            r#"(module
            (memory (export "memory") 1 1)
            (func (export "recover_v0") (param i32 i32 i32 i32) (result i32) (local i32)
              local.get 0 i32.load8_u local.set 4
              local.get 4 i32.const 1 i32.eq if unreachable end
              local.get 4 i32.const 2 i32.eq if i32.const 7 return end
              local.get 2 i32.const 16 i32.store offset=4
              local.get 2 local.get 4 i32.store offset=8
              i32.const 0))"#,
        )
        .unwrap();
        let fixture =
            SyntheticStage::new(&module, &[("z", 4), ("a", 1), ("n", 2), ("m", 9), ("b", 3)]);
        let result = fixture.output("first");
        run_stage(&fixture.stage, &result, fixture.pins(), None).unwrap();
        let bytes = std::fs::read(&result).unwrap();
        let report: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(report["kind"], "recovery_q1_engine_result_v1");
        assert!(report["registration_sha256"].is_null());
        assert_eq!(
            report["plan_sha256"],
            digest(&std::fs::read(fixture.stage.join("plan.json")).unwrap())
        );
        let rows = report["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 5);
        assert_eq!(
            rows.iter()
                .map(|row| row["id"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["z", "a", "n", "m", "b"]
        );
        assert_eq!(rows[0]["input_sha256"], digest(&[4; INPUT_LEN]));
        assert_eq!(rows[0]["guest_return"], 0);
        assert_eq!(rows[0]["output_hex"], "00000000100000000400000000000000");
        assert!(rows[0]["error"].is_null());
        assert_eq!(rows[1]["error"]["kind"], "trap");
        assert!(rows[1]["guest_return"].is_null());
        assert!(rows[1]["output_hex"].is_null());
        assert_eq!(rows[2]["error"]["kind"], "guest_return");
        assert_eq!(rows[2]["guest_return"], 7);
        assert!(rows[2]["output_hex"].is_null());
        assert_eq!(rows[3]["error"]["kind"], "invalid_output");
        assert_eq!(rows[3]["guest_return"], 0);
        assert_eq!(rows[3]["output_hex"], "00000000100000000900000000000000");
        assert_eq!(rows[4]["output_hex"], "00000000100000000300000000000000");
        assert!(rows[4]["error"].is_null());

        let error = run_stage(&fixture.stage, &result, fixture.pins(), None).unwrap_err();
        assert!(error.to_string().contains("fresh result"));
        assert_eq!(std::fs::read(result).unwrap(), bytes);
        let fresh = fixture.output("fresh");
        run_stage(&fixture.stage, &fresh, fixture.pins(), None).unwrap();
        assert_eq!(std::fs::read(fresh).unwrap(), bytes);
    }

    #[test]
    fn q1_bridge_synthetic_rejects_identity_and_duplicate_inventory_before_output() {
        let module = b"synthetic invalid module";
        let fixture = SyntheticStage::new(module, &[("duplicate", 1), ("duplicate", 2)]);
        let output = fixture.output("duplicate");
        let error = run_stage(&fixture.stage, &output, fixture.pins(), None).unwrap_err();
        assert!(error.to_string().contains("duplicate case ID"));
        assert!(!output.exists());

        let fixture = SyntheticStage::new(module, &[("unique", 1)]);
        let output = fixture.output("identity");
        fixture.write("module.wasm", b"changed");
        let error = run_stage(&fixture.stage, &output, fixture.pins(), None).unwrap_err();
        assert!(error.to_string().contains("module digest"));
        assert!(!output.exists());

        fixture.write("module.wasm", module);
        run_stage(&fixture.stage, &output, fixture.pins(), None).unwrap();
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(output).unwrap()).unwrap();
        assert_eq!(value["rows"][0]["error"]["kind"], "module_shape");
    }

    #[test]
    fn q1_bridge_interrupted_writer_keeps_completed_row_and_fresh_run_succeeds() {
        struct FailSecondFlush {
            bytes: Vec<u8>,
            flushes: usize,
        }
        impl Write for FailSecondFlush {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.bytes.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.flushes += 1;
                if self.flushes == 2 {
                    return Err(std::io::Error::other("synthetic interrupted result"));
                }
                Ok(())
            }
        }
        let module = wat::parse_str(
            r#"(module
        (memory (export "memory") 1 1)
        (func (export "recover_v0") (param i32 i32 i32 i32) (result i32)
          local.get 2 i32.const 16 i32.store offset=4
          local.get 2 i32.const 4 i32.store offset=8
          i32.const 0))"#,
        )
        .unwrap();
        let fixture =
            SyntheticStage::new(&module, &[("first-complete", 1), ("later-unobserved", 2)]);
        let mut interrupted = FailSecondFlush {
            bytes: Vec::new(),
            flushes: 0,
        };
        let error = write_report(
            &mut interrupted,
            load_stage(&fixture.stage, fixture.pins()).unwrap(),
            fixture.pins(),
            None,
        )
        .unwrap_err();
        assert!(error.to_string().contains("synthetic interrupted result"));
        let prefix = String::from_utf8(interrupted.bytes).unwrap();
        assert!(prefix.contains("first-complete"));
        assert!(!prefix.contains("later-unobserved"));
        assert!(serde_json::from_str::<serde_json::Value>(&prefix).is_err());
        let mut good = Vec::new();
        write_report(
            &mut good,
            load_stage(&fixture.stage, fixture.pins()).unwrap(),
            fixture.pins(),
            None,
        )
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&good).unwrap();
        assert_eq!(parsed["rows"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn q1_bridge_stays_held_until_reviewed_registration_is_pinned() {
        let error = reviewed_registration(None, std::path::Path::new("never-opened")).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("reviewed comparison registration")
        );
    }
}

use super::*;
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

const CORPUS_SHA256: &str = "84eece3246d9b4521a5b8ac48fa6324cb4be4e98889277ab46837f6764aeda49";
const MODULE_SHA256: &str = "6458a173cd09e73fe0be59b1a2d339c2070c33ac05628b3d2dd5fb264cb2e079";
const REFERENCE_REVISION: &str = "958a6f1713129930b217c16b1a21140e8fab9ed0";
const REVIEWED_REGISTRATION_SHA256: Option<&str> = None;
const MAX_CORPUS_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Clone, Copy)]
struct Pins<'a> {
    corpus_sha256: &'a str,
    module_sha256: &'a str,
    case_count: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema_version: u32,
    kind: String,
    abi_sha256: String,
    corpus_sha256: String,
    module_sha256: String,
    case_count: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalCall {
    input_pointer: u32,
    input_length: u32,
    output_pointer: u32,
    output_capacity: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    family: String,
    reason: String,
    input_hex: String,
    expected_return: i32,
    expected_output_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Corpus {
    schema_version: u32,
    packet: String,
    contract_sha256: String,
    ramenos_reference_revision: String,
    canonical_call: CanonicalCall,
    derivation: String,
    cases: Vec<Case>,
}

struct Prepared {
    plan_sha256: String,
    module: Vec<u8>,
    cases: Vec<(String, [u8; INPUT_LEN])>,
}

#[derive(Serialize)]
struct ErrorRecord {
    kind: &'static str,
    detail: String,
}

#[derive(Serialize)]
struct Row {
    id: String,
    input_sha256: String,
    guest_return: Option<i32>,
    output_hex: Option<String>,
    error: Option<ErrorRecord>,
}

#[derive(Serialize)]
struct Header<'a> {
    schema_version: u32,
    kind: &'static str,
    plan_sha256: String,
    registration_sha256: Option<&'a str>,
}

fn digest(raw: &[u8]) -> String {
    hex::encode(Sha256::digest(raw))
}

fn private_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir()
            && metadata.permissions().mode() & 0o077 == 0
            && metadata.uid() == unsafe { libc::geteuid() },
        "expected owned private directory"
    );
    Ok(())
}

fn read_regular(path: &Path, bound: u64) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.permissions().mode() & 0o077 == 0
            && metadata.uid() == unsafe { libc::geteuid() },
        "expected owned private regular file"
    );
    let mut raw = Vec::new();
    file.take(bound + 1).read_to_end(&mut raw)?;
    ensure!(raw.len() as u64 <= bound, "artifact byte bound");
    Ok(raw)
}

fn decode_hex<const N: usize>(text: &str) -> Result<[u8; N]> {
    ensure!(
        text.len() == 2 * N
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "canonical fixed-length hex"
    );
    let mut raw = [0; N];
    hex::decode_to_slice(text, &mut raw)?;
    Ok(raw)
}

fn load_stage(directory: &Path, pins: Pins<'_>) -> Result<Prepared> {
    ensure!((1..=627).contains(&pins.case_count), "pinned case count");
    decode_hex::<32>(pins.module_sha256)?;
    decode_hex::<32>(pins.corpus_sha256)?;
    private_directory(directory)?;
    let plan_bytes = read_regular(&directory.join("plan.json"), 4096)?;
    let plan: Plan = serde_json::from_slice(&plan_bytes)?;
    ensure!(
        plan.schema_version == 1
            && plan.kind == "recovery_q1_plan_v1"
            && plan.abi_sha256 == hex::encode(RECOVERY_ABI_SHA256)
            && plan.corpus_sha256 == pins.corpus_sha256
            && plan.module_sha256 == pins.module_sha256
            && plan.case_count == pins.case_count,
        "plan metadata differs from pinned inputs"
    );
    let module = read_regular(&directory.join("module.wasm"), MAX_MODULE_BYTES as u64)?;
    ensure!(
        digest(&module) == pins.module_sha256,
        "module digest mismatch"
    );
    let corpus_bytes = read_regular(&directory.join("corpus.json"), MAX_CORPUS_BYTES)?;
    ensure!(
        digest(&corpus_bytes) == pins.corpus_sha256,
        "corpus digest mismatch"
    );
    let corpus: Corpus = serde_json::from_slice(&corpus_bytes)?;
    let call = corpus.canonical_call;
    ensure!(
        corpus.schema_version == 1
            && corpus.packet == "recovery-r0-v1"
            && corpus.contract_sha256 == hex::encode(RECOVERY_ABI_SHA256)
            && corpus.ramenos_reference_revision == REFERENCE_REVISION
            && call.input_pointer == INPUT as u32
            && call.input_length == INPUT_LEN as u32
            && call.output_pointer == OUTPUT as u32
            && call.output_capacity == OUTPUT_LEN as u32
            && !corpus.derivation.is_empty()
            && corpus.cases.len() == pins.case_count,
        "corpus envelope or count"
    );
    let mut seen = HashSet::new();
    let mut cases = Vec::with_capacity(pins.case_count);
    for case in corpus.cases {
        ensure!(
            !case.id.is_empty()
                && case.id.len() <= 96
                && case
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
            "case ID"
        );
        ensure!(seen.insert(case.id.clone()), "duplicate case ID");
        ensure!(
            !case.family.is_empty() && !case.reason.is_empty() && case.expected_return == 0,
            "case labels or expected return"
        );
        let input = decode_hex::<INPUT_LEN>(&case.input_hex)?;
        decode_output(decode_hex::<OUTPUT_LEN>(&case.expected_output_hex)?)?;
        cases.push((case.id, input));
    }
    Ok(Prepared {
        plan_sha256: digest(&plan_bytes),
        module,
        cases,
    })
}

fn describe(error: &RecoveryError) -> ErrorRecord {
    let kind = match error {
        RecoveryError::ArtifactIdentity => "artifact_identity",
        RecoveryError::ModuleShape => "module_shape",
        RecoveryError::Engine(_) => "engine",
        RecoveryError::InvalidOriginal => "invalid_original",
        RecoveryError::Fuel => "fuel",
        RecoveryError::Stack => "stack",
        RecoveryError::Trap(_) => "trap",
        RecoveryError::Return(_) => "guest_return",
        RecoveryError::Output => "invalid_output",
        RecoveryError::Disagreement { .. } => "disagreement",
    };
    ErrorRecord {
        kind,
        detail: error.to_string().chars().take(512).collect(),
    }
}

fn capture_row(
    adapter: &Result<RecoveryDecisionAdapter, RecoveryError>,
    id: String,
    input: [u8; INPUT_LEN],
) -> Row {
    let mut row = Row {
        id,
        input_sha256: digest(&input),
        guest_return: None,
        output_hex: None,
        error: None,
    };
    let observed = match adapter {
        Ok(adapter) => adapter.invoke(&input),
        Err(error) => {
            row.error = Some(describe(error));
            return row;
        }
    };
    match observed {
        Ok(raw) => {
            row.guest_return = Some(0);
            row.output_hex = Some(hex::encode(raw));
            if let Err(error) = decode_output(raw) {
                row.error = Some(describe(&error));
            }
        }
        Err(error) => {
            if let RecoveryError::Return(code) = &error {
                row.guest_return = Some(*code);
            }
            row.error = Some(describe(&error));
        }
    }
    row
}

fn run_stage(
    directory: &Path,
    output: &Path,
    pins: Pins<'_>,
    registration_sha256: Option<&str>,
) -> Result<()> {
    let prepared = load_stage(directory, pins)?;
    private_directory(output.parent().context("result needs a private parent")?)?;
    // Reserve the unique result before any engine execution.
    let mut result = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(output)
        .context("fresh result required")?;
    write_report(&mut result, prepared, pins, registration_sha256)
}

fn write_report<W: Write>(
    result: &mut W,
    prepared: Prepared,
    pins: Pins<'_>,
    registration_sha256: Option<&str>,
) -> Result<()> {
    let header = serde_json::to_vec(&Header {
        schema_version: 1,
        kind: "recovery_q1_engine_result_v1",
        plan_sha256: prepared.plan_sha256,
        registration_sha256,
    })?;
    result.write_all(&header[..header.len() - 1])?;
    result.write_all(b",\"rows\":[\n")?;
    result.flush()?;
    let adapter = RecoveryDecisionAdapter::new(
        &prepared.module,
        RecoveryArtifactV0 {
            abi_sha256: RECOVERY_ABI_SHA256,
            module_sha256: decode_hex::<32>(pins.module_sha256)?,
        },
    );
    for (index, (id, input)) in prepared.cases.into_iter().enumerate() {
        if index != 0 {
            result.write_all(b",\n")?;
        }
        let row = capture_row(&adapter, id, input);
        serde_json::to_writer(&mut *result, &row)?;
        result.flush()?;
    }
    result.write_all(b"\n]}\n")?;
    result.flush()?;
    Ok(())
}

fn reviewed_registration(pin: Option<&str>, path: &Path) -> Result<String> {
    let Some(expected) = pin else {
        bail!("reviewed comparison registration is pending");
    };
    decode_hex::<32>(expected)?;
    let raw = read_regular(path, MAX_CORPUS_BYTES)?;
    ensure!(digest(&raw) == expected, "registration digest mismatch");
    Ok(expected.to_owned())
}

#[test]
#[ignore = "requires reviewed comparison registration, frozen stage and explicit coordinator release"]
fn run_registered_recovery_corpus() {
    let registration = reviewed_registration(
        REVIEWED_REGISTRATION_SHA256,
        Path::new(&std::env::var_os("RECOVERY_Q1_REGISTRATION").unwrap_or_default()),
    )
    .unwrap();
    let stage =
        PathBuf::from(std::env::var_os("RECOVERY_Q1_STAGE_DIR").expect("explicit frozen stage"));
    let output =
        PathBuf::from(std::env::var_os("RECOVERY_Q1_RESULT").expect("explicit fresh result"));
    run_stage(
        &stage,
        &output,
        Pins {
            corpus_sha256: CORPUS_SHA256,
            module_sha256: MODULE_SHA256,
            case_count: 627,
        },
        Some(&registration),
    )
    .unwrap();
}

#[cfg(test)]
struct SyntheticStage {
    root: tempfile::TempDir,
    stage: PathBuf,
    corpus_sha256: String,
    module_sha256: String,
    case_count: usize,
}

#[cfg(test)]
impl SyntheticStage {
    fn new(module: &[u8], cases: &[(&str, u8)]) -> Self {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let stage = root.path().join("stage");
        fs::create_dir(&stage).unwrap();
        fs::set_permissions(&stage, fs::Permissions::from_mode(0o700)).unwrap();
        let corpus = serde_json::json!({
            "schema_version": 1, "packet": "recovery-r0-v1",
            "contract_sha256": hex::encode(RECOVERY_ABI_SHA256),
            "ramenos_reference_revision": REFERENCE_REVISION,
            "canonical_call": {"input_pointer": 4096, "input_length": 336,
                               "output_pointer": 4448, "output_capacity": 16},
            "derivation": "Synthetic evaluator fixture",
            "cases": cases.iter().map(|(id, byte)| serde_json::json!({
                "id": id, "family": "synthetic", "reason": "Synthetic evaluator fixture",
                "input_hex": hex::encode([*byte; INPUT_LEN]), "expected_return": 0,
                "expected_output_hex": "00000000100000000400000000000000"
            })).collect::<Vec<_>>(),
        });
        let raw = serde_json::to_vec_pretty(&corpus).unwrap();
        let fixture = Self {
            root,
            stage,
            corpus_sha256: digest(&raw),
            module_sha256: digest(module),
            case_count: cases.len(),
        };
        fixture.write("corpus.json", &raw);
        fixture.write("module.wasm", module);
        let plan = serde_json::json!({
            "schema_version": 1, "kind": "recovery_q1_plan_v1",
            "abi_sha256": hex::encode(RECOVERY_ABI_SHA256),
            "corpus_sha256": fixture.corpus_sha256,
            "module_sha256": fixture.module_sha256, "case_count": fixture.case_count,
        });
        let mut plan_bytes = serde_json::to_vec_pretty(&plan).unwrap();
        plan_bytes.push(b'\n');
        fixture.write("plan.json", &plan_bytes);
        fixture
    }

    fn pins(&self) -> Pins<'_> {
        Pins {
            corpus_sha256: &self.corpus_sha256,
            module_sha256: &self.module_sha256,
            case_count: self.case_count,
        }
    }

    fn output(&self, name: &str) -> PathBuf {
        self.root.path().join(format!("{name}.json"))
    }

    fn write(&self, name: &str, raw: &[u8]) {
        let path = self.stage.join(name);
        if path.exists() {
            fs::remove_file(&path).unwrap();
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(raw).unwrap();
    }
}
