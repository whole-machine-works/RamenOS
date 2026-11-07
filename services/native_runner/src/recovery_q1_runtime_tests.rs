//! Test-only T1 raw ABI observations. Candidate execution remains review-gated.

use super::*;
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

const FIXTURES_SHA256: &str = "0a1ebe3fb0023270b44fe7d1e23f1545f34d980e075dd9b1e8e9cbd756bbc2f2";
const MODULE_SHA256: &str = "6458a173cd09e73fe0be59b1a2d339c2070c33ac05628b3d2dd5fb264cb2e079";
const REGISTRATION_SHA256: &str =
    "185957fc5f45900995de9c4705c7936ac834cffea3006c67b6596e7e33e656e2";
const REVIEWED_MANIFEST_SHA256: Option<&str> = None;
const FALSE_FLAGS: [&str; 4] = [
    "owner_lifecycle_exercised",
    "live_parent_authority_exercised",
    "measured_benefit",
    "activation_accepted",
];
const PAGE: usize = 65536;
const CALLS: [[u32; 4]; 6] = [
    [4096, 335, 4448, 16],
    [4096, 337, 4448, 16],
    [65535, 336, 4448, 16],
    [u32::MAX, 336, 4448, 16],
    [4096, 336, 65528, 16],
    [4096, 336, 4448, 15],
];
const IDS: [&str; 6] = [
    "bad-call-input-short",
    "bad-call-input-long",
    "bad-call-input-end",
    "bad-call-pointer-wrap",
    "bad-call-output-end",
    "bad-call-output-capacity",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema_version: u32,
    kind: String,
    fixtures_sha256: String,
    module_sha256: String,
    owner_lifecycle_exercised: bool,
    live_parent_authority_exercised: bool,
    measured_benefit: bool,
    activation_accepted: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceCase {
    id: String,
    family: String,
    reason: String,
    input_hex: String,
    expected_return: i32,
    expected_output_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    call: [u32; 4],
    input_hex: String,
    expected_return: String,
    expected_memory: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    schema_version: u32,
    kind: String,
    abi_sha256: String,
    corpus_sha256: String,
    obligations_sha256: String,
    source_case: SourceCase,
    memory_bytes: usize,
    initial_fill_byte: u8,
    input_initialization_offset: usize,
    canonical_call: [u32; 4],
    cases: Vec<Case>,
}

#[derive(Clone, Copy)]
struct Pins<'a> {
    fixtures_sha256: &'a str,
    module_sha256: &'a str,
}

struct Prepared {
    plan_sha256: String,
    module: Vec<u8>,
    fixture: Fixture,
}

#[derive(Serialize)]
struct TrapRecord {
    kind: &'static str,
    detail: String,
}

#[derive(Serialize)]
struct Observation {
    guest_return: Option<i32>,
    trap: Option<TrapRecord>,
    memory_before_hex: String,
    memory_after_hex: String,
}

fn digest(raw: &[u8]) -> String {
    hex::encode(Sha256::digest(raw))
}

fn private_directory(path: &Path) -> Result<()> {
    let info = fs::symlink_metadata(path)?;
    ensure!(
        info.is_dir()
            && info.uid() == unsafe { libc::geteuid() }
            && info.permissions().mode() & 0o777 == 0o700,
        "private owned directory required"
    );
    Ok(())
}

fn read_regular(path: &Path, bound: u64) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let info = file.metadata()?;
    ensure!(
        info.is_file()
            && info.uid() == unsafe { libc::geteuid() }
            && info.permissions().mode() & 0o777 == 0o600,
        "private owned artifact required"
    );
    let mut raw = vec![];
    file.take(bound + 1).read_to_end(&mut raw)?;
    ensure!(raw.len() as u64 <= bound, "artifact byte bound");
    Ok(raw)
}

fn bytes(text: &str, length: usize) -> Result<Vec<u8>> {
    ensure!(
        text.len() == length * 2
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "fixed canonical hex"
    );
    Ok(hex::decode(text)?)
}

fn load_stage(directory: &Path, pins: Pins<'_>) -> Result<Prepared> {
    private_directory(directory)?;
    bytes(pins.fixtures_sha256, 32)?;
    bytes(pins.module_sha256, 32)?;
    let plan_raw = read_regular(&directory.join("plan.json"), 4096)?;
    let plan: Plan = serde_json::from_slice(&plan_raw)?;
    ensure!(
        plan.schema_version == 1
            && plan.kind == "recovery_q1_runtime_plan_v1"
            && plan.fixtures_sha256 == pins.fixtures_sha256
            && plan.module_sha256 == pins.module_sha256
            && !plan.owner_lifecycle_exercised
            && !plan.live_parent_authority_exercised
            && !plan.measured_benefit
            && !plan.activation_accepted,
        "exact scoped plan"
    );
    let module = read_regular(&directory.join("module.wasm"), MAX_MODULE_BYTES as u64)?;
    ensure!(
        digest(&module) == pins.module_sha256,
        "module digest mismatch"
    );
    let raw = read_regular(&directory.join("fixtures.json"), 32768)?;
    ensure!(
        digest(&raw) == pins.fixtures_sha256,
        "fixture digest mismatch"
    );
    let fixture: Fixture = serde_json::from_slice(&raw)?;
    ensure!(
        fixture.schema_version == 1
            && fixture.kind == "recovery_q1_runtime_fixtures_v1"
            && fixture.abi_sha256 == hex::encode(RECOVERY_ABI_SHA256)
            && fixture.memory_bytes == PAGE
            && fixture.initial_fill_byte == 165
            && fixture.input_initialization_offset == INPUT
            && fixture.canonical_call == [4096, 336, 4448, 16]
            && fixture.cases.len() == 6,
        "fixture identity/inventory"
    );
    bytes(&fixture.corpus_sha256, 32)?;
    bytes(&fixture.obligations_sha256, 32)?;
    let source = &fixture.source_case;
    ensure!(
        source.id == "outcome-0"
            && !source.family.is_empty()
            && !source.reason.is_empty()
            && source.expected_return == 0,
        "source case"
    );
    let canonical = bytes(&source.input_hex, INPUT_LEN)?;
    decode_output(
        bytes(&source.expected_output_hex, OUTPUT_LEN)?
            .try_into()
            .unwrap(),
    )?;
    for (n, case) in fixture.cases.iter().enumerate() {
        ensure!(
            case.id == IDS[n]
                && case.call == CALLS[n]
                && case.expected_return == "nonzero-not-trap"
                && case.expected_memory == "unchanged-outside-declared-output-capacity",
            "frozen call inventory"
        );
        let mut expected = canonical.clone();
        if n == 0 {
            expected.pop();
        } else if n == 1 {
            expected.push(0);
        }
        ensure!(
            bytes(&case.input_hex, expected.len())? == expected,
            "exact input mutation"
        );
    }
    Ok(Prepared {
        plan_sha256: digest(&plan_raw),
        module,
        fixture,
    })
}

fn initial_memory(fixture: &Fixture, case: Option<&Case>) -> Result<Vec<u8>> {
    let call = case.map_or(fixture.canonical_call, |case| case.call);
    let input = hex::decode(case.map_or(&fixture.source_case.input_hex, |case| &case.input_hex))?;
    let mut page = vec![165; PAGE];
    // All host accesses use checked legal offsets, even for invalid guest pointers.
    ensure!(
        INPUT
            .checked_add(input.len())
            .is_some_and(|end| end <= PAGE),
        "legal host input initialization"
    );
    page[INPUT..INPUT + input.len()].copy_from_slice(&input);
    let output = call[2] as usize;
    ensure!(output <= PAGE, "legal host output initialization");
    let end = output + OUTPUT_LEN.min(PAGE - output);
    page[output..end].fill(0);
    Ok(page)
}

fn observe(
    adapter: &RecoveryDecisionAdapter,
    initial: &[u8],
    call: [u32; 4],
) -> Result<Observation> {
    let mut store = Store::new(&adapter.engine, ());
    store.set_fuel(MAX_FUEL)?;
    let instance = Instance::new(&mut store, &adapter.module, &[])?;
    let recover = instance.get_typed_func::<(i32, i32, i32, i32), i32>(&mut store, "recover_v0")?;
    let memory = instance
        .get_memory(&mut store, "memory")
        .context("admitted memory export")?;
    ensure!(
        memory.data_size(&store) == PAGE && initial.len() == PAGE,
        "exact one page"
    );
    memory.write(&mut store, 0, initial)?;
    let mut before = vec![0; PAGE];
    memory.read(&store, 0, &mut before)?;
    // Rust's as conversion preserves the exact u32 two's-complement Wasm bits.
    let actual = recover.call(
        &mut store,
        (
            call[0] as i32,
            call[1] as i32,
            call[2] as i32,
            call[3] as i32,
        ),
    );
    let mut after = vec![0; PAGE];
    memory.read(&store, 0, &mut after)?;
    let (guest_return, trap) = match actual {
        Ok(returned) => (Some(returned), None),
        Err(error) => {
            let kind = match error.downcast_ref::<Trap>() {
                Some(Trap::OutOfFuel) => "fuel",
                Some(Trap::StackOverflow) => "stack",
                _ => "trap",
            };
            (
                None,
                Some(TrapRecord {
                    kind,
                    detail: error.to_string().chars().take(512).collect(),
                }),
            )
        }
    };
    Ok(Observation {
        guest_return,
        trap,
        memory_before_hex: hex::encode(before),
        memory_after_hex: hex::encode(after),
    })
}

fn write_report<W: Write>(
    output: &mut W,
    prepared: Prepared,
    registration: Option<&str>,
    manifest: Option<&str>,
) -> Result<()> {
    let header = serde_json::to_vec(
        &serde_json::json!({"schema_version":1,"kind":"recovery_q1_runtime_result_v1",
        "plan_sha256":prepared.plan_sha256,"registration_sha256":registration,"reviewed_manifest_sha256":manifest,
        "owner_lifecycle_exercised":false,"live_parent_authority_exercised":false,"measured_benefit":false,"activation_accepted":false}),
    )?;
    output.write_all(&header[..header.len() - 1])?;
    output.write_all(b",\"rows\":[\n")?;
    output.flush()?;
    let adapter = RecoveryDecisionAdapter::new(
        &prepared.module,
        RecoveryArtifactV0 {
            abi_sha256: RECOVERY_ABI_SHA256,
            module_sha256: Sha256::digest(&prepared.module).into(),
        },
    )?;
    for (n, case) in prepared.fixture.cases.iter().enumerate() {
        if n > 0 {
            output.write_all(b",\n")?;
        }
        let row = serde_json::to_vec(&serde_json::json!({"id":case.id,"call":case.call}))?;
        output.write_all(&row[..row.len() - 1])?;
        output.write_all(b",\"fault\":")?;
        let fault = observe(
            &adapter,
            &initial_memory(&prepared.fixture, Some(case))?,
            case.call,
        )?;
        serde_json::to_writer(&mut *output, &fault)?;
        output.flush()?;
        // The raw fault is retained before a separately instantiated fresh call.
        output.write_all(b",\"fresh\":")?;
        let fresh = observe(
            &adapter,
            &initial_memory(&prepared.fixture, None)?,
            prepared.fixture.canonical_call,
        )?;
        serde_json::to_writer(&mut *output, &fresh)?;
        output.write_all(b"}")?;
        output.flush()?;
    }
    output.write_all(b"\n],\"complete\":true}\n")?;
    output.flush()?;
    Ok(())
}

fn run_stage(
    directory: &Path,
    result: &Path,
    pins: Pins<'_>,
    registration: Option<&str>,
    manifest: Option<&str>,
) -> Result<()> {
    let prepared = load_stage(directory, pins)?;
    private_directory(result.parent().context("private result parent")?)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(result)
        .context("fresh result required")?;
    write_report(&mut output, prepared, registration, manifest)
}

fn reviewed_digest(pin: Option<&str>, path: &Path) -> Result<String> {
    let Some(pin) = pin else {
        bail!("reviewed T1 manifest is pending");
    };
    bytes(pin, 32)?;
    ensure!(
        digest(&read_regular(path, 2 * 1024 * 1024)?) == pin,
        "reviewed identity mismatch"
    );
    Ok(pin.to_owned())
}

#[test]
#[ignore = "requires new reviewed T1 manifest, exact source/executable pins and explicit coordinator release"]
fn run_registered_recovery_abi_refusals() {
    // Hold before consulting stage/output paths or creating an Engine.
    let manifest = reviewed_digest(
        REVIEWED_MANIFEST_SHA256,
        Path::new(&std::env::var_os("RECOVERY_Q1_T1_MANIFEST").unwrap_or_default()),
    )
    .unwrap();
    let registration = reviewed_digest(
        Some(REGISTRATION_SHA256),
        Path::new(&std::env::var_os("RECOVERY_Q1_REGISTRATION").unwrap_or_default()),
    )
    .unwrap();
    let stage =
        PathBuf::from(std::env::var_os("RECOVERY_Q1_T1_STAGE_DIR").expect("explicit frozen stage"));
    let result =
        PathBuf::from(std::env::var_os("RECOVERY_Q1_T1_RESULT").expect("explicit fresh result"));
    run_stage(
        &stage,
        &result,
        Pins {
            fixtures_sha256: FIXTURES_SHA256,
            module_sha256: MODULE_SHA256,
        },
        Some(&registration),
        Some(&manifest),
    )
    .unwrap();
}

struct SyntheticStage {
    root: tempfile::TempDir,
    stage: PathBuf,
    module_sha256: String,
    fixtures_sha256: String,
}
impl SyntheticStage {
    fn new(module: &[u8]) -> Self {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let stage = root.path().join("stage");
        fs::create_dir(&stage).unwrap();
        fs::set_permissions(&stage, fs::Permissions::from_mode(0o700)).unwrap();
        let input = vec![85; INPUT_LEN];
        let cases:Vec<_>=IDS.iter().enumerate().map(|(n,id)|{
            let mut raw=input.clone();if n==0 {raw.pop();} else if n==1 {raw.push(0);}
            serde_json::json!({"id":id,"call":CALLS[n],"input_hex":hex::encode(raw),
                "expected_return":"nonzero-not-trap","expected_memory":"unchanged-outside-declared-output-capacity"})
        }).collect();
        let fixture=serde_json::to_vec(&serde_json::json!({"schema_version":1,"kind":"recovery_q1_runtime_fixtures_v1",
            "abi_sha256":hex::encode(RECOVERY_ABI_SHA256),"corpus_sha256":"1".repeat(64),"obligations_sha256":"2".repeat(64),
            "source_case":{"id":"outcome-0","family":"synthetic","reason":"synthetic evaluator controls",
                "input_hex":hex::encode(input),"expected_return":0,"expected_output_hex":"00000000100000000100000000000000"},
            "memory_bytes":PAGE,"initial_fill_byte":165,"input_initialization_offset":INPUT,"canonical_call":[4096,336,4448,16],"cases":cases})).unwrap();
        let module_sha256 = digest(module);
        let fixtures_sha256 = digest(&fixture);
        let plan=serde_json::to_vec(&serde_json::json!({"schema_version":1,"kind":"recovery_q1_runtime_plan_v1",
            "fixtures_sha256":fixtures_sha256,"module_sha256":module_sha256,"owner_lifecycle_exercised":false,
            "live_parent_authority_exercised":false,"measured_benefit":false,"activation_accepted":false})).unwrap();
        for (name, raw) in [
            ("fixtures.json", fixture.as_slice()),
            ("module.wasm", module),
            ("plan.json", plan.as_slice()),
        ] {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(stage.join(name))
                .unwrap();
            file.write_all(raw).unwrap();
        }
        Self {
            root,
            stage,
            module_sha256,
            fixtures_sha256,
        }
    }
    fn pins(&self) -> Pins<'_> {
        Pins {
            fixtures_sha256: &self.fixtures_sha256,
            module_sha256: &self.module_sha256,
        }
    }
}

#[cfg(test)]
mod controls {
    use super::*;

    fn synthetic(reject: &str) -> Vec<u8> {
        wat::parse_str(format!(
            r#"(module (memory (export "memory") 1 1)
          (func (export "recover_v0") (param i32 i32 i32 i32) (result i32)
            local.get 0 i32.const 4096 i32.ne
            local.get 1 i32.const 336 i32.ne i32.or
            local.get 2 i32.const 4448 i32.ne i32.or
            local.get 3 i32.const 16 i32.ne i32.or
            if {reject} end
            local.get 2 i32.const 16 i32.store offset=4
            local.get 2 i32.const 1 i32.store offset=8 i32.const 0))"#
        ))
        .unwrap()
    }

    #[test]
    fn t1_synthetic_observes_all_six_returns_full_pages_and_fresh_success() {
        let fixture = SyntheticStage::new(&synthetic("i32.const 7 return"));
        let result = fixture.root.path().join("raw.json");
        run_stage(&fixture.stage, &result, fixture.pins(), None, None).unwrap();
        let raw = std::fs::read(&result).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(value["rows"].as_array().unwrap().len(), 6);
        assert_eq!(value["complete"], true);
        for flag in FALSE_FLAGS {
            assert_eq!(value[flag], false);
        }
        for (n, row) in value["rows"].as_array().unwrap().iter().enumerate() {
            assert_eq!(row["call"], serde_json::json!(CALLS[n]));
            assert_eq!(row["fault"]["guest_return"], 7);
            assert!(row["fault"]["trap"].is_null());
            let before = hex::decode(row["fault"]["memory_before_hex"].as_str().unwrap()).unwrap();
            let after = hex::decode(row["fault"]["memory_after_hex"].as_str().unwrap()).unwrap();
            assert_eq!(before.len(), 65536);
            assert_eq!(before, after);
            assert_eq!(row["fresh"]["guest_return"], 0);
            assert!(row["fresh"]["trap"].is_null());
            let fresh = hex::decode(row["fresh"]["memory_after_hex"].as_str().unwrap()).unwrap();
            assert_eq!(
                &fresh[OUTPUT..OUTPUT + OUTPUT_LEN],
                &hex::decode("00000000100000000100000000000000").unwrap()
            );
        }
        assert!(run_stage(&fixture.stage, &result, fixture.pins(), None, None).is_err());
        assert_eq!(std::fs::read(&result).unwrap(), raw);
        run_stage(
            &fixture.stage,
            &fixture.root.path().join("next.json"),
            fixture.pins(),
            None,
            None,
        )
        .unwrap();
    }

    #[test]
    fn t1_synthetic_records_actual_trap_zero_and_guard_write_before_comparison() {
        for (code, kind) in [
            ("unreachable", "trap"),
            ("i32.const 0 return", "zero"),
            (
                "i32.const 0 i32.const 42 i32.store8 i32.const 9 return",
                "guard",
            ),
        ] {
            let fixture = SyntheticStage::new(&synthetic(code));
            let output = fixture.root.path().join("raw.json");
            run_stage(&fixture.stage, &output, fixture.pins(), None, None).unwrap();
            let value: serde_json::Value =
                serde_json::from_slice(&std::fs::read(output).unwrap()).unwrap();
            let fault = &value["rows"][0]["fault"];
            match kind {
                "trap" => {
                    assert!(fault["guest_return"].is_null());
                    assert_eq!(fault["trap"]["kind"], "trap");
                }
                "zero" => assert_eq!(fault["guest_return"], 0),
                _ => assert!(
                    fault["memory_after_hex"]
                        .as_str()
                        .unwrap()
                        .starts_with("2a")
                ),
            }
            assert_eq!(value["rows"][0]["fresh"]["guest_return"], 0);
        }
    }

    #[test]
    fn t1_identity_refuses_before_output_and_governed_run_stays_held() {
        let fixture = SyntheticStage::new(&synthetic("i32.const 7 return"));
        std::fs::write(fixture.stage.join("module.wasm"), b"changed").unwrap();
        let output = fixture.root.path().join("raw.json");
        assert!(run_stage(&fixture.stage, &output, fixture.pins(), None, None).is_err());
        assert!(!output.exists());
        assert!(reviewed_digest(REVIEWED_MANIFEST_SHA256, Path::new("never-opened")).is_err());
    }

    #[test]
    fn t1_interrupted_writer_preserves_raw_completed_prefix_then_fresh_run_succeeds() {
        struct FailFlush {
            raw: Vec<u8>,
            flushes: usize,
        }
        impl Write for FailFlush {
            fn write(&mut self, raw: &[u8]) -> std::io::Result<usize> {
                self.raw.extend_from_slice(raw);
                Ok(raw.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.flushes += 1;
                if self.flushes == 2 {
                    Err(std::io::Error::other("interrupted"))
                } else {
                    Ok(())
                }
            }
        }
        let fixture = SyntheticStage::new(&synthetic("i32.const 7 return"));
        let mut output = FailFlush {
            raw: vec![],
            flushes: 0,
        };
        assert!(
            write_report(
                &mut output,
                load_stage(&fixture.stage, fixture.pins()).unwrap(),
                None,
                None
            )
            .is_err()
        );
        let prefix = String::from_utf8(output.raw).unwrap();
        assert!(prefix.contains("bad-call-input-short"));
        assert!(!prefix.contains("bad-call-input-long"));
        assert!(serde_json::from_str::<serde_json::Value>(&prefix).is_err());
        run_stage(
            &fixture.stage,
            &fixture.root.path().join("fresh.json"),
            fixture.pins(),
            None,
            None,
        )
        .unwrap();
    }
}
