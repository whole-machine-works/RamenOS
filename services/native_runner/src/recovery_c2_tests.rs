//! Isolated test-only C2 correspondence harness and synthetic controls.
use super::*;

#[test]
fn c2_synthetic_raw_error_rows_preserve_observations_and_fresh_call() {
    let wasm = wat::parse_str(
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
    let adapter = RecoveryDecisionAdapter::new(
        &wasm,
        RecoveryArtifactV0 {
            abi_sha256: RECOVERY_ABI_SHA256,
            module_sha256: Sha256::digest(&wasm).into(),
        },
    )
    .unwrap();
    let trap = capture_raw(&adapter, "trap", [1; INPUT_LEN]);
    assert_eq!(trap.error.as_ref().unwrap().kind, "trap");
    assert_eq!(trap.guest_return, None);
    assert_eq!(trap.output_hex, None);
    let returned = capture_raw(&adapter, "return", [2; INPUT_LEN]);
    assert_eq!(returned.guest_return, Some(7));
    assert_eq!(returned.output_hex, None);
    let invalid = capture_raw(&adapter, "invalid", [9; INPUT_LEN]);
    assert_eq!(invalid.guest_return, Some(0));
    assert_eq!(invalid.error.as_ref().unwrap().kind, "invalid_output");
    assert_eq!(
        invalid.output_hex.as_deref(),
        Some("00000000100000000900000000000000")
    );
    let fresh = capture_raw(&adapter, "fresh", [3; INPUT_LEN]);
    assert_eq!(fresh.guest_return, Some(0));
    assert_eq!(
        fresh.output_hex.as_deref(),
        Some("00000000100000000300000000000000")
    );
    assert!(fresh.error.is_none());
}

#[test]
fn c2_synthetic_typed_pre_admission_refusals_and_fresh_success_are_actual() {
    let wasm = wat::parse_str(
        r#"(module (memory (export "memory") 1 1)
      (func (export "recover_v0") (param i32 i32 i32 i32) (result i32)
        local.get 2 i32.const 16 i32.store offset=4
        local.get 2 i32.const 1 i32.store offset=8 i32.const 0))"#,
    )
    .unwrap();
    let adapter = RecoveryDecisionAdapter::new(
        &wasm,
        RecoveryArtifactV0 {
            abi_sha256: RECOVERY_ABI_SHA256,
            module_sha256: Sha256::digest(&wasm).into(),
        },
    )
    .unwrap();
    let invalid = typed_zero_epoch(&adapter);
    assert_eq!(invalid.as_str(), "InvalidOriginal");
    let fresh = typed_fresh_committed(&adapter);
    assert_eq!(fresh.as_str(), "Committed");
}

use artifact_store_schema::editor_save::{
    EditorActorV0, EditorCommitPermitV0, EditorSaveAllocationV0, EditorSourceBindingV0, VERSION,
};
use serde::Serialize;

#[derive(Serialize)]
struct ErrorRecord {
    kind: &'static str,
    detail: String,
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

#[derive(Serialize)]
struct RawRow {
    id: String,
    input_sha256: String,
    guest_return: Option<i32>,
    output_hex: Option<String>,
    error: Option<ErrorRecord>,
}

fn capture_raw(adapter: &RecoveryDecisionAdapter, id: &str, input: [u8; INPUT_LEN]) -> RawRow {
    let mut row = RawRow {
        id: id.into(),
        input_sha256: hex::encode(Sha256::digest(input)),
        guest_return: None,
        output_hex: None,
        error: None,
    };
    match adapter.invoke(&input) {
        Ok(output) => {
            row.guest_return = Some(0);
            row.output_hex = Some(hex::encode(output));
            if let Err(error) = decode_output(output) {
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

fn binding(operation_id: u64) -> EditorSaveBindingV0 {
    EditorSaveBindingV0::try_new(
        EditorSaveAllocationV0 {
            schema_version: VERSION,
            actor: EditorActorV0::try_new(1, 2, 3, 4, 5).unwrap(),
            selected_object_id: 6,
            selected_generation: 7,
            operation_id,
            expected_revision: 9,
            expected_content_hash: [10; 32],
        },
        EditorSourceBindingV0::try_new(11, 12, 13, [14; 32]).unwrap(),
    )
    .unwrap()
}

fn committed(binding: &EditorSaveBindingV0, epoch: u64) -> [u8; RECEIPT_LEN] {
    let permit = EditorCommitPermitV0::try_new(binding.clone(), epoch, 18, 19).unwrap();
    EditorSaveReceiptV0::committed(&permit, 0)
        .unwrap()
        .encode_le()
        .unwrap()
}

fn disposition_name(value: RecoveryDispositionV0) -> &'static str {
    match value {
        RecoveryDispositionV0::Pending => "Pending",
        RecoveryDispositionV0::Committed => "Committed",
        RecoveryDispositionV0::DefinitiveNoncommit => "DefinitiveNoncommit",
        RecoveryDispositionV0::Denied => "Denied",
        RecoveryDispositionV0::Invalid => "Invalid",
    }
}

#[derive(Serialize)]
struct TypedResult {
    disposition: Option<&'static str>,
    error: Option<ErrorRecord>,
}
fn capture_typed(result: Result<RecoveryDispositionV0, RecoveryError>) -> TypedResult {
    match result {
        Ok(value) => TypedResult {
            disposition: Some(disposition_name(value)),
            error: None,
        },
        Err(error) => TypedResult {
            disposition: None,
            error: Some(describe(&error)),
        },
    }
}
fn typed_zero_epoch(adapter: &RecoveryDecisionAdapter) -> String {
    match adapter.decide(&binding(21), 0, RecoveryObservationV0::Pending) {
        Err(RecoveryError::InvalidOriginal) => "InvalidOriginal".into(),
        Ok(value) => disposition_name(value).into(),
        Err(error) => format!("unexpected:{error}"),
    }
}
fn typed_fresh_committed(adapter: &RecoveryDecisionAdapter) -> String {
    let b = binding(22);
    let receipt = committed(&b, 17);
    match adapter.decide(&b, 17, RecoveryObservationV0::Receipt(&receipt)) {
        Ok(value) => disposition_name(value).into(),
        Err(error) => format!("unexpected:{error}"),
    }
}

const TYPED_IDS: [&str; 13] = [
    "pending",
    "denied",
    "invalid",
    "committed",
    "noncommit",
    "foreign_operation",
    "foreign_epoch",
    "foreign_binding",
    "malformed_receipt",
    "zero_epoch",
    "invalid_original",
    "module_identity",
    "abi_identity",
];

#[derive(Serialize)]
struct TypedRow {
    id: String,
    actual: TypedResult,
    fresh_id: String,
    fresh: TypedResult,
}

fn typed_rows<'a>(
    module: &'a [u8],
    adapter: &'a Result<RecoveryDecisionAdapter, RecoveryError>,
) -> impl Iterator<Item = TypedRow> + 'a {
    let identity = RecoveryArtifactV0 {
        abi_sha256: RECOVERY_ABI_SHA256,
        module_sha256: Sha256::digest(module).into(),
    };
    let original = binding(21);
    let normal = committed(&original, 17);
    let noncommit = EditorSaveReceiptV0::noncommit(&original, 17)
        .unwrap()
        .encode_le()
        .unwrap();
    let foreign_operation = committed(&binding(22), 17);
    let foreign_epoch = committed(&original, 18);
    let mut foreign = original.clone();
    foreign.source.content_hash = [15; 32];
    let foreign_binding = committed(&foreign, 17);
    let mut malformed = normal;
    malformed[0] ^= 1;
    let mut invalid_original = original.clone();
    invalid_original.allocation.operation_id = 0;
    TYPED_IDS.into_iter().map(move |id| {
        let actual = if id == "module_identity" || id == "abi_identity" {
            let mut bad = identity;
            if id == "module_identity" {
                bad.module_sha256[0] ^= 1;
            } else {
                bad.abi_sha256[0] ^= 1;
            }
            match RecoveryDecisionAdapter::new(module, bad) {
                Err(error) => TypedResult {
                    disposition: None,
                    error: Some(describe(&error)),
                },
                Ok(_) => TypedResult {
                    disposition: Some("UnexpectedAdmitted"),
                    error: None,
                },
            }
        } else {
            match adapter {
                Err(error) => TypedResult {
                    disposition: None,
                    error: Some(describe(error)),
                },
                Ok(adapter) => {
                    let result = match id {
                        "pending" => adapter.decide(&original, 17, RecoveryObservationV0::Pending),
                        "denied" => adapter.decide(&original, 17, RecoveryObservationV0::Denied),
                        "invalid" => adapter.decide(&original, 17, RecoveryObservationV0::Invalid),
                        "committed" => {
                            adapter.decide(&original, 17, RecoveryObservationV0::Receipt(&normal))
                        }
                        "noncommit" => adapter.decide(
                            &original,
                            17,
                            RecoveryObservationV0::Receipt(&noncommit),
                        ),
                        "foreign_operation" => adapter.decide(
                            &original,
                            17,
                            RecoveryObservationV0::Receipt(&foreign_operation),
                        ),
                        "foreign_epoch" => adapter.decide(
                            &original,
                            17,
                            RecoveryObservationV0::Receipt(&foreign_epoch),
                        ),
                        "foreign_binding" => adapter.decide(
                            &original,
                            17,
                            RecoveryObservationV0::Receipt(&foreign_binding),
                        ),
                        "malformed_receipt" => adapter.decide(
                            &original,
                            17,
                            RecoveryObservationV0::Receipt(&malformed),
                        ),
                        "zero_epoch" => {
                            adapter.decide(&original, 0, RecoveryObservationV0::Pending)
                        }
                        "invalid_original" => {
                            adapter.decide(&invalid_original, 17, RecoveryObservationV0::Pending)
                        }
                        _ => unreachable!("fixed typed case inventory"),
                    };
                    capture_typed(result)
                }
            }
        };
        let fresh_adapter = if id == "module_identity" || id == "abi_identity" {
            Some(RecoveryDecisionAdapter::new(module, identity))
        } else {
            None
        };
        let fresh_owner = fresh_adapter.as_ref().unwrap_or(adapter);
        let fresh = match fresh_owner {
            Ok(adapter) => {
                let b = binding(22);
                let receipt = committed(&b, 17);
                capture_typed(adapter.decide(&b, 17, RecoveryObservationV0::Receipt(&receipt)))
            }
            Err(error) => TypedResult {
                disposition: None,
                error: Some(describe(error)),
            },
        };
        TypedRow {
            id: id.into(),
            actual,
            fresh_id: format!("fresh_after_{id}"),
            fresh,
        }
    })
}

#[test]
fn c2_synthetic_typed_matrix_keeps_all_fresh_ids_and_real_disagreements() {
    let wasm = wat::parse_str(
        r#"(module (memory (export "memory") 1 1)
      (func (export "recover_v0") (param i32 i32 i32 i32) (result i32)
        local.get 2 i32.const 16 i32.store offset=4
        local.get 2 i32.const 1 i32.store offset=8 i32.const 0))"#,
    )
    .unwrap();
    let adapter = RecoveryDecisionAdapter::new(
        &wasm,
        RecoveryArtifactV0 {
            abi_sha256: RECOVERY_ABI_SHA256,
            module_sha256: Sha256::digest(&wasm).into(),
        },
    );
    let rows: Vec<_> = typed_rows(&wasm, &adapter).collect();
    assert_eq!(rows.len(), 13);
    for (row, id) in rows.iter().zip(TYPED_IDS) {
        assert_eq!(row.id, id);
        assert_eq!(row.fresh_id, format!("fresh_after_{id}"));
        assert_eq!(row.fresh.disposition, Some("Committed"));
        assert!(row.fresh.error.is_none());
    }
    assert_eq!(rows[0].actual.error.as_ref().unwrap().kind, "disagreement");
    assert_eq!(
        rows[9].actual.error.as_ref().unwrap().kind,
        "invalid_original"
    );
    assert_eq!(
        rows[10].actual.error.as_ref().unwrap().kind,
        "invalid_original"
    );
    assert_eq!(
        rows[11].actual.error.as_ref().unwrap().kind,
        "artifact_identity"
    );
    assert_eq!(
        rows[12].actual.error.as_ref().unwrap().kind,
        "artifact_identity"
    );
}

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

const CORPUS_SHA: &str = "84eece3246d9b4521a5b8ac48fa6324cb4be4e98889277ab46837f6764aeda49";
const C2_SHA: &str = "fbcceae4411b17f2e517a8539991bfb41b097b2aa2b037ca58a828972a3b3ce4";
const TYPED_SHA: &str = "7c171588e54f7af16b63fdd86a075c57cc8bca4bfbf346bd84c2b397bce329a9";
const REGISTRATION_SHA: &str = "27758558349696918c0325ce692f0cdb1ba52ef1f1cd2904cb0cacf6a7012b2a";
const R0_REFERENCE: &str = "958a6f1713129930b217c16b1a21140e8fab9ed0";
const MAX_JSON: u64 = 2 * 1024 * 1024;

#[derive(Clone, Copy)]
struct Pins<'a> {
    corpus: &'a str,
    module: &'a str,
    typed: &'a str,
    registration: &'a str,
    count: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema_version: u32,
    kind: String,
    abi_sha256: String,
    corpus_sha256: String,
    module_sha256: String,
    typed_sha256: String,
    registration_sha256: String,
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
    registration_sha256: String,
    module: Vec<u8>,
    cases: Vec<(String, [u8; INPUT_LEN])>,
}

fn digest(raw: &[u8]) -> String {
    hex::encode(Sha256::digest(raw))
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
fn private_directory(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir()
            && !m.file_type().is_symlink()
            && m.permissions().mode() & 0o077 == 0
            && m.uid() == unsafe { libc::geteuid() },
        "expected owned private directory"
    );
    Ok(())
}
fn read_regular(path: &Path, bound: u64) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let m = file.metadata()?;
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.permissions().mode() & 0o077 == 0
            && m.uid() == unsafe { libc::geteuid() },
        "expected owned private regular file"
    );
    let mut raw = Vec::new();
    file.take(bound + 1).read_to_end(&mut raw)?;
    ensure!(raw.len() as u64 <= bound, "artifact byte bound");
    Ok(raw)
}
fn load_stage(directory: &Path, pins: Pins<'_>) -> Result<Prepared> {
    ensure!((1..=627).contains(&pins.count), "pinned case count");
    for pin in [pins.corpus, pins.module, pins.typed, pins.registration] {
        decode_hex::<32>(pin)?;
    }
    private_directory(directory)?;
    let plan_bytes = read_regular(&directory.join("plan.json"), 4096)?;
    let plan: Plan = serde_json::from_slice(&plan_bytes)?;
    ensure!(
        plan.schema_version == 1
            && plan.kind == "recovery_c2_plan_v1"
            && plan.abi_sha256 == hex::encode(RECOVERY_ABI_SHA256)
            && plan.corpus_sha256 == pins.corpus
            && plan.module_sha256 == pins.module
            && plan.typed_sha256 == pins.typed
            && plan.registration_sha256 == pins.registration
            && plan.case_count == pins.count,
        "plan metadata differs from pins"
    );
    let registration = read_regular(&directory.join("registration.json"), MAX_JSON)?;
    ensure!(
        digest(&registration) == pins.registration,
        "registration digest mismatch"
    );
    let _: serde_json::Value = serde_json::from_slice(&registration)?;
    let typed = read_regular(&directory.join("typed.json"), MAX_JSON)?;
    ensure!(digest(&typed) == pins.typed, "typed matrix digest mismatch");
    let matrix: serde_json::Value = serde_json::from_slice(&typed)?;
    let ids = matrix
        .get("cases")
        .and_then(|v| v.as_array())
        .context("typed cases")?;
    ensure!(
        ids.len() == TYPED_IDS.len()
            && ids
                .iter()
                .zip(TYPED_IDS)
                .all(|(r, id)| r.get("id").and_then(|x| x.as_str()) == Some(id)),
        "typed case IDs"
    );
    let module = read_regular(&directory.join("module.wasm"), MAX_MODULE_BYTES as u64)?;
    ensure!(digest(&module) == pins.module, "module digest mismatch");
    let bytes = read_regular(&directory.join("corpus.json"), MAX_JSON)?;
    ensure!(digest(&bytes) == pins.corpus, "corpus digest mismatch");
    let corpus: Corpus = serde_json::from_slice(&bytes)?;
    let call = corpus.canonical_call;
    ensure!(
        corpus.schema_version == 1
            && corpus.packet == "recovery-r0-v1"
            && corpus.contract_sha256 == hex::encode(RECOVERY_ABI_SHA256)
            && corpus.ramenos_reference_revision == R0_REFERENCE
            && call.input_pointer == INPUT as u32
            && call.input_length == INPUT_LEN as u32
            && call.output_pointer == OUTPUT as u32
            && call.output_capacity == OUTPUT_LEN as u32
            && !corpus.derivation.is_empty()
            && corpus.cases.len() == pins.count,
        "corpus envelope or count"
    );
    let mut seen = HashSet::new();
    let mut cases = Vec::with_capacity(pins.count);
    for case in corpus.cases {
        ensure!(
            !case.id.is_empty()
                && case.id.len() <= 96
                && case
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                && seen.insert(case.id.clone()),
            "case ID"
        );
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
        registration_sha256: digest(&registration),
        module,
        cases,
    })
}

fn write_report<W: Write>(out: &mut W, prepared: Prepared, pins: Pins<'_>) -> Result<()> {
    let adapter = RecoveryDecisionAdapter::new(
        &prepared.module,
        RecoveryArtifactV0 {
            abi_sha256: RECOVERY_ABI_SHA256,
            module_sha256: decode_hex::<32>(pins.module)?,
        },
    );
    let header = serde_json::json!({"schema_version":1,"kind":"recovery_c2_engine_result_v1","plan_sha256":prepared.plan_sha256,"registration_sha256":prepared.registration_sha256});
    let header = serde_json::to_vec(&header)?;
    out.write_all(&header[..header.len() - 1])?;
    out.write_all(b",\"raw_rows\":[\n")?;
    out.flush()?;
    for (i, (id, input)) in prepared.cases.into_iter().enumerate() {
        if i != 0 {
            out.write_all(b",\n")?;
        }
        let row = match &adapter {
            Ok(adapter) => capture_raw(adapter, &id, input),
            Err(error) => RawRow {
                id,
                input_sha256: digest(&input),
                guest_return: None,
                output_hex: None,
                error: Some(describe(error)),
            },
        };
        serde_json::to_writer(&mut *out, &row)?;
        out.flush()?;
    }
    out.write_all(b"\n],\"typed_rows\":[\n")?;
    out.flush()?;
    for (i, row) in typed_rows(&prepared.module, &adapter).enumerate() {
        if i != 0 {
            out.write_all(b",\n")?;
        }
        serde_json::to_writer(&mut *out, &row)?;
        out.flush()?;
    }
    out.write_all(b"\n]}\n")?;
    out.flush()?;
    Ok(())
}
fn run_stage(directory: &Path, output: &Path, pins: Pins<'_>) -> Result<()> {
    let prepared = load_stage(directory, pins)?;
    private_directory(output.parent().context("result needs a private parent")?)?;
    let mut result = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(output)
        .context("fresh result required")?;
    write_report(&mut result, prepared, pins)
}

#[test]
#[ignore = "requires independently reviewed fixed C2 registration, frozen stage and coordinator release"]
fn run_registered_c2_correspondence() {
    let stage =
        PathBuf::from(std::env::var_os("RECOVERY_C2_STAGE_DIR").expect("explicit frozen C2 stage"));
    let output =
        PathBuf::from(std::env::var_os("RECOVERY_C2_RESULT").expect("explicit fresh C2 result"));
    run_stage(
        &stage,
        &output,
        Pins {
            corpus: CORPUS_SHA,
            module: C2_SHA,
            typed: TYPED_SHA,
            registration: REGISTRATION_SHA,
            count: 627,
        },
    )
    .unwrap();
}

#[cfg(test)]
mod stage_controls {
    use super::*;

    struct Fixture {
        root: tempfile::TempDir,
        stage: PathBuf,
        corpus: String,
        module: String,
        typed: String,
        registration: String,
    }
    impl Fixture {
        fn new(ids: &[&str]) -> Self {
            let root = tempfile::tempdir().unwrap();
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let stage = root.path().join("stage");
            fs::create_dir(&stage).unwrap();
            fs::set_permissions(&stage, fs::Permissions::from_mode(0o700)).unwrap();
            let wasm = wat::parse_str(
                r#"(module (memory (export "memory") 1 1)
             (func (export "recover_v0") (param i32 i32 i32 i32) (result i32)
                local.get 2 i32.const 16 i32.store offset=4
                local.get 2 i32.const 1 i32.store offset=8 i32.const 0))"#,
            )
            .unwrap();
            let valid_output = "00000000100000000100000000000000";
            let cases:Vec<_>=ids.iter().map(|id|serde_json::json!({"id":id,"family":"synthetic","reason":"control","input_hex":hex::encode([0;INPUT_LEN]),"expected_return":0,"expected_output_hex":valid_output})).collect();
            let corpus=serde_json::to_vec(&serde_json::json!({"schema_version":1,"packet":"recovery-r0-v1","contract_sha256":hex::encode(RECOVERY_ABI_SHA256),"ramenos_reference_revision":R0_REFERENCE,"canonical_call":{"input_pointer":INPUT,"input_length":INPUT_LEN,"output_pointer":OUTPUT,"output_capacity":OUTPUT_LEN},"derivation":"synthetic","cases":cases})).unwrap();
            let typed=serde_json::to_vec(&serde_json::json!({"cases":TYPED_IDS.iter().map(|id|serde_json::json!({"id":id})).collect::<Vec<_>>()})).unwrap();
            let registration = b"{\"kind\":\"synthetic\"}";
            let v = Self {
                root,
                stage,
                corpus: digest(&corpus),
                module: digest(&wasm),
                typed: digest(&typed),
                registration: digest(registration),
            };
            v.write("corpus.json", &corpus);
            v.write("typed.json", &typed);
            v.write("registration.json", registration);
            v.write("module.wasm", &wasm);
            let plan=serde_json::to_vec(&serde_json::json!({"schema_version":1,"kind":"recovery_c2_plan_v1","abi_sha256":hex::encode(RECOVERY_ABI_SHA256),"corpus_sha256":v.corpus,"module_sha256":v.module,"typed_sha256":v.typed,"registration_sha256":v.registration,"case_count":ids.len()})).unwrap();
            v.write("plan.json", &plan);
            v
        }
        fn pins(&self, count: usize) -> Pins<'_> {
            Pins {
                corpus: &self.corpus,
                module: &self.module,
                typed: &self.typed,
                registration: &self.registration,
                count,
            }
        }
        fn write(&self, name: &str, bytes: &[u8]) {
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
            file.write_all(bytes).unwrap();
        }
        fn output(&self, name: &str) -> PathBuf {
            self.root.path().join(name)
        }
    }

    #[test]
    fn c2_synthetic_wrong_pins_and_duplicate_ids_deny_before_output_then_fresh() {
        let duplicate = Fixture::new(&["dup", "dup"]);
        let out = duplicate.output("duplicate.json");
        assert!(run_stage(&duplicate.stage, &out, duplicate.pins(2)).is_err());
        assert!(!out.exists());
        let f = Fixture::new(&["one"]);
        let plan = fs::read(f.stage.join("plan.json")).unwrap();
        let module = fs::read(f.stage.join("module.wasm")).unwrap();
        let reg = fs::read(f.stage.join("registration.json")).unwrap();
        let typed = fs::read(f.stage.join("typed.json")).unwrap();
        let corpus = fs::read(f.stage.join("corpus.json")).unwrap();
        for (name, good) in [
            ("registration.json", reg.as_slice()),
            ("typed.json", typed.as_slice()),
            ("module.wasm", module.as_slice()),
            ("corpus.json", corpus.as_slice()),
        ] {
            let output = f.output(&format!("denied-{name}"));
            f.write(name, b"changed");
            assert!(run_stage(&f.stage, &output, f.pins(1)).is_err());
            assert!(!output.exists());
            f.write(name, good);
        }
        let mut extra: serde_json::Value = serde_json::from_slice(&plan).unwrap();
        extra["extra"] = serde_json::Value::Bool(true);
        f.write("plan.json", &serde_json::to_vec(&extra).unwrap());
        let out = f.output("extra.json");
        assert!(run_stage(&f.stage, &out, f.pins(1)).is_err());
        assert!(!out.exists());
        f.write("plan.json", &plan);
        let mut duplicate_key = b"{\"schema_version\":1,".to_vec();
        duplicate_key.extend_from_slice(&plan[1..]);
        f.write("plan.json", &duplicate_key);
        let out = f.output("duplicate-key.json");
        assert!(run_stage(&f.stage, &out, f.pins(1)).is_err());
        assert!(!out.exists());
        f.write("plan.json", &plan);
        let fresh = f.output("fresh.json");
        run_stage(&f.stage, &fresh, f.pins(1)).unwrap();
        let before = fs::read(&fresh).unwrap();
        assert!(run_stage(&f.stage, &fresh, f.pins(1)).is_err());
        assert_eq!(fs::read(&fresh).unwrap(), before);
        let report: serde_json::Value = serde_json::from_slice(&before).unwrap();
        assert_eq!(report["raw_rows"][0]["id"], "one");
        assert_eq!(report["typed_rows"].as_array().unwrap().len(), 13);
    }

    #[test]
    fn c2_synthetic_interrupted_writer_keeps_actual_prefix_then_fresh_run_succeeds() {
        struct FailSecondFlush {
            bytes: Vec<u8>,
            flushes: usize,
        }
        impl Write for FailSecondFlush {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.bytes.extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.flushes += 1;
                if self.flushes == 2 {
                    Err(std::io::Error::other("injected"))
                } else {
                    Ok(())
                }
            }
        }
        let f = Fixture::new(&["one", "two"]);
        let mut partial = FailSecondFlush {
            bytes: vec![],
            flushes: 0,
        };
        assert!(
            write_report(
                &mut partial,
                load_stage(&f.stage, f.pins(2)).unwrap(),
                f.pins(2)
            )
            .is_err()
        );
        let prefix = String::from_utf8(partial.bytes).unwrap();
        assert!(prefix.contains("\"id\":\"one\""));
        assert!(!prefix.contains("\"id\":\"two\""));
        let output = f.output("after-interruption.json");
        run_stage(&f.stage, &output, f.pins(2)).unwrap();
        let result: serde_json::Value = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
        assert_eq!(result["raw_rows"].as_array().unwrap().len(), 2);
        assert_eq!(result["typed_rows"].as_array().unwrap().len(), 13);
    }
}
