use super::*;
use artifact_store_schema::editor_save::{
    EditorActorV0, EditorCommitPermitV0, EditorSaveAllocationV0, EditorSourceBindingV0, VERSION,
};

const WRITES: &str = "
    local.get 2 i32.const 0 i32.store offset=0 align=1
    local.get 2 i32.const 16 i32.store offset=4 align=1
    local.get 2 i32.const 1 i32.store offset=8 align=1
    local.get 2 i32.const 0 i32.store offset=12 align=1
";
const EPOCH: u64 = 17;

fn fixture(body: &str) -> Vec<u8> {
    wasm(&format!(
        r#"(module (memory (export "memory") 1 1)
        (func (export "recover_v0") (param i32 i32 i32 i32) (result i32) {body}))"#
    ))
}

fn wasm(wat: &str) -> Vec<u8> {
    wat::parse_str(wat).unwrap()
}

fn identity(bytes: &[u8]) -> RecoveryArtifactV0 {
    RecoveryArtifactV0 {
        abi_sha256: RECOVERY_ABI_SHA256,
        module_sha256: Sha256::digest(bytes).into(),
    }
}

fn admit(bytes: &[u8]) -> Result<RecoveryDecisionAdapter, RecoveryError> {
    RecoveryDecisionAdapter::new(bytes, identity(bytes))
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

fn committed_call(
    adapter: &RecoveryDecisionAdapter,
    operation_id: u64,
) -> Result<RecoveryDispositionV0, RecoveryError> {
    let binding = binding(operation_id);
    let receipt = committed(&binding, EPOCH);
    adapter.decide(&binding, EPOCH, RecoveryObservationV0::Receipt(&receipt))
}

fn succeeds_fresh(adapter: &RecoveryDecisionAdapter) {
    assert_eq!(
        committed_call(adapter, 22).unwrap(),
        RecoveryDispositionV0::Committed
    );
}

fn fault_then_success(fault: &str) -> RecoveryError {
    let body = format!(
        "local.get 0 i64.load offset=72 align=1 i64.const 21 i64.eq
        if {fault} end
        {WRITES} i32.const 0"
    );
    let adapter = admit(&fixture(&body)).unwrap();
    let error = committed_call(&adapter, 21).unwrap_err();
    succeeds_fresh(&adapter);
    error
}

#[test]
fn artifact_and_abi_identity_precede_module_admission() {
    let bytes = fixture(&format!("{WRITES} i32.const 0"));
    let mut wrong = identity(&bytes);
    wrong.module_sha256[0] ^= 1;
    assert!(matches!(
        RecoveryDecisionAdapter::new(&bytes, wrong),
        Err(RecoveryError::ArtifactIdentity)
    ));
    wrong = identity(&bytes);
    wrong.abi_sha256[0] ^= 1;
    assert!(matches!(
        RecoveryDecisionAdapter::new(&bytes, wrong),
        Err(RecoveryError::ArtifactIdentity)
    ));
    succeeds_fresh(&admit(&bytes).unwrap());
}

#[test]
fn rejects_wrong_module_envelope_before_compilation() {
    const SIGNATURE: &str = r#"(func (export "recover_v0") (param i32 i32 i32 i32)
        (result i32) i32.const 0)"#;
    let parts = [
        "(memory 1 1)",
        r#"(memory (export "memory") 1)"#,
        r#"(memory (export "memory") 1 2)"#,
        r#"(memory (export "memory") 1 1 shared)"#,
        r#"(memory (export "memory") 2 2)"#,
        r#"(memory (export "memory") 1 1) (memory 1 1)"#,
        r#"(import "wasi_snapshot_preview1" "memory" (memory 1 1)) (export "memory" (memory 0))"#,
        r#"(memory (export "memory") 1 1) (export "extra" (memory 0))"#,
        r#"(memory (export "memory") 1 1) (table 1 funcref)"#,
        r#"(memory (export "memory") 1 1) (data (i32.const 0) "x")"#,
        r#"(memory (export "memory") 1 1) (func) (start 0)"#,
        r#"(import "host" "callback" (func)) (memory (export "memory") 1 1)"#,
    ];
    for part in parts {
        let bytes = wasm(&format!("(module {part} {SIGNATURE})"));
        assert!(
            matches!(admit(&bytes), Err(RecoveryError::ModuleShape)),
            "{part}"
        );
    }

    let mut bad = vec![
        b"not wasm".to_vec(),
        vec![0; MAX_MODULE_BYTES + 1],
        wasm(&format!("(module {SIGNATURE})")),
        wasm(r#"(module (memory (export "memory") 1 1))"#),
        wasm(
            r#"(module (memory (export "memory") 1 1) (func (export "recover_v0") (result i32) i32.const 0))"#,
        ),
        wasm(
            r#"(module (memory (export "memory") 1 1) (func (export "wrong") (param i32 i32 i32 i32) (result i32) i32.const 0))"#,
        ),
    ];
    let mut noncanonical = fixture("i32.const 0");
    noncanonical.splice(9..10, [0x89, 0]);
    bad.push(noncanonical);
    let mut extra_section = fixture("i32.const 0");
    extra_section.extend([0, 1, 0]);
    bad.push(extra_section);
    for bytes in bad {
        assert!(matches!(admit(&bytes), Err(RecoveryError::ModuleShape)));
    }
    succeeds_fresh(&admit(&fixture(&format!("{WRITES} i32.const 0"))).unwrap());
}

#[test]
fn admission_delegates_code_validation_to_the_locked_engine() {
    let mut bytes = fixture("i32.const 0");
    let body_end = bytes.len() - 1;
    bytes[body_end] = 0xff;
    assert!(matches!(admit(&bytes), Err(RecoveryError::Engine(_))));
    succeeds_fresh(&admit(&fixture(&format!("{WRITES} i32.const 0"))).unwrap());
}

#[test]
fn exhausts_actual_fuel_and_then_succeeds_on_same_adapter() {
    assert!(matches!(
        fault_then_success("loop br 0 end"),
        RecoveryError::Fuel
    ));
}

#[test]
fn overflows_configured_stack_and_then_succeeds_on_same_adapter() {
    assert!(matches!(
        fault_then_success("local.get 0 local.get 1 local.get 2 local.get 3 call 0 drop"),
        RecoveryError::Stack
    ));
}

#[test]
fn trap_and_nonzero_return_discard_plausible_output() {
    let trap = fault_then_success(&format!("{WRITES} unreachable"));
    assert!(matches!(trap, RecoveryError::Trap(_)));
    let nonzero = fault_then_success(&format!("{WRITES} i32.const 7 return"));
    assert!(matches!(nonzero, RecoveryError::Return(7)));
}

#[test]
fn malformed_output_is_refused_before_rust_receipt_comparison() {
    for (offset, invalid) in [(0, 1), (4, 15), (8, 5), (12, 1)] {
        let overwrite = format!(
            "{WRITES} local.get 2 i32.const {invalid}
            i32.store offset={offset} align=1 i32.const 0 return"
        );
        assert!(matches!(
            fault_then_success(&overwrite),
            RecoveryError::Output
        ));
    }
    assert!(matches!(
        fault_then_success("local.get 2 i32.const 1 i32.store offset=8 align=1 i32.const 0 return"),
        RecoveryError::Output
    ));
}

#[test]
fn rejects_plausible_terminal_output_on_foreign_or_malformed_receipt() {
    let adapter = admit(&fixture(&format!("{WRITES} i32.const 0"))).unwrap();
    let original = binding(21);
    let mut malformed = committed(&original, EPOCH);
    malformed[0] ^= 1;
    for bytes in [
        committed(&binding(22), EPOCH),
        committed(&original, EPOCH + 1),
        malformed,
    ] {
        let error = adapter.decide(&original, EPOCH, RecoveryObservationV0::Receipt(&bytes));
        assert!(matches!(error, Err(RecoveryError::Disagreement { .. })));
        succeeds_fresh(&adapter);
    }

    let noncommit = WRITES.replace(
        "i32.const 1 i32.store offset=8",
        "i32.const 2 i32.store offset=8",
    );
    let adapter = admit(&fixture(&format!("{noncommit} i32.const 0"))).unwrap();
    let receipt = EditorSaveReceiptV0::noncommit(&binding(22), EPOCH)
        .unwrap()
        .encode_le()
        .unwrap();
    assert!(matches!(
        adapter.decide(&original, EPOCH, RecoveryObservationV0::Receipt(&receipt)),
        Err(RecoveryError::Disagreement { .. })
    ));
    assert_eq!(
        adapter
            .decide(
                &binding(22),
                EPOCH,
                RecoveryObservationV0::Receipt(&receipt)
            )
            .unwrap(),
        RecoveryDispositionV0::DefinitiveNoncommit
    );
}

#[test]
fn fresh_memory_and_zero_output_on_every_call() {
    let body = format!(
        "memory.size i32.const 1 i32.ne if unreachable end
        i32.const 1 memory.grow i32.const -1 i32.ne if unreachable end
        i32.const 32 i32.load if unreachable end
        local.get 2 i64.load i64.const 0 i64.ne if unreachable end
        local.get 2 i64.load offset=8 i64.const 0 i64.ne if unreachable end
        i32.const 32 i32.const 1 i32.store
        {WRITES} i32.const 0"
    );
    let adapter = admit(&fixture(&body)).unwrap();
    assert_eq!(
        committed_call(&adapter, 21).unwrap(),
        RecoveryDispositionV0::Committed
    );
    succeeds_fresh(&adapter);
}

#[test]
fn projects_complete_original_binding_and_checks_all_nonterminal_results() {
    let binding = binding(21);
    let receipt = committed(&binding, EPOCH);
    let input = project(&binding, EPOCH, RecoveryObservationV0::Receipt(&receipt)).unwrap();
    assert_eq!(&input[..16], b"WMR0\0\0\0\0P\x01\0\0\x03\0\0\0");
    let fields: Vec<_> = input[16..96]
        .chunks_exact(8)
        .map(|field| u64::from_le_bytes(field.try_into().unwrap()))
        .collect();
    assert_eq!(fields, [1, 2, 3, 4, 5, 6, 7, 21, 9, EPOCH]);
    assert_eq!(&input[96..128], &[10; 32]);
    assert_eq!(&input[128..160], &[14; 32]);
    assert_eq!(&input[160..], &receipt);

    let success = admit(&fixture(&format!("{WRITES} i32.const 0"))).unwrap();
    assert!(matches!(
        success.decide(&binding, 0, RecoveryObservationV0::Pending),
        Err(RecoveryError::InvalidOriginal)
    ));
    succeeds_fresh(&success);

    for (observation, disposition) in [
        (
            RecoveryObservationV0::Pending,
            RecoveryDispositionV0::Pending,
        ),
        (RecoveryObservationV0::Denied, RecoveryDispositionV0::Denied),
        (
            RecoveryObservationV0::Invalid,
            RecoveryDispositionV0::Invalid,
        ),
    ] {
        let output = WRITES.replace(
            "i32.const 1 i32.store offset=8",
            &format!("i32.const {} i32.store offset=8", disposition as u32),
        );
        let adapter = admit(&fixture(&format!("{output} i32.const 0"))).unwrap();
        assert_eq!(
            adapter.decide(&binding, EPOCH, observation).unwrap(),
            disposition
        );
        assert!(matches!(
            committed_call(&adapter, 21),
            Err(RecoveryError::Disagreement { .. })
        ));
        assert_eq!(
            adapter.decide(&binding, EPOCH, observation).unwrap(),
            disposition
        );
    }
}
