//! T2 static recipes and review-gated test-only runtime observations.
//!
//! Static emission is not release. Focused synthetic tests never qualify the campaign.
//! The coordinator owns the parent test linkage and any later execution guard.

use super::super::{section, uleb32, validate_shape};
use super::{digest, private_directory, read_regular};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::Path,
};

const RECIPE_CONTRACT: &str = "6f96425bf55222eea630b15926284400a57488c8885ab5fb6c3372a35c62d1dd";
const C1_SHA256: &str = "6458a173cd09e73fe0be59b1a2d339c2070c33ac05628b3d2dd5fb264cb2e079";
const ABI_SHA256: &str = "49daf52dd669411376770b3bc2a007d7c6a8b346843bcd123a45da8139b0da60";
const C1_BYTES: usize = 1349;
const MAX_STATIC_BYTES: usize = 65537; // A02 only; production limit is unchanged.

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct Recipe {
    id: &'static str,
    input_case: &'static str,
    input_sha256: &'static str,
    expected_receiving_error: &'static str,
    expected_fault_admitted: bool,
    expected_raw_output_hex: Option<&'static str>,
    expected_raw_guest_return: Option<i32>,
    expected_raw_trap_kind: Option<&'static str>,
}

fn recipes() -> Vec<Recipe> {
    vec![
        Recipe {
            id: "A01-malformed-magic",
            input_case: "outcome-0",
            input_sha256: "e635728a7387ed65ae7e9ea5253193660ec311fbbdf61ca6214af1245442634c",
            expected_receiving_error: "module_shape",
            expected_fault_admitted: false,
            expected_raw_output_hex: None,
            expected_raw_guest_return: None,
            expected_raw_trap_kind: None,
        },
        Recipe {
            id: "A02-module-one-over",
            input_case: "outcome-0",
            input_sha256: "e635728a7387ed65ae7e9ea5253193660ec311fbbdf61ca6214af1245442634c",
            expected_receiving_error: "module_shape",
            expected_fault_admitted: false,
            expected_raw_output_hex: None,
            expected_raw_guest_return: None,
            expected_raw_trap_kind: None,
        },
        Recipe {
            id: "A03-contract-identity",
            input_case: "outcome-0",
            input_sha256: "e635728a7387ed65ae7e9ea5253193660ec311fbbdf61ca6214af1245442634c",
            expected_receiving_error: "artifact_identity",
            expected_fault_admitted: false,
            expected_raw_output_hex: None,
            expected_raw_guest_return: None,
            expected_raw_trap_kind: None,
        },
        Recipe {
            id: "A04-artifact-identity",
            input_case: "outcome-0",
            input_sha256: "e635728a7387ed65ae7e9ea5253193660ec311fbbdf61ca6214af1245442634c",
            expected_receiving_error: "artifact_identity",
            expected_fault_admitted: false,
            expected_raw_output_hex: None,
            expected_raw_guest_return: None,
            expected_raw_trap_kind: None,
        },
        Recipe {
            id: "A05-host-callback-import",
            input_case: "outcome-0",
            input_sha256: "e635728a7387ed65ae7e9ea5253193660ec311fbbdf61ca6214af1245442634c",
            expected_receiving_error: "module_shape",
            expected_fault_admitted: false,
            expected_raw_output_hex: None,
            expected_raw_guest_return: None,
            expected_raw_trap_kind: None,
        },
        Recipe {
            id: "A06-wasi-import",
            input_case: "outcome-0",
            input_sha256: "e635728a7387ed65ae7e9ea5253193660ec311fbbdf61ca6214af1245442634c",
            expected_receiving_error: "module_shape",
            expected_fault_admitted: false,
            expected_raw_output_hex: None,
            expected_raw_guest_return: None,
            expected_raw_trap_kind: None,
        },
        Recipe {
            id: "A07-imported-memory",
            input_case: "outcome-0",
            input_sha256: "e635728a7387ed65ae7e9ea5253193660ec311fbbdf61ca6214af1245442634c",
            expected_receiving_error: "module_shape",
            expected_fault_admitted: false,
            expected_raw_output_hex: None,
            expected_raw_guest_return: None,
            expected_raw_trap_kind: None,
        },
        Recipe {
            id: "A08-start-function",
            input_case: "outcome-0",
            input_sha256: "e635728a7387ed65ae7e9ea5253193660ec311fbbdf61ca6214af1245442634c",
            expected_receiving_error: "module_shape",
            expected_fault_admitted: false,
            expected_raw_output_hex: None,
            expected_raw_guest_return: None,
            expected_raw_trap_kind: None,
        },
        Recipe {
            id: "A09-shared-memory",
            input_case: "outcome-0",
            input_sha256: "e635728a7387ed65ae7e9ea5253193660ec311fbbdf61ca6214af1245442634c",
            expected_receiving_error: "module_shape",
            expected_fault_admitted: false,
            expected_raw_output_hex: None,
            expected_raw_guest_return: None,
            expected_raw_trap_kind: None,
        },
        Recipe {
            id: "A10-threads-opcode",
            input_case: "outcome-0",
            input_sha256: "e635728a7387ed65ae7e9ea5253193660ec311fbbdf61ca6214af1245442634c",
            expected_receiving_error: "engine",
            expected_fault_admitted: false,
            expected_raw_output_hex: None,
            expected_raw_guest_return: None,
            expected_raw_trap_kind: None,
        },
        Recipe {
            id: "A11-absent-memory",
            input_case: "outcome-0",
            input_sha256: "e635728a7387ed65ae7e9ea5253193660ec311fbbdf61ca6214af1245442634c",
            expected_receiving_error: "module_shape",
            expected_fault_admitted: false,
            expected_raw_output_hex: None,
            expected_raw_guest_return: None,
            expected_raw_trap_kind: None,
        },
        Recipe {
            id: "A12-extra-memory",
            input_case: "outcome-0",
            input_sha256: "e635728a7387ed65ae7e9ea5253193660ec311fbbdf61ca6214af1245442634c",
            expected_receiving_error: "module_shape",
            expected_fault_admitted: false,
            expected_raw_output_hex: None,
            expected_raw_guest_return: None,
            expected_raw_trap_kind: None,
        },
        Recipe {
            id: "A13-memory-min0-max1",
            input_case: "outcome-0",
            input_sha256: "e635728a7387ed65ae7e9ea5253193660ec311fbbdf61ca6214af1245442634c",
            expected_receiving_error: "module_shape",
            expected_fault_admitted: false,
            expected_raw_output_hex: None,
            expected_raw_guest_return: None,
            expected_raw_trap_kind: None,
        },
        Recipe {
            id: "A14-memory-min2-max2",
            input_case: "outcome-0",
            input_sha256: "e635728a7387ed65ae7e9ea5253193660ec311fbbdf61ca6214af1245442634c",
            expected_receiving_error: "module_shape",
            expected_fault_admitted: false,
            expected_raw_output_hex: None,
            expected_raw_guest_return: None,
            expected_raw_trap_kind: None,
        },
        Recipe {
            id: "A15-memory-min1-max2",
            input_case: "outcome-0",
            input_sha256: "e635728a7387ed65ae7e9ea5253193660ec311fbbdf61ca6214af1245442634c",
            expected_receiving_error: "module_shape",
            expected_fault_admitted: false,
            expected_raw_output_hex: None,
            expected_raw_guest_return: None,
            expected_raw_trap_kind: None,
        },
        Recipe {
            id: "A16-memory-no-maximum",
            input_case: "outcome-0",
            input_sha256: "e635728a7387ed65ae7e9ea5253193660ec311fbbdf61ca6214af1245442634c",
            expected_receiving_error: "module_shape",
            expected_fault_admitted: false,
            expected_raw_output_hex: None,
            expected_raw_guest_return: None,
            expected_raw_trap_kind: None,
        },
        Recipe {
            id: "A17-missing-recover-export",
            input_case: "outcome-0",
            input_sha256: "e635728a7387ed65ae7e9ea5253193660ec311fbbdf61ca6214af1245442634c",
            expected_receiving_error: "module_shape",
            expected_fault_admitted: false,
            expected_raw_output_hex: None,
            expected_raw_guest_return: None,
            expected_raw_trap_kind: None,
        },
        Recipe {
            id: "A18-wrong-recover-signature",
            input_case: "outcome-0",
            input_sha256: "e635728a7387ed65ae7e9ea5253193660ec311fbbdf61ca6214af1245442634c",
            expected_receiving_error: "module_shape",
            expected_fault_admitted: false,
            expected_raw_output_hex: None,
            expected_raw_guest_return: None,
            expected_raw_trap_kind: None,
        },
        Recipe {
            id: "A19-missing-memory-export",
            input_case: "outcome-0",
            input_sha256: "e635728a7387ed65ae7e9ea5253193660ec311fbbdf61ca6214af1245442634c",
            expected_receiving_error: "module_shape",
            expected_fault_admitted: false,
            expected_raw_output_hex: None,
            expected_raw_guest_return: None,
            expected_raw_trap_kind: None,
        },
        Recipe {
            id: "A20-extra-export",
            input_case: "outcome-0",
            input_sha256: "e635728a7387ed65ae7e9ea5253193660ec311fbbdf61ca6214af1245442634c",
            expected_receiving_error: "module_shape",
            expected_fault_admitted: false,
            expected_raw_output_hex: None,
            expected_raw_guest_return: None,
            expected_raw_trap_kind: None,
        },
        Recipe {
            id: "A21-invalid-code",
            input_case: "outcome-0",
            input_sha256: "e635728a7387ed65ae7e9ea5253193660ec311fbbdf61ca6214af1245442634c",
            expected_receiving_error: "engine",
            expected_fault_admitted: false,
            expected_raw_output_hex: None,
            expected_raw_guest_return: None,
            expected_raw_trap_kind: None,
        },
        Recipe {
            id: "R01-fuel",
            input_case: "outcome-0",
            input_sha256: "e635728a7387ed65ae7e9ea5253193660ec311fbbdf61ca6214af1245442634c",
            expected_receiving_error: "fuel",
            expected_fault_admitted: true,
            expected_raw_output_hex: Some("00000000000000000000000000000000"),
            expected_raw_guest_return: None,
            expected_raw_trap_kind: Some("fuel"),
        },
        Recipe {
            id: "R02-stack",
            input_case: "outcome-0",
            input_sha256: "e635728a7387ed65ae7e9ea5253193660ec311fbbdf61ca6214af1245442634c",
            expected_receiving_error: "stack",
            expected_fault_admitted: true,
            expected_raw_output_hex: Some("00000000000000000000000000000000"),
            expected_raw_guest_return: None,
            expected_raw_trap_kind: Some("stack"),
        },
        Recipe {
            id: "E01-trap-after-plausible-output",
            input_case: "outcome-0",
            input_sha256: "e635728a7387ed65ae7e9ea5253193660ec311fbbdf61ca6214af1245442634c",
            expected_receiving_error: "trap",
            expected_fault_admitted: true,
            expected_raw_output_hex: Some("00000000100000000100000000000000"),
            expected_raw_guest_return: None,
            expected_raw_trap_kind: Some("trap"),
        },
        Recipe {
            id: "E02-return7-after-plausible-output",
            input_case: "outcome-0",
            input_sha256: "e635728a7387ed65ae7e9ea5253193660ec311fbbdf61ca6214af1245442634c",
            expected_receiving_error: "guest_return",
            expected_fault_admitted: true,
            expected_raw_output_hex: Some("00000000100000000100000000000000"),
            expected_raw_guest_return: Some(7),
            expected_raw_trap_kind: None,
        },
        Recipe {
            id: "O01-version1",
            input_case: "outcome-0",
            input_sha256: "e635728a7387ed65ae7e9ea5253193660ec311fbbdf61ca6214af1245442634c",
            expected_receiving_error: "invalid_output",
            expected_fault_admitted: true,
            expected_raw_output_hex: Some("01000000100000000100000000000000"),
            expected_raw_guest_return: Some(0),
            expected_raw_trap_kind: None,
        },
        Recipe {
            id: "O02-length15",
            input_case: "outcome-0",
            input_sha256: "e635728a7387ed65ae7e9ea5253193660ec311fbbdf61ca6214af1245442634c",
            expected_receiving_error: "invalid_output",
            expected_fault_admitted: true,
            expected_raw_output_hex: Some("000000000f0000000100000000000000"),
            expected_raw_guest_return: Some(0),
            expected_raw_trap_kind: None,
        },
        Recipe {
            id: "O03-disposition5",
            input_case: "outcome-0",
            input_sha256: "e635728a7387ed65ae7e9ea5253193660ec311fbbdf61ca6214af1245442634c",
            expected_receiving_error: "invalid_output",
            expected_fault_admitted: true,
            expected_raw_output_hex: Some("00000000100000000500000000000000"),
            expected_raw_guest_return: Some(0),
            expected_raw_trap_kind: None,
        },
        Recipe {
            id: "O04-reserved1",
            input_case: "outcome-0",
            input_sha256: "e635728a7387ed65ae7e9ea5253193660ec311fbbdf61ca6214af1245442634c",
            expected_receiving_error: "invalid_output",
            expected_fault_admitted: true,
            expected_raw_output_hex: Some("00000000100000000100000001000000"),
            expected_raw_guest_return: Some(0),
            expected_raw_trap_kind: None,
        },
        Recipe {
            id: "O05-incomplete-header",
            input_case: "outcome-0",
            input_sha256: "e635728a7387ed65ae7e9ea5253193660ec311fbbdf61ca6214af1245442634c",
            expected_receiving_error: "invalid_output",
            expected_fault_admitted: true,
            expected_raw_output_hex: Some("00000000000000000100000000000000"),
            expected_raw_guest_return: Some(0),
            expected_raw_trap_kind: None,
        },
        Recipe {
            id: "S01-foreign-operation-plausible-commit",
            input_case: "outcome-0-receipt-foreign-operation_id",
            input_sha256: "c65d257e8391056469243740049f68e34d5024761a23afa3e45e25704092b7c6",
            expected_receiving_error: "disagreement",
            expected_fault_admitted: true,
            expected_raw_output_hex: Some("00000000100000000100000000000000"),
            expected_raw_guest_return: Some(0),
            expected_raw_trap_kind: None,
        },
        Recipe {
            id: "S02-foreign-generation-plausible-noncommit",
            input_case: "outcome-1-receipt-foreign-original_instance_generation",
            input_sha256: "0b2dac9acc72b24c9ff41424a0247bcad022100ff61a3078f53c1f8c4291bc88",
            expected_receiving_error: "disagreement",
            expected_fault_admitted: true,
            expected_raw_output_hex: Some("00000000100000000200000000000000"),
            expected_raw_guest_return: Some(0),
            expected_raw_trap_kind: None,
        },
    ]
}

#[derive(Debug)]
struct StaticModule {
    recipe: Recipe,
    wat: Option<String>,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BlobRef {
    path: String,
    length: usize,
    sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StaticCase {
    id: String,
    input_case: String,
    input_sha256: String,
    actual_module: BlobRef,
    wat: Option<BlobRef>,
    declared_abi_sha256: String,
    declared_module_sha256: String,
    qualified_new_binary_sha256: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StaticInventory {
    schema_version: u32,
    kind: String,
    recipe_contract_sha256: String,
    c1_ref: BlobRef,
    execution_released: bool,
    campaigns_run: u32,
    new_binary_pins_reviewed: bool,
    cases: Vec<StaticCase>,
}

fn declared_identity(id: &str, actual: &str) -> (String, String) {
    let mut abi = ABI_SHA256.to_owned();
    let mut module = actual.to_owned();
    if id == "A03-contract-identity" {
        abi.replace_range(..2, "48");
    }
    if id == "A04-artifact-identity" {
        module.replace_range(..2, "65");
    }
    (abi, module)
}

fn is_reused(id: &str) -> bool {
    matches!(id, "A03-contract-identity" | "A04-artifact-identity")
}

fn ordinary_wat(body: &str) -> String {
    format!(
        r#"(module (memory (export "memory") 1 1)
        (func (export "recover_v0") (param i32 i32 i32 i32) (result i32) {body}))"#
    )
}

fn stores(words: [i32; 4]) -> String {
    words
        .iter()
        .enumerate()
        .map(|(n, value)| format!("local.get 2 i32.const {value} i32.store offset={} ", n * 4))
        .collect()
}

fn new_modules() -> Result<Vec<StaticModule>> {
    let base = ordinary_wat("i32.const 0");
    recipes()
        .into_iter()
        .filter(|r| !is_reused(r.id))
        .map(|recipe| {
            let wat = match recipe.id {
                "A01-malformed-magic" | "A02-module-one-over" => None,
                "A05-host-callback-import" => Some(base.replacen(
                    "(module",
                    r#"(module (import "host" "callback" (func))"#,
                    1,
                )),
                "A06-wasi-import" => Some(base.replacen(
                    "(module",
                    r#"(module (import "wasi_snapshot_preview1" "fd_write" (func))"#,
                    1,
                )),
                "A07-imported-memory" => Some(base.replace(
                    r#"(memory (export "memory") 1 1)"#,
                    r#"(import "host" "memory" (memory 1 1)) (export "memory" (memory 0))"#,
                )),
                "A08-start-function" => {
                    Some(base.replacen("(module", "(module (func) (start 0)", 1))
                }
                "A09-shared-memory" => Some(base.replace(
                    r#"(memory (export "memory") 1 1)"#,
                    r#"(memory (export "memory") 1 1 shared)"#,
                )),
                "A10-threads-opcode" => {
                    Some(ordinary_wat("i32.const 0 i32.atomic.load drop i32.const 0"))
                }
                "A11-absent-memory" => Some(base.replace(r#"(memory (export "memory") 1 1)"#, "")),
                "A12-extra-memory" => Some(base.replace(
                    r#"(memory (export "memory") 1 1)"#,
                    r#"(memory (export "memory") 1 1) (memory 1 1)"#,
                )),
                "A13-memory-min0-max1" => Some(base.replace(
                    r#"(memory (export "memory") 1 1)"#,
                    r#"(memory (export "memory") 0 1)"#,
                )),
                "A14-memory-min2-max2" => Some(base.replace(
                    r#"(memory (export "memory") 1 1)"#,
                    r#"(memory (export "memory") 2 2)"#,
                )),
                "A15-memory-min1-max2" => Some(base.replace(
                    r#"(memory (export "memory") 1 1)"#,
                    r#"(memory (export "memory") 1 2)"#,
                )),
                "A16-memory-no-maximum" => Some(base.replace(
                    r#"(memory (export "memory") 1 1)"#,
                    r#"(memory (export "memory") 1)"#,
                )),
                "A17-missing-recover-export" => Some(base.replace(r#"(export "recover_v0")"#, "")),
                "A18-wrong-recover-signature" => {
                    Some(base.replace("(param i32 i32 i32 i32)", "(param i32 i32 i32)"))
                }
                "A19-missing-memory-export" => Some(base.replace(r#"(export "memory")"#, "")),
                "A20-extra-export" => {
                    Some(base.replacen("(module", r#"(module (export "alias" (func 0))"#, 1))
                }
                "A21-invalid-code" => Some(base.clone()),
                "R01-fuel" => Some(ordinary_wat("(loop br 0) i32.const 0")),
                "R02-stack" => Some(ordinary_wat(
                    "local.get 0 local.get 1 local.get 2 local.get 3 call 0 drop i32.const 0",
                )),
                "E01-trap-after-plausible-output" => {
                    Some(ordinary_wat(&(stores([0, 16, 1, 0]) + "unreachable")))
                }
                "E02-return7-after-plausible-output" => {
                    Some(ordinary_wat(&(stores([0, 16, 1, 0]) + "i32.const 7")))
                }
                "O01-version1" => Some(ordinary_wat(&(stores([1, 16, 1, 0]) + "i32.const 0"))),
                "O02-length15" => Some(ordinary_wat(&(stores([0, 15, 1, 0]) + "i32.const 0"))),
                "O03-disposition5" => Some(ordinary_wat(&(stores([0, 16, 5, 0]) + "i32.const 0"))),
                "O04-reserved1" => Some(ordinary_wat(&(stores([0, 16, 1, 1]) + "i32.const 0"))),
                "O05-incomplete-header" => Some(ordinary_wat(
                    "local.get 2 i32.const 1 i32.store offset=8 i32.const 0",
                )),
                "S01-foreign-operation-plausible-commit" => {
                    Some(ordinary_wat(&(stores([0, 16, 1, 0]) + "i32.const 0")))
                }
                "S02-foreign-generation-plausible-noncommit" => {
                    Some(ordinary_wat(&(stores([0, 16, 2, 0]) + "i32.const 0")))
                }
                _ => bail!("unknown frozen T2 recipe"),
            };
            let bytes = match recipe.id {
                "A01-malformed-magic" => b"not wasm".to_vec(),
                "A02-module-one-over" => vec![0; MAX_STATIC_BYTES],
                _ => {
                    let mut bytes = wat::parse_str(wat.as_ref().context("WAT recipe")?)?;
                    if recipe.id == "A21-invalid-code" {
                        ensure!(
                            bytes.last() == Some(&0x0b),
                            "exact final function end before mutation"
                        );
                        *bytes.last_mut().unwrap() = 0xff;
                    }
                    bytes
                }
            };
            ensure!(
                !bytes.is_empty() && bytes.len() <= MAX_STATIC_BYTES,
                "static fixture bound"
            );
            ensure!(
                recipe.id == "A02-module-one-over" || bytes.len() <= 65536,
                "one-over exception only A02"
            );
            Ok(StaticModule { recipe, wat, bytes })
        })
        .collect()
}

fn blob(path: String, bytes: &[u8]) -> BlobRef {
    BlobRef {
        path,
        length: bytes.len(),
        sha256: digest(bytes),
    }
}

fn static_inventory(modules: &[StaticModule]) -> Result<StaticInventory> {
    ensure!(modules.len() == 30, "exact new module inventory");
    let mut cases = Vec::with_capacity(32);
    for recipe in recipes() {
        let (actual_module, wat) = if is_reused(recipe.id) {
            (
                BlobRef {
                    path: "c1.wasm".into(),
                    length: C1_BYTES,
                    sha256: C1_SHA256.into(),
                },
                None,
            )
        } else {
            let module = modules
                .iter()
                .find(|m| m.recipe.id == recipe.id)
                .context("missing recipe")?;
            (
                blob(format!("{}.wasm", recipe.id), &module.bytes),
                module
                    .wat
                    .as_ref()
                    .map(|w| blob(format!("{}.wat", recipe.id), w.as_bytes())),
            )
        };
        let (declared_abi_sha256, declared_module_sha256) =
            declared_identity(recipe.id, &actual_module.sha256);
        cases.push(StaticCase {
            id: recipe.id.into(),
            input_case: recipe.input_case.into(),
            input_sha256: recipe.input_sha256.into(),
            actual_module,
            wat,
            declared_abi_sha256,
            declared_module_sha256,
            qualified_new_binary_sha256: None,
        });
    }
    Ok(StaticInventory {
        schema_version: 1,
        kind: "recovery_q1_t2_static_fixture_inventory_v1".into(),
        recipe_contract_sha256: RECIPE_CONTRACT.into(),
        c1_ref: BlobRef {
            path: "c1.wasm".into(),
            length: C1_BYTES,
            sha256: C1_SHA256.into(),
        },
        execution_released: false,
        campaigns_run: 0,
        new_binary_pins_reviewed: false,
        cases,
    })
}

fn validate_static_inventory(value: &StaticInventory, modules: &[StaticModule]) -> Result<()> {
    ensure!(
        value == &static_inventory(modules)?,
        "exact static inventory required"
    );
    Ok(())
}

fn write_exclusive(directory: &Path, reference: &BlobRef, data: &[u8]) -> Result<()> {
    ensure!(
        reference
            .path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            && reference.path != "."
            && reference.path != ".."
            && !reference.path.is_empty()
            && reference.path.len() <= 100,
        "flat static output name"
    );
    ensure!(
        reference.length == data.len() && reference.sha256 == digest(data),
        "output identity"
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join(&reference.path))?;
    file.write_all(data)?;
    file.flush()?;
    Ok(())
}

fn emit_static(c1: &[u8], directory: &Path) -> Result<()> {
    checked_c1(c1)?; // refuse before output creation
    let modules = new_modules()?;
    let inventory = static_inventory(&modules)?;
    let mut raw = serde_json::to_vec_pretty(&inventory)?;
    raw.push(b'\n');
    ensure!(raw.len() <= 65536, "static inventory bound");
    fs::DirBuilder::new().mode(0o700).create(directory)?;
    private_directory(directory)?;
    write_exclusive(directory, &blob("c1.wasm".into(), c1), c1)?;
    for module in &modules {
        write_exclusive(
            directory,
            &blob(format!("{}.wasm", module.recipe.id), &module.bytes),
            &module.bytes,
        )?;
        if let Some(wat) = &module.wat {
            write_exclusive(
                directory,
                &blob(format!("{}.wat", module.recipe.id), wat.as_bytes()),
                wat.as_bytes(),
            )?;
        }
    }
    write_exclusive(directory, &blob("inventory.json".into(), &raw), &raw)?;
    Ok(())
}

// This is solely optional static emission. It never compiles/adopts/instantiates
// a module in Wasmtime and cannot select the separately held runtime qualifier.
#[test]
fn t2_emit_static_bytes_only_when_explicit_paths_are_given() {
    match (
        std::env::var_os("RAMEN_Q1_T2_STATIC_C1"),
        std::env::var_os("RAMEN_Q1_T2_STATIC_OUTPUT"),
    ) {
        (None, None) => {}
        (Some(input), Some(output)) => {
            let c1 = read_regular(Path::new(&input), C1_BYTES as u64).unwrap();
            emit_static(&c1, Path::new(&output)).unwrap();
        }
        _ => panic!("both explicit static emission paths required"),
    }
}

fn checked_c1(bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() == C1_BYTES && digest(bytes) == C1_SHA256,
        "exact accepted C1 required"
    );
    Ok(())
}

#[test]
fn t2_static_inventory_preserves_32_rows_phases_and_null_pins() {
    let rows = recipes();
    assert_eq!(rows.len(), 32);
    assert_eq!(rows.iter().map(|x| x.id).collect::<BTreeSet<_>>().len(), 32);
    assert_eq!(rows.first().unwrap().id, "A01-malformed-magic");
    assert_eq!(
        rows.last().unwrap().id,
        "S02-foreign-generation-plausible-noncommit"
    );
    let admitted = rows.iter().filter(|x| x.expected_fault_admitted).count();
    assert_eq!(admitted, 11);
    assert_eq!((32 - admitted) * 2 + admitted * 4, 86);
    assert_eq!((32 - admitted) * 3 + admitted * 4, 107);
    assert_eq!(rows.iter().filter(|x| is_reused(x.id)).count(), 2);
    for row in &rows {
        assert_eq!(row.input_sha256.len(), 64);
        if !row.expected_fault_admitted {
            assert_eq!(row.expected_raw_output_hex, None);
            assert_eq!(row.expected_raw_guest_return, None);
            assert_eq!(row.expected_raw_trap_kind, None);
        }
    }
}

#[test]
fn t2_static_30_new_modules_are_bounded_unique_and_deterministic() {
    let a = new_modules().unwrap();
    let b = new_modules().unwrap();
    assert_eq!(a.len(), 30);
    assert_eq!(a.len(), b.len());
    assert_eq!(
        a.iter()
            .map(|x| digest(&x.bytes))
            .collect::<BTreeSet<_>>()
            .len(),
        30
    );
    for (a, b) in a.iter().zip(&b) {
        assert_eq!(a.recipe, b.recipe);
        assert_eq!(a.bytes, b.bytes);
        assert_eq!(a.wat, b.wat);
        assert!(!is_reused(a.recipe.id));
        assert!(!a.bytes.is_empty() && a.bytes.len() <= MAX_STATIC_BYTES);
        if a.recipe.id != "A02-module-one-over" {
            assert!(a.bytes.len() <= 65536);
        }
    }
}

#[test]
fn t2_static_envelope_keeps_engine_only_cases_and_admitted_recipes() {
    for module in new_modules().unwrap() {
        let expected = module.recipe.expected_fault_admitted
            || matches!(module.recipe.id, "A10-threads-opcode" | "A21-invalid-code");
        assert_eq!(
            validate_shape(&module.bytes).is_some(),
            expected,
            "{}",
            module.recipe.id
        );
    }
}

#[test]
fn t2_static_identity_cases_reuse_c1_with_only_declared_mismatch() {
    let (abi, module) = declared_identity("A03-contract-identity", C1_SHA256);
    assert_eq!(
        abi,
        "48daf52dd669411376770b3bc2a007d7c6a8b346843bcd123a45da8139b0da60"
    );
    assert_eq!(module, C1_SHA256);
    let (abi, module) = declared_identity("A04-artifact-identity", C1_SHA256);
    assert_eq!(abi, ABI_SHA256);
    assert_eq!(
        module,
        "6558a173cd09e73fe0be59b1a2d339c2070c33ac05628b3d2dd5fb264cb2e079"
    );
    assert!(checked_c1(&vec![0; C1_BYTES]).is_err());
    assert!(checked_c1(&[]).is_err());
    assert_eq!(
        declared_identity("O01-version1", C1_SHA256),
        (ABI_SHA256.into(), C1_SHA256.into())
    );
}

#[test]
fn t2_static_special_fault_bytes_do_not_hide_behind_wat_validity() {
    let modules = new_modules().unwrap();
    let get = |id| &modules.iter().find(|m| m.recipe.id == id).unwrap().bytes;
    assert_eq!(get("A01-malformed-magic"), b"not wasm");
    assert_eq!(get("A02-module-one-over"), &vec![0; 65537]);
    let invalid = get("A21-invalid-code");
    assert_eq!(invalid.last(), Some(&0xff));
    assert_eq!(validate_shape(invalid), Some(())); // Pure envelope only, no engine validation.
    assert_eq!(
        get("R01-fuel")
            .windows(4)
            .filter(|b| *b == [0x03, 0x40, 0x0c, 0])
            .count(),
        1
    );
    let stack = get("R02-stack");
    assert!(stack.windows(3).any(|b| b == [0x10, 0, 0x1a])); // call0/drop, no tail-call.
    let atomic = get("A10-threads-opcode");
    assert!(atomic.windows(2).any(|b| b == [0xfe, 0x10]));
}

#[test]
fn t2_static_serialization_round_trip_rejects_unknown_and_promoted_inventory() {
    let modules = new_modules().unwrap();
    let inventory = static_inventory(&modules).unwrap();
    let raw = serde_json::to_vec(&inventory).unwrap();
    let parsed: StaticInventory = serde_json::from_slice(&raw).unwrap();
    validate_static_inventory(&parsed, &modules).unwrap();
    let mut mutated = serde_json::to_value(&inventory).unwrap();
    mutated["unknown"] = true.into();
    assert!(serde_json::from_value::<StaticInventory>(mutated).is_err());
    for field in ["execution_released", "new_binary_pins_reviewed"] {
        let mut changed = inventory.clone();
        if field == "execution_released" {
            changed.execution_released = true;
        } else {
            changed.new_binary_pins_reviewed = true;
        }
        assert!(validate_static_inventory(&changed, &modules).is_err());
    }
    let mut changed = inventory.clone();
    changed.cases[0].qualified_new_binary_sha256 =
        Some(changed.cases[0].actual_module.sha256.clone());
    assert!(validate_static_inventory(&changed, &modules).is_err());
    changed = inventory.clone();
    changed.cases[3].declared_module_sha256 = C1_SHA256.into();
    assert!(validate_static_inventory(&changed, &modules).is_err());
    changed = inventory.clone();
    changed.cases.swap(0, 1);
    assert!(validate_static_inventory(&changed, &modules).is_err());
    validate_static_inventory(
        &static_inventory(&new_modules().unwrap()).unwrap(),
        &modules,
    )
    .unwrap();
    assert_eq!(
        inventory.cases[2].actual_module,
        inventory.cases[3].actual_module
    );
    assert!(
        inventory
            .cases
            .iter()
            .all(|c| c.qualified_new_binary_sha256.is_none())
    );
}

fn code_body(module: &[u8]) -> &[u8] {
    validate_shape(module).unwrap(); // Existing pure outer-envelope checker only.
    let mut tail = &module[8..];
    for id in [1, 3, 5, 7] {
        tail = section(tail, id).unwrap().1;
    }
    let payload = section(tail, 10).unwrap().0;
    let (_, body) = uleb32(&payload[1..]).unwrap();
    assert_eq!(body[0], 0); // no locals
    &body[1..]
}

#[test]
fn t2_static_output_recipe_instruction_bytes_match_frozen_little_endian_words() {
    for module in new_modules()
        .unwrap()
        .iter()
        .filter(|m| m.recipe.expected_fault_admitted)
    {
        let body = code_body(&module.bytes);
        match module.recipe.id {
            "R01-fuel" => assert_eq!(body, [0x03, 0x40, 0x0c, 0, 0x0b, 0x41, 0, 0x0b]),
            "R02-stack" => assert_eq!(
                body,
                [
                    0x20, 0, 0x20, 1, 0x20, 2, 0x20, 3, 0x10, 0, 0x1a, 0x41, 0, 0x0b
                ]
            ),
            id => {
                let output = hex::decode(module.recipe.expected_raw_output_hex.unwrap()).unwrap();
                let mut expected = Vec::new();
                for (n, word) in output.chunks_exact(4).enumerate() {
                    if id == "O05-incomplete-header" && n != 2 {
                        continue;
                    }
                    let value = u32::from_le_bytes(word.try_into().unwrap());
                    assert!(value < 64);
                    expected.extend([0x20, 2, 0x41, value as u8, 0x36, 2, (n * 4) as u8]);
                }
                if id == "E01-trap-after-plausible-output" {
                    expected.push(0x00);
                } else {
                    expected.extend([0x41, module.recipe.expected_raw_guest_return.unwrap() as u8]);
                }
                expected.push(0x0b);
                assert_eq!(body, expected, "{id}");
            }
        }
    }
}

#[test]
fn t2_static_writer_refuses_collision_identity_and_bad_c1_then_fresh_write_succeeds() {
    let private = tempfile::tempdir().unwrap();
    let directory = private.path();
    let reference = blob("one.wasm".into(), b"one");
    write_exclusive(directory, &reference, b"one").unwrap();
    assert!(write_exclusive(directory, &reference, b"one").is_err());
    assert_eq!(fs::read(directory.join("one.wasm")).unwrap(), b"one");
    let mut changed = blob("changed.wasm".into(), b"one");
    assert!(write_exclusive(directory, &changed, b"two").is_err());
    assert!(!directory.join("changed.wasm").exists());
    changed.path = "../escape.wasm".into();
    assert!(write_exclusive(directory, &changed, b"one").is_err());
    let output = directory.join("uncreated");
    assert!(emit_static(b"bad", &output).is_err());
    assert!(!output.exists());
    write_exclusive(directory, &blob("fresh.wasm".into(), b"fresh"), b"fresh").unwrap();
    assert_eq!(fs::read(directory.join("fresh.wasm")).unwrap(), b"fresh");
}

// A2: review-gated stage/result bridge. Synthetic unit calls are disposable;
// the separately ignored canonical campaign remains default-denied.
use super::super::{
    INPUT_LEN, RECOVERY_ABI_SHA256, RecoveryArtifactV0, RecoveryDecisionAdapter,
    RecoveryDispositionV0, RecoveryError, RecoveryObservationV0, project,
};
use artifact_store_schema::editor_save::{
    EditorActorV0, EditorSaveAllocationV0, EditorSaveBindingV0, EditorSourceBindingV0, RECEIPT_LEN,
    VERSION,
};
use serde_json::{Value, json};

const T2_REVIEWED_MANIFEST_SHA256: Option<&str> =
    Some("9eb988c2a85180db3bf7068270694730fe785960d2aa2413502da46010cc663b");
const T2_SCHEMA_SHA256: &str = "4ebdd90672f221cf53bbdd1326b81f734a363dbda0d30bc702a8b2fbca62f2a4";
const T2_REGISTRATION_SHA256: &str =
    "185957fc5f45900995de9c4705c7936ac834cffea3006c67b6596e7e33e656e2";
const T2_CORPUS_SHA256: &str = "84eece3246d9b4521a5b8ac48fa6324cb4be4e98889277ab46837f6764aeda49";
const T2_REPORT_BYTES: usize = 16 * 1024 * 1024;

fn t2_detail(text: impl ToString) -> String {
    text.to_string().chars().take(512).collect()
}

fn t2_disposition(value: RecoveryDispositionV0) -> &'static str {
    match value {
        RecoveryDispositionV0::Pending => "Pending",
        RecoveryDispositionV0::Committed => "Committed",
        RecoveryDispositionV0::DefinitiveNoncommit => "DefinitiveNoncommit",
        RecoveryDispositionV0::Denied => "Denied",
        RecoveryDispositionV0::Invalid => "Invalid",
    }
}

fn t2_error(error: &RecoveryError) -> Value {
    match error {
        RecoveryError::ArtifactIdentity => json!({"kind":"artifact_identity"}),
        RecoveryError::ModuleShape => json!({"kind":"module_shape"}),
        RecoveryError::Engine(error) => json!({"kind":"engine","detail":t2_detail(error)}),
        RecoveryError::InvalidOriginal => json!({"kind":"invalid_original"}),
        RecoveryError::Fuel => json!({"kind":"fuel"}),
        RecoveryError::Stack => json!({"kind":"stack"}),
        RecoveryError::Trap(error) => json!({"kind":"trap","detail":t2_detail(error)}),
        RecoveryError::Return(code) => json!({"kind":"guest_return","code":code}),
        RecoveryError::Output => json!({"kind":"invalid_output"}),
        RecoveryError::Disagreement {
            candidate,
            expected,
        } => json!({"kind":"disagreement",
            "candidate":t2_disposition(*candidate),"expected":t2_disposition(*expected)}),
    }
}

fn t2_err_result(error: &RecoveryError) -> Value {
    json!({"status":"error","error":t2_error(error)})
}

fn t2_admission(module: &[u8], identity: RecoveryArtifactV0) -> Value {
    let result = match RecoveryDecisionAdapter::new(module, identity) {
        Ok(_) => json!({"status":"accepted"}), // Do not execute an unexpectedly accepted admission case.
        Err(error) => t2_err_result(&error),
    };
    json!({"phase":"admission","module_sha256":digest(module),"result":result,"raw":null})
}

fn t2_checked_observation(observation: super::Observation) -> Result<Value> {
    ensure!(
        observation.guest_return.is_some() != observation.trap.is_some(),
        "return/trap XOR"
    );
    super::bytes(&observation.memory_before_hex, super::PAGE)?;
    super::bytes(&observation.memory_after_hex, super::PAGE)?;
    if let Some(trap) = &observation.trap {
        ensure!(
            matches!(trap.kind, "fuel" | "stack" | "trap") && trap.detail.chars().count() <= 512,
            "actual bounded trap record"
        );
    }
    Ok(serde_json::to_value(observation)?)
}

fn t2_raw(
    phase: &str,
    module: &[u8],
    identity: RecoveryArtifactV0,
    initial: &[u8],
) -> Result<Value> {
    ensure!(matches!(phase, "fault_raw" | "fresh_raw"), "raw phase");
    let (admission, observation, observation_error) =
        match RecoveryDecisionAdapter::new(module, identity) {
            Err(error) => (t2_err_result(&error), Value::Null, Value::Null),
            Ok(adapter) => match super::observe(&adapter, initial, [4096, 336, 4448, 16]) {
                Ok(actual) => (
                    json!({"status":"accepted"}),
                    t2_checked_observation(actual)?,
                    Value::Null,
                ),
                Err(error) => (
                    json!({"status":"accepted"}),
                    Value::Null,
                    json!({"detail":t2_detail(error)}),
                ),
            },
        };
    Ok(
        json!({"phase":phase,"module_sha256":digest(module),"admission":admission,
        "observation":observation,"observation_error":observation_error}),
    )
}

fn t2_receiving(
    phase: &str,
    module: &[u8],
    identity: RecoveryArtifactV0,
    original: &EditorSaveBindingV0,
    epoch: u64,
    input: &[u8; INPUT_LEN],
) -> Result<Value> {
    ensure!(
        matches!(phase, "fault_receiving" | "fresh_receiving"),
        "receiving phase"
    );
    let (stage, projected_input_hex, projection_error, result) =
        match RecoveryDecisionAdapter::new(module, identity) {
            Err(error) => ("new", Value::Null, Value::Null, t2_err_result(&error)),
            Ok(adapter) => {
                let receipt: &[u8; RECEIPT_LEN] = input[160..].try_into()?;
                let observation = RecoveryObservationV0::Receipt(receipt);
                let (projected, projection_error) = match project(original, epoch, observation) {
                    Ok(bytes) => (json!(hex::encode(bytes)), Value::Null),
                    Err(error) => (Value::Null, t2_error(&error)),
                };
                // Actual decide is called even when the separately observed project failed.
                let result = match adapter.decide(original, epoch, observation) {
                    Ok(value) => json!({"status":"ok","disposition":t2_disposition(value)}),
                    Err(error) => t2_err_result(&error),
                };
                ("decide", projected, projection_error, result)
            }
        };
    Ok(
        json!({"phase":phase,"module_sha256":digest(module),"stage":stage,
        "projected_input_hex":projected_input_hex,"projection_error":projection_error,"result":result}),
    )
}

#[cfg(test)]
mod runtime_controls {
    use super::*;
    use artifact_store_schema::editor_save::{EditorCommitPermitV0, EditorSaveReceiptV0};

    pub(super) fn synthetic(body: &str) -> Vec<u8> {
        // Deliberately distinct from canonical binary recipes: unused local.
        wat::parse_str(ordinary_wat(&format!("(local i32) {body}"))).unwrap()
    }
    pub(super) fn identity(module: &[u8]) -> RecoveryArtifactV0 {
        RecoveryArtifactV0 {
            abi_sha256: RECOVERY_ABI_SHA256,
            module_sha256: hex::decode(digest(module)).unwrap().try_into().unwrap(),
        }
    }
    pub(super) fn original() -> EditorSaveBindingV0 {
        EditorSaveBindingV0::try_new(
            EditorSaveAllocationV0 {
                schema_version: VERSION,
                actor: EditorActorV0::try_new(1, 2, 3, 4, 5).unwrap(),
                selected_object_id: 6,
                selected_generation: 7,
                operation_id: 8,
                expected_revision: 9,
                expected_content_hash: [10; 32],
            },
            EditorSourceBindingV0::try_new(11, 12, 13, [14; 32]).unwrap(),
        )
        .unwrap()
    }
    pub(super) fn input(original: &EditorSaveBindingV0) -> [u8; INPUT_LEN] {
        let permit = EditorCommitPermitV0::try_new(original.clone(), 17, 18, 19).unwrap();
        let receipt = EditorSaveReceiptV0::committed(&permit, 0)
            .unwrap()
            .encode_le()
            .unwrap();
        project(original, 17, RecoveryObservationV0::Receipt(&receipt)).unwrap()
    }
    fn initial(input: &[u8; INPUT_LEN]) -> Vec<u8> {
        t2_initial_memory(input).unwrap()
    }
    pub(super) fn success() -> Vec<u8> {
        synthetic(&(stores([0, 16, 1, 0]) + "i32.const 0"))
    }

    #[test]
    fn t2_synthetic_records_unexpected_admission_acceptance_without_disposition() {
        let module = synthetic("unreachable");
        let result = t2_admission(&module, identity(&module));
        assert_eq!(result["result"], json!({"status":"accepted"}));
        assert!(result["raw"].is_null());
        let fresh = success();
        let original = original();
        let next = t2_receiving(
            "fresh_receiving",
            &fresh,
            identity(&fresh),
            &original,
            17,
            &input(&original),
        )
        .unwrap();
        assert_eq!(
            next["result"],
            json!({"status":"ok","disposition":"Committed"})
        );
    }
    #[test]
    fn t2_synthetic_raw_failure_and_actual_receiving_error_then_fresh_success() {
        let module = synthetic(&(stores([0, 16, 1, 0]) + "i32.const 7"));
        let original = original();
        let input = input(&original);
        let raw = t2_raw("fault_raw", &module, identity(&module), &initial(&input)).unwrap();
        assert_eq!(raw["observation"]["guest_return"], 7);
        assert!(raw["observation"]["trap"].is_null());
        assert_eq!(
            raw["observation"]["memory_before_hex"]
                .as_str()
                .unwrap()
                .len(),
            131072
        );
        let receiving = t2_receiving(
            "fault_receiving",
            &module,
            identity(&module),
            &original,
            17,
            &input,
        )
        .unwrap();
        assert_eq!(receiving["stage"], "decide");
        assert_eq!(receiving["projected_input_hex"], hex::encode(input));
        assert_eq!(
            receiving["result"],
            json!({"status":"error","error":{"kind":"guest_return","code":7}})
        );
        let fresh = success();
        let next = t2_receiving(
            "fresh_receiving",
            &fresh,
            identity(&fresh),
            &original,
            17,
            &input,
        )
        .unwrap();
        assert_eq!(next["result"]["disposition"], "Committed");
    }
    #[test]
    fn t2_synthetic_constructor_and_observe_failures_remain_distinct_and_null() {
        let original = original();
        let input = input(&original);
        let malformed = b"not wasm";
        let result = t2_receiving(
            "fault_receiving",
            malformed,
            identity(malformed),
            &original,
            17,
            &input,
        )
        .unwrap();
        assert_eq!(result["stage"], "new");
        assert!(result["projected_input_hex"].is_null());
        assert!(result["projection_error"].is_null());
        assert_eq!(result["result"]["error"]["kind"], "module_shape");
        let fresh = success();
        let result = t2_raw("fault_raw", &fresh, identity(&fresh), &[]).unwrap();
        assert_eq!(result["admission"]["status"], "accepted");
        assert!(result["observation"].is_null());
        assert!(result["observation_error"]["detail"].is_string());
        let next = t2_raw("fresh_raw", &fresh, identity(&fresh), &initial(&input)).unwrap();
        assert_eq!(next["observation"]["guest_return"], 0);
    }
    #[test]
    fn t2_synthetic_actual_fault_families_keep_raw_and_public_results_separate() {
        let original = original();
        let input = input(&original);
        let fresh = success();
        let bodies = [
            ("fuel", "(loop br 0) i32.const 0".into()),
            (
                "stack",
                "local.get 0 local.get 1 local.get 2 local.get 3 call 0 drop i32.const 0".into(),
            ),
            ("trap", stores([0, 16, 1, 0]) + "unreachable"),
            ("invalid_output", stores([1, 16, 1, 0]) + "i32.const 0"),
        ];
        for (kind, body) in bodies {
            let module = synthetic(&body);
            let raw = t2_raw("fault_raw", &module, identity(&module), &initial(&input)).unwrap();
            assert_eq!(raw["admission"]["status"], "accepted");
            if matches!(kind, "fuel" | "stack" | "trap") {
                assert!(raw["observation"]["guest_return"].is_null());
                assert_eq!(raw["observation"]["trap"]["kind"], kind);
            } else {
                assert_eq!(raw["observation"]["guest_return"], 0);
            }
            let next = t2_raw("fresh_raw", &fresh, identity(&fresh), &initial(&input)).unwrap();
            assert_eq!(next["observation"]["guest_return"], 0);
            let actual = t2_receiving(
                "fault_receiving",
                &module,
                identity(&module),
                &original,
                17,
                &input,
            )
            .unwrap();
            assert_eq!(actual["result"]["error"]["kind"], kind);
            let next = t2_receiving(
                "fresh_receiving",
                &fresh,
                identity(&fresh),
                &original,
                17,
                &input,
            )
            .unwrap();
            assert_eq!(next["result"]["disposition"], "Committed");
        }
        let mut foreign = input;
        let receipt: &[u8; RECEIPT_LEN] = foreign[160..].try_into().unwrap();
        let mut receipt = EditorSaveReceiptV0::decode_le(receipt).unwrap();
        receipt.operation_id += 1;
        foreign[160..].copy_from_slice(&receipt.encode_le().unwrap());
        let actual = t2_receiving(
            "fault_receiving",
            &fresh,
            identity(&fresh),
            &original,
            17,
            &foreign,
        )
        .unwrap();
        assert_eq!(actual["projected_input_hex"], hex::encode(foreign));
        assert_eq!(
            actual["result"]["error"],
            json!({"kind":"disagreement","candidate":"Committed","expected":"Invalid"})
        );
        assert_eq!(
            t2_receiving(
                "fresh_receiving",
                &fresh,
                identity(&fresh),
                &original,
                17,
                &input
            )
            .unwrap()["result"]["disposition"],
            "Committed"
        );
    }
    #[test]
    fn t2_synthetic_projection_refusal_and_engine_error_are_actual_results() {
        let original = original();
        let input = input(&original);
        let module = success();
        let actual = t2_receiving(
            "fault_receiving",
            &module,
            identity(&module),
            &original,
            0,
            &input,
        )
        .unwrap();
        assert_eq!(actual["stage"], "decide");
        assert!(actual["projected_input_hex"].is_null());
        assert_eq!(
            actual["projection_error"],
            json!({"kind":"invalid_original"})
        );
        assert_eq!(actual["result"]["error"]["kind"], "invalid_original");
        let mut invalid = synthetic("i32.const 0");
        *invalid.last_mut().unwrap() = 0xff;
        let actual = t2_admission(&invalid, identity(&invalid));
        assert_eq!(actual["result"]["error"]["kind"], "engine");
        assert!(actual["raw"].is_null());
        let next = t2_receiving(
            "fresh_receiving",
            &module,
            identity(&module),
            &original,
            17,
            &input,
        )
        .unwrap();
        assert_eq!(next["result"]["disposition"], "Committed");
    }
    #[test]
    fn t2_synthetic_raw_guard_damage_is_retained_then_fresh_instance_has_clean_page() {
        let original = original();
        let input = input(&original);
        let module = synthetic(
            &(String::from("i32.const 0 i32.const 42 i32.store8 ")
                + &stores([0, 16, 1, 0])
                + "i32.const 7"),
        );
        let actual = t2_raw("fault_raw", &module, identity(&module), &initial(&input)).unwrap();
        assert!(
            actual["observation"]["memory_before_hex"]
                .as_str()
                .unwrap()
                .starts_with("a5")
        );
        assert!(
            actual["observation"]["memory_after_hex"]
                .as_str()
                .unwrap()
                .starts_with("2a")
        );
        let fresh = success();
        let next = t2_raw("fresh_raw", &fresh, identity(&fresh), &initial(&input)).unwrap();
        assert!(
            next["observation"]["memory_before_hex"]
                .as_str()
                .unwrap()
                .starts_with("a5")
        );
        assert!(
            next["observation"]["memory_after_hex"]
                .as_str()
                .unwrap()
                .starts_with("a5")
        );
    }
    #[test]
    fn t2_full_snapshot_xor_lowercase_and_unicode_scalar_guards() {
        let observation = || super::super::Observation {
            guest_return: Some(0),
            trap: None,
            memory_before_hex: "a5".repeat(65536),
            memory_after_hex: "a5".repeat(65536),
        };
        let mut invalid = observation();
        invalid.trap = Some(super::super::TrapRecord {
            kind: "trap",
            detail: "actual".into(),
        });
        assert!(t2_checked_observation(invalid).is_err());
        let mut invalid = observation();
        invalid.memory_after_hex.pop();
        assert!(t2_checked_observation(invalid).is_err());
        let mut invalid = observation();
        invalid.memory_before_hex.replace_range(..1, "A");
        assert!(t2_checked_observation(invalid).is_err());
        let detail = "é🦀".repeat(300);
        let actual = t2_error(&RecoveryError::Trap(anyhow::anyhow!(detail)));
        let bounded = actual["detail"].as_str().unwrap();
        assert_eq!(bounded.chars().count(), 512);
        assert!(bounded.len() > 512);
        let mut actual = observation();
        actual.guest_return = None;
        actual.trap = Some(super::super::TrapRecord {
            kind: "trap",
            detail: bounded.into(),
        });
        assert!(t2_checked_observation(actual).is_ok());
        let mut invalid = observation();
        invalid.guest_return = None;
        invalid.trap = Some(super::super::TrapRecord {
            kind: "trap",
            detail: "🦀".repeat(513),
        });
        assert!(t2_checked_observation(invalid).is_err());
        assert!(t2_checked_observation(observation()).is_ok());
    }
}

fn t2_initial_memory(input: &[u8; INPUT_LEN]) -> Result<Vec<u8>> {
    // Only a carrier for the unchanged T1 initializer. It is never serialized,
    // admitted as a T1 fixture or used to classify candidate/receiving behavior.
    let carrier = super::Fixture {
        schema_version: 1,
        kind: "t2-initialization-carrier".into(),
        abi_sha256: ABI_SHA256.into(),
        corpus_sha256: T2_CORPUS_SHA256.into(),
        obligations_sha256: String::new(),
        source_case: super::SourceCase {
            id: "t2-bound-input".into(),
            family: "initialization-only".into(),
            reason: "reuse T1 initializer".into(),
            input_hex: hex::encode(input),
            expected_return: 0,
            expected_output_hex: "00000000100000000100000000000000".into(),
        },
        memory_bytes: super::PAGE,
        initial_fill_byte: 165,
        input_initialization_offset: 4096,
        canonical_call: [4096, 336, 4448, 16],
        cases: vec![],
    };
    super::initial_memory(&carrier, None)
}

#[derive(Clone)]
struct T2Manifest {
    sha256: String,
    fixture_inventory_sha256: String,
    expected_cases_sha256: String,
    parent_pins: Value,
}
struct T2LoadedCase {
    id: String,
    module: Vec<u8>,
    identity: RecoveryArtifactV0,
    input: [u8; INPUT_LEN],
    admitted: bool,
}
struct PreparedT2 {
    plan_sha256: String,
    manifest_sha256: String,
    inventory_sha256: String,
    expected_sha256: String,
    c1: Vec<u8>,
    canonical_input: [u8; INPUT_LEN],
    original: EditorSaveBindingV0,
    epoch: u64,
    cases: Vec<T2LoadedCase>,
}

// Deserialize through a duplicate-rejecting tree before typed field decoding.
// Opaque manifest provenance may contain floats; schema integer fields may not.
struct T2UniqueJson(Value);
impl<'de> Deserialize<'de> for T2UniqueJson {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = T2UniqueJson;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("unique-key JSON")
            }
            fn visit_bool<E: serde::de::Error>(
                self,
                v: bool,
            ) -> std::result::Result<Self::Value, E> {
                Ok(T2UniqueJson(json!(v)))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> std::result::Result<Self::Value, E> {
                Ok(T2UniqueJson(json!(v)))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> std::result::Result<Self::Value, E> {
                Ok(T2UniqueJson(json!(v)))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> std::result::Result<Self::Value, E> {
                Ok(T2UniqueJson(Value::Number(
                    serde_json::Number::from_f64(v).ok_or_else(|| E::custom("nonfinite"))?,
                )))
            }
            fn visit_str<E: serde::de::Error>(
                self,
                v: &str,
            ) -> std::result::Result<Self::Value, E> {
                Ok(T2UniqueJson(json!(v)))
            }
            fn visit_string<E: serde::de::Error>(
                self,
                v: String,
            ) -> std::result::Result<Self::Value, E> {
                Ok(T2UniqueJson(json!(v)))
            }
            fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(T2UniqueJson(Value::Null))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = seq.next_element::<T2UniqueJson>()? {
                    values.push(value.0)
                }
                Ok(T2UniqueJson(Value::Array(values)))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate JSON key"));
                    }
                    values.insert(key, map.next_value::<T2UniqueJson>()?.0);
                }
                Ok(T2UniqueJson(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}
fn t2_json<T: serde::de::DeserializeOwned>(raw: &[u8]) -> Result<T> {
    let mut de = serde_json::Deserializer::from_slice(raw);
    let value = T2UniqueJson::deserialize(&mut de)?.0;
    de.end()?;
    Ok(serde_json::from_value(value)?)
}
fn t2_no_float(value: &Value) -> Result<()> {
    match value {
        Value::Number(n) => ensure!(n.is_u64() || n.is_i64(), "strict integer"),
        Value::Array(a) => {
            for v in a {
                t2_no_float(v)?
            }
        }
        Value::Object(o) => {
            for v in o.values() {
                t2_no_float(v)?
            }
        }
        _ => {}
    }
    Ok(())
}
fn t2_read(path: &Path, bound: usize) -> Result<Vec<u8>> {
    use std::{
        io::Read,
        os::unix::fs::{MetadataExt, PermissionsExt},
    };
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.permissions().mode() & 0o777 == 0o600
            && metadata.len() <= bound as u64,
        "bounded private regular artifact"
    );
    let mut bytes = Vec::new();
    file.take(bound as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= bound, "artifact byte bound");
    Ok(bytes)
}
fn t2_ref_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 100
            && name != "."
            && name != ".."
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "flat stage reference"
    );
    Ok(())
}
fn t2_read_ref(directory: &Path, reference: &BlobRef, bound: usize) -> Result<Vec<u8>> {
    t2_ref_name(&reference.path)?;
    super::bytes(&reference.sha256, 32)?;
    ensure!(reference.length <= bound, "role-specific bound");
    let bytes = t2_read(&directory.join(&reference.path), bound)?;
    ensure!(
        reference.length == bytes.len() && reference.sha256 == digest(&bytes),
        "stage artifact identity"
    );
    Ok(bytes)
}
fn t2_contract() -> Result<Value> {
    let raw = include_bytes!("../../../docs/contracts/recovery-q1-t2-fixture-contract-v1.json");
    ensure!(
        raw.len() == 43314 && digest(raw) == RECIPE_CONTRACT,
        "frozen recipe source identity"
    );
    t2_json(raw)
}
fn t2_reviewed_manifest(pin: Option<&str>, path: &Path) -> Result<T2Manifest> {
    let Some(pin) = pin else {
        bail!("reviewed T2 manifest pending")
    };
    super::bytes(pin, 32)?;
    ensure!(path.is_absolute(), "absolute manifest path");
    let raw = t2_read(path, 32768)?;
    ensure!(digest(&raw) == pin, "reviewed manifest identity");
    let value: Value = t2_json(&raw)?;
    ensure!(
        value["schema_version"].as_u64() == Some(1)
            && value["kind"] == "recovery_q1_t2_manifest_v1"
            && value["schema_sha256"] == T2_SCHEMA_SHA256
            && value["recipe_contract_sha256"] == RECIPE_CONTRACT,
        "manifest envelope"
    );
    let inventory = value["fixture_inventory_sha256"]
        .as_str()
        .context("inventory pin")?;
    let expected = value["expected_cases_sha256"]
        .as_str()
        .context("expected pin")?;
    super::bytes(inventory, 32)?;
    super::bytes(expected, 32)?;
    t2_no_float(&value["parent_pins"])?;
    ensure!(
        value["parent_pins"] == t2_contract()?["existing_pins"],
        "exact parent pins"
    );
    // Additional fields are opaque bounded provenance, never extra file paths.
    Ok(T2Manifest {
        sha256: pin.into(),
        fixture_inventory_sha256: inventory.into(),
        expected_cases_sha256: expected.into(),
        parent_pins: value["parent_pins"].clone(),
    })
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct T2Plan {
    schema_version: u32,
    kind: String,
    manifest_sha256: String,
    recipe_contract_sha256: String,
    fixture_inventory_ref: BlobRef,
    expected_cases_ref: BlobRef,
    abi_sha256: String,
    candidate_module_sha256: String,
    registration_sha256: String,
    owner_lifecycle_exercised: bool,
    live_parent_authority_exercised: bool,
    measured_benefit: bool,
    activation_accepted: bool,
    full_q1_qualified: bool,
    full_18_receiving_acceptance: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct T2CanonicalInput {
    id: String,
    input_hex: String,
    input_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct T2ExpectedRow {
    id: String,
    input_case: String,
    input_hex: String,
    input_sha256: String,
    expected_fault_admitted: bool,
    expected_receiving_error: String,
    expected_raw_output_hex: Option<String>,
    expected_raw_guest_return: Option<i32>,
    expected_raw_trap_kind: Option<String>,
    expected_receiving_return_code: Option<i32>,
    expected_disagreement: Option<Value>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct T2Expected {
    schema_version: u32,
    kind: String,
    recipe_contract_sha256: String,
    abi_sha256: String,
    corpus_sha256: String,
    receiving_original: Value,
    canonical_case: T2CanonicalInput,
    cases: Vec<T2ExpectedRow>,
}
fn t2_canonical_original() -> Result<EditorSaveBindingV0> {
    let expected_hash: Vec<u8> = (0u8..32).collect();
    let source_hash: Vec<u8> = (0xe0u8..=0xff).collect();
    EditorSaveBindingV0::try_new(
        EditorSaveAllocationV0 {
            schema_version: VERSION,
            actor: EditorActorV0::try_new(101, 202, 303, 404, 505)
                .map_err(|e| anyhow::anyhow!("actor: {e:?}"))?,
            selected_object_id: 606,
            selected_generation: 707,
            operation_id: 808,
            expected_revision: 909,
            expected_content_hash: expected_hash.try_into().unwrap(),
        },
        EditorSourceBindingV0::try_new(1101, 1102, 1103, source_hash.try_into().unwrap())
            .map_err(|e| anyhow::anyhow!("source: {e:?}"))?,
    )
    .map_err(|e| anyhow::anyhow!("original: {e:?}"))
}
fn t2_fixed_input(text: &str, expected_hash: &str) -> Result<[u8; INPUT_LEN]> {
    super::bytes(expected_hash, 32)?;
    let input = super::bytes(text, INPUT_LEN)?;
    ensure!(digest(&input) == expected_hash, "frozen input digest");
    Ok(input.try_into().unwrap())
}
fn t2_identity(case: &StaticCase) -> Result<RecoveryArtifactV0> {
    Ok(RecoveryArtifactV0 {
        abi_sha256: super::bytes(&case.declared_abi_sha256, 32)?
            .try_into()
            .unwrap(),
        module_sha256: super::bytes(&case.declared_module_sha256, 32)?
            .try_into()
            .unwrap(),
    })
}
fn t2_exact_keys(value: &Value, required: &[&str]) -> Result<()> {
    let object = value.as_object().context("required object")?;
    ensure!(
        object.len() == required.len() && required.iter().all(|key| object.contains_key(*key)),
        "exact required JSON keys including nulls"
    );
    Ok(())
}
fn t2_load_stage(directory: &Path, manifest: &T2Manifest) -> Result<PreparedT2> {
    ensure!(directory.is_absolute(), "absolute stage directory");
    private_directory(directory)?;
    let schema = t2_read(&directory.join("schema-v1.json"), 128 * 1024)?;
    ensure!(
        schema.len() == 99643 && digest(&schema) == T2_SCHEMA_SHA256,
        "exact schema source identity"
    );
    let contract_raw = t2_read(&directory.join("fixture-contract-v1.json"), 65536)?;
    ensure!(
        contract_raw.len() == 43314 && digest(&contract_raw) == RECIPE_CONTRACT,
        "exact recipe source identity"
    );
    let contract: Value = t2_json(&contract_raw)?;
    t2_no_float(&manifest.parent_pins)?;
    ensure!(
        manifest.parent_pins == contract["existing_pins"],
        "exact parent closure"
    );
    let plan_raw = t2_read(&directory.join("plan.json"), 32768)?;
    let plan: T2Plan = t2_json(&plan_raw)?;
    ensure!(
        plan.schema_version == 1
            && plan.kind == "recovery_q1_t2_plan_v1"
            && plan.manifest_sha256 == manifest.sha256
            && plan.recipe_contract_sha256 == RECIPE_CONTRACT
            && plan.abi_sha256 == ABI_SHA256
            && plan.candidate_module_sha256 == C1_SHA256
            && plan.registration_sha256 == T2_REGISTRATION_SHA256
            && !plan.owner_lifecycle_exercised
            && !plan.live_parent_authority_exercised
            && !plan.measured_benefit
            && !plan.activation_accepted
            && !plan.full_q1_qualified
            && !plan.full_18_receiving_acceptance,
        "exact held-scope plan"
    );
    ensure!(
        plan.fixture_inventory_ref.path == "fixture-inventory.json"
            && plan.expected_cases_ref.path == "expected-cases.json"
            && plan.fixture_inventory_ref.sha256 == manifest.fixture_inventory_sha256
            && plan.expected_cases_ref.sha256 == manifest.expected_cases_sha256,
        "manifest/plan byte pins"
    );
    let inventory_raw = t2_read_ref(directory, &plan.fixture_inventory_ref, 65536)?;
    let expected_raw = t2_read_ref(directory, &plan.expected_cases_ref, 65536)?;
    let inventory_value: Value = t2_json(&inventory_raw)?;
    for case in inventory_value["cases"]
        .as_array()
        .context("inventory rows")?
    {
        t2_exact_keys(
            case,
            &[
                "id",
                "input_case",
                "input_sha256",
                "actual_module",
                "wat",
                "declared_abi_sha256",
                "declared_module_sha256",
                "qualified_new_binary_sha256",
            ],
        )?;
    }
    let expected_value: Value = t2_json(&expected_raw)?;
    for case in expected_value["cases"]
        .as_array()
        .context("expected rows")?
    {
        t2_exact_keys(
            case,
            &[
                "id",
                "input_case",
                "input_hex",
                "input_sha256",
                "expected_fault_admitted",
                "expected_receiving_error",
                "expected_raw_output_hex",
                "expected_raw_guest_return",
                "expected_raw_trap_kind",
                "expected_receiving_return_code",
                "expected_disagreement",
            ],
        )?;
    }
    let inventory: StaticInventory = serde_json::from_value(inventory_value)?;
    let expected: T2Expected = serde_json::from_value(expected_value)?;
    ensure!(
        inventory.schema_version == 1
            && inventory.kind == "recovery_q1_t2_static_fixture_inventory_v1"
            && inventory.recipe_contract_sha256 == RECIPE_CONTRACT
            && !inventory.execution_released
            && inventory.campaigns_run == 0
            && !inventory.new_binary_pins_reviewed
            && inventory.cases.len() == 32,
        "immutable emission inventory"
    );
    ensure!(
        inventory.c1_ref
            == BlobRef {
                path: "c1.wasm".into(),
                length: C1_BYTES,
                sha256: C1_SHA256.into()
            },
        "accepted C1 reference"
    );
    let c1 = t2_read_ref(directory, &inventory.c1_ref, C1_BYTES)?;
    checked_c1(&c1)?;
    ensure!(
        expected.schema_version == 1
            && expected.kind == "recovery_q1_t2_expected_cases_v1"
            && expected.recipe_contract_sha256 == RECIPE_CONTRACT
            && expected.abi_sha256 == ABI_SHA256
            && expected.corpus_sha256 == T2_CORPUS_SHA256
            && expected.cases.len() == 32,
        "bound expected inventory"
    );
    let mut required_original = contract["common_call"]["receiving_original_fixture"].clone();
    required_original
        .as_object_mut()
        .context("frozen original")?
        .retain(|k, _| {
            matches!(
                k.as_str(),
                "actor" | "allocation" | "source" | "original_store_epoch"
            )
        });
    t2_no_float(&expected.receiving_original)?;
    ensure!(
        expected.receiving_original == required_original,
        "frozen structural original"
    );
    let canonical = &expected.canonical_case;
    ensure!(
        canonical.id == "outcome-0" && canonical.input_sha256 == recipes()[0].input_sha256,
        "canonical input pin"
    );
    let canonical_input = t2_fixed_input(&canonical.input_hex, &canonical.input_sha256)?;
    let original = t2_canonical_original()?;
    let epoch = 1010;
    let reserved = [
        "plan.json",
        "fixture-inventory.json",
        "expected-cases.json",
        "schema-v1.json",
        "fixture-contract-v1.json",
    ];
    let mut seen = std::collections::BTreeMap::new();
    seen.insert(inventory.c1_ref.path.clone(), inventory.c1_ref.clone());
    let mut new_hashes = BTreeSet::new();
    let mut cases = Vec::with_capacity(32);
    for (((entry, row), recipe), frozen) in inventory
        .cases
        .iter()
        .zip(&expected.cases)
        .zip(recipes())
        .zip(contract["fixtures"].as_array().context("frozen rows")?)
    {
        ensure!(
            entry.id == recipe.id
                && row.id == recipe.id
                && entry.input_case == recipe.input_case
                && row.input_case == recipe.input_case
                && entry.input_sha256 == recipe.input_sha256
                && row.input_sha256 == recipe.input_sha256
                && entry.qualified_new_binary_sha256.is_none(),
            "ordered case input identity"
        );
        ensure!(
            row.expected_fault_admitted == recipe.expected_fault_admitted
                && row.expected_receiving_error == recipe.expected_receiving_error
                && row.expected_raw_output_hex.as_deref() == recipe.expected_raw_output_hex
                && row.expected_raw_guest_return == recipe.expected_raw_guest_return
                && row.expected_raw_trap_kind.as_deref() == recipe.expected_raw_trap_kind
                && serde_json::to_value(row.expected_receiving_return_code)?
                    == frozen
                        .get("expected_receiving_return_code")
                        .cloned()
                        .unwrap_or(Value::Null)
                && serde_json::to_value(&row.expected_disagreement)?
                    == frozen
                        .get("expected_disagreement")
                        .cloned()
                        .unwrap_or(Value::Null),
            "frozen expectation metadata"
        );
        let input = t2_fixed_input(&row.input_hex, &row.input_sha256)?;
        let receipt: &[u8; RECEIPT_LEN] = input[160..].try_into()?;
        // Input source remains independently frozen bytes, never the projection.
        ensure!(
            project(&original, epoch, RecoveryObservationV0::Receipt(receipt))? == input,
            "actual structural projection binding"
        );
        let (abi, module_hash) = declared_identity(recipe.id, &entry.actual_module.sha256);
        ensure!(
            entry.declared_abi_sha256 == abi && entry.declared_module_sha256 == module_hash,
            "declared fault identity"
        );
        if is_reused(recipe.id) {
            ensure!(
                entry.actual_module == inventory.c1_ref && entry.wat.is_none(),
                "unchanged C1 identity case"
            );
        } else {
            ensure!(
                entry.actual_module.path == format!("{}.wasm", recipe.id)
                    && entry.actual_module.sha256 != C1_SHA256
                    && new_hashes.insert(entry.actual_module.sha256.clone()),
                "unique new fixture identity"
            );
            ensure!(
                entry.wat.is_some()
                    != matches!(recipe.id, "A01-malformed-magic" | "A02-module-one-over"),
                "exact WAT recipe inventory"
            );
        }
        for reference in std::iter::once(&entry.actual_module).chain(entry.wat.iter()) {
            t2_ref_name(&reference.path)?;
            ensure!(
                !reserved.contains(&reference.path.as_str()),
                "reserved input namespace"
            );
            if let Some(previous) = seen.insert(reference.path.clone(), reference.clone()) {
                ensure!(previous == *reference, "conflicting file reference");
            }
        }
        if let Some(wat) = &entry.wat {
            ensure!(
                wat.path == format!("{}.wat", recipe.id),
                "frozen WAT filename"
            );
            let raw = t2_read_ref(directory, wat, 65536)?;
            std::str::from_utf8(&raw).context("WAT source UTF8")?;
        }
        let bound = if recipe.id == "A02-module-one-over" {
            65537
        } else {
            65536
        };
        let module = t2_read_ref(directory, &entry.actual_module, bound)?;
        if recipe.id == "A02-module-one-over" {
            ensure!(module.len() == 65537, "one-over fixture exact size");
        }
        cases.push(T2LoadedCase {
            id: recipe.id.into(),
            module,
            identity: t2_identity(entry)?,
            input,
            admitted: recipe.expected_fault_admitted,
        });
    }
    ensure!(new_hashes.len() == 30, "thirty unique new fixtures");
    ensure!(canonical_input == cases[0].input, "same canonical input");
    Ok(PreparedT2 {
        plan_sha256: digest(&plan_raw),
        manifest_sha256: manifest.sha256.clone(),
        inventory_sha256: digest(&inventory_raw),
        expected_sha256: digest(&expected_raw),
        c1,
        canonical_input,
        original,
        epoch,
        cases,
    })
}

struct T2BoundedWriter<'a, W: Write> {
    inner: &'a mut W,
    used: usize,
    limit: usize,
}
impl<W: Write> Write for T2BoundedWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self
            .used
            .checked_add(bytes.len())
            .is_none_or(|n| n > self.limit)
        {
            return Err(std::io::Error::other("T2 result byte bound"));
        }
        let count = self.inner.write(bytes)?;
        self.used += count;
        Ok(count)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
fn t2_write_report<W: Write>(writer: &mut W, prepared: &PreparedT2) -> Result<()> {
    let mut output = T2BoundedWriter {
        inner: writer,
        used: 0,
        limit: T2_REPORT_BYTES,
    };
    let header = serde_json::to_vec(&json!({"schema_version":1,"kind":"recovery_q1_t2_raw_v1",
        "plan_sha256":prepared.plan_sha256,"manifest_sha256":prepared.manifest_sha256,
        "fixture_inventory_sha256":prepared.inventory_sha256,"expected_cases_sha256":prepared.expected_sha256,"claims":t2_claims()}))?;
    output.write_all(&header[..header.len() - 1])?;
    output.write_all(b",\"records\":[")?;
    output.flush()?;
    let c1_identity = RecoveryArtifactV0 {
        abi_sha256: RECOVERY_ABI_SHA256,
        module_sha256: super::bytes(&digest(&prepared.c1), 32)?.try_into().unwrap(),
    };
    for (index, case) in prepared.cases.iter().enumerate() {
        if index > 0 {
            output.write_all(b",")?;
        }
        let row = serde_json::to_vec(&json!({"id":case.id}))?;
        output.write_all(&row[..row.len() - 1])?;
        output.write_all(b",\"phases\":[")?;
        let phases: &[&str] = if case.admitted {
            &[
                "fault_raw",
                "fresh_raw",
                "fault_receiving",
                "fresh_receiving",
            ]
        } else {
            &["admission", "fresh_raw", "fresh_receiving"]
        };
        for (n, phase) in phases.iter().enumerate() {
            if n > 0 {
                output.write_all(b",")?;
            }
            // Compute exactly one phase only after the previous actual phase flushed.
            let actual = match *phase {
                "admission" => t2_admission(&case.module, case.identity),
                "fault_raw" => t2_raw(
                    phase,
                    &case.module,
                    case.identity,
                    &t2_initial_memory(&case.input)?,
                )?,
                "fresh_raw" => t2_raw(
                    phase,
                    &prepared.c1,
                    c1_identity,
                    &t2_initial_memory(&prepared.canonical_input)?,
                )?,
                "fault_receiving" => t2_receiving(
                    phase,
                    &case.module,
                    case.identity,
                    &prepared.original,
                    prepared.epoch,
                    &case.input,
                )?,
                "fresh_receiving" => t2_receiving(
                    phase,
                    &prepared.c1,
                    c1_identity,
                    &prepared.original,
                    prepared.epoch,
                    &prepared.canonical_input,
                )?,
                _ => unreachable!(),
            };
            serde_json::to_writer(&mut output, &actual)?;
            output.flush()?;
        }
        output.write_all(b"]}")?;
        output.flush()?;
    }
    output.write_all(b"]}\n")?;
    output.flush()?;
    Ok(())
}
fn t2_run_stage(directory: &Path, result: &Path, manifest: &T2Manifest) -> Result<()> {
    let prepared = t2_load_stage(directory, manifest)?;
    ensure!(result.is_absolute(), "absolute result path");
    private_directory(result.parent().context("private result parent")?)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(result)
        .context("fresh result required")?;
    t2_write_report(&mut output, &prepared)
}
#[test]
#[ignore = "requires separately reviewed T2 manifest/source/executable/platform and explicit coordinator execution release"]
fn run_registered_recovery_t2_faults() {
    // No environment or caller pin can replace this separately reviewed constant.
    let manifest = t2_reviewed_manifest(
        T2_REVIEWED_MANIFEST_SHA256,
        Path::new(&std::env::var_os("RECOVERY_Q1_T2_MANIFEST").unwrap_or_default()),
    )
    .unwrap();
    let stage = std::env::var_os("RECOVERY_Q1_T2_STAGE_DIR").expect("explicit frozen T2 stage");
    let result = std::env::var_os("RECOVERY_Q1_T2_RESULT").expect("explicit fresh T2 result");
    t2_run_stage(Path::new(&stage), Path::new(&result), &manifest).unwrap();
}

fn t2_claims() -> Value {
    json!({"owner_lifecycle_exercised":false,"live_parent_authority_exercised":false,
        "measured_benefit":false,"activation_accepted":false,"full_q1_qualified":false,
        "full_18_receiving_acceptance":false})
}

#[cfg(test)]
mod stage_controls {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    const CONTRACT: &[u8] =
        include_bytes!("../../../docs/contracts/recovery-q1-t2-fixture-contract-v1.json");
    const SCHEMA: &[u8] = include_bytes!("../../../docs/contracts/recovery-q1-t2-schema-v1.json");
    // Static loader controls only; these canonical bytes are never instantiated here.
    const C1_HEX: &str = "0061736d0100000001090160047f7f7f7f017f03020100050401010101071702066d656d6f727902000a7265636f7665725f763000000a8c0a01890a02047e017f200141d00247044041010f0b2003411049044041010f0b200041b0fd034b044041010f0b200241f0ff034b044041010f0b200028000041d79ac9820346047f2000280004410046047f200028000841d00246047f200028000c410449047f4200200029001054047f4200200029001854047f4200200029002054047f4200200029002854047f4200200029003054047f4200200029003854047f4200200029004054047f4200200029004854047f4200200029005054047f42002000290058540541000b0541000b0541000b0541000b0541000b0541000b0541000b0541000b0541000b0541000b0541000b0541000b0541000b047f200028000c410349047f20002900a001420051047f20002900a801420051047f20002900b001420051047f20002900b801420051047f20002900c001420051047f20002900c801420051047f20002900d001420051047f20002900d801420051047f20002900e001420051047f20002900e801420051047f20002900f001420051047f20002900f801420051047f200029008002420051047f200029008802420051047f200029009002420051047f200029009802420051047f20002900a002420051047f20002900a802420051047f20002900b002420051047f20002900b802420051047f20002900c002420051047f20002900c8024200510541000b0541000b0541000b0541000b0541000b0541000b0541000b0541000b0541000b0541000b0541000b0541000b0541000b0541000b0541000b0541000b0541000b0541000b0541000b0541000b0541000b047f200028000c410046047f410005200028000c410146047f41030541040b0b0541040b0520002800a001410146047f20002800a40141b00146047f20002800a801410249047f20002800ac01410046047f420020002900b00154047f420020002900b80154047f420020002900c00154047f420020002900c80154047f420020002900d00154047f420020002900d80154047f420020002900e00154047f420020002900e80154047f420020002900f00154047f420020002900800254047f200029001020002900b00151047f200029001820002900b80151047f200029002020002900c00151047f200029002820002900c80151047f200029003020002900d00151047f200029003820002900d80151047f200029004020002900e00151047f200029004820002900e80151047f200029005020002900f00151047f200029005820002900800251047f200029006020002900900251047f200029006820002900980251047f200029007020002900a00251047f200029007820002900a802510541000b0541000b0541000b047f20002900800120002900b00251047f20002900880120002900b80251047f20002900900120002900c00251047f20002900980120002900c802510541000b0541000b0541000b0541000b0541000b0541000b0541000b0541000b0541000b0541000b0541000b0541000b0541000b0541000b0541000b0541000b0541000b0541000b0541000b0541000b0541000b0541000b0541000b0541000b0541000b0541000b0541000b0541000b047f20002800a801410046047f200029005021044201210520002900f8012106200420057c2107200720045a200720065171047f41010541040b0520002900f801420051047f2000290088024200510541000b047f41020541040b0b0541040b0b0541040b21082002410036000020024110360004200220083600082002410036000c41000b";
    const INPUTS: [(&str, &str); 3] = [
        (
            "outcome-0",
            "574d52300000000050010000030000006500000000000000ca000000000000002f010000000000009401000000000000f9010000000000005e02000000000000c30200000000000028030000000000008d03000000000000f203000000000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff01000000b000000000000000000000006500000000000000ca000000000000002f010000000000009401000000000000f9010000000000005e02000000000000c30200000000000028030000000000008d030000000000008e03000000000000f2030000000000005704000000000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        ),
        (
            "outcome-0-receipt-foreign-operation_id",
            "574d52300000000050010000030000006500000000000000ca000000000000002f010000000000009401000000000000f9010000000000005e02000000000000c30200000000000028030000000000008d03000000000000f203000000000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff01000000b000000000000000000000006500000000000000ca000000000000002f010000000000009401000000000000f9010000000000005e02000000000000c3020000000000002f030000000000008d030000000000008e03000000000000f2030000000000005704000000000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        ),
        (
            "outcome-1-receipt-foreign-original_instance_generation",
            "574d52300000000050010000030000006500000000000000ca000000000000002f010000000000009401000000000000f9010000000000005e02000000000000c30200000000000028030000000000008d03000000000000f203000000000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff01000000b000000001000000000000006500000000000000ca000000000000002f01000000000000940100000000000000020000000000005e02000000000000c30200000000000028030000000000008d030000000000000000000000000000f2030000000000000000000000000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        ),
    ];

    struct Stage {
        root: tempfile::TempDir,
        directory: PathBuf,
        manifest_path: PathBuf,
        manifest: T2Manifest,
    }
    fn write(directory: &Path, name: &str, bytes: &[u8]) {
        write_exclusive(directory, &blob(name.into(), bytes), bytes).unwrap();
    }
    fn fixture() -> Stage {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let directory = root.path().join("stage");
        emit_static(&hex::decode(C1_HEX).unwrap(), &directory).unwrap();
        fs::rename(
            directory.join("inventory.json"),
            directory.join("fixture-inventory.json"),
        )
        .unwrap();
        write(&directory, "schema-v1.json", SCHEMA);
        write(&directory, "fixture-contract-v1.json", CONTRACT);
        let contract: Value = serde_json::from_slice(CONTRACT).unwrap();
        let mut original = contract["common_call"]["receiving_original_fixture"].clone();
        original.as_object_mut().unwrap().retain(|k, _| {
            matches!(
                k.as_str(),
                "actor" | "allocation" | "source" | "original_store_epoch"
            )
        });
        let cases: Vec<Value>=contract["fixtures"].as_array().unwrap().iter().map(|r| {
            json!({"id":r["id"],"input_case":r["input_case"],
                "input_hex":INPUTS.iter().find(|(id,_)|*id==r["input_case"].as_str().unwrap()).unwrap().1,
                "input_sha256":r["input_sha256"],"expected_fault_admitted":r["expected_fault_admitted"],
                "expected_receiving_error":r["expected_receiving_error"],
                "expected_raw_output_hex":r.get("expected_raw_output_hex"),
                "expected_raw_guest_return":r.get("expected_raw_guest_return"),
                "expected_raw_trap_kind":r.get("expected_raw_trap_kind"),
                "expected_receiving_return_code":r.get("expected_receiving_return_code"),
                "expected_disagreement":r.get("expected_disagreement")})
        }).collect();
        let expected = json!({"schema_version":1,"kind":"recovery_q1_t2_expected_cases_v1",
            "recipe_contract_sha256":RECIPE_CONTRACT,"abi_sha256":ABI_SHA256,"corpus_sha256":T2_CORPUS_SHA256,
            "receiving_original":original,"canonical_case":{"id":"outcome-0","input_hex":INPUTS[0].1,
            "input_sha256":digest(&hex::decode(INPUTS[0].1).unwrap())},"cases":cases});
        let raw = serde_json::to_vec(&expected).unwrap();
        write(&directory, "expected-cases.json", &raw);
        let inventory = fs::read(directory.join("fixture-inventory.json")).unwrap();
        let manifest_value = json!({"schema_version":1,"kind":"recovery_q1_t2_manifest_v1",
            "fixture_inventory_sha256":digest(&inventory),"expected_cases_sha256":digest(&raw),
            "schema_sha256":T2_SCHEMA_SHA256,"recipe_contract_sha256":RECIPE_CONTRACT,
            "parent_pins":contract["existing_pins"],"provenance":{"only":"static loader test"}});
        let manifest_raw = serde_json::to_vec(&manifest_value).unwrap();
        let manifest_path = root.path().join("private-manifest.json");
        write(root.path(), "private-manifest.json", &manifest_raw);
        let manifest = T2Manifest {
            sha256: digest(&manifest_raw),
            fixture_inventory_sha256: digest(&inventory),
            expected_cases_sha256: digest(&raw),
            parent_pins: contract["existing_pins"].clone(),
        };
        let mut plan = t2_claims();
        let o = plan.as_object_mut().unwrap();
        o.extend(json!({"schema_version":1,"kind":"recovery_q1_t2_plan_v1","manifest_sha256":manifest.sha256,
            "recipe_contract_sha256":RECIPE_CONTRACT,"fixture_inventory_ref":blob("fixture-inventory.json".into(),&inventory),
            "expected_cases_ref":blob("expected-cases.json".into(),&raw),"abi_sha256":ABI_SHA256,
            "candidate_module_sha256":C1_SHA256,"registration_sha256":T2_REGISTRATION_SHA256}).as_object().unwrap().clone());
        write(&directory, "plan.json", &serde_json::to_vec(&plan).unwrap());
        Stage {
            root,
            directory,
            manifest_path,
            manifest,
        }
    }
    fn rebind(stage: &mut Stage, name: &str, value: &Value) {
        fs::write(
            stage.directory.join(name),
            serde_json::to_vec(value).unwrap(),
        )
        .unwrap();
        let inventory = fs::read(stage.directory.join("fixture-inventory.json")).unwrap();
        let expected = fs::read(stage.directory.join("expected-cases.json")).unwrap();
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(&stage.manifest_path).unwrap()).unwrap();
        manifest["fixture_inventory_sha256"] = json!(digest(&inventory));
        manifest["expected_cases_sha256"] = json!(digest(&expected));
        let raw = serde_json::to_vec(&manifest).unwrap();
        fs::write(&stage.manifest_path, &raw).unwrap();
        stage.manifest = t2_reviewed_manifest(Some(&digest(&raw)), &stage.manifest_path).unwrap();
        let mut plan: Value =
            serde_json::from_slice(&fs::read(stage.directory.join("plan.json")).unwrap()).unwrap();
        plan["manifest_sha256"] = json!(stage.manifest.sha256);
        plan["fixture_inventory_ref"] = json!(blob("fixture-inventory.json".into(), &inventory));
        plan["expected_cases_ref"] = json!(blob("expected-cases.json".into(), &expected));
        fs::write(
            stage.directory.join("plan.json"),
            serde_json::to_vec(&plan).unwrap(),
        )
        .unwrap();
    }
    #[test]
    fn t2_static_loader_requires_explicit_null_keys_after_actual_pins_match() {
        for (name, key) in [
            ("fixture-inventory.json", "wat"),
            ("fixture-inventory.json", "qualified_new_binary_sha256"),
            ("expected-cases.json", "expected_raw_guest_return"),
            ("expected-cases.json", "expected_disagreement"),
        ] {
            let mut stage = fixture();
            let mut value: Value =
                serde_json::from_slice(&fs::read(stage.directory.join(name)).unwrap()).unwrap();
            value["cases"][0].as_object_mut().unwrap().remove(key);
            rebind(&mut stage, name, &value);
            assert!(
                t2_load_stage(&stage.directory, &stage.manifest).is_err(),
                "missing {key} was accepted"
            );
        }
    }
    fn synthetic_prepared() -> PreparedT2 {
        let original = runtime_controls::original();
        let input = runtime_controls::input(&original);
        let module = runtime_controls::synthetic(&(stores([0, 16, 1, 0]) + "i32.const 7"));
        PreparedT2 {
            plan_sha256: "11".repeat(32),
            manifest_sha256: "22".repeat(32),
            inventory_sha256: "33".repeat(32),
            expected_sha256: "44".repeat(32),
            c1: runtime_controls::success(),
            canonical_input: input,
            original,
            epoch: 17,
            cases: vec![T2LoadedCase {
                id: "private-synthetic-return7".into(),
                identity: runtime_controls::identity(&module),
                module,
                input,
                admitted: true,
            }],
        }
    }
    #[test]
    fn t2_strict_stage_json_rejects_duplicate_keys_and_boolean_integer() {
        let value: Value = t2_json(br#"{"a":1}"#).unwrap();
        assert_eq!(value["a"], 1);
        assert!(t2_json::<Value>(br#"{"a":1,"a":2}"#).is_err());
        assert!(t2_json::<Value>(br#"{"nested":{"a":1,"a":2}}"#).is_err());
        assert!(t2_json::<Value>(br#"{"x":"\ud800"}"#).is_err());
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Integer {
            n: u32,
        }
        assert!(t2_json::<Integer>(br#"{"n":true}"#).is_err());
        assert!(t2_json::<Integer>(br#"{"n":1.0}"#).is_err());
        assert_eq!(t2_json::<Integer>(br#"{"n":1}"#).unwrap().n, 1);
    }
    #[test]
    fn t2_manifest_hold_precedes_paths_and_static_loader_has_no_engine_calls() {
        let error = t2_reviewed_manifest(None, Path::new("/nonexistent/not-read"))
            .err()
            .unwrap();
        assert!(error.to_string().contains("reviewed T2 manifest pending"));
        let stage = fixture();
        let manifest =
            t2_reviewed_manifest(Some(&stage.manifest.sha256), &stage.manifest_path).unwrap();
        let prepared = t2_load_stage(&stage.directory, &manifest).unwrap();
        assert_eq!(prepared.cases.len(), 32);
        assert_eq!(prepared.c1.len(), 1349);
        assert_eq!(prepared.cases.iter().filter(|r| r.admitted).count(), 11);
        assert_eq!(
            prepared.canonical_input,
            hex::decode(INPUTS[0].1).unwrap().as_slice()
        );
        assert!(!stage.root.path().join("raw.json").exists());
    }
    #[test]
    fn t2_synthetic_stream_preserves_actual_four_phases_without_pass_annotation() {
        let mut raw = Vec::new();
        t2_write_report(&mut raw, &synthetic_prepared()).unwrap();
        let value: Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(value["kind"], "recovery_q1_t2_raw_v1");
        assert_eq!(
            value["records"][0]["phases"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| p["phase"].as_str().unwrap())
                .collect::<Vec<_>>(),
            [
                "fault_raw",
                "fresh_raw",
                "fault_receiving",
                "fresh_receiving"
            ]
        );
        assert_eq!(
            value["records"][0]["phases"][2]["result"]["error"]["code"],
            7
        );
        assert_eq!(
            value["records"][0]["phases"][3]["result"]["disposition"],
            "Committed"
        );
        assert!(value.get("PASS").is_none());
        assert!(value.get("complete").is_none());
    }
    #[test]
    fn t2_loader_rejects_roles_input_metadata_and_paths_before_output_then_fresh_loads() {
        for mutation in [
            "plan_scope",
            "input_bytes",
            "reserved_module",
            "over_module",
            "schema_bytes",
            "wat_missing",
        ] {
            let mut stage = fixture();
            match mutation {
                "plan_scope" => {
                    let mut value: Value = serde_json::from_slice(
                        &fs::read(stage.directory.join("plan.json")).unwrap(),
                    )
                    .unwrap();
                    value["activation_accepted"] = true.into();
                    fs::write(
                        stage.directory.join("plan.json"),
                        serde_json::to_vec(&value).unwrap(),
                    )
                    .unwrap();
                }
                "input_bytes" => {
                    let mut value: Value = serde_json::from_slice(
                        &fs::read(stage.directory.join("expected-cases.json")).unwrap(),
                    )
                    .unwrap();
                    value["cases"][0]["input_hex"] = json!("00".repeat(336));
                    rebind(&mut stage, "expected-cases.json", &value);
                }
                "schema_bytes" => {
                    fs::write(stage.directory.join("schema-v1.json"), b"wrong").unwrap();
                }
                _ => {
                    let mut value: Value = serde_json::from_slice(
                        &fs::read(stage.directory.join("fixture-inventory.json")).unwrap(),
                    )
                    .unwrap();
                    if mutation == "reserved_module" {
                        value["cases"][0]["actual_module"]["path"] = json!("plan.json");
                    }
                    if mutation == "wat_missing" {
                        value["cases"][4]["wat"] = Value::Null;
                    }
                    if mutation == "over_module" {
                        let bytes = vec![b'x'; 65537];
                        let name = value["cases"][23]["actual_module"]["path"]
                            .as_str()
                            .unwrap()
                            .to_owned();
                        fs::write(stage.directory.join(&name), &bytes).unwrap();
                        value["cases"][23]["actual_module"] = json!(blob(name, &bytes));
                        value["cases"][23]["declared_module_sha256"] = json!(digest(&bytes));
                    }
                    rebind(&mut stage, "fixture-inventory.json", &value);
                }
            }
            let result = stage.root.path().join("not-created.json");
            assert!(
                t2_run_stage(&stage.directory, &result, &stage.manifest).is_err(),
                "{mutation}"
            );
            assert!(!result.exists(), "before output {mutation}");
        }
        let fresh = fixture();
        assert_eq!(
            t2_load_stage(&fresh.directory, &fresh.manifest)
                .unwrap()
                .cases
                .len(),
            32
        );
        let mut raw = Vec::new();
        t2_write_report(&mut raw, &synthetic_prepared()).unwrap();
        let value: Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(
            value["records"][0]["phases"][3]["result"]["disposition"],
            "Committed"
        );
    }
    #[test]
    fn t2_stage_hardlinks_symlinks_and_output_collision_refuse_without_repair() {
        for hard in [true, false] {
            let stage = fixture();
            let file = stage.directory.join("A01-malformed-magic.wasm");
            let copy = stage.root.path().join("copy.wasm");
            fs::copy(&file, &copy).unwrap();
            fs::remove_file(&file).unwrap();
            if hard {
                fs::hard_link(&copy, &file).unwrap();
            } else {
                std::os::unix::fs::symlink(&copy, &file).unwrap();
            }
            assert!(t2_load_stage(&stage.directory, &stage.manifest).is_err());
        }
        let stage = fixture();
        let output = stage.root.path().join("existing.json");
        write(stage.root.path(), "existing.json", b"retained");
        let error = t2_run_stage(&stage.directory, &output, &stage.manifest).unwrap_err();
        assert!(error.to_string().contains("fresh result"), "{error:#}");
        assert_eq!(fs::read(&output).unwrap(), b"retained");
        let mut next = Vec::new();
        t2_write_report(&mut next, &synthetic_prepared()).unwrap();
        assert!(serde_json::from_slice::<Value>(&next).is_ok());
    }
    #[test]
    fn t2_manifest_parent_hashes_provenance_and_size_are_closed() {
        let stage = fixture();
        let mut value: Value =
            serde_json::from_slice(&fs::read(&stage.manifest_path).unwrap()).unwrap();
        value["provenance"] = json!({"opaque_path":"/nonexistent/never-read","elapsed":0.5});
        let raw = serde_json::to_vec(&value).unwrap();
        fs::write(&stage.manifest_path, &raw).unwrap();
        assert!(t2_reviewed_manifest(Some(&digest(&raw)), &stage.manifest_path).is_ok());
        for field in ["schema_sha256", "recipe_contract_sha256"] {
            let mut invalid = value.clone();
            invalid[field] = json!("00".repeat(32));
            let raw = serde_json::to_vec(&invalid).unwrap();
            fs::write(&stage.manifest_path, &raw).unwrap();
            assert!(t2_reviewed_manifest(Some(&digest(&raw)), &stage.manifest_path).is_err());
        }
        value["parent_pins"]["closeout"] = json!("00".repeat(32));
        let raw = serde_json::to_vec(&value).unwrap();
        fs::write(&stage.manifest_path, &raw).unwrap();
        assert!(t2_reviewed_manifest(Some(&digest(&raw)), &stage.manifest_path).is_err());
        let raw = vec![b'x'; 32769];
        fs::write(&stage.manifest_path, &raw).unwrap();
        assert!(t2_reviewed_manifest(Some(&digest(&raw)), &stage.manifest_path).is_err());
        assert!(
            t2_reviewed_manifest(None, &stage.manifest_path)
                .err()
                .unwrap()
                .to_string()
                .contains("pending")
        );
    }
    #[test]
    fn t2_synthetic_unexpected_new_outcomes_still_record_the_next_success() {
        let mut prepared = synthetic_prepared();
        prepared.cases[0].module = runtime_controls::synthetic("unreachable");
        prepared.cases[0].identity = runtime_controls::identity(&prepared.cases[0].module);
        prepared.cases[0].admitted = false;
        let mut raw = Vec::new();
        t2_write_report(&mut raw, &prepared).unwrap();
        let value: Value = serde_json::from_slice(&raw).unwrap();
        let phases = value["records"][0]["phases"].as_array().unwrap();
        assert_eq!(phases.len(), 3);
        assert_eq!(phases[0]["result"]["status"], "accepted");
        assert!(phases[0]["raw"].is_null());
        assert_eq!(phases[2]["result"]["disposition"], "Committed");
        prepared.cases[0].module = b"bad wasm".to_vec();
        prepared.cases[0].identity = runtime_controls::identity(&prepared.cases[0].module);
        prepared.cases[0].admitted = true;
        let mut raw = Vec::new();
        t2_write_report(&mut raw, &prepared).unwrap();
        let value: Value = serde_json::from_slice(&raw).unwrap();
        let phases = value["records"][0]["phases"].as_array().unwrap();
        assert_eq!(phases.len(), 4);
        assert_eq!(phases[0]["admission"]["error"]["kind"], "module_shape");
        assert!(phases[0]["observation"].is_null());
        assert_eq!(phases[2]["stage"], "new");
        assert!(phases[2]["projection_error"].is_null());
        assert_eq!(phases[3]["result"]["disposition"], "Committed");
    }
    #[test]
    fn t2_synthetic_flush_interruption_and_bounded_growth_preserve_prefix_then_fresh_success() {
        struct FailFlush {
            bytes: Vec<u8>,
            flushes: usize,
        }
        impl Write for FailFlush {
            fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                self.bytes.extend_from_slice(data);
                Ok(data.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.flushes += 1;
                if self.flushes == 2 {
                    Err(std::io::Error::other("private interrupt"))
                } else {
                    Ok(())
                }
            }
        }
        let mut writer = FailFlush {
            bytes: vec![],
            flushes: 0,
        };
        assert!(t2_write_report(&mut writer, &synthetic_prepared()).is_err());
        let prefix = String::from_utf8(writer.bytes).unwrap();
        assert!(prefix.contains("\"guest_return\":7"));
        assert!(!prefix.contains("\"phase\":\"fresh_raw\""));
        assert!(serde_json::from_str::<Value>(&prefix).is_err());
        let mut retained = Vec::new();
        let mut bounded = T2BoundedWriter {
            inner: &mut retained,
            used: 0,
            limit: 4,
        };
        assert!(bounded.write_all(b"12345").is_err());
        assert_eq!(bounded.used, 0);
        assert!(retained.is_empty());
        let mut fresh = Vec::new();
        t2_write_report(&mut fresh, &synthetic_prepared()).unwrap();
        let value: Value = serde_json::from_slice(&fresh).unwrap();
        assert_eq!(
            value["records"][0]["phases"][3]["result"]["disposition"],
            "Committed"
        );
    }
}
