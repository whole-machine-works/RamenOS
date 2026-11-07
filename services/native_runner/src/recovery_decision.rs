//! Host-only Save recovery comparison for the fixed recovery-decision v0 ABI.
//!
//! A returned disposition is advisory. The caller keeps the authorized lookup,
//! the original operation and its leases, and all terminal effects.

use artifact_store_schema::editor_save::{
    EditorReceiptOutcomeV0, EditorSaveBindingV0, EditorSaveReceiptV0, RECEIPT_LEN,
};
use sha2::{Digest, Sha256};
use wasmtime::{Config, Engine, Instance, Module, Store, Strategy, Trap};

const RECOVERY_ABI_SHA256: [u8; 32] = [
    0x49, 0xda, 0xf5, 0x2d, 0xd6, 0x69, 0x41, 0x13, 0x76, 0x77, 0x0b, 0x3b, 0xc2, 0xa0, 0x07, 0xd7,
    0xc6, 0xa8, 0xb3, 0x46, 0x84, 0x3b, 0xcd, 0x12, 0x3a, 0x45, 0xda, 0x81, 0x39, 0xb0, 0xda, 0x60,
];
const MAX_MODULE_BYTES: usize = 64 * 1024;
const MAX_FUEL: u64 = 100_000;
const MAX_WASM_STACK: usize = 32 * 1024;
const INPUT: usize = 4096;
const OUTPUT: usize = 4448;
const INPUT_LEN: usize = 336;
const OUTPUT_LEN: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryArtifactV0 {
    /// The independently reviewed contract digest.
    pub abi_sha256: [u8; 32],
    /// The independently reviewed artifact digest supplied by the trusted caller.
    pub module_sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug)]
pub enum RecoveryObservationV0<'a> {
    Pending,
    Denied,
    Invalid,
    Receipt(&'a [u8; RECEIPT_LEN]),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum RecoveryDispositionV0 {
    Pending = 0,
    Committed = 1,
    DefinitiveNoncommit = 2,
    Denied = 3,
    Invalid = 4,
}

#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    #[error("recovery artifact or ABI identity differs from the reviewed identity")]
    ArtifactIdentity,
    #[error("recovery module does not match the bounded v0 envelope")]
    ModuleShape,
    #[error("recovery engine admission or setup failed: {0}")]
    Engine(#[source] anyhow::Error),
    #[error("invalid original Save binding or Store epoch")]
    InvalidOriginal,
    #[error("recovery call exhausted fuel")]
    Fuel,
    #[error("recovery call reached the configured Wasm stack limit")]
    Stack,
    #[error("recovery call trapped: {0}")]
    Trap(#[source] anyhow::Error),
    #[error("recovery call returned {0}")]
    Return(i32),
    #[error("recovery output does not match the v0 wire format")]
    Output,
    #[error("recovery result {candidate:?} disagrees with the Rust check {expected:?}")]
    Disagreement {
        candidate: RecoveryDispositionV0,
        expected: RecoveryDispositionV0,
    },
}

/// A validated module. Every call creates its own Store, instance and memory.
pub struct RecoveryDecisionAdapter {
    engine: Engine,
    module: Module,
}

impl RecoveryDecisionAdapter {
    pub fn new(module: &[u8], identity: RecoveryArtifactV0) -> Result<Self, RecoveryError> {
        if module.len() > MAX_MODULE_BYTES {
            return Err(RecoveryError::ModuleShape);
        }
        let actual: [u8; 32] = Sha256::digest(module).into();
        if identity.abi_sha256 != RECOVERY_ABI_SHA256 || identity.module_sha256 != actual {
            return Err(RecoveryError::ArtifactIdentity);
        }
        validate_shape(module).ok_or(RecoveryError::ModuleShape)?;

        let mut config = Config::new();
        config
            .strategy(Strategy::Cranelift)
            .consume_fuel(true)
            .max_wasm_stack(MAX_WASM_STACK)
            .wasm_threads(false);
        let engine = Engine::new(&config).map_err(RecoveryError::Engine)?;
        let module = Module::from_binary(&engine, module).map_err(RecoveryError::Engine)?;
        Ok(Self { engine, module })
    }

    /// Compare the candidate with Rust for one retained original Save.
    ///
    /// The caller still verifies current authorization, reply identity and live
    /// ownership before applying a terminal outcome.
    pub fn decide(
        &self,
        original: &EditorSaveBindingV0,
        original_store_epoch: u64,
        observation: RecoveryObservationV0<'_>,
    ) -> Result<RecoveryDispositionV0, RecoveryError> {
        let input = project(original, original_store_epoch, observation)?;
        let candidate = self.call(&input)?;
        let expected = reference(original, original_store_epoch, observation);
        if candidate != expected {
            return Err(RecoveryError::Disagreement {
                candidate,
                expected,
            });
        }
        Ok(candidate)
    }

    fn call(&self, input: &[u8; INPUT_LEN]) -> Result<RecoveryDispositionV0, RecoveryError> {
        decode_output(self.invoke(input)?)
    }

    fn invoke(&self, input: &[u8; INPUT_LEN]) -> Result<[u8; OUTPUT_LEN], RecoveryError> {
        let mut store = Store::new(&self.engine, ());
        store.set_fuel(MAX_FUEL).map_err(RecoveryError::Engine)?;
        let instance =
            Instance::new(&mut store, &self.module, &[]).map_err(RecoveryError::Engine)?;
        let recover = instance
            .get_typed_func::<(i32, i32, i32, i32), i32>(&mut store, "recover_v0")
            .map_err(RecoveryError::Engine)?;
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or(RecoveryError::ModuleShape)?;
        let mut output = [0; OUTPUT_LEN];
        memory
            .write(&mut store, INPUT, input)
            .map_err(|error| RecoveryError::Engine(error.into()))?;
        memory
            .write(&mut store, OUTPUT, &output)
            .map_err(|error| RecoveryError::Engine(error.into()))?;
        let status = recover
            .call(
                &mut store,
                (
                    INPUT as i32,
                    INPUT_LEN as i32,
                    OUTPUT as i32,
                    OUTPUT_LEN as i32,
                ),
            )
            .map_err(|error| match error.downcast_ref::<Trap>() {
                Some(Trap::OutOfFuel) => RecoveryError::Fuel,
                Some(Trap::StackOverflow) => RecoveryError::Stack,
                _ => RecoveryError::Trap(error),
            })?;
        if status != 0 {
            return Err(RecoveryError::Return(status));
        }
        memory
            .read(&store, OUTPUT, &mut output)
            .map_err(|error| RecoveryError::Engine(error.into()))?;
        Ok(output)
    }
}

fn project(
    original: &EditorSaveBindingV0,
    epoch: u64,
    observation: RecoveryObservationV0<'_>,
) -> Result<[u8; INPUT_LEN], RecoveryError> {
    original
        .validate()
        .map_err(|_| RecoveryError::InvalidOriginal)?;
    if epoch == 0 {
        return Err(RecoveryError::InvalidOriginal);
    }
    let allocation = &original.allocation;
    let actor = &allocation.actor;
    let mut bytes = [0; INPUT_LEN];
    bytes[..4].copy_from_slice(b"WMR0");
    bytes[8..12].copy_from_slice(&(INPUT_LEN as u32).to_le_bytes());
    bytes[12] = match observation {
        RecoveryObservationV0::Pending => 0,
        RecoveryObservationV0::Denied => 1,
        RecoveryObservationV0::Invalid => 2,
        RecoveryObservationV0::Receipt(receipt) => {
            bytes[160..].copy_from_slice(receipt);
            3
        }
    };
    let fields = [
        actor.owner_id,
        actor.session_id,
        actor.session_generation,
        actor.instance_id,
        actor.instance_generation,
        allocation.selected_object_id,
        allocation.selected_generation,
        allocation.operation_id,
        allocation.expected_revision,
        epoch,
    ];
    for (chunk, value) in bytes[16..96].chunks_exact_mut(8).zip(fields) {
        chunk.copy_from_slice(&value.to_le_bytes());
    }
    bytes[96..128].copy_from_slice(&allocation.expected_content_hash);
    bytes[128..160].copy_from_slice(&original.source.content_hash);
    Ok(bytes)
}

fn reference(
    original: &EditorSaveBindingV0,
    epoch: u64,
    observation: RecoveryObservationV0<'_>,
) -> RecoveryDispositionV0 {
    match observation {
        RecoveryObservationV0::Pending => RecoveryDispositionV0::Pending,
        RecoveryObservationV0::Denied => RecoveryDispositionV0::Denied,
        RecoveryObservationV0::Invalid => RecoveryDispositionV0::Invalid,
        RecoveryObservationV0::Receipt(bytes) => {
            let Ok(receipt) = EditorSaveReceiptV0::decode_le(bytes) else {
                return RecoveryDispositionV0::Invalid;
            };
            if receipt.backend_service_epoch != epoch || receipt.validate_binding(original).is_err()
            {
                return RecoveryDispositionV0::Invalid;
            }
            match receipt.outcome {
                EditorReceiptOutcomeV0::Committed => RecoveryDispositionV0::Committed,
                EditorReceiptOutcomeV0::DefinitiveNoncommit => {
                    RecoveryDispositionV0::DefinitiveNoncommit
                }
            }
        }
    }
}

fn decode_output(bytes: [u8; OUTPUT_LEN]) -> Result<RecoveryDispositionV0, RecoveryError> {
    if bytes[..8] != [0, 0, 0, 0, 16, 0, 0, 0] || bytes[9..] != [0; 7] {
        return Err(RecoveryError::Output);
    }
    match bytes[8] {
        0 => Ok(RecoveryDispositionV0::Pending),
        1 => Ok(RecoveryDispositionV0::Committed),
        2 => Ok(RecoveryDispositionV0::DefinitiveNoncommit),
        3 => Ok(RecoveryDispositionV0::Denied),
        4 => Ok(RecoveryDispositionV0::Invalid),
        _ => Err(RecoveryError::Output),
    }
}

fn validate_shape(module: &[u8]) -> Option<()> {
    let mut tail = module.strip_prefix(b"\0asm\x01\0\0\0")?;
    for (id, expected) in [
        (1, &[1, 0x60, 4, 0x7f, 0x7f, 0x7f, 0x7f, 1, 0x7f][..]),
        (3, &[1, 0][..]),
        (5, &[1, 1, 1, 1][..]),
        (7, b"\x02\x06memory\x02\0\x0arecover_v0\0\0"),
    ] {
        let (payload, rest) = section(tail, id)?;
        if payload != expected {
            return None;
        }
        tail = rest;
    }
    let (code, rest) = section(tail, 10)?;
    let (body_length, body) = uleb32(code.strip_prefix(&[1])?)?;
    // The engine validates the complete instruction stream and its types.
    (rest.is_empty() && !body.is_empty() && body.len() == body_length as usize).then_some(())
}

fn section(bytes: &[u8], id: u8) -> Option<(&[u8], &[u8])> {
    let (length, payload) = uleb32(bytes.strip_prefix(&[id])?)?;
    payload.split_at_checked(length as usize)
}

fn uleb32(bytes: &[u8]) -> Option<(u32, &[u8])> {
    let mut value = 0;
    for (index, &byte) in bytes.iter().take(5).enumerate() {
        if index == 4 && byte > 0x0f {
            return None;
        }
        value |= u32::from(byte & 0x7f) << (7 * index);
        if byte < 0x80 {
            return (index == 0 || byte != 0).then_some((value, &bytes[index + 1..]));
        }
    }
    None
}

#[cfg(test)]
#[path = "recovery_decision_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "recovery_q1_tests.rs"]
mod q1_tests;
