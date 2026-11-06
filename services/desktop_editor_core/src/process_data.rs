//! Pure bounded bytes shared by the process child and its validating parent.
//!
//! Parsing, hashes and copied state grant no document, process, mapping or Save
//! authority. Actual FD identity, seals, lineage and current authority belong to
//! the carrier. The embedded Text64 length excludes the extra state header.
use crate::{EditorModel, EditorSnapshot, FRAME_BYTES, FontRows, TEXT_LIMIT};
use sha2::{Digest, Sha256};

pub const TEXT_HEADER_BYTES: usize = 64;
pub const STATE_HEADER_BYTES: usize = 128;
pub const FONT_BYTES: &[u8; 1536] = include_bytes!("../tests/fixtures/ascii8x16_v0.bin");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataError {
    Length,
    Version,
    Reserved,
    Identity,
    Ascii,
    Hash,
    State,
    Surface,
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn frozen_font() -> FontRows {
    std::array::from_fn(|index| {
        let mut rows = [0; 16];
        rows.copy_from_slice(&FONT_BYTES[index * 16..(index + 1) * 16]);
        rows
    })
}

fn body(bytes: &[u8]) -> Result<(), DataError> {
    crate::validate_body(bytes).map_err(|error| match error {
        crate::EditError::BodyTooLong => DataError::Length,
        _ => DataError::Ascii,
    })
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

// Calls use fixed offsets only after an exact minimum header length check.
fn get32(bytes: &[u8], offset: usize) -> u32 {
    let mut value = [0; 4];
    value.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(value)
}

fn get64(bytes: &[u8], offset: usize) -> u64 {
    let mut value = [0; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(value)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TextHeader {
    pub selected_object_id: u64,
    pub revision: u64,
    pub content_hash: [u8; 32],
    pub byte_len: u32,
}

impl TextHeader {
    pub fn new(selected_object_id: u64, revision: u64, bytes: &[u8]) -> Result<Self, DataError> {
        body(bytes)?;
        let header = Self {
            selected_object_id,
            revision,
            content_hash: sha256(bytes),
            byte_len: bytes.len() as u32,
        };
        header.validate()?;
        Ok(header)
    }

    fn validate(&self) -> Result<(), DataError> {
        if self.selected_object_id == 0 || self.revision == 0 {
            return Err(DataError::Identity);
        }
        if self.byte_len as usize > TEXT_LIMIT {
            return Err(DataError::Length);
        }
        Ok(())
    }

    pub fn validate_body(&self, bytes: &[u8]) -> Result<(), DataError> {
        self.validate()?;
        body(bytes)?;
        if bytes.len() != self.byte_len as usize {
            return Err(DataError::Length);
        }
        if sha256(bytes) != self.content_hash {
            return Err(DataError::Hash);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<[u8; TEXT_HEADER_BYTES], DataError> {
        self.validate()?;
        let mut bytes = [0; TEXT_HEADER_BYTES];
        put32(&mut bytes, 0, 1);
        put32(&mut bytes, 4, TEXT_HEADER_BYTES as u32 + self.byte_len);
        put64(&mut bytes, 8, self.selected_object_id);
        put64(&mut bytes, 16, self.revision);
        bytes[24..56].copy_from_slice(&self.content_hash);
        put32(&mut bytes, 56, self.byte_len);
        // Reserved bytes 60..64 remain zero.
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DataError> {
        if bytes.len() != TEXT_HEADER_BYTES {
            return Err(DataError::Length);
        }
        if get32(bytes, 0) != 1 {
            return Err(DataError::Version);
        }
        if get32(bytes, 60) != 0 {
            return Err(DataError::Reserved);
        }
        let mut content_hash = [0; 32];
        content_hash.copy_from_slice(&bytes[24..56]);
        let header = Self {
            selected_object_id: get64(bytes, 8),
            revision: get64(bytes, 16),
            content_hash,
            byte_len: get32(bytes, 56),
        };
        header.validate()?;
        if get32(bytes, 4) != TEXT_HEADER_BYTES as u32 + header.byte_len {
            return Err(DataError::Length);
        }
        Ok(header)
    }
}

pub fn encode_text64(object: u64, revision: u64, bytes: &[u8]) -> Result<Vec<u8>, DataError> {
    let header = TextHeader::new(object, revision, bytes)?;
    let mut output = Vec::with_capacity(TEXT_HEADER_BYTES + bytes.len());
    output.extend_from_slice(&header.encode()?);
    output.extend_from_slice(bytes);
    Ok(output)
}

pub fn decode_text64(bytes: &[u8]) -> Result<(TextHeader, &[u8]), DataError> {
    if !(TEXT_HEADER_BYTES..=TEXT_HEADER_BYTES + TEXT_LIMIT).contains(&bytes.len()) {
        return Err(DataError::Length);
    }
    let header = TextHeader::decode(&bytes[..TEXT_HEADER_BYTES])?;
    let body = &bytes[TEXT_HEADER_BYTES..];
    header.validate_body(body)?;
    Ok((header, body))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TextState {
    pub header: TextHeader,
    pub cursor: u32,
    pub selection: Option<(u32, u32)>,
    pub first_visible_line: u32,
    pub text_generation: u64,
    pub view_generation: u64,
    pub surface_sha256: [u8; 32],
}

impl TextState {
    pub fn validate_body(&self, bytes: &[u8]) -> Result<(), DataError> {
        self.header.validate_body(bytes)?;
        let length = bytes.len() as u32;
        if self.cursor > length
            || self.text_generation == 0
            || self.view_generation == 0
            || self.first_visible_line > length
            || self
                .selection
                .is_some_and(|(start, end)| start > end || end > length)
        {
            return Err(DataError::State);
        }
        // Reuse the core's actual tab/wrap/newline inventory rather than a
        // second line-count algorithm. Neutral cursor/selection avoid adding
        // a cursor-at-selection-end requirement absent from the wire contract.
        EditorModel::from_snapshot(EditorSnapshot {
            bytes: bytes.to_vec(),
            cursor: 0,
            selection: None,
            first_visible_line: self.first_visible_line as usize,
            selection_anchor: None,
            preferred_column: None,
            text_generation: self.text_generation,
        })
        .map_err(|_| DataError::State)?;
        Ok(())
    }

    pub fn validate_surface(&self, pixels: &[u8]) -> Result<(), DataError> {
        if pixels.len() != FRAME_BYTES {
            return Err(DataError::Length);
        }
        if pixels.chunks_exact(4).any(|pixel| pixel[3] != 255) {
            return Err(DataError::Surface);
        }
        if sha256(pixels) != self.surface_sha256 {
            return Err(DataError::Hash);
        }
        Ok(())
    }

    pub fn encode(&self, body: &[u8]) -> Result<Vec<u8>, DataError> {
        self.validate_body(body)?;
        let mut output = vec![0; STATE_HEADER_BYTES + body.len()];
        output[..TEXT_HEADER_BYTES].copy_from_slice(&self.header.encode()?);
        put32(&mut output, 64, self.cursor);
        let (start, end) = self.selection.unwrap_or((u32::MAX, u32::MAX));
        put32(&mut output, 68, start);
        put32(&mut output, 72, end);
        put32(&mut output, 76, self.first_visible_line);
        put64(&mut output, 80, self.text_generation);
        put64(&mut output, 88, self.view_generation);
        output[96..128].copy_from_slice(&self.surface_sha256);
        output[STATE_HEADER_BYTES..].copy_from_slice(body);
        Ok(output)
    }

    pub fn decode(bytes: &[u8]) -> Result<(Self, &[u8]), DataError> {
        if !(STATE_HEADER_BYTES..=STATE_HEADER_BYTES + TEXT_LIMIT).contains(&bytes.len()) {
            return Err(DataError::Length);
        }
        let start = get32(bytes, 68);
        let end = get32(bytes, 72);
        let selection = match (start, end) {
            (u32::MAX, u32::MAX) => None,
            (u32::MAX, _) | (_, u32::MAX) => return Err(DataError::State),
            pair => Some(pair),
        };
        let mut surface_sha256 = [0; 32];
        surface_sha256.copy_from_slice(&bytes[96..128]);
        let state = Self {
            header: TextHeader::decode(&bytes[..TEXT_HEADER_BYTES])?,
            cursor: get32(bytes, 64),
            selection,
            first_visible_line: get32(bytes, 76),
            text_generation: get64(bytes, 80),
            view_generation: get64(bytes, 88),
            surface_sha256,
        };
        let body = &bytes[STATE_HEADER_BYTES..];
        state.validate_body(body)?;
        Ok((state, body))
    }
}
