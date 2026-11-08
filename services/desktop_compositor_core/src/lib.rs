//! Fixed, allocation-free application-region placement.
//!
//! This component authenticates no frame or caller and never publishes pixels.
#![no_std]
#![forbid(unsafe_code)]

pub const WIDTH: usize = 640;
pub const APP_HEIGHT: usize = 480;
pub const OUTPUT_HEIGHT: usize = 568;
pub const BYTES_PER_PIXEL: usize = 4;
pub const APP_BYTES: usize = WIDTH * APP_HEIGHT * BYTES_PER_PIXEL;
pub const DESTINATION_BYTES: usize = WIDTH * OUTPUT_HEIGHT * BYTES_PER_PIXEL;
pub const APP_OFFSET: usize = WIDTH * 48 * BYTES_PER_PIXEL;
const APP_END: usize = APP_OFFSET + APP_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlacementError {
    DestinationLength,
    SourceLength,
}

/// Place one complete BGRA app frame into the caller-owned composed buffer.
///
/// The whole destination is left unchanged when either supplied length is
/// invalid; the protected chrome regions are unchanged on success as well.
pub fn place_app(source: Option<&[u8]>, destination: &mut [u8]) -> Result<(), PlacementError> {
    if destination.len() != DESTINATION_BYTES {
        return Err(PlacementError::DestinationLength);
    }
    if source.is_some_and(|bytes| bytes.len() != APP_BYTES) {
        return Err(PlacementError::SourceLength);
    }
    let region = &mut destination[APP_OFFSET..APP_END];
    if let Some(bytes) = source {
        region.copy_from_slice(bytes);
    } else {
        region.fill(0xff);
    }
    Ok(())
}
