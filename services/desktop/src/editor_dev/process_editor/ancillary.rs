//! Pure bounded Linux ancillary grammar. The native receiver uses this same
//! validator; structural assertion records never pretend to be recvmsg calls.
use crate::dev::Status;

pub(super) fn validate(bytes: &[u8]) -> Result<(), Status> {
    if bytes.len() > 256 {
        return Err(Status::Invalid);
    }
    let width = std::mem::size_of::<usize>();
    let header = width + 8;
    let mut offset = 0usize;
    let mut credentials = 0usize;
    let mut rights = 0usize;
    while offset < bytes.len() {
        if bytes.len() - offset < header {
            return Err(Status::Invalid);
        }
        let length = usize::from_ne_bytes(
            bytes[offset..offset + width]
                .try_into()
                .map_err(|_| Status::Invalid)?,
        );
        let level = i32::from_ne_bytes(
            bytes[offset + width..offset + width + 4]
                .try_into()
                .map_err(|_| Status::Invalid)?,
        );
        let kind = i32::from_ne_bytes(
            bytes[offset + width + 4..offset + header]
                .try_into()
                .map_err(|_| Status::Invalid)?,
        );
        if length < header || length > bytes.len() - offset || level != libc::SOL_SOCKET {
            return Err(Status::Invalid);
        }
        let payload = length - header;
        match kind {
            libc::SCM_CREDENTIALS => {
                credentials += 1;
                if credentials != 1 || payload != std::mem::size_of::<libc::ucred>() {
                    return Err(Status::Invalid);
                }
            }
            libc::SCM_RIGHTS => {
                rights += 1;
                if rights != 1 || payload == 0 || !payload.is_multiple_of(4) || payload / 4 > 4 {
                    return Err(Status::Invalid);
                }
            }
            _ => return Err(Status::Invalid),
        }
        let aligned = length.checked_add(width - 1).ok_or(Status::Invalid)? & !(width - 1);
        offset = offset.checked_add(aligned).ok_or(Status::Invalid)?;
        // A final native cmsg may omit its trailing alignment padding.
        if offset > bytes.len() && length == bytes.len() - (offset - aligned) {
            offset = bytes.len();
        }
    }
    if credentials != 1 {
        return Err(Status::Invalid);
    }
    Ok(())
}

#[cfg(feature = "host_editor_process_assertions_v0_dev")]
fn append(out: &mut Vec<u8>, kind: i32, payload: &[u8]) {
    let width = std::mem::size_of::<usize>();
    let length = width + 8 + payload.len();
    let aligned = (length + width - 1) & !(width - 1);
    out.extend_from_slice(&length.to_ne_bytes());
    out.extend_from_slice(&libc::SOL_SOCKET.to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(payload);
    out.resize(out.len() + aligned - length, 0);
}
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
pub(super) fn closed_attempt(trace: &super::diagnostics::Trace) -> Result<(), Status> {
    use super::diagnostics::*;
    let id = trace.scenario().ok_or(Status::Invalid)?.id();
    let mut bytes = Vec::new();
    let mut cred = Vec::new();
    cred.extend_from_slice(&(unsafe { libc::getpid() } as u32).to_ne_bytes());
    cred.extend_from_slice(&unsafe { libc::getuid() }.to_ne_bytes());
    cred.extend_from_slice(&unsafe { libc::getgid() }.to_ne_bytes());
    if id != "D04MissingCredentials" {
        append(&mut bytes, libc::SCM_CREDENTIALS, &cred);
    }
    match id {
        "D04MissingCredentials" => append(&mut bytes, libc::SCM_RIGHTS, &[0; 4]),
        "D04DuplicateCredentials" => append(&mut bytes, libc::SCM_CREDENTIALS, &cred),
        "D05UnknownAncillary" => append(&mut bytes, 0x7fff, &[0; 4]),
        "D05DuplicateRights" => {
            append(&mut bytes, libc::SCM_RIGHTS, &[0; 4]);
            append(&mut bytes, libc::SCM_RIGHTS, &[0; 4]);
        }
        _ => return Err(Status::Invalid),
    }
    let result = validate(&bytes);
    trace.syscall(ProcessAssertionSyscall {
        operation: ProcessAssertionOperation::ParseAncillary,
        origin: ProcessAssertionOrigin::ParserStructural,
        result: if result.is_ok() { 0 } else { -1 },
        errno: None,
        sender: None,
        msg_flags: 0,
        received_fds: 0,
        descriptor_id: None,
        poll_revents: 0,
        ancillary: bytes,
        ancillary_descriptor_ids: Vec::new(),
    });
    result
}
