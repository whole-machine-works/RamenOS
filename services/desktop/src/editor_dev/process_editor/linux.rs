//! Native Linux ownership. Only the supervisor below owns the fork-derived
//! wait right. No public child, Drop path or diagnostic controller can waitpid.
use super::diagnostics::*;
use super::{ProcessRetireReason, ProcessWaitOutcome};
use crate::dev::Status;
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::os::fd::RawFd;
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicU8, Ordering},
    mpsc,
};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub(super) const SEALS: i32 =
    libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
fn error() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}
fn status(errno: i32) -> Status {
    match errno {
        libc::EAGAIN | libc::EINTR => Status::NotReady,
        libc::ENOSYS | libc::EOPNOTSUPP => Status::Unsupported,
        libc::EPERM | libc::EACCES => Status::Denied,
        _ => Status::Internal,
    }
}
fn data(role: ProcessAssertionDescriptorRole) -> bool {
    matches!(
        role,
        ProcessAssertionDescriptorRole::Selected
            | ProcessAssertionDescriptorRole::TextState
            | ProcessAssertionDescriptorRole::Surface
    )
}

pub(super) struct Fd {
    raw: RawFd,
    pub(super) id: u64,
    pub(super) role: ProcessAssertionDescriptorRole,
    trace: Trace,
    data: bool,
}
unsafe impl Send for Fd {}
unsafe impl Sync for Fd {}
fn close_unadopted(raw: RawFd, trace: &Trace, is_data: bool, charged: bool) {
    let result = unsafe { libc::close(raw) };
    trace.call(
        ProcessAssertionOperation::Close,
        result as i64,
        (result < 0).then(error),
        None,
    );
    if result == 0 {
        if charged {
            trace.release_fd(is_data);
        }
    } else {
        // The unadopted native result is still an owned cleanup uncertainty.
        // Never retry close against a possibly reused numeric descriptor.
        trace.retain_uncertain(0, Some(raw), None);
    }
}
impl Fd {
    fn adopt(
        raw: RawFd,
        role: ProcessAssertionDescriptorRole,
        trace: &Trace,
        reserved: bool,
    ) -> Result<Self, Status> {
        if raw < 0 {
            return Err(Status::Internal);
        }
        let is_data = data(role);
        if !reserved {
            if let Err(e) = trace.reserve_fd(is_data, 0, false) {
                close_unadopted(raw, trace, is_data, false);
                return Err(e);
            }
        }
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        let result = unsafe { libc::fstat(raw, st.as_mut_ptr()) };
        trace.call(
            ProcessAssertionOperation::Fstat,
            result as i64,
            (result < 0).then(error),
            None,
        );
        if result < 0 {
            close_unadopted(raw, trace, is_data, true);
            return Err(Status::Internal);
        }
        let st = unsafe { st.assume_init() };
        let seals = unsafe { libc::fcntl(raw, libc::F_GET_SEALS) };
        let id = match trace.descriptor(ProcessAssertionDescriptor {
            role,
            descriptor_id: 0,
            device: st.st_dev,
            inode: st.st_ino,
            byte_len: st.st_size.max(0) as u64,
            mode: st.st_mode,
            seals: seals.max(0) as u32,
            owner_process_id: None,
            offer_id: None,
            event: ProcessAssertionDescriptorEvent::Other,
            mapping: ProcessAssertionMapping::None,
            disposition: ProcessAssertionDisposition::Held,
        }) {
            Ok(id) => id,
            Err(e) => {
                close_unadopted(raw, trace, is_data, true);
                return Err(e);
            }
        };
        Ok(Self {
            raw,
            id,
            role,
            trace: trace.clone(),
            data: is_data,
        })
    }
    pub(super) fn stat(&self) -> Result<libc::stat, Status> {
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        let r = unsafe { libc::fstat(self.raw, st.as_mut_ptr()) };
        self.trace.call(
            ProcessAssertionOperation::Fstat,
            r as i64,
            (r < 0).then(error),
            Some(self.id),
        );
        if r < 0 {
            Err(Status::Internal)
        } else {
            Ok(unsafe { st.assume_init() })
        }
    }
    pub(super) fn identity(&self) -> Result<(u64, u64), Status> {
        let st = self.stat()?;
        Ok((st.st_dev, st.st_ino))
    }
    pub(super) fn seals(&self) -> Result<i32, Status> {
        let r = unsafe { libc::fcntl(self.raw, libc::F_GET_SEALS) };
        self.trace.call(
            ProcessAssertionOperation::GetSeals,
            r as i64,
            (r < 0).then(error),
            Some(self.id),
        );
        if r < 0 { Err(Status::Invalid) } else { Ok(r) }
    }
    pub(super) fn truncate(&self, length: usize) -> Result<(), Status> {
        let r = unsafe { libc::ftruncate(self.raw, length as libc::off_t) };
        self.trace.call(
            ProcessAssertionOperation::Truncate,
            r as i64,
            (r < 0).then(error),
            Some(self.id),
        );
        if r < 0 { Err(status(error())) } else { Ok(()) }
    }
    pub(super) fn write_at(&self, mut bytes: &[u8], mut offset: usize) -> Result<(), Status> {
        while !bytes.is_empty() {
            let r = unsafe {
                libc::pwrite(
                    self.raw,
                    bytes.as_ptr().cast(),
                    bytes.len(),
                    offset as libc::off_t,
                )
            };
            let errno = (r < 0).then(error);
            self.trace.call(
                ProcessAssertionOperation::Pwrite,
                r as i64,
                errno,
                Some(self.id),
            );
            if r < 0 {
                if errno == Some(libc::EINTR) {
                    continue;
                }
                return Err(status(errno.unwrap()));
            }
            if r == 0 {
                return Err(Status::Internal);
            }
            offset += r as usize;
            bytes = &bytes[r as usize..];
        }
        Ok(())
    }
    pub(super) fn read_at(&self, mut bytes: &mut [u8], mut offset: usize) -> Result<(), Status> {
        while !bytes.is_empty() {
            let r = unsafe {
                libc::pread(
                    self.raw,
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                    offset as libc::off_t,
                )
            };
            let errno = (r < 0).then(error);
            self.trace.call(
                ProcessAssertionOperation::Pread,
                r as i64,
                errno,
                Some(self.id),
            );
            if r < 0 {
                if errno == Some(libc::EINTR) {
                    continue;
                }
                return Err(status(errno.unwrap()));
            }
            if r == 0 {
                return Err(Status::Invalid);
            }
            offset += r as usize;
            bytes = &mut bytes[r as usize..];
        }
        Ok(())
    }
    pub(super) fn seal(&self) -> Result<(), Status> {
        let r = unsafe { libc::fcntl(self.raw, libc::F_ADD_SEALS, SEALS) };
        self.trace.call(
            ProcessAssertionOperation::AddSeals,
            r as i64,
            (r < 0).then(error),
            Some(self.id),
        );
        if r < 0 { Err(status(error())) } else { Ok(()) }
    }
    pub(super) fn mark(
        &self,
        owner: Option<u32>,
        offer: Option<u64>,
        event: ProcessAssertionDescriptorEvent,
        disposition: ProcessAssertionDisposition,
    ) -> Result<(), Status> {
        let st = self.stat()?;
        let owner = self.trace.descriptor_owner(st.st_dev, st.st_ino).or(owner);
        self.trace.descriptor(ProcessAssertionDescriptor {
            role: self.role,
            descriptor_id: self.id,
            device: st.st_dev,
            inode: st.st_ino,
            byte_len: st.st_size.max(0) as u64,
            mode: st.st_mode,
            seals: self.seals().unwrap_or(0) as u32,
            owner_process_id: owner,
            offer_id: offer,
            event,
            mapping: ProcessAssertionMapping::None,
            disposition,
        })?;
        Ok(())
    }
    fn high(&mut self) -> Result<(), Status> {
        if self.raw >= 16 {
            return Ok(());
        }
        self.trace.reserve_fd(self.data, 0, false)?;
        let raw = unsafe { libc::fcntl(self.raw, libc::F_DUPFD_CLOEXEC, 16) };
        self.trace.call(
            ProcessAssertionOperation::DuplicateFd,
            if raw < 0 { -1 } else { 0 },
            (raw < 0).then(error),
            Some(self.id),
        );
        if raw < 0 {
            self.trace.release_fd(self.data);
            return Err(Status::Internal);
        }
        let replacement = Fd::adopt(raw, self.role, &self.trace, true)?;
        let old = std::mem::replace(self, replacement);
        drop(old);
        if self.trace.quarantined() {
            return Err(Status::Internal);
        }
        Ok(())
    }
}
impl Drop for Fd {
    fn drop(&mut self) {
        let r = unsafe { libc::close(self.raw) };
        self.trace.call(
            ProcessAssertionOperation::Close,
            r as i64,
            (r < 0).then(error),
            Some(self.id),
        );
        if r == 0 {
            self.trace
                .disposition(self.id, ProcessAssertionDisposition::Closed, None);
            self.trace.release_fd(self.data);
        } else {
            self.trace
                .disposition(self.id, ProcessAssertionDisposition::Quarantined, None);
            self.trace.retain_uncertain(self.id, Some(self.raw), None);
        }
    }
}
pub(super) fn memfd(
    name: &str,
    length: usize,
    role: ProcessAssertionDescriptorRole,
    trace: &Trace,
    lifetime: bool,
) -> Result<Fd, Status> {
    trace.reserve_fd(data(role), length as u64, lifetime)?;
    let name = CString::new(name).map_err(|_| Status::Invalid)?;
    let raw = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            name.as_ptr(),
            libc::MFD_ALLOW_SEALING | libc::MFD_CLOEXEC,
        ) as RawFd
    };
    trace.call(
        ProcessAssertionOperation::MemfdCreate,
        if raw < 0 { -1 } else { 0 },
        (raw < 0).then(error),
        None,
    );
    if raw < 0 {
        trace.release_fd(data(role));
        return Err(status(error()));
    }
    let fd = Fd::adopt(raw, role, trace, true)?;
    if lifetime {
        trace.commit_lifetime(0)?;
    }
    fd.truncate(length)?;
    if lifetime {
        trace.grow_lifetime(length as u64)?;
    }
    Ok(fd)
}
pub(super) struct Mapped {
    fd: Fd,
    address: *mut libc::c_void,
    length: usize,
}
unsafe impl Send for Mapped {}
impl Mapped {
    pub(super) fn bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.address.cast(), self.length) }
    }
    pub(super) fn fd(&self) -> &Fd {
        &self.fd
    }
}
impl Drop for Mapped {
    fn drop(&mut self) {
        let r = unsafe { libc::munmap(self.address, self.length) };
        self.fd.trace.call(
            ProcessAssertionOperation::Munmap,
            r as i64,
            (r < 0).then(error),
            Some(self.fd.id),
        );
        if r == 0 {
            self.fd.trace.disposition(
                self.fd.id,
                ProcessAssertionDisposition::Held,
                Some(ProcessAssertionMapping::Unmapped),
            );
            self.fd.trace.release_map();
        } else {
            self.fd.trace.retain_uncertain(
                self.fd.id,
                None,
                Some((self.address as usize, self.length)),
            );
        }
    }
}
pub(super) fn map_read_only(fd: Fd, length: usize) -> Result<Mapped, Status> {
    if length == 0
        || length > desktop_editor_core::FRAME_BYTES + 1
        || fd.stat()?.st_size != length as i64
        || fd.seals()? & SEALS != SEALS
    {
        return Err(Status::Invalid);
    }
    fd.trace.reserve_map()?;
    let address = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            length,
            libc::PROT_READ,
            libc::MAP_SHARED,
            fd.raw,
            0,
        )
    };
    let failed = address == libc::MAP_FAILED;
    fd.trace.call(
        ProcessAssertionOperation::Mmap,
        if failed { -1 } else { 0 },
        failed.then(error),
        Some(fd.id),
    );
    if failed {
        fd.trace.release_map();
        return Err(Status::Internal);
    }
    fd.trace.disposition(
        fd.id,
        ProcessAssertionDisposition::Held,
        Some(ProcessAssertionMapping::ReadOnly),
    );
    Ok(Mapped {
        fd,
        address,
        length,
    })
}
pub(super) fn sockets(trace: &Trace) -> Result<(Fd, Fd), Status> {
    trace.reserve_fd(false, 0, false)?;
    if let Err(e) = trace.reserve_fd(false, 0, false) {
        trace.release_fd(false);
        return Err(e);
    }
    let mut pair = [-1; 2];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
            pair.as_mut_ptr(),
        )
    } < 0
    {
        trace.release_fd(false);
        trace.release_fd(false);
        return Err(Status::Unsupported);
    }
    let left = Fd::adopt(
        pair[0],
        ProcessAssertionDescriptorRole::Control,
        trace,
        true,
    );
    let right = Fd::adopt(
        pair[1],
        ProcessAssertionDescriptorRole::Control,
        trace,
        true,
    );
    let (a, b) = (left?, right?);
    for fd in [&a, &b] {
        let value = 1i32;
        if unsafe {
            libc::setsockopt(
                fd.raw,
                libc::SOL_SOCKET,
                libc::SO_PASSCRED,
                (&value as *const i32).cast(),
                4,
            )
        } < 0
        {
            return Err(Status::Unsupported);
        }
    }
    Ok((a, b))
}
fn pipe(role: ProcessAssertionDescriptorRole, trace: &Trace) -> Result<(Fd, Fd), Status> {
    trace.reserve_fd(false, 0, false)?;
    if let Err(e) = trace.reserve_fd(false, 0, false) {
        trace.release_fd(false);
        return Err(e);
    }
    let mut pair = [-1; 2];
    if unsafe { libc::pipe2(pair.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } < 0 {
        trace.release_fd(false);
        trace.release_fd(false);
        return Err(Status::Unsupported);
    }
    let a = Fd::adopt(pair[0], role, trace, true);
    let b = Fd::adopt(pair[1], role, trace, true);
    Ok((a?, b?))
}

pub(super) struct Received {
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    pub(super) syscall_index: usize,
    pub(super) bytes: Vec<u8>,
    pub(super) fds: Vec<Fd>,
    pub(super) credentials: (u32, u32, u32),
}
pub(super) fn send(socket: &Fd, bytes: &[u8], fds: &[&Fd]) -> Result<(), Status> {
    send_inner(
        socket,
        bytes,
        fds,
        4,
        ProcessAssertionDirection::ParentToChild,
        None,
    )
}
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
pub(super) fn readable(socket: &Fd) -> Result<bool, Status> {
    let mut fd = libc::pollfd {
        fd: socket.raw,
        events: libc::POLLIN,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut fd, 1, 0) };
    let errno = (result < 0).then(error);
    socket.trace.syscall(ProcessAssertionSyscall {
        operation: ProcessAssertionOperation::Poll,
        origin: ProcessAssertionOrigin::Native,
        result: result as i64,
        errno,
        sender: None,
        msg_flags: 0,
        received_fds: 0,
        descriptor_id: Some(socket.id),
        poll_revents: fd.revents as u32,
        ancillary: Vec::new(),
        ancillary_descriptor_ids: Vec::new(),
    });
    if result < 0 {
        return Err(status(errno.unwrap()));
    }
    if fd.revents & libc::POLLIN != 0 {
        return Ok(true);
    }
    if fd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
        return Err(Status::Disconnected);
    }
    Ok(false)
}
fn send_inner(
    socket: &Fd,
    bytes: &[u8],
    fds: &[&Fd],
    max_fds: usize,
    direction: ProcessAssertionDirection,
    sender: Option<(u32, u32, u32)>,
) -> Result<(), Status> {
    if fds.len() > max_fds || bytes.len() > 89 {
        return Err(Status::Invalid);
    }
    if socket.trace.is("D25SendInterrupted")
        && socket
            .trace
            .inject_once(ProcessAssertionOperation::Sendmsg, libc::EINTR)
    {
        return Err(Status::NotReady);
    }
    let control_slot = socket.trace.reserve_control()?;
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    let mut ancillary = [0usize; 8];
    let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
    header.msg_iov = &mut iov;
    header.msg_iovlen = 1;
    if !fds.is_empty() {
        let space = unsafe { libc::CMSG_SPACE((fds.len() * 4) as u32) } as usize;
        header.msg_control = ancillary.as_mut_ptr().cast();
        header.msg_controllen = space;
        let cmsg = unsafe { libc::CMSG_FIRSTHDR(&header) };
        unsafe {
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN((fds.len() * 4) as u32) as usize;
            for (index, fd) in fds.iter().enumerate() {
                std::ptr::write_unaligned(
                    libc::CMSG_DATA(cmsg).add(index * 4).cast::<i32>(),
                    fd.raw,
                );
            }
        }
    }
    let result =
        unsafe { libc::sendmsg(socket.raw, &header, libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) };
    let errno = (result < 0).then(error);
    let mut projection = unsafe {
        std::slice::from_raw_parts(ancillary.as_ptr().cast::<u8>(), header.msg_controllen)
    }
    .to_vec();
    if !fds.is_empty() {
        let offset = unsafe { libc::CMSG_LEN(0) } as usize;
        projection[offset..offset + fds.len() * 4].fill(0);
    }
    let call = ProcessAssertionSyscall {
        operation: ProcessAssertionOperation::Sendmsg,
        origin: ProcessAssertionOrigin::Native,
        result: result as i64,
        errno,
        sender,
        msg_flags: 0,
        received_fds: 0,
        descriptor_id: Some(socket.id),
        poll_revents: 0,
        ancillary: projection,
        ancillary_descriptor_ids: fds.iter().map(|fd| fd.id).collect(),
    };
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    let bootstrap_call = call.clone();
    let syscall_index = socket.trace.syscall(call);
    if result < 0 {
        if !matches!(errno, Some(libc::EAGAIN | libc::EINTR)) {
            control_slot.commit(direction, bytes, None, 0, fds.len() as u32, syscall_index)?;
        }
        return Err(status(errno.unwrap()));
    }
    control_slot.commit(direction, bytes, None, 0, fds.len() as u32, syscall_index)?;
    if result as usize != bytes.len() {
        return Err(Status::Invalid);
    }
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    if bytes.len() == 88
        && fds.len() == 3
        && u32::from_le_bytes(bytes[4..8].try_into().map_err(|_| Status::Invalid)?) == 1
    {
        let mut facts = Vec::with_capacity(4);
        for fd in fds {
            facts.push(fd.fact()?);
        }
        facts.push(socket.fact()?);
        socket
            .trace
            .capture_bootstrap(bytes, bootstrap_call, facts)?;
    }
    Ok(())
}
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
pub(super) fn send_ancillary_truncation(
    peer: &Fd,
    bytes: &[u8; 88],
    selected: &Fd,
) -> Result<(), Status> {
    if !peer.trace.is("D05AncillaryTruncation") {
        return Err(Status::Denied);
    }
    // Five references to one genuine held object exceed only the receiver's
    // bounded ancillary capacity; no new sender FD is allocated here.
    send_inner(
        peer,
        bytes,
        &[selected; 5],
        5,
        ProcessAssertionDirection::ChildToParent,
        Some((
            unsafe { libc::getpid() } as u32,
            unsafe { libc::getuid() },
            unsafe { libc::getgid() },
        )),
    )
}
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
pub(super) fn forged_credentials(socket: &Fd, bytes: &[u8; 88]) -> Result<(), Status> {
    let scenario = socket.trace.scenario().ok_or(Status::Invalid)?;
    let actual = (
        unsafe { libc::getpid() } as u32,
        unsafe { libc::getuid() },
        unsafe { libc::getgid() },
    );
    let mut requested = actual;
    match scenario.id() {
        "D04ForgedPidKernelReject" => {
            requested.0 = actual.0.checked_add(1).ok_or(Status::Exhausted)?
        }
        "D04ForgedUidKernelReject" => {
            requested.1 = actual.1.checked_add(1).ok_or(Status::Exhausted)?
        }
        "D04ForgedGidKernelReject" => {
            requested.2 = actual.2.checked_add(1).ok_or(Status::Exhausted)?
        }
        _ => return Err(Status::Invalid),
    }
    let slot = socket.trace.reserve_control()?;
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    let mut control = [0usize; 8];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen =
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::ucred>() as u32) } as usize;
    let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    unsafe {
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_CREDENTIALS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::ucred>() as u32) as usize;
        std::ptr::write_unaligned(
            libc::CMSG_DATA(header).cast::<libc::ucred>(),
            libc::ucred {
                pid: requested.0 as i32,
                uid: requested.1,
                gid: requested.2,
            },
        );
    }
    let result = unsafe {
        libc::sendmsg(
            socket.raw,
            &message,
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        )
    };
    let errno = (result < 0).then(error);
    let ancillary = unsafe {
        std::slice::from_raw_parts(control.as_ptr().cast::<u8>(), message.msg_controllen)
    }
    .to_vec();
    let syscall = socket.trace.syscall(ProcessAssertionSyscall {
        operation: ProcessAssertionOperation::Sendmsg,
        origin: ProcessAssertionOrigin::Native,
        result: result as i64,
        errno,
        sender: Some(actual),
        msg_flags: 0,
        received_fds: 0,
        descriptor_id: Some(socket.id),
        poll_revents: 0,
        ancillary,
        ancillary_descriptor_ids: Vec::new(),
    });
    if !matches!(errno, Some(libc::EAGAIN | libc::EINTR)) {
        slot.commit(
            ProcessAssertionDirection::ParentToChild,
            bytes,
            None,
            0,
            0,
            syscall,
        )?;
    }
    if result < 0 {
        Err(status(errno.unwrap()))
    } else {
        Err(Status::Internal)
    }
}
pub(super) fn receive(socket: &Fd) -> Result<Received, Status> {
    if socket.trace.is("D25ReceiveInterrupted")
        && socket
            .trace
            .inject_once(ProcessAssertionOperation::Recvmsg, libc::EINTR)
    {
        return Err(Status::NotReady);
    }
    let control_slot = socket.trace.reserve_control()?;
    // At most four actual aliases can be delivered in this bounded cmsg buffer.
    // Reserve their entire temporary footprint before the native receive.
    for index in 0..4 {
        if let Err(e) = socket.trace.reserve_fd(true, 0, false) {
            for _ in 0..index {
                socket.trace.release_fd(true);
            }
            return Err(e);
        }
    }
    let mut bytes = [0u8; 89];
    let mut ancillary = [0usize; 8];
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
    header.msg_iov = &mut iov;
    header.msg_iovlen = 1;
    header.msg_control = ancillary.as_mut_ptr().cast();
    header.msg_controllen = 64;
    let result = unsafe {
        libc::recvmsg(
            socket.raw,
            &mut header,
            libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
        )
    };
    let errno = (result < 0).then(error);
    let mut fds = Vec::new();
    let mut credentials = None;
    let mut invalid = false;
    let mut consumed = 0;
    if result >= 0 {
        let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&header) };
        while !cmsg.is_null() {
            let value = unsafe { &*cmsg };
            let base = unsafe { libc::CMSG_LEN(0) } as usize;
            let offset = (cmsg as usize).saturating_sub(header.msg_control as usize);
            if value.cmsg_len < base
                || offset > header.msg_controllen
                || value.cmsg_len > header.msg_controllen - offset
            {
                invalid = true;
                break;
            }
            let length = value.cmsg_len - base;
            let payload = unsafe { libc::CMSG_DATA(cmsg) };
            if value.cmsg_level != libc::SOL_SOCKET {
                invalid = true;
            } else if value.cmsg_type == libc::SCM_CREDENTIALS {
                if length != std::mem::size_of::<libc::ucred>() || credentials.is_some() {
                    invalid = true;
                } else {
                    let cred = unsafe { std::ptr::read_unaligned(payload.cast::<libc::ucred>()) };
                    credentials = Some((cred.pid as u32, cred.uid, cred.gid));
                }
            } else if value.cmsg_type == libc::SCM_RIGHTS {
                if !length.is_multiple_of(4) || !fds.is_empty() {
                    invalid = true;
                }
                for index in 0..length / 4 {
                    let raw =
                        unsafe { std::ptr::read_unaligned(payload.add(index * 4).cast::<i32>()) };
                    consumed += 1;
                    if fds.len() < 4 {
                        match Fd::adopt(
                            raw,
                            ProcessAssertionDescriptorRole::TextState,
                            &socket.trace,
                            true,
                        ) {
                            Ok(fd) => {
                                let _ = fd.mark(
                                    None,
                                    None,
                                    ProcessAssertionDescriptorEvent::Returned,
                                    ProcessAssertionDisposition::Received,
                                );
                                fds.push(fd)
                            }
                            Err(_) => {
                                invalid = true;
                            }
                        }
                    } else {
                        unsafe {
                            libc::close(raw);
                        }
                        invalid = true;
                    }
                }
                unsafe {
                    std::ptr::write_bytes(payload, 0, length);
                }
            } else {
                invalid = true;
            }
            cmsg = unsafe { libc::CMSG_NXTHDR(&header, cmsg) };
        }
    }
    for _ in consumed..4 {
        socket.trace.release_fd(true);
    }
    let projection = if result > 0 {
        unsafe {
            std::slice::from_raw_parts(
                ancillary.as_ptr().cast::<u8>(),
                header.msg_controllen.min(64),
            )
        }
        .to_vec()
    } else {
        Vec::new()
    };
    let structural = if result > 0 {
        super::ancillary::validate(&projection)
    } else {
        Ok(())
    };
    let syscall_index = socket.trace.syscall(ProcessAssertionSyscall {
        operation: ProcessAssertionOperation::Recvmsg,
        origin: ProcessAssertionOrigin::Native,
        result: result as i64,
        errno,
        sender: credentials,
        msg_flags: header.msg_flags as u32,
        received_fds: fds.len() as u32,
        descriptor_id: Some(socket.id),
        poll_revents: 0,
        ancillary: projection,
        ancillary_descriptor_ids: fds.iter().map(|fd| fd.id).collect(),
    });
    if result < 0 {
        return Err(status(errno.unwrap()));
    }
    if result == 0 {
        return Err(Status::Disconnected);
    }
    let bytes = bytes[..(result as usize).min(89)].to_vec();
    control_slot.commit(
        ProcessAssertionDirection::ChildToParent,
        &bytes,
        credentials,
        header.msg_flags as u32,
        fds.len() as u32,
        syscall_index,
    )?;
    structural?;
    if invalid
        || header.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
        || credentials.is_none()
    {
        return Err(Status::Invalid);
    }
    Ok(Received {
        #[cfg(feature = "host_editor_process_assertions_v0_dev")]
        syscall_index,
        bytes,
        fds,
        credentials: credentials.unwrap(),
    })
}

pub(super) struct Executable {
    fd: Fd,
    pub(super) sha256: [u8; 32],
}
fn registered(assertion: bool) -> Result<(&'static str, [u8; 32]), Status> {
    let pair = if assertion {
        (
            option_env!("RAMEN_EDITOR_PROCESS_ASSERTION_ARTIFACT_PATH"),
            option_env!("RAMEN_EDITOR_PROCESS_ASSERTION_ARTIFACT_SHA256"),
        )
    } else {
        (
            option_env!("RAMEN_EDITOR_PROCESS_ARTIFACT_PATH"),
            option_env!("RAMEN_EDITOR_PROCESS_ARTIFACT_SHA256"),
        )
    };
    let (path, hash) = (pair.0.ok_or(Status::Denied)?, pair.1.ok_or(Status::Denied)?);
    if !std::path::Path::new(path).is_absolute() || hash.len() != 64 {
        return Err(Status::Invalid);
    }
    let mut digest = [0u8; 32];
    for (index, slot) in digest.iter_mut().enumerate() {
        *slot =
            u8::from_str_radix(&hash[index * 2..index * 2 + 2], 16).map_err(|_| Status::Invalid)?;
    }
    Ok((path, digest))
}
fn valid_elf(header: &[u8], length: u64) -> bool {
    if header.len() < 64 || &header[..4] != b"\x7fELF" || header[4..7] != [2, 1, 1] {
        return false;
    }
    let u16at = |i| u16::from_le_bytes([header[i], header[i + 1]]);
    let mut offset = [0; 8];
    offset.copy_from_slice(&header[32..40]);
    let phoff = u64::from_le_bytes(offset);
    matches!(u16at(16), 2 | 3)
        && u16at(18) == 62
        && u16at(52) == 64
        && u16at(54) == 56
        && u16at(56) > 0
        && phoff >= 64
        && phoff
            .checked_add(u16at(56) as u64 * 56)
            .is_some_and(|end| end <= length)
}
struct SourceFixture {
    root: std::path::PathBuf,
    path: std::path::PathBuf,
}
impl Drop for SourceFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_file(self.root.join("replacement"));
        let _ = std::fs::remove_dir(&self.root);
    }
}
fn open_source(path: &std::path::Path, flags: i32, trace: &Trace) -> Result<Fd, Status> {
    use std::os::unix::ffi::OsStrExt;
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| Status::Invalid)?;
    trace.reserve_fd(false, 0, false)?;
    let raw = unsafe {
        libc::open(
            path.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            0o600,
        )
    };
    let errno = (raw < 0).then(error);
    trace.call(
        ProcessAssertionOperation::Open,
        if raw < 0 { -1 } else { 0 },
        errno,
        None,
    );
    if raw < 0 {
        trace.release_fd(false);
        return Err(if errno == Some(libc::ELOOP) {
            Status::Invalid
        } else {
            status(errno.unwrap())
        });
    }
    Fd::adopt(raw, ProcessAssertionDescriptorRole::Executable, trace, true)
}
fn hash_source(fd: &Fd) -> Result<[u8; 32], Status> {
    let stat = fd.stat()?;
    if stat.st_size < 0 || stat.st_size > 1_073_741_824 {
        return Err(Status::Invalid);
    }
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut offset = 0usize;
    while offset < stat.st_size as usize {
        let count = (stat.st_size as usize - offset).min(buffer.len());
        fd.read_at(&mut buffer[..count], offset)?;
        digest.update(&buffer[..count]);
        offset += count;
    }
    Ok(digest.finalize().into())
}
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
pub(super) fn child_mapping(pid: u32, object: &Fd) -> Result<ProcessAssertionMapping, Status> {
    let path = std::path::PathBuf::from(format!("/proc/{pid}/maps"));
    let fd = open_source(&path, libc::O_RDONLY, &object.trace)?;
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let count = unsafe { libc::read(fd.raw, chunk.as_mut_ptr().cast(), chunk.len()) };
        let errno = (count < 0).then(error);
        object.trace.call(
            ProcessAssertionOperation::Read,
            count as i64,
            errno,
            Some(fd.id),
        );
        if count < 0 {
            if errno == Some(libc::EINTR) {
                continue;
            }
            return Err(Status::Internal);
        }
        if count == 0 {
            break;
        }
        if bytes.len() + count as usize > 1_048_576 {
            return Err(Status::Exhausted);
        }
        bytes.extend_from_slice(&chunk[..count as usize]);
    }
    let stat = object.stat()?;
    let text = std::str::from_utf8(&bytes).map_err(|_| Status::Invalid)?;
    let mut found = ProcessAssertionMapping::None;
    for line in text.lines() {
        let mut fields = line.split_ascii_whitespace();
        let _address = fields.next();
        let perms = fields.next().ok_or(Status::Invalid)?;
        let _offset = fields.next();
        let device = fields.next().ok_or(Status::Invalid)?;
        let inode = fields
            .next()
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or(Status::Invalid)?;
        let (major, minor) = device.split_once(':').ok_or(Status::Invalid)?;
        let major = u64::from_str_radix(major, 16).map_err(|_| Status::Invalid)?;
        let minor = u64::from_str_radix(minor, 16).map_err(|_| Status::Invalid)?;
        if inode == stat.st_ino
            && major == libc::major(stat.st_dev) as u64
            && minor == libc::minor(stat.st_dev) as u64
        {
            if perms == "rw-s" {
                return Ok(ProcessAssertionMapping::SharedWritable);
            }
            if perms == "r--s" {
                found = ProcessAssertionMapping::ReadOnly;
            }
        }
    }
    Ok(found)
}
impl SourceFixture {
    fn new(registered: &str, trace: &Trace) -> Result<Option<Self>, Status> {
        if !matches!(
            trace.scenario().map(|s| s.id()),
            Some(
                "D02SourceSymlink"
                    | "D02SourceNonregular"
                    | "D02ScriptExecutable"
                    | "D02InvalidElf"
                    | "D02PreSnapshotSourceReplacement"
                    | "D02PostHeldPathReplacement"
                    | "D02PostHeldInodeMutation"
            )
        ) {
            return Ok(None);
        }
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        let mut template = std::env::temp_dir()
            .join("ramen-owned-elf-XXXXXXXX")
            .as_os_str()
            .as_bytes()
            .to_vec();
        template.push(0);
        if unsafe { libc::mkdtemp(template.as_mut_ptr().cast()) }.is_null() {
            return Err(Status::Internal);
        }
        template.pop();
        let root = std::path::PathBuf::from(std::ffi::OsString::from_vec(template));
        let fixture = Self {
            path: root.join("source"),
            root,
        };
        if trace.is("D02SourceSymlink") {
            std::os::unix::fs::symlink(registered, &fixture.path).map_err(|_| Status::Internal)?;
        } else if trace.is("D02SourceNonregular") {
            let path =
                CString::new(fixture.path.as_os_str().as_bytes()).map_err(|_| Status::Invalid)?;
            if unsafe { libc::mkfifo(path.as_ptr(), 0o600) } != 0 {
                return Err(Status::Internal);
            }
        } else {
            let target = open_source(
                &fixture.path,
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
                trace,
            )?;
            if trace.is("D02ScriptExecutable") || trace.is("D02InvalidElf") {
                let mut bytes = [0u8; 64];
                if trace.is("D02ScriptExecutable") {
                    bytes[..10].copy_from_slice(b"#!/bin/sh\n");
                }
                target.write_at(&bytes, 0)?;
            } else {
                let source = open_source(std::path::Path::new(registered), libc::O_RDONLY, trace)?;
                let stat = source.stat()?;
                if stat.st_mode & libc::S_IFMT != libc::S_IFREG
                    || !(64..=1_073_741_824).contains(&stat.st_size)
                {
                    return Err(Status::Invalid);
                }
                let mut bytes = [0u8; 65536];
                let mut offset = 0usize;
                while offset < stat.st_size as usize {
                    let count = (stat.st_size as usize - offset).min(bytes.len());
                    source.read_at(&mut bytes[..count], offset)?;
                    target.write_at(&bytes[..count], offset)?;
                    offset += count;
                }
            }
        }
        Ok(Some(fixture))
    }
    fn replace(&self, trace: &Trace) -> Result<Fd, Status> {
        let replacement = self.root.join("replacement");
        let file = open_source(
            &replacement,
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
            trace,
        )?;
        file.write_at(&[0x5a; 64], 0)?;
        std::fs::rename(replacement, &self.path).map_err(|_| Status::Internal)?;
        Ok(file)
    }
}
pub(super) fn pin(trace: &Trace, assertion: bool) -> Result<Executable, Status> {
    let (path, registered_sha256) = registered(assertion)?;
    let fixture = SourceFixture::new(path, trace)?;
    let path = fixture
        .as_ref()
        .map(|f| f.path.to_str().ok_or(Status::Invalid))
        .transpose()?
        .unwrap_or(path);
    let path = CString::new(path).map_err(|_| Status::Invalid)?;
    trace.point(ProcessAssertionPoint::BeforeSnapshotCopy)?;
    trace.reserve_fd(false, 0, false)?;
    let raw = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    trace.call(
        ProcessAssertionOperation::Open,
        if raw < 0 { -1 } else { 0 },
        (raw < 0).then(error),
        None,
    );
    if raw < 0 {
        trace.release_fd(false);
        return Err(if error() == libc::ELOOP {
            Status::Invalid
        } else {
            status(error())
        });
    }
    let mut source = Fd::adopt(raw, ProcessAssertionDescriptorRole::Executable, trace, true)?;
    let before = source.stat()?;
    if before.st_mode & libc::S_IFMT != libc::S_IFREG
        || !(64..=1_073_741_824).contains(&before.st_size)
    {
        return Err(Status::Invalid);
    }
    let mut header = vec![0; 64];
    source.read_at(&mut header, 0)?;
    let mut source_digest = Sha256::new();
    let mut source_buffer = [0u8; 65536];
    let mut source_offset = 0usize;
    while source_offset < before.st_size as usize {
        let count = (before.st_size as usize - source_offset).min(source_buffer.len());
        source.read_at(&mut source_buffer[..count], source_offset)?;
        source_digest.update(&source_buffer[..count]);
        source_offset += count;
    }
    let audited_source: [u8; 32] = source_digest.finalize().into();
    let mut registered_sha256 = registered_sha256;
    if trace.is("D02WrongRegisteredDigest") {
        registered_sha256[0] ^= 1;
    }
    trace.set_executable(ProcessAssertionExecutable {
        registered_sha256,
        held_sha256: [0; 32],
        source_before_sha256: audited_source,
        source_after_sha256: audited_source,
        source_before_device: before.st_dev,
        source_before_inode: before.st_ino,
        source_after_device: before.st_dev,
        source_after_inode: before.st_ino,
        held_device: 0,
        held_inode: 0,
        executed_device: None,
        executed_inode: None,
        executed_sha256: None,
        held_mode: 0,
        held_seals: 0,
        checkpoint_sequence: 0,
        action: None,
        source_header: header.clone(),
    });
    if !valid_elf(&header, before.st_size as u64) {
        return Err(Status::Invalid);
    }
    if trace.is("D02PreSnapshotSourceReplacement") {
        source = fixture.as_ref().ok_or(Status::Internal)?.replace(trace)?;
        let after = source.stat()?;
        let digest = hash_source(&source)?;
        trace.update_executable(|e| {
            e.source_after_sha256 = digest;
            e.source_after_device = after.st_dev;
            e.source_after_inode = after.st_ino;
        });
        // A changed registered source cannot enter the held-image copy.
        return Err(Status::Denied);
    }
    if trace.is("D02MemfdUnavailable") {
        trace.inject(
            ProcessAssertionOperation::MemfdCreate,
            ProcessAssertionOrigin::InjectedBeforeSyscall,
            libc::ENOSYS,
        );
        return Err(Status::Unsupported);
    }
    let held = memfd(
        "ramen-editor-elf",
        before.st_size as usize,
        ProcessAssertionDescriptorRole::Executable,
        trace,
        false,
    )?;
    let mut digest = Sha256::new();
    let mut bytes = [0u8; 65536];
    let mut offset = 0usize;
    while offset < before.st_size as usize {
        let count = (before.st_size as usize - offset).min(bytes.len());
        source.read_at(&mut bytes[..count], offset)?;
        held.write_at(&bytes[..count], offset)?;
        digest.update(&bytes[..count]);
        offset += count;
    }
    let source_hash: [u8; 32] = digest.finalize().into();
    let after = source.stat()?;
    if before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || before.st_size != after.st_size
        || before.st_mtime_nsec != after.st_mtime_nsec
        || before.st_ctime_nsec != after.st_ctime_nsec
    {
        return Err(Status::Denied);
    }
    let mut digest = Sha256::new();
    offset = 0;
    while offset < before.st_size as usize {
        let count = (before.st_size as usize - offset).min(bytes.len());
        held.read_at(&mut bytes[..count], offset)?;
        digest.update(&bytes[..count]);
        offset += count;
    }
    let held_hash: [u8; 32] = digest.finalize().into();
    let held_metadata = held.stat()?;
    trace.update_executable(|e| {
        e.held_sha256 = held_hash;
        e.source_after_sha256 = source_hash;
        e.source_after_device = after.st_dev;
        e.source_after_inode = after.st_ino;
        e.held_device = held_metadata.st_dev;
        e.held_inode = held_metadata.st_ino;
        e.held_mode = held_metadata.st_mode;
    });
    if source_hash != registered_sha256 || held_hash != registered_sha256 {
        return Err(Status::Denied);
    }
    if unsafe { libc::fchmod(held.raw, 0o500) } < 0 {
        return Err(Status::Internal);
    }
    held.seal()?;
    let metadata = held.stat()?;
    if held.seals()? & SEALS != SEALS || metadata.st_mode & 0o777 != 0o500 {
        return Err(Status::Invalid);
    }
    held.mark(
        None,
        None,
        ProcessAssertionDescriptorEvent::Other,
        ProcessAssertionDisposition::Held,
    )?;
    trace.set_executable(ProcessAssertionExecutable {
        registered_sha256,
        held_sha256: held_hash,
        source_before_sha256: source_hash,
        source_after_sha256: source_hash,
        source_before_device: before.st_dev,
        source_before_inode: before.st_ino,
        source_after_device: after.st_dev,
        source_after_inode: after.st_ino,
        held_device: metadata.st_dev,
        held_inode: metadata.st_ino,
        executed_device: None,
        executed_inode: None,
        executed_sha256: None,
        held_mode: metadata.st_mode,
        held_seals: SEALS as u32,
        checkpoint_sequence: 0,
        action: None,
        source_header: header,
    });
    let sequence = trace.point(ProcessAssertionPoint::HeldVerifiedBeforeExec)?;
    trace.update_executable(|e| e.checkpoint_sequence = sequence);
    if trace.is("D02PostHeldPathReplacement") {
        let replacement = fixture.as_ref().ok_or(Status::Internal)?.replace(trace)?;
        let after = replacement.stat()?;
        let digest = hash_source(&replacement)?;
        trace.update_executable(|e| {
            e.action = Some(ProcessAssertionExecutableAction::ReplacePath);
            e.source_after_device = after.st_dev;
            e.source_after_inode = after.st_ino;
            e.source_after_sha256 = digest;
        });
    } else if trace.is("D02PostHeldInodeMutation") {
        let writer = open_source(
            &fixture.as_ref().ok_or(Status::Internal)?.path,
            libc::O_RDWR,
            trace,
        )?;
        writer.write_at(&[0x5a], 0)?;
        let digest = hash_source(&source)?;
        trace.update_executable(|e| {
            e.action = Some(ProcessAssertionExecutableAction::MutateOriginalInode);
            e.source_after_sha256 = digest;
        });
    } else if trace.is("D02HeldWriteDenied") {
        let result = held.write_at(&[0x5a], 0);
        trace.update_executable(|e| e.action = Some(ProcessAssertionExecutableAction::HeldWrite));
        if result.is_ok() {
            return Err(Status::Internal);
        }
    } else if trace.is("D02HeldGrowDenied") || trace.is("D02HeldShrinkDenied") {
        let grow = trace.is("D02HeldGrowDenied");
        let result = held.truncate(if grow {
            before.st_size as usize + 1
        } else {
            before.st_size as usize - 1
        });
        trace.update_executable(|e| {
            e.action = Some(if grow {
                ProcessAssertionExecutableAction::HeldGrow
            } else {
                ProcessAssertionExecutableAction::HeldShrink
            })
        });
        if result.is_ok() {
            return Err(Status::Internal);
        }
    }
    drop(source);
    Ok(Executable {
        fd: held,
        sha256: held_hash,
    })
}
fn birth(pid: libc::pid_t, trace: &Trace) -> Result<u64, Status> {
    let path = CString::new(format!("/proc/{pid}/stat")).map_err(|_| Status::Invalid)?;
    trace.reserve_fd(false, 0, false)?;
    let raw = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    trace.call(
        ProcessAssertionOperation::Open,
        if raw < 0 { -1 } else { 0 },
        (raw < 0).then(error),
        None,
    );
    if raw < 0 {
        trace.release_fd(false);
        return Err(Status::Internal);
    }
    let mut bytes = [0u8; 4096];
    let count = unsafe { libc::read(raw, bytes.as_mut_ptr().cast(), bytes.len()) };
    let errno = (count < 0).then(error);
    trace.call(ProcessAssertionOperation::Read, count as i64, errno, None);
    let closed = unsafe { libc::close(raw) };
    trace.call(
        ProcessAssertionOperation::Close,
        closed as i64,
        (closed < 0).then(error),
        None,
    );
    if closed == 0 {
        trace.release_fd(false);
    } else {
        trace.retain_uncertain(0, Some(raw), None);
        return Err(Status::Internal);
    }
    if count <= 0 {
        return Err(Status::Internal);
    }
    let text = std::str::from_utf8(&bytes[..count as usize]).map_err(|_| Status::Invalid)?;
    let end = text.rfind(')').ok_or(Status::Invalid)?;
    text[end + 1..]
        .split_whitespace()
        .nth(19)
        .ok_or(Status::Invalid)?
        .parse()
        .map_err(|_| Status::Invalid)
}
fn record_exec_failure(trace: &Trace, executable_id: u64, errno: i32, count: isize) -> Status {
    if count != 4 {
        return Status::Invalid;
    }
    if trace.is("D02ExecveatUnavailable") {
        trace.inject(
            ProcessAssertionOperation::Execveat,
            ProcessAssertionOrigin::InjectedBeforeSyscall,
            errno,
        );
    } else {
        trace.call(
            ProcessAssertionOperation::Execveat,
            -1,
            Some(errno),
            Some(executable_id),
        );
    }
    status(errno)
}
fn audit_executed(pid: libc::pid_t, trace: &Trace, expected: &Executable) -> Result<(), Status> {
    let path = CString::new(format!("/proc/{pid}/exe")).map_err(|_| Status::Invalid)?;
    trace.reserve_fd(false, 0, false)?;
    let raw = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    trace.call(
        ProcessAssertionOperation::Open,
        if raw < 0 { -1 } else { 0 },
        (raw < 0).then(error),
        None,
    );
    if raw < 0 {
        trace.release_fd(false);
        return Err(Status::NotReady);
    }
    let fd = Fd::adopt(raw, ProcessAssertionDescriptorRole::Executable, trace, true)?;
    let st = fd.stat()?;
    if st.st_size < 64 || st.st_size > 1_073_741_824 {
        return Err(Status::Invalid);
    }
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut offset = 0;
    while offset < st.st_size as usize {
        let count = (st.st_size as usize - offset).min(buffer.len());
        fd.read_at(&mut buffer[..count], offset)?;
        hash.update(&buffer[..count]);
        offset += count;
    }
    let hash: [u8; 32] = hash.finalize().into();
    let held = expected.fd.stat()?;
    if (st.st_dev, st.st_ino) != (held.st_dev, held.st_ino) || hash != expected.sha256 {
        return Err(Status::Denied);
    }
    trace.update_executable(|e| {
        e.executed_device = Some(st.st_dev);
        e.executed_inode = Some(st.st_ino);
        e.executed_sha256 = Some(hash);
    });
    // A successful execveat never returns to the invoking image. This native
    // success observation is made only after exec-error-pipe EOF and the
    // kernel /proc executable's held inode, device and full SHA all agree.
    // Zero is normalized observed success, never a claimed child return value.
    trace.call(
        ProcessAssertionOperation::Execveat,
        0,
        None,
        Some(expected.fd.id),
    );
    Ok(())
}

struct Prepared {
    executable: Executable,
    control: Fd,
    error_read: Fd,
    error_write: Fd,
    barrier_read: Fd,
    barrier_write: Fd,
    stdout_read: Fd,
    stdout_write: Fd,
    stderr_read: Fd,
    stderr_write: Fd,
    null: Fd,
    // Own the C strings referenced by argument_pointers through child exec.
    _arguments: Vec<CString>,
    argument_pointers: Vec<usize>,
    assertion: bool,
    exec_unavailable: bool,
}
impl Prepared {
    fn new(
        executable: Executable,
        control: Fd,
        trace: &Trace,
        assertion: Option<&str>,
    ) -> Result<Self, (Status, Executable, Fd)> {
        let setup = (|| {
            let (error_read, error_write) = pipe(ProcessAssertionDescriptorRole::ExecError, trace)?;
            let (barrier_read, barrier_write) =
                pipe(ProcessAssertionDescriptorRole::Barrier, trace)?;
            let (stdout_read, stdout_write) = pipe(ProcessAssertionDescriptorRole::Stdout, trace)?;
            let (stderr_read, stderr_write) = pipe(ProcessAssertionDescriptorRole::Stderr, trace)?;
            trace.reserve_fd(false, 0, false)?;
            let raw =
                unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
            if raw < 0 {
                trace.release_fd(false);
                return Err(Status::Internal);
            }
            let null = Fd::adopt(raw, ProcessAssertionDescriptorRole::Control, trace, true)?;
            Ok((
                error_read,
                error_write,
                barrier_read,
                barrier_write,
                stdout_read,
                stdout_write,
                stderr_read,
                stderr_write,
                null,
            ))
        })();
        let (
            error_read,
            error_write,
            barrier_read,
            barrier_write,
            stdout_read,
            stdout_write,
            stderr_read,
            stderr_write,
            null,
        ) = match setup {
            Ok(parts) => parts,
            Err(e) => return Err((e, executable, control)),
        };
        let mut arguments = vec![
            CString::new("editor-process").unwrap(),
            CString::new("--control-fd").unwrap(),
            CString::new("3").unwrap(),
            CString::new("--parent-pid").unwrap(),
            CString::new(unsafe { libc::getpid() }.to_string()).unwrap(),
            CString::new("--parent-uid").unwrap(),
            CString::new(unsafe { libc::getuid() }.to_string()).unwrap(),
            CString::new("--parent-gid").unwrap(),
            CString::new(unsafe { libc::getgid() }.to_string()).unwrap(),
        ];
        if let Some(case) = assertion {
            arguments.extend([
                CString::new("--assertion-case").unwrap(),
                CString::new(case).unwrap(),
                CString::new("--barrier-fd").unwrap(),
                CString::new("5").unwrap(),
            ]);
        }
        let mut pointers: Vec<_> = arguments.iter().map(|s| s.as_ptr() as usize).collect();
        pointers.push(0);
        let flags = unsafe { libc::fcntl(barrier_read.raw, libc::F_GETFL) };
        if flags < 0
            || unsafe { libc::fcntl(barrier_read.raw, libc::F_SETFL, flags & !libc::O_NONBLOCK) }
                < 0
        {
            return Err((Status::Internal, executable, control));
        }
        let mut p = Self {
            executable,
            control,
            error_read,
            error_write,
            barrier_read,
            barrier_write,
            stdout_read,
            stdout_write,
            stderr_read,
            stderr_write,
            null,
            _arguments: arguments,
            argument_pointers: pointers,
            assertion: assertion.is_some(),
            exec_unavailable: trace.is("D02ExecveatUnavailable"),
        };
        let result = (|| {
            for fd in [
                &mut p.executable.fd,
                &mut p.control,
                &mut p.error_write,
                &mut p.barrier_read,
                &mut p.stdout_write,
                &mut p.stderr_write,
                &mut p.null,
            ] {
                fd.high()?;
            }
            Ok(())
        })();
        if let Err(e) = result {
            return Err((e, p.executable, p.control));
        }
        Ok(p)
    }
}
/// Only fixed, prepared pointers and async-signal-safe native operations occur
/// here. This branch never formats, allocates, locks, unwinds or runs destructors.
unsafe fn child_exec(p: &Prepared) -> ! {
    let remaps = [
        (p.null.raw, 0),
        (p.stdout_write.raw, 1),
        (p.stderr_write.raw, 2),
        (p.control.raw, 3),
        (p.error_write.raw, 4),
        (p.barrier_read.raw, 5),
        (p.executable.fd.raw, 6),
    ];
    for (source, target) in remaps {
        if unsafe { libc::dup2(source, target) } < 0 {
            unsafe {
                libc::_exit(126);
            }
        }
    }
    // Only error/executable require CLOEXEC after dup2. Use prepared fcntl
    // operations; no unlisted descriptor may survive the close-range boundary.
    if unsafe { libc::fcntl(4, libc::F_SETFD, libc::FD_CLOEXEC) } < 0
        || unsafe { libc::fcntl(6, libc::F_SETFD, libc::FD_CLOEXEC) } < 0
    {
        unsafe {
            libc::_exit(126);
        }
    }
    if unsafe { libc::syscall(libc::SYS_close_range, 7u32, u32::MAX, 0u32) } < 0 {
        unsafe {
            libc::_exit(126);
        }
    }
    let mut byte = 0u8;
    loop {
        let count = unsafe { libc::read(5, (&mut byte as *mut u8).cast(), 1) };
        if count == 1 {
            if byte != 1 {
                unsafe {
                    libc::_exit(126);
                }
            }
            break;
        }
        if count == 0 {
            unsafe {
                libc::_exit(126);
            }
        }
        if unsafe { *libc::__errno_location() } != libc::EINTR {
            unsafe {
                libc::_exit(126);
            }
        }
    }
    if !p.assertion {
        unsafe {
            libc::close(5);
        }
    }
    let empty = [0u8];
    let environment = [std::ptr::null::<libc::c_char>()];
    if p.exec_unavailable {
        let errno = libc::ENOSYS;
        unsafe {
            libc::write(4, (&errno as *const i32).cast(), 4);
            libc::_exit(127);
        }
    }
    unsafe {
        libc::syscall(
            libc::SYS_execveat,
            6,
            empty.as_ptr(),
            p.argument_pointers.as_ptr().cast::<*const libc::c_char>(),
            environment.as_ptr(),
            libc::AT_EMPTY_PATH,
        );
    }
    let errno = unsafe { *libc::__errno_location() };
    unsafe {
        libc::write(4, (&errno as *const i32).cast(), 4);
        libc::_exit(127);
    }
}

#[derive(Clone, Copy)]
pub(super) struct Identity {
    pub(super) pid: u32,
    pub(super) birth: u64,
    pub(super) executable: [u8; 32],
}
struct SupervisorState {
    identity: Option<Identity>,
    outcome: Option<ProcessWaitOutcome>,
    start_error: Option<Status>,
    joined: bool,
    quarantined: bool,
}
pub(super) struct Supervisor {
    state: Arc<Mutex<SupervisorState>>,
    retire: Arc<AtomicU8>,
    handle: Option<JoinHandle<()>>,
    trace: Trace,
}
pub(super) enum StartFailure {
    Unspawned(Status, Executable, Fd),
    Spawned(Status, Supervisor),
}
impl Supervisor {
    pub(super) fn request_retire(&self, reason: ProcessRetireReason) {
        let code = if reason == ProcessRetireReason::HumanClose {
            1
        } else {
            2
        };
        let _ = self
            .retire
            .compare_exchange(0, code, Ordering::AcqRel, Ordering::Acquire);
    }
    pub(super) fn identity(&self) -> Result<Identity, Status> {
        self.state
            .lock()
            .map_err(|_| Status::Internal)?
            .identity
            .ok_or(Status::NotReady)
    }
    pub(super) fn terminal(&self) -> bool {
        self.state
            .lock()
            .map(|s| s.outcome.is_some())
            .unwrap_or(false)
    }
    pub(super) fn try_join(&mut self) -> Result<(Identity, ProcessWaitOutcome), Status> {
        let (identity, outcome) = {
            let s = self.state.lock().map_err(|_| Status::Internal)?;
            if s.quarantined {
                return Err(Status::Internal);
            }
            (
                s.identity.ok_or(Status::NotReady)?,
                s.outcome.ok_or(Status::NotReady)?,
            )
        };
        if !self.handle.as_ref().is_some_and(JoinHandle::is_finished) {
            return Err(Status::NotReady);
        }
        let handle = self.handle.take().ok_or(Status::Stale)?;
        if handle.join().is_err() {
            self.trace.quarantine();
            return Err(Status::Internal);
        }
        self.trace.joined();
        if let Ok(mut s) = self.state.lock() {
            s.joined = true;
        }
        Ok((identity, outcome))
    }
}
impl Drop for Supervisor {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            self.request_retire(ProcessRetireReason::ChildFault);
            std::mem::forget(handle);
            self.trace.quarantine();
        }
    }
}

pub(super) fn start(
    executable: Executable,
    control: Fd,
    trace: &Trace,
    deadline: Instant,
    assertion: Option<&'static str>,
    core_retire: Box<dyn Fn(ProcessRetireReason, u8, Status) + Send + Sync>,
) -> Result<Supervisor, StartFailure> {
    if trace.is("D02SupervisorInstallFailure") {
        trace.inject(
            ProcessAssertionOperation::SupervisorStart,
            ProcessAssertionOrigin::InjectedBeforeOperation,
            libc::EAGAIN,
        );
        return Err(StartFailure::Unspawned(
            Status::Internal,
            executable,
            control,
        ));
    }
    let prepared = Prepared::new(executable, control, trace, assertion)
        .map_err(|(s, e, c)| StartFailure::Unspawned(s, e, c))?;
    let staged = Arc::new(Mutex::new(Some(prepared)));
    let failed = Arc::new(Mutex::new(None));
    let state = Arc::new(Mutex::new(SupervisorState {
        identity: None,
        outcome: None,
        start_error: None,
        joined: false,
        quarantined: false,
    }));
    let retire = Arc::new(AtomicU8::new(0));
    let (worker_stage, worker_failed, worker_state, worker_retire, worker_trace) = (
        staged.clone(),
        failed.clone(),
        state.clone(),
        retire.clone(),
        trace.clone(),
    );
    let (sender, receiver) = mpsc::sync_channel(1);
    let start_gate = Arc::new((Mutex::new(false), Condvar::new()));
    let worker_gate = start_gate.clone();
    let handle = std::thread::Builder::new()
        .name("ramen-editor-supervisor".to_owned())
        .spawn(move || {
            {
                let mut ready = worker_gate.0.lock().unwrap_or_else(|e| e.into_inner());
                while !*ready {
                    ready = worker_gate.1.wait(ready).unwrap_or_else(|e| e.into_inner());
                }
            }
            let Some(p) = worker_stage
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
            else {
                return;
            };
            worker_trace.process_started();
            let pid = unsafe { libc::fork() };
            let errno = (pid < 0).then(error);
            if pid == 0 {
                unsafe {
                    child_exec(&p);
                }
            }
            worker_trace.call(ProcessAssertionOperation::Fork, pid as i64, errno, None);
            if pid < 0 {
                let status = status(errno.unwrap());
                *worker_failed.lock().unwrap_or_else(|e| e.into_inner()) =
                    Some((status, p.executable, p.control));
                let _ = sender.send(Err(status));
                return;
            }
            worker_trace.process_forked(pid as u32);
            let hash = p.executable.sha256;
            if let Ok(mut state) = worker_state.lock() {
                state.identity = Some(Identity {
                    pid: pid as u32,
                    birth: 0,
                    executable: hash,
                });
            }
            drop((
                p.control,
                p.error_write,
                p.barrier_read,
                p.stdout_write,
                p.stderr_write,
                p.null,
            ));
            let birth_install_failure = worker_trace.is("D02BirthInstallFailure");
            if birth_install_failure {
                worker_trace.inject(
                    ProcessAssertionOperation::Open,
                    ProcessAssertionOrigin::InjectedBeforeSyscall,
                    libc::EIO,
                );
            }
            let birth = birth(pid, &worker_trace);
            let pidfd_install_failure = worker_trace.is("D02PidfdInstallFailure");
            if pidfd_install_failure {
                worker_trace.inject(
                    ProcessAssertionOperation::PidfdOpen,
                    ProcessAssertionOrigin::InjectedBeforeSyscall,
                    libc::EMFILE,
                );
            }
            let pidfd_reserved = if pidfd_install_failure {
                Err(Status::Internal)
            } else {
                worker_trace.reserve_fd(false, 0, false)
            };
            let pidfd_raw = if pidfd_reserved.is_ok() {
                unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as RawFd }
            } else {
                -1
            };
            if pidfd_raw < 0 && pidfd_reserved.is_ok() {
                worker_trace.release_fd(false);
            }
            let pidfd_errno = (pidfd_raw < 0).then(error);
            if pidfd_reserved.is_ok() {
                worker_trace.call(
                    ProcessAssertionOperation::PidfdOpen,
                    if pidfd_raw < 0 { -1 } else { 0 },
                    pidfd_errno,
                    None,
                );
            }
            let pidfd = if pidfd_raw >= 0 {
                Fd::adopt(
                    pidfd_raw,
                    ProcessAssertionDescriptorRole::Pidfd,
                    &worker_trace,
                    true,
                )
                .ok()
            } else {
                None
            };
            if let Some(pidfd) = &pidfd {
                worker_trace.process_pidfd(pidfd.id);
            }
            let mut startup = birth.and_then(|birth| {
                worker_trace.process_birth(birth);
                if let Ok(mut state) = worker_state.lock() {
                    state.identity = Some(Identity {
                        pid: pid as u32,
                        birth,
                        executable: hash,
                    });
                }
                if birth_install_failure || pidfd_install_failure {
                    return Err(Status::Internal);
                }
                if pidfd.is_none() {
                    return Err(Status::Unsupported);
                }
                worker_trace.point(ProcessAssertionPoint::ForkOwnedBeforeExecRelease)?;
                if Instant::now() >= deadline {
                    return Err(Status::Timeout);
                }
                write_byte(&p.barrier_write)?;
                Ok(())
            });
            if startup.is_err() {
                if let Ok(mut state) = worker_state.lock() {
                    state.start_error = startup.err();
                }
            }
            let mut barrier = Some(p.barrier_write);
            if startup.is_err() {
                drop(barrier.take());
            }
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let mut notifications = Vec::new();
            let mut occurrence = 0u32;
            let mut waiting_release = false;
            let mut signaled = false;
            let mut announced = false;
            let mut exec_confirmed = false;
            let mut terminal = None;
            let mut terminal_wait_checkpoint = false;
            let mut wait_fault_observed = false;
            let mut signal_fault_observed = false;
            let mut pidfd_ready_observed = false;
            let mut pidfd_ready_baseline = false;
            let mut eof_wait_started = None;
            loop {
                if signaled && !terminal_wait_checkpoint {
                    let _ = worker_trace.point(ProcessAssertionPoint::SupervisorBeforeWait);
                    terminal_wait_checkpoint = true;
                }
                if signaled && worker_trace.is("D29WaitFailureRetainsOwner") && !wait_fault_observed
                {
                    core_retire(ProcessRetireReason::ChildFault, 0, Status::Internal);
                    worker_trace.inject(
                        ProcessAssertionOperation::Waitpid,
                        ProcessAssertionOrigin::InjectedBeforeSyscall,
                        libc::EIO,
                    );
                    core_retire(ProcessRetireReason::ChildFault, 1, Status::Internal);
                    wait_fault_observed = true;
                    continue;
                }
                if signaled && worker_trace.is("D29PidfdReadyIsNotReap") && !pidfd_ready_observed {
                    if !pidfd_ready_baseline {
                        // The named observation is pidfd readiness, after the
                        // actual signal and unused gate-pipe close. Retain both
                        // earlier native records, then pin all still-required
                        // owners immediately before the first native poll.
                        core_retire(ProcessRetireReason::ChildFault, 0, Status::NotReady);
                        pidfd_ready_baseline = true;
                    }
                    let Some(fd) = &pidfd else {
                        worker_trace.fail_recording();
                        break;
                    };
                    let mut polled = libc::pollfd {
                        fd: fd.raw,
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    let result = unsafe { libc::poll(&mut polled, 1, 2) };
                    worker_trace.syscall(ProcessAssertionSyscall {
                        operation: ProcessAssertionOperation::Poll,
                        origin: ProcessAssertionOrigin::Native,
                        result: result as i64,
                        errno: (result < 0).then(error),
                        sender: None,
                        msg_flags: 0,
                        received_fds: 0,
                        descriptor_id: Some(fd.id),
                        poll_revents: polled.revents as u32,
                        ancillary: Vec::new(),
                        ancillary_descriptor_ids: Vec::new(),
                    });
                    if result > 0 && polled.revents & libc::POLLIN != 0 {
                        core_retire(ProcessRetireReason::ChildFault, 1, Status::NotReady);
                        pidfd_ready_observed = true;
                    }
                    continue;
                }
                if signaled && worker_trace.is("D29EofIsNotReap") && !worker_trace.has_after() {
                    // Retain this sole wait owner while the parent makes the
                    // actual EOF observation on its existing channel. This is
                    // a bounded closed-fixture hold, never a synthetic reap.
                    let start = eof_wait_started.get_or_insert_with(Instant::now);
                    if start.elapsed() < Duration::from_millis(500) && !worker_trace.cancelled() {
                        std::thread::yield_now();
                        continue;
                    }
                    worker_trace.fail_recording();
                }
                let mut native_status = 0;
                let waited = unsafe { libc::waitpid(pid, &mut native_status, libc::WNOHANG) };
                let wait_errno = (waited < 0).then(error);
                worker_trace.call(
                    ProcessAssertionOperation::Waitpid,
                    waited as i64,
                    wait_errno,
                    None,
                );
                if waited == pid {
                    let outcome = if libc::WIFEXITED(native_status) {
                        Some(ProcessWaitOutcome::Exited(libc::WEXITSTATUS(native_status)))
                    } else if libc::WIFSIGNALED(native_status) {
                        Some(ProcessWaitOutcome::Signaled(libc::WTERMSIG(native_status)))
                    } else {
                        None
                    };
                    if let Some(outcome) = outcome {
                        // Native wait does not consume the error pipe. A fast
                        // failed exec can already be reaped with its atomic
                        // errno still queued; observe it before publishing the
                        // terminal decision or a generic disconnection.
                        if startup.is_ok() && !exec_confirmed {
                            let mut errno = 0i32;
                            let count = unsafe {
                                libc::read(p.error_read.raw, (&mut errno as *mut i32).cast(), 4)
                            };
                            let read_errno = (count < 0).then(error);
                            worker_trace.call(
                                ProcessAssertionOperation::Read,
                                count as i64,
                                read_errno,
                                Some(p.error_read.id),
                            );
                            if count > 0 {
                                let failure = record_exec_failure(
                                    &worker_trace,
                                    p.executable.fd.id,
                                    errno,
                                    count,
                                );
                                startup = Err(failure);
                                if let Ok(mut state) = worker_state.lock() {
                                    state.start_error = Some(failure);
                                }
                                if !announced {
                                    let _ = sender.send(Err(failure));
                                    announced = true;
                                }
                            }
                        }
                        worker_trace.process_wait(native_status, outcome);
                        if worker_state
                            .lock()
                            .map_or(true, |s| s.identity.is_none_or(|i| i.birth == 0))
                        {
                            worker_trace.quarantine();
                            if let Ok(mut s) = worker_state.lock() {
                                s.quarantined = true;
                            }
                        }
                        core_retire(
                            ProcessRetireReason::ChildFault,
                            2,
                            startup.err().unwrap_or(Status::Disconnected),
                        );
                        terminal = Some(outcome);
                        break;
                    }
                } else if waited < 0 && wait_errno != Some(libc::EINTR) {
                    worker_trace.quarantine();
                    if let Ok(mut state) = worker_state.lock() {
                        state.quarantined = true;
                    }
                    break;
                }
                if startup.is_ok() && !exec_confirmed {
                    let mut errno = 0i32;
                    let count =
                        unsafe { libc::read(p.error_read.raw, (&mut errno as *mut i32).cast(), 4) };
                    let read_errno = (count < 0).then(error);
                    worker_trace.call(
                        ProcessAssertionOperation::Read,
                        count as i64,
                        read_errno,
                        Some(p.error_read.id),
                    );
                    if count == 0 {
                        if audit_executed(pid, &worker_trace, &p.executable).is_ok() {
                            exec_confirmed = true;
                            if !announced {
                                let _ = sender.send(Ok(()));
                                announced = true;
                            }
                        }
                    } else if count > 0 {
                        let failure =
                            record_exec_failure(&worker_trace, p.executable.fd.id, errno, count);
                        startup = Err(failure);
                        if let Ok(mut state) = worker_state.lock() {
                            state.start_error = Some(failure);
                        }
                        if !announced {
                            let _ = sender.send(Err(failure));
                            announced = true;
                        }
                    }
                }
                if startup.is_err() && !announced {
                    let _ = sender.send(Err(startup.err().unwrap()));
                    announced = true;
                }
                for (fd, output) in [(&p.stdout_read, &mut stdout), (&p.stderr_read, &mut stderr)] {
                    let mut buffer = [0u8; 4096];
                    let remaining = (16385usize).saturating_sub(output.len()).min(buffer.len());
                    if remaining == 0 {
                        continue;
                    }
                    let count =
                        unsafe { libc::read(fd.raw, buffer.as_mut_ptr().cast(), remaining) };
                    let errno = (count < 0).then(error);
                    worker_trace.call(
                        ProcessAssertionOperation::Read,
                        count as i64,
                        errno,
                        Some(fd.id),
                    );
                    if count > 0 {
                        output.extend_from_slice(&buffer[..count as usize]);
                        if output.len() > 16384 {
                            let _ = worker_trace.object(fd.id, &output[..16384]);
                            let _ = worker_trace.object(fd.id, output);
                            worker_retire.store(2, Ordering::Release);
                            startup = Err(Status::Exhausted);
                        }
                        if let Some(case) = assertion.filter(|case| {
                            fd.role == ProcessAssertionDescriptorRole::Stdout
                                && !matches!(*case, "D25StdoutCapPlusOne" | "D25StderrCapPlusOne")
                        }) {
                            notifications.extend_from_slice(&buffer[..count as usize]);
                            while notifications.len() >= 32 && !waiting_release {
                                let mut frame = [0u8; 32];
                                frame.copy_from_slice(&notifications[..32]);
                                notifications.drain(..32);
                                let expected: [u8; 32] = Sha256::digest(case.as_bytes()).into();
                                let version = u32::from_le_bytes(frame[4..8].try_into().unwrap());
                                let code = u32::from_le_bytes(frame[8..12].try_into().unwrap());
                                let next = u32::from_le_bytes(frame[12..16].try_into().unwrap());
                                if &frame[..4] != b"RPF0"
                                    || version != 1
                                    || next != occurrence.checked_add(1).unwrap_or(0)
                                    || next == 0
                                    || frame[16..] != expected[..16]
                                    || !matches!(code, 5 | 6)
                                {
                                    startup = Err(Status::Invalid);
                                    worker_retire.store(2, Ordering::Release);
                                    break;
                                }
                                occurrence = next;
                                let point = if code == 5 {
                                    ProcessAssertionPoint::InputReceivedBeforeAck
                                } else {
                                    ProcessAssertionPoint::OfferMappedBeforeSeal
                                };
                                match worker_trace.child_point(point) {
                                    Ok(()) => waiting_release = true,
                                    Err(_) => {
                                        worker_retire.store(2, Ordering::Release);
                                    }
                                }
                            }
                        }
                    }
                }
                if waiting_release && worker_trace.child_released() {
                    if let Some(fd) = &barrier {
                        if write_byte(fd).is_err() {
                            worker_retire.store(2, Ordering::Release);
                        }
                    }
                    waiting_release = false;
                }
                let expired = Instant::now() >= deadline;
                if !signaled
                    && (expired
                        || worker_retire.load(Ordering::Acquire) != 0
                        || startup.is_err()
                        || worker_trace.cancelled())
                {
                    core_retire(
                        if expired {
                            ProcessRetireReason::Deadline
                        } else {
                            ProcessRetireReason::ChildFault
                        },
                        0,
                        startup.err().unwrap_or(if expired {
                            Status::Timeout
                        } else {
                            Status::Disconnected
                        }),
                    );
                    let _ = worker_trace.point(ProcessAssertionPoint::SupervisorBeforeSignal);
                    if worker_trace.is("D29SignalFailureRetainsOwner") && !signal_fault_observed {
                        worker_trace.inject(
                            ProcessAssertionOperation::Signal,
                            ProcessAssertionOrigin::InjectedBeforeSyscall,
                            libc::EIO,
                        );
                        core_retire(ProcessRetireReason::ChildFault, 1, Status::Internal);
                        signal_fault_observed = true;
                        continue;
                    }
                    if let Some(pidfd) = &pidfd {
                        let result = unsafe {
                            libc::syscall(
                                libc::SYS_pidfd_send_signal,
                                pidfd.raw,
                                libc::SIGKILL,
                                std::ptr::null::<libc::siginfo_t>(),
                                0,
                            ) as i32
                        };
                        let errno = (result < 0).then(error);
                        worker_trace.call(
                            ProcessAssertionOperation::Signal,
                            result as i64,
                            errno,
                            Some(pidfd.id),
                        );
                        if result == 0 || errno == Some(libc::ESRCH) {
                            signaled = true;
                        }
                    }
                    drop(barrier.take());
                }
                let mut pollfds = [
                    libc::pollfd {
                        fd: p.stdout_read.raw,
                        events: libc::POLLIN,
                        revents: 0,
                    },
                    libc::pollfd {
                        fd: p.stderr_read.raw,
                        events: libc::POLLIN,
                        revents: 0,
                    },
                ];
                let result = unsafe { libc::poll(pollfds.as_mut_ptr(), 2, 2) };
                worker_trace.syscall(ProcessAssertionSyscall {
                    operation: ProcessAssertionOperation::Poll,
                    origin: ProcessAssertionOrigin::Native,
                    result: result as i64,
                    errno: (result < 0).then(error),
                    sender: None,
                    msg_flags: 0,
                    received_fds: 0,
                    descriptor_id: None,
                    poll_revents: (pollfds[0].revents | pollfds[1].revents) as u32,
                    ancillary: Vec::new(),
                    ancillary_descriptor_ids: Vec::new(),
                });
            }
            let drain_end = Instant::now() + Duration::from_millis(2000);
            for (fd, output) in [(&p.stdout_read, &mut stdout), (&p.stderr_read, &mut stderr)] {
                loop {
                    let mut bytes = [0u8; 4096];
                    let count =
                        unsafe { libc::read(fd.raw, bytes.as_mut_ptr().cast(), bytes.len()) };
                    let errno = (count < 0).then(error);
                    worker_trace.call(
                        ProcessAssertionOperation::Read,
                        count as i64,
                        errno,
                        Some(fd.id),
                    );
                    if count == 0 {
                        let _ = worker_trace.object(fd.id, output);
                        break;
                    }
                    if count > 0 {
                        let retain = 16385usize.saturating_sub(output.len()).min(count as usize);
                        output.extend_from_slice(&bytes[..retain]);
                        if fd.role == ProcessAssertionDescriptorRole::Stdout
                            && assertion.is_some()
                            && !assertion.is_some_and(|s| {
                                matches!(s, "D25StdoutCapPlusOne" | "D25StderrCapPlusOne")
                            })
                        {
                            notifications.extend_from_slice(&bytes[..count as usize]);
                        }
                        if retain < count as usize {
                            worker_trace.fail_recording();
                        }
                        if output.len() > 16384 {
                            let _ = worker_trace.object(fd.id, &output[..16384]);
                            let _ = worker_trace.object(fd.id, output);
                            startup = Err(Status::Exhausted);
                        }
                        continue;
                    }
                    if !matches!(errno, Some(libc::EINTR | libc::EAGAIN))
                        || Instant::now() >= drain_end
                    {
                        worker_trace.quarantine();
                        if let Ok(mut s) = worker_state.lock() {
                            s.quarantined = true;
                        }
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
            // A late complete notification is validated as an observation,
            // never exposed as a still-blocked/live child checkpoint after wait.
            while notifications.len() >= 32 {
                let frame = &notifications[..32];
                let expected: [u8; 32] = Sha256::digest(assertion.unwrap_or("").as_bytes()).into();
                let version = u32::from_le_bytes(frame[4..8].try_into().unwrap());
                let code = u32::from_le_bytes(frame[8..12].try_into().unwrap());
                let next = u32::from_le_bytes(frame[12..16].try_into().unwrap());
                if &frame[..4] != b"RPF0"
                    || version != 1
                    || next == 0
                    || Some(next) != occurrence.checked_add(1)
                    || frame[16..] != expected[..16]
                    || !matches!(code, 5 | 6)
                {
                    worker_trace.fail_recording();
                    break;
                }
                let point = if code == 5 {
                    ProcessAssertionPoint::InputReceivedBeforeAck
                } else {
                    ProcessAssertionPoint::OfferMappedBeforeSeal
                };
                if worker_trace.child_observation_after_wait(point).is_err() {
                    worker_trace.fail_recording();
                    break;
                }
                occurrence = next;
                notifications.drain(..32);
            }
            if !notifications.is_empty() {
                worker_trace.fail_recording();
            }
            if let Some(outcome) = terminal {
                core_retire(
                    ProcessRetireReason::ChildFault,
                    1,
                    startup.err().unwrap_or(if Instant::now() >= deadline {
                        Status::Timeout
                    } else {
                        Status::Disconnected
                    }),
                );
                worker_trace.terminal(outcome);
                if let Ok(mut state) = worker_state.lock() {
                    state.outcome = Some(outcome);
                }
                let _ = worker_trace.point(ProcessAssertionPoint::SupervisorTerminalBeforeJoin);
            }
            if !announced {
                let _ = sender.send(Err(Status::Disconnected));
            }
            drop((
                barrier,
                p.error_read,
                p.stdout_read,
                p.stderr_read,
                p.executable,
                pidfd,
            ));
        });
    let handle = match handle {
        Ok(handle) => handle,
        Err(_) => {
            let p = staged
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
                .expect("failed thread retains staged native launch");
            return Err(StartFailure::Unspawned(
                Status::Internal,
                p.executable,
                p.control,
            ));
        }
    };
    trace.started();
    {
        let mut ready = start_gate.0.lock().unwrap_or_else(|e| e.into_inner());
        *ready = true;
        start_gate.1.notify_all();
    }
    let supervisor = Supervisor {
        state,
        retire,
        handle: Some(handle),
        trace: trace.clone(),
    };
    loop {
        match receiver.try_recv() {
            Ok(Ok(())) => return Ok(supervisor),
            Ok(Err(e)) => {
                if let Some((e, exe, control)) =
                    failed.lock().unwrap_or_else(|e| e.into_inner()).take()
                {
                    let mut supervisor = supervisor;
                    if let Some(handle) = supervisor.handle.take() {
                        let _ = handle.join();
                    }
                    return Err(StartFailure::Unspawned(e, exe, control));
                }
                return Err(StartFailure::Spawned(e, supervisor));
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                return Err(StartFailure::Spawned(Status::Internal, supervisor));
            }
            Err(mpsc::TryRecvError::Empty) => {
                if Instant::now() >= deadline {
                    return Err(StartFailure::Spawned(Status::Timeout, supervisor));
                }
                std::thread::yield_now();
            }
        }
    }
}
fn write_byte(fd: &Fd) -> Result<(), Status> {
    let byte = 1u8;
    loop {
        let result = unsafe { libc::write(fd.raw, (&byte as *const u8).cast(), 1) };
        let errno = (result < 0).then(error);
        fd.trace.call(
            ProcessAssertionOperation::Write,
            result as i64,
            errno,
            Some(fd.id),
        );
        if result == 1 {
            return Ok(());
        }
        if errno == Some(libc::EINTR) {
            continue;
        }
        return Err(status(errno.unwrap_or(libc::EIO)));
    }
}
pub(super) struct SelectedMap {
    address: *mut libc::c_void,
    length: usize,
    id: u64,
    trace: Trace,
}
pub(super) fn validate_selected(fd: &Fd, genuine: &[u8]) -> Result<(), Status> {
    if !(64..=4160).contains(&genuine.len())
        || fd.stat()?.st_size != genuine.len() as i64
        || fd.seals()? & SEALS != SEALS
    {
        return Err(Status::Invalid);
    }
    let mut actual = vec![0; genuine.len()];
    fd.read_at(&mut actual, 0)?;
    if actual != genuine {
        return Err(Status::Denied);
    }
    Ok(())
}
unsafe impl Send for SelectedMap {}
pub(super) fn map_selected(fd: &Fd, length: usize) -> Result<SelectedMap, Status> {
    if length == 0
        || length > 4160
        || fd.seals()? & SEALS != SEALS
        || fd.stat()?.st_size != length as i64
    {
        return Err(Status::Invalid);
    }
    fd.trace.reserve_map()?;
    let address = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            length,
            libc::PROT_READ,
            libc::MAP_SHARED,
            fd.raw,
            0,
        )
    };
    let failed = address == libc::MAP_FAILED;
    fd.trace.call(
        ProcessAssertionOperation::Mmap,
        if failed { -1 } else { 0 },
        failed.then(error),
        Some(fd.id),
    );
    if failed {
        fd.trace.release_map();
        return Err(Status::Internal);
    }
    fd.trace.disposition(
        fd.id,
        ProcessAssertionDisposition::Held,
        Some(ProcessAssertionMapping::ReadOnly),
    );
    Ok(SelectedMap {
        address,
        length,
        id: fd.id,
        trace: fd.trace.clone(),
    })
}
impl Drop for SelectedMap {
    fn drop(&mut self) {
        let result = unsafe { libc::munmap(self.address, self.length) };
        self.trace.call(
            ProcessAssertionOperation::Munmap,
            result as i64,
            (result < 0).then(error),
            Some(self.id),
        );
        if result == 0 {
            self.trace.disposition(
                self.id,
                ProcessAssertionDisposition::Held,
                Some(ProcessAssertionMapping::Unmapped),
            );
            self.trace.release_map();
        } else {
            self.trace
                .retain_uncertain(self.id, None, Some((self.address as usize, self.length)));
        }
    }
}
/// Actual bounded pread captures are diagnostics only. They are performed even
/// for rejected/unsealed/short objects; they can never become an adopted map.
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
pub(super) fn capture_received(
    packet: &mut Received,
    owner: Option<u32>,
    offer: Option<u64>,
) -> Result<(), Status> {
    if packet
        .fds
        .first()
        .is_none_or(|fd| fd.trace.scenario().is_none())
    {
        return Ok(());
    }
    for (index, fd) in packet.fds.iter_mut().enumerate() {
        fd.role = if index == 0 {
            ProcessAssertionDescriptorRole::TextState
        } else {
            ProcessAssertionDescriptorRole::Surface
        };
        fd.mark(
            owner,
            offer,
            ProcessAssertionDescriptorEvent::Returned,
            ProcessAssertionDisposition::Received,
        )?;
        let st = fd.stat()?;
        if st.st_mode & libc::S_IFMT != libc::S_IFREG
            || st.st_size < 0
            || st.st_size as usize > desktop_editor_core::FRAME_BYTES + 1
        {
            continue;
        }
        let mut bytes = vec![0; st.st_size as usize];
        fd.read_at(&mut bytes, 0)?;
        fd.trace.object(fd.id, &bytes)?;
    }
    Ok(())
}
impl Fd {
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    fn fact(&self) -> Result<ProcessAssertionDescriptor, Status> {
        let st = self.stat()?;
        Ok(ProcessAssertionDescriptor {
            role: self.role,
            descriptor_id: self.id,
            device: st.st_dev,
            inode: st.st_ino,
            byte_len: st.st_size.max(0) as u64,
            mode: st.st_mode,
            seals: self.seals().unwrap_or(0) as u32,
            owner_process_id: None,
            offer_id: None,
            event: ProcessAssertionDescriptorEvent::Other,
            mapping: ProcessAssertionMapping::None,
            disposition: ProcessAssertionDisposition::Held,
        })
    }
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    pub(super) fn project(
        &self,
        trace: &Trace,
        owner: Option<u32>,
        offer: Option<u64>,
    ) -> Result<(), Status> {
        let st = self.stat()?;
        trace.descriptor(ProcessAssertionDescriptor {
            role: self.role,
            descriptor_id: self.id,
            device: st.st_dev,
            inode: st.st_ino,
            byte_len: st.st_size.max(0) as u64,
            mode: st.st_mode,
            seals: self.seals()? as u32,
            owner_process_id: owner,
            offer_id: offer,
            event: ProcessAssertionDescriptorEvent::Offered,
            mapping: ProcessAssertionMapping::None,
            disposition: ProcessAssertionDisposition::Held,
        })?;
        Ok(())
    }
    /// Actual parent-owned alias charged to its authentic source transport.
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    pub(super) fn duplicate(&self) -> Result<Fd, Status> {
        self.trace.reserve_fd(self.data, 0, false)?;
        let raw = unsafe { libc::fcntl(self.raw, libc::F_DUPFD_CLOEXEC, 16) };
        self.trace.call(
            ProcessAssertionOperation::DuplicateFd,
            if raw < 0 { -1 } else { 0 },
            (raw < 0).then(error),
            Some(self.id),
        );
        if raw < 0 {
            self.trace.release_fd(self.data);
            return Err(Status::Internal);
        }
        Fd::adopt(raw, self.role, &self.trace, true)
    }
}

#[cfg(feature = "host_editor_process_assertions_v0_dev")]
pub(super) struct ForkHelperReport {
    pub(super) process: RecordedProcess,
    pub(super) syscall_indices: Vec<usize>,
    pub(super) descriptor: ProcessAssertionDescriptor,
}
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
pub(super) struct ForkHelper {
    handle: Option<JoinHandle<Result<ForkHelperReport, Status>>>,
    trace: Trace,
}
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
impl ForkHelper {
    pub(super) fn try_join(&mut self) -> Result<ForkHelperReport, Status> {
        if !self.handle.as_ref().is_some_and(JoinHandle::is_finished) {
            return Err(Status::NotReady);
        }
        let handle = self.handle.take().ok_or(Status::Stale)?;
        let result = handle.join().map_err(|_| Status::Internal);
        self.trace.helper_joined();
        match result {
            Ok(Ok(mut report)) if !self.trace.quarantined() => {
                report.process.supervisor_joined = true;
                Ok(report)
            }
            _ => {
                self.trace.quarantine();
                Err(Status::Internal)
            }
        }
    }
}
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
impl Drop for ForkHelper {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            std::mem::forget(handle);
            self.trace.quarantine();
        }
    }
}
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
pub(super) fn peer_credentials(socket: &Fd) -> Result<((u32, u32, u32), usize), Status> {
    let mut peer = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            socket.raw,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            peer.as_mut_ptr().cast(),
            &mut length,
        )
    };
    let peer = if result == 0 && length as usize == std::mem::size_of::<libc::ucred>() {
        let peer = unsafe { peer.assume_init() };
        Some((peer.pid as u32, peer.uid, peer.gid))
    } else {
        None
    };
    let index = socket.trace.syscall(ProcessAssertionSyscall {
        operation: ProcessAssertionOperation::PeerCredentials,
        origin: ProcessAssertionOrigin::Native,
        result: result as i64,
        errno: (result < 0).then(error),
        // For this descriptive getsockopt row only, this is the actual
        // returned creation peer. It is never received SCM_CREDENTIALS.
        sender: peer,
        msg_flags: 0,
        received_fds: 0,
        descriptor_id: Some(socket.id),
        poll_revents: 0,
        ancillary: Vec::new(),
        ancillary_descriptor_ids: Vec::new(),
    });
    Ok((peer.ok_or(Status::Internal)?, index))
}
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
pub(super) fn start_fork_helper(
    endpoint: Fd,
    bytes: [u8; 88],
    trace: &Trace,
) -> Result<ForkHelper, (Status, Fd)> {
    // Reserve the actual Rust supervisor footprint before thread creation;
    // the roster's independent helper slot was already reserved by caller.
    if let Err(status) = trace.helper_started() {
        return Err((status, endpoint));
    }
    let staged = Arc::new(Mutex::new(Some(endpoint)));
    let work = staged.clone();
    let worker_trace = trace.clone();
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let worker_gate = gate.clone();
    let handle = match std::thread::Builder::new()
        .name("ramen-assertion-fork-helper".to_owned())
        .spawn(move || {
            let mut ready = worker_gate.0.lock().unwrap_or_else(|e| e.into_inner());
            while !*ready {
                ready = worker_gate.1.wait(ready).unwrap_or_else(|e| e.into_inner());
            }
            drop(ready);
            let endpoint = work
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
                .ok_or(Status::Internal)?;
            let mut fact = endpoint.fact()?;
            let parent = unsafe { libc::getpid() };
            let mut process = RecordedProcess {
                parent_pid: parent as u32,
                child_pid: None,
                birth_ticks: None,
                pidfd_ledger_id: None,
                supervisor_native_tid: unsafe { libc::syscall(libc::SYS_gettid) } as u32,
                supervisor_rust_id: format!("{:?}", std::thread::current().id()),
                wait_raw_status: None,
                wait_outcome: None,
                supervisor_joined: false,
                quarantined: false,
            };
            // Prepare every pointer before fork. The child performs only the
            // async-safe native descriptor plan, one copied send and _exit.
            let mut iov = libc::iovec {
                iov_base: bytes.as_ptr().cast_mut().cast(),
                iov_len: 88,
            };
            let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
            message.msg_iov = &mut iov;
            message.msg_iovlen = 1;
            worker_trace.reserve_helper_child()?;
            let pid = unsafe { libc::fork() };
            if pid == 0 {
                unsafe {
                    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                        || libc::getppid() != parent
                    {
                        libc::_exit(70);
                    }
                    if libc::dup2(endpoint.raw, 3) < 0
                        || libc::syscall(libc::SYS_close_range, 4u32, u32::MAX, 0u32) < 0
                    {
                        libc::_exit(72);
                    }
                    loop {
                        let sent =
                            libc::sendmsg(3, &message, libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL);
                        if sent == 88 {
                            libc::_exit(0);
                        }
                        if sent < 0 && *libc::__errno_location() == libc::EINTR {
                            continue;
                        }
                        libc::_exit(71);
                    }
                }
            }
            let mut indices = vec![worker_trace.syscall(ProcessAssertionSyscall {
                operation: ProcessAssertionOperation::Fork,
                origin: ProcessAssertionOrigin::Native,
                result: pid as i64,
                errno: (pid < 0).then(error),
                sender: None,
                msg_flags: 0,
                received_fds: 0,
                descriptor_id: None,
                poll_revents: 0,
                ancillary: Vec::new(),
                ancillary_descriptor_ids: Vec::new(),
            })];
            if pid < 0 {
                worker_trace.helper_waited();
                return Err(Status::Internal);
            }
            process.child_pid = Some(pid as u32);
            process.birth_ticks = birth(pid, &worker_trace).ok();
            loop {
                let mut raw = 0;
                let waited = unsafe { libc::waitpid(pid, &mut raw, 0) };
                let errno = (waited < 0).then(error);
                let index = worker_trace.syscall(ProcessAssertionSyscall {
                    operation: ProcessAssertionOperation::Waitpid,
                    origin: ProcessAssertionOrigin::Native,
                    result: waited as i64,
                    errno,
                    sender: None,
                    msg_flags: 0,
                    received_fds: 0,
                    descriptor_id: None,
                    poll_revents: 0,
                    ancillary: Vec::new(),
                    ancillary_descriptor_ids: Vec::new(),
                });
                if indices.len() < 62 {
                    indices.push(index);
                } else {
                    // Bound the descriptive projection without abandoning
                    // this thread's actual native cleanup responsibility.
                    worker_trace.fail_recording();
                }
                if waited == pid && (libc::WIFEXITED(raw) || libc::WIFSIGNALED(raw)) {
                    process.wait_raw_status = Some(raw);
                    process.wait_outcome = Some(if libc::WIFEXITED(raw) {
                        ProcessWaitOutcome::Exited(libc::WEXITSTATUS(raw))
                    } else {
                        ProcessWaitOutcome::Signaled(libc::WTERMSIG(raw))
                    });
                    worker_trace.helper_waited();
                    break;
                }
                if errno != Some(libc::EINTR) {
                    worker_trace.quarantine();
                    // Keep the same native wait owner and endpoint staged on an
                    // uncertain wait. No second waiter or numeric-PID fallback.
                    loop {
                        std::thread::park_timeout(Duration::from_secs(1));
                    }
                }
            }
            let id = endpoint.id;
            drop(endpoint);
            if let Some(close) = worker_trace.native_close_index(id) {
                indices.push(close);
                fact.disposition = ProcessAssertionDisposition::Closed;
            } else {
                return Err(Status::Internal);
            }
            if process.birth_ticks.is_none()
                || process.wait_outcome != Some(ProcessWaitOutcome::Exited(0))
            {
                return Err(Status::Internal);
            }
            Ok(ForkHelperReport {
                process,
                syscall_indices: indices,
                descriptor: fact,
            })
        }) {
        Ok(handle) => handle,
        Err(_) => {
            trace.helper_joined();
            return Err((
                Status::Internal,
                staged
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take()
                    .unwrap(),
            ));
        }
    };
    *gate.0.lock().unwrap_or_else(|e| e.into_inner()) = true;
    gate.1.notify_all();
    Ok(ForkHelper {
        handle: Some(handle),
        trace: trace.clone(),
    })
}
