//! Native Linux prerequisite witnesses for the frozen editor-process contract.
//!
//! These tests exercise actual Linux mappings, seals and ancillary records. They
//! do not call an editor carrier, accept a publication or qualify a D-family.
//! The full process assertions still require the reviewed private handoff.
#![cfg(target_os = "linux")]

use std::{
    ffi::CString,
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    ptr::NonNull,
};

const ALL_SEALS: i32 =
    libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
const PAGE: usize = 4096;

fn error() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap()
}

fn memfd(name: &str) -> OwnedFd {
    let name = CString::new(name).unwrap();
    let raw =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    assert!(raw >= 0, "memfd_create: {}", io::Error::last_os_error());
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    assert_eq!(unsafe { libc::ftruncate(raw, PAGE as libc::off_t) }, 0);
    fd
}

struct Mapping {
    address: NonNull<libc::c_void>,
    bytes: usize,
}

impl Mapping {
    fn shared(fd: &OwnedFd, writable: bool) -> Self {
        let protection = libc::PROT_READ | if writable { libc::PROT_WRITE } else { 0 };
        let raw = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE,
                protection,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        assert_ne!(
            raw,
            libc::MAP_FAILED,
            "mmap: {}",
            io::Error::last_os_error()
        );
        Self {
            address: NonNull::new(raw).unwrap(),
            bytes: PAGE,
        }
    }

    fn write(&mut self, byte: u8) {
        unsafe { self.address.as_ptr().cast::<u8>().write_volatile(byte) };
    }

    fn first(&self) -> u8 {
        unsafe { self.address.as_ptr().cast::<u8>().read_volatile() }
    }

    fn protect_read_only(&mut self) {
        assert_eq!(
            unsafe { libc::mprotect(self.address.as_ptr(), self.bytes, libc::PROT_READ) },
            0
        );
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        assert_eq!(
            unsafe { libc::munmap(self.address.as_ptr(), self.bytes) },
            0
        );
    }
}

fn seals(fd: &OwnedFd) -> i32 {
    let result = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS) };
    assert!(result >= 0);
    result
}

fn add_seals(fd: &OwnedFd, requested: i32) -> Result<(), i32> {
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_ADD_SEALS, requested) } == 0 {
        Ok(())
    } else {
        Err(error())
    }
}

fn assert_mutations_denied(fd: &OwnedFd, expected: u8) {
    let byte = [expected.wrapping_add(1)];
    assert_eq!(
        unsafe { libc::pwrite(fd.as_raw_fd(), byte.as_ptr().cast(), 1, 0) },
        -1
    );
    assert_eq!(error(), libc::EPERM);
    for size in [(PAGE - 1) as libc::off_t, (PAGE + 1) as libc::off_t] {
        assert_eq!(unsafe { libc::ftruncate(fd.as_raw_fd(), size) }, -1);
        assert_eq!(error(), libc::EPERM);
    }
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    assert_eq!(unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) }, 0);
    assert_eq!(unsafe { stat.assume_init() }.st_size, PAGE as libc::off_t);
    let mapping = Mapping::shared(fd, false);
    assert_eq!(mapping.first(), expected);
    assert_eq!(seals(fd) & ALL_SEALS, ALL_SEALS);
    eprintln!(
        "immutable fd={} seals={:#x} bytes={} first={expected}",
        fd.as_raw_fd(),
        seals(fd),
        PAGE
    );
}

#[test]
fn process_linux_prerequisite_write_seal_rejects_writable_and_mprotected_aliases() {
    let fd = memfd("process-prerequisite-write-alias");
    let mut map = Mapping::shared(&fd, true);
    map.write(0x41);
    assert_eq!(add_seals(&fd, ALL_SEALS), Err(libc::EBUSY));
    assert_eq!(
        seals(&fd),
        0,
        "failed atomic seal operation must not pretend immutability"
    );
    map.protect_read_only();
    assert_eq!(add_seals(&fd, ALL_SEALS), Err(libc::EBUSY));
    assert_eq!(
        seals(&fd),
        0,
        "mprotect does not remove the retained writable mapping"
    );
    drop(map);
    assert_eq!(add_seals(&fd, ALL_SEALS), Ok(()));
    assert_mutations_denied(&fd, 0x41);
}

#[test]
fn process_linux_prerequisite_future_write_does_not_freeze_existing_alias() {
    let fd = memfd("process-prerequisite-future-write");
    let mut map = Mapping::shared(&fd, true);
    map.write(0x41);
    assert_eq!(add_seals(&fd, libc::F_SEAL_FUTURE_WRITE), Ok(()));
    assert_eq!(seals(&fd) & libc::F_SEAL_WRITE, 0);
    map.write(0x42);
    assert_eq!(
        map.first(),
        0x42,
        "existing writable mapping survives FUTURE_WRITE"
    );
    assert_eq!(add_seals(&fd, libc::F_SEAL_WRITE), Err(libc::EBUSY));
    drop(map);
    assert_eq!(add_seals(&fd, ALL_SEALS), Ok(()));
    assert_mutations_denied(&fd, 0x42);
}

#[test]
fn process_linux_prerequisite_all_write_aliases_close_before_complete_immutable_pair() {
    let pair = [
        memfd("process-prerequisite-text"),
        memfd("process-prerequisite-surface"),
    ];
    for (index, fd) in pair.iter().enumerate() {
        let mut first = Mapping::shared(fd, true);
        let second = Mapping::shared(fd, true);
        first.write(0x51 + index as u8);
        assert_eq!(second.first(), 0x51 + index as u8);
        drop(first);
        assert_eq!(add_seals(fd, ALL_SEALS), Err(libc::EBUSY));
        drop(second);
        assert_eq!(add_seals(fd, ALL_SEALS), Ok(()));
        assert_mutations_denied(fd, 0x51 + index as u8);
    }
    let identity = |fd: &OwnedFd| {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        assert_eq!(unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) }, 0);
        let stat = unsafe { stat.assume_init() };
        (stat.st_dev, stat.st_ino)
    };
    assert_ne!(identity(&pair[0]), identity(&pair[1]));
}

const FRAME: [u8; 88] = [0x33; 88];

fn socket_pair() -> [OwnedFd; 2] {
    let mut raw = [-1; 2];
    assert_eq!(
        unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                raw.as_mut_ptr(),
            )
        },
        0
    );
    let pair = unsafe { [OwnedFd::from_raw_fd(raw[0]), OwnedFd::from_raw_fd(raw[1])] };
    let enable: libc::c_int = 1;
    assert_eq!(
        unsafe {
            libc::setsockopt(
                pair[0].as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PASSCRED,
                (&enable as *const libc::c_int).cast(),
                std::mem::size_of_val(&enable) as libc::socklen_t,
            )
        },
        0
    );
    pair
}

fn send(
    socket: RawFd,
    bytes: &[u8],
    rights: &[RawFd],
    credential: Option<libc::ucred>,
) -> Result<usize, i32> {
    // usize storage guarantees cmsghdr alignment. No receiver trusts this
    // sender-side inventory; every actual received alias gets its own owner.
    let mut control = [0usize; 32];
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    let mut used = 0usize;
    if let Some(credential) = credential {
        let header = control.as_mut_ptr().cast::<libc::cmsghdr>();
        unsafe {
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_CREDENTIALS;
            (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::ucred>() as u32) as usize;
            std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<libc::ucred>(), credential);
            used += libc::CMSG_SPACE(std::mem::size_of::<libc::ucred>() as u32) as usize;
        }
    }
    if !rights.is_empty() {
        let size = std::mem::size_of_val(rights);
        assert!(
            used + unsafe { libc::CMSG_SPACE(size as u32) } as usize
                <= std::mem::size_of_val(&control)
        );
        let header = unsafe {
            control
                .as_mut_ptr()
                .cast::<u8>()
                .add(used)
                .cast::<libc::cmsghdr>()
        };
        unsafe {
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(size as u32) as usize;
            std::ptr::copy_nonoverlapping(
                rights.as_ptr().cast::<u8>(),
                libc::CMSG_DATA(header),
                size,
            );
            used += libc::CMSG_SPACE(size as u32) as usize;
        }
    }
    if used > 0 {
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = used;
    }
    let sent = unsafe { libc::sendmsg(socket, &message, libc::MSG_NOSIGNAL) };
    if sent < 0 {
        Err(error())
    } else {
        Ok(sent as usize)
    }
}

struct Received {
    bytes: Vec<u8>,
    flags: i32,
    credentials: Vec<libc::ucred>,
    rights: Vec<OwnedFd>,
}

fn receive(socket: RawFd, data_capacity: usize, control_capacity: usize) -> Received {
    let mut ready = libc::pollfd {
        fd: socket,
        events: libc::POLLIN,
        revents: 0,
    };
    assert_eq!(
        unsafe { libc::poll(&mut ready, 1, 1000) },
        1,
        "bounded ancillary witness receive"
    );
    let mut bytes = vec![0; data_capacity];
    let mut control = [0usize; 32];
    assert!(control_capacity <= std::mem::size_of_val(&control));
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control_capacity;
    let count = unsafe { libc::recvmsg(socket, &mut message, libc::MSG_CMSG_CLOEXEC) };
    assert!(count >= 0, "recvmsg: {}", io::Error::last_os_error());
    bytes.truncate(count as usize);
    let mut received = Received {
        bytes,
        flags: message.msg_flags,
        credentials: Vec::new(),
        rights: Vec::new(),
    };
    let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    while !header.is_null() {
        let level = unsafe { (*header).cmsg_level };
        let kind = unsafe { (*header).cmsg_type };
        let length = unsafe { (*header).cmsg_len };
        let base = unsafe { libc::CMSG_LEN(0) } as usize;
        assert!(length >= base);
        if level == libc::SOL_SOCKET && kind == libc::SCM_RIGHTS {
            let length = length - base;
            assert_eq!(length % std::mem::size_of::<RawFd>(), 0);
            for index in 0..length / std::mem::size_of::<RawFd>() {
                let raw = unsafe {
                    std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<RawFd>().add(index))
                };
                received.rights.push(unsafe { OwnedFd::from_raw_fd(raw) });
            }
        } else if level == libc::SOL_SOCKET && kind == libc::SCM_CREDENTIALS {
            assert_eq!(length - base, std::mem::size_of::<libc::ucred>());
            received.credentials.push(unsafe {
                std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::ucred>())
            });
        } else {
            panic!("unexpected native ancillary record {level}/{kind}");
        }
        header = unsafe { libc::CMSG_NXTHDR(&message, header) };
    }
    received
}

fn assert_received_cloexec_and_close(received: Received) {
    let raw: Vec<_> = received.rights.iter().map(AsRawFd::as_raw_fd).collect();
    for &fd in &raw {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(flags >= 0 && flags & libc::FD_CLOEXEC != 0);
    }
    drop(received);
    for fd in raw {
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
        assert_eq!(error(), libc::EBADF);
    }
}

#[test]
fn process_linux_prerequisite_ancillary_truncation_owns_only_received_aliases() {
    let pair = socket_pair();
    let originals: Vec<_> = (0..8)
        .map(|_| memfd("process-prerequisite-ancillary"))
        .collect();
    let raw: Vec<_> = originals.iter().map(AsRawFd::as_raw_fd).collect();
    // Correct native transport control, followed by independently observable
    // data and ancillary truncation. No editor decoder is claimed here.
    assert_eq!(
        send(pair[1].as_raw_fd(), &FRAME, &raw[..2], None),
        Ok(FRAME.len())
    );
    let correct = receive(pair[0].as_raw_fd(), FRAME.len(), 256);
    assert_eq!(correct.bytes, FRAME);
    assert_eq!(correct.flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC), 0);
    assert_eq!(correct.credentials.len(), 1);
    assert_eq!(correct.credentials[0].pid, unsafe { libc::getpid() });
    assert_eq!(correct.rights.len(), 2);
    assert_received_cloexec_and_close(correct);

    assert_eq!(
        send(pair[1].as_raw_fd(), &[0x44; 89], &raw[..2], None),
        Ok(89)
    );
    let truncated = receive(pair[0].as_raw_fd(), FRAME.len(), 256);
    assert_eq!(truncated.flags & libc::MSG_TRUNC, libc::MSG_TRUNC);
    assert_eq!(truncated.bytes.len(), 88);
    assert_eq!(truncated.rights.len(), 2);
    assert_received_cloexec_and_close(truncated);

    assert_eq!(
        send(pair[1].as_raw_fd(), &FRAME, &raw, None),
        Ok(FRAME.len())
    );
    let capacity = unsafe {
        libc::CMSG_SPACE(std::mem::size_of::<libc::ucred>() as u32)
            + libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32)
    } as usize;
    let truncated = receive(pair[0].as_raw_fd(), FRAME.len(), capacity);
    assert_eq!(truncated.flags & libc::MSG_CTRUNC, libc::MSG_CTRUNC);
    assert!(truncated.rights.len() < originals.len());
    eprintln!(
        "MSG_CTRUNC actual_received_aliases={} sent={} kernel_discarded_not_claimed_closed",
        truncated.rights.len(),
        originals.len()
    );
    assert_received_cloexec_and_close(truncated);
    // SCM_RIGHTS duplicates ownership; denial must not close the sender's FDs.
    for fd in originals {
        assert!(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) } >= 0);
    }
    assert_eq!(
        send(pair[1].as_raw_fd(), &FRAME, &[], None),
        Ok(FRAME.len())
    );
    let fresh = receive(pair[0].as_raw_fd(), FRAME.len(), 256);
    assert_eq!(fresh.flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC), 0);
    assert_eq!(fresh.credentials.len(), 1);
    assert!(fresh.rights.is_empty());
}

#[test]
fn process_linux_prerequisite_kernel_rejects_unprivileged_forged_credentials() {
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "INCOMPLETE: forged-credential prerequisite requires an unprivileged executor"
    );
    let pair = socket_pair();
    let real = libc::ucred {
        pid: unsafe { libc::getpid() },
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
    };
    for forged in [
        libc::ucred {
            pid: real.pid + 1,
            ..real
        },
        libc::ucred {
            uid: real.uid.wrapping_add(1),
            ..real
        },
        libc::ucred {
            gid: real.gid.wrapping_add(1),
            ..real
        },
    ] {
        assert_eq!(
            send(pair[1].as_raw_fd(), &FRAME, &[], Some(forged)),
            Err(libc::EPERM)
        );
    }
    assert_eq!(
        send(pair[1].as_raw_fd(), &FRAME, &[], Some(real)),
        Ok(FRAME.len())
    );
    let fresh = receive(pair[0].as_raw_fd(), FRAME.len(), 256);
    assert_eq!(fresh.credentials.len(), 1);
    let actual = fresh.credentials[0];
    assert_eq!(
        (actual.pid, actual.uid, actual.gid),
        (real.pid, real.uid, real.gid)
    );
    assert_eq!(fresh.bytes, FRAME);
}

struct Helper {
    pid: libc::pid_t,
    joined: bool,
}

impl Helper {
    fn join(&mut self) {
        let end = std::time::Instant::now() + std::time::Duration::from_secs(1);
        loop {
            let mut status = 0;
            let result = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
            if result == self.pid {
                self.joined = true;
                assert!(libc::WIFEXITED(status));
                assert_eq!(libc::WEXITSTATUS(status), 0);
                return;
            }
            assert_eq!(result, 0, "helper waitpid: {}", io::Error::last_os_error());
            assert!(
                std::time::Instant::now() < end,
                "helper did not exit after acknowledgment"
            );
            std::thread::yield_now();
        }
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        if !self.joined {
            // The test owns exactly this fork child and is its only waiter.
            // This is cleanup for a finite primitive witness, not the future
            // editor ProcessSupervisor or its ownership/uncertainty proof.
            unsafe { libc::kill(self.pid, libc::SIGKILL) };
            let mut status = 0;
            loop {
                let result = unsafe { libc::waitpid(self.pid, &mut status, 0) };
                if result == self.pid {
                    break;
                }
                if result < 0 && error() == libc::EINTR {
                    continue;
                }
                eprintln!(
                    "INCOMPLETE: helper waitpid cleanup failed: {}",
                    io::Error::last_os_error()
                );
                break;
            }
        }
    }
}

#[test]
fn process_linux_prerequisite_inherited_endpoint_reports_actual_helper_pid() {
    let pair = socket_pair();
    let creator = unsafe { libc::getpid() };
    let mut peer = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut peer_len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    assert_eq!(
        unsafe {
            libc::getsockopt(
                pair[0].as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                peer.as_mut_ptr().cast(),
                &mut peer_len,
            )
        },
        0
    );
    assert_eq!(unsafe { peer.assume_init() }.pid, creator);
    // Prepare every pointer and descriptor before fork. The child branch uses
    // only async-safe syscalls and _exit, with no allocation, logging or Drop.
    let receiver = pair[0].as_raw_fd();
    let sender = pair[1].as_raw_fd();
    let mut iov = libc::iovec {
        iov_base: FRAME.as_ptr().cast_mut().cast(),
        iov_len: FRAME.len(),
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    let mut acknowledgment = 0u8;
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork: {}", io::Error::last_os_error());
    if pid == 0 {
        unsafe {
            libc::close(receiver);
            if libc::sendmsg(sender, &message, libc::MSG_NOSIGNAL) != FRAME.len() as isize {
                libc::_exit(71);
            }
            if libc::read(sender, (&mut acknowledgment as *mut u8).cast(), 1) != 1 {
                libc::_exit(72);
            }
            libc::_exit(if acknowledgment == 1 { 0 } else { 73 });
        }
    }
    let mut helper = Helper { pid, joined: false };
    let birth = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let after_name = birth.rsplit_once(')').unwrap().1;
    let birth_ticks: u64 = after_name
        .split_whitespace()
        .nth(19)
        .unwrap()
        .parse()
        .unwrap();
    assert!(birth_ticks > 0);
    let actual = receive(receiver, FRAME.len(), 256);
    assert_eq!(actual.credentials.len(), 1);
    assert_eq!(actual.credentials[0].pid, pid);
    assert_ne!(
        actual.credentials[0].pid, creator,
        "creation-time SO_PEERCRED is not sender identity"
    );
    assert_eq!(actual.credentials[0].uid, unsafe { libc::getuid() });
    assert_eq!(actual.credentials[0].gid, unsafe { libc::getgid() });
    assert_eq!(
        actual.bytes, FRAME,
        "copied payload does not change kernel sender PID"
    );
    assert!(actual.rights.is_empty());
    assert_eq!(send(receiver, &[1], &[], None), Ok(1));
    helper.join();
    eprintln!(
        "actual inherited sender pid={pid} birth_ticks={birth_ticks} creator={creator} waitpid=Exited(0)"
    );
    // The original authorized native sender remains usable after the foreign
    // sender witness and genuine helper reap.
    assert_eq!(send(sender, &FRAME, &[], None), Ok(FRAME.len()));
    let fresh = receive(receiver, FRAME.len(), 256);
    assert_eq!(fresh.credentials.len(), 1);
    assert_eq!(fresh.credentials[0].pid, creator);
}
