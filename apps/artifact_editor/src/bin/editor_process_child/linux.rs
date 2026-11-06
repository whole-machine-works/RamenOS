use desktop_editor_core::process_data::{self as data, TextHeader, TextState};
use desktop_editor_core::wire::{self, Direction, ProcessMessage as Message};
use desktop_editor_core::{EditorModel, FRAME_BYTES, InitialView, ResetPolicy};
use kernel_api::generated::desktop_editor_process_v1 as p;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};

type Result<T> = std::result::Result<T, String>;
const ALL_SEALS: i32 =
    libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
fn need(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}
fn sys(result: i32, operation: &str) -> Result<i32> {
    if result < 0 {
        Err(format!("{operation}: {}", std::io::Error::last_os_error()))
    } else {
        Ok(result)
    }
}
fn next(value: u64) -> Result<u64> {
    value
        .checked_add(1)
        .ok_or_else(|| "counter exhausted".into())
}

pub(super) struct Args {
    parent: libc::ucred,
    #[cfg(feature = "host_editor_process_child_assertions_v0_dev")]
    pub case: Option<&'static str>,
}
impl Args {
    fn parse() -> Result<Self> {
        let args: Vec<_> = std::env::args().skip(1).collect();
        need(
            args.len() == 8
                || cfg!(feature = "host_editor_process_child_assertions_v0_dev")
                    && args.len() == 12,
            "argv length",
        )?;
        need(
            args[0] == "--control-fd"
                && args[1] == "3"
                && args[2] == "--parent-pid"
                && args[4] == "--parent-uid"
                && args[6] == "--parent-gid",
            "argv layout",
        )?;
        let pid = args[3].parse::<i32>().map_err(|_| "parent pid")?;
        need(pid > 0, "positive parent pid")?;
        let uid = args[5].parse::<u32>().map_err(|_| "parent uid")?;
        let gid = args[7].parse::<u32>().map_err(|_| "parent gid")?;
        #[cfg(feature = "host_editor_process_child_assertions_v0_dev")]
        let case = if args.len() == 12 {
            need(
                args[8] == "--assertion-case" && args[10] == "--barrier-fd" && args[11] == "5",
                "assertion argv",
            )?;
            Some(crate::assertions::case(&args[9]).ok_or("unknown assertion case")?)
        } else {
            None
        };
        #[cfg(not(feature = "host_editor_process_child_assertions_v0_dev"))]
        need(args.len() == 8, "production rejects assertion argv")?;
        need(
            std::env::vars_os().next().is_none(),
            "child environment must be empty",
        )?;
        for fd in [4, 6] {
            need(
                unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0
                    && std::io::Error::last_os_error().raw_os_error() == Some(libc::EBADF),
                "exec-only descriptor survived exec",
            )?;
        }
        let has_barrier = unsafe { libc::fcntl(5, libc::F_GETFD) } >= 0;
        #[cfg(feature = "host_editor_process_child_assertions_v0_dev")]
        need(
            has_barrier == case.is_some(),
            "assertion barrier descriptor",
        )?;
        #[cfg(not(feature = "host_editor_process_child_assertions_v0_dev"))]
        need(!has_barrier, "production barrier descriptor")?;
        Ok(Self {
            parent: libc::ucred { pid, uid, gid },
            #[cfg(feature = "host_editor_process_child_assertions_v0_dev")]
            case,
        })
    }
}

pub(super) struct Carrier {
    fd: OwnedFd,
    parent: libc::ucred,
    end: Instant,
}
pub(super) struct Packet {
    pub bytes: Vec<u8>,
    pub fds: Vec<OwnedFd>,
}
impl Carrier {
    fn new(args: &Args) -> Result<Self> {
        let fd = unsafe { OwnedFd::from_raw_fd(3) };
        let mut kind = 0i32;
        let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
        sys(
            unsafe {
                libc::getsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_TYPE,
                    &mut kind as *mut _ as *mut _,
                    &mut len,
                )
            },
            "socket type",
        )?;
        need(kind == libc::SOCK_SEQPACKET, "control must be seqpacket")?;
        let yes = 1i32;
        sys(
            unsafe {
                libc::setsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_PASSCRED,
                    &yes as *const _ as *const _,
                    std::mem::size_of::<i32>() as _,
                )
            },
            "passcred",
        )?;
        Ok(Self {
            fd,
            parent: args.parent,
            end: Instant::now() + Duration::from_millis(5000),
        })
    }
    fn ready(&self, events: i16) -> Result<()> {
        loop {
            let remaining = self.end.saturating_duration_since(Instant::now());
            need(!remaining.is_zero(), "original child deadline")?;
            let mut poll = libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events,
                revents: 0,
            };
            let n = unsafe { libc::poll(&mut poll, 1, remaining.as_millis().clamp(1, 100) as i32) };
            if n < 0 {
                if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err("control poll".into());
            }
            if n > 0 {
                need(poll.revents & libc::POLLNVAL == 0, "invalid control fd")?;
                return Ok(());
            }
        }
    }
    fn receive(&self) -> Result<Packet> {
        loop {
            self.ready(libc::POLLIN)?;
            let mut bytes = [0u8; 89];
            let mut ancillary = [0usize; 64];
            let mut iov = libc::iovec {
                iov_base: bytes.as_mut_ptr().cast(),
                iov_len: bytes.len(),
            };
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = ancillary.as_mut_ptr().cast();
            msg.msg_controllen = std::mem::size_of_val(&ancillary);
            let received = unsafe {
                libc::recvmsg(
                    self.fd.as_raw_fd(),
                    &mut msg,
                    libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
                )
            };
            if received < 0 {
                if matches!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EINTR | libc::EAGAIN)
                ) {
                    continue;
                }
                return Err("receive control".into());
            }
            let mut fds = Vec::new();
            let mut credentials = None;
            let mut rights = 0;
            let mut invalid = false;
            let mut offset = 0usize;
            let available = msg.msg_controllen.min(std::mem::size_of_val(&ancillary));
            let header = unsafe { libc::CMSG_LEN(0) } as usize;
            while offset + std::mem::size_of::<libc::cmsghdr>() <= available {
                let c = unsafe {
                    std::ptr::read_unaligned(
                        (msg.msg_control as *const u8)
                            .add(offset)
                            .cast::<libc::cmsghdr>(),
                    )
                };
                if c.cmsg_len < header || c.cmsg_len > available - offset {
                    invalid = true;
                    break;
                }
                let length = c.cmsg_len - header;
                let payload = unsafe { (msg.msg_control as *const u8).add(offset + header) };
                if c.cmsg_level == libc::SOL_SOCKET && c.cmsg_type == libc::SCM_RIGHTS {
                    rights += 1;
                    if !length.is_multiple_of(std::mem::size_of::<i32>()) {
                        invalid = true;
                    }
                    for index in 0..length / std::mem::size_of::<i32>() {
                        let raw = unsafe {
                            std::ptr::read_unaligned(payload.add(index * 4).cast::<i32>())
                        };
                        if raw >= 0 {
                            fds.push(unsafe { OwnedFd::from_raw_fd(raw) });
                        } else {
                            invalid = true;
                        }
                    }
                } else if c.cmsg_level == libc::SOL_SOCKET
                    && c.cmsg_type == libc::SCM_CREDENTIALS
                    && length == std::mem::size_of::<libc::ucred>()
                {
                    let cred = unsafe { std::ptr::read_unaligned(payload.cast::<libc::ucred>()) };
                    if credentials.replace(cred).is_some() {
                        invalid = true;
                    }
                } else {
                    invalid = true;
                }
                let align = std::mem::size_of::<usize>();
                let advance = (c.cmsg_len + align - 1) & !(align - 1);
                if advance > available - offset {
                    break;
                }
                offset += advance;
            }
            need(
                received == 88
                    && msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) == 0
                    && !invalid,
                "control framing/ancillary",
            )?;
            let cred = credentials.ok_or("missing credentials")?;
            need(
                (cred.pid, cred.uid, cred.gid)
                    == (self.parent.pid, self.parent.uid, self.parent.gid),
                "foreign parent credentials",
            )?;
            need(
                fds.len() <= 3 && rights == usize::from(!fds.is_empty()),
                "rights inventory",
            )?;
            return Ok(Packet {
                bytes: bytes[..88].to_vec(),
                fds,
            });
        }
    }
    pub fn send_raw(&self, bytes: &[u8], fds: &[RawFd]) -> Result<()> {
        loop {
            self.ready(libc::POLLOUT)?;
            let mut iov = libc::iovec {
                iov_base: bytes.as_ptr().cast_mut().cast(),
                iov_len: bytes.len(),
            };
            let mut ancillary = [0usize; 8];
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            if !fds.is_empty() {
                need(fds.len() <= 3, "send fd bound")?;
                msg.msg_control = ancillary.as_mut_ptr().cast();
                msg.msg_controllen =
                    unsafe { libc::CMSG_SPACE(std::mem::size_of_val(fds) as u32) } as usize;
                let c = msg.msg_control.cast::<libc::cmsghdr>();
                unsafe {
                    (*c).cmsg_level = libc::SOL_SOCKET;
                    (*c).cmsg_type = libc::SCM_RIGHTS;
                    (*c).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(fds) as u32) as usize;
                    std::ptr::copy_nonoverlapping(
                        fds.as_ptr().cast::<u8>(),
                        libc::CMSG_DATA(c),
                        std::mem::size_of_val(fds),
                    );
                }
            }
            let n = unsafe {
                libc::sendmsg(
                    self.fd.as_raw_fd(),
                    &msg,
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                )
            };
            if n < 0
                && matches!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EINTR | libc::EAGAIN)
                )
            {
                continue;
            }
            need(n == bytes.len() as isize, "complete seqpacket send")?;
            return Ok(());
        }
    }
}

fn stat(fd: &OwnedFd) -> Result<libc::stat> {
    let mut s = unsafe { std::mem::zeroed() };
    sys(unsafe { libc::fstat(fd.as_raw_fd(), &mut s) }, "fstat")?;
    need(
        s.st_mode & libc::S_IFMT == libc::S_IFREG && s.st_size >= 0,
        "regular bounded object",
    )?;
    Ok(s)
}
struct Mapping {
    ptr: std::ptr::NonNull<u8>,
    len: usize,
}
impl Mapping {
    fn map(fd: &OwnedFd, len: usize, writable: bool) -> Result<Self> {
        need(len > 0 && len <= FRAME_BYTES + 1, "mapping length")?;
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | if writable { libc::PROT_WRITE } else { 0 },
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        need(ptr != libc::MAP_FAILED, "mmap")?;
        Ok(Self {
            ptr: std::ptr::NonNull::new(ptr.cast()).ok_or("null mapping")?,
            len,
        })
    }
    fn bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
    fn write(&mut self, bytes: &[u8]) {
        assert_eq!(self.len, bytes.len());
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.ptr.as_ptr(), bytes.len());
        }
    }
}
impl Drop for Mapping {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr.as_ptr().cast(), self.len);
        }
    }
}

struct Capture {
    input: u64,
    text: u64,
    hash: [u8; 32],
    operation: Option<u64>,
    noticed: bool,
    acknowledged: bool,
}
struct Pending {
    request: u64,
    input: u64,
    publication: u64,
    capture: bool,
}
struct Engine {
    model: EditorModel,
    object: u64,
    base: u64,
    view: u64,
    channel: u64,
    handle: u64,
    last_request: u64,
    input: u64,
    publication: u64,
    deliveries: u32,
    downs: u32,
    capture: Option<Capture>,
    frozen: bool,
    pending: Option<Pending>,
}
impl Engine {
    fn boot(message: p::Bootstrap, handle: u64, selected: &OwnedFd) -> Result<Self> {
        need(
            message.request_id == 1
                && message.channel_generation > 0
                && message.document_binding_id > 0
                && message.offer_id == 1,
            "bootstrap identity",
        )?;
        need(
            stat(selected)?.st_size == i64::from(message.selected_text_len),
            "selected size",
        )?;
        let seals = sys(
            unsafe { libc::fcntl(selected.as_raw_fd(), libc::F_GET_SEALS) },
            "selected seals",
        )?;
        need(seals & ALL_SEALS == ALL_SEALS, "unsealed selected input")?;
        let map = Mapping::map(selected, message.selected_text_len as usize, false)?;
        let (header, body) = data::decode_text64(map.bytes()).map_err(|_| "selected Text64")?;
        let model = EditorModel::from_selected_ascii(body, 1, InitialView::KeepTop)
            .map_err(|_| "selected model")?;
        Ok(Self {
            model,
            object: header.selected_object_id,
            base: header.revision,
            view: 1,
            channel: message.channel_generation,
            handle,
            last_request: message.request_id,
            input: 0,
            publication: 0,
            deliveries: 0,
            downs: 0,
            capture: None,
            frozen: false,
            pending: None,
        })
    }
    fn parent_request(&mut self, request: u64, channel: u64) -> Result<()> {
        need(
            channel == self.channel && request > self.last_request,
            "parent request lineage",
        )?;
        self.last_request = request;
        Ok(())
    }
    fn input(
        &mut self,
        value: p::DeliverInput,
        #[cfg(feature = "host_editor_process_child_assertions_v0_dev")] observer_only: bool,
    ) -> Result<Message> {
        self.parent_request(value.request_id, value.channel_generation)?;
        need(
            self.pending.is_none() && !self.frozen && self.deliveries < 128 && self.downs < 64,
            "input during publication/freeze/batch boundary",
        )?;
        need(
            value.input_sequence > self.input
                && value.focus_epoch > 0
                && value.focus_service_epoch > 0,
            "input lineage",
        )?;
        #[cfg(not(feature = "host_editor_process_child_assertions_v0_dev"))]
        let observer_only = false;
        // This closed assertion child deliberately acknowledges ordinary keys
        // without editing. Reset and genuine CtrlS retain their normal rules.
        // Production has no selector or runtime argument enabling this branch.
        let effect = if observer_only && value.flags == 0 && matches!(value.phase, 1 | 2) {
            self.model.reset_navigation(ResetPolicy::PreserveNavigation)
        } else if value.flags == 1 || value.phase == 3 {
            self.model
                .reset_navigation(ResetPolicy::ClearPreferredColumn)
        } else if value.phase == 1 {
            self.model
                .apply_key(value.usage, value.modifiers)
                .map_err(|_| "unsupported input")?
        } else {
            self.model.reset_navigation(ResetPolicy::PreserveNavigation)
        };
        if effect.view_changed {
            self.view = next(self.view)?;
        }
        self.input = value.input_sequence;
        self.deliveries += 1;
        if value.phase == 1 {
            self.downs += 1;
        }
        let snapshot = self.model.snapshot();
        if value.flags == 2 {
            need(
                value.usage == 22 && value.phase == 1 && value.modifiers & 1 != 0,
                "capture input must be actual CtrlS",
            )?;
            need(
                self.capture
                    .as_ref()
                    .is_none_or(|c| c.acknowledged && value.input_sequence > c.input),
                "prior capture not acknowledged or new capture sequence is stale",
            )?;
            self.capture = Some(Capture {
                input: self.input,
                text: snapshot.text_generation,
                hash: data::sha256(&snapshot.bytes),
                operation: None,
                noticed: false,
                acknowledged: false,
            });
            self.frozen = true;
        }
        Ok(Message::InputAck(p::InputAck {
            request_id: value.request_id,
            channel_generation: self.channel,
            input_sequence: self.input,
            text_generation: snapshot.text_generation,
            view_generation: self.view,
            flags: u32::from(effect.view_changed || effect.text_changed),
            status: 0,
            reserved: [0; 16],
        }))
    }
    fn acknowledge(&mut self, value: p::PublishAck) -> Result<()> {
        let pending = self.pending.as_ref().ok_or("unsolicited publication ack")?;
        need(
            value.request_id == pending.request,
            "publication ack request",
        )?;
        if value.status == 0 {
            need(
                value.channel_generation == self.channel
                    && value.publication_sequence == pending.publication
                    && value.input_sequence == pending.input,
                "publication ack lineage",
            )?;
            if pending.capture {
                self.capture
                    .as_mut()
                    .ok_or("capture ack owner")?
                    .acknowledged = true;
            }
            self.deliveries = 0;
            self.downs = 0;
        } else {
            need(
                value.status == 4 && !pending.capture,
                "terminal publication denial",
            )?;
        }
        self.pending = None;
        self.frozen = false;
        Ok(())
    }
    fn notice(&mut self, value: p::ReceiptNotice) -> Result<()> {
        self.parent_request(value.request_id, value.channel_generation)?;
        let capture = self.capture.as_mut().ok_or("notice without own capture")?;
        need(
            capture.acknowledged
                && !self.frozen
                && !capture.noticed
                && value.operation_id > 0
                && value.capture_input_sequence == capture.input
                && value.capture_text_generation == capture.text,
            "receipt capture binding/replay",
        )?;
        need(
            capture.operation.is_none_or(|op| op == value.operation_id),
            "receipt operation rebinding",
        )?;
        capture.operation = Some(value.operation_id);
        let snapshot = self.model.snapshot();
        if snapshot.text_generation == capture.text {
            need(
                data::sha256(&snapshot.bytes) == capture.hash,
                "own capture bytes changed without generation",
            )?;
        }
        if value.outcome == 0 {
            need(
                value.committed_revision == next(self.base)?,
                "receipt revision successor",
            )?;
            self.base = value.committed_revision;
        } else {
            need(value.committed_revision == 0, "noncommit revision")?;
        }
        capture.noticed = true;
        Ok(())
    }
}

pub(super) fn run() -> Result<()> {
    let args = Args::parse()?;
    let carrier = Carrier::new(&args)?;
    #[cfg(feature = "host_editor_process_child_assertions_v0_dev")]
    let mut fixture = crate::assertions::Fixture::new(args.case);
    let packet = carrier.receive()?;
    let (handle, message) = wire::decode_frame(&packet.bytes).map_err(|_| "bootstrap frame")?;
    wire::validate_delivery(&message, Direction::ParentToChild, packet.fds.len())
        .map_err(|_| "bootstrap delivery")?;
    let Message::Bootstrap(bootstrap) = message else {
        return Err("first message is not bootstrap".into());
    };
    let mut fds = packet.fds.into_iter();
    let selected = fds.next().ok_or("selected fd")?;
    let pair = [
        fds.next().ok_or("state fd")?,
        fds.next().ok_or("surface fd")?,
    ];
    let mut engine = Engine::boot(bootstrap, handle, &selected)?;
    drop(selected);
    publish(
        &carrier,
        &mut engine,
        pair,
        bootstrap.request_id,
        bootstrap.offer_id,
        false,
        #[cfg(feature = "host_editor_process_child_assertions_v0_dev")]
        &mut fixture,
    )?;
    loop {
        let packet = carrier.receive()?;
        let (handle, message) = wire::decode_frame(&packet.bytes).map_err(|_| "parent frame")?;
        need(handle == engine.handle, "wire handle reference")?;
        wire::validate_delivery(&message, Direction::ParentToChild, packet.fds.len())
            .map_err(|_| "parent delivery")?;
        if engine.frozen {
            let expected = match &message {
                Message::Stop(_) => true,
                Message::RequestPublication(_) => engine.pending.is_none(),
                Message::PublishAck(_) => engine.pending.as_ref().is_some_and(|p| p.capture),
                _ => false,
            };
            need(
                expected,
                "capture flush/terminal ack must precede later controls",
            )?;
        }
        match message {
            Message::DeliverInput(value) => {
                #[cfg(feature = "host_editor_process_child_assertions_v0_dev")]
                fixture.input_point()?;
                let ack = match engine.input(
                    value,
                    #[cfg(feature = "host_editor_process_child_assertions_v0_dev")]
                    fixture.observer_only(),
                ) {
                    Ok(ack) => ack,
                    Err(error) => {
                        let ack = Message::InputAck(p::InputAck {
                            request_id: value.request_id,
                            channel_generation: 0,
                            input_sequence: 0,
                            text_generation: 0,
                            view_generation: 0,
                            flags: 0,
                            status: 2,
                            reserved: [0; 16],
                        });
                        carrier.send_raw(
                            &wire::encode_frame(&ack, handle).map_err(|_| "error ack encode")?,
                            &[],
                        )?;
                        return Err(error);
                    }
                };
                let bytes = wire::encode_frame(&ack, handle).map_err(|_| "ack encode")?;
                #[cfg(feature = "host_editor_process_child_assertions_v0_dev")]
                {
                    fixture.send_ack(&carrier, bytes)?;
                }
                #[cfg(not(feature = "host_editor_process_child_assertions_v0_dev"))]
                carrier.send_raw(&bytes, &[])?;
            }
            Message::RequestPublication(value) => {
                engine.parent_request(value.request_id, value.channel_generation)?;
                let snapshot = engine.model.snapshot();
                need(
                    engine.pending.is_none()
                        && value.offer_id > 0
                        && value.last_input_sequence == engine.input
                        && value.expected_text_generation == snapshot.text_generation
                        && value.expected_view_generation == engine.view,
                    "publication request lineage",
                )?;
                need(
                    (value.flags == 2) == engine.frozen,
                    "publication capture state",
                )?;
                let mut fds = packet.fds.into_iter();
                let pair = [
                    fds.next().ok_or("state offer")?,
                    fds.next().ok_or("surface offer")?,
                ];
                publish(
                    &carrier,
                    &mut engine,
                    pair,
                    value.request_id,
                    value.offer_id,
                    value.flags == 2,
                    #[cfg(feature = "host_editor_process_child_assertions_v0_dev")]
                    &mut fixture,
                )?;
            }
            Message::PublishAck(value) => {
                engine.acknowledge(value)?;
                #[cfg(feature = "host_editor_process_child_assertions_v0_dev")]
                fixture.after_ack(&carrier)?;
            }
            Message::ReceiptNotice(value) => engine.notice(value)?,
            Message::Stop(value) => {
                engine.parent_request(value.request_id, value.channel_generation)?;
                return Ok(());
            }
            _ => return Err("wrong parent message direction".into()),
        }
    }
}

fn publish(
    carrier: &Carrier,
    engine: &mut Engine,
    pair: [OwnedFd; 2],
    request: u64,
    offer: u64,
    capture: bool,
    #[cfg(feature = "host_editor_process_child_assertions_v0_dev")]
    fixture: &mut crate::assertions::Fixture,
) -> Result<()> {
    need(engine.pending.is_none(), "publication already pending")?;
    #[cfg(feature = "host_editor_process_child_assertions_v0_dev")]
    let sealed_reuse = if fixture.sealed_return_case() && engine.publication > 0 {
        let mut immutable = true;
        for fd in &pair {
            let seals = sys(
                unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS) },
                "reused pair actual seals",
            )?;
            immutable &= seals & ALL_SEALS == ALL_SEALS;
        }
        immutable
    } else {
        false
    };
    #[cfg(feature = "host_editor_process_child_assertions_v0_dev")]
    if fixture.foreign_return(engine.publication, sealed_reuse) {
        // Closed foreign/reused-inode probes return actual sealed aliases unchanged;
        // healthy bootstrap always uses the production write/map/seal path.
        let text = stat(&pair[0])?;
        let surface = stat(&pair[1])?;
        need(
            (128..=4224).contains(&text.st_size) && surface.st_size == FRAME_BYTES as i64,
            "foreign sealed pair extents",
        )?;
        for fd in &pair {
            let seals = sys(
                unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS) },
                "foreign pair seals",
            )?;
            need(
                seals & ALL_SEALS == ALL_SEALS,
                "foreign pair must already be immutable",
            )?;
        }
        engine.publication = next(engine.publication)?;
        let snapshot = engine.model.snapshot();
        let message = Message::Publish(p::Publish {
            request_id: request,
            channel_generation: engine.channel,
            input_sequence: engine.input,
            publication_sequence: engine.publication,
            text_generation: snapshot.text_generation,
            view_generation: engine.view,
            offer_id: offer,
            text_state_len: text.st_size as u32,
            surface_len: FRAME_BYTES as u32,
        });
        let bytes =
            wire::encode_frame(&message, engine.handle).map_err(|_| "foreign return encode")?;
        carrier.send_raw(&bytes, &[pair[0].as_raw_fd(), pair[1].as_raw_fd()])?;
        engine.pending = Some(Pending {
            request,
            input: engine.input,
            publication: engine.publication,
            capture,
        });
        return Ok(());
    }

    let a = stat(&pair[0])?;
    let b = stat(&pair[1])?;
    need(
        (a.st_dev, a.st_ino) != (b.st_dev, b.st_ino),
        "offered aliases",
    )?;
    need(
        a.st_size == 4224 && b.st_size == FRAME_BYTES as i64,
        "offered sizes",
    )?;
    for fd in &pair {
        let seals = sys(
            unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS) },
            "offered seals",
        )?;
        need(seals == 0, "offered object already sealed")?;
    }
    let snapshot = engine.model.snapshot();
    let mut pixels = vec![0; FRAME_BYTES];
    engine
        .model
        .rasterize_bgra(&data::frozen_font(), &mut pixels)
        .map_err(|_| "raster")?;
    let state = TextState {
        header: TextHeader::new(engine.object, engine.base, &snapshot.bytes)
            .map_err(|_| "text header")?,
        cursor: snapshot.cursor as u32,
        selection: snapshot.selection.map(|(a, b)| (a as u32, b as u32)),
        first_visible_line: snapshot.first_visible_line as u32,
        text_generation: snapshot.text_generation,
        view_generation: engine.view,
        surface_sha256: data::sha256(&pixels),
    };
    let text = state.encode(&snapshot.bytes).map_err(|_| "state encode")?;
    #[cfg(feature = "host_editor_process_child_assertions_v0_dev")]
    let mut text = text;
    #[cfg(feature = "host_editor_process_child_assertions_v0_dev")]
    fixture.mutate_objects(&mut text, &mut pixels, engine.input, engine.publication)?;
    sys(
        unsafe { libc::ftruncate(pair[0].as_raw_fd(), text.len() as libc::off_t) },
        "state resize",
    )?;
    sys(
        unsafe { libc::ftruncate(pair[1].as_raw_fd(), pixels.len() as libc::off_t) },
        "surface resize",
    )?;
    let mut text_map = Mapping::map(&pair[0], text.len(), true)?;
    let mut surface_map = Mapping::map(&pair[1], pixels.len(), true)?;
    text_map.write(&text);
    surface_map.write(&pixels);
    #[cfg(feature = "host_editor_process_child_assertions_v0_dev")]
    fixture.mapping_point()?;
    #[cfg(feature = "host_editor_process_child_assertions_v0_dev")]
    if fixture.mapping_mode() != 0 {
        if fixture.mapping_mode() == 2 {
            sys(
                unsafe {
                    libc::mprotect(text_map.ptr.as_ptr().cast(), text_map.len, libc::PROT_READ)
                },
                "actual shared state readonly protection",
            )?;
            sys(
                unsafe {
                    libc::mprotect(
                        surface_map.ptr.as_ptr().cast(),
                        surface_map.len,
                        libc::PROT_READ,
                    )
                },
                "actual shared surface readonly protection",
            )?;
        }
        for fd in &pair {
            let result = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_ADD_SEALS, ALL_SEALS) };
            need(
                result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EBUSY),
                "retained real mapping must block WRITE seal",
            )?;
        }
        // This closed fault intentionally retains actual shared aliases until
        // OS process retirement. Parent independently probes the same inodes.
        std::mem::forget((text_map, surface_map));
    } else {
        drop((text_map, surface_map));
    }
    #[cfg(not(feature = "host_editor_process_child_assertions_v0_dev"))]
    drop((text_map, surface_map));
    let seals = ALL_SEALS;
    #[cfg(feature = "host_editor_process_child_assertions_v0_dev")]
    let seals = fixture.seals(seals);
    #[cfg(feature = "host_editor_process_child_assertions_v0_dev")]
    let seal_success_expected = fixture.mapping_mode() == 0;
    #[cfg(not(feature = "host_editor_process_child_assertions_v0_dev"))]
    let seal_success_expected = true;
    if seal_success_expected {
        for fd in &pair {
            sys(
                unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_ADD_SEALS, seals) },
                "publication seal",
            )?;
        }
    }
    engine.publication = next(engine.publication)?;
    let message = Message::Publish(p::Publish {
        request_id: request,
        channel_generation: engine.channel,
        input_sequence: engine.input,
        publication_sequence: engine.publication,
        text_generation: snapshot.text_generation,
        view_generation: engine.view,
        offer_id: offer,
        text_state_len: text.len().clamp(128, 4224) as u32,
        surface_len: FRAME_BYTES as u32,
    });
    let bytes = wire::encode_frame(&message, engine.handle).map_err(|_| "publication encode")?;
    let raw = [pair[0].as_raw_fd(), pair[1].as_raw_fd()];
    #[cfg(feature = "host_editor_process_child_assertions_v0_dev")]
    fixture.send_publication(carrier, bytes, raw, engine.input, capture)?;
    #[cfg(not(feature = "host_editor_process_child_assertions_v0_dev"))]
    carrier.send_raw(&bytes, &raw)?;
    engine.pending = Some(Pending {
        request,
        input: engine.input,
        publication: engine.publication,
        capture,
    });
    Ok(())
}
