//! Closed assertion-only child faults; absent from production.
use super::linux::Carrier;
use desktop_editor_core::process_data::{FONT_BYTES, sha256};
use std::{
    io,
    os::fd::RawFd,
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, String>;
const CASES: &[&str] = &[
    "D03ForeignProtocolVersion",
    "D03Frame87Bytes",
    "D03Frame89Bytes",
    "D03MessageTypeNine",
    "D03MessageTypeZero",
    "D03NonzeroReservedField",
    "D03NonzeroTail84",
    "D03NonzeroTail85",
    "D03NonzeroTail86",
    "D03NonzeroTail87",
    "D03ProtocolZero",
    "D03UnknownFlags",
    "D03WrongMessageDirection",
    "D03WrongPayloadLength",
    "D05InputAckFdOne",
    "D05PublishFdOne",
    "D05PublishFdThree",
    "D05PublishFdZero",
    "D05RecordTruncation",
    "D08Body4097",
    "D08BodyNonAscii",
    "D08BodyNul",
    "D09CursorBeyondBody",
    "D09FirstLineBeyondInventory",
    "D09HalfSelectionSentinel",
    "D09SelectionBeyondBody",
    "D09SelectionReversed",
    "D09WrongViewGeneration",
    "D10ChildSavedImitationClipped",
    "D10OversizedSurface",
    "D11FutureWriteOnly",
    "D11MissingFinalSeal",
    "D11MissingGrowSeal",
    "D11MissingShrinkSeal",
    "D11MprotectOnly",
    "D11RetainedWritableMapping",
    "D12ForeignChildText",
    "D12ForeignChildSurface",
    "D12EqualBytesForeignInode",
    "D12DuplicateOfferedFdRoles",
    "D12StaleOfferId",
    "D12SwappedOfferedRoles",
    "D13BaseRevisionMismatch",
    "D13ControlLengthVsFstat",
    "D13StateControlGenerationMismatch",
    "D13SurfaceAlphaMismatch",
    "D13SurfaceCompanionHashMismatch",
    "D13SurfaceFormatMismatch",
    "D13SurfaceLength1228799",
    "D13SurfaceLength1228801",
    "D13TextBodyHash",
    "D13TextHeaderReserved",
    "D13TextHeaderVersion",
    "D13TextLength127",
    "D13TextLength4225",
    "D13TextObjectMismatch",
    "D14DuplicateAck",
    "D14DuplicatePublish",
    "D14FutureInput",
    "D14OldRequest",
    "D14WrongChannelGeneration",
    "D16ExistingInodeAsNewCredit",
    "D18CopiedOldCaptureRequest",
    "D18UnsolicitedCapture",
    "D25ActualSendBackpressure",
    "D25EofWithPendingOffer",
    "D25ShortRecord",
    "D25StderrCapPlusOne",
    "D25StdoutCapPlusOne",
    "D27OldSurfaceGeneration",
    "D28BackdatedCoreClock",
    "D28RoundTripCannotRenew",
];
pub(super) fn case(value: &str) -> Option<&'static str> {
    CASES.iter().copied().find(|case| *case == value)
}
fn put32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}
fn get64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
fn write_all(fd: i32, mut bytes: &[u8], end: Instant) -> Result<()> {
    while !bytes.is_empty() {
        if Instant::now() >= end {
            return Err("fixture original deadline".into());
        }
        let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if n > 0 {
            bytes = &bytes[n as usize..];
            continue;
        }
        if n < 0
            && matches!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::EINTR | libc::EAGAIN)
            )
        {
            let mut poll = libc::pollfd {
                fd,
                events: libc::POLLOUT,
                revents: 0,
            };
            unsafe {
                libc::poll(&mut poll, 1, 1);
            }
            continue;
        }
        return Err("fixture pipe write".into());
    }
    Ok(())
}
pub(super) struct Fixture {
    case: Option<&'static str>,
    fired: bool,
    current: bool,
    occurrence: u32,
    end: Instant,
    captured: Option<[u8; 88]>,
}
impl Fixture {
    pub fn new(case: Option<&'static str>) -> Self {
        Self {
            case,
            fired: false,
            current: false,
            occurrence: 0,
            end: Instant::now() + Duration::from_millis(5000),
            captured: None,
        }
    }
    fn notify(&mut self, point: u32) -> Result<()> {
        let case = self.case.ok_or("fixture case missing")?;
        self.occurrence = self
            .occurrence
            .checked_add(1)
            .ok_or("fixture occurrence overflow")?;
        let mut record = [0u8; 32];
        record[..4].copy_from_slice(b"RPF0");
        put32(&mut record, 4, 1);
        put32(&mut record, 8, point);
        put32(&mut record, 12, self.occurrence);
        record[16..].copy_from_slice(&sha256(case.as_bytes())[..16]);
        write_all(1, &record, self.end)?;
        loop {
            if Instant::now() >= self.end {
                return Err("fixture barrier deadline".into());
            }
            let mut p = libc::pollfd {
                fd: 5,
                events: libc::POLLIN,
                revents: 0,
            };
            let n = unsafe { libc::poll(&mut p, 1, 1) };
            if n < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                return Err("fixture barrier poll".into());
            }
            if n > 0 {
                let mut byte = 0u8;
                let n = unsafe { libc::read(5, &mut byte as *mut _ as *mut _, 1) };
                if n == 1 && byte == 1 {
                    return Ok(());
                }
                if n < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err("fixture barrier release/EOF".into());
            }
        }
    }
    pub fn input_point(&mut self) -> Result<()> {
        if matches!(
            self.case,
            Some("D28RoundTripCannotRenew" | "D28BackdatedCoreClock")
        ) && !self.fired
        {
            self.fired = true;
            self.notify(5)?;
        }
        Ok(())
    }
    pub fn mapping_point(&mut self) -> Result<()> {
        Ok(())
    }
    pub fn reused_inode_case(&self) -> bool {
        self.case == Some("D16ExistingInodeAsNewCredit")
    }
    pub fn foreign_return(&mut self, publication: u64, sealed_reuse: bool) -> bool {
        if publication > 0
            && !self.fired
            && (matches!(
                self.case,
                Some(
                    "D12ForeignChildText"
                        | "D12ForeignChildSurface"
                        | "D12EqualBytesForeignInode"
                        | "D27OldSurfaceGeneration"
                )
            ) || self.reused_inode_case() && sealed_reuse)
        {
            self.fired = true;
            true
        } else {
            false
        }
    }
    pub fn mapping_mode(&self) -> u32 {
        if !self.current {
            return 0;
        }
        match self.case {
            Some("D11RetainedWritableMapping") => 1,
            Some("D11MprotectOnly") => 2,
            _ => 0,
        }
    }
    pub fn mutate_objects(
        &mut self,
        text: &mut Vec<u8>,
        surface: &mut Vec<u8>,
        input: u64,
        publication: u64,
    ) -> Result<()> {
        self.current = input > 0
            && !self.fired
            && self.case.is_some()
            && !self.reused_inode_case()
            && (self.case != Some("D10ChildSavedImitationClipped") || publication >= 2);
        if !self.current {
            return Ok(());
        }
        let case = self.case.unwrap();
        match case {
            "D08Body4097" => {
                text.resize(128 + 4097, b'a');
                put32(text, 4, 64 + 4097);
                put32(text, 56, 4097);
                let hash = sha256(&text[128..]);
                text[24..56].copy_from_slice(&hash);
            }
            "D08BodyNonAscii" | "D08BodyNul" => {
                text[128] = if case == "D08BodyNul" { 0 } else { 0xff };
                let hash = sha256(&text[128..]);
                text[24..56].copy_from_slice(&hash);
            }
            "D09CursorBeyondBody" => {
                let len = text.len() - 128;
                put32(text, 64, len as u32 + 1);
            }
            "D09HalfSelectionSentinel" => {
                put32(text, 68, u32::MAX);
                put32(text, 72, 0);
            }
            "D09SelectionReversed" => {
                put32(text, 68, 2);
                put32(text, 72, 1);
            }
            "D09SelectionBeyondBody" => {
                let len = text.len() - 128;
                put32(text, 68, 0);
                put32(text, 72, len as u32 + 1);
            }
            "D09FirstLineBeyondInventory" => {
                let len = text.len() - 128;
                put32(text, 76, len as u32 + 1);
            }
            "D09WrongViewGeneration" | "D13StateControlGenerationMismatch" => {
                let value = get64(text, 88)
                    .checked_add(1)
                    .ok_or("fault generation overflow")?;
                put64(text, 88, value);
            }
            "D10OversizedSurface" | "D13SurfaceLength1228801" => {
                surface.push(255);
            }
            "D10ChildSavedImitationClipped" => {
                for (column, byte) in b"Saved".iter().enumerate() {
                    for y in 0..16 {
                        for x in 0..8 {
                            let set = FONT_BYTES[(*byte as usize - 32) * 16 + y] & (128 >> x) != 0;
                            let offset = (y * 640 + column * 8 + x) * 4;
                            surface[offset..offset + 4].copy_from_slice(if set {
                                &[0, 0, 0, 255]
                            } else {
                                &[255; 4]
                            });
                        }
                    }
                }
                text[96..128].copy_from_slice(&sha256(surface));
            }
            "D13TextLength127" => text.truncate(127),
            "D13TextLength4225" => text.resize(4225, b'a'),
            "D13SurfaceLength1228799" => surface.truncate(1_228_799),
            "D13TextHeaderVersion" => put32(text, 0, 2),
            "D13TextHeaderReserved" => put32(text, 60, 1),
            "D13TextBodyHash" => text[24] ^= 1,
            "D13BaseRevisionMismatch" => {
                let revision = get64(text, 16)
                    .checked_add(1)
                    .ok_or("fault base overflow")?;
                put64(text, 16, revision);
            }
            "D13TextObjectMismatch" => {
                let object = get64(text, 8)
                    .checked_add(1)
                    .ok_or("fault object overflow")?;
                put64(text, 8, object);
            }
            "D13SurfaceCompanionHashMismatch" => text[96] ^= 1,
            "D13SurfaceAlphaMismatch" => {
                surface[3] = 0;
                text[96..128].copy_from_slice(&sha256(surface));
            }
            _ => {}
        }
        Ok(())
    }
    pub fn seals(&self, normal: i32) -> i32 {
        if !self.current {
            return normal;
        }
        match self.case {
            Some("D11RetainedWritableMapping" | "D11MprotectOnly") => 0,
            Some("D11FutureWriteOnly") => {
                libc::F_SEAL_FUTURE_WRITE
                    | libc::F_SEAL_GROW
                    | libc::F_SEAL_SHRINK
                    | libc::F_SEAL_SEAL
            }
            Some("D11MissingGrowSeal") => normal & !libc::F_SEAL_GROW,
            Some("D11MissingShrinkSeal") => normal & !libc::F_SEAL_SHRINK,
            Some("D11MissingFinalSeal") => normal & !libc::F_SEAL_SEAL,
            _ => normal,
        }
    }
    pub fn send_ack(&mut self, carrier: &Carrier, bytes: [u8; 88]) -> Result<()> {
        if self.fired {
            return carrier.send_raw(&bytes, &[]);
        }
        let Some(case) = self.case else {
            return carrier.send_raw(&bytes, &[]);
        };
        let mut raw = bytes.to_vec();
        let mut fds = Vec::new();
        let mut mutated = true;
        match case {
            "D03Frame87Bytes" | "D25ShortRecord" => raw.truncate(87),
            "D03Frame89Bytes" => raw.push(0),
            "D03ProtocolZero" => put32(&mut raw, 0, 0),
            "D03ForeignProtocolVersion" => put32(&mut raw, 0, 383),
            "D03MessageTypeZero" => put32(&mut raw, 4, 0),
            "D03MessageTypeNine" => put32(&mut raw, 4, 9),
            "D03NonzeroTail84" => raw[84] = 1,
            "D03NonzeroTail85" => raw[85] = 1,
            "D03NonzeroTail86" => raw[86] = 1,
            "D03NonzeroTail87" => raw[87] = 1,
            "D03WrongPayloadLength" => put32(&mut raw, 16, 63),
            "D03NonzeroReservedField" => raw[68] = 1,
            "D03UnknownFlags" => put32(&mut raw, 60, 2),
            "D03WrongMessageDirection" => {
                let request = get64(&raw, 20);
                let channel = get64(&raw, 28);
                let input = get64(&raw, 36);
                raw[20..84].fill(0);
                put32(&mut raw, 4, 2);
                put64(&mut raw, 20, request);
                put64(&mut raw, 28, channel);
                put64(&mut raw, 36, input);
                put64(&mut raw, 44, 1);
                put64(&mut raw, 52, 1);
                put32(&mut raw, 68, 4);
                put32(&mut raw, 72, 1);
            }
            "D05InputAckFdOne" => fds.push(3),
            "D05RecordTruncation" => raw.resize(512, 0x5a),
            "D14OldRequest" => {
                let value = get64(&raw, 20);
                put64(&mut raw, 20, value.saturating_sub(1));
            }
            "D14FutureInput" => {
                let value = get64(&raw, 36)
                    .checked_add(1)
                    .ok_or("fault input overflow")?;
                put64(&mut raw, 36, value);
            }
            "D14WrongChannelGeneration" => {
                let value = get64(&raw, 28)
                    .checked_add(1)
                    .ok_or("fault channel overflow")?;
                put64(&mut raw, 28, value);
            }
            "D14DuplicateAck" => {
                carrier.send_raw(&raw, &[])?;
            }
            _ => mutated = false,
        }
        if mutated {
            self.fired = true;
        }
        carrier.send_raw(&raw, &fds)
    }
    pub fn send_publication(
        &mut self,
        carrier: &Carrier,
        bytes: [u8; 88],
        fds: [RawFd; 2],
        input: u64,
        capture: bool,
    ) -> Result<()> {
        if capture {
            self.captured = Some(bytes);
        }
        if input == 0 || self.fired {
            return carrier.send_raw(&bytes, &fds);
        }
        let case = self.case.unwrap_or("");
        if self.reused_inode_case() || case == "D10ChildSavedImitationClipped" && !self.current {
            return carrier.send_raw(&bytes, &fds);
        }
        let mut raw = bytes;
        let mut aliases = fds.to_vec();
        match case {
            "D05PublishFdZero" => aliases.clear(),
            "D05PublishFdOne" => aliases.truncate(1),
            "D05PublishFdThree" => aliases.push(fds[0]),
            "D12SwappedOfferedRoles" => aliases.swap(0, 1),
            "D12DuplicateOfferedFdRoles" => aliases[1] = aliases[0],
            "D12StaleOfferId" => {
                let id = get64(&raw, 68);
                put64(&mut raw, 68, id.saturating_sub(1));
            }
            "D13TextLength127" => put32(&mut raw, 76, 127),
            "D13TextLength4225" | "D08Body4097" => put32(&mut raw, 76, 4225),
            "D13ControlLengthVsFstat" => {
                let len = u32::from_le_bytes(raw[76..80].try_into().unwrap());
                put32(&mut raw, 76, len.saturating_add(1));
            }
            "D14DuplicatePublish" => {
                carrier.send_raw(&raw, &aliases)?;
            }
            "D18UnsolicitedCapture" => {
                put32(&mut raw, 4, 8);
                put32(&mut raw, 68, 2);
                raw[72..84].fill(0);
                aliases.clear();
            }
            "D18CopiedOldCaptureRequest" => {
                if capture {
                    return carrier.send_raw(&bytes, &fds);
                }
                if let Some(old) = self.captured {
                    raw = old;
                } else {
                    return carrier.send_raw(&bytes, &fds);
                }
            }
            "D25EofWithPendingOffer" => {
                return Err("closed actual control with pending offer".into());
            }
            _ => {}
        }
        self.fired = true;
        carrier.send_raw(&raw, &aliases)
    }
    pub fn after_ack(&mut self, _carrier: &Carrier) -> Result<()> {
        if self.fired {
            return Ok(());
        }
        match self.case {
            Some("D25StdoutCapPlusOne" | "D25StderrCapPlusOne") => {
                self.fired = true;
                let fd = if self.case == Some("D25StdoutCapPlusOne") {
                    1
                } else {
                    2
                };
                write_all(fd, &[0x61; 16385], self.end)?;
            }
            Some("D25ActualSendBackpressure") => {
                self.fired = true;
                while Instant::now() < self.end {
                    std::thread::sleep(Duration::from_millis(1));
                }
                return Err("closed fixture stopped reading until original deadline".into());
            }
            _ => {}
        }
        Ok(())
    }
}
