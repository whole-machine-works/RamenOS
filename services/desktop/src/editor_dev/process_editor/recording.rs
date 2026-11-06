//! Diagnostic corpus persistence. No value loaded here grants native authority.
use super::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::atomic::Ordering;

fn checked<T>(r: std::io::Result<T>) -> Result<T, Status> {
    r.map_err(|_| Status::Internal)
}
fn require(b: bool) -> Result<(), Status> {
    if b { Ok(()) } else { Err(Status::Invalid) }
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}
fn sha(b: &[u8]) -> String {
    hex(&Sha256::digest(b))
}
fn label(s: &str, scenario: bool) -> Result<(), Status> {
    require(
        !s.is_empty()
            && s.len() <= 128
            && s.bytes().all(|b| {
                b.is_ascii_digit()
                    || b.is_ascii_lowercase()
                    || (scenario && b.is_ascii_uppercase())
                    || matches!(b, b'_' | b'-')
            }),
    )
}
fn open_at(parent: &File, name: &str, flags: i32, mode: u32) -> Result<File, Status> {
    let name = CString::new(name).map_err(|_| Status::Invalid)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    if fd < 0 {
        Err(Status::Internal)
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}
fn private(file: &File, directory: bool) -> Result<(), Status> {
    let m = checked(file.metadata())?;
    require(
        m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o777 == if directory { 0o700 } else { 0o600 }
            && if directory {
                m.is_dir()
            } else {
                m.is_file() && m.nlink() == 1
            },
    )
}
fn directory(parent: &File, name: &str, exclusive: bool) -> Result<File, Status> {
    let n = CString::new(name).map_err(|_| Status::Invalid)?;
    let rc = unsafe { libc::mkdirat(parent.as_raw_fd(), n.as_ptr(), 0o700) };
    if rc < 0 && (exclusive || std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST))
    {
        return Err(Status::Internal);
    }
    let f = open_at(parent, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
    private(&f, true)?;
    Ok(f)
}
fn write_leaf(dir: &File, name: &str, bytes: &[u8]) -> Result<(), Status> {
    let mut f = open_at(
        dir,
        name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )?;
    private(&f, false)?;
    checked(f.write_all(bytes))?;
    checked(f.sync_all())
}
fn bounded_json(v: &Value, cap: usize) -> Result<Vec<u8>, Status> {
    let mut b = serde_json::to_vec(v).map_err(|_| Status::Internal)?;
    b.push(b'\n');
    require(b.len() <= cap)?;
    Ok(b)
}
fn padded(v: &Value) -> Result<Vec<u8>, Status> {
    let mut b = bounded_json(v, 4096)?;
    b.resize(4096, b' ');
    Ok(b)
}
struct BudgetLock(File);
impl Drop for BudgetLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}
struct Raw {
    files: Vec<(String, Vec<u8>)>,
}
impl Raw {
    fn add(&mut self, bytes: &[u8]) -> Result<Value, Status> {
        require(bytes.len() <= 2_097_152)?;
        let digest = sha(bytes);
        if let Some((name, b)) = self.files.iter().find(|(_, b)| b.as_slice() == bytes) {
            return Ok(
                json!({"index": self.files.iter().position(|(n,_)|n==name).unwrap()+1,"path":name,"bytes":b.len(),"sha256":digest}),
            );
        }
        require(self.files.len() < 1024)?;
        let index = self.files.len() + 1;
        let name = format!("raw-{index:04}.bin");
        self.files.push((name.clone(), bytes.to_vec()));
        Ok(json!({"index":index,"path":name,"bytes":bytes.len(),"sha256":digest}))
    }
}
fn nanos(at: Instant, start: Instant) -> Result<u64, Status> {
    u64::try_from(
        at.checked_duration_since(start)
            .ok_or(Status::Invalid)?
            .as_nanos(),
    )
    .map_err(|_| Status::Exhausted)
}
fn time(at: Option<Instant>, start: Instant) -> Value {
    // Deadlines/admission may precede arming. Retain signed relative offsets.
    at.map(|at| {
        if at >= start {
            json!(at.duration_since(start).as_nanos().to_string())
        } else {
            json!(format!("-{}", start.duration_since(at).as_nanos()))
        }
    })
    .unwrap_or(Value::Null)
}
fn snapshot(s: &ProcessAssertionSnapshot, raw: &mut Raw, start: Instant) -> Result<Value, Status> {
    let document=s.document.as_ref().map(|d|json!({"actor":d.actor,"document_id":d.document_id,"bytes":d.bytes,"cursor":d.cursor,"selection":d.selection,"first_visible_line":d.first_visible_line,"text_generation":d.text_generation,"view_version":d.view_version,"confirmed_revision":d.confirmed_revision,"confirmed_hash":hex(&d.confirmed_hash),"phase":format!("{:?}",d.phase)}));
    Ok(
        json!({"document":document,"app_pixels":raw.add(&s.app_pixels)?,"composed_pixels":raw.add(&s.composed_pixels)?,"app_sha256":hex(&s.app_sha256),"composed_sha256":hex(&s.composed_sha256),"core_ordinary_queue":s.core_ordinary_queue,"core_reset_queue":s.core_reset_queue,"offer_cursor":s.offer_cursor,"frame_surface_id":s.frame_surface_id,"frame_surface_generation":s.frame_surface_generation,"frame_surface_epoch":s.frame_surface_epoch,"frame_surface_live":s.frame_surface_live,"owner_confirm_request":s.owner_confirm_request.map(|bytes|bytes.to_vec()),"owner_confirm_status":s.owner_confirm_status.map(|status|format!("{status:?}")),"focus_epoch":s.focus_epoch,"service_epoch":s.service_epoch,"channel_generation":s.channel_generation,"publication_generation":s.publication_generation,"delivered_sequence":s.delivered_sequence,"acknowledged_sequence":s.acknowledged_sequence,"request_sequence":s.request_sequence,"pending_offer_id":s.pending_offer_id,"syscall_count":s.syscall_count,"control_count":s.control_count,"descriptor_count":s.descriptor_count,"owners":{"data":s.owners.data,"fixed":s.owners.fixed,"combined":s.owners.combined,"maps":s.owners.maps,"children":s.owners.children,"supervisors":s.owners.supervisors,"pending_inputs":s.owners.pending_inputs,"ordinary_queue":s.owners.ordinary_queue,"reset_queue":s.owners.reset_queue,"lifetime_objects":s.owners.lifetime_objects,"lifetime_bytes":s.owners.lifetime_bytes,"lifetime_offers":s.owners.lifetime_offers},"adoption_status":s.adoption_status.map(|v|format!("{v:?}")),"admitted_at_ns":time(s.admitted_at,start),"child_deadline_ns":time(s.child_deadline,start),"captured_at_ns":time(s.captured_at,start),"save_deadline_ns":time(s.save_deadline,start)}),
    )
}
fn base64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for c in bytes.chunks(3) {
        let n = ((c[0] as u32) << 16)
            | ((c.get(1).copied().unwrap_or(0) as u32) << 8)
            | c.get(2).copied().unwrap_or(0) as u32;
        s.push(T[(n >> 18) as usize] as char);
        s.push(T[((n >> 12) & 63) as usize] as char);
        s.push(if c.len() > 1 {
            T[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        s.push(if c.len() > 2 {
            T[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    s
}
fn controls(
    e: &ProcessAssertionEvidence,
    scope: &RunScope,
    raw: &mut Raw,
) -> Result<Vec<u8>, Status> {
    require(
        e.controls.len() <= 32768
            && e.controls.len() == e.control_times.len()
            && e.controls.len() == e.control_syscalls.len(),
    )?;
    let mut out = Vec::new();
    for (i, c) in e.controls.iter().enumerate() {
        require(c.sequence == i as u64 + 1)?;
        let call = e
            .syscalls
            .get(e.control_syscalls[i])
            .ok_or(Status::Invalid)?;
        require(
            matches!(
                call.operation,
                ProcessAssertionOperation::Sendmsg | ProcessAssertionOperation::Recvmsg
            ) && call
                .ancillary_descriptor_ids
                .iter()
                .all(|n| *n <= u32::MAX as u64),
        )?;
        let k = if call.result < 0 {
            "kernel_reject"
        } else if call.operation == ProcessAssertionOperation::Sendmsg {
            "send"
        } else {
            "recv"
        };
        let d = match c.direction {
            ProcessAssertionDirection::ParentToChild => 0,
            ProcessAssertionDirection::ChildToParent => 1,
        };
        let b = if c.bytes.len() == 88 {
            base64(&c.bytes)
        } else {
            String::new()
        };
        let r = if c.bytes.len() == 88 {
            0
        } else {
            raw.add(&c.bytes)?["index"]
                .as_u64()
                .ok_or(Status::Internal)?
        };
        let (q, s) = match desktop_editor_core::wire::decode_frame(&c.bytes) {
            Ok((_, m)) => match m {
                ProcessMessage::Bootstrap(v) => (v.request_id, 0),
                ProcessMessage::Stop(v) => (v.request_id, 0),
                ProcessMessage::DeliverInput(v) => (v.request_id, v.input_sequence),
                ProcessMessage::InputAck(v) => (v.request_id, v.input_sequence),
                ProcessMessage::Publish(v) => (v.request_id, v.input_sequence),
                ProcessMessage::PublishAck(v) => (v.request_id, v.input_sequence),
                ProcessMessage::ReceiptNotice(v) => (v.request_id, v.capture_input_sequence),
                ProcessMessage::RequestPublication(v) => (v.request_id, v.last_input_sequence),
            },
            Err(_) => (0, 0),
        };
        let cred = serde_json::to_string(&c.sender.map(|(a, b, c)| [a, b, c]))
            .map_err(|_| Status::Internal)?;
        let objects = serde_json::to_string(if call.ancillary_descriptor_ids.len() <= 3 {
            &call.ancillary_descriptor_ids[..]
        } else {
            &[]
        })
        .map_err(|_| Status::Internal)?;
        let line = format!(
            "{{\"i\":{},\"k\":\"{}\",\"d\":{},\"b\":\"{}\",\"c\":{},\"o\":{},\"q\":{},\"s\":{},\"t\":{},\"f\":{},\"r\":{}}}\n",
            i + 1,
            k,
            d,
            b,
            cred,
            objects,
            q,
            s,
            nanos(e.control_times[i], scope.started_at)?,
            c.msg_flags,
            r
        );
        require(line.len() <= 512 && out.len() + line.len() <= 16_777_216)?;
        out.extend_from_slice(line.as_bytes());
    }
    Ok(out)
}

fn owners_json(o: &ProcessAssertionOwners) -> Value {
    json!({"data":o.data,"fixed":o.fixed,"combined":o.combined,"maps":o.maps,"children":o.children,"supervisors":o.supervisors,"pending_inputs":o.pending_inputs,"ordinary_queue":o.ordinary_queue,"reset_queue":o.reset_queue,"lifetime_objects":o.lifetime_objects,"lifetime_bytes":o.lifetime_bytes,"lifetime_offers":o.lifetime_offers})
}
fn syscall_rows(rows: &[ProcessAssertionSyscall]) -> Vec<Value> {
    rows.iter().map(|s|json!({"operation":format!("{:?}",s.operation),"origin":format!("{:?}",s.origin),"result":s.result,"errno":s.errno,"sender":s.sender,"msg_flags":s.msg_flags,"received_fds":s.received_fds,"descriptor_id":s.descriptor_id,"poll_revents":s.poll_revents,"ancillary":s.ancillary,"ancillary_descriptor_ids":s.ancillary_descriptor_ids})).collect()
}
fn descriptor_rows(rows: &[ProcessAssertionDescriptor]) -> Vec<Value> {
    rows.iter().map(|d|json!({"role":format!("{:?}",d.role),"descriptor_id":d.descriptor_id,"device":d.device,"inode":d.inode,"byte_len":d.byte_len,"owner_process_id":d.owner_process_id,"offer_id":d.offer_id,"event":format!("{:?}",d.event),"mode":d.mode,"seals":d.seals,"mapping":format!("{:?}",d.mapping),"disposition":format!("{:?}",d.disposition)})).collect()
}
fn process_rows(rows: &[RecordedProcess]) -> Vec<Value> {
    rows.iter().map(|p|json!({"parent_pid":p.parent_pid,"child_pid":p.child_pid,"birth_ticks":p.birth_ticks,"pidfd_ledger_id":p.pidfd_ledger_id,"supervisor_native_tid":p.supervisor_native_tid,"supervisor_rust_id":p.supervisor_rust_id,"wait_raw_status":p.wait_raw_status,"wait_outcome":p.wait_outcome.map(|v|format!("{v:?}")),"supervisor_joined":p.supervisor_joined,"quarantined":p.quarantined})).collect()
}
fn executable_json(value: Option<&ProcessAssertionExecutable>) -> Option<Value> {
    value.map(|x|json!({"registered_sha256":hex(&x.registered_sha256),"held_sha256":hex(&x.held_sha256),"source_before_sha256":hex(&x.source_before_sha256),"source_after_sha256":hex(&x.source_after_sha256),"source_before_device":x.source_before_device,"source_before_inode":x.source_before_inode,"source_after_device":x.source_after_device,"source_after_inode":x.source_after_inode,"held_device":x.held_device,"held_inode":x.held_inode,"executed_device":x.executed_device,"executed_inode":x.executed_inode,"executed_sha256":x.executed_sha256.map(|v|hex(&v)),"held_mode":x.held_mode,"held_seals":x.held_seals,"checkpoint_sequence":x.checkpoint_sequence,"action":x.action.map(|a|format!("{a:?}")),"source_header":x.source_header}))
}

pub(super) fn persist(e: &ProcessAssertionEvidence, scope: &RunScope) -> Result<(), Status> {
    label(scope.parent_case, false)?;
    label(scope.scenario_id, true)?;
    require(e.scenario == scope.scenario_id && e.processes.len() <= 8 && e.objects.len() <= 2056)?;
    let nonce = std::env::var("RAMEN_PROCESS_RUN_NONCE").map_err(|_| Status::Invalid)?;
    require(
        nonce.len() == 32
            && nonce
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && std::env::var("RAMEN_NATIVE_TASK_RUN_NONCE").ok().as_ref() == Some(&nonce),
    )?;
    let root_path = std::env::var_os("RAMEN_PROCESS_EVIDENCE").ok_or(Status::Invalid)?;
    require(Path::new(&root_path).is_absolute())?;
    let root = checked(
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(root_path),
    )?;
    private(&root, true)?;
    let gate_path = std::env::var_os("RAMEN_PROCESS_GATE_RECORD").ok_or(Status::Invalid)?;
    let gate = checked(
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(gate_path),
    )?;
    let gm = checked(gate.metadata())?;
    require(gm.is_file() && gm.len() <= 33_554_432)?;
    let mut gb = Vec::new();
    checked(gate.take(33_554_433).read_to_end(&mut gb))?;
    require(gb.len() <= 33_554_432)?;
    let gate: Value = serde_json::from_slice(&gb).map_err(|_| Status::Invalid)?;
    let source = gate["source_manifest"]["sha256"]
        .as_str()
        .ok_or(Status::Invalid)?;
    require(
        source.len() == 64
            && source
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
    )?;
    let mut raw = Raw { files: Vec::new() };
    let before = snapshot(&e.before, &mut raw, scope.started_at)?;
    let after = snapshot(&e.after, &mut raw, scope.started_at)?;
    let control = controls(e, scope, &mut raw)?;
    let mut objects = Vec::new();
    for o in &e.objects {
        require(sha(&o.bytes) == hex(&o.sha256))?;
        objects.push(json!({"descriptor_id":o.descriptor_id,"raw":raw.add(&o.bytes)?,"sha256":hex(&o.sha256),"observation":"actual retained bytes; immutability requires matching native seals/mapping ledger"}));
    }
    let syscalls = syscall_rows(&e.syscalls);
    let descriptors = descriptor_rows(&e.descriptors);
    let mut points = Vec::new();
    for p in &e.points {
        points.push(json!({"point":format!("{:?}",p.point()),"sequence":p.sequence(),"reached_at_ns":nanos(p.reached_at(),scope.started_at)?}));
    }
    let processes = process_rows(&e.processes);
    let executable = executable_json(e.executable.as_ref());
    require(
        e.referenced_processes.len() <= 7
            && e.processes.len()
                + e.referenced_processes
                    .iter()
                    .map(|r| r.processes.len())
                    .sum::<usize>()
                <= 8,
    )?;
    let referenced_processes:Vec<_>=e.referenced_processes.iter().map(|r|json!({"role":"ReferencedSibling","source_scope":{"parent_case":r.parent_case,"channel_generation":r.channel_generation,"scenario_id":r.scenario_id},"processes":process_rows(&r.processes),"syscalls":syscall_rows(&r.syscalls),"descriptors":descriptor_rows(&r.descriptors),"executable":executable_json(r.executable.as_ref()),"owners_after_cleanup":owners_json(&r.owners_after_cleanup)})).collect();
    require(
        e.retired_bootstraps.len() <= 2
            && e.processes.len()
                + e.referenced_processes
                    .iter()
                    .map(|r| r.processes.len())
                    .sum::<usize>()
                + e.retired_bootstraps
                    .iter()
                    .map(|h| h.processes.len())
                    .sum::<usize>()
                <= 8,
    )?;
    let mut retired_bootstraps = Vec::new();
    for h in &e.retired_bootstraps {
        let o = &h.owners_after_cleanup;
        retired_bootstraps.push(json!({"role":"RetiredBootstrapSource","source_scope":{"parent_case":h.parent_case,"channel_generation":h.channel_generation,"scenario_id":h.scenario_id},"raw":raw.add(&h.bytes)?,"send":syscall_rows(std::slice::from_ref(&h.send)).pop().ok_or(Status::Internal)?,"processes":process_rows(&h.processes),"proof_syscalls":syscall_rows(&h.proof_syscalls),"descriptors":descriptor_rows(&h.descriptors),"executable":executable_json(h.executable.as_ref()),"owners_after_cleanup":{"data":o.data,"fixed":o.fixed,"combined":o.combined,"maps":o.maps,"children":o.children,"supervisors":o.supervisors,"pending_inputs":o.pending_inputs,"ordinary_queue":o.ordinary_queue,"reset_queue":o.reset_queue,"lifetime_objects":o.lifetime_objects,"lifetime_bytes":o.lifetime_bytes,"lifetime_offers":o.lifetime_offers}}));
    }
    require(
        e.fork_helpers.len() <= 1
            && e.processes.len()
                + e.referenced_processes
                    .iter()
                    .map(|r| r.processes.len())
                    .sum::<usize>()
                + e.retired_bootstraps
                    .iter()
                    .map(|h| h.processes.len())
                    .sum::<usize>()
                + e.fork_helpers.len()
                <= 8,
    )?;
    let fork_helpers:Vec<_>=e.fork_helpers.iter().map(|h|json!({"role":"AssertionForkHelper","execution_kind":"ForkOnlyNoExec","source_scope":{"parent_case":h.parent_case,"scenario_id":h.scenario_id,"channel_generation":h.channel_generation},"process":process_rows(std::slice::from_ref(&h.process)).pop(),"syscall_indices":h.syscall_indices,"received_syscall_index":h.received_syscall_index,"descriptors":descriptor_rows(&h.descriptors),"creation_peer_credentials":h.creation_peer_credentials,"received_credentials":h.received_credentials,"endpoint_aliases_after_cleanup":h.endpoint_aliases_after_cleanup,"helper_slots_after_cleanup":h.helper_slots_after_cleanup})).collect();
    let mut budget = BudgetLock(open_at(
        &root,
        ".budget.json",
        libc::O_RDWR | libc::O_CREAT,
        0o600,
    )?);
    private(&budget.0, false)?;
    if unsafe { libc::flock(budget.0.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(Status::Internal);
    }
    let mut bytes = Vec::new();
    checked((&mut budget.0).take(4097).read_to_end(&mut bytes))?;
    require(bytes.len() <= 4096)?;
    let mut ledger: Value = if bytes.is_empty() {
        json!({"schema_version":1,"run_nonce":nonce,"next_run":0,"files":1,"entries":1,"bytes":4096,"controls":0})
    } else {
        {
            require(bytes.len() == 4096)?;
            let frame: Value = serde_json::from_slice(&bytes).map_err(|_| Status::Invalid)?;
            require(frame.as_object().is_some_and(|o| o.len() == 2))?;
            let payload = serde_json::to_vec(&frame["ledger"]).map_err(|_| Status::Internal)?;
            require(frame["sha256"].as_str() == Some(sha(&payload).as_str()))?;
            frame["ledger"].clone()
        }
    };
    require(
        ledger["schema_version"] == 1
            && ledger["run_nonce"] == nonce
            && scope.run_ordinal.load(Ordering::Acquire) == 0,
    )?;
    let ordinal = ledger["next_run"]
        .as_u64()
        .ok_or(Status::Invalid)?
        .checked_add(1)
        .ok_or(Status::Exhausted)?;
    require(
        scope.parent_case.len() + 1 + scope.scenario_id.len() + 1 + ordinal.to_string().len()
            <= 256,
    )?;
    let metadata = json!({"schema_version":1,"run_nonce":nonce,"source_manifest_sha256":source,"scope":{"parent_case":scope.parent_case,"scenario_id":scope.scenario_id,"run_ordinal":ordinal,"parent_pid":scope.parent_pid,"channel_generation":e.active_channel_generation},"recording_complete":true,"controls":{"path":"controls.jsonl","bytes":control.len(),"sha256":sha(&control),"rows":e.controls.len(),"first_row":if e.controls.is_empty(){0}else{1},"last_row":e.controls.len(),"syscall_indices":e.control_syscalls},"before":before,"after":after,"syscalls":syscalls,"descriptors":descriptors,"objects":objects,"executable":executable,"checkpoints":points,"native_wait_outcome":e.wait.map(|v|format!("{v:?}")),"supervisor_joined":e.joined,"quarantined":e.quarantined,"processes":processes,"referenced_processes":referenced_processes,"retired_bootstraps":retired_bootstraps,"fork_helpers":fork_helpers});
    let metadata = bounded_json(&metadata, 33_554_432)?;
    let files = raw.files.len() as u64 + 3;
    let total = raw.files.iter().try_fold(
        control.len() as u64 + metadata.len() as u64 + 4096,
        |n, (_, b)| n.checked_add(b.len() as u64).ok_or(Status::Exhausted),
    )?;
    for (key, delta, max) in [
        ("files", files, 16384),
        ("entries", files + 2, 17000),
        ("bytes", total, 2_147_483_648),
        ("controls", e.controls.len() as u64, 131072),
    ] {
        let n = ledger[key]
            .as_u64()
            .ok_or(Status::Invalid)?
            .checked_add(delta)
            .ok_or(Status::Exhausted)?;
        if n > max {
            return Err(Status::Exhausted);
        }
        ledger[key] = json!(n);
    }
    ledger["next_run"] = json!(ordinal);
    let payload = serde_json::to_vec(&ledger).map_err(|_| Status::Internal)?;
    let bytes = padded(&json!({"ledger":ledger,"sha256":sha(&payload)}))?;
    checked(budget.0.seek(SeekFrom::Start(0)))?;
    checked(budget.0.write_all(&bytes))?;
    checked(budget.0.sync_all())?;
    scope.run_ordinal.store(ordinal, Ordering::Release);
    drop(budget);
    let case = directory(&root, scope.parent_case, false)?;
    let run = directory(&case, &format!("{}-{ordinal}", scope.scenario_id), true)?;
    let mut progress = open_at(
        &run,
        "progress.json",
        libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )?;
    private(&progress, false)?;
    checked(progress.write_all(&padded(&json!({"schema_version":1,"run_nonce":nonce,"run_ordinal":ordinal,"recording_complete":false,"files_written":0}))?))?;
    checked(progress.sync_all())?;
    let update_progress = |file: &mut File, count: u64, complete: bool| -> Result<(), Status> {
        checked(file.seek(SeekFrom::Start(0)))?;
        checked(file.write_all(&padded(&json!({"schema_version":1,"run_nonce":nonce,"run_ordinal":ordinal,"recording_complete":complete,"files_written":count}))?))?;
        checked(file.sync_all())
    };
    let mut written = 1;
    for (name, b) in &raw.files {
        write_leaf(&run, name, b)?;
        written += 1;
        update_progress(&mut progress, written, false)?;
    }
    write_leaf(&run, "controls.jsonl", &control)?;
    written += 1;
    update_progress(&mut progress, written, false)?;
    write_leaf(&run, "metadata.json", &metadata)?;
    written += 1;
    checked(run.sync_all())?;
    update_progress(&mut progress, written, true)?;
    checked(run.sync_all())?;
    checked(case.sync_all())?;
    checked(root.sync_all())?;
    Ok(())
}
