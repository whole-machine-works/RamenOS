#!/usr/bin/env python3
"""Read complete bounded native process recordings; diagnostic data grants no authority."""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat

LIMITS = {'files': 16384, 'entries': 17000, 'bytes': 2147483648, 'controls': 131072}
KEYS = ['i', 'k', 'd', 'b', 'c', 'o', 'q', 's', 't', 'f', 'r']
class Invalid(RuntimeError):
    pass

def need(condition, reason):
    if not condition:
        raise Invalid(reason)

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def read(path: Path, cap: int):
    # Hold every parent across no-follow traversal; never reopen through a
    # checked directory name that can subsequently become a symlink.
    absolute = path.absolute()
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in absolute.parts[1:-1]:
            following = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            os.close(parent)
            parent = following
        fd = os.open(absolute.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= cap, f'bounded regular leaf: {path}')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(cap + 1)
        after = os.fstat(fd)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(len(raw) <= cap and identity(before) == identity(after), f'leaf changed: {path}')
        return raw
    finally:
        os.close(fd)

def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'duplicate JSON field')
        result[key] = value
    return result

def decode(raw):
    return json.loads(raw, object_pairs_hook=unique)

def integer(n, maximum=(1 << 64)-1):
    return type(n) is int and 0 <= n <= maximum

def ref(directory, item, inventory, refs):
    need(set(item) == {'index', 'path', 'bytes', 'sha256'}, 'exact raw reference')
    index = item['index']
    need(integer(index, 1024) and index > 0, 'bounded raw index')
    name = f'raw-{index:04}.bin'
    need(item['path'] == name and name in inventory, 'raw reference identity')
    raw = read(directory/name, 2097152)
    need(integer(item['bytes'],2097152) and hash_value(item['sha256']) and len(raw) == item['bytes'] and digest(raw) == item['sha256'], 'raw length/hash')
    prior = refs.setdefault(index, item)
    need(prior == item, 'raw index reused with other identity')
    return raw

def shape(value, keys, reason):
    need(type(value) is dict and set(value) == set(keys.split()), reason)

def credential(value):
    return value is None or type(value) is list and len(value)==3 and all(integer(n,0xffffffff) for n in value)

def hash_value(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None

def wire_projection(frame):
    # Mirrors the recorder's production-codec success boundary, not merely
    # unvalidated offsets. Invalid encodings have no decoded q/s projection.
    if len(frame)!=88:return (0,0)
    u32=lambda n:int.from_bytes(frame[n:n+4],'little')
    u64=lambda n:int.from_bytes(frame[n:n+8],'little')
    kind=u32(4)
    if u32(0)!=384 or not 1<=kind<=8 or u32(16)!=64 or any(frame[84:]):return (0,0)
    payload=frame[20:84]
    zero=lambda a,b: not any(payload[a:b])
    v32=lambda n:int.from_bytes(payload[n:n+4],'little')
    v64=lambda n:int.from_bytes(payload[n:n+8],'little')
    valid=True
    if kind==1:valid=zero(48,64) and 64<=v32(32)<=4160 and (v32(36),v32(40),v32(44))==(640,480,2560)
    elif kind==2:valid=v64(40)==0 and v32(60)<=2 and 1<=v32(52)<=3 and v32(56)&~3==0
    elif kind==3:valid=zero(48,64) and v32(40)<=1 and v32(44)<=11 and (v32(44)==0 or zero(8,44))
    elif kind==4:valid=zero(20,64) and 1<=v32(16)<=6
    elif kind==5:valid=128<=v32(56)<=4224 and v32(60)==1228800
    elif kind==6:valid=zero(36,64) and v32(32)<=11 and (v32(32)==0 or zero(8,32))
    elif kind==7:valid=zero(56,64) and (v32(48),v32(52)) in ((0,0),(0,1),(1,2))
    elif kind==8:valid=zero(52,64) and v32(48) in (0,2)
    if not valid:return (0,0)
    return (u64(20),u64(44) if kind==6 else u64(36) if kind in (2,3,5,7,8) else 0)

def descriptor_facts(descriptors):
    known = set()
    for row in descriptors:
        shape(row,'role descriptor_id device inode byte_len owner_process_id offer_id event mode seals mapping disposition','exact descriptor')
        for field in ('device','inode','byte_len','mode','seals'):need(integer(row[field]), 'descriptor scalar')
        need(row['role'] in {'Selected','TextState','Surface','Executable','Control','Barrier','Pidfd','ExecError','Stdout','Stderr'} and row['event'] in {'Offered','Returned','Other'} and row['mapping'] in {'None','SharedWritable','ReadOnly','Unmapped'} and row['disposition'] in {'Held','Received','Closed','Quarantined'}, 'descriptor enums')
        need(row['owner_process_id'] is None or integer(row['owner_process_id'],0xffffffff) and row['owner_process_id']>0, 'descriptor owner pid')
        need(row['offer_id'] is None or integer(row['offer_id']), 'descriptor offer')
        need(integer(row['descriptor_id']) and row['descriptor_id'] > 0, 'descriptor identity')
        known.add(row['descriptor_id'])
    return known

def syscall_facts(calls,known):
    need(len(calls) <= 131072, 'syscall recording bound')
    for call in calls:
        shape(call,'operation origin result errno sender msg_flags received_fds descriptor_id poll_revents ancillary ancillary_descriptor_ids','exact syscall')
        need(type(call['result']) is int and -(1<<63)<=call['result']<(1<<63), 'signed actual syscall result')
        need(call['errno'] is None or integer(call['errno'],0x7fffffff), 'native errno')
        need(credential(call['sender']), 'actual credential tuple')
        need(integer(call['msg_flags'],0xffffffff) and integer(call['received_fds'],0xffffffff) and integer(call['poll_revents'],0xffffffff), 'native syscall scalar')
        need(call['descriptor_id'] is None or call['descriptor_id'] in known, 'syscall descriptor')
        need(call['operation'] in {'Open','MemfdCreate','Fstat','Pread','Pwrite','Read','Write','Poll','Truncate','GetSeals','AddSeals','Mmap','Munmap','Fork','PidfdOpen','Execveat','Sendmsg','Recvmsg','Signal','Waitpid','Close','SupervisorStart','ParseAncillary','DuplicateFd','PeerCredentials'}, 'closed syscall operation')
        need(call['origin'] in {'Native','InjectedBeforeSyscall','ParserStructural','InjectedBeforeOperation'}, 'syscall origin')
        need(len(call['ancillary']) <= 256 and all(integer(v,255) for v in call['ancillary']), 'complete bounded ancillary projection')
        need(all(integer(v) and v in known for v in call['ancillary_descriptor_ids']), 'ancillary descriptor join')

def process_facts(processes,calls,known,executable,parent_pid,require_editor_image=True):
    for process in processes:
        shape(process,'parent_pid child_pid birth_ticks pidfd_ledger_id supervisor_native_tid supervisor_rust_id wait_raw_status wait_outcome supervisor_joined quarantined','exact process row')
        need(type(process['supervisor_joined']) is bool and process['quarantined'] is False, 'process terminal flags')
        need(integer(process['supervisor_native_tid'],0xffffffff) and process['supervisor_native_tid']>0 and type(process['supervisor_rust_id']) is str and re.fullmatch(r'ThreadId\([0-9]+\)',process['supervisor_rust_id']), 'actual supervisor identities')
        need(process['birth_ticks'] is None or integer(process['birth_ticks']) and process['birth_ticks']>0, 'actual birth ticks')
        need(process['pidfd_ledger_id'] is None or process['pidfd_ledger_id'] in known, 'pidfd ledger join')
        need(process['parent_pid'] == parent_pid, 'actual parent binding')
        pid = process['child_pid']
        if pid is not None:
            need(integer(pid,0xffffffff) and pid > 0 and any(c['operation']=='Fork' and c['origin']=='Native' and c['result']==pid for c in calls), 'fork-derived child')
        status = process['wait_raw_status']
        if status is not None:
            need(type(status) is int and -(1<<31)<=status<(1<<31), 'bounded raw native wait status')
            need(any(c['operation']=='Waitpid' and c['origin']=='Native' and c['result']==pid for c in calls), 'actual consuming wait')
            expected = f'Exited({os.waitstatus_to_exitcode(status)})' if os.WIFEXITED(status) else f'Signaled({os.WTERMSIG(status)})' if os.WIFSIGNALED(status) else None
            need(expected is not None and expected == process['wait_outcome'], 'raw wait outcome decode')
        if pid is not None:
            need(process['supervisor_joined'] and status is not None and process['birth_ticks'] is not None, 'completed child requires genuine birth/wait/supervisor join')
            if require_editor_image:need(executable is not None, 'fork requires held executable provenance')
    if executable is not None:
        shape(executable,'registered_sha256 held_sha256 source_before_sha256 source_after_sha256 source_before_device source_before_inode source_after_device source_after_inode held_device held_inode executed_device executed_inode executed_sha256 held_mode held_seals checkpoint_sequence action source_header','exact executable')
        for field in ('registered_sha256','held_sha256','source_before_sha256','source_after_sha256'):need(hash_value(executable[field]), 'executable hash')
        for field in ('source_before_device','source_before_inode','source_after_device','source_after_inode','held_device','held_inode','held_mode','held_seals','checkpoint_sequence'):need(integer(executable[field]), 'executable scalar')
        for field in ('executed_device','executed_inode'):need(executable[field] is None or integer(executable[field]), 'executed identity')
        need(executable['executed_sha256'] is None or hash_value(executable['executed_sha256']), 'executed hash')
        need(executable['action'] is None or executable['action'] in {'ReplacePath','MutateOriginalInode','HeldWrite','HeldGrow','HeldShrink'}, 'executable closed action')
        if any(p['child_pid'] is not None for p in processes):
            need(executable['held_inode']>0 and executable['held_mode'] & 0o170000 == 0o100000 and executable['held_seals'] & 15 == 15 and executable['held_sha256']==executable['registered_sha256'], 'held ELF identity before fork')
        if executable['executed_sha256'] is not None:
            need((executable['executed_device'],executable['executed_inode'],executable['executed_sha256'])==(executable['held_device'],executable['held_inode'],executable['held_sha256']), 'actual executed held ELF identity')
        need(type(executable['source_header']) is list and len(executable['source_header'])<=64 and all(integer(v,255) for v in executable['source_header']), 'bounded ELF header')
    return {p["child_pid"] for p in processes if p["child_pid"] is not None}

def inspect_run(directory, nonce, source, inventory):
    metadata = decode(read(directory/'metadata.json', 33554432))
    progress = decode(read(directory/'progress.json', 4096))
    need(metadata['schema_version'] == progress['schema_version'] == 1, 'record version')
    need(metadata['recording_complete'] is True and progress['recording_complete'] is True, 'incomplete process recording')
    shape(metadata, 'schema_version run_nonce source_manifest_sha256 scope recording_complete controls before after syscalls descriptors objects executable checkpoints native_wait_outcome supervisor_joined quarantined processes referenced_processes retired_bootstraps fork_helpers', 'exact declared metadata')
    shape(progress, 'schema_version run_nonce run_ordinal recording_complete files_written', 'exact progress')
    need(type(metadata['supervisor_joined']) is bool and metadata['quarantined'] is False, 'known nonquarantined recording completion')
    scope = metadata['scope']
    shape(scope, 'parent_case scenario_id run_ordinal parent_pid channel_generation', 'exact scope')
    need(integer(scope['channel_generation']), 'channel generation')
    need(metadata['run_nonce'] == progress['run_nonce'] == nonce and metadata['source_manifest_sha256'] == source, 'record provenance')
    need(progress['run_ordinal'] == scope['run_ordinal'] and integer(scope['run_ordinal']) and scope['run_ordinal'] > 0, 'actual ordinal')
    need(re.fullmatch('[a-z0-9_-]{1,128}', scope['parent_case']) and re.fullmatch('[A-Za-z0-9_-]{1,128}', scope['scenario_id']), 'scope label')
    need(directory.parent.name == scope['parent_case'] and directory.name == f"{scope['scenario_id']}-{scope['run_ordinal']}", 'scope path')
    need(integer(scope['parent_pid'], 0xffffffff) and scope['parent_pid'] > 0, 'actual parent pid')
    need(progress['files_written'] == len(inventory), 'complete file inventory')
    refs = {}
    for snapshot in (metadata['before'], metadata['after']):
        shape(snapshot, 'document app_pixels composed_pixels app_sha256 composed_sha256 core_ordinary_queue core_reset_queue offer_cursor frame_surface_id frame_surface_generation frame_surface_epoch frame_surface_live owner_confirm_request owner_confirm_status focus_epoch service_epoch channel_generation publication_generation delivered_sequence acknowledged_sequence request_sequence pending_offer_id syscall_count control_count descriptor_count owners adoption_status admitted_at_ns child_deadline_ns captured_at_ns save_deadline_ns', 'exact snapshot')
        for field in ('focus_epoch','service_epoch','channel_generation','publication_generation','delivered_sequence','acknowledged_sequence','request_sequence','syscall_count','control_count','descriptor_count'):
            need(integer(snapshot[field]), 'snapshot scalar')
        need(snapshot['pending_offer_id'] is None or integer(snapshot['pending_offer_id']), 'pending offer')
        need(snapshot['adoption_status'] is None or snapshot['adoption_status'] in {'Ok','Denied','Stale','Invalid','Timeout','NotReady','Exhausted','Disconnected','Unsupported','Internal','NotFound','Busy'}, 'status enum')
        for field in ('admitted_at_ns','child_deadline_ns','captured_at_ns','save_deadline_ns'):
            need(snapshot[field] is None or type(snapshot[field]) is str and re.fullmatch('-?(0|[1-9][0-9]{0,38})',snapshot[field]), 'signed relative time')
        frame_keys=('frame_surface_id','frame_surface_generation','frame_surface_epoch')
        present=snapshot['frame_surface_id'] is not None
        need(all((snapshot[k] is not None)==present and (not present or integer(snapshot[k]) and snapshot[k]>0) for k in frame_keys) and (type(snapshot['frame_surface_live']) is bool if present else snapshot['frame_surface_live'] is None), 'actual complete typed Core surface binding')
        request = snapshot['owner_confirm_request']
        need(request is None or type(request) is list and len(request)==88 and all(integer(b,255) for b in request), 'actual owner confirm request')
        need((request is None)==(snapshot['owner_confirm_status'] is None) and (request is None or snapshot['owner_confirm_status'] in {'Ok','Stale','Denied','Invalid','NotReady','Timeout','Exhausted','Unsupported','Disconnected','Internal','Conflict'}), 'actual owner invocation status')
        need(integer(snapshot['offer_cursor']), 'actual offer cursor')
        need(integer(snapshot['core_ordinary_queue'],64) and integer(snapshot['core_reset_queue'],1) and not(snapshot['core_ordinary_queue'] and snapshot['core_reset_queue']), 'separate unchanged Core queue bounds')
        document=snapshot['document']
        if document is not None:
            shape(document,'actor document_id bytes cursor selection first_visible_line text_generation view_version confirmed_revision confirmed_hash phase','exact document')
            shape(document['actor'],'owner_id session_id session_generation instance_id instance_generation','actual actor tuple')
            need(all(integer(n) for n in document['actor'].values()), 'actor scalars')
            need(type(document['bytes']) is list and len(document['bytes'])<=4096 and all(integer(b,127) and b!=0 for b in document['bytes']), 'bounded native document')
            need(document['cursor']<=len(document['bytes']), 'native cursor bound')
            selection=document['selection']
            need(selection is None or type(selection) is list and len(selection)==2 and all(integer(n) for n in selection) and selection[0]<=selection[1]<=len(document['bytes']), 'native selection bound')
            for field in ('document_id','cursor','first_visible_line','text_generation','view_version','confirmed_revision'):need(integer(document[field]), 'document scalar')
            need(hash_value(document['confirmed_hash']) and document['phase'] in {'Loaded','Unsaved','AllocationPending','AllocationUnknown','Saving','Unknown','Saved','Conflict','Unavailable'}, 'document state')
        shape(snapshot['owners'],'data fixed combined maps children supervisors pending_inputs ordinary_queue reset_queue lifetime_objects lifetime_bytes lifetime_offers','exact owner fields')
        for field in ('app_pixels', 'composed_pixels'):
            raw = ref(directory, snapshot[field], inventory, refs)
            need(digest(raw) == snapshot[field.replace('_pixels', '_sha256')], 'snapshot pixels hash')
            need(not raw or len(raw)==(1228800 if field=='app_pixels' else 1454080), 'complete bounded pixels')
        owners = snapshot['owners']
        for key, maximum in [('data',12),('fixed',16),('combined',28),('maps',12),('children',2),('supervisors',2),('pending_inputs',1),('ordinary_queue',64),('reset_queue',1),('lifetime_objects',257),('lifetime_offers',128),('lifetime_bytes',157831232)]:
            need(integer(owners[key], maximum), f'actual owner bound: {key}')
        for entered,deadline,cap in [('admitted_at_ns','child_deadline_ns',5000000000),('captured_at_ns','save_deadline_ns',1000000000)]:
            if snapshot[entered] is not None and snapshot[deadline] is not None:
                need(0<int(snapshot[deadline])-int(snapshot[entered])<=cap, 'original bounded deadline')
        need(owners['combined'] == owners['data'] + owners['fixed'], 'owner accounting')
    descriptors = metadata['descriptors']
    known=descriptor_facts(descriptors)
    for obj in metadata['objects']:
        raw = ref(directory, obj['raw'], inventory, refs)
        need(obj['descriptor_id'] in known and digest(raw) == obj['sha256'], 'object ledger join')
    calls = metadata['syscalls']
    syscall_facts(calls,known)
    controls = metadata['controls']
    need(controls['path'] == 'controls.jsonl', 'one complete control leaf')
    raw = read(directory/'controls.jsonl', 16777216)
    need(len(raw) == controls['bytes'] and digest(raw) == controls['sha256'], 'control file hash/length')
    lines = raw.splitlines(keepends=True)
    need(len(lines) == controls['rows'] <= 32768 and controls['first_row'] == (1 if lines else 0) and controls['last_row'] == len(lines), 'complete control range')
    need(len(controls['syscall_indices']) == len(lines), 'complete native control joins')
    expected_events=[i for i,c in enumerate(calls) if c['origin']=='Native' and (c['operation']=='Recvmsg' and c['result']>0 or c['operation']=='Sendmsg' and (c['result']>=0 or c['errno'] not in (4,11)))]
    need(controls['syscall_indices']==expected_events, 'one complete ordered row per actual native control event')
    prior_time = 0
    for index, line in enumerate(lines):
        need(len(line) <= 512 and line.endswith(b'\n'), 'canonical bounded control row')
        row = decode(line)
        need(list(row) == KEYS and json.dumps(row, separators=(',',':'), ensure_ascii=False).encode()+b'\n' == line, 'canonical control encoding')
        need(type(row['i']) is int and type(row['d']) is int and row['i'] == index+1 and row['k'] in {'send','recv','kernel_reject'} and row['d'] in (0,1,2), 'control identity')
        need(all(integer(row[k]) for k in ('q','s','t')) and row['t'] >= prior_time and integer(row['f'],0xffffffff) and integer(row['r'],0xffffffff), 'control scalar/timing')
        prior_time = row['t']
        frame = base64.b64decode(row['b'], validate=True)
        need(base64.b64encode(frame).decode() == row['b'] and (len(frame) == 88 or not frame), 'complete frame base64')
        if not frame:
            need(row['r'] in refs or f"raw-{row['r']:04}.bin" in inventory, 'malformed frame raw reference')
            if row['r'] not in refs:
                b = read(directory/f"raw-{row['r']:04}.bin", 2097152)
                ref(directory, {'index':row['r'],'path':f"raw-{row['r']:04}.bin",'bytes':len(b),'sha256':digest(b)}, inventory, refs)
        else:
            need(row['r'] == 0, '88-byte frame needs no extra raw leaf')
        need(credential(row['c']), 'control credential tuple')
        need((row['q'],row['s'])==wire_projection(frame), 'wire request/sequence projection')
        need(len(row['o']) <= 3 and all(integer(v,0xffffffff) for v in row['o']), 'bounded control object refs')
        call_index = controls['syscall_indices'][index]
        need(integer(call_index) and call_index < len(calls), 'native syscall index')
        call = calls[call_index]
        need(call['operation'] in {'Sendmsg','Recvmsg'} and call['origin'] == 'Native', 'actual native control event')
        expected_kind = 'kernel_reject' if call['result'] < 0 else ('send' if call['operation']=='Sendmsg' else 'recv')
        need(row['k'] == expected_kind and row['f'] == call['msg_flags'], 'kernel event projection')
        if call['operation']=='Recvmsg':need(row['c']==call['sender'], 'received kernel credential projection')
        else:need(row['c'] is None and (call['sender'] is None or call['sender'][0]==scope['parent_pid']), 'send caller context is not received credentials')
        ids = call['ancillary_descriptor_ids']
        need(row['o'] == (ids if len(ids) <= 3 else []), 'complete ancillary join; invalid arity has no protocol objects')
        if call['result'] >= 0:
            need(call['result'] == (len(frame) if frame else len(read(directory/f"raw-{row['r']:04}.bin",2097152))), 'actual native control byte count')
    processes = metadata['processes']
    need(len(processes) <= 8, 'process row bound')
    shape(controls,'path bytes sha256 rows first_row last_row syscall_indices','exact control inventory')
    for snapshot in (metadata['before'],metadata['after']):
        need(snapshot['syscall_count']<=len(calls) and snapshot['control_count']<=len(lines) and snapshot['descriptor_count']<=len(descriptors), 'actual decision prefix')
    checkpoints=metadata['checkpoints']
    need(type(checkpoints) is list and len(checkpoints)<=131072, 'bounded checkpoints')
    prior=0
    for i,point in enumerate(checkpoints):
        shape(point,'point sequence reached_at_ns','exact checkpoint')
        need(point['point'] in {'BeforeSnapshotCopy','HeldVerifiedBeforeExec','ForkOwnedBeforeExecRelease','BootstrapBeforeSend','InputReceivedBeforeAck','OfferMappedBeforeSeal','PairValidatedBeforeAdopt','CaptureBeforeAdopt','SupervisorBeforeSignal','SupervisorBeforeWait','SupervisorTerminalBeforeJoin'} and type(point['sequence']) is int and point['sequence']==i+1 and integer(point['reached_at_ns']) , 'actual ordered checkpoint')
        prior=point['reached_at_ns']
    owner_pids=process_facts(processes,calls,known,metadata['executable'],scope['parent_pid'])
    primary=processes[0] if processes else None
    need(metadata['native_wait_outcome']==(primary['wait_outcome'] if primary else None) and metadata['supervisor_joined']==(primary['supervisor_joined'] if primary else False), 'top-level native completion joins actual primary process')
    referenced=metadata['referenced_processes']
    need(type(referenced) is list and len(referenced)<=7 and len(processes)+sum(len(r['processes']) for r in referenced)<=8, 'bounded referenced process facts')
    channels={scope['channel_generation']}
    for reference in referenced:
        shape(reference,'role source_scope processes syscalls descriptors executable owners_after_cleanup','exact referenced process scope')
        need(reference['role']=='ReferencedSibling', 'explicit sibling role')
        source_scope=reference['source_scope']
        shape(source_scope,'parent_case channel_generation scenario_id','exact referenced source scope')
        need(source_scope['parent_case']==scope['parent_case'] and source_scope['scenario_id'] is None and integer(source_scope['channel_generation']) and source_scope['channel_generation']>0 and source_scope['channel_generation'] not in channels, 'actual same-host unarmed sibling channel')
        channels.add(source_scope['channel_generation'])
        need(len(reference['syscalls'])<=64 and len(reference['descriptors'])<=64 and len(reference['processes'])==1, 'bounded minimal sibling provenance')
        shape(reference['owners_after_cleanup'],'data fixed combined maps children supervisors pending_inputs ordinary_queue reset_queue lifetime_objects lifetime_bytes lifetime_offers','exact sibling cleanup owners')
        need(all(type(reference['owners_after_cleanup'][k]) is int and reference['owners_after_cleanup'][k]==0 for k in ('data','fixed','combined','maps','children','supervisors','pending_inputs','ordinary_queue','reset_queue')), 'actual sibling owners closed')
        sibling_known=descriptor_facts(reference['descriptors'])
        syscall_facts(reference['syscalls'],sibling_known)
        need(all(c['origin']=='Native' and c['operation'] in {'Fork','Execveat','PidfdOpen','Waitpid'} for c in reference['syscalls']), 'actual minimal native sibling operations')
        sibling_pids=process_facts(reference['processes'],reference['syscalls'],sibling_known,reference['executable'],scope['parent_pid'])
        need(len(sibling_pids)==1 and not(owner_pids&sibling_pids), 'distinct actual sibling owner')
        owner_pids.update(sibling_pids)
    if referenced:
        need(all(d['owner_process_id'] is None or d['owner_process_id'] in owner_pids for d in descriptors), 'actual cross-child descriptor owner provenance')
    histories=metadata['retired_bootstraps']
    need(type(histories) is list and len(histories)<=2, 'bounded retired histories')
    for history in histories:
        shape(history,'role source_scope raw send processes proof_syscalls descriptors executable owners_after_cleanup','exact retired history')
        need(history['role']=='RetiredBootstrapSource', 'explicit old source scope')
        old=history['source_scope']
        shape(old,'parent_case channel_generation scenario_id','exact old source')
        need(old['parent_case']==scope['parent_case'] and integer(old['channel_generation']) and 0<old['channel_generation']<scope['channel_generation'] and (old['scenario_id'] is None or type(old['scenario_id']) is str and re.fullmatch('[A-Za-z0-9_-]{1,128}',old['scenario_id'])), 'actual retired channel precedes current admission')
        frame=ref(directory,history['raw'],inventory,refs)
        need(len(frame)==88 and int.from_bytes(frame[4:8],'little')==1 and int.from_bytes(frame[28:36],'little')==old['channel_generation'] and int.from_bytes(frame[8:16],'little')==old['channel_generation'] and wire_projection(frame)[0]>0, 'exact actual old bootstrap')
        old_known=descriptor_facts(history['descriptors'])
        need(len(history['proof_syscalls'])<=131072 and len(history['processes'])==1, 'bounded old native provenance')
        syscall_facts([history['send'],*history['proof_syscalls']],old_known)
        send=history['send']
        need(send['operation']=='Sendmsg' and send['origin']=='Native' and send['result']==88 and send['errno'] is None and len(send['ancillary_descriptor_ids'])==3 and len(set(send['ancillary_descriptor_ids']))==3, 'actual successful old bootstrap send')
        for identity,role in zip(send['ancillary_descriptor_ids'],['Selected','TextState','Surface']):
            need(any(d['descriptor_id']==identity and d['role']==role for d in history['descriptors']), 'actual old offered alias roles')
            need(any(c['operation']=='Close' and c['origin']=='Native' and c['result']==0 and c['descriptor_id']==identity for c in history['proof_syscalls']), 'actual old alias close proof')
        old_pids=process_facts(history['processes'],history['proof_syscalls'],old_known,history['executable'],scope['parent_pid'])
        need(old_pids and not(old_pids&owner_pids), 'distinct retired source')
        shape(history['owners_after_cleanup'],'data fixed combined maps children supervisors pending_inputs ordinary_queue reset_queue lifetime_objects lifetime_bytes lifetime_offers','exact cleanup owners')
        need(all(type(history['owners_after_cleanup'][key]) is int and history['owners_after_cleanup'][key]==0 for key in ('data','fixed','combined','maps','children','supervisors','pending_inputs','ordinary_queue','reset_queue')), 'retired native owners genuinely closed')
    helpers=metadata['fork_helpers']
    need(type(helpers) is list and len(helpers)<=1 and len(processes)+sum(len(r['processes']) for r in referenced)+sum(len(h['processes']) for h in histories)+len(helpers)<=8, 'bounded full native process inventory')
    for helper in helpers:
        shape(helper,'role execution_kind source_scope process syscall_indices received_syscall_index descriptors creation_peer_credentials received_credentials endpoint_aliases_after_cleanup helper_slots_after_cleanup','exact fork helper')
        need(helper['role']=='AssertionForkHelper' and helper['execution_kind']=='ForkOnlyNoExec', 'helper never claims editor ELF execution')
        where=helper['source_scope']
        shape(where,'parent_case scenario_id channel_generation','exact helper scope')
        need(where=={'parent_case':scope['parent_case'],'scenario_id':scope['scenario_id'],'channel_generation':scope['channel_generation']} and where['scenario_id'] in {'D04InheritedEndpointForeignPid','D04CreationPeercredIsNotSender','D04CopiedBootstrapPidActor'}, 'closed actual helper scope')
        indices=helper['syscall_indices']
        need(type(indices) is list and len(indices)<=64 and all(integer(i) and i<len(calls) for i in indices) and indices==sorted(set(indices)), 'actual distinct helper native indices')
        helper_calls=[calls[i] for i in indices]
        need(all(c['origin']=='Native' and c['operation']!='Execveat' for c in helper_calls), 'fork-only native proof')
        helper_known=known|descriptor_facts(helper['descriptors'])
        syscall_facts(helper_calls,helper_known)
        helper_pids=process_facts([helper['process']],helper_calls,helper_known,None,scope['parent_pid'],False)
        need(len(helper_pids)==1 and not(helper_pids&owner_pids) and helper['process']['wait_outcome']=='Exited(0)', 'actual distinct successful fork helper')
        helper_pid=next(iter(helper_pids));owner_pids.update(helper_pids)
        need(helper['process']['pidfd_ledger_id'] is None, 'fork-only helper has no invented pidfd')
        endpoints=[d for d in helper['descriptors'] if d['role']=='Control']
        need(len(endpoints)==1 and endpoints[0]['disposition']=='Closed' and any(c['operation']=='Close' and c['origin']=='Native' and c['result']==0 and c['errno'] is None and c['descriptor_id']==endpoints[0]['descriptor_id'] for c in helper_calls), 'actual helper endpoint close proof')
        receive_index=helper['received_syscall_index']
        need(integer(receive_index) and receive_index<len(calls), 'actual received helper syscall index')
        received=calls[receive_index]
        need(received['operation']=='Recvmsg' and received['origin']=='Native' and received['result']==88 and received['sender']==helper['received_credentials'] and credential(helper['received_credentials']) and helper['received_credentials'][0]==helper_pid, 'actual helper kernel sender')
        native_rows=[decode(line) for line in lines]
        observed=[row for i,row in enumerate(native_rows) if controls['syscall_indices'][i]==receive_index]
        bootstrap=[row for row in native_rows if row['k']=='send' and len(base64.b64decode(row['b']))==88 and int.from_bytes(base64.b64decode(row['b'])[4:8],'little')==1]
        need(len(observed)==1 and bootstrap and observed[0]['b']==bootstrap[0]['b'], 'actual helper copied bootstrap on same run')
        if helper['creation_peer_credentials'] is not None:
            need(credential(helper['creation_peer_credentials']) and helper['creation_peer_credentials']!=helper['received_credentials'] and any(c['operation']=='PeerCredentials' and c['result']==0 and c['sender']==helper['creation_peer_credentials'] and c['descriptor_id']==received['descriptor_id'] for c in helper_calls), 'actual same-socket creation credentials differ from sender')
        if scope['scenario_id']=='D04CreationPeercredIsNotSender':need(helper['creation_peer_credentials'] is not None, 'actual creation peercred required')
        need(type(helper['endpoint_aliases_after_cleanup']) is int and helper['endpoint_aliases_after_cleanup']==0 and type(helper['helper_slots_after_cleanup']) is int and helper['helper_slots_after_cleanup']==0, 'actual helper ownership cleanup')
    needed = {'metadata.json','progress.json','controls.jsonl'} | {item['path'] for item in refs.values()}
    need(set(inventory) == needed, 'exact referenced file inventory, no unaccounted artifacts')
    return {'scope':scope, 'controls':len(lines), 'raw_leaves':len(refs), 'files':len(inventory)}

def inspect(root: Path, nonce: str, source: str):
    need(re.fullmatch('[0-9a-f]{32}',nonce) and re.fullmatch('[0-9a-f]{64}',source), 'provenance syntax')
    root_stat = root.lstat()
    need(stat.S_ISDIR(root_stat.st_mode) and stat.S_IMODE(root_stat.st_mode)==0o700, 'private actual corpus')
    root = root.resolve(strict=True)
    files, entries, size, actual_dirs = {}, 0, 0, set()
    def visit(fd, prefix):
        nonlocal entries,size
        # Count before collecting or descending; a hostile directory cannot
        # force an unbounded list allocation before its entry cap is checked.
        with os.scandir(fd) as iterator:
            for entry in iterator:
                entries+=1
                need(entries<=LIMITS['entries'], 'corpus entry cap')
                relative=prefix/entry.name
                need(len(str(relative).encode())<=256 and len(relative.parts)<=16, 'bounded corpus path')
                st=entry.stat(follow_symlinks=False)
                need(not stat.S_ISLNK(st.st_mode) and st.st_uid==os.geteuid(), 'owned no-symlink corpus')
                if stat.S_ISDIR(st.st_mode):
                    need(stat.S_IMODE(st.st_mode)==0o700, 'private directory')
                    child=os.open(entry.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
                    try:
                        held=os.fstat(child)
                        need((held.st_dev,held.st_ino)==(st.st_dev,st.st_ino), 'directory changed')
                        actual_dirs.add(str(relative));visit(child,relative)
                    finally:os.close(child)
                else:
                    need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600, 'private leaf')
                    size+=st.st_size;files[str(relative)]=st.st_size
                    need(len(files)<=LIMITS['files'] and size<=LIMITS['bytes'], 'corpus file/byte cap')
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        held=os.fstat(fd)
        need((held.st_dev,held.st_ino)==(root_stat.st_dev,root_stat.st_ino), 'root changed')
        visit(fd,Path())
    finally:os.close(fd)
    frame=decode(read(root/'.budget.json',4096))
    need(set(frame)=={'ledger','sha256'} and frame['sha256']==digest(json.dumps(frame['ledger'],sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()), 'budget framing checksum')
    ledger=frame['ledger']
    need(ledger['schema_version']==1 and ledger['run_nonce']==nonce, 'budget provenance')
    for key, actual in [('files',len(files)),('entries',entries),('bytes',size)]:
        need(integer(ledger[key],LIMITS[key]) and actual<=ledger[key], 'conservative reserved corpus budget')
    directories={str(Path(name).parent) for name in files if name!='.budget.json'}
    runs=[]
    for relative in sorted(directories):
        path=Path(relative);need(len(path.parts)==2, 'exact case/run hierarchy')
        inventory={Path(name).name for name in files if Path(name).parent==path}
        runs.append(inspect_run(root/path,nonce,source,inventory))
    expected_dirs = directories | {str(Path(d).parent) for d in directories}
    need(actual_dirs == expected_dirs, 'no empty/unaccounted directories')
    need(runs and len({r['scope']['run_ordinal'] for r in runs})==len(runs), 'complete unique native runs')
    need(max(r['scope']['run_ordinal'] for r in runs)==ledger['next_run'] and len(runs)==ledger['next_run'], 'no omitted/incomplete reserved runs')
    need(sum(r['controls'] for r in runs)==ledger['controls']<=LIMITS['controls'], 'complete aggregate control accounting')
    return {'schema_version':1,'status':'RECORDING_COMPLETE','scope':'complete diagnostic recordings only; native assertions and complete gate required for acceptance','run_nonce':nonce,'source_manifest_sha256':source,'runs':runs,'files':len(files),'bytes':size,'controls':ledger['controls']}

def join_parent_recordings(result, manifest_path):
    """Join complete process diagnostics to this candidate's actual parent IO.

    This checks provenance and raw closure. Existing owner assertions validate
    Store semantics; it does not relabel these arbitrary cases as Reader93.
    """
    manifest=decode(read(manifest_path,8388608))
    shape(manifest,'schema_version run_nonce source_manifest_sha256 parent_root files','exact parent IO manifest')
    need(manifest['schema_version']==1 and manifest['run_nonce']==result['run_nonce'] and manifest['source_manifest_sha256']==result['source_manifest_sha256'], 'same candidate parent IO source and nonce')
    root=Path(manifest['parent_root'])
    need(root.is_absolute() and stat.S_ISDIR(root.lstat().st_mode) and not root.is_symlink(), 'actual parent recording root')
    rows=manifest['files']
    need(type(rows) is list and 0<len(rows)<=20000, 'bounded parent raw inventory')
    expected={}
    for row in rows:
        shape(row,'path bytes sha256','exact parent raw row')
        name=row['path'];path=Path(name)
        need(type(name) is str and name and not path.is_absolute() and '..' not in path.parts and len(path.parts)<=8 and name not in expected and integer(row['bytes'],33554432) and hash_value(row['sha256']), 'bounded relative parent raw identity')
        expected[name]=row
    actual=set();size=0
    for directory, directories, names in os.walk(root,followlinks=False):
        need(len(Path(directory).relative_to(root).parts)<=8, 'bounded parent directory depth')
        for name in directories:need(not (Path(directory)/name).is_symlink(), 'no parent directory link')
        for name in names:
            path=Path(directory)/name;relative=str(path.relative_to(root))
            need(len(actual)<20000 and relative in expected, 'exact parent raw inventory')
            row=expected[relative];raw=read(path,33554432);size+=len(raw)
            need(size<=2147483648 and len(raw)==row['bytes'] and digest(raw)==row['sha256'], 'actual parent raw length and hash')
            actual.add(relative)
    need(actual==set(expected), 'no missing parent raw leaf')
    joined=[]
    for run in result['runs']:
        case=run['scope']['parent_case']
        summaries=[name for name in expected if Path(name).parts[0]==case and Path(name).name=='summary.json']
        need(len(summaries)==1, 'one actual parent IO case for process scope')
        summary_path=root/summaries[0]
        summary=decode(read(summary_path,33554432))
        binding=summary['binding']
        need(binding['schema_version']==1 and binding['run_nonce']==result['run_nonce'] and binding['case']==case, 'actual parent IO case and nonce binding')
        # The established recorder publishes binding and raw references in its
        # semantic JSON files. Independently join every declared raw reference.
        count=0
        def references(value):
            nonlocal count
            if type(value) is dict:
                if 'binding' in value and type(value['binding']) is dict and ('case' in value['binding'] or 'run_nonce' in value['binding']):
                    b=value['binding']
                    need(b['case']==case and b['run_nonce']==result['run_nonce'], 'same parent case throughout retained records')
                if {'file','byte_len','sha256'}<=set(value):
                    name=value['file'];path=Path(name)
                    need(type(name) is str and name and not path.is_absolute() and '..' not in path.parts, 'relative parent raw reference')
                    raw=read(summary_path.parent/path,33554432)
                    need(len(raw)==value['byte_len'] and digest(raw)==value['sha256'], 'parent declared raw reference intact')
                    count+=1
                for child in value.values():references(child)
            elif type(value) is list:
                for child in value:references(child)
        for name in expected:
            path=Path(name)
            if path.parts[0]==case and path.suffix=='.json':references(decode(read(root/path,33554432)))
        need(count>0, 'genuine raw parent IO references required')
        joined.append({'parent_case':case,'process_run_ordinal':run['scope']['run_ordinal'],'summary':summaries[0],'raw_references':count})
    result['parent_io_join']={'manifest_path':str(manifest_path),'manifest_sha256':digest(read(manifest_path,8388608)),'files':len(actual),'bytes':size,'runs':joined,'scope':'same candidate raw parent IO provenance; no Reader93 or additional runtime acceptance claim'}
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--evidence',required=True,type=Path);p.add_argument('--nonce',required=True);p.add_argument('--source-sha256',required=True);p.add_argument('--output',required=True,type=Path);p.add_argument('--parent-manifest',type=Path);a=p.parse_args()
    try:
        result=inspect(a.evidence,a.nonce,a.source_sha256)
        if a.parent_manifest is not None:result=join_parent_recordings(result,a.parent_manifest)
    except (Invalid,OSError,ValueError,KeyError,TypeError) as e:
        result={'schema_version':1,'status':'FAIL','error':str(e)}
    with a.output.open('x') as f:json.dump(result,f,indent=2);f.write('\n')
    print('PROCESS_RECORDING_READER: '+result['status'])
    return 0 if result['status']=='RECORDING_COMPLETE' else 1
if __name__=='__main__':raise SystemExit(main())
