"""Fixed owned same-call producer; public capture registration stays closed.

No caller-selected command, origin flag, callback registry or copied observation
issues live authority. Capture owns exact native types and the release guard;
this module supplies their fixed bodies. Tests use explicit private synthetic
owners and never execute a VM, CPU reader or guest-memory request.
"""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
from types import MappingProxyType
import selectors
import signal
import socket
import stat
import subprocess
import threading
import time

import boot_profile_capture as base
import run0_call_capture as capture
import run0_call_budget as budget
import run0_call_owner as ownership
import run0_call_read as read
import run0_call_wire as wiremod
import run0_call_host as host
import run0_call_session as sessionmod
import run0_call_decode as pure
import run0_c0_decode as c0
import run0_host_cpu_witness as witness
import run0_host_cpu_reader as reader
import run0_rsp as rsp

deny,incomplete=base.deny,base.incomplete
SECOND=1_000_000_000
EPOCHS=('C0','C1','C2')
CHILD_ROLES=('qemu',)+tuple(f'{e.lower()}_{r}' for e in EPOCHS for r in host.LOCAL_ROLES)
VM_STREAMS=('qmp-in','rsp','serial','debug','qemu_stdout','qemu_stderr')
RAW_FILES=dict(zip((*VM_STREAMS,'qmp-out','rsp-out'),('qmp.bin','rsp.bin','serial.bin','debug.bin',
    'stdout.bin','stderr.bin','qmp-requests.bin','rsp-requests.bin')))

@dataclass(frozen=True,slots=True)
class _Endpoint:
    source:object
    descriptor:int
    device:int
    inode:int
    mode:int

@dataclass(slots=True)
class _EpochArchive:
    registered:object
    snapshot:object=None
    closed:object=None
    refs:object=None
    copied:object=None
    projection:object=None


def _native(kind,**fields):
    deny(kind in (capture.ClosedOwnedCallRegistration,capture.RegisteredCurrentEpochBinding,
        capture.BoundCallTarget,sessionmod.CurrentEpochRamBinding,read._HeldReadAttempt),
        'call_runtime_native_kind')
    deny(set(fields)==set(kind.__dataclass_fields__),'call_runtime_native_fields')
    value=object.__new__(kind)
    for name,item in fields.items():object.__setattr__(value,name,item)
    return value


def _new_inert_runtime(prepared,policy,accounting,inventory,native):
    deny(type(prepared) is capture.PreparedCallInputs and type(policy) is ownership.ParentDeadlines
        and type(accounting) is budget.ParentAccounting and accounting.started_ns==policy.started_ns
        and type(inventory) is capture.RootRawInventory,'call_runtime_inert_inputs')
    value=object.__new__(capture._OwnedCallRuntime)
    owner=ownership.ParentOwnedWait('qemu',policy)
    transition=object.__new__(ownership.NativeTransitionOwner)
    for name,item in dict(_policy=policy,_wire=None,_ledger=accounting,_epoch='C0',_source_stop_ns=None,
        _admission_started_ns=None,_registered=False,_held={},_tickets=[],_used=False).items():setattr(transition,name,item)
    fields=dict(prepared=prepared,_registration=None,qemu_owner=owner,_wire=None,deadlines=policy,
        accounting=accounting,inventory=inventory,parent_identity=object(),transition_owner=transition,
        read_attempts={},read_operations={},native=native,before_spawn=None,before_spawn_ns=None,
        _descriptors={},_children={'qemu':owner},_launch_identity=None,_observations={},_current=None,
        _closed_epochs={},_fact_receipts={},_failure=None,_closed=False,_preparing_epoch=None,_epochs={},_plan=None,_verification=None)
    for name,item in fields.items():setattr(value,name,item)
    policy._owner=transition
    return value


def _input_ref(value):
    deny(type(value) is tuple and len(value)==3,'call_runtime_input_ref_shape')
    return capture._ref(dict(zip(capture.REF_KEYS,value)))


def _freeze_plan(plan,accounting):
    # Native logical tree copies are charged before constructing immutable
    # containers. Strings/scalars remain the exact already parsed values.
    size=_json_size(plan);accounting.reserve_output(4*size+4096)
    def freeze(value):
        if type(value) is dict:return MappingProxyType({k:freeze(v) for k,v in value.items()})
        if type(value) is list:return tuple(freeze(v) for v in value)
        deny(value is None or type(value) in (str,int,bool),'call_runtime_plan_type')
        return value
    deny(type(plan) is dict,'call_runtime_plan_type')
    return freeze(plan)


def _held_plan(owner):
    deny(type(owner._plan) is MappingProxyType,'call_runtime_held_plan')
    return owner._plan


def _thaw_plan(owner):
    held=_held_plan(owner)
    owner.accounting.reserve_output(16*len(owner.prepared.plan_bytes)+4096)
    def thaw(value):
        if type(value) is MappingProxyType:return {k:thaw(v) for k,v in value.items()}
        if type(value) is tuple:return [thaw(v) for v in value]
        deny(value is None or type(value) in (str,int,bool),'call_runtime_plan_type')
        return value
    return thaw(held)


def _prepared(prepared,run,plan):
    deny(type(prepared) is capture.PreparedCallInputs and type(run) is type(Path())
        and str(run)==prepared.run,'call_runtime_prepared_identity')
    deny(type(plan) is dict and plan.get('kind')=='run0_same_call_map_plan_v1'
        and plan.get('context')=='call' and plan.get('run')==prepared.run
        and plan.get('inputs')==prepared.inputs and witness.canonical(plan)==prepared.plan_bytes,
        'call_runtime_plan_identity')
    return plan


def _validate_call_runtime_inputs(prepared,plan,accounting,deadline_ns,*,verification=None):
    """Fixed streaming verifier; immutable semantic state is paid only once."""
    from run0_call_verify import validate_call_inputs
    return validate_call_inputs(prepared,plan,accounting,deadline_ns,verification=verification)


def _issued_call_registration(registration,wire):
    """Archival native provenance; deliberately no live child/source requirement."""
    try:
        owner=registration._owner
        return (type(registration) is capture.ClosedOwnedCallRegistration
            and type(owner) is capture._OwnedCallRuntime and owner._registration is registration
            and type(wire) is wiremod.CallWire and owner._wire is wire and registration.wire is wire
            and wire._registration is registration and registration.prepared is owner.prepared
            and registration.qemu_owner is owner.qemu_owner and registration.deadlines is owner.deadlines
            and registration.accounting is owner.accounting and registration.inventory is owner.inventory
            and registration.parent_identity is owner.parent_identity
            and registration.transition_owner is owner.transition_owner
            and registration.read_attempts is owner.read_attempts is wire._read_attempts
            and registration.read_operations is owner.read_operations is wire._read_operations
            and type(owner._children) is dict and owner._children.get('qemu') is owner.qemu_owner
            and type(owner.qemu_owner) is ownership.ParentOwnedWait
            and type(owner.qemu_owner.child) is subprocess.Popen
            and type(owner._descriptors) is dict and tuple(owner._descriptors)==VM_STREAMS
            and all(type(value) is _Endpoint for value in owner._descriptors.values())
            and owner._descriptors['qmp-in'].source is wire._qmp
            and all(owner._descriptors[name].source is wire._streams[name] for name in VM_STREAMS[1:])
            and owner._descriptors['qemu_stdout'].source is owner.qemu_owner.child.stdout
            and owner._descriptors['qemu_stderr'].source is owner.qemu_owner.child.stderr)
    except (AttributeError,TypeError):return False


def _graph(owner,wire=None):
    deny(type(owner) is capture._OwnedCallRuntime and _issued_call_registration(owner._registration,owner._wire)
        and (wire is None or wire is owner._wire),'call_runtime_graph')
    return owner._registration


def _live(owner,wire=None):
    registration=_graph(owner,wire)
    capture.require_call_runtime_registration(owner.prepared,_held_plan(owner))
    deny(not owner._closed and owner._failure is None and not owner.qemu_owner.reaped
        and not owner.qemu_owner.ownership_lost and owner.qemu_owner.child.returncode is None
        and owner._wire.failure is None,'call_runtime_not_live')
    incomplete(time.monotonic_ns()<owner.deadlines.effective_work_ns,'call_runtime_work_deadline')
    for endpoint in owner._descriptors.values():
        current=os.fstat(endpoint.descriptor)
        deny(endpoint.source.fileno()==endpoint.descriptor and
            (current.st_dev,current.st_ino,stat.S_IFMT(current.st_mode))==
            (endpoint.device,endpoint.inode,stat.S_IFMT(endpoint.mode)),
            'call_runtime_descriptor_replaced')
    return registration


def _require_wire_bootstrap(owner,wire):
    _live(owner,wire)
    deny(owner._current is None and not owner._epochs and wire._epoch=='C0'
        and wire._state in ('RESET','C_DISPATCH','FLIGHT','STOP_ACK','DEBUG_FENCE'),
        'call_runtime_bootstrap_phase')


def _require_wire_stop(owner,wire,stop):
    _live(owner,wire)
    deny(type(stop) is wiremod.EpochStopReceipt and stop is wire._stop
        and stop._wire is wire and stop._registration is owner._registration
        and stop.epoch==wire._epoch and wire._state=='STOPPED'
        and stop.flight is wire._flights[-1] and stop.flight.result=='ok',
        'call_runtime_current_stop')
    incomplete(time.monotonic_ns()<min(stop.stop_deadline_ns,owner.deadlines.effective_work_ns),
        'call_runtime_stop_deadline')


def _require_wire_binding(owner,wire,registered,session):
    _require_wire_stop(owner,wire,wire._stop)
    deny(type(registered) is capture.RegisteredCurrentEpochBinding and registered is owner._current
        and registered._owner is owner and registered.registration is owner._registration
        and registered.session is session and type(session) is sessionmod.ParentAcquisitionSession
        and session.binding is registered.binding and session.retainer is registered.retainer
        and registered.retainer._origin is None and registered.binding.stop is wire._stop and not session._retired and session._failure is None,
        'call_runtime_current_binding')
    deny(type(owner._epochs.get(registered.binding.epoch)) is _EpochArchive and
        owner._epochs[registered.binding.epoch].registered is registered,
        'call_runtime_epoch_archive')


def _require_wire_after(owner,wire,complete):
    current=owner._current
    incomplete(current is not None,'call_runtime_current_pending')
    _require_wire_binding(owner,wire,current,current.session)
    current.session.require_reads_complete(complete,actual_wire_identity=wire,
        actual_transport_identity=_transport(owner),actual_epoch_nonce=wire._stop.stop_nonce,now_ns=time.monotonic_ns())


def _transport(owner):
    endpoint=owner._descriptors['rsp']
    current=os.fstat(endpoint.descriptor)
    deny((current.st_dev,current.st_ino)==(endpoint.device,endpoint.inode),'call_runtime_rsp_identity')
    return ('rsp',current.st_dev,current.st_ino)


def _archive_for(owner,epoch):
    _graph(owner)
    deny(type(epoch) is str and epoch in EPOCHS,'call_runtime_epoch')
    record=owner._epochs.get(epoch)
    deny(type(record) is _EpochArchive and type(record.registered) is capture.RegisteredCurrentEpochBinding
        and record.registered._owner is owner and record.registered.registration is owner._registration,
        'call_runtime_archived_epoch')
    return record


def _require_session_archival(owner,session):
    deny(type(session) is sessionmod.ParentAcquisitionSession,'call_runtime_session_type')
    record=_archive_for(owner,session.binding.epoch)
    deny(record.registered.session is session and session._owner is owner
        and session.retainer is record.registered.retainer,'call_runtime_archived_session')


def _require_epoch_initialization(owner,binding,retainer):
    _require_wire_stop(owner,owner._wire,binding.stop)
    deny(type(binding) is sessionmod.CurrentEpochRamBinding and type(retainer) is read._ReadRetainer
        and retainer._origin is None and owner._preparing_epoch==(binding,retainer) and owner._preparing_epoch[0] is binding
        and owner._preparing_epoch[1] is retainer and owner._current is None
        and binding._owner is owner and binding.registration is owner._registration,
        'call_runtime_epoch_initialization')


def _require_retainer_initialization(owner,registration,binding,root,plan_ref,deadline_ns):
    _require_wire_stop(owner,owner._wire,binding.stop)
    deny(registration is owner._registration and type(binding) is sessionmod.CurrentEpochRamBinding
        and owner._preparing_epoch is not None and owner._preparing_epoch[0] is binding
        and owner._preparing_epoch[1] is None and owner._current is None
        and type(root) is type(Path()) and root==Path(owner.prepared.run)
        and type(plan_ref) is read.BlobRef and plan_ref.path=='plan.json'
        and deadline_ns==min(binding.work_deadline_ns,binding.stop_deadline_ns),
        'call_runtime_retainer_initialization')
    owner.inventory.require_exact(plan_ref,owner.prepared.plan_bytes)


def _require_retainer_current(owner,retainer):
    current=owner._current
    incomplete(current is not None,'call_runtime_current_pending')
    _require_wire_binding(owner,owner._wire,current,current.session)
    deny(current.retainer is retainer and retainer._origin is None and retainer._parent is owner.parent_identity
        and retainer._session is current.session and retainer._binding is current.binding
        and retainer._attempts is owner.read_attempts and retainer._operations is owner.read_operations,
        'call_runtime_current_retainer')


def _require_retainer_archival(owner,retainer):
    _graph(owner)
    matches=[row for row in owner._epochs.values() if type(row) is _EpochArchive and row.registered.retainer is retainer]
    deny(len(matches)==1 and retainer._origin is None and retainer._parent is owner.parent_identity
        and retainer._wire is owner._wire and retainer._session is matches[0].registered.session
        and retainer._binding is matches[0].registered.binding
        and retainer._attempts is owner.read_attempts and retainer._operations is owner.read_operations,
        'call_runtime_archived_retainer')


def _require_native_read_receipt(owner,receipt):
    deny(type(receipt) is read.NativePhysicalReadReceipt and receipt.parent is owner.parent_identity,
        'call_runtime_native_receipt')
    record=_archive_for(owner,receipt.epoch)
    _require_retainer_archival(owner,record.registered.retainer)
    record.registered.retainer._receipt(receipt)
    deny(receipt.session is record.registered.session and receipt.binding is record.registered.binding,
        'call_runtime_receipt_epoch')


def _require_epoch_after(owner,session,after):
    _require_wire_after(owner,owner._wire,after.reads_complete)
    deny(owner._current.session is session and type(after) is wiremod.EpochAfterReceipt
        and after is owner._wire._after_receipt and after.registers is owner._wire._after_registers
        and after.hmp is owner._wire._final_register_view and after.layout is owner._wire._layout_after,
        'call_runtime_after_identity')


def _require_host_observation(owner,wire,observation):
    _require_wire_stop(owner,wire,observation._confirmed)
    deny(type(observation) is host._OwnedParentObservation
        and owner._observations.get(wire._stop.epoch) is observation
        and observation._wire is wire and observation._registration is owner._registration
        and observation._registers is wire._before_registers and observation.child is owner.qemu_owner.child,
        'call_runtime_host_observation')


def _register_host_helper(owner,wire,observation,helper):
    # Actual child registration also runs after failed start. It is archival,
    # never contingent on a live host lease/child or a successful field result.
    _graph(owner,wire)
    deny(type(observation) is host._OwnedParentObservation and
        owner._observations.get(observation._confirmed.epoch) is observation
        and type(helper) is host._ParentHostHelper and type(helper.child) is subprocess.Popen,
        'call_runtime_host_helper')
    matches=[name for name,value in observation.helpers.items() if value is helper]
    deny(len(matches)==1 and matches[0] in host.LOCAL_ROLES and
        helper.role==observation._confirmed.epoch.lower()+'_'+matches[0]
        and helper._policy is owner.deadlines,'call_runtime_helper_role')
    existing=owner._children.get(helper.role)
    deny(existing is None or existing is helper,'call_runtime_helper_reused')
    deny(not any(value is not helper and value.child is not None and value.child.pid==helper.child.pid
        for value in owner._children.values()),'call_runtime_helper_pid')
    owner._children[helper.role]=helper


def _abort_wire_epoch(owner,wire,failure):
    _graph(owner,wire)
    if owner._failure is None:owner._failure=failure
    if owner._current is not None:
        owner._current.session.abort(failure)
        owner._current.retainer._revoked=True
    # Current/archival references remain for failure projection and owned cleanup.


def _require_wire_failure_drain(owner,wire):
    _graph(owner,wire)
    deny(owner._failure is not None or wire.failure is not None,'call_runtime_failure_drain')
    deny(not owner._closed and not owner.qemu_owner.ownership_lost,'call_runtime_failure_owner')
    incomplete(time.monotonic_ns()<owner.deadlines.effective_hard_ns,'call_runtime_cleanup_deadline')


def _validate_complete_lifecycle(owner):
    deny(type(owner) is capture._OwnedCallRuntime and type(owner._children) is dict
        and set(owner._children)==set(CHILD_ROLES),'call_runtime_child_inventory')
    pids=set();eofs=0
    for role in CHILD_ROLES:
        child=owner._children[role]
        deny(type(child) is (ownership.ParentOwnedWait if role=='qemu' else host._ParentHostHelper)
            and child.role==role and type(child.child) is subprocess.Popen
            and type(child.child.pid) is int and child.child.pid>0 and child.child.pid not in pids,
            'call_runtime_child_identity')
        pids.add(child.child.pid)
        incomplete(child.reaped and not child.ownership_lost and child.returncode==0
            and child.child.returncode==0,'call_runtime_actual_wait')
        rows=child.lifecycle
        deny(type(rows) is list and len(rows)==3 and len({row['operation'] for row in rows})==len(rows),
            'call_runtime_lifecycle_rows')
        for operation in ('spawn','wait','close'):
            found=[row for row in rows if row['operation']==operation]
            deny(len(found)==1 and found[0]['role']==role and found[0]['pid']==child.child.pid
                and found[0]['result']=='ok' and found[0]['errno'] is None
                and type(found[0]['started_ns']) is int and type(found[0]['finished_ns']) is int
                and owner.deadlines.started_ns<=found[0]['started_ns']<=found[0]['finished_ns']
                <=owner.deadlines.effective_hard_ns,'call_runtime_lifecycle_receipt')
        spawn=next(row for row in rows if row['operation']=='spawn')
        wait=next(row for row in rows if row['operation']=='wait')
        close=next(row for row in rows if row['operation']=='close')
        deny(spawn['finished_ns']<=wait['started_ns']<=wait['finished_ns']<=close['started_ns'],
            'call_runtime_lifecycle_order')
        deny(wait['returncode']==0,'call_runtime_wait_receipt')
        if role!='qemu':
            incomplete(child.closed and not child.io_errors and child.eofs=={'stdout','stderr'},'call_runtime_helper_eof')
            eofs+=2
    actual=owner._wire._eofs
    incomplete(not owner._wire._io_errors and len(actual)==6
        and {row.stream for row in actual}==set(VM_STREAMS),'call_runtime_VM_eof')
    deny(all(type(row) is wiremod.EndOfStream and owner.deadlines.started_ns<=row.observed_ns
        <=owner.deadlines.effective_hard_ns for row in actual),'call_runtime_VM_eof_clock')
    incomplete(eofs+len(actual)==24,'call_runtime_24EOF')
    return tuple(sorted(pids))


def _physical_row(owner,wire,seq):
    deny(type(seq) is int and 1<=seq<=len(wire._operations),'call_runtime_read_sequence')
    row=wire._operations[seq-1]
    deny(type(row) is wiremod.Operation and row is wire._operations[-1] and row.seq==seq
        and row.charged_epoch==wire._epoch and row.protocol=='rsp' and row.operation=='physical_read'
        and row.finished_ns is None and row.request is None and row.response is None
        and row.result=='pending','call_runtime_read_row')
    incomplete(time.monotonic_ns()<row.started_ns+5*SECOND,'call_runtime_read_response_deadline')
    return row


def _prepare_wire_read(owner,wire,grant,*,operation_seq):
    current=owner._current
    incomplete(current is not None,'call_runtime_current_pending')
    _require_wire_binding(owner,wire,current,current.session)
    row=_physical_row(owner,wire,operation_seq)
    deny(wire._active_pending is None and operation_seq==owner.accounting.view()['allocated_operations']+1,
        'call_runtime_read_allocation')
    reservation,index,target=current.session._validate_prepare(grant,now_ns=time.monotonic_ns())
    request=owner.accounting.view()['physical_claimed']+1
    key=read.ReadKey(row.charged_epoch,request,request-1,operation_seq)
    return current.retainer.prepare(reservation,index,key,target)


def _commit_wire_read(owner,wire,grant,pending):
    current=owner._current
    incomplete(current is not None,'call_runtime_current_pending')
    _require_wire_binding(owner,wire,current,current.session)
    deny(type(pending) is read.PendingReadRetention and pending is wire._active_pending
        and pending.owner is current.retainer,'call_runtime_pending_read')
    row=_physical_row(owner,wire,pending.key.operation_seq)
    current.session._validate_dispatch(grant,pending,now_ns=time.monotonic_ns())
    attempt=_native(read._HeldReadAttempt,_parent=owner.parent_identity,_wire=wire,key=pending.key,
        target=pending.target,started_ns=row.started_ns,finished_ns=None,result='pending')
    # The exact same table is held by runtime, wire, session and retainer. This
    # ONE publication commits admission before any byte; no second consumed bit.
    owner.read_attempts[row.seq]=attempt
    return attempt


def _recheck_wire_read(owner,wire,attempt):
    current=owner._current
    incomplete(current is not None,'call_runtime_current_pending')
    _require_wire_binding(owner,wire,current,current.session)
    deny(type(attempt) is read._HeldReadAttempt and attempt._parent is owner.parent_identity
        and attempt._wire is wire and owner.read_attempts.get(attempt.key.operation_seq) is attempt
        and attempt.result in ('pending','ok'),'call_runtime_read_attempt')
    pending=wire._active_pending
    deny(type(pending) is read.PendingReadRetention and pending.key==attempt.key,
        'call_runtime_read_pending')
    current.session._recheck_admitted(current.session.pending,pending,attempt,now_ns=time.monotonic_ns())


def _seal_wire_read(owner,wire,pending,operation,*,request_bytes,response_bytes):
    _recheck_wire_read(owner,wire,operation.attempt)
    deny(type(operation) is read._HeldReadOperation and operation is owner.read_operations.get(pending.key.operation_seq)
        and operation.attempt is owner.read_attempts.get(pending.key.operation_seq)
        and operation._parent is owner.parent_identity and operation._wire is wire,
        'call_runtime_read_ack')
    return owner._current.retainer.seal(pending,operation=operation,
        request_position=operation.request_position,request_ack_position=operation.request_ack_position,
        response_position=operation.response_position,response_ack_position=operation.response_ack_position,
        request_bytes=request_bytes,response_bytes=response_bytes,started_ns=operation.started_ns,
        response_received_ns=operation.response_received_ns,ack_finished_ns=operation.ack_finished_ns)

def _put(owner,name,raw):
    deny(type(raw) is bytes,'call_runtime_output_bytes')
    return owner.inventory.put(name,raw)


def _json_size(value):
    # Closed bounded native JSON, counted before an encoded allocation. This is
    # the parent record size (up to2957 inventory rows), not the read-row cap64.
    nodes=0
    def size(item,depth):
        nonlocal nodes
        nodes+=1
        deny(depth<=32 and nodes<=262144,'call_runtime_json_shape')
        if type(item) is str:
            deny(item.isascii() and len(item)<=65536,'call_runtime_json_string')
            return 2+sum(2 if c in ('"','\\','\b','\f','\n','\r','\t') else
                6 if ord(c)<32 else 1 for c in item)
        if item is None:return 4
        if type(item) is bool:return 4 if item else 5
        if type(item) is int:
            deny(-(1<<64)<=item<=(1<<64),'call_runtime_json_integer')
            return len(str(item))
        if type(item) in (tuple,list):
            deny(len(item)<=4096,'call_runtime_json_vector')
            return 2+max(0,len(item)-1)+sum(size(v,depth+1) for v in item)
        deny(type(item) is dict and len(item)<=128 and all(type(k) is str for k in item),
            'call_runtime_json_object')
        return 2+max(0,len(item)-1)+sum(size(k,depth+1)+1+size(v,depth+1) for k,v in item.items())
    return size(value,0)+1


def _json(owner,name,value):
    # Logical JSON copies are charged before serialization; inventory separately
    # charges the actual retained file and its fixed metadata/hash buffer.
    amount=_json_size(value)
    purpose=capture.TERMINAL_PURPOSE.get(name)
    if purpose is None:owner.accounting.reserve_output(2*amount)
    else:owner.accounting.redeem_terminal(2*amount,purpose=purpose)
    raw=witness.canonical(value)
    deny(len(raw)<=amount,'call_runtime_json_size')
    return _put(owner,name,raw),raw


def _fact_value(owner,value):
    # Finite native structures only. Charge the immutable dataclass projection
    # before pure._value makes dictionaries/lists; it performs no I/O or issuer.
    from dataclasses import fields,is_dataclass
    def bound(v,depth=0):
        deny(depth<=32,'call_runtime_value_depth')
        if v is None or type(v) in (bool,int):return 64
        if type(v) is str:return 128+6*len(v)
        if type(v) in (tuple,list):return 128+8*len(v)+sum(bound(x,depth+1) for x in v)
        deny(is_dataclass(v) and type(v).__module__ in (pure.__name__,read.__name__,'run0_c0_paging'),
            'call_runtime_projection_type')
        return 256+sum(128+bound(getattr(v,f.name),depth+1) for f in fields(v))
    owner.accounting.reserve_output(bound(value))
    return pure._value(value)


def _held_blob(owner,name):
    value=owner.inventory._slots.get(name)
    incomplete(value is not None and value.state=='complete' and type(value.data) is bytes,
        'call_runtime_sealed_record_missing')
    owner.inventory.require_exact(value.ref,value.data)
    return value.ref,value.data


def _transition_proof(kind,owner,epoch,**fields):
    deny(kind in ownership.TRANSITION_NATIVE_TYPES[1:-1],'call_runtime_transition_kind')
    value=object.__new__(kind)
    for key,item in dict(_owner=owner.transition_owner,_wire=owner._wire,_epoch=epoch,**fields).items():
        object.__setattr__(value,key,item)
    return value


def _closed_source(owner,wire,closed,epoch):
    _live(owner,wire)
    archive=_archive_for(owner,epoch)
    deny(type(closed) is ownership.ClosedEpochReceipt and archive.closed is closed
        and owner._closed_epochs.get(epoch) is closed and closed._owner is owner.transition_owner
        and closed._wire is wire and closed._epoch==epoch and closed._memory_revoked is True
        and archive.registered.session._retired and archive.registered.retainer._revoked
        and owner._current is None,'call_runtime_closed_source')
    incomplete(time.monotonic_ns()<archive.registered.binding.stop_ns+60*SECOND,
        'call_runtime_closed_stop_deadline')
    return archive


def issue_first_target(owner,closed_C0,completed_fresh_C0_facts_receipt):
    return _issue_target(owner,'C0',closed_C0,completed_fresh_C0_facts_receipt)


def issue_return_target(owner,closed_C1,selected_call_receipt):
    return _issue_target(owner,'C1',closed_C1,selected_call_receipt)


def _issue_target(owner,epoch,closed,fact):
    archive=_closed_source(owner,owner._wire,closed,epoch)
    cls=sessionmod.FreshC0FactsReceipt if epoch=='C0' else sessionmod.SelectedCallReceipt
    deny(type(fact) is cls and owner._fact_receipts.get(epoch) is fact and fact._owner is owner
        and fact.registration is owner._registration and fact.closed is closed
        and fact.session is archive.registered.session and fact.snapshot is archive.snapshot,
        'call_runtime_target_source')
    deny(('target',epoch) not in owner._fact_receipts,'call_runtime_target_once')
    closure,data=_held_blob(owner,f'epochs/{epoch}/closure.json')
    deny(archive.refs['closure_ref'] is closure,'call_runtime_target_closure')
    address=fact.facts.get_memory_map if epoch=='C0' else fact.facts.saved_return
    deny(type(address) is int and 0<address<(1<<64),'call_runtime_target_address')
    target=_native(capture.BoundCallTarget,_owner=owner,registration=owner._registration,
        closed=closed,source_fact=fact,source_epoch=epoch,target_epoch='C1' if epoch=='C0' else 'C2',
        address=address,source_closure_ref=closure)
    owner._fact_receipts[('target',epoch)]=target
    return target


def _require_wire_transition(owner,wire,closed,target):
    deny(type(target) is capture.BoundCallTarget and target.source_epoch in ('C0','C1'),
        'call_runtime_target_type')
    archive=_closed_source(owner,wire,closed,target.source_epoch)
    deny(owner._fact_receipts.get(('target',target.source_epoch)) is target
        and target._owner is owner and target.registration is owner._registration
        and target.closed is closed and target.source_fact is owner._fact_receipts.get(target.source_epoch)
        and target.source_epoch==wire._epoch and target.source_closure_ref is archive.refs['closure_ref']
        and wire._state in ('STOPPED','TRANSITION_PREP'),'call_runtime_transition_target')


def _issue_wire_transition(owner,wire,closed,target):
    _require_wire_transition(owner,wire,closed,target)
    deny(wire._state=='TRANSITION_PREP' and wire._transition_target is target
        and wire._transition_closed is closed and wire._ticket is None,'call_runtime_transition_preparation')
    clear,setrow=wire._transition_clear,wire._transition_set
    deny(all(type(row) is wiremod.Operation and wire._operations[row.seq-1] is row
        and row.charged_epoch==target.source_epoch and row.protocol=='rsp' and row.result=='ok'
        and row.finished_ns is not None for row in (clear,setrow))
        and clear.operation=='hardware_breakpoint_clear' and setrow.operation=='hardware_breakpoint_set'
        and clear.seq+1==setrow.seq and setrow is wire._operations[-1]
        and clear.started_ns<=clear.finished_ns<=setrow.started_ns<=setrow.finished_ns<=wire._transition_quiet_ns,
        'call_runtime_transition_operations')
    transition=owner.transition_owner;epoch=target.source_epoch
    archive=_archive_for(owner,epoch)
    # Same native transition owner across both epochs; no new deadline policy.
    deny(transition._wire is wire and transition._policy is owner.deadlines and transition._registered,
        'call_runtime_transition_owner')
    if epoch=='C1':
        deny(len(transition._tickets)==1 and transition._tickets[0]._consumed,
            'call_runtime_second_transition_order')
    transition._epoch=epoch;transition._source_stop_ns=archive.registered.binding.stop_ns
    transition._admission_started_ns=wire._transition_started_ns;transition._used=False
    before=time.monotonic_ns()
    ref,_=_json(owner,f'transitions/{epoch}-{target.target_epoch}.json',dict(
        schema_version=1,source_epoch=epoch,target_epoch=target.target_epoch,
        source_closure_ref=target.source_closure_ref.as_json(),target=target.address,
        clear_operation_seq=clear.seq,set_operation_seq=setrow.seq,
        quiet_received_ns=wire._transition_quiet_ns,admission_started_ns=wire._transition_started_ns))
    flushed=time.monotonic_ns()
    deny(before<=flushed,'call_runtime_journal_clock')
    proofs=(closed,
        _transition_proof(ownership.BreakpointClearReceipt,owner,epoch),
        _transition_proof(ownership.BreakpointSetReceipt,owner,epoch),
        _transition_proof(ownership.TransitionReservation,owner,epoch,_ledger=owner.accounting),
        _transition_proof(ownership.QuietReceipt,owner,epoch,_observed_ns=wire._transition_quiet_ns),
        _transition_proof(ownership.TransitionJournalReceipt,owner,epoch,
            _ref=(ref.path,ref.sha256,ref.length),_flushed_ns=flushed))
    transition._held={type(value):value for value in proofs}
    return transition.issue_admission(*proofs,now_ns=time.monotonic_ns())


def _require_wire_resume(owner,wire,ticket):
    _live(owner,wire)
    transition=owner.transition_owner
    deny(type(ticket) is ownership.TransitionAdmission and ticket is wire._ticket
        and ticket._owner is transition and ticket._wire is wire and ticket._policy is owner.deadlines
        and ticket._committed is True and any(item is ticket for item in transition._tickets)
        and owner.deadlines._first_owner is transition
        and wire._state in ('TRANSITION_PREP','C_DISPATCH','FLIGHT','STOP_ACK','DEBUG_FENCE'),
        'call_runtime_resume_ticket')
    archive=_archive_for(owner,ticket.source_epoch)
    deny(archive.closed is wire._transition_closed and archive.closed._memory_revoked
        and owner._current is None,'call_runtime_resume_retired')
    # c and its request ACK retain their original5s window. The later silent
    # stop/ACK/debug fence uses the independently frozen original60s flight.
    flight=wire._flights[-1] if wire._flights and wire._flights[-1].target_epoch==ticket.target_epoch else None
    initial=flight is None or flight.request_ack_received_ns is None
    incomplete(time.monotonic_ns()<min(owner.deadlines.effective_work_ns,
        ticket.response_deadline_ns if initial else ticket.next_stop_deadline_ns),
        'call_runtime_resume_deadline')


def _require_wire_termination(owner,wire,closed_C2):
    _closed_source(owner,wire,closed_C2,'C2')
    deny(wire._epoch=='C2' and wire._state in ('STOPPED','TERMINAL_CLEAR','QUIT_DISPATCH','QUIT_WAIT','DRAIN')
        and owner._fact_receipts.get('C2') is not None,'call_runtime_termination_phase')


def _require_closed_projection(owner,session,snapshot,closed,copied):
    _require_session_archival(owner,session)
    archive=_archive_for(owner,session.binding.epoch)
    deny(archive.snapshot is snapshot and session._snapshot is snapshot
        and archive.closed is closed and owner._closed_epochs.get(session.binding.epoch) is closed
        and session._retired and session.retainer._revoked and archive.copied is copied,
        'call_runtime_closed_projection')


def _publish_c0_facts(owner,receipt):
    deny(type(receipt) is sessionmod.FreshC0FactsReceipt,'call_runtime_C0_fact_type')
    archive=_archive_for(owner,'C0')
    deny('C0' not in owner._fact_receipts and receipt._owner is owner
        and receipt.registration is owner._registration and receipt.session is archive.registered.session
        and receipt.snapshot is archive.snapshot and receipt.closed is archive.closed
        and archive.projection is receipt.facts,'call_runtime_C0_fact_join')
    ref,raw=_held_blob(owner,'epochs/C0/epoch.json')
    deny(receipt.facts.epoch_ref is ref and receipt.epoch_bytes is raw,'call_runtime_C0_epoch_seal')
    owner._fact_receipts['C0']=receipt


def _publish_selected_call(owner,receipt):
    deny(type(receipt) is sessionmod.SelectedCallReceipt,'call_runtime_selected_type')
    archive=_archive_for(owner,'C1')
    deny('C1' not in owner._fact_receipts and receipt._owner is owner
        and receipt.registration is owner._registration and receipt.session is archive.registered.session
        and receipt.snapshot is archive.snapshot and receipt.closed is archive.closed
        and receipt.c0_receipt is owner._fact_receipts.get('C0') and archive.projection is receipt.facts,
        'call_runtime_selected_join')
    owner.inventory.require_exact(receipt.facts_ref,receipt.facts_bytes)
    deny(receipt.facts_ref.path=='selected-call.json','call_runtime_selected_path')
    owner._fact_receipts['C1']=receipt


def _require_extent_record(owner,session,ref,data):
    _require_wire_binding(owner,owner._wire,owner._current,session)
    deny(session.binding.epoch=='C2' and session.map_extent_pending and ref.path=='map-extent.json',
        'call_runtime_extent_phase')
    owner.inventory.require_exact(ref,data)
def _publish_owned_graph(owner,streams):
    deny(type(owner) is capture._OwnedCallRuntime and owner._registration is None
        and owner._wire is None and owner.qemu_owner.child is not None
        and type(streams) is dict and tuple(streams)==VM_STREAMS,'call_runtime_graph_inputs')
    deny(streams['qemu_stdout'] is owner.qemu_owner.child.stdout
        and streams['qemu_stderr'] is owner.qemu_owner.child.stderr,'call_runtime_owned_pipes')
    capture.require_call_runtime_registration(owner.prepared,_held_plan(owner))
    incomplete(not owner.qemu_owner.reaped and not owner.qemu_owner.ownership_lost
        and owner.qemu_owner.child.returncode is None,'call_runtime_owned_child')
    endpoints={}
    for name,source in streams.items():
        fd=source.fileno();info=os.fstat(fd)
        deny(type(fd) is int and fd>=0 and fd not in [p.descriptor for p in endpoints.values()]
            and stat.S_IFMT(info.st_mode) in (stat.S_IFSOCK,stat.S_IFIFO),
            'call_runtime_endpoint')
        endpoints[name]=_Endpoint(source,fd,info.st_dev,info.st_ino,info.st_mode)
    value=object.__new__(wiremod.CallWire)
    registration=_native(capture.ClosedOwnedCallRegistration,_owner=owner,prepared=owner.prepared,
        qemu_owner=owner.qemu_owner,wire=value,deadlines=owner.deadlines,accounting=owner.accounting,
        inventory=owner.inventory,parent_identity=owner.parent_identity,
        transition_owner=owner.transition_owner,read_attempts=owner.read_attempts,read_operations=owner.read_operations)
    value._init_inert(registration,streams['qmp-in'],{name:streams[name] for name in VM_STREAMS[1:]})
    owner._wire=value;owner._descriptors=endpoints
    owner.transition_owner._wire=value;owner.transition_owner._registered=True
    # All reciprocal aliases already point at their final objects. This single
    # held pointer is the graph publication; constructor work has performed no IO.
    owner._registration=registration
    deny(_issued_call_registration(registration,value),'call_runtime_graph_publication')
    return value


def _slice(owner,position,refs):
    if position is None:return None
    deny(type(position) is wiremod.WirePosition and position.stream in refs,'call_runtime_slice')
    return read.RawSlice(refs[position.stream],position.offset,position.length).as_json()


def _operation_json(owner,row,refs):
    return {key:getattr(row,key) for key in ('seq','charged_epoch','protocol','operation','started_ns',
        'finished_ns','result')}|dict(request=_slice(owner,row.request,refs),response=_slice(owner,row.response,refs))


def _event_json(owner,row,refs):
    return {key:getattr(row,key) for key in ('seq','protocol','name','received_ns','receive_ordinal',
        'state','confirmed_epoch','target_epoch','cause_epoch','flight_id')}|dict(wire=_slice(owner,row.wire,refs))


def _raw_copy(owner,stream,path):
    raw=owner._wire.raw(stream)
    return _put(owner,path,raw),raw


def _retain_operation_copies(owner):
    for row in owner._wire._operations:
        if row.operation=='physical_read':continue # Already charged/sealed by exact retainer.
        for label,position in (('request',row.request),('response',row.response)):
            if position is None:continue
            name=f'operations/{row.seq:04d}-{label}.bin'
            owner.accounting.reserve_output(position.length)
            raw=bytes(memoryview(owner._wire._raw[position.stream])[position.offset:position.offset+position.length])
            if name in owner.inventory._slots:
                ref,data=_held_blob(owner,name)
                deny(data==raw,'call_runtime_operation_copy_changed')
            else:_put(owner,name,raw)


def _retain_host(owner,observation):
    import struct
    epoch=observation._confirmed.epoch;prefix=f'epochs/{epoch}/host/'
    refs={}
    # Retain the exact already-parsed five-frame metadata protocol, without
    # reparsing all maps text or introducing a new field/read request.
    for phase in ('before','after'):
        helper=observation.helpers['metadata_'+phase]
        owner.accounting.reserve_output(len(helper.output)+len(helper.stderr))
        raw=bytes(helper.output);err=bytes(helper.stderr)
        wire_ref=_put(owner,prefix+f'metadata-{phase}.bin',raw)
        err_ref=_put(owner,prefix+f'metadata-{phase}-stderr.bin',err)
        row=dict(schema_version=1,phase=phase,reader_pid=helper.child.pid,
            started_ns=helper.lifecycle[0]['started_ns'],
            finished_ns=next(r['finished_ns'] for r in helper.lifecycle if r['operation']=='wait'),
            wait_role=helper.role,wire_ref=wire_ref.as_json(),stderr_ref=err_ref.as_json())
        offset=0
        for name in ('stat','maps','smaps','mountinfo','exe_identity'):
            deny(offset+4<=len(raw),'call_runtime_metadata_frame')
            length,=struct.unpack_from('>I',raw,offset);offset+=4
            deny(offset+length<=len(raw),'call_runtime_metadata_length')
            owner.accounting.reserve_output(length)
            ref=_put(owner,prefix+f'metadata-{phase}-{name}.bin',raw[offset:offset+length]);offset+=length
            row[name+'_ref']=ref.as_json()
        deny(offset==len(raw),'call_runtime_metadata_tail')
        refs['metadata_'+phase+'_ref']=_json(owner,prefix+f'metadata-{phase}.json',row)[0].as_json()
    helper=observation.helpers['fields']
    owner.accounting.reserve_output(len(observation.begin_raw)+len(observation.admit_raw))
    deny(observation.request_sent==observation.begin_raw+observation.admit_raw,
        'call_runtime_field_request_prefix')
    refs2={}
    for name,data in (('fields-output.bin',helper.output),('fields-stderr.bin',helper.stderr),
            ('fields-begin.json',observation.begin_raw),('fields-admit.json',observation.admit_raw)):
        if type(data) is bytearray:owner.accounting.reserve_output(len(data));data=bytes(data)
        refs2[name]=_put(owner,prefix+name,data)
    owner.accounting.reserve_output(16384+2048*len(observation.reads))
    rows=[]
    for observed in observation.reads:
        row=dict(observed)
        for key in ('started_wire','finished_wire'):
            row[key]=read.RawSlice(refs2['fields-output.bin'],*row[key]).as_json()
        rows.append(row)
    refs['reads_ref']=_json(owner,prefix+'fields.json',dict(schema_version=1,
        helper_pid=helper.child.pid,wait_role=helper.role,reads=rows,
        begin_ref=refs2['fields-begin.json'].as_json(),admit_cpu_ref=refs2['fields-admit.json'].as_json(),
        output_ref=refs2['fields-output.bin'].as_json(),stderr_ref=refs2['fields-stderr.bin'].as_json()))[0].as_json()
    for name,data in (('peer.bin',observation.peer_raw),('sigchld-spawn.bin',owner.before_spawn),
                     ('sigchld-open.bin',observation.sigchld_raw)):
        refs[name]=_put(owner,prefix+name,data).as_json()
    refs['peer_ref']=_json(owner,prefix+'peer.json',dict(raw_ref=refs['peer.bin'],
        observed_ns=observation.peer_at_ns,pid=owner.qemu_owner.child.pid,uid=os.getuid(),gid=os.getgid()))[0].as_json()
    refs['sigchld_ref']=_json(owner,prefix+'sigchld.json',dict(
        spawn_ref=refs['sigchld-spawn.bin'],spawn_ns=owner.before_spawn_ns,
        open_ref=refs['sigchld-open.bin'],open_ns=observation.sigchld_at_ns))[0].as_json()
    refs['process']=observation.process
    return refs


def _retain_prefix(owner,stop,registers,observation,layout):
    epoch=stop.epoch;prefix=f'epochs/{epoch}/';wire=owner._wire
    refs={stream:_raw_copy(owner,stream,prefix+'prefix/'+RAW_FILES[stream])[0]
        for stream in ('qmp-in','qmp-out','rsp','rsp-out')}
    _retain_operation_copies(owner)
    owner.accounting.reserve_output(4096+2048*(len(wire._operations)+len(wire._events)))
    _json(owner,prefix+'prefix/index.json',dict(schema_version=1,epoch=epoch,
        raw_refs=[r.as_json() for r in refs.values()],
        operations=[_operation_json(owner,r,refs) for r in wire._operations],
        events=[_event_json(owner,r,refs) for r in wire._events]))
    event=wire._events[stop.stop_event_seq-1]
    deny(event.protocol=='rsp' and event.name=='T05thread:01;' and event.flight_id==epoch,'call_runtime_stop_event')
    owner.accounting.reserve_output(event.wire.length)
    stop_raw=bytes(memoryview(wire._raw['rsp'])[event.wire.offset:event.wire.offset+event.wire.length])
    _put(owner,prefix+'stop.bin',stop_raw)
    _json(owner,prefix+'before-registers.json',dict(schema_version=1,operations=[r[3] for r in registers.values]))
    _put(owner,prefix+'hmp-before.txt',wire._host_before.hmp_bytes)
    _put(owner,prefix+'layout-before.txt',layout.raw_bytes)
    helper_refs=_retain_host(owner,observation)
    _json(owner,prefix+'host-phase.json',dict(schema_version=1,epoch=epoch,
        lease_started_ns=observation._lease.started_ns,lease_deadline_ns=observation._lease.deadline_ns,
        finished_ns=observation._receipt.finished_ns,before=dict(wire._host_before.operations),
        after=dict(wire._host_after.operations),cpu_identity=list(wire._host_before.cpu_identity),
        helpers=helper_refs,field_state=observation.state,
        process_identity=list(observation._receipt.process_identity)))


def _copied_blobs(owner,session=None):
    # Include only already-sealed native bytes; these references do not perform
    # reads or promote copied facts. Input caller/C0/selected records are explicit.
    owner.accounting.reserve_output(512*(len(owner.inventory._slots)
        +(0 if session is None else len(session._blobs))+len(owner.prepared.prior_blobs))+4096)
    values={name:(slot.ref,slot.data) for name,slot in owner.inventory._slots.items()
        if slot.state=='complete' and type(slot.data) is bytes and
        (name.startswith('epochs/') or name in ('selected-call.json','map-extent.json','map-index.json','coverage.json','caller-manifest.json'))}
    if session is not None:
        for name,pair in session._blobs.items():
            deny(name not in values or values[name]==pair,'call_runtime_copied_blob_changed')
            values[name]=pair
    manifest=_input_ref(owner.prepared.caller_manifest_ref)
    raw=dict(owner.prepared.prior_blobs)[manifest['path']]
    values[manifest['path']]=(read.BlobRef(**manifest),raw)
    return tuple(pure.CopiedBlob(ref,data) for ref,data in values.values())


def _issue_current_epoch(owner,stop,registers,receipt,layout):
    wire=owner._wire
    _require_wire_stop(owner,wire,stop)
    observation=owner._observations.get(stop.epoch)
    deny(type(observation) is host._OwnedParentObservation
        and host._issued_parent_observation(receipt,wire,observation._lease)
        and receipt is wire._host_receipt and receipt is observation._receipt
        and layout is wire._layout_before and registers is wire._before_registers
        and owner._current is None and stop.epoch not in owner._epochs,
        'call_runtime_epoch_admission')
    deny(receipt.process_identity==(owner.qemu_owner.child.pid,os.getpid(),observation.process['starttime_ticks'])
        and receipt.finished_ns<=wire._operations[layout.operation_seq-1].started_ns,
        'call_runtime_host_before_memory')
    _retain_prefix(owner,stop,registers,observation,layout)
    owner.accounting.reserve_output(32768)
    values={n:v for n,_,v,_ in registers.values};hmp=c0._hmp(wire._host_before.hmp_bytes,values)
    state=c0._mode(dict(phys_bits=wire._host_before.cpu_identity[2],cr0=values[27],cr3=values[29],
        cr4=values[30],efer=values[32],cpl=hmp['cpl'],cs64=hmp['cs64'],a20=hmp['a20'],
        **{k:observation.state[k] for k in ('no_npt','no_svm_guest','no_smm')}))
    source=None if stop.epoch=='C0' else owner._fact_receipts['C0' if stop.epoch=='C1' else 'C1']
    binding=_native(sessionmod.CurrentEpochRamBinding,_owner=owner,registration=owner._registration,
        parent_identity=owner.parent_identity,wire=wire,epoch=stop.epoch,epoch_nonce=stop.stop_nonce,
        stop=stop,mode=wire._current_mode,before_registers=registers,host_receipt=receipt,
        layout_receipt=layout,transport_identity=_transport(owner),state=tuple(state.items()),
        registers=registers.values,hmp_raw=wire._host_before.hmp_bytes,layout_raw=layout.raw_bytes,
        ranges=layout.ranges,prefix_blobs=_copied_blobs(owner),source_fact=source,
        stop_ns=stop.received_ns,work_deadline_ns=owner.deadlines.effective_work_ns,
        stop_deadline_ns=stop.received_ns+60*SECOND)
    plan_ref,plan_raw=_held_blob(owner,'plan.json')
    owner._preparing_epoch=(binding,None)
    factory=getattr(read,'_prepare_owned_retainer',None)
    incomplete(callable(factory),'call_runtime_retainer_producer_pending')
    retainer=factory(owner._registration,binding,Path(owner.prepared.run),plan_ref,
        min(binding.work_deadline_ns,binding.stop_deadline_ns))
    owner._preparing_epoch=(binding,retainer)
    session=sessionmod._initialize_owned_epoch(binding,owner,retainer)
    registered=_native(capture.RegisteredCurrentEpochBinding,_owner=owner,registration=owner._registration,
        binding=binding,session=session,retainer=retainer,host_receipt=receipt,layout_receipt=layout)
    attach=getattr(read,'_attach_owned_retainer',None)
    incomplete(callable(attach),'call_runtime_retainer_attachment_pending')
    attach(retainer,session,registered)
    owner._epochs[stop.epoch]=_EpochArchive(registered)
    owner._current=registered
    owner._preparing_epoch=None
    wire.bind_acquisition(registered,session)
    return registered
def _adopt_retainer(owner,retainer):
    adopt=getattr(type(owner.inventory),'_adopt_retainer',None)
    incomplete(callable(adopt),'call_runtime_retainer_adoption_pending')
    return adopt(owner.inventory,retainer)


def _closed_context(owner,archive,*,final=False):
    session=archive.registered.session;snapshot=archive.snapshot;binding=archive.registered.binding
    epoch=binding.epoch;prefix=f'epochs/{epoch}/'
    ref=lambda name:_held_blob(owner,prefix+name)[0]
    common=(epoch,ref('epoch.json'),ref('stop.bin'),ref('before-registers.json'),binding.registers,
        snapshot.after.registers.values,binding.state,ref('hmp-before.txt'),ref('hmp-after.txt'),
        ref('layout-before.txt'),ref('layout-after.txt'),ref('host-phase.json'))
    blobs=_copied_blobs(owner,session)
    if epoch=='C0':return sessionmod.ClosedC0CopiedInput(*common,snapshot.frames,blobs)
    return pure.CopiedEpochBinding(*common,owner._fact_receipts['C0'].facts,snapshot.frames,blobs,
        _held_blob(owner,'map-extent.json')[0] if epoch=='C2' else None,
        _held_blob(owner,'map-index.json')[0] if final else None,
        _held_blob(owner,'coverage.json')[0] if final else None)


def _close_epoch(owner,current,complete,after):
    session=current.session;epoch=current.binding.epoch;prefix=f'epochs/{epoch}/'
    _require_wire_binding(owner,owner._wire,current,session)
    archive=_archive_for(owner,epoch)
    deny(archive.snapshot is None and epoch not in owner._closed_epochs,'call_runtime_close_once')
    snapshot=session.finish(after)
    # Retirement precedes every sealed closed-epoch/public-facts artifact. No
    # old RAM cache/grant survives either successful or failed later retention.
    current.retainer._revoked=True
    owner._current=None
    archive.snapshot=snapshot
    closed=_transition_proof(ownership.ClosedEpochReceipt,owner,epoch,_memory_revoked=True)
    archive.closed=closed;owner._closed_epochs[epoch]=closed
    _adopt_retainer(owner,current.retainer)
    ar,_=_json(owner,prefix+'after-registers.json',dict(schema_version=1,
        operations=[r[3] for r in after.registers.values]))
    hr=_put(owner,prefix+'hmp-after.txt',after.hmp.raw_bytes)
    lr=_put(owner,prefix+'layout-after.txt',after.layout.raw_bytes)
    owner.accounting.reserve_output(8192+512*len(snapshot.receipts))
    physical=[dict(epoch=r.epoch,request_id=r.request_id,physical_ordinal=r.physical_ordinal,
        operation_seq=r.operation_seq,target_kind=r.target_kind,pass_index=r.pass_index,
        target_ordinal=r.target_ordinal,logical_offset=r.logical_offset,physical=r.physical,length=r.length)
        for r in snapshot.receipts]
    plan=dict(schema_version=1,epoch=epoch,reads=physical,map_translation=None)
    if epoch=='C2':
        mp=session._map_plan
        incomplete(type(mp) is sessionmod.MapTranslationPlan,'call_runtime_map_plan_missing')
        plan['map_translation']=dict(epoch='C2',extent_ref=mp.extent_ref.as_json(),
            map_object_ordinal=mp.map_object_ordinal,map_parts=_fact_value(owner,mp.map_parts),
            frame_ordinals=list(mp.frame_ordinals),reserved_read_operations=mp.reserved_read_operations,
            reserved_bytes=mp.reserved_bytes,discovery_frozen=mp.discovery_frozen)
    pr,_=_json(owner,prefix+'read-plan.json',plan)
    cr,_=_json(owner,prefix+'completion.json',dict(schema_version=1,epoch=epoch,
        last_read_seq=complete.last_read_seq,last_finished_ns=complete.last_finished_ns,
        frames=len(snapshot.frames),objects=len(snapshot.objects),physical_reads=len(snapshot.receipts),
        observed_consistent=True,atomic_snapshot=False,device_quiescence_verified=False))
    closure,_=_json(owner,prefix+'closure.json',dict(schema_version=1,epoch=epoch,
        memory_revoked=True,after_register_operations=[r[3] for r in after.registers.values],
        hmp_operation_seq=after.hmp.operation_seq,layout_operation_seq=after.layout.operation_seq,
        closed_ns=time.monotonic_ns(),parent_lifecycle_pending=True))
    ref=lambda name:_held_blob(owner,prefix+name)[0]
    archive.refs=dict(stop_ref=ref('stop.bin'),before_registers_ref=ref('before-registers.json'),
        host_phase_ref=ref('host-phase.json'),layout_before_ref=ref('layout-before.txt'),read_plan_ref=pr,
        completion_ref=cr,after_registers_ref=ar,hmp_after_ref=hr,layout_after_ref=lr,closure_ref=closure)
    value=dict(phase=epoch,epoch=epoch,firmware_phase='firmware_active',
        **{name:ref.as_json() for name,ref in archive.refs.items()},
        table_snapshots=_fact_value(owner,snapshot.frames),objects=_fact_value(owner,snapshot.objects),
        translations=_fact_value(owner,tuple(part for obj in snapshot.objects for part in obj.parts)))
    _json(owner,prefix+'epoch.json',value)
    archive.copied=_closed_context(owner,archive)
    result=session._project_closed_facts(snapshot,closed,archive.copied)
    archive.projection=result
    if epoch=='C0':
        sessionmod._register_closed_c0_facts(session,snapshot,closed,archive.copied,result)
    elif epoch=='C1':
        ref,data=_json(owner,'selected-call.json',_fact_value(owner,result))
        sessionmod._register_selected_call(session,snapshot,closed,archive.copied,result,ref,data)
    else:
        deny(type(result) is pure.C2ReturnProjection,'call_runtime_map_projection')
        _put(owner,'map-index.json',result.descriptor_index_bytes)
        _put(owner,'coverage.json',result.coverage_bytes)
        copied=_closed_context(owner,archive,final=True)
        # Final verification is a separate pure invocation with its own context,
        # scalar, projection and byte-copy credit; no recycled W+5J allowance.
        bound=pure.projection_size_bound(snapshot.map_extent,snapshot.objects,snapshot.frames)
        owner.accounting.reserve_output(sessionmod._validation_bound(copied,snapshot.objects,complete=True,final=True)
            +sessionmod._validation_bound(copied,snapshot.objects[:6],complete=False,scalar=True)
            +bound.pure_call_credit)
        facts=pure.validate_c2_return(copied,owner._fact_receipts['C1'].facts,
            snapshot.map_extent,snapshot.objects,snapshot.frames)
        ref,raw=_json(owner,'map-facts.json',_fact_value(owner,facts))
        owner._fact_receipts['C2']=(facts,ref,raw)
    return closed


def _acquire_epoch(owner,stop):
    wire=owner._wire
    _require_wire_stop(owner,wire,stop)
    wire.confirm_stopped_physical_mode(stop)
    registers=wire.read_selected_registers(stop,'before')
    deny(stop.epoch not in owner._observations,'call_runtime_observation_once')
    observation=host._OwnedParentObservation(owner._registration,stop,registers)
    owner._observations[stop.epoch]=observation
    receipt=observation.observe()
    layout=wire.read_current_layout(stop,'before')
    current=_issue_current_epoch(owner,stop,registers,receipt,layout)
    session=current.session
    while True:
        if session.map_extent_pending:
            evidence=session.scalar_evidence()
            owner.accounting.reserve_output(sessionmod._validation_bound(evidence.context,
                evidence.code_objects+evidence.scalar_objects,complete=False,scalar=True))
            extent=pure.validate_c2_scalars(owner._fact_receipts['C1'].facts,evidence)
            ref,data=_json(owner,'map-extent.json',_fact_value(owner,extent))
            session._attach_extent_record(ref,data)
            session.install_map_extent(extent)
        request=session.next_request()
        if type(request) is sessionmod.PhaseReadsComplete:break
        deny(type(request) is sessionmod.EpochReadGrant,'call_runtime_session_request')
        session.accept(wire.read_physical(request))
    after=wire.complete_phase(request)
    return _close_epoch(owner,current,request,after)


def _capture_three_epochs(owner):
    wire=owner._wire
    wire.prelaunch();wire.prepare_reset()
    stop=wire.stop_at_entry(owner.prepared.prior)
    for epoch in EPOCHS:
        deny(stop.epoch==epoch,'call_runtime_epoch_order')
        closed=_acquire_epoch(owner,stop)
        if epoch=='C2':return wire.terminate_parent(closed)
        target=(issue_first_target(owner,closed,owner._fact_receipts['C0']) if epoch=='C0'
            else issue_return_target(owner,closed,owner._fact_receipts['C1']))
        ticket=wire.prepare_transition(closed,target)
        stop=wire.resume_to_next(ticket)
    raise AssertionError('closed three-epoch sequence')
def _bytes_at(raw,position,stream):
    deny(type(position) is wiremod.WirePosition and position.stream==stream
        and type(position.offset) is int and type(position.length) is int
        and 0<=position.offset and 0<position.length and position.offset+position.length<=len(raw),
        'call_runtime_raw_position')
    return raw[position.offset:position.offset+position.length]


def _validate_rsp_history(wire,rawin,rawout):
    # Whole streams, including every request ACK and outgoing response ACK.
    codec=rsp.AckDecoder();frames=codec.feed(rawin)
    deny(not codec.pending,'call_runtime_rsp_tail')
    spans={};offset=0
    for frame in frames:
        spans[offset]=(frame,offset+len(frame.raw));offset+=len(frame.raw)
    deny(offset==len(rawin) and len(frames)==len(wire._rsp_frame_rows),'call_runtime_rsp_inventory')
    for (kind,position,_,_),frame in zip(wire._rsp_frame_rows,frames):
        deny(kind==frame.kind and _bytes_at(rawin,position,'rsp')==frame.raw,'call_runtime_rsp_frame_join')
    used=set();outpos=0
    for row in wire._operations:
        if row.protocol!='rsp':continue
        deny(row.result=='ok' and row.request is not None and row.request.offset==outpos,
            'call_runtime_rsp_request_cover')
        request=_bytes_at(rawout,row.request,'rsp-out');outpos+=len(request)
        if row.operation=='stop_ack':
            deny(request==b'+' and row.response is None,'call_runtime_stop_ack')
            continue
        request_decoder=rsp.AckDecoder();decoded=request_decoder.feed(request)
        deny(not request_decoder.pending and len(decoded)==1 and decoded[0].kind=='PACKET',
            'call_runtime_rsp_request_packet')
        response=row.response;deny(response is not None and response.offset in spans,'call_runtime_rsp_response')
        frame,end=spans[response.offset]
        deny(response.offset not in used and _bytes_at(rawin,response,'rsp')==frame.raw,
            'call_runtime_rsp_response_unique')
        if row.operation=='continue':
            deny(decoded[0].payload==b'c' and frame.kind=='ACK','call_runtime_continue_ack')
            used.add(response.offset)
            continue
        ackoffset=response.offset-1
        deny(frame.kind=='PACKET' and ackoffset in spans and spans[ackoffset][0].kind=='ACK'
            and spans[ackoffset][1]==response.offset and ackoffset not in used,
            'call_runtime_rsp_request_ack')
        deny(rawout[outpos:outpos+1]==b'+','call_runtime_rsp_response_ack')
        used.update((ackoffset,response.offset));outpos+=1
    for event in wire._events:
        if event.protocol!='rsp':continue
        pos=event.wire
        deny(pos.offset in spans and pos.offset not in used and event.name=='T05thread:01;'
            and spans[pos.offset][0].payload==b'T05thread:01;'
            and _bytes_at(rawin,pos,'rsp')==spans[pos.offset][0].raw,'call_runtime_stop_packet')
        used.add(pos.offset)
    deny(used==set(spans) and outpos==len(rawout),'call_runtime_rsp_unexplained_bytes')
    segment_end=0
    for position,observed in wire._rsp_segment_rows:
        deny(position.stream=='rsp-out' and position.offset==segment_end and position.length>0,
            'call_runtime_rsp_segment_coverage')
        segment_end+=position.length
    deny(segment_end==len(rawout),'call_runtime_rsp_segment_end')


def _validate_qmp_history(wire,rawin,rawout):
    spans={};offset=0;greeting=None
    for line in rawin.splitlines(keepends=True):
        deny(line.endswith(b'\r\n'),'call_runtime_qmp_frame')
        value=witness.strict_json(line,65536)
        spans[offset]=(value,len(line));offset+=len(line)
        if greeting is None:greeting=value
    deny(offset==len(rawin) and greeting is not None and set(greeting)=={'QMP'},
        'call_runtime_qmp_greeting')
    used={0};outpos=0;identifier=0
    for row in wire._operations:
        if row.protocol!='qmp':continue
        identifier+=1
        deny(row.result=='ok' and row.request is not None and row.request.offset==outpos,
            'call_runtime_qmp_request_cover')
        request=_bytes_at(rawout,row.request,'qmp-out');outpos+=len(request)
        data=witness.strict_json(request,65536)
        deny(type(data) is dict and type(data.get('id')) is int and data['id']==identifier
            and set(data)<= {'execute','arguments','id'} and type(data.get('execute')) is str,
            'call_runtime_qmp_id')
        if row.operation=='quit':deny(not request.endswith(b'\n') and data=={'execute':'quit','id':identifier},'call_runtime_undelimited_quit')
        else:deny(request.endswith(b'\r\n'),'call_runtime_qmp_delimiter')
        pos=row.response
        deny(pos is not None and pos.offset in spans and pos.offset not in used
            and pos.length==spans[pos.offset][1]-2,'call_runtime_qmp_response')
        response=spans[pos.offset][0]
        deny(set(response)=={'return','id'} and type(response['id']) is int and response['id']==identifier,
            'call_runtime_qmp_response_id')
        used.add(pos.offset)
    for event in wire._events:
        if event.protocol!='qmp':continue
        pos=event.wire
        deny(pos.offset in spans and pos.offset not in used and pos.length==spans[pos.offset][1]-2
            and spans[pos.offset][0].get('event')==event.name,'call_runtime_qmp_event_join')
        value=spans[pos.offset][0]
        if event.name=='SHUTDOWN':
            deny(value.get('data')=={'guest':False,'reason':'host-qmp-quit'}
                and event.state in ('QUIT_WAIT','DRAIN'),'call_runtime_shutdown')
        else:deny(witness.shared_qmp_boot_event(value,base.VAPIC_OFF_INVOCATION_PROFILE),'call_runtime_boot_event')
        used.add(pos.offset)
    deny(used==set(spans) and outpos==len(rawout),'call_runtime_qmp_unexplained_bytes')
    deny(len(wire._qmp_frame_rows)==len(spans),'call_runtime_qmp_native_inventory')
    for pos,stamp,ordinal in wire._qmp_frame_rows:
        deny(pos.offset in spans and pos.length==spans[pos.offset][1],'call_runtime_qmp_native_span')


def _validate_flights(owner):
    wire=owner._wire
    deny(tuple(f.target_epoch for f in wire._flights)==EPOCHS and len(wire._events)<=128,
        'call_runtime_three_flights')
    deny(tuple(r.seq for r in wire._events)==tuple(range(1,len(wire._events)+1)),
        'call_runtime_event_sequence')
    recognized=sorted([(p,o,n,'qmp') for p,o,n in wire._qmp_frame_rows]+
        [(p,o,n,'rsp') for _,p,o,n in wire._rsp_frame_rows],key=lambda row:row[2])
    deny([r[2] for r in recognized]==list(range(1,len(recognized)+1)),
        'call_runtime_receive_sequence')
    previous=owner.deadlines.started_ns
    for _,at,_,_ in recognized:
        deny(type(at) is int and previous<=at<=owner.deadlines.effective_hard_ns,
            'call_runtime_receive_clock');previous=at
    event_slots=set()
    for i,flight in enumerate(wire._flights):
        deny(type(flight) is wiremod.FlightRecord and flight.result=='ok'
            and flight.source_epoch==(None if i==0 else EPOCHS[i-1]),'call_runtime_flight_identity')
        rows=[wire._events[n-1] for n in (flight.qmp_resume_event_seq,flight.qmp_stop_event_seq,flight.rsp_stop_event_seq)]
        deny(tuple(r.name for r in rows)==('RESUME','STOP','T05thread:01;')
            and all(r.flight_id==flight.target_epoch and r.cause_epoch==flight.target_epoch for r in rows)
            and rows[0].seq<rows[1].seq,'call_runtime_flight_events')
        event_slots.update(r.seq for r in rows)
        resume=wire._operations[flight.resume_operation_seq-1]
        ack=wire._operations[flight.stop_ack_operation_seq-1]
        debug=wire._operations[flight.debug_operation_seq-1]
        deny(resume.operation=='continue' and resume.result=='ok'
            and ack.operation=='stop_ack' and debug.operation=='query_status'
            and resume.request==flight.c_sent_slice and resume.response==flight.request_ack_slice
            and resume.finished_ns==flight.request_ack_received_ns,
            'call_runtime_flight_operations')
        deny(resume.started_ns<=flight.c_complete_ns<=flight.request_ack_received_ns<=rows[2].received_ns
            <=ack.started_ns<=ack.finished_ns<=debug.started_ns<=debug.finished_ns
            and flight.request_ack_received_ns<flight.response_deadline_ns
            and debug.finished_ns<flight.stop_deadline_ns,'call_runtime_flight_deadlines')
        archive=_archive_for(owner,flight.target_epoch)
        deny(archive.registered.binding.stop.flight is flight,'call_runtime_flight_stop_identity')
        if i:
            ticket=owner.transition_owner._tickets[i-1]
            deny(ticket._consumed and ticket._committed and flight.admission_ref==ticket.journal_ref
                and flight.response_deadline_ns==ticket.response_deadline_ns
                and flight.stop_deadline_ns==ticket.next_stop_deadline_ns
                and flight.source_closure_ref is _archive_for(owner,EPOCHS[i-1]).refs['closure_ref'],
                'call_runtime_flight_ticket')
    for event in wire._events:
        if event.seq in event_slots:continue
        deny(event.name in ('RTC_CHANGE','SHUTDOWN') and event.protocol=='qmp'
            and event.flight_id is None and event.cause_epoch is None,'call_runtime_extra_event')
        deny(event.receive_ordinal>wire._events[wire._flights[0].qmp_resume_event_seq-1].receive_ordinal,
            'call_runtime_early_passive_event')


def _archival_host_receipt(owner,receipt,observation):
    # Admission already authenticated the exact wire-held brackets. Retirement
    # clears current wire slots, so archival provenance uses those held receipts,
    # not an attempt to reauthorize an earlier stop.
    return (type(receipt) is host.ParentHostObservationReceipt
        and type(observation) is host._OwnedParentObservation
        and owner._observations.get(receipt.epoch) is observation and observation._receipt is receipt
        and observation._finished and observation._registration is owner._registration
        and receipt._registration is owner._registration and receipt._wire is owner._wire
        and receipt._owner is observation and receipt.stop is observation._confirmed
        and receipt.lease is observation._lease and receipt.before_registers is observation._registers
        and receipt.before_bracket.lease is receipt.lease and receipt.after_bracket.lease is receipt.lease
        and receipt.before_bracket.operations==tuple(observation.before_bracket.items())
        and receipt.after_bracket.operations==tuple(observation.after_bracket.items())
        and receipt.before_bracket.cpu_identity==receipt.after_bracket.cpu_identity
        and receipt.lease.started_ns<=receipt.finished_ns<receipt.lease.deadline_ns)


def _validate_register_bytes(wire,registers,raw):
    from run0_c0_acquire import REGISTER_WIDTHS
    deny(type(registers) is wiremod.SelectedEpochRegisters and len(registers.values)==29,
        'call_runtime_register_receipt')
    for (number,width),(n,w,value,seq) in zip(REGISTER_WIDTHS,registers.values):
        deny(type(n) is int and type(w) is int and (n,w)==(number,width)
            and type(value) is int and type(seq) is int,
            'call_runtime_register_shape')
        row=wire._operations[seq-1]
        deny(row.protocol=='rsp' and row.operation==f'p{n:x}' and row.result=='ok'
            and row.charged_epoch==registers.stop.epoch,'call_runtime_register_operation')
        deny(_bytes_at(raw['rsp-out'],row.request,'rsp-out')==rsp.encode_packet(f'p{n:x}'.encode()),
            'call_runtime_register_request')
        decoder=rsp.AckDecoder();frames=decoder.feed(_bytes_at(raw['rsp'],row.response,'rsp'))
        deny(not decoder.pending and len(frames)==1 and frames[0].kind=='PACKET'
            and len(frames[0].payload)==2*w and rsp.HEX.fullmatch(frames[0].payload) is not None,
            'call_runtime_register_response')
        deny(int.from_bytes(bytes.fromhex(frames[0].payload.decode('ascii')),'little')==value,
            'call_runtime_register_value')


def _validate_qmp_text(wire,seq,expected,raw):
    deny(type(seq) is int and 1<=seq<=len(wire._operations),'call_runtime_text_sequence')
    row=wire._operations[seq-1]
    deny(row.protocol=='qmp' and row.result=='ok' and row.operation in ('hmp_registers','hmp_flatview'),
        'call_runtime_text_operation')
    value=witness.strict_json(_bytes_at(raw['qmp-in'],row.response,'qmp-in'),65536)
    deny(type(value.get('return')) is str and value['return'].isascii()
        and value['return'].encode('ascii')==expected,'call_runtime_text_value')


def _validate_epoch_prefix(owner,epoch,raw):
    prefix=f'epochs/{epoch}/prefix/'
    refs={}
    for name in ('qmp-in','qmp-out','rsp','rsp-out'):
        ref,data=_held_blob(owner,prefix+RAW_FILES[name]);refs[name]=ref
        deny(type(raw[name]) is bytes and len(data)<=len(raw[name])
            and memoryview(raw[name])[:len(data)]==data,'call_runtime_prefix_bytes')
    _,data=_held_blob(owner,prefix+'index.json')
    owner.accounting.reserve_output(8*len(data)+4096)
    index=witness.strict_json(data,1<<20)
    deny(type(index) is dict and set(index)=={'schema_version','epoch','raw_refs','operations','events'}
        and pure._same_json(index['schema_version'],1) and index['epoch']==epoch
        and pure._same_json(index['raw_refs'],[r.as_json() for r in refs.values()])
        and type(index['operations']) is list and type(index['events']) is list
        and len(index['operations'])<=len(owner._wire._operations)
        and len(index['events'])<=len(owner._wire._events),'call_runtime_prefix_index')
    owner.accounting.reserve_output(2048*(len(index['operations'])+len(index['events'])))
    deny(pure._same_json(index['operations'],[_operation_json(owner,row,refs)
        for row in owner._wire._operations[:len(index['operations'])]])
        and pure._same_json(index['events'],[_event_json(owner,row,refs)
        for row in owner._wire._events[:len(index['events'])]]),'call_runtime_prefix_history')


def _validate_complete_history(owner,raw):
    _graph(owner)
    wire=owner._wire
    deny(owner._failure is None and wire.failure is None and owner._closed and wire._state=='DONE',
        'call_runtime_final_state')
    deny(tuple(owner._epochs)==EPOCHS and tuple(owner._closed_epochs)==EPOCHS
        and owner._current is None,'call_runtime_epoch_inventory')
    incomplete(wire._drain is not None and wire._drain.closed is owner._closed_epochs['C2']
        and wire._quit.result=='ok' and wire._quit_reply is not None,
        'call_runtime_strict_quit')
    deny(tuple(row.seq for row in wire._operations)==tuple(range(1,len(wire._operations)+1))
        and len(wire._operations)<=1024 and all(row.result=='ok' for row in wire._operations),
        'call_runtime_operation_inventory')
    view=owner.accounting.view()
    deny(not view['aborted'] and view['allocated_operations']==len(wire._operations)
        and all(v<=512 for v in view['phase_operations']) and view['committed_bytes']<=32<<20
        and view['remaining_controls']==0 and view['epoch']=='C2',
        'call_runtime_ledger_history')
    owner.accounting.reserve_output(12*sum(len(raw[n]) for n in ('rsp','rsp-out','qmp-in','qmp-out'))
        +2048*(len(wire._operations)+len(wire._events)))
    _validate_rsp_history(wire,raw['rsp'],raw['rsp-out'])
    _validate_qmp_history(wire,raw['qmp-in'],raw['qmp-out'])
    _validate_flights(owner)
    _validate_complete_lifecycle(owner)
    allreads=[]
    for epoch in EPOCHS:
        _validate_epoch_prefix(owner,epoch,raw)
        archive=_archive_for(owner,epoch);registered=archive.registered
        deny(archive.closed is owner._closed_epochs[epoch] and registered.session._retired
            and registered.retainer._revoked and archive.snapshot is registered.session._snapshot,
            'call_runtime_closed_epoch_history')
        observation=owner._observations[epoch]
        deny(_archival_host_receipt(owner,registered.host_receipt,observation)
            and registered.host_receipt.field_state==host._freeze(observation.state)
            and registered.host_receipt.field_reads==host._freeze(observation.reads)
            and len(observation.reads)==14 and sum(row['length'] for row in observation.reads)==104,
            'call_runtime_host14_104')
        deny(len(archive.snapshot.objects)==(7 if epoch=='C2' else 8)
            and 1<=len(archive.snapshot.frames)<=32
            and sum(len(o.parts) for o in archive.snapshot.objects)<=(29 if epoch=='C2' else 16),
            'call_runtime_snapshot_shape')
        _validate_register_bytes(wire,registered.binding.before_registers,raw)
        _validate_register_bytes(wire,archive.snapshot.after.registers,raw)
        _validate_qmp_text(wire,archive.snapshot.after.hmp.operation_seq,archive.snapshot.after.hmp.raw_bytes,raw)
        _validate_qmp_text(wire,archive.snapshot.after.layout.operation_seq,archive.snapshot.after.layout.raw_bytes,raw)
        _validate_qmp_text(wire,registered.layout_receipt.operation_seq,registered.binding.layout_raw,raw)
        for bracket in (registered.host_receipt.before_bracket,registered.host_receipt.after_bracket):
            _validate_qmp_text(wire,dict(bracket.operations)['hmp_seq'],bracket.hmp_bytes,raw)
        allreads.extend(archive.snapshot.receipts)
        for receipt in archive.snapshot.receipts:
            registered.retainer._receipt(receipt)
            row=wire._operations[receipt.operation_seq-1]
            deny(row.operation=='physical_read' and row.charged_epoch==epoch and row.result=='ok'
                and row.started_ns==receipt.started_ns and row.finished_ns==receipt.finished_ns,
                'call_runtime_read_final_operation')
    deny(len(allreads)<=506 and tuple(r.physical_ordinal for r in allreads)==tuple(range(len(allreads)))
        and set(owner.read_attempts)==set(owner.read_operations)=={r.operation_seq for r in allreads},
        'call_runtime_physical_inventory')
    facts=owner._fact_receipts['C2'][0]
    deny(type(facts) is pure.CallMapFacts and facts.observed_consistent is True
        and facts.atomic_snapshot is False and facts.device_quiescence_verified is False,
        'call_runtime_subset_facts')
def _failure(error):
    if isinstance(error,(base.ProbeError,c0.C0DecodeError,rsp.RSPError)):
        return dict(status=error.status,reason=error.reason)
    if isinstance(error,KeyboardInterrupt):return dict(status='INCOMPLETE',reason='call_cancelled')
    if isinstance(error,OSError):return dict(status='INCOMPLETE',reason='call_io_error',errno=error.errno)
    return dict(status='INCOMPLETE',reason='call_internal_failure',exception_type=type(error).__name__)


def _record_failure(owner,error,failures):
    value=_failure(error)
    if not failures and owner._failure is not None:
        prior=dict(status=owner._failure.status,reason=owner._failure.reason)
        if (prior['status'],prior['reason'])!=(value['status'],value['reason']):failures.append(prior)
    if len(failures)<32:failures.append(value)
    if owner._failure is None:owner._failure=wiremod.Failure(value['status'],value['reason'])
    if owner._wire is not None:
        owner._wire._latch_failure(owner._failure)
        if owner._registration is not None:
            try:_abort_wire_epoch(owner,owner._wire,owner._failure)
            except BaseException as abort_error:
                if len(failures)<32:failures.append(dict(status='INCOMPLETE',reason='call_abort_incomplete',
                    exception_type=type(abort_error).__name__))


def _cleanup_wait(owner,pump,failures):
    child=owner.qemu_owner
    if child.child is None or child.reaped or child.ownership_lost:return
    try:
        if child.wait(time.monotonic(),pump=pump) is not None:return
    except BaseException as error:_record_failure(owner,error,failures)
    for sig,name,window in ((signal.SIGTERM,'SIGTERM',0.25),(signal.SIGKILL,'SIGKILL',None)):
        if child.reaped or child.ownership_lost:break
        operation='signal_term' if sig==signal.SIGTERM else 'signal_kill'
        try:
            if not any(r['operation']==operation for r in child.lifecycle):child._signal(sig,name)
        except BaseException as error:_record_failure(owner,error,failures)
        try:
            pump()
            child.wait(child.deadline if window is None else min(time.monotonic()+window,child.deadline),pump=pump)
        except BaseException as error:_record_failure(owner,error,failures)


def _cleanup(owner,streams,failures):
    wire=owner._wire
    def pump():
        if wire is None:return
        try:wire._drain_failed_owner(min(time.monotonic_ns()+10_000_000,owner.deadlines.effective_hard_ns))
        except BaseException as error:
            # Every real failure is retained; repeated polls cannot grow metadata.
            value=_failure(error)
            if value not in failures and len(failures)<32:failures.append(value)
    with witness.defer_cleanup_interrupt() as interrupted:
        if wire is not None and not failures:
            try:
                code=owner.qemu_owner.wait(owner.qemu_owner.deadline)
                incomplete(code==0,'call_runtime_VM_wait')
            except BaseException as error:_record_failure(owner,error,failures)
        if failures:
            _cleanup_wait(owner,pump,failures)
            pump()
        for observation in tuple(owner._observations.values()):
            for helper in observation.helpers.values():
                if not helper.closed:
                    try:helper.close()
                    except BaseException as error:_record_failure(owner,error,failures)
        started=time.monotonic_ns();close_errors=[]
        if wire is not None:
            try:wire.close()
            except BaseException as error:close_errors.append(error)
        seen=set()
        for source in streams.values():
            if id(source) in seen:continue
            seen.add(id(source))
            try:source.close()
            except BaseException as error:close_errors.append(error)
        if owner.qemu_owner.child is not None:
            owner.qemu_owner._receipt('close',started,'error' if close_errors else 'ok',
                errno=next((e.errno for e in close_errors if isinstance(e,OSError)),None))
        owner._closed=True
        for error in close_errors:_record_failure(owner,error,failures)
    if interrupted[0]:_record_failure(owner,KeyboardInterrupt(),failures)


def _cleanup_pre_graph(owner,streams,failures):
    # Same original owner/hard deadline, zero protocol sends. Only already-owned
    # connected endpoints are read; no invented EOF for missing roles.
    buffers={name:bytearray() for name in streams};eofs=[];errors=[]
    selector=selectors.DefaultSelector();storage=None
    try:
        owner.accounting.reserve_output(65536)
        storage=bytearray(65536)
        for name,source in streams.items():
            os.set_blocking(source.fileno(),False);selector.register(source,selectors.EVENT_READ,name)
    except BaseException as error:_record_failure(owner,error,failures)
    def pump():
        if storage is None or time.monotonic_ns()>=owner.deadlines.effective_hard_ns:return
        for key,_ in selector.select(0):
            name=key.data
            try:
                n=os.readv(key.fd,[storage])
                if n==0:
                    eofs.append(dict(stream=name,observed_ns=time.monotonic_ns()));selector.unregister(key.fileobj)
                else:
                    owner.accounting.reserve_output(2*n)
                    buffers[name].extend(memoryview(storage)[:n])
            except (BlockingIOError,InterruptedError):continue
            except BaseException as error:
                if len(errors)<6:errors.append(dict(stream=name,**_failure(error)))
                selector.unregister(key.fileobj)
    with witness.defer_cleanup_interrupt():
        try:_cleanup_wait(owner,pump,failures);pump()
        finally:selector.close();_cleanup(owner,streams,failures)
    refs={}
    for name,data in buffers.items():
        owner.accounting.reserve_output(len(data));raw=bytes(data)
        refs[name]=_put(owner,'raw/'+RAW_FILES[name],raw).as_json()
    _json(owner,'pre-wire-cleanup.json',dict(schema_version=1,raw_refs=refs,eofs=eofs,errors=errors,
        reaped=owner.qemu_owner.reaped,ownership_lost=owner.qemu_owner.ownership_lost,
        returncode=owner.qemu_owner.returncode))


def _retain_partial_helpers(owner):
    for epoch,observation in owner._observations.items():
        for role,helper in observation.helpers.items():
            if helper.child is None:continue
            prefix=f'epochs/{epoch}/host/'
            stem='fields' if role=='fields' else 'metadata-'+role.removeprefix('metadata_')
            for suffix,data in ((('-output.bin' if role=='fields' else '.bin'),helper.output),('-stderr.bin',helper.stderr)):
                name=prefix+stem+suffix
                owner.accounting.reserve_output(len(data));raw=bytes(data)
                if name in owner.inventory._slots:
                    ref,held=_held_blob(owner,name);deny(held==raw,'call_runtime_helper_changed')
                else:_put(owner,name,raw)


def _retain_final_streams(owner):
    refs={};raw={}
    _retain_partial_helpers(owner)
    for stream in RAW_FILES:
        refs[stream],raw[stream]=_raw_copy(owner,stream,'raw/'+RAW_FILES[stream])
    _retain_operation_copies(owner)
    for archive in owner._epochs.values():
        if any(row.blob.path not in owner.inventory._slots for row in archive.registered.retainer.inventory()):
            _adopt_retainer(owner,archive.registered.retainer)
        receipts=tuple(archive.registered.retainer._receipts.values())
        archive.registered.retainer.resolve_positions(receipts,tuple((n,refs[n]) for n in ('rsp','rsp-out')),
            tuple((n,raw[n]) for n in ('rsp','rsp-out')))
    return refs,raw


def _lifecycle_record(owner):
    owner.accounting.reserve_output(65536)
    children=[];rows=[]
    for role,child in owner._children.items():
        if child.child is None:continue
        children.append(dict(role=role,pid=child.child.pid,reaped=child.reaped,
            ownership_lost=child.ownership_lost,returncode=child.returncode,
            wait_summary=dict(child.wait_summary)))
        rows.extend(dict(row) for row in child.lifecycle)
    rows.sort(key=lambda row:(row['started_ns'],row['finished_ns'],row['role'],row['operation']))
    for index,row in enumerate(rows):row['seq']=index+1
    return _json(owner,'lifecycle.json',dict(schema_version=1,kind='run0_call_parent_lifecycle_v1',
        children=children,operations=rows,started_ns=owner.deadlines.started_ns,
        work_deadline_ns=owner.deadlines.effective_work_ns,hard_deadline_ns=owner.deadlines.effective_hard_ns,
        first_transition_committed=owner.deadlines._ticket is not None))[0]


def _source_postcheck(owner):
    prepared=owner.prepared;plan=_thaw_plan(owner)
    _validate_call_runtime_inputs(prepared,plan,owner.accounting,owner.deadlines.effective_hard_ns,
        verification=owner._verification)
    from run0_call_verify import recheck_runtime
    actual=recheck_runtime(prepared,owner.accounting,verification=owner._verification,
        expected_identity=plan['launch_identity'],deadline_ns=int(owner.qemu_owner.deadline*SECOND),receipts=None)
    deny(actual==owner._launch_identity,'call_runtime_launch_identity_changed')
    return _json(owner,'source-postcheck.json',dict(schema_version=1,
        observer_sha256=hashlib.sha256(prepared.observer_source_bytes).hexdigest(),
        prior_inputs_sha256=plan['prior_inputs_sha256'],source_unchanged=True,inputs_unchanged=True,
        launch_identity=actual,checked_ns=time.monotonic_ns()))[0]


_FALSE_CLAIMS={key:False for key in ('guest_access_executed','post_exit_verified','interrupt_masking_verified',
    'retention_complete','allocator_installed','target_user_execution','physical_hardware','atomic_snapshot',
    'device_quiescence_verified','full_parent_oracle_complete','complete_c2_graph_verified',
    'initial_guest_reader_preconditions_verified','old_c0_report_reinterpreted_as_parent')}


def _base_report(owner):
    refs=lambda name:(_held_blob(owner,name)[0].as_json() if name in owner.inventory._slots else None)
    owner.accounting.redeem_terminal(8192,purpose='report')
    return dict(schema_version=1,kind='run0_same_call_map_report_v1',run_id=Path(owner.prepared.run).name,
        profile_ref=refs('profile.json'),input_closure_ref=refs('input-closure.json'),
        caller_manifest_ref=_input_ref(owner.prepared.caller_manifest_ref),
        source_persistence_ref=_input_ref(owner.prepared.source_persistence_ref),observer_ref=refs('observer.json'),
        operations=None,raw_inventory_ref=None,epochs=[],selected_call=None,lifecycle_ref=None,
        transitions=[],termination=None,capture_status='partial',acceptance_status='INCOMPLETE',
        named_object_translation_facts=None,claims=dict(_FALSE_CLAIMS))

def _transition_projection(owner):
    """Actual reached transitions; immutable precommit journal is never rewritten."""
    wire=owner._wire;transition=owner.transition_owner;tickets=transition._tickets
    deny(type(tickets) is list and len(tickets)<=2,'call_runtime_transition_count')
    owner.accounting.reserve_output(16384)
    by_epoch={}
    for ticket in tickets:
        deny(type(ticket) is ownership.TransitionAdmission and ticket._owner is transition
            and ticket._wire is wire and ticket._policy is owner.deadlines
            and ticket.source_epoch in ('C0','C1') and ticket.source_epoch not in by_epoch,
            'call_runtime_transition_ticket_origin')
        by_epoch[ticket.source_epoch]=ticket
    rows=[]
    for epoch,next_epoch in (('C0','C1'),('C1','C2')):
        name=f'transitions/{epoch}-{next_epoch}.json';ticket=by_epoch.get(epoch)
        target=owner._fact_receipts.get(('target',epoch))
        active=wire._transition_target is target and target is not None and wire._transition_started_ns is not None
        if name not in owner.inventory._slots and ticket is None and not active:continue
        deny(type(target) is capture.BoundCallTarget and target._owner is owner
            and target.registration is owner._registration and target.source_epoch==epoch
            and target.target_epoch==next_epoch,'call_runtime_transition_target_history')
        archive=_archive_for(owner,epoch);closure=archive.refs['closure_ref']
        deny(target.source_closure_ref is closure,'call_runtime_transition_closure_history')
        owner.inventory.require_exact(closure,_held_blob(owner,closure.path)[1])
        journal=None;record=None
        if name in owner.inventory._slots and owner.inventory._slots[name].state=='complete':
            journal,data=_held_blob(owner,name);owner.accounting.reserve_output(8*len(data)+2048)
            record=witness.strict_json(data,8192)
            deny(set(record)=={'schema_version','source_epoch','target_epoch','source_closure_ref','target',
                'clear_operation_seq','set_operation_seq','quiet_received_ns','admission_started_ns'}
                and pure._same_json(record['schema_version'],1) and record['source_epoch']==epoch
                and record['target_epoch']==next_epoch and pure._same_json(record['source_closure_ref'],closure.as_json())
                and pure._same_json(record['target'],target.address),'call_runtime_transition_journal_history')
        clear=(record['clear_operation_seq'] if record is not None else
            (wire._transition_clear.seq if active and wire._transition_clear is not None else None))
        setseq=(record['set_operation_seq'] if record is not None else
            (wire._transition_set.seq if active and wire._transition_set is not None else None))
        started=record['admission_started_ns'] if record is not None else wire._transition_started_ns
        for seq,operation in ((clear,'hardware_breakpoint_clear'),(setseq,'hardware_breakpoint_set')):
            if seq is None:continue
            deny(type(seq) is int and 0<seq<=len(wire._operations),'call_runtime_transition_row_sequence')
            row=wire._operations[seq-1]
            deny(row.operation==operation and row.charged_epoch==epoch and row.result=='ok',
                'call_runtime_transition_row_history')
        deny(type(started) is int and type(archive.registered.binding.stop_ns) is int
            and owner.deadlines.started_ns<=archive.registered.binding.stop_ns<=started,
            'call_runtime_transition_clock_history')
        if ticket is not None:
            deny(journal is not None and ticket.journal_ref==(journal.path,journal.sha256,journal.length)
                and ticket.target_epoch==next_epoch and type(ticket._committed) is bool
                and type(ticket._consumed) is bool and (not ticket._consumed or ticket._committed)
                and all(type(x) is int for x in (ticket.admitted_ns,ticket.response_deadline_ns,ticket.next_stop_deadline_ns))
                and started<=ticket.admitted_ns and ticket.response_deadline_ns<=started+5*SECOND
                and ticket.next_stop_deadline_ns<=started+60*SECOND,'call_runtime_transition_ticket_history')
        rows.append(dict(source_epoch=epoch,target_epoch=next_epoch,
            journal_ref=None if journal is None else journal.as_json(),source_closure_ref=closure.as_json(),
            clear_operation_seq=clear,set_operation_seq=setseq,source_stop_received_ns=archive.registered.binding.stop_ns,
            admission_started_ns=started,admitted_ns=None if ticket is None else ticket.admitted_ns,
            response_deadline_ns=None if ticket is None else ticket.response_deadline_ns,
            next_stop_deadline_ns=None if ticket is None else ticket.next_stop_deadline_ns,
            committed=None if ticket is None else ticket._committed,consumed=None if ticket is None else ticket._consumed))
    return rows


def _validate_transition_projection(owner,rows,*,complete):
    expected=_transition_projection(owner)
    deny(pure._same_json(rows,expected),'call_runtime_transition_projection')
    if not complete:return
    deny(len(rows)==2 and len(owner.transition_owner._tickets)==2
        and all(row['committed'] is True and row['consumed'] is True for row in rows),
        'call_runtime_transition_complete')
    for row in rows:
        flights=[f for f in owner._wire._flights if f.target_epoch==row['target_epoch']]
        deny(len(flights)==1,'call_runtime_transition_flight_count');flight=flights[0]
        journal=row['journal_ref']
        deny(flight.source_epoch==row['source_epoch'] and flight.source_closure_ref.as_json()==row['source_closure_ref']
            and flight.admission_ref==(journal['path'],journal['sha256'],journal['length'])
            and flight.clear_operation_seq==row['clear_operation_seq']
            and flight.set_operation_seq==row['set_operation_seq']
            and flight.response_deadline_ns==row['response_deadline_ns']
            and flight.stop_deadline_ns==row['next_stop_deadline_ns'] and flight.result=='ok',
            'call_runtime_transition_flight_projection')


def _control_history(owner,refs,raw):
    wire=owner._wire
    owner.accounting.reserve_output(8192+2048*(len(wire._operations)+len(wire._events))
        +512*(len(wire._rsp_frame_rows)+len(wire._qmp_frame_rows)+len(wire._rsp_segment_rows)))
    operations=[_operation_json(owner,row,refs) for row in wire._operations]
    flights=[]
    for flight in wire._flights:
        data={name:getattr(flight,name) for name in wiremod.FlightRecord.__dataclass_fields__}
        data['source_closure_ref']=None if flight.source_closure_ref is None else flight.source_closure_ref.as_json()
        data['c_sent_slice']=_slice(owner,flight.c_sent_slice,refs)
        data['request_ack_slice']=_slice(owner,flight.request_ack_slice,refs)
        flights.append(data)
    # These are actual recognition/send envelopes, including partial-run
    # unmatched frames. Only a real operation join can create a closed ACK row.
    qmp=[dict(wire=_slice(owner,p,refs),received_ns=at,receive_ordinal=n) for p,at,n in wire._qmp_frame_rows]
    rspframes=[dict(kind=kind,wire=_slice(owner,p,refs),received_ns=at,receive_ordinal=n)
        for kind,p,at,n in wire._rsp_frame_rows]
    segments=[dict(wire=_slice(owner,p,refs),sent_ns=at) for p,at in wire._rsp_segment_rows]
    inbound={};outbound={}
    for row in wire._operations:
        if row.protocol!='rsp':continue
        if row.operation=='stop_ack':
            if row.request is not None:outbound[row.request.offset]=(row.seq,'stop_ack')
        elif row.response is not None:
            if row.operation=='continue':inbound[row.response.offset]=row.seq
            else:
                inbound[row.response.offset-1]=row.seq
                if row.request is not None:outbound[row.request.offset+row.request.length]=(row.seq,'response_ack')
    acks=[]
    for kind,pos,stamp,ordinal in wire._rsp_frame_rows:
        if kind not in ('ACK','NACK') or pos.offset not in inbound:continue
        acks.append(dict(protocol='rsp',direction='in',wire=_slice(owner,pos,refs),kind=kind,
            operation_seq=inbound[pos.offset],purpose='request_ack',observed_ns=stamp,receive_ordinal=ordinal))
    for pos,stamp in wire._rsp_segment_rows:
        if pos.length==1 and pos.offset in outbound and raw['rsp-out'][pos.offset:pos.offset+1] in (b'+',b'-'):
            seq,purpose=outbound[pos.offset]
            acks.append(dict(protocol='rsp',direction='out',wire=_slice(owner,pos,refs),
                kind='ACK' if raw['rsp-out'][pos.offset:pos.offset+1]==b'+' else 'NACK',
                operation_seq=seq,purpose=purpose,observed_ns=stamp,receive_ordinal=None))
    acks.sort(key=lambda r:(r['observed_ns'],r['direction'],r['wire']['offset']))
    physical=[]
    for archive in owner._epochs.values():
        retainer=archive.registered.retainer
        for receipt in retainer._receipts.values():
            row=retainer.export_row(receipt)
            owner.accounting.reserve_output(3*len(row.canonical_bytes)+4096)
            physical.append({key:value.as_json() if type(value) in (read.BlobRef,read.RawSlice,read.LiveWirePosition)
                else value for key,value in row.fields})
    return dict(schema_version=1,kind='run0_same_call_map_control_v1',scope='shared_same_call_c0_c1_c2',
        operations=operations,events=[_event_json(owner,row,refs) for row in wire._events],
        flights=flights,acks=acks,qmp_frames=qmp,rsp_frames=rspframes,rsp_segments=segments,physical_reads=physical)


def _uncompleted_attempts(owner):
    completed={seq for archive in owner._epochs.values() for seq in
        (r.operation_seq for r in archive.registered.retainer._receipts.values())}
    rows=[]
    for seq,attempt in owner.read_attempts.items():
        if seq in completed:continue
        deny(type(attempt) is read._HeldReadAttempt,'call_runtime_partial_attempt_type')
        t=attempt.target;k=attempt.key
        rows.append(dict(epoch=k.epoch,request_id=k.request_id,physical_ordinal=k.physical_ordinal,
            operation_seq=seq,target_kind=t.kind,pass_index=t.pass_index,target_ordinal=t.target_ordinal,
            logical_offset=t.logical_offset,physical=t.gpa,length=t.length,
            started_ns=attempt.started_ns,finished_ns=attempt.finished_ns,protocol_result=attempt.result,
            retained_success_receipt=False))
    return rows

def _validate_path_closure(owner):
    root=owner.inventory.run;stack=[root];files=set();directories=0;entries=0
    sockets={'qmp.sock','gdb.sock','serial.sock','debug.sock'}
    while stack:
        directory=stack.pop();directories+=1
        deny(directories<=64,'call_runtime_directory_limit')
        with os.scandir(directory) as iterator:
            while True:
                # Directory-entry name/metadata credit precedes iteration growth.
                owner.accounting.reserve_output(1024)
                try:entry=next(iterator)
                except StopIteration:break
                entries+=1;deny(entries<=3025,'call_runtime_path_count')
                path=Path(entry.path);name=path.relative_to(root).as_posix()
                info=entry.stat(follow_symlinks=False)
                deny(info.st_uid==os.getuid() and info.st_mode&0o077==0,'call_runtime_path_owner')
                if stat.S_ISDIR(info.st_mode):stack.append(path)
                elif stat.S_ISREG(info.st_mode):
                    deny(info.st_nlink==1 and name in owner.inventory._slots,'call_runtime_unindexed_file')
                    files.add(name)
                elif stat.S_ISSOCK(info.st_mode):deny(name in sockets,'call_runtime_unknown_socket')
                else:raise base.ProbeError('DENY','call_runtime_unknown_path_type')
    deny(files==set(owner.inventory._slots) and not owner.inventory._unindexed,
        'call_runtime_output_path_closure')


def _finish_report(owner,failures):
    report=_base_report(owner);wire=owner._wire;refs={};raw={}
    try:
        if wire is not None:refs,raw=_retain_final_streams(owner)
        lifecycle=_lifecycle_record(owner);report['lifecycle_ref']=lifecycle.as_json()
        source=_source_postcheck(owner)
        final_vars=getattr(type(owner.inventory),'seal_final_vars',None)
        incomplete(callable(final_vars),'call_runtime_final_vars_pending')
        vars_ref,_=final_vars(owner.inventory,owner)
        if wire is not None:
            control_value=_control_history(owner,refs,raw)
            control,_=_json(owner,'control.json',control_value)
            # Same exact ordered native array, separately prepaid at both JSON
            # serialization sites. Parent operations is never a reference alias.
            report['operations']=control_value['operations']
            report['transitions']=_transition_projection(owner)
            streams,_=_json(owner,'streams.json',dict(schema_version=1,raw_refs=[r.as_json() for r in refs.values()],
                eofs=[dict(stream=r.stream,observed_ns=r.observed_ns) for r in wire._eofs],
                errors=[dict(stream=r.stream,operation=r.operation,errno=r.errno,observed_ns=r.observed_ns) for r in wire._io_errors]))
            report['termination']=dict(reaped=owner.qemu_owner.reaped,returncode=owner.qemu_owner.returncode,
                ownership_lost=owner.qemu_owner.ownership_lost,streams_ref=streams.as_json(),
                source_postcheck_ref=source.as_json(),final_vars_ref=vars_ref.as_json(),first_failure=None if not failures else failures[0])
        report['epochs']=[_held_blob(owner,f'epochs/{ep}/epoch.json')[0].as_json() for ep in EPOCHS
            if f'epochs/{ep}/epoch.json' in owner.inventory._slots]
        if 'selected-call.json' in owner.inventory._slots:report['selected_call']=_held_blob(owner,'selected-call.json')[0].as_json()
        if 'map-facts.json' in owner.inventory._slots:report['named_object_translation_facts']=_held_blob(owner,'map-facts.json')[0].as_json()
        if not failures:
            _validate_complete_history(owner,raw)
            _validate_transition_projection(owner,report['transitions'],complete=True)
            owner.inventory.audit()
            _validate_path_closure(owner)
            incomplete(time.monotonic_ns()<owner.deadlines.effective_hard_ns,'call_runtime_final_deadline')
            report['capture_status']='complete';report['acceptance_status']='same_call_map_subset_PASS'
    except BaseException as error:
        _record_failure(owner,error,failures)
    if failures:
        report['capture_status']='partial';report['acceptance_status']=failures[0]['status']
        _json(owner,'failure-details.json',dict(schema_version=1,first_failure=failures[0],
            secondary_failures=failures[1:],reaped=owner.qemu_owner.reaped,
            ownership_lost=owner.qemu_owner.ownership_lost,returncode=owner.qemu_owner.returncode,
            actual_admitted_operations=sorted(owner.read_attempts),
            uncompleted_read_attempts=_uncompleted_attempts(owner)))
    rows=owner.inventory.rows()
    terminal_name='report.json' if not failures else 'partial-report.json'
    inventory,_=_json(owner,'raw-inventory.json',dict(schema_version=1,records=list(rows),
        excluded_paths=['raw-inventory.json',terminal_name]))
    report['raw_inventory_ref']=inventory.as_json()
    ref,_=_json(owner,'report.json' if not failures else 'partial-report.json',report)
    if not failures:
        # A failure after final sealing cannot rewrite history or return success.
        _validate_path_closure(owner)
        incomplete(time.monotonic_ns()<owner.deadlines.effective_hard_ns,'call_runtime_final_deadline')
    return report,ref

def _run_call_capture(prepared,run):
    # The parent clock and one ledger precede bounded plan parsing. No output,
    # process, field read or graph exists before the default-closed public guard.
    deny(type(prepared) is capture.PreparedCallInputs and type(prepared.plan_bytes) is bytes
        and 0<len(prepared.plan_bytes)<=witness.REPORT_LIMIT,'call_runtime_prepared_plan')
    started=time.monotonic_ns();policy=ownership.ParentDeadlines(started)
    ledger=budget.ParentAccounting(started)
    ledger.reserve_output(16*len(prepared.plan_bytes)+4096)
    plan=prepared.plan
    capture.require_call_runtime_registration(prepared,plan)
    verification=_validate_call_runtime_inputs(prepared,plan,ledger,policy.effective_work_ns)
    _prepared(prepared,run,plan)
    held_plan=_freeze_plan(plan,ledger)
    deny(threading.current_thread() is threading.main_thread() and threading.active_count()==1,
        'main_thread_owner_required')
    native=witness.NativeQueries(dict(prepared.native_layout))
    base.create_run(run)
    inventory=capture.RootRawInventory(run,ledger)
    owner=_new_inert_runtime(prepared,policy,ledger,inventory,native)
    owner._plan=held_plan
    owner._verification=verification
    streams={};failures=[]
    try:
        for name,raw in (('profile.json',prepared.profile_bytes),('plan.json',prepared.plan_bytes),
                         ('observer.json',prepared.observer_source_bytes)):_put(owner,name,raw)
        _json(owner,'argv.json',plan['argv'])
        ledger.reserve_output(512*len(prepared.prior_blobs))
        _json(owner,'input-closure.json',dict(schema_version=1,inputs=[witness.CaptureEvidence.ref(name,raw)
            for name,raw in prepared.prior_blobs],prior_inputs_sha256=plan['prior_inputs_sha256']))
        prior=dict(prepared.prior_blobs)
        _put(owner,'caller-manifest.json',prior[prepared.caller_manifest_ref[0]])
        _put(owner,'source-persistence.json',prior[prepared.source_persistence_ref[0]])
        vars_spec=prepared.profile['inputs']['initial_vars']
        # Mutable VM backing is separate from immutable evidence until actual
        # writer reap. It receives a final measured immutable identity only then.
        ledger.reserve_output(2*vars_spec['length']+1024)
        initial=witness.read_exact(Path(prepared.inputs)/'initial_vars',vars_spec['sha256'],vars_spec['length'])
        # Use the unbuffered exclusive writer without publishing an immutable
        # slot: QEMU still owns this mutable backing until its actual reap.
        inventory._write_file('vars.fd',initial)
        from run0_call_verify import recheck_runtime
        receipts={}
        owner._launch_identity=recheck_runtime(prepared,ledger,verification=owner._verification,
            expected_identity=plan['launch_identity'],deadline_ns=int(owner.qemu_owner.io_deadline*SECOND),receipts=receipts)
        _json(owner,'source-closure.json',receipts)
        _json(owner,'runtime-observer.json',dict(schema_version=1,kind='run0_same_call_map_runtime_observer_v1',
            observer_ref=_held_blob(owner,'observer.json')[0].as_json(),launch_identity=owner._launch_identity,
            started_ns=started))
        capture.require_call_runtime_registration(prepared,_held_plan(owner))
        ledger.reserve_output(3*152);owner.before_spawn=native.sigchld();owner.before_spawn_ns=time.monotonic_ns()
        witness.decode_sigchld(owner.before_spawn)
        with witness.defer_cleanup_interrupt() as interrupted:
            at=time.monotonic_ns()
            owner.qemu_owner.child=subprocess.Popen(plan['argv'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,start_new_session=True,close_fds=True,umask=0o077,
                env=witness.clean_launch_env(run),bufsize=0)
            owner.qemu_owner._receipt('spawn',at,'ok')
        streams['qemu_stdout']=owner.qemu_owner.child.stdout;streams['qemu_stderr']=owner.qemu_owner.child.stderr
        if interrupted[0]:raise KeyboardInterrupt
        for role,path in (('qmp-in','qmp.sock'),('rsp','gdb.sock'),('serial','serial.sock'),('debug','debug.sock')):
            streams[role]=witness.connect_owned(run/path,min(time.monotonic()+5,policy.effective_work_ns/SECOND))
        for source in streams.values():os.set_blocking(source.fileno(),False)
        _publish_owned_graph(owner,{name:streams[name] for name in VM_STREAMS})
        _capture_three_epochs(owner)
    except BaseException as error:
        _record_failure(owner,error,failures)
    finally:
        if owner._registration is not None:_cleanup(owner,streams,failures)
        else:
            try:_cleanup_pre_graph(owner,streams,failures)
            except BaseException as error:_record_failure(owner,error,failures)
    return _finish_report(owner,failures)
