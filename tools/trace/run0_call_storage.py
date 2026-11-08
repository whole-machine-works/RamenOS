"""Fixed native read-file adoption and post-reap VARS sealing.

These functions confer no process origin or RAM authority. The existing Root
archival registration must already authenticate the exact original graph. Copy
charges are permanent logical byte charges in the original parent ledger, not
RSS observations. Adoption never writes a payload or spends its read-file credit
again; verification uses the inventory's existing4KiB scratch buffer. Complete
held payloads are aliased. A complete file lacking a held payload is read only
with separately prepaid bounded native copies. Incomplete files stay incomplete.
"""
import hashlib
import os
from pathlib import Path
import stat
import subprocess

from boot_profile_capture import ProbeError, deny, incomplete
import run0_call_capture as root
import run0_call_read as read
from run0_call_budget import ParentAccounting
from run0_call_owner import ParentOwnedWait
from run0_call_session import CurrentEpochRamBinding, ParentAcquisitionSession

MAX_FILES = 2957


def _inventory(value):
    deny(type(value) is root.RootRawInventory
         and type(value.accounting) is ParentAccounting
         and type(value.run) is type(Path()) and value.run.is_absolute()
         and type(value._slots) is dict and type(value._unindexed) is dict
         and len(value._slots)+len(value._unindexed) <= MAX_FILES,
         'call_storage_inventory')


def _graph(inventory, runtime):
    _inventory(inventory)
    deny(type(runtime) is root._OwnedCallRuntime, 'call_storage_runtime')
    try:
        registration=runtime._registration
        deny(type(registration) is root.ClosedOwnedCallRegistration
             and registration._owner is runtime and runtime.inventory is inventory
             and registration.inventory is inventory
             and registration.accounting is runtime.accounting is inventory.accounting
             and type(runtime.prepared) is root.PreparedCallInputs
             and registration.prepared is runtime.prepared
             and runtime.prepared.run == str(inventory.run)
             and registration.wire is runtime._wire
             and registration.parent_identity is runtime.parent_identity
             and registration.read_attempts is runtime.read_attempts
             and registration.read_operations is runtime.read_operations,
             'call_storage_original_graph')
        incomplete(root._issued_call_registration(registration,runtime._wire),
                   'call_storage_producer_unregistered')
        return registration
    except AttributeError as error:
        raise ProbeError('INCOMPLETE','call_storage_producer_unregistered') from error


def _retainer(inventory, retainer):
    _inventory(inventory)
    deny(type(retainer) is read._ReadRetainer and retainer._origin is None,
         'call_storage_native_retainer')
    # Fixed native guard, including archived/revoked epochs; never _ready(),
    # which would incorrectly require live RAM authority after retirement.
    read._retainer_guard(retainer,'_require_retainer_archival')
    binding=retainer._binding
    deny(type(binding) is CurrentEpochRamBinding, 'call_storage_binding')
    runtime=binding._owner;registration=_graph(inventory,runtime)
    session=retainer._session;wire=runtime._wire
    deny(retainer._registration is binding.registration is registration
         and retainer._parent is binding.parent_identity is runtime.parent_identity
         and retainer._wire is binding.wire is wire
         and retainer._root == inventory.run
         and retainer._accounting is inventory.accounting
         and type(session) is ParentAcquisitionSession
         and session._owner is runtime and session._registration is registration
         and session.binding is binding and session.retainer is retainer
         and retainer._attempts is registration.read_attempts
         and retainer._operations is registration.read_operations
         and type(retainer._raw) is dict and tuple(retainer._raw)==('rsp','rsp-out')
         and type(wire._raw) is dict
         and all(retainer._raw[n] is wire._raw[n] and type(wire._raw[n]) is bytearray
                 for n in ('rsp','rsp-out'))
         and type(retainer._inventory) is dict and len(retainer._inventory)<=MAX_FILES
         and type(retainer._receipts) is dict and len(retainer._receipts)<=506
         and type(retainer._slots) is dict and type(retainer._prepared) is dict
         and type(session._blobs) is dict and len(session._blobs)<=MAX_FILES,
         'call_storage_retainer_alias')
    return binding,session


def _read_existing(inventory, name, length):
    """Two exact native buffers, already prepaid by the caller; no file write."""
    inventory._parents(name,create=False)
    fd=os.open(inventory.run/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    primary=None
    try:
        first=os.fstat(fd)
        deny(stat.S_ISREG(first.st_mode) and first.st_uid==os.getuid()
             and first.st_mode & 0o077==0 and first.st_nlink==1,
             'call_storage_private_file')
        incomplete(first.st_size==length,'call_storage_file_length')
        data=bytearray(length);view=memoryview(data);offset=0
        while offset<length:
            count=os.readv(fd,[view[offset:]])
            incomplete(count>0,'call_storage_short_read');offset+=count
        incomplete(os.readv(fd,[memoryview(inventory._scratch)[:1]])==0,
                   'call_storage_file_length')
        last=os.fstat(fd);actual=os.lstat(inventory.run/name)
        fields=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        deny(fields(first)==fields(last)==fields(actual), 'call_storage_file_changed')
        return bytes(data)
    except BaseException as error:
        primary=error
        raise
    finally:
        inventory._close_file(name,fd,primary)


def _held_data(retainer, session, row):
    for receipt in retainer._receipts.values():
        deny(type(receipt) is read.NativePhysicalReadReceipt,'call_storage_receipt_type')
        for ref_name,data_name in (('request_ref','request_bytes'),('response_ref','response_bytes'),
                                   ('decoded_data_ref','data')):
            if getattr(receipt,ref_name) is row.blob:
                retainer._receipt(receipt)
                return getattr(receipt,data_name)
    item=session._blobs.get(row.blob.path)
    if item is not None:
        deny(type(item) is tuple and len(item)==2 and item[0] is row.blob,
             'call_storage_held_assembly')
        return item[1]
    return None


def adopt_retainer(inventory:root.RootRawInventory, retainer:read._ReadRetainer)->tuple[dict,...]:
    """Adopt measured native files without rewriting or recharging their payload."""
    binding,session=_retainer(inventory,retainer)
    count=len(retainer._inventory)
    # New slot + exported6-field row + hashing/verification metadata. No payload
    # copy here. Existing rows still need bounded verification/export metadata.
    inventory.accounting.reserve_output(4096+2048*count)
    result=[]
    # Validate every native row and total capacity before any host file I/O.
    new_count=0
    for name,row in retainer._inventory.items():
        deny(type(name) is str and type(row) is read._InventoryRow
             and type(row.blob) is read.BlobRef and row.blob.path==name
             and row.epoch==binding.epoch and row.state in ('complete','incomplete_write'),
             'call_storage_native_row')
        family,epoch=root._output_role(name)
        deny(family in ('actual operation copies','decoded physical read data',
                        'frame assemblies','object assemblies')
             and row.family==family and (epoch is None or epoch==row.epoch),
             'call_storage_row_role')
        slot=retainer._slots.get(name)
        deny(type(slot) is tuple and len(slot)==2 and type(slot[0]) is read.ReadKey
             and slot[1]=='pending' and slot[0].epoch==row.epoch,
             'call_storage_retainer_slot')
        pending=retainer._prepared.get(slot[0].physical_ordinal)
        deny(type(pending) is read.PendingReadRetention and pending.owner is retainer
             and pending.key is slot[0], 'call_storage_retainer_pending')
        key=pending.key
        expected=(f'operations/{key.operation_seq:04d}-request.bin',
                  f'operations/{key.operation_seq:04d}-response.bin',
                  f'memory/read-{key.physical_ordinal:03d}.bin',
                  retainer._assembly_path(row.epoch,pending.target))
        deny(name in expected,'call_storage_native_path')
        if family=='object assemblies':
            # The partial write has no minimum or alignment, but cannot exceed
            # this exact path's fixed004 full-object bound.
            object_max={'C0':(64,24,240,3840,32,120,376,32),
                        'C1':(120,376,32,435,348,8,8,8),
                        'C2':(435,348,8,8,8,4,32768)}
            maximum=object_max[row.epoch][int(name.split('/')[3][:2])]
        else:
            maximum=4096 if family=='frame assemblies' else (
                65536 if family=='actual operation copies' else 2048)
        if row.state=='complete':root._output_size(name,row.blob.length)
        else:deny(type(row.blob.length) is int and 0<=row.blob.length<=maximum,'call_storage_partial_length')
        deny(name not in inventory._unindexed,'call_storage_unindexed_conflict')
        existing=inventory._slots.get(name)
        if existing is not None:
            deny(type(existing) is root._SealedOutput and existing.ref is row.blob
                 and (existing.family,existing.epoch,existing.state)==(family,row.epoch,row.state),
                 'call_storage_immutable_slot')
        else:
            new_count+=1
    incomplete(len(inventory._slots)+len(inventory._unindexed)+new_count<=MAX_FILES,
               'call_inventory_path_limit')
    for name,row in retainer._inventory.items():
        family=row.family
        existing=inventory._slots.get(name)
        actual=inventory._measure(name,row.blob.length,flush=False)
        deny(actual==row.blob,'call_storage_changed_file')
        data=None
        if row.state=='complete':
            data=_held_data(retainer,session,row)
            if data is None:
                inventory.accounting.reserve_output(2*row.blob.length+1024)
                data=_read_existing(inventory,name,row.blob.length)
            deny(type(data) is bytes and len(data)==row.blob.length
                 and hashlib.sha256(data).hexdigest()==row.blob.sha256,
                 'call_storage_held_bytes')
        if existing is None:inventory._record(row.blob,data,family,row.epoch,row.state)
        else:
            deny((existing.data is None and data is None) or
                 (type(existing.data) is bytes and existing.data==data),'call_storage_immutable_data')
        result.append(dict(path=name,sha256=row.blob.sha256,length=row.blob.length,
                           family=family,epoch=row.epoch,state=row.state))
    return tuple(result)


def seal_final_vars(inventory:root.RootRawInventory, runtime:root._OwnedCallRuntime)->tuple[read.BlobRef,bytes]:
    """Seal the actual fixed writable VARS file only after its writer is reaped."""
    registration=_graph(inventory,runtime)
    child=runtime.qemu_owner
    deny(type(child) is ParentOwnedWait and registration.qemu_owner is child
         and type(child.child) is subprocess.Popen and child.role=='qemu',
         'call_storage_qemu_owner')
    incomplete(child.reaped is True and child.ownership_lost is False
        and type(child.returncode) is int and child.child.returncode==child.returncode,
        'call_storage_qemu_not_reaped')
    deny(type(child.lifecycle) is list and len(child.lifecycle)<=50
         and any(type(r) is dict and r.get('role')=='qemu' and r.get('pid')==child.child.pid
                 and r.get('operation')=='wait' and r.get('result')=='ok'
                 and type(r.get('returncode')) is int and r['returncode']==child.returncode
                 for r in child.lifecycle),'call_storage_reap_receipt')
    name='vars.fd'
    deny(name not in inventory._slots and name not in inventory._unindexed,
         'call_storage_final_vars_reused')
    incomplete(len(inventory._slots)+len(inventory._unindexed)<MAX_FILES,'call_inventory_path_limit')
    raw=runtime.prepared.profile_bytes
    deny(type(raw) is bytes and 0<len(raw)<=65536,'call_storage_profile_bytes')
    inventory.accounting.reserve_output(8*len(raw)+4096)
    profile=runtime.prepared.profile
    length=profile['inputs']['initial_vars']['length']
    deny(type(length) is int and 0<length<=root.base.INPUT_LIMITS['initial_vars'],
         'call_storage_vars_template_length')
    # Existing file was prepaid when created. Two new native read/bytes buffers
    # plus fixed hash/ref/slot metadata are charged before either allocation.
    inventory.accounting.reserve_output(2*length+4096)
    data=_read_existing(inventory,name,length)
    ref=read.BlobRef(name,hashlib.sha256(data).hexdigest(),length)
    root._output_size(name,length)
    inventory._record(ref,data,'root fixed records',None,'complete')
    return ref,data
