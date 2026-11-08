"""One immutable-epoch suspended acquisition; only Root can publish live origin.

Copied facts, allocation rows and reservations do not grant RAM authority. The
fixed Root guards remain INCOMPLETE until its genuine producer exists. Synthetic
fixtures live only in the test module. Logical validation-copy charges below are
permanent common-ledger debits, not observed raw byte counts or Python RSS.
"""
from dataclasses import dataclass, fields, replace
import hashlib
import struct
import time

from boot_profile_capture import ProbeError, deny, incomplete
import run0_c0_decode as c0
import run0_c0_acquire as old
import run0_c0_entry as entry
import run0_call_decode as pure
import run0_call_budget as budget
import run0_call_read as read
from run0_c0_paging import PageWalk, NeedFrame, PageEntry, canonical_span
from run0_call_owner import ClosedEpochReceipt

SECOND=1_000_000_000
_ROOT_METHODS=frozenset(('_require_epoch_initialization','_require_session_archival',
    '_require_closed_projection','_publish_c0_facts','_publish_selected_call',
    '_require_wire_binding','_require_extent_record','_require_epoch_after'))


class _Closed:
    __slots__=()

    def __init__(self,*args,**kwargs):
        raise TypeError('only the exact held Root graph initializes this native value')


@dataclass(frozen=True,slots=True,init=False)
class CurrentEpochRamBinding(_Closed):
    _owner:object
    registration:object
    parent_identity:object
    wire:object
    epoch:str
    epoch_nonce:object
    stop:object
    mode:object
    before_registers:object
    host_receipt:object
    layout_receipt:object
    transport_identity:tuple
    state:tuple
    registers:tuple
    hmp_raw:bytes
    layout_raw:bytes
    ranges:tuple
    prefix_blobs:tuple
    source_fact:object
    stop_ns:int
    work_deadline_ns:int
    stop_deadline_ns:int


@dataclass(frozen=True,slots=True,init=False)
class EpochReadGrant(_Closed):
    session:object
    binding:CurrentEpochRamBinding
    epoch_nonce:object
    target:read.ReadTarget
    virtual:int|None
    level:int|None
    path:tuple
    ancestor_read_sequences:tuple
    reservation:budget.ReadBatchReservation
    item_ordinal:int
    deadline_ns:int


@dataclass(frozen=True,slots=True,init=False)
class PhaseReadsComplete(_Closed):
    session:object
    binding:CurrentEpochRamBinding
    epoch_nonce:object
    last_read_seq:int
    last_finished_ns:int
    frames:tuple
    objects:tuple
    receipts:tuple
    map_extent:pure.MapExtent|None


@dataclass(frozen=True,slots=True,init=False)
class ClosedEpochSnapshot(_Closed):
    session:object
    binding:CurrentEpochRamBinding
    reads_complete:PhaseReadsComplete
    after:object
    frames:tuple
    objects:tuple
    receipts:tuple
    map_extent:pure.MapExtent|None


@dataclass(frozen=True,slots=True,init=False)
class FreshC0FactsReceipt(_Closed):
    _owner:object
    registration:object
    session:object
    snapshot:ClosedEpochSnapshot
    closed:ClosedEpochReceipt
    facts:pure.C0CopiedFacts
    epoch_bytes:bytes


@dataclass(frozen=True,slots=True,init=False)
class SelectedCallReceipt(_Closed):
    _owner:object
    registration:object
    session:object
    snapshot:ClosedEpochSnapshot
    closed:ClosedEpochReceipt
    c0_receipt:FreshC0FactsReceipt
    facts:pure.SelectedCallFacts
    facts_ref:read.BlobRef
    facts_bytes:bytes


@dataclass(frozen=True,slots=True)
class ClosedC0CopiedInput:
    epoch:str
    epoch_ref:read.BlobRef
    stop_ref:read.BlobRef
    registers_ref:read.BlobRef
    before_registers:tuple
    after_registers:tuple
    state:tuple
    hmp_before_ref:read.BlobRef
    hmp_after_ref:read.BlobRef
    layout_before_ref:read.BlobRef
    layout_after_ref:read.BlobRef
    host_phase_ref:read.BlobRef
    frames:tuple
    blobs:tuple


@dataclass(frozen=True,slots=True,init=False)
class MapTranslationPlan(_Closed):
    epoch:str
    extent_ref:read.BlobRef
    binding_identity:CurrentEpochRamBinding
    map_object_ordinal:int
    map_parts:tuple
    frame_ordinals:tuple
    reserved_read_operations:int
    reserved_bytes:int
    discovery_frozen:bool


def _native(kind,**values):
    deny(set(values)==set(kind.__dataclass_fields__),'call_session_native_fields')
    result=object.__new__(kind)
    for name,value in values.items():object.__setattr__(result,name,value)
    return result


def _root_method(owner,name,*args):
    deny(name in _ROOT_METHODS,'call_session_root_method')
    try:
        import run0_call_capture as root
        incomplete(type(owner) is root._OwnedCallRuntime,'call_session_runtime_pending')
        method=getattr(root._OwnedCallRuntime,name,None)
        incomplete(method is not None,'call_session_runtime_pending')
    except (ImportError,AttributeError) as error:
        raise ProbeError('INCOMPLETE','call_session_runtime_pending') from error
    return method(owner,*args)


def _int(value,low=0,high=(1<<63)-1):
    deny(type(value) is int and low<=value<=high,'call_session_integer')
    return value


def _tuple(value,maximum,minimum=0):
    deny(type(value) is tuple and minimum<=len(value)<=maximum,'call_session_tuple')
    return value


def _blob_tuple(blobs):
    _tuple(blobs,2957,1);total=0
    for item in blobs:
        deny(type(item) is pure.CopiedBlob and type(item.data) is bytes
             and type(item.ref) is read.BlobRef,'call_session_copied_blob')
        total+=len(item.data)
        incomplete(total<=32<<20,'call_session_copied_bytes')
        deny(type(item.ref.path) is str and len(item.ref.path)<=256
             and type(item.ref.length) is int and item.ref.length==len(item.data),
             'call_session_copied_identity')
    return len(blobs)


def _json_copy_cost(raw):
    # Scan native bytes without allocating decoded input/tree first. Covers the
    # input string and all logical JSON scalar/container/key copies. The128
    # per delimiter/string start is conservative native metadata credit, notRSS.
    deny(type(raw) is bytes and len(raw)<=1<<20,'call_session_json_bound')
    starts=0;quoted=escaped=False
    for char in raw:
        if quoted:
            if escaped:escaped=False
            elif char==92:escaped=True
            elif char==34:quoted=False
        elif char==34:quoted=True;starts+=1
        elif char in (91,123,93,125,44,58):starts+=1
    return 4*len(raw)+128*starts


def _pe_copy_bound(data):
    # Read only fixed header scalars to bound the unchanged parser BEFORE it
    # creates section/relocation/sort metadata; this is no second PE validator.
    deny(type(data) is bytes and 64<=len(data)<=32<<20,'call_session_pe_bytes')
    at=struct.unpack_from('<I',data,60)[0]
    deny(at<=len(data)-136,'call_session_pe_header_bound')
    count=struct.unpack_from('<H',data,at+6)[0]
    optional=struct.unpack_from('<H',data,at+20)[0]
    deny(1<=count<=96 and 112<=optional<=240 and at+24+optional<=len(data),
         'call_session_pe_header_bound')
    dirs=struct.unpack_from('<I',data,at+24+108)[0]
    deny(dirs<=16 and 112+8*dirs<=optional,'call_session_pe_directory_bound')
    reloc=struct.unpack_from('<I',data,at+24+156)[0] if dirs>5 else 0
    deny(reloc<=1<<20,'call_session_pe_relocation_bound')
    return 65536+512*count+512*(reloc//2)


def _frame_shapes(frames,epoch):
    for i,row in enumerate(_tuple(frames,32,1)):
        deny(type(row) is pure.FrameEvidence,'call_session_frame_fact_type')
        _int(row.ordinal,0,31);_int(row.physical,0,(1<<64)-1);_int(row.level,1,4)
        deny(row.ordinal==i and row.physical%4096==0,'call_session_frame_fact_identity')
        for ref,which in ((row.first_ref,'first'),(row.recheck_ref,'recheck')):
            pure._ref(ref,f'epochs/{epoch}/frames/{i:02d}-{which}.bin')
            deny(ref.length==4096,'call_session_frame_fact_length')
        for seqs,cs in ((row.first_read_sequences,row.first_contributions),
                       (row.recheck_read_sequences,row.recheck_contributions)):
            _tuple(seqs,2,2);_tuple(cs,2,2)
            for seq,c in zip(seqs,cs):
                _int(seq,1,1024);pure._contribution_shape(c)


def _validation_bound(copied,objects,*,complete,scalar=False,project=False,final=False):
    """Logical copies outside A1 W+5J, derived before parsing/metadata growth.

    Every Context is charged separately. Payload bytes in the copied store are
    aliases;256/blob covers index/identity/digest metadata,4096/frame-or-part
    covers bounded native walk/projection rows. Raw JSON costs count actual
    lexical inventory; HMP/layout16L covers unchanged decoded/parser strings.
    Canonical walk equality has two projections/text/newline/encoded copies.
    """
    deny(type(copied.epoch) is str and copied.epoch in read.EPOCHS,'call_session_context_epoch')
    k=_blob_tuple(copied.blobs);_tuple(copied.frames,32,1);_tuple(objects,8)
    f=len(copied.frames);p=0
    for obj in objects:
        deny(type(obj) in (pure.ObjectFirstEvidence,pure.ObjectEvidence),'call_session_object')
        p+=len(_tuple(obj.parts,17,1))
    incomplete(p<=29,'call_session_parts')
    amount=256*k+128*(80 if complete else 51)+4096*(f+p+len(objects))
    prefix='epochs/'+copied.epoch+'/'
    for item in copied.blobs:
        name=item.ref.path
        if name==prefix+'before-registers.json' or complete and name==prefix+'after-registers.json':
            amount+=_json_copy_cost(item.data)
        if name in (prefix+'hmp-before.txt',prefix+'layout-before.txt') or complete and name in (
                prefix+'hmp-after.txt',prefix+'layout-after.txt'):
            amount+=16*len(item.data)
        if scalar and name=='selected-call.json':amount+=_json_copy_cost(item.data)+8192
        if complete and name==prefix+'epoch.json':amount+=_json_copy_cost(item.data)+4096*(f+p+len(objects))
        if project and name=='map-extent.json':amount+=_json_copy_cost(item.data)
    if project:amount+=8*4096*f
    if final:amount+=2048
    return amount


def _initialize_owned_epoch(binding,runtime,retainer):
    deny(type(binding) is CurrentEpochRamBinding and type(retainer) is read._ReadRetainer,
         'call_session_initial_types')
    _root_method(runtime,'_require_epoch_initialization',binding,retainer)
    result=object.__new__(ParentAcquisitionSession)
    result._initialize(binding,runtime,retainer)
    return result

class ParentAcquisitionSession(_Closed):
    """One epoch's actual bounded planner; immutable binding, one pending grant."""
    __slots__=('_owner','_registration','binding','accounting','retainer','_attempts','_operations',
        '_prepared','_source_fact','_state','_registers','_guard','_blobs','_failure','_pending',
        '_complete','_snapshot','_frames','_objects','_receipts','_levels','_ready','_started',
        '_retired','_map_extent','_extent_record','_map_capacity','_map_plan','_map_extent_pending',
        '_closed_projection','_last_seq','_last_finished','_c0_values','_pe','_driver',
        '_discovery_commitment')
    def _initialize(self,binding,runtime,retainer):
        import run0_call_capture as root
        deny(type(binding.registration) is root.ClosedOwnedCallRegistration
             and binding.registration._owner is runtime and binding._owner is runtime
             and binding.registration is runtime._registration
             and binding.parent_identity is binding.registration.parent_identity
             and binding.wire is binding.registration.wire,'call_session_initial_graph')
        deny(type(runtime.prepared) is root.PreparedCallInputs
             and type(binding.epoch) is str and binding.epoch in read.EPOCHS,
             'call_session_prepared')
        deny(type(binding.transport_identity) is tuple and len(binding.transport_identity)==3
             and binding.transport_identity[0]=='rsp','call_session_transport')
        _int(binding.transport_identity[1]);_int(binding.transport_identity[2])
        for stamp in (binding.stop_ns,binding.work_deadline_ns,binding.stop_deadline_ns):_int(stamp,1)
        deny(binding.stop_deadline_ns==binding.stop_ns+60*SECOND,'call_session_stop_deadline')
        for raw in (binding.hmp_raw,binding.layout_raw):
            deny(type(raw) is bytes and 0<len(raw)<=65536,'call_session_prefix_raw')
        deny(type(runtime.accounting) is budget.ParentAccounting
             and retainer._parent is binding.parent_identity and retainer._wire is binding.wire
             and retainer._binding is binding and retainer._accounting is runtime.accounting
             and retainer._attempts is runtime.read_attempts
             and retainer._operations is runtime.read_operations,'call_session_retainer_graph')
        self._owner=runtime;self._registration=binding.registration;self.binding=binding
        self.accounting=runtime.accounting;self.retainer=retainer
        self._attempts=runtime.read_attempts;self._operations=runtime.read_operations
        self._prepared=runtime.prepared;self._source_fact=binding.source_fact
        k=_blob_tuple(binding.prefix_blobs)
        # These are permanently charged logical validation copies, not raw/RSS.
        self._charge(256*k+128*51+16*(len(binding.hmp_raw)+len(binding.layout_raw))+65536)
        self._state=old._state(binding.state);self._registers,before_sequences=old._registers(binding.registers)
        from run0_call_wire import EpochStopReceipt,CurrentEpochMode,SelectedEpochRegisters,EpochLayoutReceipt
        deny(type(binding.stop) is EpochStopReceipt and type(binding.mode) is CurrentEpochMode
             and type(binding.before_registers) is SelectedEpochRegisters
             and type(binding.layout_receipt) is EpochLayoutReceipt,'call_session_prefix_native_types')
        old._registers(binding.before_registers.values)
        deny(type(binding.stop.epoch) is str and type(binding.before_registers.phase) is str
             and type(binding.layout_receipt.phase) is str,'call_session_prefix_native_scalar_types')
        deny(binding.stop.epoch==binding.epoch and binding.stop.stop_nonce is binding.epoch_nonce
             and binding.stop._registration is binding.registration and binding.stop._wire is binding.wire
             and binding.stop.received_ns==binding.stop_ns
             and binding.mode.stop is binding.stop and type(binding.mode.value) is int and binding.mode.value==1
             and binding.before_registers.stop is binding.stop and binding.before_registers.phase=='before'
             and binding.before_registers.values==binding.registers
             and binding.layout_receipt.stop is binding.stop and binding.layout_receipt.phase=='before',
             'call_session_prefix_native_join')
        _tuple(binding.ranges,1024,1)
        for pair in binding.ranges:
            _tuple(pair,2,2);_int(pair[0],0,(1<<64)-1);_int(pair[1],1,1<<64)
        c0._hmp(binding.hmp_raw,self._registers)
        deny(c0._layout(binding.layout_raw)==binding.ranges,'call_session_layout_identity')
        for name,n in (('cr0',27),('cr3',29),('cr4',30),('efer',32)):
            deny(self._state[name]==self._registers[n],'call_session_mode_registers')
        self._guard=c0._Walker(self._state,{},binding.ranges)
        self._blobs={}
        for item in binding.prefix_blobs:
            pure._ref(item.ref)
            deny(item.ref.path not in self._blobs and hashlib.sha256(item.data).hexdigest()==item.ref.sha256,
                 'call_session_prefix_identity')
            self._blobs[item.ref.path]=(item.ref,item.data)
        self._failure=self._pending=self._complete=self._snapshot=None
        self._frames={};self._objects=[];self._receipts=[];self._levels={}
        self._ready=None;self._started=False;self._retired=False
        self._map_extent=self._extent_record=self._map_capacity=self._map_plan=None
        self._map_extent_pending=False;self._closed_projection=None;self._discovery_commitment=None
        self._last_seq=self.accounting.view()['allocated_operations']
        deny(before_sequences[-1]<binding.layout_receipt.operation_seq==self._last_seq
             and type(binding.mode.operation_seq) is int
             and 0<binding.mode.operation_seq<before_sequences[0],
             'call_session_before_operation_order')
        self._last_finished=binding.stop_ns
        self._c0_values=None
        if binding.epoch=='C0':
            deny(binding.source_fact is None,'call_session_C0_source')
            entry.export_validated_prior_entry(self._prepared.prior)
            deny(type(self._prepared.pinned_efi) is bytes,'call_session_pinned_efi')
            self._charge(_pe_copy_bound(self._prepared.pinned_efi))
            self._pe=c0.entry.parse_pe(self._prepared.pinned_efi,32)
            c0.entry.loaded_extent(self._prepared.prior.loaded_base,self._pe.image_size)
            deny(c0.entry.expected_entry(self._pe,self._prepared.prior.loaded_base).hex()==
                 self._prepared.prior.expected_entry_hex,'call_session_prior_entry_bytes')
            deny(self._registers[16]==self._prepared.prior.entry_address==
                 self._prepared.prior.loaded_base+self._pe.entry_rva,'call_session_C0_entry')
        elif binding.epoch=='C1':
            deny(type(binding.source_fact) is FreshC0FactsReceipt
                 and binding.source_fact._owner is runtime
                 and binding.source_fact.registration is binding.registration,
                 'call_session_C1_source')
            deny(type(binding.source_fact.facts) is pure.C0CopiedFacts,'call_session_C0_facts')
            for field in fields(pure.C0CopiedFacts):
                value=getattr(binding.source_fact.facts,field.name)
                if field.name=='epoch_ref':pure._ref(value,'epochs/C0/epoch.json')
                else:_int(value,0,(1<<64)-1)
            pure._pinned(self._prepared.pinned_caller)
        else:
            deny(type(binding.source_fact) is SelectedCallReceipt
                 and binding.source_fact._owner is runtime
                 and binding.source_fact.registration is binding.registration,
                 'call_session_C2_source')
            pure._selected(binding.source_fact.facts)
            deny(type(binding.source_fact.c0_receipt) is FreshC0FactsReceipt
                 and binding.source_fact.c0_receipt._owner is runtime
                 and binding.source_fact.c0_receipt.registration is binding.registration,
                 'call_session_C2_C0_lineage')
        self._driver=self._drive()

    pending=property(lambda self:self._pending)
    failure=property(lambda self:self._failure)
    map_extent_pending=property(lambda self:self._map_extent_pending)

    def abort(self,first_failure):
        try:
            from run0_call_wire import Failure
        except ImportError:
            Failure=None
        deny(type(first_failure) in (ProbeError,c0.C0DecodeError,Failure),
             'call_session_failure_type')
        deny(type(first_failure.status) is str and first_failure.status in ('DENY','INCOMPLETE')
             and type(first_failure.reason) is str and 0<len(first_failure.reason)<=240,
             'call_session_failure_fields')
        if self._failure is None:self._failure=ProbeError(first_failure.status,first_failure.reason)
        self._retired=True
        # Retained rows/assemblies are immutable archive; never clear them.
        self._driver=None

    def _fail(self,error):
        failure=error if type(error) in (ProbeError,c0.C0DecodeError) else ProbeError(
            'INCOMPLETE','call_session_'+type(error).__name__)
        self.abort(failure)
        raise self._failure from error

    def _live(self):
        if self._failure is not None:raise self._failure
        deny(not self._retired,'call_session_retired')
        import run0_call_capture as root
        current=self._owner._current
        deny(type(current) is root.RegisteredCurrentEpochBinding and current.binding is self.binding
             and current.session is self and current.retainer is self.retainer,
             'call_session_current_identity')
        deny(self._attempts is self._owner.read_attempts is self.retainer._attempts
             and self._operations is self._owner.read_operations is self.retainer._operations,
             'call_session_map_alias')
        _root_method(self._owner,'_require_wire_binding',self.binding.wire,current,self)
        self._clock(time.monotonic_ns())

    def _clock(self,now):
        _int(now,1)
        deny(self.binding.stop_ns<=self._last_finished<=now<=time.monotonic_ns(),
             'call_session_clock')
        incomplete(now<min(self.binding.work_deadline_ns,self.binding.stop_deadline_ns),
                   'call_session_deadline')

    def _charge(self,amount):
        deny(type(amount) is int and amount>=0,'call_session_copy_charge')
        incomplete(amount<=budget.REGULAR_BYTES,'call_session_copy_limit')
        self.accounting.reserve_output(amount,purpose='output')

    def _archive(self):
        _root_method(self._owner,'_require_session_archival',self)
        deny(self._attempts is self.retainer._attempts
             and self._operations is self.retainer._operations,'call_session_archive_alias')

    def _put(self,ref,data):
        self._charge(256)
        pure._ref(ref)
        deny(type(data) is bytes and len(data)==ref.length
             and hashlib.sha256(data).hexdigest()==ref.sha256,'call_session_data_identity')
        if ref.path in self._blobs:
            deny(self._blobs[ref.path]==(ref,data),'call_session_blob_conflict')
        else:
            incomplete(len(self._blobs)<2957,'call_session_blob_count')
            self._blobs[ref.path]=(ref,data)

    def _advance(self,receipt=None):
        self._started=True
        try:
            result=self._driver.send(receipt)
        except StopIteration:
            deny(self._pending is None and not self._map_extent_pending
                 and self.accounting._reserved_reads==0
                 and self.accounting.view()['discovery_state']!='open',
                 'call_session_completion_obligations')
            frames=self._frame_facts(True);objects=self._object_facts(True)
            self._complete=_native(PhaseReadsComplete,session=self,binding=self.binding,
                epoch_nonce=self.binding.epoch_nonce,last_read_seq=self._last_seq,
                last_finished_ns=self._last_finished,frames=frames,objects=objects,
                receipts=tuple(self._receipts),map_extent=self._map_extent)
            self._ready=None
            return
        if result is _MAP_BARRIER:
            self._map_extent_pending=True;self._ready=None
        else:self._ready=result

    def next_request(self):
        try:
            self._live();deny(self._pending is None,'call_session_pending')
            if self._complete is not None:return self._complete
            if not self._started:self._advance()
            if self._complete is not None:return self._complete
            incomplete(not self._map_extent_pending,'call_session_extent_required')
            batch,index,virtual,level,path,ancestors=self._ready
            target=batch.charges[index].target
            self._pending=_native(EpochReadGrant,session=self,binding=self.binding,
                epoch_nonce=self.binding.epoch_nonce,target=target,virtual=virtual,level=level,
                path=path,ancestor_read_sequences=ancestors,reservation=batch,item_ordinal=index,
                deadline_ns=min(self.binding.work_deadline_ns,self.binding.stop_deadline_ns))
            self._ready=None
            return self._pending
        except BaseException as error:self._fail(error)

    def _validate_prepare(self,grant,*,now_ns):
        self._live();self._clock(now_ns)
        deny(type(grant) is EpochReadGrant and grant is self._pending
             and grant.session is self and grant.binding is self.binding
             and grant.epoch_nonce is self.binding.epoch_nonce,
             'call_session_grant_identity')
        deny(grant.reservation.owner is self.accounting
             and grant.reservation.epoch==self.binding.epoch
             and grant.target is grant.reservation.charges[grant.item_ordinal].target,
             'call_session_grant_plan')
        self._guard._ram(grant.target.gpa,grant.target.length)
        return grant.reservation,grant.item_ordinal,grant.target

    def _pending_join(self,grant,pending):
        deny(type(pending) is read.PendingReadRetention and pending.owner is self.retainer
             and pending is self.retainer._prepared.get(pending.key.physical_ordinal)
             and pending.reservation is grant.reservation
             and pending.item_ordinal==grant.item_ordinal and pending.target is grant.target
             and pending.key.epoch==self.binding.epoch,'call_session_pending_identity')

    def _validate_dispatch(self,grant,pending,*,now_ns):
        self._validate_prepare(grant,now_ns=now_ns);self._pending_join(grant,pending)
        deny(pending.key.operation_seq not in self._attempts,'call_session_already_admitted')
        # No consumed flag: the caller's single shared-table publication commits.

    def _recheck_admitted(self,grant,pending,attempt,*,now_ns):
        self._validate_prepare(grant,now_ns=now_ns);self._pending_join(grant,pending)
        deny(type(attempt) is read._HeldReadAttempt
             and self._attempts.get(pending.key.operation_seq) is attempt
             and attempt._parent is self.binding.parent_identity
             and attempt._wire is self.binding.wire and attempt.key==pending.key
             and attempt.target is pending.target,'call_session_attempt_identity')
        _int(attempt.started_ns,1)
        incomplete(now_ns<min(grant.deadline_ns,attempt.started_ns+5*SECOND),
                   'call_session_read_deadline')

    def accept(self,receipt):
        try:
            self._live();grant=self._pending
            deny(type(grant) is EpochReadGrant and type(receipt) is read.NativePhysicalReadReceipt,
                 'call_session_receipt_type')
            self.retainer._receipt(receipt)
            pending=self.retainer._retained_pending.get(receipt.physical_ordinal)
            self._pending_join(grant,pending)
            attempt=self._attempts.get(receipt.operation_seq)
            self._recheck_admitted(grant,pending,attempt,now_ns=time.monotonic_ns())
            t=grant.target
            deny(receipt.parent is self.binding.parent_identity and receipt.session is self
                 and receipt.binding is self.binding and receipt.epoch==self.binding.epoch
                 and receipt.transport_identity==self.binding.transport_identity
                 and (receipt.request_id,receipt.physical_ordinal,receipt.operation_seq)==
                     (pending.key.request_id,pending.key.physical_ordinal,pending.key.operation_seq)
                 and (receipt.target_kind,receipt.pass_index,receipt.target_ordinal,
                      receipt.logical_offset,receipt.physical,receipt.length)==
                     (t.kind,t.pass_index,t.target_ordinal,t.logical_offset,t.gpa,t.length)
                 and receipt.result=='ok' and receipt.operation_seq>self._last_seq,
                 'call_session_receipt_identity')
            incomplete(self._last_finished<=receipt.started_ns<=receipt.finished_ns
                       <min(grant.deadline_ns,receipt.started_ns+5*SECOND),
                       'call_session_receipt_time')
            deny(type(receipt.data) is bytes and len(receipt.data)==t.length,
                 'call_session_receipt_bytes')
            self._put(receipt.decoded_data_ref,receipt.data)
            self._last_seq=receipt.operation_seq;self._last_finished=receipt.finished_ns
            self._receipts.append(receipt);self._pending=None
            self._advance(receipt)
        except BaseException as error:self._fail(error)

    def _batch(self,targets):
        self._charge(512*len(targets))
        requests=tuple(budget.ReadCharge.for_target(t) for t in targets)
        batch=self.accounting.reserve_reads(self.binding.epoch,requests)
        credit=getattr(budget.ParentAccounting,'reserve_wire_batch',None)
        incomplete(credit is not None,'call_session_wire_batch_credit_pending')
        credit(self.accounting,batch)
        return batch

    def _assemble(self,receipts,length):
        result=self.retainer.assemble(tuple(receipts),target_length=length)
        self._put(result.blob,result.data)
        return result

    def _frame(self,need,ancestors):
        address,level=need.physical,need.level
        self._guard._ram(address,4096)  # before cache lookup, even on reuse
        deny(address not in self._levels or self._levels[address]==level,
             'call_session_frame_level')
        if address in self._frames:
            deny(self._frames[address]['first'] is not None,'call_session_frame_cycle')
            return self._frames[address]['first'].data
        incomplete(len(self._frames)<32,'call_session_frame_cap')
        self._charge(4096)
        ordinal=len(self._frames)
        if self._map_capacity is not None:
            batch=self.accounting.materialize_c2_frame(self._map_capacity,ordinal=ordinal,physical=address)
        else:
            batch=self._batch(tuple(read.ReadTarget('frame',p,ordinal,off,address+off,2048)
                                   for p in (0,1) for off in (0,2048)))
        row=dict(ordinal=ordinal,physical=address,level=level,batch=batch,first=None,recheck=None,
                 first_reads=(),recheck_reads=(),ancestors=ancestors)
        self._frames[address]=row;self._levels[address]=level
        chunks=[]
        for i in (0,1):
            chunks.append((yield (batch,i,None,level,(),ancestors)))
        deny(chunks[1].operation_seq==chunks[0].operation_seq+1,'call_session_frame_sequence')
        row['first_reads']=tuple(chunks);row['first']=self._assemble(chunks,4096)
        return row['first'].data

    def _object(self,role,virtual,length,executable=False):
        canonical_span(virtual,length);_int(length,1,32768)
        ordinal=len(self._objects)
        incomplete(ordinal<(8,8,7)[read.EPOCHS.index(self.binding.epoch)],'call_session_object_cap')
        cursor=virtual;remaining=length;parts=[]
        prior=sum(len(o['parts']) for o in self._objects)
        limit=29 if self.binding.epoch=='C2' else 16
        while remaining:
            incomplete(prior+len(parts)<limit and len(parts)<(17 if self.binding.epoch=='C2' and ordinal==6 else 16),
                       'call_session_part_cap')
            walk=PageWalk(cursor,self._guard.root,self._state['phys_bits'],bool(self._state['efer']&(1<<11)))
            step=walk.next_frame;ancestors=()
            while type(step) is NeedFrame:
                data=yield from self._frame(step,ancestors)
                ancestors+=tuple(r.operation_seq for r in self._frames[step.physical]['first_reads'])
                step=walk.accept(data)
            incomplete(not executable or step.executable,'call_session_code_execute')
            chunk=min(remaining,step.page_bytes-step.page_offset,2048)
            boundary=self._guard._ram(step.physical,chunk);chunk=min(chunk,boundary-step.physical)
            self._charge(4096)  # plan/path native metadata before growth
            parts.append(dict(virtual=cursor,physical=step.physical,length=chunk,page_bytes=step.page_bytes,
                path=step.path,writable=step.writable,executable=step.executable,user=step.user,
                ancestors=ancestors,offset=cursor-virtual))
            cursor+=chunk;remaining-=chunk
        targets=tuple(read.ReadTarget('object',p,ordinal,part['offset'],part['physical'],part['length'])
                      for p in (0,1) for part in parts)
        if self._map_capacity is not None:
            deny(ordinal==6 and self.binding.epoch=='C2','call_session_map_stage')
            self._charge(512*len(targets))
            batch=self.accounting.materialize_c2_map(self._map_capacity,
                requests=tuple(budget.ReadCharge.for_target(t) for t in targets))
            self._map_plan=_native(MapTranslationPlan,epoch='C2',extent_ref=self._extent_record[0],
                binding_identity=self.binding,map_object_ordinal=6,
                map_parts=tuple(self._part_fact(ordinal,i,p,None,None) for i,p in enumerate(parts)),
                frame_ordinals=tuple(r['ordinal'] for r in self._frames.values()),
                reserved_read_operations=self._discovery_commitment[0],
                reserved_bytes=self._discovery_commitment[1],
                discovery_frozen=True)
        else:batch=self._batch(targets)
        row=dict(role=role,virtual=virtual,length=length,ordinal=ordinal,parts=tuple(parts),batch=batch,
                 first=None,recheck=None,first_reads=(),recheck_reads=())
        self._objects.append(row);chunks=[]
        for i,part in enumerate(parts):
            chunks.append((yield (batch,i,part['virtual'],None,part['path'],part['ancestors'])))
        row['first_reads']=tuple(chunks);row['first']=self._assemble(chunks,length)
        return row['first'].data

    def _drive(self):
        epoch=self.binding.epoch;r=self._registers
        if epoch=='C0':
            pinned=self._prepared.pinned_efi;prior=self._prepared.prior;b=prior.loaded_base
            at=struct.unpack_from('<I',pinned,60)[0]
            optional=struct.unpack_from('<H',pinned,at+20)[0]
            count=struct.unpack_from('<H',pinned,at+6)[0]
            extents=((0,64),(at,24),(at+24,optional),(at+24+optional,count*40))
            headers={}
            roles=('pe_dos_header64','pe_coff_header24','pe_optional_header(pinned length)',
                   'pe_sections(pinned length)')
            for (offset,length),role in zip(extents,roles):
                headers[offset]=yield from self._object(role,b+offset,length)
            code=yield from self._object('entry_code32',r[16],32,True)
            self._charge(4*sum(map(len,headers.values()))+_pe_copy_bound(pinned))
            c0._loaded_pe(pinned,b,r[16],headers,code)
            system=r[3];deny(system%8==0,'call_session_system_alignment')
            data=yield from self._object('system_table120',system,120)
            self._charge(4*120+4096);boot=c0._efi('system',data,system)
            data=yield from self._object('boot_services376',boot,376)
            self._charge(4*376+4096);gmm=c0._efi('boot',data,boot)
            yield from self._object('get_memory_map_code32',gmm,32,True)
            self._c0_values=(b,r[16],r[2],system,boot,gmm)
        elif epoch=='C1':
            cf=self._source_fact.facts;b=cf.loaded_base;s=r[7]
            incomplete(r[16]==cf.get_memory_map,'call_session_unselected_function')
            data=yield from self._object(pure.C1_ROLES[0],cf.system_table,120)
            self._charge(4*120+4096);boot=c0._efi('system',data,cf.system_table)
            deny(boot==r[0],'call_session_fresh_boot')
            data=yield from self._object(pure.C1_ROLES[1],boot,376)
            self._charge(4*376+4096)
            deny(c0._efi('boot',data,boot)==r[16],'call_session_fresh_gmm')
            yield from self._object(pure.C1_ROLES[2],r[16],32,True)
            caller=yield from self._object(pure.C1_ROLES[3],b+0x6200,435,True)
            helper=yield from self._object(pure.C1_ROLES[4],b+0x1810,348,True)
            deny(caller==self._prepared.pinned_caller.caller_code
                 and helper==self._prepared.pinned_caller.helper_code,'call_session_caller_code')
            canonical_span(s,0x80);deny(s%8==0,'call_session_stack_alignment')
            saved=struct.unpack('<Q',(yield from self._object(pure.C1_ROLES[5],s,8)))[0]
            incomplete(saved==b+0x6350,'call_session_unselected_first_caller')
            fifth=struct.unpack('<Q',(yield from self._object(pure.C1_ROLES[6],s+0x28,8)))[0]
            capacity=struct.unpack('<Q',(yield from self._object(pure.C1_ROLES[7],r[2],8)))[0]
            deny((r[2],r[3],r[8],r[9],fifth,capacity)==
                 (s+0x60,b+0x7f998,s+0x68,s+0x70,s+0x7c,32768),'call_session_C1_arguments')
        else:
            selected=self._source_fact.facts
            incomplete((r[16],r[7],r[0])==(selected.saved_return,selected.stack_pointer+8,0),
                       'call_session_same_call_success')
            b=selected.loaded_base
            addresses=(b+0x6200,b+0x1810,selected.size_pointer,selected.key_pointer,
                       selected.stride_pointer,selected.version_pointer)
            for i,(address,length) in enumerate(zip(addresses,(435,348,8,8,8,4))):
                yield from self._object(pure.C2_ROLES[i],address,length,i<2)
            yield _MAP_BARRIER
            deny(self._map_extent is not None and self._map_capacity is not None,
                 'call_session_map_not_installed')
            yield from self._object(pure.C2_ROLES[6],selected.map_pointer,self._map_extent.map_size)
        # No pointer discovery or new translation is allowed during rechecks.
        for row in tuple(self._frames.values()):
            chunks=[]
            for i in (2,3):
                chunks.append((yield (row['batch'],i,None,row['level'],(),row['ancestors'])))
            deny(chunks[1].operation_seq==chunks[0].operation_seq+1,'call_session_frame_sequence')
            row['recheck_reads']=tuple(chunks);row['recheck']=self._assemble(chunks,4096)
            incomplete(row['recheck'].data==row['first'].data,'call_session_frame_changed')
        for row in self._objects:
            chunks=[];count=len(row['parts'])
            for i,part in enumerate(row['parts']):
                chunks.append((yield (row['batch'],count+i,part['virtual'],None,
                                     part['path'],part['ancestors'])))
            row['recheck_reads']=tuple(chunks);row['recheck']=self._assemble(chunks,row['length'])
            incomplete(row['recheck'].data==row['first'].data,'call_session_object_changed')

    @staticmethod
    def _part_fact(ordinal,index,part,first,recheck):
        return pure.ObjectPart(index,ordinal,part['offset'],part['virtual'],part['physical'],part['length'],
            part['page_bytes'],part['path'],part['writable'],part['executable'],part['user'],first,recheck)

    def _frame_facts(self,complete):
        self._charge(2048*len(self._frames))
        result=[]
        for row in self._frames.values():
            first=row['first'];again=row['recheck']
            result.append(pure.FrameEvidence(row['ordinal'],row['physical'],row['level'],first.blob,
                again.blob if complete else None,
                tuple(r.operation_seq for r in row['first_reads']),
                tuple(r.operation_seq for r in row['recheck_reads']) if complete else (),
                first.contributions,again.contributions if complete else ()))
        return tuple(result)

    def _object_facts(self,complete):
        self._charge(4096*sum(len(r['parts']) for r in self._objects)+1024*len(self._objects))
        result=[]
        for row in self._objects:
            first=row['first'];again=row['recheck']
            seqs=tuple(r.operation_seq for r in row['first_reads'])
            checks=tuple(r.operation_seq for r in row['recheck_reads']) if complete else ()
            parts=tuple(self._part_fact(row['ordinal'],i,p,seqs[i],checks[i] if complete else None)
                        for i,p in enumerate(row['parts']))
            values=(self.binding.epoch,row['ordinal'],row['role'],row['virtual'],row['length'],
                    first.blob,parts,seqs,first.contributions)
            result.append(pure.ObjectEvidence(*values,again.blob,checks,again.contributions)
                          if complete else pure.ObjectFirstEvidence(*values))
        return tuple(result)

    def _source_c0(self):
        if self.binding.epoch=='C1':return self._source_fact
        deny(self.binding.epoch=='C2','call_session_C0_context_type')
        return self._source_fact.c0_receipt

    def _copied_context(self,frames):
        prefix='epochs/'+self.binding.epoch+'/'
        def ref(name):
            deny(prefix+name in self._blobs,'call_session_context_missing')
            return self._blobs[prefix+name][0]
        self._charge(256*len(self._blobs)+4096)
        return pure.CopiedEpochBinding(self.binding.epoch,None,ref('stop.bin'),ref('before-registers.json'),
            self.binding.registers,None,self.binding.state,ref('hmp-before.txt'),None,
            ref('layout-before.txt'),None,ref('host-phase.json'),self._source_c0().facts,
            frames,tuple(pure.CopiedBlob(r,b) for r,b in self._blobs.values()),
            self._extent_record[0] if self._extent_record else None)

    def scalar_evidence(self):
        try:
            self._live()
            deny(self.binding.epoch=='C2' and self._map_extent_pending and self._pending is None
                 and len(self._objects)==6,'call_session_scalar_barrier')
            frames=self._frame_facts(False);objects=self._object_facts(False)
            context=self._copied_context(frames)
            return pure.C2ScalarEvidence(self._source_fact.facts_ref,context.stop_ref,context.registers_ref,
                                         objects[:2],objects[2:6],context)
        except BaseException as error:self._fail(error)

    def _attach_extent_record(self,ref,data):
        try:
            self._live()
            deny(self.binding.epoch=='C2' and self._map_extent_pending
                 and self._pending is None and self._extent_record is None,'call_session_extent_record_stage')
            _root_method(self._owner,'_require_extent_record',self,ref,data)
            self._charge(256)
            pure._ref(ref,'map-extent.json')
            deny(type(data) is bytes and 0<len(data)<=1<<20 and len(data)==ref.length
                 and hashlib.sha256(data).hexdigest()==ref.sha256,'call_session_extent_record_identity')
            self._put(ref,data);self._extent_record=(ref,data)
        except BaseException as error:self._fail(error)

    def install_map_extent(self,extent):
        try:
            evidence=self.scalar_evidence()
            deny(self._extent_record is not None,'call_session_extent_record_required')
            self._charge(8192)  # bounded extent/ref shape copies before checking
            pure._extent_shape(extent)
            self._charge(_validation_bound(evidence.context,
                evidence.code_objects+evidence.scalar_objects,complete=False,scalar=True)
                +_json_copy_cost(self._extent_record[1])+8192)
            recomputed=pure.validate_c2_scalars(self._source_fact.facts,evidence)
            deny(extent==recomputed,'call_session_extent_provenance')
            deny(pure._same_json(pure._parse(self._extent_record[1]),pure._value(recomputed)),
                 'call_session_extent_record_join')
            # Charge both ledger-view metadata copies before the adjacent
            # capacity+wire reservation snapshots; no other charge is inside.
            self._charge(8192)
            before=self.accounting.view()
            self._map_capacity=self.accounting.reserve_c2_discovery_capacity(
                map_virtual=recomputed.map_pointer,map_length=recomputed.map_size)
            credit=getattr(budget.ParentAccounting,'reserve_wire_discovery',None)
            incomplete(credit is not None,'call_session_wire_discovery_credit_pending')
            credit(self.accounting,self._map_capacity)
            after=self.accounting.view()
            # COMPLETE original discovery commitment, including unused potential
            # and wire credit, never a count of dispatched/observed reads.
            self._discovery_commitment=(after['committed_operations']-before['committed_operations'],
                                        after['committed_bytes']-before['committed_bytes'])
            self._map_extent=recomputed;self._map_extent_pending=False
            self._advance()
        except BaseException as error:self._fail(error)

    def require_reads_complete(self,receipt,*,actual_wire_identity,actual_transport_identity,
                               actual_epoch_nonce,now_ns):
        self._live();self._clock(now_ns)
        deny(type(receipt) is PhaseReadsComplete and receipt is self._complete
             and receipt.session is self and receipt.binding is self.binding
             and self._pending is None and self.retainer._pending is None
             and receipt.last_read_seq==self._last_seq and receipt.last_finished_ns==self._last_finished
             and actual_wire_identity is self.binding.wire
             and type(actual_transport_identity) is tuple
             and actual_transport_identity==self.binding.transport_identity
             and all(type(v) is int for v in actual_transport_identity[1:])
             and actual_epoch_nonce is self.binding.epoch_nonce,'call_session_complete_identity')
        return self.binding

    def finish(self,after):
        try:
            self._live()
            from run0_call_wire import (EpochAfterReceipt,SelectedEpochRegisters,
                                        EpochRegisterView,EpochLayoutReceipt)
            deny(type(after) is EpochAfterReceipt and type(after.registers) is SelectedEpochRegisters
                 and type(after.hmp) is EpochRegisterView and type(after.layout) is EpochLayoutReceipt,
                 'call_session_after_types')
            _root_method(self._owner,'_require_epoch_after',self,after)
            done=self._complete
            deny(type(done) is PhaseReadsComplete and self._pending is None
                 and self.retainer._pending is None and after.reads_complete is done
                 and after._registration is self._registration and after._wire is self.binding.wire
                 and after.stop is self.binding.stop,'call_session_after_identity')
            deny(all(type(raw) is bytes and len(raw)<=65536 for raw in
                     (after.hmp.raw_bytes,after.layout.raw_bytes)),'call_session_after_raw_types')
            self._charge(128*40+16*(len(after.hmp.raw_bytes)+len(after.layout.raw_bytes))+8192)
            values,seqs=old._registers(after.registers.values)
            deny(after.registers.stop is self.binding.stop and after.registers._registration is self._registration
                 and after.registers._wire is self.binding.wire and after.registers.phase=='after'
                 and after.hmp.registers is after.registers and after.hmp.stop is self.binding.stop
                 and after.layout.stop is self.binding.stop and after.layout.phase=='after',
                 'call_session_after_lineage')
            incomplete(values==self._registers and type(after.hmp.raw_bytes) is bytes
                       and after.hmp.raw_bytes==self.binding.hmp_raw
                       and type(after.layout.raw_bytes) is bytes
                       and after.layout.raw_bytes==self.binding.layout_raw,'call_session_after_changed')
            deny(self._last_seq<seqs[0] and seqs[-1]<_int(after.hmp.operation_seq,1)
                 <_int(after.layout.operation_seq,1),'call_session_after_order')
            c0._hmp(after.hmp.raw_bytes,values)
            deny(c0._layout(after.layout.raw_bytes)==self.binding.ranges,'call_session_after_ranges')
            self._clock(time.monotonic_ns())
            self._snapshot=_native(ClosedEpochSnapshot,session=self,binding=self.binding,
                reads_complete=done,after=after,frames=done.frames,objects=done.objects,
                receipts=done.receipts,map_extent=self._map_extent)
            self._retired=True
            return self._snapshot
        except BaseException as error:self._fail(error)

    def _project_closed_facts(self,snapshot,closed,copied):
        self._archive()
        deny(type(snapshot) is ClosedEpochSnapshot and snapshot is self._snapshot
             and snapshot.session is self and type(closed) is ClosedEpochReceipt and self._retired,
             'call_session_closed_identity')
        _root_method(self._owner,'_require_closed_projection',self,snapshot,closed,copied)
        if self.binding.epoch=='C0':
            deny(type(copied) is ClosedC0CopiedInput,'call_session_C0_input_type')
            self._charge(_validation_bound(copied,snapshot.objects,complete=True)
                +_pe_copy_bound(self._prepared.pinned_efi))
            _frame_shapes(copied.frames,'C0')
            result=self._project_fresh_c0(copied,snapshot)
        else:
            deny(type(copied) is pure.CopiedEpochBinding and copied.c0_facts is self._source_c0().facts,
                 'call_session_closed_context')
            if self.binding.epoch=='C1':
                self._charge(_validation_bound(copied,snapshot.objects,complete=True))
                _frame_shapes(copied.frames,'C1')
                deny(pure._same_json(pure._value(copied.frames),pure._value(snapshot.frames)),
                     'call_session_closed_frames')
                result=pure.validate_c1_entry(copied,snapshot.objects,self._prepared.pinned_caller)
            else:
                self._charge(8192+512*(len(snapshot.frames)+len(snapshot.objects)
                    +sum(len(o.parts) for o in snapshot.objects)))
                bound=pure.projection_size_bound(self._map_extent,snapshot.objects,snapshot.frames)
                self._charge(
                    _validation_bound(copied,snapshot.objects,complete=True,project=True)
                    +_validation_bound(copied,snapshot.objects[:6],complete=False,scalar=True)
                    +bound.pure_call_credit)
                _frame_shapes(copied.frames,'C2')
                deny(pure._same_json(pure._value(copied.frames),pure._value(snapshot.frames)),
                     'call_session_closed_frames')
                result=pure.project_c2_return(copied,self._source_fact.facts,self._map_extent,
                                              snapshot.objects,snapshot.frames)
        self._closed_projection=(snapshot,closed,copied,result)
        return result

    def _project_fresh_c0(self,copied,snapshot):
        deny(copied.epoch=='C0','call_session_C0_epoch')
        before,seqs=old._registers(copied.before_registers)
        after,afterseqs=old._registers(copied.after_registers)
        deny(copied.before_registers==self.binding.registers
             and copied.after_registers==snapshot.after.registers.values
             and old._state(copied.state)==self._state and before==after,
             'call_session_C0_register_join')
        deny(pure._same_json(pure._value(copied.frames),pure._value(snapshot.frames)),
             'call_session_C0_frames')
        blobs={}
        for item in copied.blobs:
            pure._ref(item.ref)
            deny(item.ref.path not in blobs and hashlib.sha256(item.data).hexdigest()==item.ref.sha256,
                 'call_session_C0_blob_identity')
            blobs[item.ref.path]=(item.ref,item.data)
        def get(ref,path=None):
            pure._ref(ref,path)
            deny(ref.path in blobs and blobs[ref.path][0]==ref,'call_session_C0_ref')
            data=blobs[ref.path][1]
            if ref.path in self._blobs:deny(self._blobs[ref.path]==(ref,data),'call_session_C0_data')
            return data
        prefix='epochs/C0/'
        for ref,name,raw in ((copied.hmp_before_ref,'hmp-before.txt',self.binding.hmp_raw),
                (copied.hmp_after_ref,'hmp-after.txt',snapshot.after.hmp.raw_bytes),
                (copied.layout_before_ref,'layout-before.txt',self.binding.layout_raw),
                (copied.layout_after_ref,'layout-after.txt',snapshot.after.layout.raw_bytes)):
            deny(get(ref,prefix+name)==raw,'call_session_C0_raw_join')
        get(copied.stop_ref,prefix+'stop.bin');get(copied.host_phase_ref,prefix+'host-phase.json')
        for ref,rows,name in ((copied.registers_ref,copied.before_registers,'before-registers.json'),
                (blobs[prefix+'after-registers.json'][0],copied.after_registers,'after-registers.json')):
            deny(pure._same_json(pure._parse(get(ref,prefix+name)),
                {'schema_version':1,'operations':[row[3] for row in rows]}),'call_session_C0_register_index')
        epoch=pure._parse(get(copied.epoch_ref,prefix+'epoch.json'))
        names=('phase','epoch','firmware_phase','stop_ref','before_registers_ref','host_phase_ref',
            'layout_before_ref','read_plan_ref','table_snapshots','objects','translations','completion_ref',
            'after_registers_ref','hmp_after_ref','layout_after_ref','closure_ref')
        pure._fields(epoch,names)
        expected={'phase':'C0','epoch':'C0','firmware_phase':'firmware_active',
            'stop_ref':pure._value(copied.stop_ref),'before_registers_ref':pure._value(copied.registers_ref),
            'host_phase_ref':pure._value(copied.host_phase_ref),'layout_before_ref':pure._value(copied.layout_before_ref),
            'after_registers_ref':pure._value(blobs[prefix+'after-registers.json'][0]),
            'hmp_after_ref':pure._value(copied.hmp_after_ref),'layout_after_ref':pure._value(copied.layout_after_ref),
            'table_snapshots':pure._value(snapshot.frames),'objects':pure._value(snapshot.objects),
            'translations':pure._value(tuple(p for obj in snapshot.objects for p in obj.parts))}
        for name,value in expected.items():deny(pure._same_json(epoch[name],value),'call_session_C0_epoch_join')
        for name,file in (('read_plan_ref','read-plan.json'),('completion_ref','completion.json'),('closure_ref','closure.json')):
            pure._fields(epoch[name],('path','sha256','length'))
            get(read.BlobRef(**epoch[name]),prefix+file)
        # Exact native snapshots already tie every decoded assembly to an actual
        # retained read. Recheck all copied bytes and recompute ordinary walks.
        tables={}
        for f in snapshot.frames:
            first=get(f.first_ref);again=get(f.recheck_ref)
            deny(len(first)==4096 and first==again,'call_session_C0_frame_copy')
            tables[f.physical]=first
        walker=c0._Walker(self._state,tables,c0._layout(self.binding.layout_raw))
        for f in snapshot.frames:walker._ram(f.physical,4096)
        data=[]
        for obj in snapshot.objects:
            first=get(obj.first_ref);again=get(obj.recheck_ref)
            deny(len(first)==obj.length and first==again,'call_session_C0_object_copy')
            translated=walker.translate(obj.virtual,obj.length)
            deny(len(translated)==len(obj.parts),'call_session_C0_parts')
            for part,observed in zip(obj.parts,translated):
                t=observed['translation']
                deny(all(getattr(part,n)==t[n] for n in ('virtual','physical','length','page_bytes',
                        'writable','executable','user'))
                     and tuple((p.frame,p.index,p.entry) for p in part.path)==
                         tuple((p['frame'],p['index'],p['entry']) for p in t['path']),
                     'call_session_C0_walk')
            data.append(first)
        deny(tuple(walker.lookups)==tuple(f.physical for f in snapshot.frames),'call_session_C0_frame_set')
        for receipt in snapshot.receipts:self.retainer._receipt(receipt)
        pinned=self._prepared.pinned_efi;b=self._prepared.prior.loaded_base
        at=struct.unpack_from('<I',pinned,60)[0];opt=struct.unpack_from('<H',pinned,at+20)[0]
        count=struct.unpack_from('<H',pinned,at+6)[0]
        c0._loaded_pe(pinned,b,before[16],dict(zip((0,at,at+24,at+24+opt),data[:4])),data[4])
        boot=c0._efi('system',data[5],before[3]);gmm=c0._efi('boot',data[6],boot)
        deny((b,before[16],before[2],before[3],boot,gmm)==self._c0_values,
             'call_session_C0_fact_derivation')
        return pure.C0CopiedFacts(copied.epoch_ref,b,before[16],before[2],before[3],boot,gmm)


_MAP_BARRIER=object()


def _register_closed_c0_facts(session,snapshot,closed,copied,facts):
    deny(type(session) is ParentAcquisitionSession and type(copied) is ClosedC0CopiedInput
         and session.binding.epoch=='C0','call_session_C0_registration_type')
    session._archive()
    deny(session._closed_projection is not None and all(a is b for a,b in zip(
        session._closed_projection,(snapshot,closed,copied,facts))),'call_session_C0_projection_identity')
    ref=facts.epoch_ref
    data=next((b.data for b in copied.blobs if b.ref==ref),None)
    deny(type(data) is bytes,'call_session_C0_epoch_bytes')
    session._charge(4096)
    receipt=_native(FreshC0FactsReceipt,_owner=session._owner,registration=session._registration,
        session=session,snapshot=snapshot,closed=closed,facts=facts,epoch_bytes=data)
    _root_method(session._owner,'_publish_c0_facts',receipt)
    return receipt


def _register_selected_call(session,snapshot,closed,copied,facts,ref,data):
    deny(type(session) is ParentAcquisitionSession and session.binding.epoch=='C1',
         'call_session_selected_registration_type')
    session._archive()
    deny(session._closed_projection is not None and all(a is b for a,b in zip(
        session._closed_projection,(snapshot,closed,copied,facts))),'call_session_selected_projection_identity')
    session._charge(5*_json_copy_cost(data)+8192)
    pure._ref(ref,'selected-call.json')
    deny(type(data) is bytes and len(data)==ref.length
         and hashlib.sha256(data).hexdigest()==ref.sha256
         and pure._same_json(pure._parse(data),pure._value(facts)),
         'call_session_selected_record')
    receipt=_native(SelectedCallReceipt,_owner=session._owner,registration=session._registration,
        session=session,snapshot=snapshot,closed=closed,c0_receipt=session._source_fact,
        facts=facts,facts_ref=ref,facts_bytes=data)
    _root_method(session._owner,'_publish_selected_call',receipt)
    return receipt
