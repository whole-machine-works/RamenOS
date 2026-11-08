"""Pure copied-byte same-call facts; no runtime issuer, reader, clock or callback.

Projection W+5J bounds only declared semantic copies. Context validation parses
bounded JSON, checks/joins copied blobs and walks frames separately; an actual
collector must prepay those input/assembly costs too. Nothing here authenticates
a process, transport or guest stop, or closes the parent's runtime budget.
"""
from dataclasses import dataclass, fields
import hashlib
import json
import struct

import run0_c0_decode as c0
import run0_c0_acquire as acquire
from run0_c0_paging import C0DecodeError, PageEntry, canonical_span
from run0_call_read import BlobRef, RawSlice, AssemblyContribution

U64 = (1 << 64)-1
MIB = 1 << 20
CALLER_HASH = '199f6dd3fcae312e79a05c764ccbe4d569363b3ce891582323f7de454c809f3f'
HELPER_HASH = '1e9cfa7f60e3b18479fa7d5445b4664fe05699ee65f209f36565f6f51c491562'
EFI_HASH = '0b3c1d65739fb6b6a3fd816cdd6188bc0c312ce99fa41e939b5af4e67f46ed0a'
PDB_HASH = '1886fb937c6eefa9045a7b498acd7962212a91e182aaaa53756e1c556fd33d13'
GUID = 'EB7DB421-F264-2CBB-4C4C-44205044422E'
C1_ROLES = ('system_table120','boot_services376','get_memory_map_code32','caller_code435',
            'helper_code348','saved_return8','fifth_argument_pointer8','input_capacity8')
C2_ROLES = ('caller_code435','helper_code348','returned_size8','returned_key8',
            'returned_stride8','returned_version4','raw_mapM')
ADMISSIBLE = frozenset((1,2,3,4,5,6,7,9,10))
SCOPE = 'current_C2_named_partial_walk_objects_only'

@dataclass(frozen=True, slots=True)
class RowRef:
    artifact: BlobRef
    collection: str
    index: int

@dataclass(frozen=True, slots=True)
class ObjectPart:
    ordinal: int
    object_ordinal: int
    object_offset: int
    virtual: int
    physical: int
    length: int
    page_bytes: int
    path: tuple
    writable: bool
    executable: bool
    user: bool
    first_read_seq: int | None
    recheck_read_seq: int | None

@dataclass(frozen=True, slots=True)
class FrameEvidence:
    ordinal: int
    physical: int
    level: int
    first_ref: BlobRef
    recheck_ref: BlobRef | None
    first_read_sequences: tuple
    recheck_read_sequences: tuple
    first_contributions: tuple
    recheck_contributions: tuple

@dataclass(frozen=True, slots=True)
class ObjectFirstEvidence:
    epoch: str
    ordinal: int
    role: str
    virtual: int
    length: int
    first_ref: BlobRef
    parts: tuple
    first_read_sequences: tuple
    first_contributions: tuple

@dataclass(frozen=True, slots=True)
class ObjectEvidence(ObjectFirstEvidence):
    recheck_ref: BlobRef
    recheck_read_sequences: tuple
    recheck_contributions: tuple

@dataclass(frozen=True, slots=True)
class C0CopiedFacts:
    epoch_ref: BlobRef
    loaded_base: int
    entry_address: int
    image_handle: int
    system_table: int
    boot_services: int
    get_memory_map: int

@dataclass(frozen=True, slots=True)
class CopiedBlob:
    ref: BlobRef
    data: bytes

@dataclass(frozen=True, slots=True)
class CopiedEpochBinding:
    epoch: str
    epoch_ref: BlobRef | None
    stop_ref: BlobRef
    registers_ref: BlobRef
    before_registers: tuple
    after_registers: tuple | None
    state: tuple
    hmp_before_ref: BlobRef
    hmp_after_ref: BlobRef | None
    layout_before_ref: BlobRef
    layout_after_ref: BlobRef | None
    host_phase_ref: BlobRef
    c0_facts: C0CopiedFacts
    frames: tuple
    blobs: tuple
    extent_ref: BlobRef | None = None
    descriptor_index_ref: BlobRef | None = None
    coverage_ref: BlobRef | None = None

@dataclass(frozen=True, slots=True)
class PinnedCaller:
    manifest_ref: BlobRef
    efi_sha256: str
    pdb_sha256: str
    codeview_guid: str
    pdb_age: int
    caller_code: bytes
    helper_code: bytes

@dataclass(frozen=True, slots=True)
class SelectedCallFacts:
    C0_epoch_ref: BlobRef
    C1_stop_ref: BlobRef
    C1_registers_ref: BlobRef
    C1_objects: tuple
    caller_manifest_ref: BlobRef
    loaded_base: int
    system_table: int
    boot_services: int
    get_memory_map: int
    stack_pointer: int
    saved_return: int
    size_pointer: int
    map_pointer: int
    key_pointer: int
    stride_pointer: int
    version_pointer: int
    input_capacity: int

@dataclass(frozen=True, slots=True)
class C2ScalarEvidence:
    selected_call_ref: BlobRef
    stop_ref: BlobRef
    registers_ref: BlobRef
    code_objects: tuple
    scalar_objects: tuple
    context: CopiedEpochBinding

@dataclass(frozen=True, slots=True)
class MapExtent:
    selected_call_ref: BlobRef
    C2_stop_ref: BlobRef
    C2_registers_ref: BlobRef
    code_object_refs: tuple
    scalar_object_refs: tuple
    map_pointer: int
    saved_capacity: int
    map_size: int
    map_key: int
    descriptor_stride: int
    descriptor_version: int
    descriptor_count: int

@dataclass(frozen=True, slots=True)
class Descriptor:
    ordinal: int
    wire: RawSlice
    type: int
    padding4: bytes
    physical_start: int
    virtual_start: int
    number_of_pages: int
    attribute: int
    extension: bytes

@dataclass(frozen=True, slots=True)
class NamedC2Extent:
    kind: str
    ordinal: int
    part_ordinal: int | None
    physical: int
    length: int
    evidence_ref: RowRef

@dataclass(frozen=True, slots=True)
class CoverageRow:
    extent: NamedC2Extent
    descriptor_ordinals: tuple

@dataclass(frozen=True, slots=True)
class CallMapFacts:
    selected_call_ref: BlobRef
    extent_ref: BlobRef
    C2_epoch_ref: BlobRef
    raw_map_ref: BlobRef
    descriptor_index_ref: BlobRef
    coverage_ref: BlobRef
    frame_count: int
    object_count: int
    object_part_count: int
    descriptor_count: int
    observed_consistent: bool
    atomic_snapshot: bool
    device_quiescence_verified: bool
    coverage_scope: str

@dataclass(frozen=True, slots=True)
class ProjectionSizeBound:
    M: int
    N: int
    F: int
    P: int
    descriptor_json_bound: int
    coverage_json_bound: int
    native_field_bytes: int
    working_copies: int
    native_metadata_credit: int
    serialization_credit: int
    pure_call_credit: int
    file_copy_credit: int

@dataclass(frozen=True, slots=True)
class C2ReturnProjection:
    descriptors: tuple
    physical_order: tuple
    coverage: tuple
    descriptor_index_bytes: bytes
    coverage_bytes: bytes
    frame_count: int
    object_count: int
    object_part_count: int
    descriptor_count: int
    observed_consistent: bool = True
    atomic_snapshot: bool = False
    device_quiescence_verified: bool = False
    coverage_scope: str = SCOPE



def _require(value, reason, status='DENY'):
    c0._require(value, 'call_'+reason, status)


def _int(value, low=0, high=U64):
    _require(type(value) is int and low <= value <= high, 'integer')
    return value


def _tuple(value, maximum, minimum=0):
    _require(type(value) is tuple and minimum <= len(value) <= maximum, 'tuple_bound')
    return value


def _ref(value, path=None):
    _require(type(value) is BlobRef, 'blob_ref')
    from boot_profile_capture import ProbeError
    try:
        value.__post_init__()
    except ProbeError as error:
        raise C0DecodeError(error.status, error.reason) from error
    _require(path is None or value.path == path, 'ref_role_path')
    return value


def _value(value):
    """Internal bounded schema projection; never applied to arbitrary objects."""
    if type(value) is bytes:
        return value.hex()
    if type(value) in (BlobRef, RawSlice):
        return value.as_json()
    if type(value) is tuple:
        return [_value(v) for v in value]
    if type(value) in (PageEntry,AssemblyContribution,RowRef,ObjectPart,FrameEvidence,ObjectFirstEvidence,ObjectEvidence,
                       SelectedCallFacts,MapExtent,Descriptor,NamedC2Extent,CoverageRow,CallMapFacts):
        return {f.name:_value(getattr(value,f.name)) for f in fields(value)}
    _require(value is None or type(value) in (str,int,bool), 'projection_type')
    return value


def _same_json(actual, expected):
    """Closed copied-record join: bool/int/float are distinct JSON types.

    Both trees are already bounded: parsed native JSON and an internal schema
    projection. No reserialization or additional payload copy is needed.
    """
    if type(actual) is not type(expected):
        return False
    if type(expected) is dict:
        return actual.keys() == expected.keys() and all(
            _same_json(actual[key],value) for key,value in expected.items())
    if type(expected) is list:
        return len(actual) == len(expected) and all(
            _same_json(a,b) for a,b in zip(actual,expected))
    return type(expected) in (str,int,bool,type(None)) and actual == expected


def _canonical(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,
                       allow_nan=False)+'\n').encode('ascii')


def _parse(raw, limit=MIB):
    # Scan before the allocating parser: no unbounded depth, strings or token
    # inventory can hide in an otherwise bounded copied context record.
    _require(type(raw) is bytes and 0 < len(raw) <= limit and raw.isascii(), 'json_bytes')
    depth=starts=string_length=0
    quoted=escaped=False
    for char in raw:
        if quoted:
            string_length += 1
            _require(string_length <= 8192, 'json_string_bound')
            if escaped:
                escaped=False
            elif char == 92:
                escaped=True
            elif char == 34:
                quoted=False
        elif char == 34:
            quoted=True;string_length=0;starts+=1
        elif char in (91,123):
            depth+=1;starts+=1
            _require(depth <= 12, 'json_depth')
        elif char in (93,125):
            depth-=1
            _require(depth >= 0, 'json_depth')
        elif char in (44,58):
            starts+=1
        _require(starts <= 65536, 'json_token_bound')
    _require(not quoted and depth == 0, 'json_incomplete')
    return c0._json(raw,limit)


def _fields(value, names):
    _require(type(value) is dict and set(value) == set(names), 'record_fields')


def _pinned(value):
    _require(type(value) is PinnedCaller, 'pinned_caller')
    _ref(value.manifest_ref)
    _require(all(type(v) is str for v in (value.efi_sha256,value.pdb_sha256,value.codeview_guid)), 'caller_identity_type')
    _require((value.efi_sha256,value.pdb_sha256,value.codeview_guid)==(EFI_HASH,PDB_HASH,GUID)
             and type(value.pdb_age) is int and value.pdb_age==1, 'caller_source_identity')
    for data,length,pin in ((value.caller_code,435,CALLER_HASH),(value.helper_code,348,HELPER_HASH)):
        _require(type(data) is bytes and len(data)==length and hashlib.sha256(data).hexdigest()==pin,
                 'caller_code_pin')
    _require(value.caller_code[0x14d:0x150]==b'\xff\x50\x38'
             and value.caller_code[0x150:0x155]==b'\x4c\x8b\x44\x24\x50', 'caller_opcode')


class _Context:
    """Bounded copied facts. Whole-wire/host/process authenticity is external."""
    def __init__(self, binding, epoch, complete):
        _require(type(binding) is CopiedEpochBinding and type(binding.epoch) is str
                 and binding.epoch==epoch, 'epoch')
        self.binding=binding;self.epoch=epoch;self.prefix=f'epochs/{epoch}/'
        blobs=_tuple(binding.blobs,2957,1)
        total=0
        # Validate counts/types/summed bytes BEFORE making the lookup mapping.
        for item in blobs:
            _require(type(item) is CopiedBlob and type(item.data) is bytes, 'copied_blob')
            _ref(item.ref);total+=len(item.data)
            _require(total<=32*MIB and len(item.data)==item.ref.length, 'copied_blob_bound')
        self.blobs={}
        for item in blobs:
            _require(item.ref.path not in self.blobs and hashlib.sha256(item.data).hexdigest()==item.ref.sha256,
                     'copied_blob_identity')
            self.blobs[item.ref.path]=(item.ref,item.data)
        self.sequences=[];self.ordinals=[];self.first=[];self.rechecks=[]
        self.registers,self.before_sequences=acquire._registers(binding.before_registers)
        self._register_index(binding.registers_ref,binding.before_registers,'before')
        _ref(binding.stop_ref,self.prefix+'stop.bin')
        self.get(binding.stop_ref,65536)
        _ref(binding.host_phase_ref,self.prefix+'host-phase.json');self.get(binding.host_phase_ref,MIB)
        self.state=acquire._state(binding.state)
        for name,number in (('cr0',27),('cr3',29),('cr4',30),('efer',32)):
            _require(self.state[name]==self.registers[number], 'mode_register_join')
        hmp=self.get(_ref(binding.hmp_before_ref,self.prefix+'hmp-before.txt'),65536)
        parsed=c0._hmp(hmp,self.registers)
        _require((parsed['cpl'],parsed['cs64'],parsed['a20'],parsed['smm'])==
                 (self.state['cpl'],self.state['cs64'],self.state['a20'],0), 'hmp_mode_join')
        layout=self.get(_ref(binding.layout_before_ref,self.prefix+'layout-before.txt'),65536)
        self.ranges=c0._layout(layout)
        _require(type(binding.c0_facts) is C0CopiedFacts, 'c0_facts')
        for f in fields(C0CopiedFacts):
            if f.name=='epoch_ref':
                self.get(_ref(binding.c0_facts.epoch_ref,'epochs/C0/epoch.json'),MIB)
            else:
                _int(getattr(binding.c0_facts,f.name),1)
        self.frames=_tuple(binding.frames,32,1)
        tables={};physical=set()
        for ordinal,row in enumerate(self.frames):
            _require(type(row) is FrameEvidence and type(row.ordinal) is int and row.ordinal==ordinal,
                     'frame_ordinal')
            _int(row.physical);_int(row.level,1,4)
            _require(row.physical%4096==0 and row.physical not in physical,'frame_identity')
            physical.add(row.physical)
            first=self.get(_ref(row.first_ref,self.prefix+f'frames/{ordinal:02d}-first.bin'),4096)
            _require(len(first)==4096,'frame_length','INCOMPLETE')
            self.assembly(first,row.first_read_sequences,row.first_contributions,(2048,2048),False)
            if complete:
                other=self.get(_ref(row.recheck_ref,self.prefix+f'frames/{ordinal:02d}-recheck.bin'),4096)
                _require(first==other,'frame_changed','INCOMPLETE')
                self.assembly(other,row.recheck_read_sequences,row.recheck_contributions,(2048,2048),True)
            tables[row.physical]=first
        try:
            self.walker=c0._Walker(self.state,tables,self.ranges)
        except C0DecodeError as error:
            if error.reason in ('ram_hole','ram_backing'):
                raise C0DecodeError('INCOMPLETE',error.reason) from error
            raise
        for row in self.frames:
            self.ram(row.physical,4096)
        self.after_sequences=()
        if complete:
            after,self.after_sequences=acquire._registers(binding.after_registers)
            _require(self.registers==after,'registers_changed','INCOMPLETE')
            ar=self.path(self.prefix+'after-registers.json')
            self._register_index(ar,binding.after_registers,'after')
            ha=self.get(_ref(binding.hmp_after_ref,self.prefix+'hmp-after.txt'),65536)
            la=self.get(_ref(binding.layout_after_ref,self.prefix+'layout-after.txt'),65536)
            _require(ha==hmp and la==layout,'after_state_changed','INCOMPLETE')
            c0._hmp(ha,after);c0._layout(la)

    def path(self,path):
        _require(path in self.blobs,'blob_missing')
        return self.blobs[path][0]

    def get(self,ref,limit):
        _ref(ref)
        _require(ref.path in self.blobs and self.blobs[ref.path][0]==ref,'blob_identity')
        raw=self.blobs[ref.path][1]
        _require(len(raw)<=limit,'blob_role_bound')
        return raw

    def _register_index(self,ref,rows,phase):
        ref=_ref(ref,self.prefix+phase+'-registers.json')
        value=_parse(self.get(ref,8192),8192)
        _fields(value,('schema_version','operations'))
        _require(type(value['schema_version']) is int and value['schema_version']==1
                 and type(value['operations']) is list and len(value['operations'])==29
                 and all(type(v) is int for v in value['operations'])
                 and value['operations']==[row[3] for row in rows], 'register_index_join')

    def ram(self,address,length):
        try:
            return self.walker._ram(address,length)
        except C0DecodeError as error:
            if error.reason in ('ram_hole','ram_backing'):
                raise C0DecodeError('INCOMPLETE',error.reason) from error
            raise

    def assembly(self,data,sequences,contributions,lengths,recheck):
        _tuple(sequences,17,1);_tuple(contributions,17,1)
        _require(len(contributions)==len(sequences)==len(lengths), 'contribution_count')
        offset=previous=0
        for c,seq,length in zip(contributions,sequences,lengths):
            _require(type(c) is AssemblyContribution,'contribution_type')
            _int(c.physical_ordinal,0,505);_int(c.operation_seq,1,1024);_int(seq,1,1024)
            _require(c.operation_seq==seq and seq>previous and c.logical_offset==offset
                     and type(c.logical_offset) is int and type(c.length) is int and c.length==length,
                     'contribution_join')
            ref=_ref(c.decoded_data_ref,f'memory/read-{c.physical_ordinal:03d}.bin')
            _require(ref.length==length,'decoded_length')
            raw=self.get(ref,2048)
            _require(memoryview(data)[offset:offset+length]==raw,'assembly_data_join')
            _require(seq not in self.sequences and c.physical_ordinal not in self.ordinals,'read_reused')
            self.sequences.append(seq);self.ordinals.append(c.physical_ordinal)
            (self.rechecks if recheck else self.first).append(seq)
            previous=seq;offset+=length
        _require(offset==len(data),'assembly_complete')

    def objects(self,objects,roles,lengths,addresses,complete,code_ordinals):
        _tuple(objects,len(roles),len(roles))
        output=[];previous=0;parts_total=0
        for ordinal,(obj,role,length,address) in enumerate(zip(objects,roles,lengths,addresses)):
            expected=ObjectEvidence if complete else ObjectFirstEvidence
            _require(type(obj) is expected and type(obj.ordinal) is int and obj.ordinal==ordinal
                     and type(obj.epoch) is str and obj.epoch==self.epoch and type(obj.role) is str and obj.role==role,'object_role')
            _int(obj.virtual,1);_int(obj.length,1,32768);canonical_span(obj.virtual,obj.length)
            _require(obj.virtual==address and obj.length==length,'object_address')
            parts=_tuple(obj.parts,17 if self.epoch=='C2' and ordinal==6 else 16,1)
            _tuple(obj.first_read_sequences,len(parts),len(parts))
            _tuple(obj.first_contributions,len(parts),len(parts))
            if complete:
                _tuple(obj.recheck_read_sequences,len(parts),len(parts))
                _tuple(obj.recheck_contributions,len(parts),len(parts))
            parts_total+=len(parts)
            _require(parts_total<=(29 if self.epoch=='C2' else 16),'object_parts_cap','INCOMPLETE')
            data=self.get(_ref(obj.first_ref,self.prefix+f'objects/{ordinal:02d}-first.bin'),length)
            _require(len(data)==length,'object_length','INCOMPLETE')
            try:
                translated=self.walker.translate(address,length)
            except C0DecodeError as error:
                if error.reason in ('ram_hole','ram_backing'):
                    raise C0DecodeError('INCOMPLETE',error.reason) from error
                raise
            _require(len(parts)==len(translated),'part_plan')
            offset=0
            for j,(part,entry) in enumerate(zip(parts,translated)):
                _require(type(part) is ObjectPart,'part_type')
                t=entry['translation'];_int(part.ordinal,0,28);_int(part.object_ordinal,0,7)
                _int(part.object_offset,0,32767)
                _require((part.ordinal,part.object_ordinal,part.object_offset)==(j,ordinal,offset),'part_identity')
                for name in ('virtual','physical','length','page_bytes'):
                    _require(type(getattr(part,name)) is int and getattr(part,name)==t[name],'part_walk')
                _tuple(part.path,4,3)
                for p in part.path:
                    _require(type(p) is PageEntry,'page_entry_type')
                    _int(p.frame);_int(p.index,0,511);_int(p.entry)
                _require(all(type(p) is PageEntry for p in part.path)
                         and tuple((p.frame,p.index,p.entry) for p in part.path)==
                         tuple((p['frame'],p['index'],p['entry']) for p in t['path']),'part_path')
                for name in ('writable','executable','user'):
                    _require(type(getattr(part,name)) is bool and getattr(part,name)==t[name],'part_permissions')
                _require(ordinal not in code_ordinals or part.executable,'code_not_executable','INCOMPLETE')
                _int(part.first_read_seq,1,1024)
                _require(part.first_read_seq==obj.first_read_sequences[j],'part_read_join')
                if complete:
                    _int(part.recheck_read_seq,1,1024)
                    _require(part.recheck_read_seq==obj.recheck_read_sequences[j],'part_recheck_join')
                offset+=part.length
            _require(offset==length,'part_cover')
            self.assembly(data,obj.first_read_sequences,obj.first_contributions,tuple(p.length for p in parts),False)
            _require(obj.first_read_sequences[0]>previous,'object_order')
            previous=obj.first_read_sequences[-1]
            if complete:
                other=self.get(_ref(obj.recheck_ref,self.prefix+f'objects/{ordinal:02d}-recheck.bin'),length)
                _require(other==data,'object_changed','INCOMPLETE')
                self.assembly(other,obj.recheck_read_sequences,obj.recheck_contributions,tuple(p.length for p in parts),True)
            output.append(data)
        return tuple(output)

    def finish(self,objects):
        _require(self.first and self.rechecks and max(self.first)<min(self.rechecks)
                 and max(self.before_sequences)<min(self.first)
                 and max(self.rechecks)<min(self.after_sequences),'freeze_read_order')
        _require(tuple(self.walker.lookups)==tuple(f.physical for f in self.frames)
                 and all(self.walker.levels[f.physical]==f.level for f in self.frames),'frame_discovery_set')
        pairs=sorted(zip(self.sequences,self.ordinals))
        _require([p[1] for p in pairs]==sorted(set(self.ordinals)),'physical_ordinal_order')
        ref=_ref(self.binding.epoch_ref,self.prefix+'epoch.json')
        value=_parse(self.get(ref,MIB))
        names=('phase','epoch','firmware_phase','stop_ref','before_registers_ref','host_phase_ref',
               'layout_before_ref','read_plan_ref','table_snapshots','objects','translations','completion_ref',
               'after_registers_ref','hmp_after_ref','layout_after_ref','closure_ref')
        _fields(value,names)
        _require(value['phase']==self.epoch and value['epoch']==self.epoch
                 and value['firmware_phase']=='firmware_active','epoch_record')
        _require(_same_json(value['table_snapshots'],_value(self.frames)) and _same_json(value['objects'],_value(objects))
                 and _same_json(value['translations'],_value(tuple(p for obj in objects for p in obj.parts))),
                 'epoch_rows')
        for name,expected in (('stop_ref',self.binding.stop_ref),('before_registers_ref',self.binding.registers_ref),
            ('host_phase_ref',self.binding.host_phase_ref),('layout_before_ref',self.binding.layout_before_ref),
            ('hmp_after_ref',self.binding.hmp_after_ref),('layout_after_ref',self.binding.layout_after_ref),
            ('after_registers_ref',self.path(self.prefix+'after-registers.json'))):
            _require(_same_json(value[name],_value(expected)),'epoch_ref_join')
        for name,file in (('read_plan_ref','read-plan.json'),('completion_ref','completion.json'),
                          ('closure_ref','closure.json')):
            self.get(_ref(self._record_ref(value[name]),self.prefix+file),MIB)
        return ref

    @staticmethod
    def _record_ref(value):
        _fields(value,('path','sha256','length'))
        _require(type(value['path']) is str and type(value['sha256']) is str
                 and type(value['length']) is int,'record_ref_types')
        from boot_profile_capture import ProbeError
        try:
            return BlobRef(value['path'],value['sha256'],value['length'])
        except ProbeError as error:
            raise C0DecodeError(error.status,error.reason) from error


def _selected(selected):
    _require(type(selected) is SelectedCallFacts,'selected_type')
    for f in fields(SelectedCallFacts):
        v=getattr(selected,f.name)
        if f.name in ('C0_epoch_ref','C1_stop_ref','C1_registers_ref','caller_manifest_ref'):
            _ref(v)
        elif f.name=='C1_objects':
            _tuple(v,8,8)
            for i,r in enumerate(v):
                _require(type(r) is RowRef and type(r.collection) is str and r.collection=='objects' and type(r.index) is int and r.index==i,
                         'selected_object_refs')
                _ref(r.artifact,'epochs/C1/epoch.json')
        else:
            _int(v,0 if f.name=='loaded_base' else 1)
    b,s=selected.loaded_base,selected.stack_pointer
    for address,length in ((b+0x6200,435),(b+0x1810,348),(s,8),(s+0x28,8),(s+0x60,8),
                           (s+0x68,8),(s+0x70,8),(s+0x7c,4),(b+0x7f998,32768)):
        canonical_span(address,length)
    _require(s%8==0 and selected.input_capacity==32768 and
             (selected.saved_return,selected.size_pointer,selected.map_pointer,selected.key_pointer,
              selected.stride_pointer,selected.version_pointer)==
             (b+0x6350,s+0x60,b+0x7f998,s+0x68,s+0x70,s+0x7c),'selected_abi')


def validate_c1_entry(binding, objects, pinnedcaller):
    _pinned(pinnedcaller)
    ctx=_Context(binding,'C1',True)
    ctx.get(pinnedcaller.manifest_ref,MIB)
    cf=binding.c0_facts;r=ctx.registers;b=cf.loaded_base;s=r[7]
    _int(s,1);_require(s%8==0,'stack_alignment')
    _require(r[16]==cf.get_memory_map,'unselected_function_entry','INCOMPLETE')
    canonical_span(s,0x80)
    data=ctx.objects(objects,C1_ROLES,(120,376,32,435,348,8,8,8),
        (cf.system_table,r[0],r[16],b+0x6200,b+0x1810,s,s+0x28,r[2]),True,(2,3,4))
    boot=c0._efi('system',data[0],cf.system_table)
    _require(boot==r[0],'fresh_boot_pointer')
    _require(c0._efi('boot',data[1],boot)==r[16],'fresh_gmm_pointer')
    _require(data[3]==pinnedcaller.caller_code and data[4]==pinnedcaller.helper_code,'loaded_caller_code')
    saved=struct.unpack('<Q',data[5])[0]
    _require(saved==b+0x6350,'unselected_first_caller','INCOMPLETE')
    fifth=struct.unpack('<Q',data[6])[0];capacity=struct.unpack('<Q',data[7])[0]
    _require((r[2],r[3],r[8],r[9],fifth,capacity)==
             (s+0x60,b+0x7f998,s+0x68,s+0x70,s+0x7c,32768),'c1_arguments')
    epoch=ctx.finish(objects)
    result=SelectedCallFacts(cf.epoch_ref,binding.stop_ref,binding.registers_ref,
        tuple(RowRef(epoch,'objects',i) for i in range(8)),pinnedcaller.manifest_ref,
        b,cf.system_table,boot,r[16],s,saved,r[2],r[3],r[8],r[9],fifth,capacity)
    _selected(result)
    return result


def _extent_shape(extent):
    _require(type(extent) is MapExtent,'extent_type')
    for name in ('selected_call_ref','C2_stop_ref','C2_registers_ref'):
        _ref(getattr(extent,name))
    for name,count in (('code_object_refs',2),('scalar_object_refs',4)):
        for r in _tuple(getattr(extent,name),count,count):_ref(r)
    for name in ('map_pointer','saved_capacity','map_size','map_key','descriptor_stride','descriptor_version','descriptor_count'):
        _int(getattr(extent,name))
    _require(extent.saved_capacity==32768,'saved_capacity')
    _require(extent.map_size>0 and extent.descriptor_stride>=40 and extent.descriptor_stride%8==0,'map_shape')
    _require(extent.map_size<=32768 and extent.descriptor_stride<=256
             and extent.descriptor_version==1,'map_format','INCOMPLETE')
    _require(extent.map_size%extent.descriptor_stride==0,'map_divisibility')
    n=extent.map_size//extent.descriptor_stride
    _require(1<=n<=256,'descriptor_count','INCOMPLETE')
    _require(extent.descriptor_count==n,'descriptor_count_identity')
    canonical_span(extent.map_pointer,extent.map_size)
    return n


def validate_c2_scalars(selected_call, scalar_evidence):
    _selected(selected_call)
    _require(type(scalar_evidence) is C2ScalarEvidence,'scalar_type')
    ev=scalar_evidence;ctx=_Context(ev.context,'C2',False);r=ctx.registers;s=selected_call
    _ref(ev.stop_ref,'epochs/C2/stop.bin');_ref(ev.registers_ref,'epochs/C2/before-registers.json')
    _require(ev.stop_ref==ev.context.stop_ref and ev.registers_ref==ev.context.registers_ref,'scalar_context_ref')
    selected_raw=_parse(ctx.get(_ref(ev.selected_call_ref,'selected-call.json'),MIB))
    _require(_same_json(selected_raw,_value(s)),'selected_call_record')
    _require((r[16],r[7],r[0])==(s.saved_return,s.stack_pointer+8,0),
             'same_call_success','INCOMPLETE')
    _require(ev.context.c0_facts.loaded_base==s.loaded_base and ev.context.c0_facts.epoch_ref==s.C0_epoch_ref,
             'selected_c0_identity')
    code=_tuple(ev.code_objects,2,2);scalars=_tuple(ev.scalar_objects,4,4)
    objects=code+scalars
    data=ctx.objects(objects,C2_ROLES[:6],(435,348,8,8,8,4),
        (s.loaded_base+0x6200,s.loaded_base+0x1810,s.size_pointer,s.key_pointer,s.stride_pointer,s.version_pointer),
        False,(0,1))
    _require(hashlib.sha256(data[0]).hexdigest()==CALLER_HASH and hashlib.sha256(data[1]).hexdigest()==HELPER_HASH,
             'c2_loaded_code')
    size,key,stride=(struct.unpack('<Q',v)[0] for v in data[2:5])
    version=struct.unpack('<I',data[5])[0]
    extent=MapExtent(ev.selected_call_ref,ev.stop_ref,ev.registers_ref,tuple(o.first_ref for o in code),
        tuple(o.first_ref for o in scalars),s.map_pointer,s.input_capacity,size,key,stride,version,
        size//stride if stride else 0)
    _extent_shape(extent)
    return extent



def _contribution_shape(c):
    _require(type(c) is AssemblyContribution,'contribution_type')
    _int(c.physical_ordinal,0,505);_int(c.operation_seq,1,1024)
    _int(c.logical_offset,0,32767);_int(c.length,1,2048)
    _ref(c.decoded_data_ref,f'memory/read-{c.physical_ordinal:03d}.bin')
    _require(c.decoded_data_ref.length==c.length,'contribution_length')


def _frame_shape(row,ordinal):
    _require(type(row) is FrameEvidence,'frame_type')
    _int(row.ordinal,0,31);_int(row.physical);_int(row.level,1,4)
    _require(row.ordinal==ordinal and row.physical%4096==0,'frame_identity')
    _ref(row.first_ref,f'epochs/C2/frames/{ordinal:02d}-first.bin')
    _ref(row.recheck_ref,f'epochs/C2/frames/{ordinal:02d}-recheck.bin')
    for seqs,contributions in ((row.first_read_sequences,row.first_contributions),
                               (row.recheck_read_sequences,row.recheck_contributions)):
        _tuple(seqs,2,2);_tuple(contributions,2,2)
        for seq,c in zip(seqs,contributions):
            _int(seq,1,1024);_contribution_shape(c)


def _object_shape(obj,ordinal):
    _require(type(obj) is ObjectEvidence,'object_type')
    _require(type(obj.epoch) is str and obj.epoch=='C2' and type(obj.role) is str
             and obj.role==C2_ROLES[ordinal],'bound_objects')
    _int(obj.ordinal,0,6);_require(obj.ordinal==ordinal,'object_ordinal')
    _int(obj.virtual,1);_int(obj.length,1,32768)
    _ref(obj.first_ref,f'epochs/C2/objects/{ordinal:02d}-first.bin')
    _ref(obj.recheck_ref,f'epochs/C2/objects/{ordinal:02d}-recheck.bin')
    parts=_tuple(obj.parts,17 if ordinal==6 else 16,1)
    for p in parts:
        _require(type(p) is ObjectPart,'part_type')
        for name in ('ordinal','object_ordinal','object_offset','virtual','physical','length','page_bytes'):
            _int(getattr(p,name))
        _tuple(p.path,4,3)
        for entry in p.path:
            _require(type(entry) is PageEntry,'page_entry_type')
            _int(entry.frame);_int(entry.index,0,511);_int(entry.entry)
        for name in ('writable','executable','user'):
            _require(type(getattr(p,name)) is bool,'part_permission_type')
        _int(p.first_read_seq,1,1024);_int(p.recheck_read_seq,1,1024)
    for seqs,cs in ((obj.first_read_sequences,obj.first_contributions),
                    (obj.recheck_read_sequences,obj.recheck_contributions)):
        _tuple(seqs,len(parts),len(parts));_tuple(cs,len(parts),len(parts))
        for seq,c in zip(seqs,cs):
            _int(seq,1,1024);_contribution_shape(c)
    return len(parts)

def projection_size_bound(extent, objects, partial_walks):
    n=_extent_shape(extent)
    _tuple(objects,7,7);_tuple(partial_walks,32,1)
    p=sum(_object_shape(obj,i) for i,obj in enumerate(objects))
    _require(p<=29,'bound_parts','INCOMPLETE')
    for ordinal,frame in enumerate(partial_walks):
        _frame_shape(frame,ordinal)
    f=len(partial_walks);m=extent.map_size
    jd=4+2049*n+2*(m-40*n);jc=4+2053*f+2057*p
    _require(jd<=MIB and jc<=MIB,'projection_role_bound','INCOMPLETE')
    binary=m-36*n;working=3*binary+m;j=jd+jc
    return ProjectionSizeBound(m,n,f,p,jd,jc,binary,working,2*j,3*j,working+5*j,j)


def _first(obj):
    return ObjectFirstEvidence(*(getattr(obj,f.name) for f in fields(ObjectFirstEvidence)))


def _full_inputs(binding, selected, extent, objects, walks):
    bound=projection_size_bound(extent,objects,walks)
    _require(type(binding) is CopiedEpochBinding,'binding_type')
    _tuple(binding.frames,32,1)
    ctx=_Context(binding,'C2',True)
    _require(_canonical(_value(ctx.frames))==_canonical(_value(walks)),'walk_set')
    _require(binding.extent_ref is not None,'extent_record')
    _require(_same_json(_parse(ctx.get(_ref(binding.extent_ref,'map-extent.json'),MIB)),_value(extent)),'extent_record')
    # Recompute preread metadata using the same scalar implementation, not a
    # caller-provided length or a second descriptor parser.
    scalar=C2ScalarEvidence(extent.selected_call_ref,binding.stop_ref,binding.registers_ref,
        tuple(_first(o) for o in objects[:2]),tuple(_first(o) for o in objects[2:6]),binding)
    _require(validate_c2_scalars(selected,scalar)==extent,'installed_extent')
    data=ctx.objects(objects,C2_ROLES,(435,348,8,8,8,4,extent.map_size),
        (selected.loaded_base+0x6200,selected.loaded_base+0x1810,selected.size_pointer,selected.key_pointer,
         selected.stride_pointer,selected.version_pointer,selected.map_pointer),True,(0,1))
    epoch=ctx.finish(objects)
    return ctx,data[-1],epoch,bound


def _rows(raw, extent, ref):
    stride=extent.descriptor_stride;n=extent.descriptor_count
    _ref(ref,'epochs/C2/objects/06-first.bin')
    _require(type(raw) is bytes and len(raw)==extent.map_size==ref.length,'map_record_length')
    descriptors=[]
    # One bounded roundtrip buffer, no row/full-map bytes clones.
    roundtrip=bytearray(extent.map_size)
    for ordinal in range(n):
        offset=ordinal*stride
        kind,padding,physical,virtual,pages,attribute=struct.unpack_from('<I4sQQQQ',raw,offset)
        extension=raw[offset+40:offset+stride]
        row=Descriptor(ordinal,RawSlice(ref,offset,stride),kind,padding,physical,virtual,pages,attribute,extension)
        _require(physical%4096==0,'descriptor_alignment')
        _require(pages <= ((1<<64)-physical)//4096,'descriptor_overflow')
        struct.pack_into('<I4sQQQQ',roundtrip,offset,kind,padding,physical,virtual,pages,attribute)
        memoryview(roundtrip)[offset+40:offset+stride]=extension
        descriptors.append(row)
    _require(memoryview(roundtrip)==memoryview(raw),'descriptor_roundtrip')
    order=tuple(sorted(range(n),key=lambda i:(descriptors[i].physical_start,i)))
    end=0
    for i in order:
        row=descriptors[i]
        if row.number_of_pages:
            _require(row.physical_start>=end,'descriptor_overlap')
            end=row.physical_start+row.number_of_pages*4096
    _require(all(row.number_of_pages for row in descriptors),'descriptor_zero_pages','INCOMPLETE')
    return tuple(descriptors),order


def _coverage(ctx, objects, frames, epoch, descriptors, order):
    named=[]
    for f in frames:
        named.append(NamedC2Extent('frame',f.ordinal,None,f.physical,4096,RowRef(epoch,'frames',f.ordinal)))
    flat=0
    for obj in objects:
        for part in obj.parts:
            named.append(NamedC2Extent('object_part',obj.ordinal,part.ordinal,part.physical,part.length,
                                       RowRef(epoch,'parts',flat)))
            flat+=1
    _require(len(named)<=61,'named_extent_bound')
    coverage=[]
    for extent in named:
        ctx.ram(extent.physical,extent.length)
        cursor=extent.physical;end=cursor+extent.length;ordinals=[]
        for ordinal in order:
            row=descriptors[ordinal];finish=row.physical_start+row.number_of_pages*4096
            if finish<=cursor:continue
            _require(row.physical_start<=cursor,'coverage_gap','INCOMPLETE')
            _require(row.type in ADMISSIBLE,'coverage_class','INCOMPLETE')
            ordinals.append(ordinal)
            # Alignment/nonoverlap validated before this list grows: <=1 for
            # an aligned frame, <=2 for a <=2048-byte physical object part.
            _require(len(ordinals)<=(1 if extent.kind=='frame' else 2),'coverage_geometry')
            cursor=min(end,finish)
            if cursor==end:break
        _require(cursor==end,'coverage_gap','INCOMPLETE')
        coverage.append(CoverageRow(extent,tuple(ordinals)))
    return tuple(coverage)


def _encoded_rows(rows,bound):
    # Measure each closed row BEFORE allocating JSON text. The old helper's
    # vector64 limit is preserved: descriptor array256 is sized row-by-row.
    from run0_call_read import _encoded_size
    projected=[];total=3+max(0,len(rows)-1)  # brackets+newline+commas
    for row in rows:
        value=_value(row)
        total+=_encoded_size(value)-1
        _require(total<=bound and total<=MIB,'actual_projection_bound','INCOMPLETE')
        projected.append(value)
    return _canonical(projected)


def project_c2_return(binding, selected_call, extent, objects, partial_walks):
    ctx,raw,epoch,bound=_full_inputs(binding,selected_call,extent,objects,partial_walks)
    descriptors,order=_rows(raw,extent,objects[6].first_ref)
    coverage=_coverage(ctx,objects,partial_walks,epoch,descriptors,order)
    index_bytes=_encoded_rows(descriptors,bound.descriptor_json_bound)
    coverage_bytes=_encoded_rows(coverage,bound.coverage_json_bound)
    return C2ReturnProjection(descriptors,order,coverage,index_bytes,coverage_bytes,
        len(partial_walks),7,sum(len(o.parts) for o in objects),extent.descriptor_count)


def validate_c2_return(binding, selected_call, extent, objects, partial_walks):
    result=project_c2_return(binding,selected_call,extent,objects,partial_walks)
    ctx=_Context(binding,'C2',False)
    ir=_ref(binding.descriptor_index_ref,'map-index.json');cr=_ref(binding.coverage_ref,'coverage.json')
    _require(ctx.get(ir,MIB)==result.descriptor_index_bytes and ctx.get(cr,MIB)==result.coverage_bytes,
             'sealed_projection_bytes')
    return CallMapFacts(extent.selected_call_ref,binding.extent_ref,binding.epoch_ref,objects[6].first_ref,
        ir,cr,result.frame_count,7,result.object_part_count,result.descriptor_count,True,False,False,SCOPE)
