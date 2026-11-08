"""Fixed, prepaid streaming checks for the original call inputs and runtime.

No helper in this module creates a runtime registration or grants live authority.
"""
import ctypes
from dataclasses import dataclass
from types import MappingProxyType
import hashlib
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import stat
import sys
import time

import boot_profile_capture as base
import boot_profile_inputs as entry
import run0_call_budget as budget
import run0_call_capture as capture
import run0_call_session as session
import run0_c0_decode as c0
import run0_host_cpu_witness as witness


deny, incomplete = base.deny, base.incomplete
BUFFER_SIZE = 65536


def _buffer(accounting):
    deny(type(accounting) is budget.ParentAccounting, 'call_verify_accounting')
    accounting.reserve_output(BUFFER_SIZE + 4096)
    return bytearray(BUFFER_SIZE)


def _check_deadline(deadline_ns):
    deny(type(deadline_ns) is int and deadline_ns > 0, 'call_verify_deadline_type')
    incomplete(time.monotonic_ns() < deadline_ns, 'runtime_check_deadline')


def _stream(path, digest, length, scratch, deadline_ns, *, private, archive_name=False):
    """One fixed buffer, stable opened/path identity, and exact digest and size."""
    _check_deadline(deadline_ns)
    deny(type(path) is type(Path()) and type(scratch) is bytearray and len(scratch)==BUFFER_SIZE
         and type(length) is int and 0<=length<=256*1024*1024
         and type(digest) is str and re.fullmatch('[0-9a-f]{64}',digest), 'call_verify_pin')
    if archive_name:
        deny(path.is_absolute() and re.fullmatch(r'[A-Za-z0-9_./+-]+',str(path))
             and '..' not in path.parts,'unsafe_archive_path')
    else:base.safe_path(path)
    if private:
        base.private_regular(path)
        deny(path.resolve()==path,'artifact_path_symlink')
    before=path.lstat()
    deny(stat.S_ISREG(before.st_mode) and before.st_size==length,'pinned_file_size')
    fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        opened=os.fstat(fd)
        identity=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
        deny(identity(before)==identity(opened),'pinned_file_race')
        hasher=hashlib.sha256();view=memoryview(scratch);remaining=length
        while remaining:
            _check_deadline(deadline_ns)
            n=os.readv(fd,[view[:min(len(view),remaining)]])
            incomplete(n>0,'pinned_file_short_read')
            hasher.update(view[:n]);remaining-=n
        deny(os.readv(fd,[view[:1]])==0,'pinned_file_grew')
        after=os.fstat(fd)
        deny(identity(before)==identity(after)==identity(path.lstat()),'pinned_file_changed')
        deny(hasher.hexdigest()==digest,'pinned_file_digest')
        return after
    finally:os.close(fd)


def _arguments(prepared,accounting,deadline_ns):
    deny(type(prepared) is capture.PreparedCallInputs and type(accounting) is budget.ParentAccounting,
         'call_verify_types')
    _check_deadline(deadline_ns)
    deny(type(prepared.inputs) is str and type(prepared.run) is str
         and type(prepared.profile_bytes) is bytes and type(prepared.plan_bytes) is bytes
         and type(prepared.observer_source_bytes) is bytes,'call_verify_prepared_fields')


def _ref(value):
    deny(type(value) is tuple and len(value)==3,'call_runtime_input_ref_shape')
    return capture._ref(dict(zip(capture.REF_KEYS,value)))


def _observer(prepared,accounting,scratch,deadline_ns):
    raw=prepared.observer_source_bytes
    deny(len(raw)<=65536,'call_verify_observer_size')
    accounting.reserve_output(16*len(raw)+8192)
    observer=witness.strict_json(raw,65536)
    deny(type(observer) is dict and set(observer)=={'schema_version','kind','python','sources'}
         and observer['schema_version']==1 and observer['kind']==capture.OBSERVER_KIND
         and type(observer['sources']) is list
         and tuple(r['path'] for r in observer['sources'])==capture.PARENT_SOURCE_NAMES
         and len(set(capture.PARENT_SOURCE_NAMES))==len(capture.PARENT_SOURCE_NAMES),
         'call_capture_source_inventory')
    directory=Path(base.__file__).resolve().parent
    for row in observer['sources']:
        deny(type(row) is dict and set(row)=={'path','length','sha256'}
             and type(row['length']) is int and 1<=row['length']<=1<<20,'call_verify_source_row')
        _stream(directory/row['path'],row['sha256'],row['length'],scratch,deadline_ns,private=False)
    python=Path(sys.executable).resolve(strict=True);row=observer['python']
    deny(type(row) is dict and set(row)=={'path','length','sha256'} and row['path']==str(python)
         and type(row['length']) is int and 0<row['length']<=64<<20,'call_verify_python')
    _stream(python,row['sha256'],row['length'],scratch,deadline_ns,private=False)
    deny(witness.canonical(observer)==raw,'call_verify_observer_canonical')


@dataclass(frozen=True, slots=True, init=False)
class _VerificationState:
    prepared: object
    accounting: object
    plan_bytes: bytes
    profile_bytes: bytes
    observer_bytes: bytes
    prepared_fields: tuple
    abi_blobs: tuple
    prior_blobs: tuple
    abi: object
    runtime: object
    inspection: object
    modules: object
    absences: tuple

    def __init__(self, *args, **kwargs):
        raise TypeError('only the fixed verifier creates this state')


def _freeze(value):
    if type(value) is dict:
        for key in value:value[key]=_freeze(value[key])
        return MappingProxyType(value)
    if type(value) is list:return tuple(_freeze(v) for v in value)
    if type(value) in (MappingProxyType,tuple):return value
    deny(value is None or type(value) in (str,int,bool),'call_verify_json_type')
    return value


class _ChargedBlobs(c0._Blobs):
    def __init__(self, values, accounting, *, parsed_paths=()):
        super().__init__(values);self.accounting=accounting
        deny(type(parsed_paths) is tuple and all(type(path) is str for path in parsed_paths),
             'call_verify_parsed_paths')
        self.parsed_paths=set(parsed_paths)
    def get(self, reference, limit):
        raw=super().get(reference,limit)
        if reference['path'] in self.parsed_paths or reference['path'].endswith('.json'):
            # Roles, not suffixes, decide which referenced bytes can be parsed.
            # Each retrieval may be followed by an independent parse/projection.
            self.accounting.reserve_output(4*session._json_copy_cost(raw))
        return raw


def _discover_parsed_paths(store, prepared):
    # These two authenticated JSON documents name nested documents parsed by
    # the unchanged C0 validators. The store charges before these parses too.
    mapping=witness.strict_json(store.get(_ref(prepared.profile_mapping_ref),witness.REPORT_LIMIT),witness.REPORT_LIMIT)
    previous=witness.strict_json(store.get(_ref(prepared.capability_ref),witness.REPORT_LIMIT),witness.REPORT_LIMIT)
    for reference in (mapping['probe_report_ref'],):
        store.parsed_paths.add(capture._ref(reference)['path'])
    for key in ('profile_ref','argv_ref'):
        reference=capture._ref(previous[key])
        store.parsed_paths.add('prior-cap1/'+reference['path'])


def _state_guard(state,prepared,accounting):
    deny(type(state) is _VerificationState and state.prepared is prepared
         and state.accounting is accounting and state.plan_bytes is prepared.plan_bytes
         and state.profile_bytes is prepared.profile_bytes
         and state.observer_bytes is prepared.observer_source_bytes
         and state.abi_blobs is prepared.abi_blobs and state.prior_blobs is prepared.prior_blobs
         and all(getattr(prepared,name) is value for name,value in state.prepared_fields),
         'call_verify_state_identity')


def validate_call_inputs(prepared, plan, accounting, deadline_ns, *, verification=None):
    _arguments(prepared,accounting,deadline_ns)
    if verification is not None:_state_guard(verification,prepared,accounting)
    deny(type(plan) is dict and plan.get('kind')==capture.PLAN_KIND
         and plan.get('context')=='call' and plan.get('run')==prepared.run
         and plan.get('inputs')==prepared.inputs,'call_runtime_plan_identity')
    deny(len(prepared.plan_bytes)<=witness.REPORT_LIMIT,'call_verify_plan_size')
    accounting.reserve_output(8*len(prepared.plan_bytes)+4096)
    deny(witness.canonical(plan)==prepared.plan_bytes,'call_runtime_plan_bytes')
    scratch=_buffer(accounting)
    _observer(prepared,accounting,scratch,deadline_ns)
    deny(plan['observer_ref']==witness.CaptureEvidence.ref('observer.json',prepared.observer_source_bytes),
         'call_runtime_observer_ref')
    if verification is not None:
        accounting.reserve_output(session._json_copy_cost(prepared.profile_bytes))
        profile=prepared.profile
        for name in ('efi','symbols'):
            ref=profile['inputs'][name]
            _stream(Path(prepared.inputs)/ref['path'],ref['sha256'],ref['length'],scratch,deadline_ns,private=True)
        return verification
    deny(type(prepared.abi_blobs) is tuple and type(prepared.prior_blobs) is tuple,
         'call_verify_blob_inventories')
    count=len(prepared.abi_blobs)+len(prepared.prior_blobs)
    deny(count<=8192,'call_verify_blob_count')
    accounting.reserve_output(8192+2048*count+4*session._json_copy_cost(prepared.profile_bytes))
    profile=prepared.profile
    deny(profile['invocation_profile']==base.VAPIC_OFF_INVOCATION_PROFILE,'call_runtime_profile')
    witness.validate_native_layout(dict(prepared.native_layout))
    parsed_paths=tuple(getattr(prepared,name)[0] for name in capture.PLAN_INPUT_FIELDS)+(prepared.abi_ref[0],'profile.json')
    store=_ChargedBlobs(capture._merge(prepared.abi_blobs,prepared.prior_blobs),accounting,
                        parsed_paths=parsed_paths)
    _discover_parsed_paths(store,prepared)
    manifest=[witness.CaptureEvidence.ref(name,raw) for name,raw in prepared.prior_blobs]
    deny(hashlib.sha256(witness.canonical(manifest)).hexdigest()==plan['prior_inputs_sha256'],
         'call_runtime_input_manifest')
    for name in capture.PLAN_INPUT_FIELDS:
        reference=getattr(prepared,name)
        deny(plan[name]==list(reference),'call_runtime_input_ref')
        store.get(_ref(reference),witness.REPORT_LIMIT)
    deny(prepared.source_persistence_ref[1]==witness.C0_SOURCE_PERSISTENCE_SHA256,
         'call_runtime_persistence_pin')
    efi=prepared.pinned_efi
    symbols=store.get(profile['inputs']['symbols'],base.INPUT_LIMITS['symbols'])
    deny(type(efi) is bytes and capture._bind_caller(_ref(prepared.caller_manifest_ref),store,efi,symbols)
         ==prepared.pinned_caller,'call_runtime_caller_closure')
    for name,raw in (('efi',efi),('symbols',symbols)):
        ref=profile['inputs'][name]
        deny(len(raw)==ref['length'] and hashlib.sha256(raw).hexdigest()==ref['sha256'],
             'call_runtime_held_input')
        _stream(Path(prepared.inputs)/ref['path'],ref['sha256'],ref['length'],scratch,deadline_ns,private=True)
    abi_index=witness.strict_json(store.get(_ref(prepared.abi_ref),witness.REPORT_LIMIT),witness.REPORT_LIMIT)
    accounting.reserve_output(session._pe_copy_bound(efi)+16*65536)
    c0._profile_binding(dict(profile_ref=witness.CaptureEvidence.ref('profile.json',prepared.profile_bytes),
        prior_admission_ref=_ref(prepared.prior_admission_ref),profile_mapping_ref=_ref(prepared.profile_mapping_ref)),store)
    c0._capability_binding(dict(capability_ref=_ref(prepared.capability_ref),source_dossier_ref=abi_index['source_dossier_ref']),store,profile)
    # Parse only the three authenticated runtime indexes needed by both checks.
    blobs=dict(prepared.abi_blobs)
    runtime=_json_blob(abi_index['runtime_dependencies_ref'],blobs,accounting)
    inspection=_json_blob(runtime['inspection_ref'],blobs,accounting)
    incomplete('module_closure_ref' in runtime,'runtime_module_closure_pending')
    deny(runtime['module_closure_ref']['sha256']==witness.MODULE_CLOSURE_SHA256,'module_closure_pin')
    modules=_json_blob(runtime['module_closure_ref'],blobs,accounting)
    absences=tuple(witness.runtime_module_absences(modules,Path(prepared.inputs),profile['invocation_profile']))
    values=dict(prepared=prepared,accounting=accounting,plan_bytes=prepared.plan_bytes,
        profile_bytes=prepared.profile_bytes,observer_bytes=prepared.observer_source_bytes,
        prepared_fields=tuple((name,getattr(prepared,name)) for name in prepared.__dataclass_fields__),
        abi_blobs=prepared.abi_blobs,prior_blobs=prepared.prior_blobs,
        abi=_freeze(abi_index),runtime=_freeze(runtime),inspection=_freeze(inspection),
        modules=_freeze(modules),absences=absences)
    state=object.__new__(_VerificationState)
    for key,value in values.items():object.__setattr__(state,key,value)
    return state


def _freeze_cost(raw):
    # JSON strings and scalar values remain aliases; only immutable-container
    # wrappers, dict/list slots and the final tuple storage are newly allocated.
    deny(type(raw) is bytes and len(raw)<=1<<20,'call_verify_json_bound')
    quoted=escaped=False;containers=entries=0
    for ch in raw:
        if quoted:
            if escaped:escaped=False
            elif ch==92:escaped=True
            elif ch==34:quoted=False
        elif ch==34:quoted=True
        elif ch in (91,123):containers+=1
        elif ch in (58,44):entries+=1
    return 4096+128*containers+16*entries


def _json_blob(ref, blobs, accounting):
    raw=witness.retained_blob(ref,blobs,1024*1024)
    accounting.reserve_output(session._json_copy_cost(raw)+_freeze_cost(raw))
    return witness.strict_json(raw,1024*1024)


def _cleanup_loader(owner):
    """Retry interrupted waits without renewing the original hard deadline."""
    if owner.child is None or owner.reaped:return True
    if owner.ownership_lost:return False
    def wait_until(bound):
        # Bound receipt growth even under a persistent EINTR storm.
        for _ in range(4):
            try:return owner.wait(bound)
            except InterruptedError:
                if time.monotonic()>=owner.deadline:break
        return None
    if wait_until(time.monotonic()) is not None:return True
    if owner.ownership_lost:return False
    owner._signal(signal.SIGTERM,'SIGTERM')
    if wait_until(min(owner.deadline,time.monotonic()+.25)) is not None:return True
    if owner.ownership_lost:return False
    owner._signal(signal.SIGKILL,'SIGKILL')
    wait_until(owner.deadline)
    return owner.reaped and not owner.ownership_lost


def _tool(argv, env, accounting, deadline_ns, scratch):
    """Original static-loader lease and output bound, with incremental prepay."""
    deadline=deadline_ns/1_000_000_000
    incomplete(time.monotonic()+1<deadline,'runtime_check_deadline')
    accounting.reserve_output(8192)
    selector=selectors.DefaultSelector()
    streams={'stdout':bytearray(),'stderr':bytearray()}
    owner=witness.OwnedWait('static_loader',deadline)
    primary=None;cleanup_error=False
    try:
        with witness.defer_cleanup_interrupt() as interrupted:
            started=time.monotonic_ns()
            owner.child=subprocess.Popen(argv,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,start_new_session=True,close_fds=True,umask=0o077)
            owner._receipt('spawn',started,'ok')
        if interrupted[0]:raise KeyboardInterrupt
        for name in streams:
            pipe=getattr(owner.child,name)
            os.set_blocking(pipe.fileno(),False)
            selector.register(pipe,selectors.EVENT_READ,name)
        view=memoryview(scratch)[:4096]
        while selector.get_map():
            incomplete(time.monotonic()<deadline-1,'runtime_check_timeout')
            for key,_ in selector.select(min(.05,max(0,deadline-1-time.monotonic()))):
                try:n=os.readv(key.fd,[view])
                except (BlockingIOError,InterruptedError):continue
                if not n:selector.unregister(key.fileobj);continue
                incomplete(sum(map(len,streams.values()))+n<=witness.MAX_STATIC_OUTPUT,
                           'runtime_check_output_limit')
                accounting.reserve_output(2*n)
                streams[key.data].extend(view[:n])
        incomplete(owner.wait() is not None,'runtime_check_wait_timeout')
    except (base.ProbeError,OSError,KeyboardInterrupt) as error:
        primary=error
    finally:
        with witness.defer_cleanup_interrupt() as interrupted:
            try:cleanup_error=not _cleanup_loader(owner)
            except OSError:cleanup_error=True
            pipes=[owner.child.stdout,owner.child.stderr] if owner.child is not None else []
            for stream in (selector,*pipes):
                try:stream.close()
                except OSError:cleanup_error=True
        if interrupted[0] and primary is None:primary=KeyboardInterrupt()
    if primary is not None:raise primary
    incomplete(owner.reaped and not cleanup_error,'runtime_check_cleanup_incomplete')
    # The final immutable bytes are a distinct allocation from both bytearrays.
    accounting.reserve_output(sum(map(len,streams.values())))
    return owner.returncode,bytes(streams['stdout']),bytes(streams['stderr'])


def _profile_files(prepared,profile,scratch,deadline_ns):
    inputs=Path(prepared.inputs)
    base.safe_path(inputs)
    deny(inputs.resolve()==inputs and inputs.is_dir() and inputs.stat().st_uid==os.getuid()
         and inputs.stat().st_mode & 0o077==0,'inputs_root_not_private')
    try:
        entry.fields(profile,('schema_version','kind','invocation_profile','source_commit',
            'assembled_patch_sha256','diagnostic_image_name','inputs','provenance'),'probe_profile_fields')
        entry.integer(profile['schema_version'],1,1,'schema_version')
        deny(profile['kind']=='boot_profile_probe_inputs_v0','profile_kind')
        base.admission_machine(profile['invocation_profile'])
        deny(type(profile['source_commit']) is str and re.fullmatch('[0-9a-f]{40}',profile['source_commit']), 'source_commit')
        entry.sha(profile['assembled_patch_sha256'],'assembled_patch_sha256')
        deny(type(profile['diagnostic_image_name']) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,120}\.efi',profile['diagnostic_image_name']), 'diagnostic_image_name')
        entry.fields(profile['inputs'],base.INPUT_LIMITS,'probe_input_fields')
        entry.fields(profile['provenance'],base.PROVENANCE_KEYS,'provenance_fields')
        for group,limits in (('inputs',base.INPUT_LIMITS),
                             ('provenance',{k:32*1024*1024 for k in base.PROVENANCE_KEYS})):
            for name,limit in limits.items():
                ref=profile[group][name];entry.validate_ref(ref,limit)
                if group=='inputs':
                    deny(ref['path']==('7z.so' if name=='seven_zip_module' else name),'input_path_identity')
                _stream(inputs/ref['path'],ref['sha256'],ref['length'],scratch,deadline_ns,private=True)
    except entry.AdmissionError as error:
        raise base.ProbeError('DENY',str(error)) from error
    except (entry.UnavailableInput,FileNotFoundError,PermissionError) as error:
        raise base.ProbeError('INCOMPLETE','required_input_unavailable') from error


def recheck_runtime(prepared, accounting, *, verification, expected_identity, deadline_ns, receipts):
    _arguments(prepared,accounting,deadline_ns)
    _state_guard(verification,prepared,accounting)
    deny(receipts is None or (type(receipts) is dict and not receipts),'runtime_receipts_not_empty')
    deny(expected_identity is None or (type(expected_identity) is dict and
         set(expected_identity)=={'device','inode','size'} and
         all(type(v) is int for v in expected_identity.values())), 'call_verify_expected_identity')
    scratch=_buffer(accounting)
    incomplete(sys.platform=='linux' and os.uname().machine=='x86_64' and sys.byteorder=='little'
         and ctypes.sizeof(ctypes.c_void_p)==8 and os.confstr('CS_GNU_LIBC_VERSION')=='glibc 2.39',
         'runtime_native_abi')
    abi=verification.abi;runtime=verification.runtime;inspection=verification.inspection
    modules=verification.modules
    accounting.reserve_output(session._json_copy_cost(prepared.profile_bytes)+16384)
    deny(os.uname().release==runtime['kernel_release']=='6.8.0-142-generic'
         and runtime['libc_version']=='2.39-0ubuntu8.9','runtime_version')
    deny(not os.path.lexists('/etc/ld.so.preload'),'runtime_preload_present')
    for pin in [runtime['loader'],*runtime['libraries']]:
        deny(type(pin['length']) is int and 0<pin['length']<=64*1024*1024,'runtime_file_identity')
        path=Path(pin['path']);deny(str(path.resolve(strict=True))==pin['path'],'runtime_path_retargeted')
        info=_stream(path,pin['sha256'],pin['length'],scratch,deadline_ns,private=False)
        deny(info.st_uid==0 and info.st_mode & 0o022==0,'runtime_file_identity')
    for row in inspection['aliases']:
        deny(str(Path(row['listed_path']).resolve(strict=True))==row['resolved_path'],'runtime_alias_retargeted')
    deny(str(Path(inspection['interpreter']['path']).resolve(strict=True))==runtime['loader']['path'],
         'runtime_interpreter_retargeted')
    profile=prepared.profile
    _profile_files(prepared,profile,scratch,deadline_ns)
    qemu=Path(prepared.inputs)/'qemu'
    info=_stream(qemu,witness.QEMU_SHA256,abi['qemu_ref']['length'],scratch,deadline_ns,private=True)
    deny(info.st_mode & 0o100 != 0,'qemu_executable_identity')
    identity={'device':info.st_dev,'inode':info.st_ino,'size':info.st_size}
    deny(expected_identity is None or identity==expected_identity,'launch_identity_changed')
    env=witness.clean_launch_env(Path(prepared.run))
    code,out,err=_tool([runtime['loader']['path'],'--list',str(qemu)],env,accounting,deadline_ns,scratch)
    deny(code==0 and not err,'runtime_loader_failed')
    accounting.reserve_output(8*len(out)+256*(out.count(b"\n")+1)+4096)
    normalized=witness.parse_loader_aliases(out,inspection['interpreter']['path'])
    deny(normalized==[(r['alias'],r['listed_path']) for r in inspection['aliases']],
         'runtime_loader_alias_changed')
    loader_hash=hashlib.sha256(out).hexdigest()
    normalized_hash=hashlib.sha256(witness.canonical(normalized)).hexdigest()
    absences=list(verification.absences)
    for path in absences:deny(not os.path.lexists(path),'module_injection_path_present')
    accounting.reserve_output(8192+2048*(len(modules['dependencies'])+len(modules['modules'])))
    directory=Path(modules['directory'])
    for target in (directory,Path('/etc'),Path('/var/run/qemu')):
        existing=target.resolve(strict=True)
        for ancestor in (existing,*existing.parents):
            info=ancestor.stat()
            deny(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and info.st_mode & 0o022==0,
                 'module_directory_permissions')
    deny(directory.resolve()==directory and sorted(p.name for p in directory.iterdir())==
         [r['name'] for r in modules['modules']],'module_directory_changed')
    observed=[];raw_listings=[]
    for pin in (*modules['dependencies'],*(r['pin'] for r in modules['modules'])):
        deny(type(pin['length']) is int and 0<pin['length']<=64*1024*1024,'module_file_identity')
        path=Path(pin['path']);deny(str(path.resolve(strict=True))==pin['path'],'module_path_retargeted')
        info=_stream(path,pin['sha256'],pin['length'],scratch,deadline_ns,private=False,archive_name=True)
        deny(info.st_uid==0 and info.st_mode & 0o022==0,'module_file_identity')
        observed.append(dict(pin))
    for row in modules['modules']:
        for alias in row['aliases']:
            deny(str(Path(alias['listed_path']).resolve(strict=True))==alias['resolved_path'],'module_alias_retargeted')
        code,out,err=_tool([runtime['loader']['path'],'--list',row['pin']['path']],env,accounting,deadline_ns,scratch)
        deny(code==0 and not err,'module_loader_failed')
        accounting.reserve_output(8*len(out)+256*(out.count(b"\n")+1)+4096)
        if row['listing_kind']=='statically_linked':
            deny(out==b'\tstatically linked\n','module_listing_changed');normalized=[]
        else:
            normalized=witness.parse_loader_aliases(out,'/lib64/ld-linux-x86-64.so.2',runtime['loader']['path'])
            deny(normalized==[(r['alias'],r['listed_path']) for r in row['aliases']],'module_listing_changed')
        observed.append({'name':row['name'],'aliases':normalized})
        raw_listings.append({'name':row['name'],'sha256':hashlib.sha256(out).hexdigest()})
    if receipts is not None:
        receipts.update(schema_version=1,kind='run0_host_cpu_runtime_recheck_v0',
            runtime_ref=dict(abi['runtime_dependencies_ref']),kernel_release=os.uname().release,
            libc_version=runtime['libc_version'],launch_identity=identity,env=env,
            loader_listing_sha256=loader_hash,normalized_aliases_sha256=normalized_hash,
            module_closure_ref=dict(runtime['module_closure_ref']),
            module_observations_sha256=hashlib.sha256(witness.canonical(observed)).hexdigest(),
            module_raw_listing_sha256=raw_listings,checked_absences=absences)
    return identity
