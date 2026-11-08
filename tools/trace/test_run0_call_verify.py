"""Streaming verifier controls use isolated files and never launch a process."""
from contextlib import ExitStack
import hashlib
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import boot_profile_capture as base
from test_run0_call_budget import memory_ledger
try:
    import run0_call_verify as verify
except ModuleNotFoundError as e:
    if e.name != 'run0_call_verify': raise
    verify=None

class StreamingControls(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(verify,'streaming verifier missing')
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve();self.root.chmod(0o700)
        self.path=self.root/'payload';self.data=b'abc123'*30000
        self.path.write_bytes(self.data);self.path.chmod(0o600)
        self.sha=hashlib.sha256(self.data).hexdigest()
        self.deadline=time.monotonic_ns()+10_000_000_000
    def stream(self,path=None,digest=None,length=None):
        return verify._stream(path or self.path,digest or self.sha,
            len(self.data) if length is None else length,bytearray(65536),self.deadline,private=True)
    def test_fixed_buffer_and_digest_size_denial_then_success(self):
        with patch.object(os,'read',side_effect=AssertionError('whole-file read')):
            self.stream()
        for digest,length in [('0'*64,len(self.data)),(self.sha,len(self.data)-1)]:
            with self.assertRaises(base.ProbeError):self.stream(digest=digest,length=length)
        self.stream()
    def test_symlink_and_public_mode_denial_then_success(self):
        alias=self.root/'alias';alias.symlink_to(self.path)
        with self.assertRaises(base.ProbeError):self.stream(alias)
        self.path.chmod(0o644)
        with self.assertRaises(base.ProbeError):self.stream()
        self.path.chmod(0o600);self.stream()
    def test_mutation_rejected_then_fresh_success(self):
        real=os.readv;done=[]
        def mutate(fd,views):
            n=real(fd,views)
            if n and not done:
                done.append(True);self.path.write_bytes(b'x'*len(self.data))
            return n
        with patch.object(os,'readv',side_effect=mutate):
            with self.assertRaises(base.ProbeError):self.stream()
        self.path.write_bytes(self.data);self.stream()
    def test_wrong_native_types_before_io(self):
        with patch.object(os,'open',side_effect=AssertionError('IO')):
            for fn,args in ((verify.validate_call_inputs,(None,None,None,self.deadline)),
                            (verify.recheck_runtime,(None,None))):
                with self.assertRaises(base.ProbeError):
                    if fn is verify.recheck_runtime:fn(*args,verification=None,expected_identity=None,deadline_ns=self.deadline,receipts={})
                    else:fn(*args)
    def test_budget_failure_before_any_io_then_independent_success(self):
        ledger=memory_ledger()
        with patch.object(type(ledger),'reserve_output',side_effect=base.ProbeError('INCOMPLETE','budget')):
            with patch.object(os,'open',side_effect=AssertionError('unpaid IO')):
                with self.assertRaises(base.ProbeError):verify._buffer(ledger)
        self.assertEqual(len(verify._buffer(memory_ledger())),65536);self.stream()

    def test_recheck_traverses_frozen_runtime_and_emits_receipts(self):
        from types import SimpleNamespace
        import run0_call_capture as capture
        prepared=object.__new__(capture.PreparedCallInputs)
        for name in capture.PreparedCallInputs.__dataclass_fields__:object.__setattr__(prepared,name,object())
        for name,value in dict(inputs=str(self.root),run=str(self.root),profile_bytes=b'{}',plan_bytes=b'{}',
            observer_source_bytes=b'{}',abi_blobs=(),prior_blobs=()).items():object.__setattr__(prepared,name,value)
        ledger=memory_ledger();state=object.__new__(verify._VerificationState)
        ref=dict(path='runtime.json',length=1,sha256='a'*64)
        pin=dict(path='/fixed/lib.so',length=1,sha256='b'*64)
        runtime=dict(kernel_release='6.8.0-142-generic',libc_version='2.39-0ubuntu8.9',
            loader=dict(pin,path='/fixed/loader'),libraries=[],module_closure_ref=ref)
        inspection=dict(aliases=[dict(alias='/fixed/loader',listed_path='/fixed/loader',resolved_path='/fixed/loader')],
            interpreter=dict(path='/fixed/loader'))
        modules=dict(directory='/fixed/modules',dependencies=[pin],modules=[dict(name='m.so',pin=pin,aliases=[],listing_kind='statically_linked')])
        values=dict(prepared=prepared,accounting=ledger,plan_bytes=prepared.plan_bytes,
            profile_bytes=prepared.profile_bytes,observer_bytes=prepared.observer_source_bytes,
            abi_blobs=prepared.abi_blobs,prior_blobs=prepared.prior_blobs,
            prepared_fields=tuple((n,getattr(prepared,n)) for n in capture.PreparedCallInputs.__dataclass_fields__),
            abi=verify._freeze(dict(runtime_dependencies_ref=ref,qemu_ref=dict(length=1))),
            runtime=verify._freeze(runtime),inspection=verify._freeze(inspection),modules=verify._freeze(modules),absences=())
        for name,value in values.items():object.__setattr__(state,name,value)
        info=SimpleNamespace(st_uid=0,st_mode=0o100700,st_dev=1,st_ino=2,st_size=1)
        directory_info=SimpleNamespace(st_uid=0,st_mode=0o40755)
        path_type=type(Path())
        with ExitStack() as stack:
            stack.enter_context(patch.object(verify.sys,'platform','linux'))
            stack.enter_context(patch.object(verify.os,'uname',return_value=SimpleNamespace(machine='x86_64',release='6.8.0-142-generic')))
            stack.enter_context(patch.object(verify.os,'confstr',return_value='glibc 2.39'))
            stack.enter_context(patch.object(verify.os.path,'lexists',return_value=False))
            stack.enter_context(patch.object(path_type,'resolve',lambda p,strict=False:p))
            stack.enter_context(patch.object(path_type,'stat',lambda p,*a,**k:directory_info))
            stack.enter_context(patch.object(path_type,'iterdir',lambda p:iter([Path('m.so')])))
            stack.enter_context(patch.object(verify,'_stream',return_value=info))
            stack.enter_context(patch.object(verify,'_profile_files'))
            stack.enter_context(patch.object(verify.witness,'decode_pinned_profile',return_value={'invocation_profile':'fixture'}))
            stack.enter_context(patch.object(verify.witness,'clean_launch_env',return_value={'HOME':str(self.root)}))
            stack.enter_context(patch.object(verify.witness,'parse_loader_aliases',return_value=[('/fixed/loader','/fixed/loader')]))
            tool=stack.enter_context(patch.object(verify,'_tool',side_effect=[(0,b'dynamic',b''),(0,b'\tstatically linked\n',b'')]))
            receipts={};identity=verify.recheck_runtime(prepared,ledger,verification=state,expected_identity=None,
                deadline_ns=self.deadline,receipts=receipts)
        self.assertEqual(identity,dict(device=1,inode=2,size=1));self.assertEqual(tool.call_count,2)
        self.assertEqual(receipts['kind'],'run0_host_cpu_runtime_recheck_v0')
        self.assertEqual(receipts['module_raw_listing_sha256'][0]['name'],'m.so')

    def test_state_requires_exact_prepared_fields_and_ledger(self):
        import run0_call_capture as capture
        prepared=object.__new__(capture.PreparedCallInputs)
        for name in capture.PreparedCallInputs.__dataclass_fields__:
            object.__setattr__(prepared,name,object())
        ledger=memory_ledger();state=object.__new__(verify._VerificationState)
        fields=dict(prepared=prepared,accounting=ledger,plan_bytes=prepared.plan_bytes,
            profile_bytes=prepared.profile_bytes,observer_bytes=prepared.observer_source_bytes,
            abi_blobs=prepared.abi_blobs,prior_blobs=prepared.prior_blobs,
            prepared_fields=tuple((n,getattr(prepared,n)) for n in capture.PreparedCallInputs.__dataclass_fields__))
        for name,value in fields.items():object.__setattr__(state,name,value)
        verify._state_guard(state,prepared,ledger)
        with self.assertRaises(base.ProbeError):verify._state_guard(state,prepared,memory_ledger())
        old=prepared.pinned_caller;object.__setattr__(prepared,'pinned_caller',object())
        with self.assertRaises(base.ProbeError):verify._state_guard(state,prepared,ledger)
        object.__setattr__(prepared,'pinned_caller',old);verify._state_guard(state,prepared,ledger)

    def test_extensionless_semantic_json_is_prepaid_before_parser(self):
        import run0_host_cpu_witness as witness
        raw=b'{"kind":"same pinned manifest"}'
        digest=hashlib.sha256(raw).hexdigest();ledger=memory_ledger()
        refs=[dict(path=name,length=len(raw),sha256=digest)
              for name in ('prior-caller/manifest.bin','admission/result.bin')]
        store=verify._ChargedBlobs({r['path']:raw for r in refs},ledger,
                                   parsed_paths=tuple(r['path'] for r in refs))
        for ref in refs:
            with patch.object(type(ledger),'reserve_output',side_effect=base.ProbeError('INCOMPLETE','budget')):
                with patch.object(witness,'strict_json',side_effect=AssertionError('unpaid parse')):
                    with self.assertRaises(base.ProbeError):
                        witness.strict_json(store.prepay_json(ref,65536),65536)
        fresh=memory_ledger();store=verify._ChargedBlobs({r['path']:raw for r in refs},fresh,
                                   parsed_paths=tuple(r['path'] for r in refs))
        for ref in refs:self.assertEqual(witness.strict_json(store.prepay_json(ref,65536),65536)['kind'],'same pinned manifest')
        self.assertGreater(fresh.view()['actual_bytes'],0)

    def test_hash_only_json_get_never_spends_parser_credit(self):
        raw=b'{"not":"parsed"}';ref=dict(path='caller/metadata.json',length=len(raw),
            sha256=hashlib.sha256(raw).hexdigest())
        ledger=memory_ledger();store=verify._ChargedBlobs({ref['path']:raw},ledger)
        before=ledger.view()['actual_bytes']
        self.assertIs(store.get(ref,65536),raw)
        self.assertEqual(ledger.view()['actual_bytes'],before)
        store.prepay_json(ref,65536)
        self.assertGreater(ledger.view()['actual_bytes'],before)

    def test_profile_and_capability_helpers_prepay_before_validator_then_fresh(self):
        import run0_call_capture as capture
        raw=b'{"fixture":true}'
        def ref(name):return dict(path=name,length=len(raw),sha256=hashlib.sha256(raw).hexdigest())
        def packed(name):
            r=ref(name);return (name,r['sha256'],r['length'])
        prepared=object.__new__(capture.PreparedCallInputs)
        for name,value in dict(profile_bytes=raw,prior_admission_ref=packed('admission.bin'),
            profile_mapping_ref=packed('mapping.bin'),capability_ref=packed('cap.bin')).items():
            object.__setattr__(prepared,name,value)
        mapping={'probe_report_ref':ref('probe.bin')}
        previous={'profile_ref':ref('profile.bin'),'argv_ref':ref('argv.bin'),
                  'observations':{'layout_ref':ref('layout.bin')}}
        paths=('profile.json','admission.bin','mapping.bin','probe.bin','cap.bin',
               'prior-cap1/profile.bin','prior-cap1/argv.bin','prior-cap1/layout.bin')
        def run_one(which,fail):
            ledger=memory_ledger();store=verify._ChargedBlobs({path:raw for path in paths},ledger)
            target='_profile_binding' if which=='profile' else '_capability_binding'
            with patch.object(verify.c0,target,return_value='accepted') as validator, \
                 patch.object(verify.session,'_pe_copy_bound',return_value=512):
                def call():
                    if which=='profile':return verify._profile_semantics(store,ledger,prepared,mapping,b'fixture')
                    return verify._capability_semantics(store,ledger,prepared,previous,{'source_dossier_ref':ref('source')},{})
                if fail:
                    with patch.object(type(ledger),'reserve_output',side_effect=base.ProbeError('INCOMPLETE','budget')):
                        with self.assertRaises(base.ProbeError):call()
                    validator.assert_not_called()
                else:
                    self.assertEqual(call(),'accepted');validator.assert_called_once()
                    self.assertGreater(ledger.view()['actual_bytes'],0)
        for kind in ('profile','capability'):
            run_one(kind,True);run_one(kind,False)

    def test_nested_parsed_document_roles_do_not_depend_on_suffix(self):
        import json
        import run0_call_capture as capture
        nested=lambda path:dict(path=path,length=1,sha256='a'*64)
        mapping=json.dumps(dict(probe_report_ref=nested('probe/report.bin'))).encode()
        cap=json.dumps(dict(profile_ref=nested('profile.bin'),argv_ref=nested('argv.bin'))).encode()
        ref=lambda path,raw:(path,hashlib.sha256(raw).hexdigest(),len(raw))
        prepared=object.__new__(capture.PreparedCallInputs)
        object.__setattr__(prepared,'profile_mapping_ref',ref('mapping.bin',mapping))
        object.__setattr__(prepared,'capability_ref',ref('prior-cap1/report.bin',cap))
        store=verify._ChargedBlobs({'mapping.bin':mapping,'prior-cap1/report.bin':cap},memory_ledger(),
                                   parsed_paths=('mapping.bin','prior-cap1/report.bin'))
        verify._discover_parsed_paths(store,prepared)
        self.assertTrue({'probe/report.bin','prior-cap1/profile.bin','prior-cap1/argv.bin'} <= store.parsed_paths)

    def test_profile_streams_every_input_and_provenance(self):
        import run0_call_capture as capture
        profile=dict(schema_version=1,kind='boot_profile_probe_inputs_v0',
            invocation_profile=base.VAPIC_OFF_INVOCATION_PROFILE,source_commit='a'*40,
            assembled_patch_sha256='b'*64,diagnostic_image_name='test.efi',inputs={},provenance={})
        for group,names in (('inputs',base.INPUT_LIMITS),('provenance',base.PROVENANCE_KEYS)):
            for name in names:
                filename=('7z.so' if name=='seven_zip_module' else name) if group=='inputs' else 'prov_'+name
                data=(group+name).encode('ascii');path=self.root/filename;path.write_bytes(data);path.chmod(0o600)
                profile[group][name]=dict(path=filename,length=len(data),sha256=hashlib.sha256(data).hexdigest())
        prepared=object.__new__(capture.PreparedCallInputs);object.__setattr__(prepared,'inputs',str(self.root))
        verify._profile_files(prepared,profile,bytearray(65536),self.deadline)
        victim=self.root/profile['provenance'][base.PROVENANCE_KEYS[-1]]['path']
        original=victim.read_bytes();victim.write_bytes(b'x'*len(original))
        with self.assertRaises(base.ProbeError):verify._profile_files(prepared,profile,bytearray(65536),self.deadline)
        victim.write_bytes(original)
        verify._profile_files(prepared,profile,bytearray(65536),self.deadline)

    def test_observer_pins_python_and_closed_source_inventory(self):
        import run0_call_capture as capture
        import run0_host_cpu_witness as witness
        source=self.root/'source.py';source.write_bytes(b'source bytes')
        python=self.root/'python';python.write_bytes(b'python bytes')
        row=lambda path:dict(path=path.name,length=path.stat().st_size,
                             sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        value=dict(schema_version=1,kind=capture.OBSERVER_KIND,python=dict(row(python),path=str(python)),
                   sources=[row(source)])
        prepared=object.__new__(capture.PreparedCallInputs)
        object.__setattr__(prepared,'observer_source_bytes',witness.canonical(value))
        with patch.object(capture,'PARENT_SOURCE_NAMES',('source.py',)), \
             patch.object(base,'__file__',str(self.root/'base.py')), \
             patch.object(verify.sys,'executable',str(python)):
            verify._observer(prepared,memory_ledger(),bytearray(65536),self.deadline)
            source.write_bytes(b'altered data')
            with self.assertRaises(base.ProbeError):
                verify._observer(prepared,memory_ledger(),bytearray(65536),self.deadline)
            source.write_bytes(b'source bytes')
            python.write_bytes(b'altered data')
            with self.assertRaises(base.ProbeError):
                verify._observer(prepared,memory_ledger(),bytearray(65536),self.deadline)
            python.write_bytes(b'python bytes')
            verify._observer(prepared,memory_ledger(),bytearray(65536),self.deadline)

    def loader_fixture(self, *, fail_growth=False, fail_read=False):
        from contextlib import ExitStack
        from types import SimpleNamespace
        class Pipe:
            def __init__(self,fd):self.fd=fd;self.closed=False
            def fileno(self):return self.fd
            def close(self):self.closed=True
        class FakeSelector:
            def __init__(self):self.keys={};self.closed=False
            def register(self,pipe,event,name):self.keys[pipe.fileno()]=SimpleNamespace(fd=pipe.fileno(),data=name,fileobj=pipe)
            def unregister(self,pipe):del self.keys[pipe.fileno()]
            def get_map(self):return self.keys
            def select(self,timeout):return [(next(iter(self.keys.values())),1)]
            def close(self):self.closed=True
        class Owner:
            def __init__(self,*args):self.child=None;self.reaped=False;self.ownership_lost=False;self.returncode=None;self.deadline=time.monotonic()+10;self.terminated=False
            def _receipt(self,*args):pass
            def wait(self,*args):self.reaped=True;self.returncode=0;return 0
            def _signal(self,*args):self.terminated=True
        selector=FakeSelector();owner=Owner();proc=SimpleNamespace(stdout=Pipe(10),stderr=Pipe(11))
        chunks=[BlockingIOError(),b'ab',b'c',b'',b'']
        def readv(fd,views):
            if fail_read:raise OSError('read error')
            item=chunks.pop(0)
            if isinstance(item,BaseException):raise item
            views[0][:len(item)]=item;return len(item)
        ledger=memory_ledger();real=type(ledger).reserve_output;amounts=[]
        def reserve(obj,amount):
            amounts.append(amount)
            if fail_growth and len(amounts)==2:raise base.ProbeError('INCOMPLETE','growth budget')
            return real(obj,amount)
        with ExitStack() as stack:
            spawn=stack.enter_context(patch.object(verify.subprocess,'Popen',return_value=proc))
            stack.enter_context(patch.object(verify.selectors,'DefaultSelector',return_value=selector))
            stack.enter_context(patch.object(verify.witness,'OwnedWait',return_value=owner))
            stack.enter_context(patch.object(verify.os,'set_blocking'))
            reader=stack.enter_context(patch.object(verify.os,'readv',side_effect=readv))
            stack.enter_context(patch.object(type(ledger),'reserve_output',reserve))
            if fail_growth or fail_read:
                with self.assertRaises((base.ProbeError,OSError)):
                    verify._tool(['/fixed/loader','--list','/fixed/target'],{},ledger,self.deadline,bytearray(65536))
            else:
                self.assertEqual(verify._tool(['/fixed/loader','--list','/fixed/target'],{},ledger,self.deadline,bytearray(65536)),(0,b'abc',b''))
            spawn.assert_called_once();self.assertTrue(owner.reaped)
            self.assertTrue(selector.closed and proc.stdout.closed and proc.stderr.closed)
            if fail_growth:self.assertEqual(amounts,[8192,4])
            if not (fail_growth or fail_read):
                self.assertEqual(amounts,[8192,4,2,3]);self.assertEqual(reader.call_count,5)

    def test_interrupted_cleanup_wait_retries_and_preserves_primary(self):
        from types import SimpleNamespace
        owner=verify.witness.OwnedWait('static_loader',time.monotonic()+5)
        owner.child=SimpleNamespace(pid=123456,returncode=None)
        with patch.object(verify.os,'waitpid',side_effect=[InterruptedError(),(123456,0)]) as wait, \
             patch.object(verify.os,'killpg',side_effect=AssertionError('unneeded signal')):
            self.assertTrue(verify._cleanup_loader(owner))
        self.assertTrue(owner.reaped);self.assertEqual(wait.call_count,2)
        self.loader_fixture(fail_read=True);self.loader_fixture()

    def test_static_loader_fragmentation_eagain_and_actual_prepayment(self):
        self.loader_fixture()

    def test_static_loader_growth_refusal_and_io_error_cleanup(self):
        self.loader_fixture(fail_growth=True);self.loader_fixture(fail_read=True);self.loader_fixture()

if __name__=='__main__':unittest.main()
