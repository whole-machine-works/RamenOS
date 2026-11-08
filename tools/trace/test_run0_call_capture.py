"""Parent preparation controls; private synthetic inputs confer no live origin."""
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import boot_profile_capture as base
import run0_call_decode as pure
import run0_host_cpu_witness as witness
from test_run0_call_decode import CALLER, HELPER

try:
    import run0_call_capture as capture
except ModuleNotFoundError as error:
    if error.name != 'run0_call_capture':
        raise
    capture = None


def raw_json(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'))+'\n').encode()


def fixture():
    code=bytearray(23000)
    code[22016:22016+435]=CALLER
    code[0xc10:0xc10+348]=HELPER
    efi=bytes(code)
    symbols=b'private synthetic symbols, not the accepted executable input'
    rows=[]
    blobs={}
    for name,raw in (('caller-code.bin',CALLER),('guest-helper-code.bin',HELPER),
                     ('source-record.json',b'{"private":"static evidence"}\n')):
        rows.append({'path':name,'sha256':hashlib.sha256(raw).hexdigest(),'length':len(raw)})
        blobs['prior-caller/'+name]=raw
    manifest={'efi_sha256':hashlib.sha256(efi).hexdigest(),
        'pdb_sha256':hashlib.sha256(symbols).hexdigest(),'pdb_guid':pure.GUID,'pdb_age':1,
        'caller':{'rva_start':0x6200,'rva_end_exclusive':0x63b3,'length':435,
            'file_offset':22016,'call_rva':0x634d,'return_rva':0x6350,
            'code_sha256':pure.CALLER_HASH},
        'guest_helper':{'rva_start':0x1810,'rva_end_exclusive':0x196c,'length':348,
            'scratch_rva':0x7f998,'scratch_source_size':32768},'artifacts':rows}
    raw=raw_json(manifest)
    ref={'path':'prior-caller/manifest.json','sha256':hashlib.sha256(raw).hexdigest(),'length':len(raw)}
    blobs[ref['path']]=raw
    return efi,symbols,ref,blobs


class PreparationControls(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(capture,'parent preparation missing: expected RED')

    def binding(self,changes=None):
        efi,symbols,ref,blobs=fixture()
        if changes:
            changes(ref,blobs)
        with patch.object(capture,'CALLER_MANIFEST_SHA256',ref['sha256']), \
             patch.object(pure,'EFI_HASH',hashlib.sha256(efi).hexdigest()), \
             patch.object(pure,'PDB_HASH',hashlib.sha256(symbols).hexdigest()):
            store=capture.decoder._Blobs(blobs)
            result=capture._bind_caller(ref,store,efi,symbols)
        return result,store

    def test_cap01_prepared_is_closed_and_not_old_c0_or_copied_json(self):
        with self.assertRaises(TypeError):
            capture.PreparedCallInputs(origin='owned')
        for value in ({'kind':'run0_call_owned_capture_plan_v0'},None,object()):
            with self.assertRaises(base.ProbeError):
                capture.require_call_runtime_registration(value,{})

    def test_cap02_actual_static_closure_preserves_manifest_and_code(self):
        pinned,store=self.binding()
        self.assertEqual(pinned.caller_code,CALLER)
        self.assertEqual(pinned.helper_code,HELPER)
        self.assertEqual(len(store.verified),4)
        self.assertEqual(pinned.manifest_ref.path,'prior-caller/manifest.json')

    def test_cap03_manifest_and_artifact_mutations_refused_then_fresh_success(self):
        for mutation in (
            lambda ref,blobs:blobs.pop('prior-caller/source-record.json'),
            lambda ref,blobs:blobs.__setitem__('prior-caller/caller-code.bin',b'X'*435),
            lambda ref,blobs:blobs.__setitem__(ref['path'],blobs[ref['path']]+b' ')):
            with self.assertRaises((base.ProbeError,pure.C0DecodeError)):
                self.binding(mutation)
            self.binding()

    def test_cap04_reviewed_manifest_pin_cannot_be_replaced_by_coherent_input(self):
        efi,symbols,ref,blobs=fixture()
        with self.assertRaises(base.ProbeError) as error:
            capture._bind_caller(ref,capture.decoder._Blobs(blobs),efi,symbols)
        self.assertEqual(error.exception.reason,'call_capture_caller_manifest_pin')

    def test_cap05_output_collision_is_closed_for_all_parent_names(self):
        for name in ('epochs/C0/epoch.json','epochs/C2/objects/06-first.bin',
            'operations/0001-request.bin','memory/read-000.bin','map-extent.json',
            'selected-call.json','parent.json','plan.json','vars.fd','qmp.bin'):
            self.assertTrue(capture._output_name(name),name)
        self.assertFalse(capture._output_name('prior-caller/caller-code.bin'))
        self.assertFalse(capture._output_name('prior-cap1/report.json'))

    def test_cap06_blob_bounds_checked_before_copy_and_conflicting_alias_denied(self):
        with self.assertRaises((base.ProbeError,pure.C0DecodeError)):
            capture._snapshot_blobs({'a':bytearray(b'x')})
        with self.assertRaises(base.ProbeError):
            capture._merge((('a',b'one'),),(('a',b'two'),))
        self.assertEqual(capture._snapshot_blobs({'a':b'one'}),(('a',b'one'),))

    def test_cap07_default_runtime_denies_before_any_output_or_spawn(self):
        with tempfile.TemporaryDirectory() as folder:
            run=Path(folder)/'not-created'
            value=object.__new__(capture.PreparedCallInputs)
            with patch.object(capture.subprocess,'Popen',side_effect=AssertionError('spawn')) as spawn:
                with self.assertRaises(base.ProbeError):
                    capture.run_call_capture(value,run)
            spawn.assert_not_called()
            self.assertFalse(run.exists())


    def test_cap08_public_owner_and_registration_constructors_are_unavailable(self):
        for cls in (capture.ClosedOwnedCallRegistration,capture.RegisteredCurrentEpochBinding,
                    capture.BoundCallTarget,capture._OwnedCallRuntime):
            with self.assertRaises(TypeError):
                cls()
        self.assertFalse(capture._issued_call_registration({},object()))

    def prepare_fixture(self, root):
        from test_run0_c0_decode import full_fixture
        from test_run0_host_cpu_reader import fixture as abi_fixture
        report,_,blobs,_,_=full_fixture(root,base.VAPIC_OFF_INVOCATION_PROFILE)
        host=json.loads(blobs['host-report.json'])
        profile=json.loads(blobs['profile.json'])
        original_plan=json.loads(blobs[host['plan_ref']['path']])
        caller_ref={'path':'prior-caller/manifest.json',
            'sha256':hashlib.sha256(b'private static caller fixture').hexdigest(),'length':29}
        blobs[caller_ref['path']]=b'private static caller fixture'
        pinned=pure.PinnedCaller(pure.BlobRef(**caller_ref),pure.EFI_HASH,pure.PDB_HASH,
                                 pure.GUID,1,CALLER,HELPER)
        values=(original_plan,profile,blobs['profile.json'],b'old reset observer',
                host['abi_ref'],dict(blobs),dict(witness.NATIVE_LAYOUT),abi_fixture()[0])
        files={key:blobs[profile['inputs'][key]['path']] for key in ('efi','symbols')}
        args=dict(prior_admission_ref=report['prior_admission_ref'],
            profile_mapping_ref=report['profile_mapping_ref'],capability_ref=report['capability_ref'],
            source_persistence_ref=host['source_ref'],caller_manifest_ref=caller_ref,prior_blobs=blobs)
        def caller(reference,store,efi,symbols):
            store.get(reference,witness.REPORT_LIMIT)
            return pinned
        return values,args,files,caller

    def test_cap09_static_preparation_freezes_explicit_abi_and_caller_without_outputs(self):
        with tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
            root=Path(folder).resolve()
            values,args,files,caller=self.prepare_fixture(root)
            stack.enter_context(patch.object(witness,'prepare_launch',return_value=values))
            stack.enter_context(patch.object(witness,'read_exact',side_effect=lambda path,*_:files[path.name]))
            stack.enter_context(patch.object(witness,'C0_SOURCE_PERSISTENCE_SHA256',
                                             args['source_persistence_ref']['sha256']))
            stack.enter_context(patch.object(capture,'parent_observer_source_bytes',return_value=b'closed parent observer'))
            bound=stack.enter_context(patch.object(capture,'_bind_caller',side_effect=caller))
            spawn=stack.enter_context(patch.object(capture.subprocess,'Popen',side_effect=AssertionError('spawn')))
            run=root/'new-parent'
            result=capture.prepare_call_inputs(root/'inputs',run,root/'source.json',root/'abi.json',**args)
            self.assertIs(type(result),capture.PreparedCallInputs)
            self.assertEqual(result.plan['context'],'call')
            self.assertEqual(result.plan['kind'],'run0_same_call_map_plan_v1')
            self.assertIn(result.abi_ref[0],dict(result.prior_blobs))
            self.assertIn(result.caller_manifest_ref[0],dict(result.prior_blobs))
            self.assertEqual(result.plan['caller_manifest_ref'],list(result.caller_manifest_ref))
            snapshot=result.prior_blobs
            args['prior_blobs'].clear()
            self.assertEqual(result.prior_blobs,snapshot)
            plan=result.plan
            plan['context']='c0'
            self.assertEqual(result.plan['context'],'call')
            bound.assert_called_once()
            spawn.assert_not_called()
            self.assertFalse(run.exists())

    def test_cap11_static_readiness_and_public_delegation_before_vm(self):
        import run0_call_runtime as runtime
        from run0_call_budget import ParentAccounting
        with tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
            root=Path(folder).resolve();values,args,files,caller=self.prepare_fixture(root)
            values[0]['inputs']=str(root/'inputs');values[0]['run']=str(root/'new-parent')
            stack.enter_context(patch.object(witness,'prepare_launch',return_value=values))
            stack.enter_context(patch.object(witness,'read_exact',side_effect=lambda path,*_:files[path.name]))
            stack.enter_context(patch.object(witness,'C0_SOURCE_PERSISTENCE_SHA256',args['source_persistence_ref']['sha256']))
            stack.enter_context(patch.object(capture,'parent_observer_source_bytes',return_value=b'closed parent observer'))
            stack.enter_context(patch.object(capture,'_bind_caller',side_effect=caller))
            result=capture.prepare_call_inputs(root/'inputs',root/'new-parent',root/'source.json',root/'abi.json',**args)
            plan=result.plan
            capture.require_call_runtime_registration(result,plan)
            held=runtime._freeze_plan(plan,ParentAccounting(time.monotonic_ns()))
            capture.require_call_runtime_registration(result,held)
            from collections.abc import Mapping
            from types import MappingProxyType
            calls=[]
            class Foreign(Mapping):
                def __getitem__(self,key): calls.append(key);raise AssertionError('callback')
                def __iter__(self): calls.append('iter');raise AssertionError('callback')
                def __len__(self): calls.append('len');raise AssertionError('callback')
            with self.assertRaises(base.ProbeError):
                capture.require_call_runtime_registration(result,MappingProxyType(Foreign()))
            self.assertEqual(calls,[])
            class Key:
                def __hash__(self):return hash('kind')
                def __eq__(self,other): calls.append('eq');raise AssertionError('callback')
            with self.assertRaises(base.ProbeError):
                capture.require_call_runtime_registration(result,{Key():1})
            self.assertEqual(calls,[])
            capture.require_call_runtime_registration(result,held)
            for mutation in ('kind','context','run','inputs','caller_manifest_ref'):
                bad=dict(plan);bad[mutation]='wrong'
                with self.assertRaises(base.ProbeError):capture.require_call_runtime_registration(result,bad)
            bad=dict(plan);bad['argv']=['changed despite matching identity']
            # The original ledger-backed verifier checks canonical bytes before IO.
            with patch.object(os,'open',side_effect=AssertionError('unexpected IO')):
                with self.assertRaises(base.ProbeError):
                    runtime._validate_call_runtime_inputs(result,bad,ParentAccounting(time.monotonic_ns()),
                                                          time.monotonic_ns()+10_000_000_000)
            # Repeated readiness remains cheap; the initial ledger-backed
            # verifier still rejects malformed prior inventory before outputs.
            import run0_call_verify as verify
            old_blobs=result.prior_blobs
            object.__setattr__(result,'prior_blobs',(('bad',object()),))
            capture.require_call_runtime_registration(result,held)
            with patch.object(verify,'_observer',return_value=None), \
                 patch.object(os,'open',side_effect=AssertionError('unexpected IO')):
                with self.assertRaises(base.ProbeError):
                    runtime._validate_call_runtime_inputs(result,plan,ParentAccounting(time.monotonic_ns()),
                                                          time.monotonic_ns()+10_000_000_000)
            object.__setattr__(result,'prior_blobs',old_blobs)
            capture.require_call_runtime_registration(result,held)
            old=result.caller_manifest_ref
            object.__setattr__(result,'caller_manifest_ref',('prior-caller/manifest.json',True,1))
            with self.assertRaises(base.ProbeError) as error:
                capture.run_call_capture(result,root/'new-parent')
            self.assertEqual(error.exception.status,'DENY')
            object.__setattr__(result,'caller_manifest_ref',old)
            capture.require_call_runtime_registration(result,held)
            with patch.object(runtime,'_run_call_capture',None):
                with self.assertRaises(base.ProbeError) as error:
                    capture.run_call_capture(result,root/'new-parent')
                self.assertEqual(error.exception.status,'INCOMPLETE')
            with patch.object(runtime,'_run_call_capture',return_value='static delegate') as delegate, \
                 patch.object(capture.PreparedCallInputs,'plan',property(lambda _: (_ for _ in ()).throw(AssertionError('early parse')))), \
                 patch.object(capture.subprocess,'Popen',side_effect=AssertionError('VM')), \
                 patch.object(Path,'mkdir',side_effect=AssertionError('output mutation')):
                self.assertEqual(capture.run_call_capture(result,root/'new-parent'),'static delegate')
                delegate.assert_called_once_with(result,root/'new-parent')
            self.assertFalse((root/'new-parent').exists())

    def test_cap12_uninitialized_foreign_and_flags_deny_before_effect(self):
        import run0_call_runtime as runtime
        from run0_c0_capture import PreparedC0Inputs
        candidates=(object.__new__(capture.PreparedCallInputs),None,object(),
                    {'origin':'native','admitted':True},object.__new__(PreparedC0Inputs))
        for value in candidates:
            with patch.object(runtime,'_run_call_capture',side_effect=AssertionError('early delegation')), \
                 patch.object(capture.subprocess,'Popen',side_effect=AssertionError('VM')), \
                 patch.object(Path,'mkdir',side_effect=AssertionError('output mutation')):
                with self.assertRaises(base.ProbeError) as error:
                    capture.run_call_capture(value,Path('/tmp/not-created'))
                self.assertEqual(error.exception.status,'DENY')

    def test_cap10_observer_uses_frozen_parent_identity_and_closed_sources(self):
        base={'schema_version':1,'kind':'old reset source','python':
              {'path':'/fixture/python','sha256':'f'*64,'length':1},'sources':[]}
        with patch.object(witness,'observer_source_bytes',return_value=raw_json(base)), \
             patch.object(witness,'_read_regular',return_value=(b'pass\n',None)):
            observer=json.loads(capture.parent_observer_source_bytes())
        self.assertEqual(observer['kind'],'run0_same_call_map_observer_source_v1')
        self.assertEqual(tuple(row['path'] for row in observer['sources']),capture.PARENT_SOURCE_NAMES)
        self.assertIn('run0_call_runtime.py',capture.PARENT_SOURCE_NAMES)


class ImmutableInventoryControls(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(capture)
        self.folder=tempfile.TemporaryDirectory(prefix='call-inventory-')
        self.addCleanup(self.folder.cleanup)
        self.root=Path(self.folder.name).resolve()
        from run0_call_budget import ParentAccounting
        self.ledger=ParentAccounting(time.monotonic_ns())

    def inventory(self):
        return capture.RootRawInventory(self.root,self.ledger)

    def test_inv01_actual_seal_has_exact_held_ref_and_bytes(self):
        inventory=self.inventory()
        raw=b'actual sealed extent record\n'
        ref=inventory.put('map-extent.json',raw)
        self.assertEqual((self.root/ref.path).read_bytes(),raw)
        inventory.require_exact(ref,raw)
        equal=pure.BlobRef(ref.path,ref.sha256,ref.length)
        with self.assertRaises(base.ProbeError):
            inventory.require_exact(equal,raw)
        self.assertEqual(inventory.rows()[0]['state'],'complete')

    def test_inv02_unknown_and_out_of_range_paths_refuse_before_write(self):
        inventory=self.inventory()
        for name in ('../outside','epochs/C3/epoch.json','epochs/C2/objects/07-first.bin',
            'epochs/C0/frames/32-first.bin','operations/0000-request.bin',
            'operations/1025-response.bin','memory/read-506.bin','map-translation-plan.json'):
            before=self.ledger.view()['committed_bytes']
            with self.assertRaises(base.ProbeError):inventory.put(name,b'x')
            self.assertEqual(self.ledger.view()['committed_bytes'],before)
        self.assertEqual(list(self.root.iterdir()),[])

    def test_inv03_duplicate_cannot_replace_actual_file_or_held_identity(self):
        inventory=self.inventory()
        ref=inventory.put('epochs/C0/stop.bin',b'stop')
        with self.assertRaises(base.ProbeError):inventory.put(ref.path,b'changed')
        self.assertEqual((self.root/ref.path).read_bytes(),b'stop')
        self.assertIs(inventory._slots[ref.path].ref,ref)

    def test_inv04_capacity_refuses_before_directory_or_file_creation(self):
        from run0_call_budget import REGULAR_BYTES
        inventory=self.inventory()
        self.ledger.reserve_output(REGULAR_BYTES-self.ledger._regular)
        with self.assertRaises(base.ProbeError):
            inventory.put('epochs/C2/objects/06-first.bin',b'map')
        self.assertEqual(list(self.root.iterdir()),[])

    def test_inv05_partial_write_is_hashed_and_cannot_be_success_evidence(self):
        inventory=self.inventory()
        original=OSError(28,'private injected write exhaustion')
        def partial(name,data):
            path=self.root/name
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            try:os.write(fd,data[:3])
            finally:os.close(fd)
            raise original
        with patch.object(capture.RootRawInventory,'_write_file',side_effect=partial):
            with self.assertRaises(OSError) as result:
                inventory.put('epochs/C0/frames/00-first.bin',b'abc'+b'd'*4093)
        self.assertIs(result.exception,original)
        row=inventory.rows()[0]
        self.assertEqual((row['length'],row['sha256'],row['state']),
                         (3,hashlib.sha256(b'abc').hexdigest(),'incomplete_write'))
        slot=inventory._slots[row['path']]
        with self.assertRaises(base.ProbeError):inventory.require_exact(slot.ref,b'abc')
        with tempfile.TemporaryDirectory() as fresh:
            from run0_call_budget import ParentAccounting
            next_inventory=capture.RootRawInventory(Path(fresh).resolve(),ParentAccounting(time.monotonic_ns()))
            raw=b'f'*4096
            ref=next_inventory.put('epochs/C0/frames/00-first.bin',raw)
            next_inventory.require_exact(ref,raw)

    def test_inv06_failure_retention_uses_prepaid_metadata_at_full_regular_pool(self):
        from run0_call_budget import REGULAR_BYTES
        inventory=self.inventory()
        self.ledger.reserve_output(REGULAR_BYTES-self.ledger._regular)
        raw=b'{"status":"INCOMPLETE"}\n'
        ref=inventory.put('failure-details.json',raw)
        self.assertEqual(ref.length,len(raw))
        self.assertEqual(self.ledger._terminal['failure'],len(raw))

    def test_inv07_final_tracked_file_audit_detects_later_mutation(self):
        inventory=self.inventory()
        ref=inventory.put('map-extent.json',b'original')
        inventory.audit()
        (self.root/ref.path).write_bytes(b'mutation')
        with self.assertRaises(base.ProbeError):inventory.audit()
        with tempfile.TemporaryDirectory() as fresh:
            from run0_call_budget import ParentAccounting
            successor=capture.RootRawInventory(Path(fresh).resolve(),ParentAccounting(time.monotonic_ns()))
            successor.put('map-extent.json',b'original')
            successor.audit()

    def test_inv08_path_derived_caps_refuse_before_allocation_or_file_effects(self):
        inventory=self.inventory()
        for name,raw in (('memory/read-000.bin',b'x'*2049),
            ('epochs/C0/frames/00-first.bin',b'x'*4095),
            ('epochs/C2/objects/05-first.bin',b'x'*8),
            ('epochs/C1/objects/03-first.bin',b'x'*436),
            ('epochs/C0/objects/03-first.bin',b'x'*41),
            ('epochs/C1/hmp-before.txt',b'x'*65537),
            ('epochs/C0/host/peer.bin',b'x'*11),
            ('epochs/C2/host/sigchld-open.bin',b'x'*151)):
            before=dict(self.ledger.view())
            with self.assertRaises(base.ProbeError):inventory.put(name,raw)
            self.assertEqual(dict(self.ledger.view()),before)
        self.assertEqual(list(self.root.iterdir()),[])
        inventory.put('memory/read-000.bin',b'x'*2048)
        inventory.put('epochs/C0/frames/00-first.bin',b'x'*4096)
        inventory.put('epochs/C2/objects/05-first.bin',b'1234')
        inventory.audit()

    def test_inv09_measurement_cleanup_preserves_original_failure_and_records_close_error(self):
        inventory=self.inventory()
        original=OSError(5,'injected fsync failure')
        close=os.close
        calls=[]
        def cleanup(fd):
            close(fd);calls.append(fd)
            if len(calls)==1:raise OSError(9,'injected close failure after actual close')
        with patch.object(capture.os,'fsync',side_effect=original), \
             patch.object(capture.os,'close',side_effect=cleanup):
            with self.assertRaises(OSError) as caught:
                inventory.put('map-extent.json',b'failed flush')
        self.assertIs(caught.exception,original)
        self.assertEqual(inventory._close_errors['map-extent.json'],(1,'OSError',9,'OSError',9))
        self.assertEqual(inventory.rows()[0]['state'],'incomplete_write')

    def test_inv10_control_preserves_registered_two_mib_exception(self):
        for size in ((1 << 20)+1, 2 << 20):
            capture._output_size('control.json',size)
        with self.assertRaises(base.ProbeError):
            capture._output_size('control.json',(2 << 20)+1)
        with self.assertRaises(base.ProbeError):
            capture._output_size('map-extent.json',(1 << 20)+1)

    def test_inv11_rejected_parent_never_measures_or_indexes_outside_file(self):
        inventory=self.inventory()
        with tempfile.TemporaryDirectory() as folder:
            outside=Path(folder).resolve()
            (outside/'C0').mkdir(mode=0o700)
            (outside/'C0'/'stop.bin').write_bytes(b'outside')
            (self.root/'epochs').symlink_to(outside,target_is_directory=True)
            with patch.object(capture.os,'readv',side_effect=AssertionError('outside read')) as read, \
                 patch.object(capture.RootRawInventory,'_write_file',side_effect=AssertionError('outside write')) as write:
                with self.assertRaisesRegex(base.ProbeError,'call_inventory_private_directory'):
                    inventory.put('epochs/C0/stop.bin',b'longer intended source')
            read.assert_not_called();write.assert_not_called()
            self.assertEqual(inventory.rows(),())
            self.assertEqual((outside/'C0'/'stop.bin').read_bytes(),b'outside')
        with tempfile.TemporaryDirectory() as folder:
            from run0_call_budget import ParentAccounting
            fresh=capture.RootRawInventory(Path(folder).resolve(),ParentAccounting(time.monotonic_ns()))
            data=b'fresh actual stop'
            ref=fresh.put('epochs/C0/stop.bin',data)
            fresh.require_exact(ref,data);fresh.audit()

    def test_inv12_audit_rechecks_parent_chain_before_any_read(self):
        inventory=self.inventory()
        inventory.put('epochs/C0/stop.bin',b'owned')
        with tempfile.TemporaryDirectory() as folder:
            outside=Path(folder).resolve()
            (outside/'C0').mkdir(mode=0o700)
            (outside/'C0'/'stop.bin').write_bytes(b'other')
            (self.root/'epochs').rename(self.root/'moved')
            (self.root/'epochs').symlink_to(outside,target_is_directory=True)
            with patch.object(capture.os,'readv',side_effect=AssertionError('outside read')) as read:
                with self.assertRaisesRegex(base.ProbeError,'call_inventory_private_directory'):
                    inventory.audit()
            read.assert_not_called()

    def test_inv13_replaced_root_identity_refuses_before_file_effects(self):
        root=self.root/'nested-root';root.mkdir(mode=0o700)
        inventory=capture.RootRawInventory(root,self.ledger)
        root.rename(self.root/'original-root')
        root.mkdir(mode=0o700)
        with patch.object(capture.os,'readv',side_effect=AssertionError('replacement read')) as read, \
             patch.object(capture.RootRawInventory,'_write_file',side_effect=AssertionError('replacement write')) as write:
            with self.assertRaisesRegex(base.ProbeError,'call_inventory_private_root'):
                inventory.put('map-extent.json',b'actual extent')
        read.assert_not_called();write.assert_not_called()
        self.assertEqual(list(root.iterdir()),[])

    def test_inv14_unbuffered_short_write_retains_prefix_and_no_false_completion(self):
        inventory=self.inventory();write=os.write
        calls=[]
        def short(fd,data):
            calls.append(len(data));return write(fd,memoryview(data)[:3])
        with patch.object(capture.os,'fdopen',side_effect=AssertionError('buffered writer')), \
             patch.object(capture.os,'write',side_effect=short):
            with self.assertRaisesRegex(base.ProbeError,'call_inventory_short_write'):
                inventory.put('map-extent.json',b'actual bytes')
        self.assertEqual(calls,[12])
        row,=inventory.rows()
        self.assertEqual((row['length'],row['state']),(3,'incomplete_write'))
        self.assertEqual((self.root/'map-extent.json').read_bytes(),b'act')

    def test_inv15_existing_fifo_measurement_is_nonblocking_and_never_read(self):
        inventory=self.inventory()
        path=self.root/'map-extent.json';os.mkfifo(path,0o600)
        opened=os.open;observed=[]
        def bounded_open(name,flags,*args,**kwargs):
            if flags & os.O_ACCMODE == os.O_RDONLY:
                observed.append(flags)
                if not flags & os.O_NONBLOCK:
                    raise AssertionError('would block FIFO open')
            return opened(name,flags,*args,**kwargs)
        with patch.object(capture.os,'open',side_effect=bounded_open), \
             patch.object(capture.os,'readv',side_effect=AssertionError('FIFO read')) as read:
            with self.assertRaises(FileExistsError):inventory.put('map-extent.json',b'actual')
        self.assertTrue(observed)
        self.assertTrue(all(flags & os.O_NONBLOCK for flags in observed))
        read.assert_not_called();self.assertEqual(inventory.rows(),())



if __name__ == '__main__':
    unittest.main(verbosity=2)
