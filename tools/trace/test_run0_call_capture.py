"""Parent preparation controls; private synthetic inputs confer no live origin."""
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import tempfile
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
            self.assertEqual(result.plan['kind'],'run0_call_owned_capture_plan_v0')
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


if __name__ == '__main__':
    unittest.main(verbosity=2)
