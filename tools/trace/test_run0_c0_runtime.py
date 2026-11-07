"""Coordinator C0 source/plan checks; no runtime issuer or VM execution."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import run0_host_cpu_witness as witness
import run0_c0_decode as decoder


NAMES = (
    'run0_host_cpu_witness.py', 'run0_host_cpu_reader.py', 'boot_profile_capture.py',
    'boot_profile_inputs.py', 'run0_rsp_capability.py', 'run0_rsp.py',
    'build_trace_artifact.py', 'replay_protocol_trace.py', 'run0_c0_paging.py',
    'run0_c0_decode.py', 'run0_c0_wire.py', 'run0_c0_rsp.py', 'run0_c0_entry.py',
    'run0_c0_acquire.py', 'run0_c0_host.py', 'run0_c0_budget.py', 'run0_c0_capture.py',
)


class C0RuntimeSourceControls(unittest.TestCase):
    def test_exact_source_inventory_and_actual_python_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in NAMES:
                (root / name).write_bytes(('source:' + name).encode())
            with patch.object(witness.base, '__file__', str(root / 'boot_profile_capture.py')):
                raw = witness.c0_observer_source_bytes()
            value = json.loads(raw)
            self.assertEqual(value['kind'], 'run0_c0_observer_v0')
            self.assertEqual(tuple(row['path'] for row in value['sources']), NAMES)
            for row in value['sources']:
                data = (root / row['path']).read_bytes()
                self.assertEqual(row['length'], len(data))
                self.assertEqual(row['sha256'], hashlib.sha256(data).hexdigest())
            python = Path(value['python']['path'])
            self.assertEqual(value['python']['length'], python.stat().st_size)
            self.assertEqual(value['python']['sha256'], hashlib.sha256(python.read_bytes()).hexdigest())

    def test_missing_or_empty_source_refuses_before_observer_publication(self):
        for empty in (False, True):
            with self.subTest(empty=empty), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for name in NAMES[:-1]:
                    (root / name).write_bytes(b'source')
                if empty:
                    (root / NAMES[-1]).write_bytes(b'')
                with patch.object(witness.base, '__file__', str(root / 'boot_profile_capture.py')):
                    with self.assertRaises((OSError, witness.base.ProbeError)):
                        witness.c0_observer_source_bytes()

    def test_exact_prepared_type_with_missing_fields_refuses_with_typed_error(self):
        import run0_c0_capture as capture
        with patch.object(witness.subprocess, 'Popen', side_effect=AssertionError('spawned')):
            with self.assertRaises(witness.base.ProbeError):
                witness.require_c0_runtime_registration(object.__new__(capture.PreparedC0Inputs),
                    dict.fromkeys((*witness.WITNESS_PLAN_FIELDS, 'context',
                                   *witness.C0_PLAN_INPUT_FIELDS, 'prior_inputs_sha256')))

    def test_native_prepared_envelopes_refuse_bad_paths_before_path_callbacks(self):
        import run0_c0_capture as capture
        plan = dict.fromkeys((*witness.WITNESS_PLAN_FIELDS, 'context',
                             *witness.C0_PLAN_INPUT_FIELDS, 'prior_inputs_sha256'))
        plan.update(schema_version=1, uid=__import__('os').getuid(), gid=__import__('os').getgid())
        value = object.__new__(capture.PreparedC0Inputs)
        for name in capture.PreparedC0Inputs.__dataclass_fields__:
            object.__setattr__(value,name,None)
        object.__setattr__(value,'plan_bytes',witness.canonical(plan))
        object.__setattr__(value,'inputs',[])
        with patch.object(witness.subprocess,'Popen',side_effect=AssertionError('spawned')):
            with self.assertRaises(witness.base.ProbeError):
                witness.require_c0_runtime_registration(value,plan)

    def test_unregistered_runtime_refuses_with_typed_error_before_any_spawn(self):
        with patch.object(witness.subprocess, 'Popen', side_effect=AssertionError('spawned')):
            with self.assertRaises(witness.base.ProbeError):
                witness.require_c0_runtime_registration(None, {})



class C0PlanControls(unittest.TestCase):
    def packet(self, directory):
        import run0_c0_decode as decoder
        from test_run0_c0_decode import full_fixture
        report, _, blobs, _, put = full_fixture(Path(directory), witness.base.VAPIC_OFF_INVOCATION_PROFILE)
        persistence = put('source-persistence.json', b'accepted conditional source proof')
        host = json.loads(blobs['host-report.json'])
        abi = json.loads(blobs[host['abi_ref']['path']])
        store = decoder._Blobs(blobs)
        decoder._profile_binding(report, store)
        decoder._capability_binding(report, store, json.loads(blobs[report['profile_ref']['path']]))
        store.get(persistence, witness.REPORT_LIMIT)
        # Public preparation also verifies the separately pinned ABI root.
        store.get(host['abi_ref'], witness.REPORT_LIMIT)
        manifest = [witness.CaptureEvidence.ref(name, raw) for name, raw in sorted(store.verified.items())]
        plan = {'context':'c0', 'abi_sha256':host['abi_ref']['sha256'], 'prior_inputs_sha256':hashlib.sha256(witness.canonical(manifest)).hexdigest()}
        for key in ('prior_admission_ref','profile_mapping_ref','capability_ref'):
            reference=report[key]
            plan[key]=[reference['path'],reference['sha256'],reference['length']]
        plan['source_persistence_ref']=[persistence['path'],persistence['sha256'],persistence['length']]
        return report, plan, blobs, abi, persistence['sha256']

    def test_exact_input_closure_is_recomputed_without_launch_or_output_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            report, plan, blobs, abi, digest = self.packet(directory)
            with patch.object(witness, 'C0_SOURCE_PERSISTENCE_SHA256', digest, create=True), \
                 patch.object(witness.subprocess, 'Popen', side_effect=AssertionError('spawned')):
                witness.validate_c0_plan_inputs(plan, report['profile_ref'], abi, blobs,
                    abi_ref=json.loads(blobs['host-report.json'])['abi_ref'])

    def test_input_ref_arrays_and_manifest_are_not_unchecked_output_escape_hatches(self):
        import copy
        with tempfile.TemporaryDirectory() as directory:
            report, plan, blobs, abi, digest = self.packet(directory)
            variants=[]
            for key in ('prior_admission_ref','profile_mapping_ref','capability_ref','source_persistence_ref'):
                for replacement in ({'path':'x','sha256':'1'*64,'length':1}, ['../escape','1'*64,1],
                                    ['control.json','1'*64,1], ['x','1'*64,True]):
                    variants.append(plan | {key:replacement})
            variants.extend((plan | {'context':'reset'},plan | {'prior_inputs_sha256':'0'*64}))
            with patch.object(witness, 'C0_SOURCE_PERSISTENCE_SHA256', digest, create=True):
                for changed in variants:
                    with self.subTest(changed=changed), self.assertRaises((witness.base.ProbeError, decoder.C0DecodeError)):
                        witness.validate_c0_plan_inputs(changed, report['profile_ref'], abi, blobs,
                            abi_ref=json.loads(blobs['host-report.json'])['abi_ref'])
                corrupted=copy.copy(blobs)
                corrupted[plan['source_persistence_ref'][0]]=b'changed'
                with self.assertRaises((witness.base.ProbeError, decoder.C0DecodeError)):
                    witness.validate_c0_plan_inputs(plan,report['profile_ref'],abi,corrupted,
                        abi_ref=json.loads(blobs['host-report.json'])['abi_ref'])

    def test_abi_root_is_explicit_verified_and_required_in_full_prepared_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            report, plan, blobs, abi, digest = self.packet(directory)
            reference = json.loads(blobs['host-report.json'])['abi_ref']
            with patch.object(witness, 'C0_SOURCE_PERSISTENCE_SHA256', digest):
                # Same full verified closure as public preparation, including
                # the ABI root in addition to prior/profile/CAP/persistence.
                witness.validate_c0_plan_inputs(plan, report['profile_ref'], abi, blobs,
                                                 abi_ref=reference)
                missing = dict(blobs)
                del missing[reference['path']]
                for changed_plan, changed_abi, changed_blobs, changed_ref in (
                    (plan, abi, missing, reference),
                    (plan, abi, blobs, reference | {'length':reference['length']+1}),
                    (plan, abi, blobs, reference | {'sha256':'0'*64}),
                    (plan | {'abi_sha256':'0'*64}, abi, blobs, reference),
                    (plan, abi | {'kind':'contradictory'}, blobs, reference),
                ):
                    with self.subTest(reference=changed_ref), self.assertRaises((
                            witness.base.ProbeError, decoder.C0DecodeError)):
                        witness.validate_c0_plan_inputs(changed_plan, report['profile_ref'],
                            changed_abi, changed_blobs, abi_ref=changed_ref)

    def test_source_persistence_and_profile_must_be_the_reviewed_pair(self):
        with tempfile.TemporaryDirectory() as directory:
            report, plan, blobs, abi, _ = self.packet(directory)
            with self.assertRaisesRegex(witness.base.ProbeError, 'persistence'):
                witness.validate_c0_plan_inputs(plan,report['profile_ref'],abi,blobs,
                    abi_ref=json.loads(blobs['host-report.json'])['abi_ref'])


if __name__ == '__main__':
    unittest.main()
