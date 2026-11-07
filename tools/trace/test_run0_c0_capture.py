"""Collector controls: private scripted joins and public prelaunch denial only.

No public fixture registration, guard override into launch, VM or guest read.
Actual child fixtures below are short local Python processes, never QEMU.
"""
import copy
from dataclasses import fields, FrozenInstanceError
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace, MappingProxyType
import unittest
from unittest.mock import patch

import boot_profile_capture as base
import run0_c0_acquire as acquire
import run0_c0_decode as decoder
import run0_c0_entry as entry
import run0_c0_host as host
import run0_c0_wire as wire
import run0_host_cpu_witness as witness
import test_run0_c0_acquire as acquisition_fixture
from test_run0_c0_decode import full_fixture
from test_run0_host_cpu_reader import fixture as abi_fixture

try:
    import run0_c0_capture as capture
except ModuleNotFoundError as error:
    if error.name != 'run0_c0_capture':
        raise
    capture = None


def fixture_value(cls, **values):
    value=object.__new__(cls)
    for name,item in values.items():
        object.__setattr__(value,name,item)
    return value


class RecordingAccounting:
    """A private representation-order fixture, never a wire attachment permit."""
    def __init__(self,limit=32<<20):
        self.limit,self.total,self.rows=limit,0,[]
    def reserve_output(self,length,purpose='output'):
        if length>self.limit-self.total:
            raise base.ProbeError('INCOMPLETE','fixture_storage_limit')
        self.total+=length
        self.rows.append(('output',length,purpose))
    def available(self,purpose='output'):
        return self.limit-self.total
    def redeem_terminal(self,length,purpose):
        self.rows.append(('terminal',length,purpose))


class CollectorControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if capture is None:
            return
        cls.tmp=tempfile.TemporaryDirectory(prefix='collector-input-fixture-')
        cls.root=Path(cls.tmp.name).resolve()
        cls.report,_,cls.blobs,cls.host_token,_=full_fixture(cls.root,base.VAPIC_OFF_INVOCATION_PROFILE)
        cls.host_report=json.loads(cls.blobs['host-report.json'])
        cls.profile=json.loads(cls.blobs['profile.json'])
        cls.prior=entry.validate_prior_entry(cls.report['profile_ref'],cls.report['prior_admission_ref'],
                                            cls.report['profile_mapping_ref'],cls.blobs)
        cls.control=json.loads(cls.blobs[cls.host_report['control_ref']['path']])
        cls.abi=abi_fixture()[0]
    @classmethod
    def tearDownClass(cls):
        if capture is not None:
            cls.tmp.cleanup()
    def setUp(self):
        self.assertIsNotNone(capture,'owned C0 collector absent: expected RED')
        self.output=tempfile.TemporaryDirectory(prefix='collector-output-fixture-')
        self.addCleanup(self.output.cleanup)
        self.run=Path(self.output.name).resolve()/'capture-run'
    def reject(self,reason,function,*args,**kwargs):
        with self.assertRaises((base.ProbeError,decoder.C0DecodeError)) as failure:
            function(*args,**kwargs)
        self.assertIn(reason,failure.exception.reason)
        return failure.exception
    def prepared(self,**changes):
        plan=json.loads(self.blobs[self.host_report['plan_ref']['path']])
        pins=(capture._fref(self.report['prior_admission_ref']),
              capture._fref(self.report['profile_mapping_ref']),
              capture._fref(self.report['capability_ref']),capture._fref(self.host_report['source_ref']))
        plan.update(kind='run0_c0_owned_capture_plan_v0',context='c0',run=str(self.run),
            prior_admission_ref=list(pins[0]),profile_mapping_ref=list(pins[1]),
            capability_ref=list(pins[2]),source_persistence_ref=list(pins[3]),prior_inputs_sha256='0'*64)
        values=dict(inputs='/fixture',run=str(self.run),source_dossier='/fixture/source.json',
            host_abi='/fixture/abi.json',plan_bytes=witness.canonical(plan),
            profile_bytes=self.blobs['profile.json'],observer_source_bytes=b'fixture observer',
            abi_ref=capture._fref(self.host_report['abi_ref']),abi_blobs=tuple(self.blobs.items()),
            native_layout=tuple(witness.NATIVE_LAYOUT.items()),field_abi=self.abi,prior=self.prior,
            prior_blobs=tuple(self.blobs.items()),prior_admission_ref=pins[0],profile_mapping_ref=pins[1],
            capability_ref=pins[2],source_persistence_ref=pins[3],pinned_efi=self.blobs['efi'])
        values.update(changes)
        return fixture_value(capture.PreparedC0Inputs,**values)
    def retention_owner(self,raw=None):
        self.run.mkdir(mode=0o700)
        owner=object.__new__(capture._OwnedC0Runtime)
        owner.accounting=RecordingAccounting()
        owner.evidence=witness.CaptureEvidence(self.run,capture._EvidenceBudget(owner.accounting),{})
        owner._wire=SimpleNamespace(_raw={} if raw is None else raw)
        owner._read_claims={}
        return owner

    def test_col01_closed_prepared_and_registered_types(self):
        for cls in (capture.PreparedC0Inputs,capture.RegisteredCurrentC0Binding):
            with self.assertRaises(TypeError):
                cls(admitted=True)
        prepared=self.prepared()
        with self.assertRaises(FrozenInstanceError):
            prepared.run='other'
        plan=prepared.plan;plan['run']='changed'
        self.assertEqual(prepared.plan['run'],str(self.run))

    def test_col02_exact_runtime_registration_refuses_fixture_before_popen_or_run_mutation(self):
        prepared=self.prepared()
        with patch.object(subprocess,'Popen',side_effect=AssertionError('unauthorized launch')) as spawn, \
             patch.object(witness,'require_c0_runtime_registration',wraps=witness.require_c0_runtime_registration) as guard:
            error=self.reject('',capture.run_c0_capture,prepared,self.run)
        self.assertIn(error.status,('DENY','INCOMPLETE'))
        spawn.assert_not_called();guard.assert_called_once()
        self.assertFalse(self.run.exists())

    def test_col02_foreign_prepared_run_and_incomplete_instances_deny_before_spawn(self):
        for value in ({},None,object.__new__(capture.PreparedC0Inputs)):
            with patch.object(subprocess,'Popen',side_effect=AssertionError('spawn')):
                self.reject('prepared',capture.run_c0_capture,value,self.run)
        self.reject('run_identity',capture.run_c0_capture,self.prepared(),self.run/'other')

    def test_col03_foreign_and_origin_only_current_registration_denied(self):
        for value in ({'origin':'owned_current_c0'},self.prepared(),self.prior,object(),
                      object.__new__(capture.RegisteredCurrentC0Binding)):
            self.assertFalse(capture._issued_current_binding(value,object()))
        owner=object.__new__(capture._OwnedC0Runtime)
        owner.prepared=self.prepared()
        registered=fixture_value(capture.RegisteredCurrentC0Binding,_owner=owner,
            binding=SimpleNamespace(origin='owned_current_c0'),prepared=owner.prepared,
            host_receipt=None,layout_receipt=None)
        self.assertFalse(capture._issued_current_binding(registered,object()))

    def test_col03_current_issuer_rechecks_root_registration_before_prefix_or_binding(self):
        owner=object.__new__(capture._OwnedC0Runtime);owner.prepared=self.prepared()
        with patch.object(capture._OwnedC0Runtime,'_prefix_current',side_effect=AssertionError('prefix before admission')):
            self.reject('',owner.issue_current_binding,{},None)

    def test_col04_prepare_reuses_static_launch_and_prior_capability_without_mutation(self):
        inputs=self.root/'static-inputs';inputs.mkdir(exist_ok=True)
        (inputs/'efi').write_bytes(self.blobs['efi']);os.chmod(inputs/'efi',0o600)
        plan=json.loads(self.blobs[self.host_report['plan_ref']['path']])
        plan.update(inputs=str(inputs),run=str(self.run))
        # Existing accepted validators still recompute prior and CAP1 bytes.
        args=(inputs,self.run,self.root/'source.json',self.root/'abi.json')
        prepared=(plan,self.profile,self.blobs['profile.json'],b'old observer',
            self.host_report['abi_ref'],self.blobs,dict(witness.NATIVE_LAYOUT),self.abi)
        prior=dict(self.blobs)
        with patch.object(witness,'prepare_launch',return_value=prepared) as static, \
             patch.object(witness,'c0_observer_source_bytes',return_value=b'private static observer fixture'), \
             patch.object(subprocess,'Popen',side_effect=AssertionError('static preparation launch')):
            value=capture.prepare_c0_inputs(*args,prior_admission_ref=self.report['prior_admission_ref'],
                profile_mapping_ref=self.report['profile_mapping_ref'],capability_ref=self.report['capability_ref'],
                source_persistence_ref=self.host_report['source_ref'],prior_blobs=prior)
        static.assert_called_once_with(*args)
        self.assertEqual(value.plan['kind'],'run0_c0_owned_capture_plan_v0')
        self.assertEqual(value.plan['context'],'c0')
        self.assertEqual(value.prior.entry_address,self.prior.entry_address)
        self.assertEqual(value.pinned_efi,self.blobs['efi'])
        self.assertIs(value.field_abi,self.abi)
        self.assertEqual(dict(value.prior_blobs)['prior-cap1/report.json'],prior['prior-cap1/report.json'])
        self.assertIsInstance(value.plan['capability_ref'],list)
        prior.clear()
        self.assertTrue(value.prior_blobs)
        self.assertFalse(self.run.exists())

    def test_col04_input_output_namespace_and_exact_native_copy_denials(self):
        for name in ('report.json','control.json','prefix-current.json','operation-1-request.bin','c0-acquired/a.bin'):
            self.assertTrue(capture._output_name(name))
        self.assertFalse(capture._output_name('prior-cap1/report.json'))
        self.assertFalse(capture._output_name('prior/report.json'))
        class Callback(dict):
            def items(self):
                raise AssertionError('duck callback')
        for value in (Callback(),MappingProxyType({}),lambda:None):
            self.reject('blob_mapping_type',capture._blobs,value)
        self.reject('input_identity',capture._merge,(('x',b'a'),),(('x',b'b'),))
        with self.assertRaises((base.ProbeError,decoder.C0DecodeError)):
            capture._ref(('x','0'*64,True))

    def test_col04_valid_admission_renamed_to_current_output_denies_before_preparation_effects(self):
        inputs=self.root/'static-inputs';inputs.mkdir(exist_ok=True)
        plan=json.loads(self.blobs[self.host_report['plan_ref']['path']])
        plan.update(inputs=str(inputs),run=str(self.run))
        prepared=(plan,self.profile,self.blobs['profile.json'],b'old observer',
            self.host_report['abi_ref'],self.blobs,dict(witness.NATIVE_LAYOUT),self.abi)
        original=self.report['prior_admission_ref']
        raw=self.blobs[original['path']]
        self.assertEqual(json.loads(raw)['status'],'ADMIT')
        for name in ('lifecycle.json','process.json','streams.json','peer.json','peer.bin',
                     'sigchld.json','sigchld-spawn.bin','sigchld-open.bin','pre-wire-cleanup.json',
                     'partial-rsp.bin','pre-wire-0.bin'):
            with self.subTest(name=name):
                renamed=dict(original,path=name)
                prior=dict(self.blobs);prior[name]=raw
                with patch.object(witness,'prepare_launch',return_value=prepared), \
                     patch.object(witness,'c0_observer_source_bytes',side_effect=AssertionError('late observer work')), \
                     patch.object(subprocess,'Popen',side_effect=AssertionError('launch')):
                    error=self.reject('c0_capture_input_output_collision',capture.prepare_c0_inputs,
                        inputs,self.run,self.root/'source.json',self.root/'abi.json',
                        prior_admission_ref=renamed,profile_mapping_ref=self.report['profile_mapping_ref'],
                        capability_ref=self.report['capability_ref'],source_persistence_ref=self.host_report['source_ref'],
                        prior_blobs=prior)
                self.assertEqual(error.status,'DENY')
                self.assertFalse(self.run.exists())

    def test_col05_prefix_copy_is_charged_before_growth_and_immutable(self):
        raw=bytearray(b'actual prefix')
        owner=self.retention_owner({'rsp':raw})
        ref=owner._raw_copy('rsp','prefix-current-rsp.bin')
        self.assertEqual(owner.accounting.rows,[('output',len(raw),'output')])
        raw.extend(b'later complete tail')
        self.assertEqual(owner.evidence.blobs[ref['path']],b'actual prefix')
        self.assertEqual(ref['sha256'],hashlib.sha256(b'actual prefix').hexdigest())
        other=self.run/'blocked.bin'
        owner.accounting.limit=owner.accounting.total
        self.reject('fixture_storage_limit',owner._raw_copy,'rsp','blocked.bin')
        self.assertFalse(other.exists())

    def test_col05_retained_identity_and_separate_source_copy_charges(self):
        owner=self.retention_owner()
        owner.evidence.blobs['profile.json']=b'pinned source'
        ref=owner._put('profile.json',b'pinned source')
        self.assertEqual((self.run/'profile.json').read_bytes(),b'pinned source')
        total=owner.accounting.total
        self.assertEqual(owner._put('profile.json',b'pinned source'),ref)
        self.assertEqual(owner.accounting.total,total)
        self.reject('retained_identity',owner._put,'profile.json',b'different')

    def test_col05_operation_copy_uses_its_exact_prepaid_identity(self):
        owner=self.retention_owner({'rsp-out':bytearray(b'$m1000,1#00'),'rsp':bytearray(b'$ff#cc')})
        owner._read_claims[9]=('read',1,9)
        op=wire.Operation(9,'rsp','physical_read',10,11,wire.WireSlice('rsp-out',0,11),
                          wire.WireSlice('rsp',0,6),'ok')
        row=owner._retain_op(op)
        self.assertEqual([item[2] for item in owner.accounting.rows],[('read',1,9)]*2)
        self.assertEqual(owner.evidence.blobs[row['response_ref']['path']],b'$ff#cc')
        charged=owner.accounting.total;owner._retain_op(op)
        self.assertEqual(owner.accounting.total,charged)

    def test_col05_terminal_records_use_only_named_terminal_budget(self):
        owner=self.retention_owner()
        owner._json('host-report.json',{'observed':True},purpose='report')
        owner._json('report.json',{'unfinished':['C1','C2']},purpose='report')
        owner._json('failure.json',{'reason':'first'},purpose='failure')
        self.assertEqual([row[0] for row in owner.accounting.rows],['terminal']*3)
        self.assertEqual([row[2] for row in owner.accounting.rows],['report','report','failure'])

    def fixture_teardown(self,*,missing_reply=False,bad_tail=False,missing_helper=False):
        order=[]
        operation=wire.Operation(1,'qmp','quit',10,11,wire.WireSlice('qmp-out',0,1),
            None if missing_reply else wire.WireSlice('qmp-in',0,1),'error' if missing_reply else 'ok')
        quit=wire.QuitReceipt(object(),operation,None,None)
        streams={'qmp-in','rsp','serial','debug','qemu_stdout','qemu_stderr'}
        helpers={name:SimpleNamespace(reaped=True,closed=True,returncode=0,io_errors=[],
            eofs={'stdout'} if missing_helper else {'stdout','stderr'}) for name in witness.WAIT_ROLES[1:]}
        class ScriptWire:
            eofs=tuple(wire.EndOfStream(name,12) for name in streams)
            io_errors=()
            _quit=quit
            _failure=None
            def _latch_failure(self,value):
                if self._failure is None:
                    self._failure=value
            def request_quit(self):
                order.append('quit');return quit
            def drain_after_quit(self,*args,**kwargs):
                order.append('six_vm_eofs')
                return SimpleNamespace(first_failure=wire.Failure('DENY','malformed_tail') if bad_tail else None)
            def close(self):
                order.append('selector_close')
        class ScriptOwner:
            child=SimpleNamespace(pid=123)
            reaped=False;returncode=None;actions=[]
            deadline=time.monotonic()+1;io_deadline=deadline-0.1
            def wait(self,*args,**kwargs):
                order.append('wait');self.reaped=True;self.returncode=0;return 0
            def _signal(self,sig,name):
                order.append(name);self.actions.append(name)
            def _receipt(self,*args,**kwargs):
                order.append('close_receipt')
        runtime=SimpleNamespace(_wire=ScriptWire(),owner=ScriptOwner(),_observation=SimpleNamespace(
            _finished=True,helpers=helpers),_closed=False)
        return runtime,order

    def test_col06_all_twelve_eofs_precede_actual_wait_and_close(self):
        runtime,order=self.fixture_teardown()
        failures=[]
        self.assertEqual(capture._teardown(runtime,[],failures),'exited')
        self.assertEqual(failures,[])
        self.assertLess(order.index('six_vm_eofs'),order.index('wait'))
        self.assertLess(order.index('wait'),order.index('close_receipt'))
        self.assertTrue(runtime._closed)

    def test_col06_replyless_quit_and_bad_tail_never_complete(self):
        for variant,reason in (({'missing_reply':True},'quit_reply_missing'),
                               ({'bad_tail':True},'malformed_tail'),
                               ({'missing_helper':True},'helper_stream_eof')):
            runtime,order=self.fixture_teardown(**variant)
            failures=[];capture._teardown(runtime,[],failures)
            self.assertIn(reason,failures[0]['reason'])
            self.assertTrue(runtime._closed)
            self.assertIn('SIGTERM',order)

    def test_col06_no_wait_or_termination_pass_from_missing_vm_eof(self):
        runtime,order=self.fixture_teardown()
        runtime._wire.eofs=runtime._wire.eofs[:-1]
        failures=[];capture._teardown(runtime,[],failures)
        self.assertEqual(failures[0]['reason'],'c0_capture_vm_stream_eof')
        self.assertIn('SIGTERM',order)

    def test_col07_true_parent_failed_launch_drains_and_reaps_short_child(self):
        child=subprocess.Popen([sys.executable,'-c','import os,time;os.write(1,b"actual stdout");os.write(2,b"actual stderr");time.sleep(5)'],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            start_new_session=True,bufsize=0)
        owner=witness.OwnedWait('qemu',time.monotonic()+2);owner.child=child
        owner._receipt('spawn',time.monotonic_ns(),'ok')
        try:
            time.sleep(0.05)
            record=capture._cleanup_unbound(owner,[child.stdout,child.stderr],RecordingAccounting())
            self.assertTrue(owner.reaped)
            self.assertEqual(owner.child.pid,child.pid)
            self.assertEqual(bytes(record['raw'][0]),b'actual stdout')
            self.assertEqual(bytes(record['raw'][1]),b'actual stderr')
            self.assertTrue(child.stdout.closed and child.stderr.closed)
            self.assertEqual(owner.lifecycle[-1]['operation'],'close')
            self.assertTrue(record['eofs'])
        finally:
            if not owner.reaped:
                owner.terminate()
            child.stdout.close();child.stderr.close()

    def test_col08_complete_receipt_record_replays_unchanged_synthetic_decoder(self):
        owner=self.retention_owner()
        raw={}
        refs={}
        source_refs={key:self.control[field] for key,field in (
            ('qmp-in','raw_qmp_in_ref'),('qmp-out','raw_qmp_out_ref'),
            ('rsp','raw_rsp_in_ref'),('rsp-out','raw_rsp_out_ref'))}
        stream_rows=json.loads(self.blobs[self.host_report['termination']['streams_ref']['path']])['rows']
        source_refs.update({row['name']:row['raw_ref'] for row in stream_rows if row['name'] in (
            'serial','debug','qemu_stdout','qemu_stderr')})
        for key,name in capture.RAW_NAMES.items():
            source=source_refs[key]
            data=self.blobs[source['path']]
            raw[key]=bytearray(data);refs[key]=owner._put(source['path'],data)
        owner._wire._raw=raw
        def segment(value,stream):
            return None if value is None else wire.WireSlice(stream,value['offset'],value['length'])
        operations=[]
        for row in self.control['operations']:
            req='qmp-out' if row['protocol']=='qmp' else 'rsp-out'
            res='qmp-in' if row['protocol']=='qmp' else 'rsp'
            operations.append(wire.Operation(row['seq'],row['protocol'],row['operation'],
                row['started_ns'],row['finished_ns'],segment(row['request'],req),segment(row['response'],res),row['result']))
        owner._wire.operations=tuple(operations)
        owner._wire.eofs=tuple(wire.EndOfStream(name,1) for name in ('qmp-in','rsp','serial','debug','qemu_stdout','qemu_stderr'))
        owner._wire.io_errors=()
        owner._prefix={key:owner._put('prefix-current-'+capture.RAW_NAMES[key],bytes(raw[key][:1]))
                       for key in capture.PREFIX_STREAMS}
        owner._prefix_ref=owner._json('prefix-current.json',{'kind':'run0_c0_current_prefix_v0',
                                                            'raw_refs':list(owner._prefix.values())})
        owner.owner=SimpleNamespace(reaped=True,returncode=0,actions=[])
        owner._closed=True
        owner._observation=SimpleNamespace(_finished=True,helpers={name:SimpleNamespace(
            reaped=True,closed=True,returncode=0,io_errors=[],eofs={'stdout','stderr'}) for name in witness.WAIT_ROLES[1:]})
        record=copy.deepcopy(self.report)
        vars_ref=next(ref for ref in record['raw_refs'] if ref['path']=='vars.fd')
        record=capture._complete_c0_record(owner,record,refs,vars_ref,record['observer_ref'],record['checkpoint'],'exited')
        self.assertEqual(len(record['raw_refs']),14)
        blobs=dict(self.blobs);blobs.update(owner.evidence.blobs)
        data=witness.canonical(record);ref=witness.CaptureEvidence.ref('collector-synthetic.json',data);blobs[ref['path']]=data
        result=decoder.decode_c0('synthetic_fixture',ref,blobs,self.host_token)
        self.assertEqual(result['status'],'PASS',result)
        self.assertFalse(result['fresh_c0_verified'])
        self.assertEqual(result['remaining_checkpoints'],['C1','C2'])
        runtime=decoder.decode_c0('retained_runtime',ref,blobs,self.host_token)
        self.assertNotEqual(runtime['status'],'PASS')

    def test_col08_incomplete_cleanup_cannot_make_complete_record(self):
        owner=self.retention_owner()
        owner.owner=SimpleNamespace(reaped=False,returncode=None,actions=[])
        owner._closed=False
        owner._observation=None
        owner._wire.eofs=();owner._wire.io_errors=()
        self.reject('vm_stream_eof',capture._complete_c0_record,owner,{}, {},{}, {},{},'not_attempted')

    def test_col09_failure_first_cause_and_partial_raw_are_preserved(self):
        owner=self.retention_owner({'rsp':bytearray(b'$partial')})
        owner.owner=SimpleNamespace(reaped=True,returncode=-signal.SIGTERM,actions=['SIGTERM'],lifecycle=[])
        owner._wire.eofs=();owner._wire.io_errors=();owner._wire.operations=()
        owner._observation=None
        failures=[{'status':'DENY','reason':'first_failed_read'},{'status':'INCOMPLETE','reason':'later_cleanup'}]
        report={'termination':None,'raw_refs':[]}
        report,ref=capture._failure_record(owner,report,failures,'not_attempted')
        self.assertEqual(report['termination']['reason'],'first_failed_read')
        self.assertFalse(any(row['eof'] for row in report['termination']['streams']))
        self.assertEqual(owner.evidence.blobs[report['raw_refs'][0]['path']],b'$partial')
        self.assertEqual(json.loads(owner.evidence.blobs[ref['path']])['termination']['status'],'DENY')

    def test_col10_private_scripted_orchestration_uses_same_ledger_and_completion(self):
        from run0_c0_budget import C0Accounting
        acquisition_fixture.AcquisitionControls.setUpClass()
        try:
            fixture=acquisition_fixture.AcquisitionControls()
            binding=fixture.binding()
            account=C0Accounting(time.monotonic_ns())
            # Actual prefix use for this private scripted ledger, never a live wire.
            for _ in range(64):
                account._reserve_operation('scripted-prefix')
            order=[]
            runtime=object.__new__(capture._OwnedC0Runtime)
            class ScriptWire:
                _session=binding.wire_identity
                _reads_complete=None
                def prelaunch(self):order.append('prelaunch')
                def prepare_rsp_reset(self):order.append('reset')
                def install_entry_breakpoint(self,prior):
                    self.prior=prior;order.append('z1')
                def resume_to_entry(self):order.append('resume')
                def confirm_entry_stop(self):return binding.confirmed_stop
                def confirm_stopped_physical_mode(self,confirmed):order.append('mode')
                def read_selected_registers(self,confirmed,phase):
                    if phase=='after':
                        assert self._reads_complete is runtime._complete
                    order.append('registers-'+phase)
                    return object()
                def read_current_layout(self,confirmed,phase):order.append('layout-'+phase);return object()
                def bind_acquisition(self,registered,session):
                    assert registered.binding.origin=='synthetic_fixture'
                    assert session.ledger is account._made
                    account.attach_acquisition(session.ledger)
                    self.harness=acquisition_fixture.Harness(session,fixture.memory())
                    order.append('bind')
                def read_physical(self,grant):
                    seq=self.harness.seq+1
                    account.redeem_read(grant,seq)
                    return self.harness.receipt(grant)
                def complete_acquisition(self,complete):
                    assert complete is runtime._session.next_request()
                    self._reads_complete=complete;order.append('complete')
                def read_final_register_view(self,*args):order.append('final-hmp');return object()
                def clear_entry_breakpoint(self,confirmed):order.append('clear')
            class ScriptObservation:
                def __init__(self,*args):pass
                def observe(self):order.append('host');return object()
            runtime._wire=ScriptWire()
            runtime.prepared=SimpleNamespace(prior=fixture.prior,pinned_efi=fixture.pinned,
                field_abi=self.abi,plan={'argv':['fixture-qemu'],'launch_identity':{'device':1,'inode':2,'size':3}})
            runtime.owner=SimpleNamespace(child=object())
            runtime.accounting=account;runtime.native=object();runtime._read_claims={}
            runtime._complete=None;runtime._registered=None
            def current(host_receipt,layout):
                order.append('retained-prefix')
                account.reserve_output(123,'output')
                runtime._registered=fixture_value(capture.RegisteredCurrentC0Binding,_owner=runtime,
                    binding=binding,prepared=runtime.prepared,host_receipt=host_receipt,layout_receipt=layout)
                return runtime._registered
            runtime.issue_current_binding=current
            runtime.issue_after_binding=lambda *args:fixture.after(runtime._session)
            with patch.object(capture.host,'_OwnedC0Observation',ScriptObservation):
                snapshot=runtime.acquire()
            self.assertEqual(snapshot.origin,'synthetic_fixture')
            self.assertIs(runtime._complete,runtime._wire._reads_complete)
            self.assertEqual(account._seed,(64,123))
            self.assertEqual(account.actual_operations,92)
            self.assertEqual(len(runtime._read_claims),28)
            self.assertEqual(order[:7],['prelaunch','reset','z1','resume','mode','registers-before','host'])
            self.assertLess(order.index('retained-prefix'),order.index('bind'))
            self.assertLess(order.index('complete'),order.index('registers-after'))
            self.assertLess(order.index('layout-after'),order.index('clear'))
        finally:
            acquisition_fixture.AcquisitionControls.tearDownClass()

    def test_col10_private_after_receipt_assembly_finishes_exact_synthetic_snapshot(self):
        acquisition_fixture.AcquisitionControls.setUpClass()
        try:
            fixture=acquisition_fixture.AcquisitionControls()
            session=fixture.session()
            harness=acquisition_fixture.Harness(session,fixture.memory());complete=harness.complete()
            runtime=self.retention_owner()
            runtime._session=session;runtime._complete=complete
            runtime._registered=fixture_value(capture.RegisteredCurrentC0Binding,_owner=runtime,
                binding=session.binding,prepared=object(),host_receipt=object(),layout_receipt=object())
            runtime._registration=lambda:None  # private record assembly only, no actual wire/launch
            rows={row['seq']:row for row in self.control['operations']}
            def segment(value,stream):
                return None if value is None else wire.WireSlice(stream,value['offset'],value['length'])
            runtime._wire._raw={key:bytearray(self.blobs[self.control[name]['path']]) for key,name in (
                ('qmp-in','raw_qmp_in_ref'),('qmp-out','raw_qmp_out_ref'),('rsp','raw_rsp_in_ref'),('rsp-out','raw_rsp_out_ref'))}
            clock_shift=session.binding.stop_ns-next(row['received_ns'] for row in self.control['events']
                if row['protocol']=='rsp')+10000
            runtime._wire.operations=tuple(wire.Operation(row['seq'],row['protocol'],row['operation'],
                row['started_ns']+clock_shift,row['finished_ns']+clock_shift,segment(row['request'],'qmp-out' if row['protocol']=='qmp' else 'rsp-out'),
                segment(row['response'],'qmp-in' if row['protocol']=='qmp' else 'rsp'),row['result']) for row in self.control['operations'])
            replay=decoder.validate_c0_rsp(self.control,self.blobs)
            after=wire.SelectedC0Registers(session.binding.wire_identity,1,'after',tuple(
                (number,replay['after_registers'][number],seq) for number,seq in zip(
                    decoder.SELECTED_REGISTERS,replay['after_sequences'])))
            hmp=wire.C0RegisterView(session.binding.wire_identity,123,None,session.binding.hmp_raw,())
            layout=wire.C0LayoutReceipt(session.binding.wire_identity,'after',124,None,
                session.binding.layout_raw,session.binding.ranges)
            runtime._wire._session=session.binding.wire_identity
            runtime._wire._reads_complete=complete;runtime._wire._after_registers=after
            runtime._wire._final_register_view=hmp;runtime._wire._layout_after=layout
            binding=runtime.issue_after_binding(after,hmp,layout)
            self.assertIs(binding.binding,session.binding)
            self.assertEqual(len(binding.raw_operation_slices),31)
            self.assertEqual(session.finish(binding).origin,'synthetic_fixture')
        finally:
            acquisition_fixture.AcquisitionControls.tearDownClass()

    def test_col11_current_prefix_uses_only_completed_actual_slices_before_ledger_factory(self):
        from run0_c0_budget import C0Accounting
        owner=self.retention_owner()
        replay=decoder.validate_c0_rsp(self.control,self.blobs)
        identity=object()
        first_memory=min(row['seq'] for row in self.control['operations'] if row['operation']=='physical_read')
        def segment(value,stream):
            return None if value is None else wire.WireSlice(stream,value['offset'],value['length'])
        operations=[]
        ends=dict.fromkeys(capture.PREFIX_STREAMS,0)
        for row in self.control['operations']:
            if row['seq']>=first_memory:
                break
            req='qmp-out' if row['protocol']=='qmp' else 'rsp-out'
            res='qmp-in' if row['protocol']=='qmp' else 'rsp'
            a,b=segment(row['request'],req),segment(row['response'],res)
            operations.append(wire.Operation(row['seq'],row['protocol'],row['operation'],
                row['started_ns'],row['finished_ns'],a,b,row['result']))
            for part in (a,b):
                if part is not None:
                    ends[part.stream]=max(ends[part.stream],part.offset+part.length)
        events=[]
        for row in self.control['events']:
            role='qmp-in' if row['protocol']=='qmp' else 'rsp'
            part=segment(row['wire'],role)
            events.append(wire.Event(row['seq'],row['protocol'],row['name'],part,row['received_ns']))
            ends[role]=max(ends[role],part.offset+part.length)
        ends['qmp-in']+=2;ends['rsp-out']+=1
        source={key:self.blobs[self.control[name]['path']] for key,name in (
            ('qmp-in','raw_qmp_in_ref'),('qmp-out','raw_qmp_out_ref'),
            ('rsp','raw_rsp_in_ref'),('rsp-out','raw_rsp_out_ref'))}
        owner._wire._raw={key:bytearray(raw[:ends[key]]) for key,raw in source.items()}
        owner._wire.operations=tuple(operations);owner._wire.events=tuple(events)
        regs=wire.SelectedC0Registers(identity,1,'before',tuple((n,replay['before_registers'][n],seq)
            for n,seq in zip(decoder.SELECTED_REGISTERS,replay['before_sequences'])))
        owner._wire._before_registers=regs
        cp=self.report['checkpoint']
        owner._wire._host_before=wire.C0HostBracket(identity,'before',tuple(self.control['before'].items()),
            ('/machine/unattached/device[0]',123,40),self.blobs[cp['hmp_before_ref']['path']],())
        owner._wire._host_after=wire.C0HostBracket(identity,'after',tuple(self.control['after'].items()),
            ('/machine/unattached/device[0]',123,40),self.blobs[cp['hmp_before_ref']['path']],())
        layout_op=next(row for row in operations if row.operation=='hmp_flatview')
        owner._layout=wire.C0LayoutReceipt(identity,'before',layout_op.seq,layout_op.response,
            self.blobs[cp['layout_before_ref']['path']],decoder._layout(self.blobs[cp['layout_before_ref']['path']]))
        stopped=wire.EntryStop(identity,self.prior.entry_address,replay['breakpoint_seq'],
            replay['resume_seq'],replay['stop_event']['seq'],replay['acknowledge_stop_seq'],
            replay['stop_event']['received_ns'])
        owner._confirmed=wire.ConfirmedEntryStop(stopped,56,operations[55].finished_ns)
        owner.prepared=SimpleNamespace(prior=self.prior,plan={'run':str(self.run)})
        owner._retain_helpers=lambda:({name:self.host_report[name] for name in
            ('metadata_before_ref','metadata_after_ref','reads_ref')},{},{})
        account=C0Accounting(time.monotonic_ns());owner.accounting=account
        account._bind_wire(owner._wire)
        for row in operations:
            account._reserve_operation(row.operation)
        before=account.actual_bytes
        owner._prefix_current()
        self.assertGreater(account.actual_bytes,before)
        ledger=account.make_acquisition_ledger()
        self.assertEqual(ledger.values['operations'],first_memory-1)
        self.assertEqual(ledger.values['retained_bytes'],account.actual_bytes)
        for key,ref in owner._prefix.items():
            snapshot=owner.evidence.blobs[ref['path']]
            self.assertEqual(snapshot,source[key][:ends[key]])
            owner._wire._raw[key].extend(b'future-tail')
            self.assertEqual(owner.evidence.blobs[ref['path']],snapshot)
        prefix=json.loads(owner.evidence.blobs[owner._prefix_ref['path']])
        self.assertEqual(prefix['kind'],'run0_c0_current_prefix_v0')
        self.assertFalse(any(row['operation']=='physical_read' for row in prefix['operations']))

    def test_col11_ambiguous_quit_uses_failure_only_no_send_drain(self):
        runtime,order=self.fixture_teardown()
        runtime._wire._quit=None
        runtime._wire.eofs=()
        runtime._wire.remaining_tail=b'actual unclaimed terminal tail'
        runtime._wire.retained_tail=b''
        self.assertIsNone(runtime._wire._failure)
        def ambiguous():
            order.append('quit-local-denial')
            raise base.ProbeError('DENY','qmp_quit_ambiguous')
        def drain(*,deadline_ns):
            self.assertLessEqual(deadline_ns,int(runtime.owner.deadline*1_000_000_000))
            self.assertIsInstance(runtime._wire._failure,wire.Failure)
            self.assertEqual(runtime._wire._failure.reason,'qmp_quit_ambiguous')
            runtime._wire.retained_tail=runtime._wire.remaining_tail
            runtime._wire.eofs=tuple(wire.EndOfStream(name,12) for name in (
                'qmp-in','rsp','serial','debug','qemu_stdout','qemu_stderr'))
            order.append('failed-owner-drain')
        runtime._wire.request_quit=ambiguous
        runtime._wire._drain_failed_owner=drain
        failures=[]
        capture._teardown(runtime,[],failures)
        self.assertEqual(failures[0]['reason'],'qmp_quit_ambiguous')
        self.assertIn('failed-owner-drain',order)
        self.assertIsNone(runtime._wire._quit)
        self.assertEqual(runtime._wire.retained_tail,b'actual unclaimed terminal tail')
        self.assertEqual(len(runtime._wire.eofs),6)
        self.assertEqual(order.count('quit-local-denial'),1)
        self.assertEqual(runtime._wire._failure.reason,'qmp_quit_ambiguous')
        self.assertTrue(runtime._closed)

    def test_col09_decoder_cause_is_retained_without_generic_io_relabel(self):
        self.assertEqual(capture._cause(decoder.C0DecodeError('DENY','frame_level')),('DENY','frame_level'))
        self.assertEqual(capture._cause(KeyboardInterrupt()),('INCOMPLETE','observer_cancelled'))


if __name__ == '__main__':
    unittest.main()
