"""Synthetic private host joins only: no VM or field-reader process is started."""
from contextlib import contextmanager, ExitStack
from dataclasses import fields, replace
import copy
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import time
import unittest
from unittest.mock import patch

from boot_profile_capture import ProbeError
import run0_call_capture as capture
import run0_call_wire as wiremod
from run0_call_budget import ParentAccounting, REGULAR_BYTES
from run0_call_owner import ParentDeadlines, ParentOwnedWait, ParentOwnedHelper
import run0_host_cpu_witness as witness
import run0_host_cpu_reader as reader
import test_run0_host_cpu_reader as rf
import run0_call_host as host


def native(cls, **values):
    value = object.__new__(cls)
    for name, item in values.items():
        object.__setattr__(value, name, item)
    return value


def child(pid=12345):
    value = object.__new__(subprocess.Popen)
    value.pid, value.returncode, value._child_created = pid, None, False
    return value


def field_wire(begin, maps, *, changed=False):
    cpu, queue = rf.CPU, reader.QUEUE
    head = struct.pack('<QQ', cpu, cpu + reader.NODE)
    node = struct.pack('<QQ', 0, queue)
    flags = struct.pack('<I', (1 << 14) | (1 << 15))
    items = [(1,'head',queue,head),(1,'generation',reader.GENERATION,struct.pack('<I',1)),
        (2,'node',cpu+reader.NODE,node),(2,'cpu_index',cpu+reader.INDEX,struct.pack('<i',0)),
        (2,'thread_id',cpu+reader.TID,struct.pack('<i',123)),
        (3,'hflags',cpu+reader.HFLAGS,flags),(3,'hflags2',cpu+reader.HFLAGS2,bytes(4)),
        (4,'hflags',cpu+reader.HFLAGS,struct.pack('<I',0) if changed else flags),
        (4,'hflags2',cpu+reader.HFLAGS2,bytes(4)),(5,'node',cpu+reader.NODE,node),
        (5,'cpu_index',cpu+reader.INDEX,struct.pack('<i',0)),
        (5,'thread_id',cpu+reader.TID,struct.pack('<i',123)),
        (6,'head',queue,head),(6,'generation',reader.GENERATION,struct.pack('<I',1))]
    rows=[]
    clock=time.monotonic_ns()
    for seq,(phase,_,address,data) in enumerate(items,1):
        rows.extend((dict(kind='read_started',seq=seq,phase=phase,address=address,
            length=len(data),started_ns=clock+seq*2),dict(kind='read_finished',seq=seq,
            finished_ns=clock+seq*2+1,returned=len(data),errno=None,hex=data.hex())))
        if seq==2:rows.append(dict(kind='head_ready',nonce=begin['nonce'],completed_phase=1))
    rows.append(dict(kind='finished',status='ADMIT',reason='field_subset_complete'))
    encoded=[witness.canonical(row) for row in rows]
    return b''.join(encoded[:5]),b''.join(encoded)


class HostControls(unittest.TestCase):
    def graph(self, epoch='C0'):
        started=time.monotonic_ns();policy=ParentDeadlines(started);ledger=ParentAccounting(started)
        runtime=object.__new__(capture._OwnedCallRuntime)
        owner=ParentOwnedWait('vm',policy);owner.child=child()
        abi,_=rf.fixture();prepared=native(capture.PreparedCallInputs,inputs='/synthetic',field_abi=abi)
        registration=native(capture.ClosedOwnedCallRegistration,_owner=runtime,prepared=prepared,
            qemu_owner=owner,deadlines=policy,accounting=ledger,parent_identity=object())
        wire=object.__new__(wiremod.CallWire);wire._registration=registration;wire._failure=None
        stop=native(wiremod.EpochStopReceipt,_registration=registration,_wire=wire,epoch=epoch,
            stop_nonce=object(),stop_event_seq=7,received_ns=started,confirmed_ns=started,
            stop_deadline_ns=started+60_000_000_000)
        from run0_c0_acquire import REGISTER_WIDTHS
        before=native(wiremod.SelectedEpochRegisters,_registration=registration,_wire=wire,
            stop=stop,phase='before',values=tuple((n,width,0,i+1) for i,(n,width) in enumerate(REGISTER_WIDTHS)))
        lease=native(wiremod.ParentHostLease,_registration=registration,_wire=wire,stop=stop,
            before_registers=before,started_ns=started,deadline_ns=started+5_000_000_000)
        wire._stop,wire._before_registers=stop,before
        wire._host_lease=wire._host_peer=wire._host_before=wire._host_after=wire._host_receipt=None
        runtime.prepared=prepared;runtime._registration=registration;runtime._wire=wire
        runtime.qemu_owner=owner;runtime.deadlines=policy;runtime.accounting=ledger
        runtime._launch_identity=(0x801,7,len(rf.elf_fixture()))
        runtime.native=type('Native',(),{'sigchld':lambda _:bytes(152),
            'filesystem_magic':lambda _,fd:witness.NATIVE_LAYOUT['proc_super_magic']})()
        runtime._observations={};runtime._failure=None;runtime._closed=False
        object.__setattr__(registration,'wire',wire)
        return runtime,registration,wire,stop,before,lease

    @contextmanager
    def admitted(self, graph):
        runtime,reg,wire,stop,before,lease=graph
        def current(w,s):
            if s is not stop or w is not wire:raise ProbeError('DENY','fixture_stop')
        def guard(r,w,o):
            if r is not runtime or w is not wire or r._observations.get(stop.epoch) is not o:
                raise ProbeError('DENY','fixture_observation')
        def registered(r,w,o,h):
            self.assertIs(r,runtime);self.assertIs(w,wire);self.assertIs(r._observations[stop.epoch],o)
            self.assertIsNotNone(h.child)
        @contextmanager
        def attempt(w,s):
            current(w,s)
            try:yield
            except BaseException as error:
                if w._failure is None:w._failure=error
                raise
        def begin(w,s,b):
            current(w,s);self.assertIs(b,before);self.assertIsNone(w._host_lease)
            w._host_lease=lease;return lease
        def require_lease(w,l):
            self.assertIs(l,lease);self.assertIs(w._host_lease,l)
            if time.monotonic_ns()>=l.deadline_ns:raise ProbeError('INCOMPLETE','fixture_lease_expired')
        def peer(w,l):
            require_lease(w,l)
            value=native(wiremod.ParentPeerReceipt,_registration=reg,_wire=w,lease=l,
                raw_bytes=struct.pack('=iII',runtime.qemu_owner.child.pid,os.getuid(),os.getgid()),
                observed_ns=time.monotonic_ns());w._host_peer=value;return value
        def bracket(w,l,phase):
            require_lease(w,l)
            value=native(wiremod.ParentHostBracket,_registration=reg,_wire=w,lease=l,phase=phase,
                operations=tuple((name,i+1) for i,name in enumerate(('status_seq','cpu_seq','realized_seq','phys_bits_seq','hmp_seq'))),
                cpu_identity=('/machine/cpu0',123,40),hmp_bytes=b'synthetic HMP',parsed_state=())
            setattr(w,'_host_'+phase,value);return value
        def finish(w,l,r):
            require_lease(w,l);self.assertTrue(host._issued_parent_observation(r,w,l))
            if w._host_receipt is not None:raise ProbeError('DENY','fixture_twice')
            w._host_receipt=r
        with ExitStack() as stack:
            for name,method in (('_require_host_observation',guard),('_register_host_helper',registered)):
                stack.enter_context(patch.object(capture._OwnedCallRuntime,name,method,create=True))
            methods={'_current_stop':current,'_epoch_attempt':attempt,'begin_host_observation':begin,
                '_lease':require_lease,'host_peer_credentials':peer,'host_bracket':bracket,
                'pump_host_observation':require_lease,'finish_host_observation':finish}
            for name,method in methods.items():stack.enter_context(patch.object(wiremod.CallWire,name,method,create=True))
            yield

    def observation(self,g):
        r,reg,w,s,b,_=g
        with patch.object(wiremod.CallWire,'_current_stop',lambda wire,stop:None,create=True):
            o=host._OwnedParentObservation(reg,s,b)
        r._observations[s.epoch]=o
        return o

    def test_public_receipt_constructor_and_foreign_graph_refuse(self):
        with self.assertRaises(TypeError):host.ParentHostObservationReceipt()
        with self.assertRaises(ProbeError):host._OwnedParentObservation(object(),object(),object())
        g=self.graph();g[2]._before_registers=object()
        with self.assertRaises(ProbeError):self.observation(g)

    def test_missing_root_hook_refuses_before_any_io_or_helper(self):
        g=self.graph();o=self.observation(g)
        with patch.object(host.os,'open') as opened,patch.object(ParentOwnedHelper,'start') as spawned:
            with self.assertRaisesRegex(ProbeError,'call_host_producer_pending'):o.observe()
        opened.assert_not_called();spawned.assert_not_called();self.assertIsNone(g[2]._host_lease)

    def test_unheld_observation_and_foreign_before_refuse_without_effects(self):
        g=self.graph();o=self.observation(g);g[0]._observations.clear()
        with self.admitted(g),patch.object(host.os,'open') as opened:
            with self.assertRaisesRegex(ProbeError,'fixture_observation'):o.observe()
        opened.assert_not_called()
        g=self.graph()
        with patch.object(wiremod.CallWire,'_current_stop',lambda *_:None,create=True):
            with self.assertRaises(ProbeError):host._OwnedParentObservation(g[1],g[3],copy.copy(g[4]))

    def test_budget_is_one_ledger_prepaid_helper_credit_not_second_allowance(self):
        g=self.graph();b=host._ParentBudget(g[1]);before=g[0].accounting.view()['actual_bytes']
        b.copy(120,"helper_test_prepaid")
        self.assertEqual(g[0].accounting.view()['actual_bytes'],before+120)
        charged=g[0].accounting.view()['actual_bytes'];b.retain(1)
        self.assertEqual(g[0].accounting.view()['actual_bytes'],charged+1)
        g[0].accounting.reserve_output(REGULAR_BYTES-g[0].accounting.view()['actual_bytes'])
        with self.assertRaises(ProbeError):b.copy(1,'fixture')

    def test_port_and_helper_keep_original_lease_and_epoch_role(self):
        g=self.graph('C1');o=self.observation(g)
        with self.admitted(g):
            o._lease=g[2].begin_host_observation(g[3],g[4]);o.deadline_ns=g[5].deadline_ns;p=host._ParentObservationPort(g[2],o._lease)
            self.assertEqual(p.deadline_ns,g[5].deadline_ns)
            for _ in range(3):p.pump()
            self.assertEqual(p.deadline_ns,g[5].deadline_ns)
            result,out=os.pipe()
            def start(h,*args):
                h.child=child(54321)
                raise ProbeError('INCOMPLETE','fixture_start_failed')
            try:
                with patch.object(ParentOwnedHelper,'start',start):
                    with self.assertRaisesRegex(ProbeError,'fixture_start_failed'):
                        o._helper('fields',result,out,{},[],64)
                h=o.helpers['fields'];self.assertIs(type(h),host._ParentHostHelper)
                self.assertEqual(h.role,'c1_fields');self.assertEqual(h._lease_deadline_ns,g[5].deadline_ns)
            finally:
                h.selector.close();os.close(result);os.close(out)

    def test_helper_missing_registration_hook_refuses_before_start(self):
        g=self.graph();o=self.observation(g)
        with self.admitted(g):
            o._lease=g[2].begin_host_observation(g[3],g[4]);o.deadline_ns=g[5].deadline_ns
            with patch.object(capture._OwnedCallRuntime,'_register_host_helper',None):
                with patch.object(ParentOwnedHelper,'start') as start:
                    with self.assertRaisesRegex(ProbeError,'call_host_helper_registration_pending'):
                        o._helper('fields',0,1,{},[],64)
                start.assert_not_called()

    def observed(self, *, changed=None, epoch='C0'):
        g=self.graph(epoch);o=self.observation(g);r,reg,w,stop,before,lease=g
        with tempfile.TemporaryDirectory() as folder,self.admitted(g),ExitStack() as stack:
            proc=Path(folder)/'proc';directory=proc/str(o.child.pid);directory.mkdir(parents=True)
            rest=[b'S',str(os.getpid()).encode(),*([b'0']*17),b'721231',*([b'0']*30)]
            stat_raw=str(o.child.pid).encode()+b' (synthetic child) '+b' '.join(rest)+b'\n'
            exe=rf.exe_identity(rf.elf_fixture());mount=b'10 1 8:1 / / rw - ext4 /dev/sda1 rw\n'
            meta=b''.join(struct.pack('>I',len(x))+x for x in (stat_raw,rf.MAPS,rf.smaps(),mount,witness.canonical(exe)))
            for name in ('stat','maps','smaps','exe','mem'):(directory/name).write_bytes(b'private fixture')
            (Path(folder)/'mountinfo').write_bytes(mount)
            opened=os.open
            def private_open(path,flags,*args,**kw):
                if path=='/proc':path=proc
                elif path=='/proc/self/mountinfo':path=Path(folder)/'mountinfo'
                return opened(path,flags,*args,**kw)
            def start(h,argv,passfds,limit,stderr):
                h.child=child(54321+len(o.helpers));h._receipt('spawn',time.monotonic_ns(),'ok')
                if '--request-fd' in argv:h._fixture_request=os.dup(int(argv[argv.index('--request-fd')+1]))
                if h.role.endswith('metadata_before') or h.role.endswith('metadata_after'):
                    raw=meta
                    if changed=='start' and h.role.endswith('metadata_after'):raw=raw.replace(b'721231',b'721232')
                    h.budget.retain(len(raw));h.output.extend(raw)
            def drain(h):h.eofs.update(('stdout','stderr'))
            def wait(h,*args,**kw):
                h.reaped=True;h.returncode=0;h._receipt('wait',time.monotonic_ns(),'ok',returncode=0);return 0
            def close(h):
                if h.closed:return
                h.reaped=True;h.returncode=0;h.eofs.update(('stdout','stderr'));h.selector.close()
                os.close(h.result_fd)
                if hasattr(h,'_fixture_request'):os.close(h._fixture_request)
                h.closed=True;h._receipt('close',time.monotonic_ns(),'ok')
            original_send=host._OwnedParentObservation._send_frame
            def send(obs,fd,frame,h):
                original_send(obs,fd,frame,h)
                request=json.loads(frame)
                if request['kind']=='begin':
                    _,maps=rf.fixture();head,full=field_wire(request,maps,changed=changed=='field')
                    h._fixture_full=full;h.budget.retain(len(head));h.output.extend(head)
                else:
                    tail=h._fixture_full[len(h.output):];h.budget.retain(len(tail));h.output.extend(tail)
            for name,func in (('start',start),('drain',drain),('wait',wait),('close',close),
                              ('until',lambda h,ready:self.assertTrue(ready()))):
                stack.enter_context(patch.object(ParentOwnedHelper,name,func))
            stack.enter_context(patch.object(host.os,'open',private_open))
            stack.enter_context(patch.object(host.os,'pidfd_open',lambda pid:opened(directory/'stat',os.O_RDONLY),create=True))
            stack.enter_context(patch.object(host,'pidfd_check',lambda fd:{'observed_ns':time.monotonic_ns(),'readable':False,'hangup':False,'error':None}))
            stack.enter_context(patch.object(host._OwnedParentObservation,'_send_frame',send))
            if changed=='abi':o.abi=replace(o.abi,elf=replace(o.abi.elf,sha256='0'*64))
            if changed=='peer':
                stack.enter_context(patch.object(wiremod.CallWire,'host_peer_credentials',lambda *args:native(wiremod.ParentPeerReceipt,raw_bytes=struct.pack('=iII',1,os.getuid(),os.getgid()),observed_ns=time.monotonic_ns())))
            if changed is None:receipt=o.observe()
            else:
                with self.assertRaises(ProbeError):o.observe()
                receipt=None
        return g,o,receipt

    def test_complete_body_fourteen_reads_brackets_helper_roles_and_ownership(self):
        for epoch in ('C0','C1','C2'):
            with self.subTest(epoch=epoch):
                g,o,receipt=self.observed(epoch=epoch)
                self.assertIs(g[2]._host_receipt,receipt)
                self.assertEqual(len(o.reads),14);self.assertEqual(sum(x['length'] for x in o.reads),104)
                self.assertEqual(tuple(o.helpers),('metadata_before','fields','metadata_after'))
                self.assertEqual(tuple(h.role for h in o.helpers.values()),tuple(epoch.lower()+'_'+x for x in o.helpers))
                self.assertTrue(all(h.closed and h.reaped and h.returncode==0 and h.eofs=={'stdout','stderr'} for h in o.helpers.values()))
                self.assertTrue(host._issued_parent_observation(receipt,g[2],g[5]))
                self.assertEqual(o.deadline_ns,g[5].deadline_ns)
                self.assertLess(o.process['mem_closed_ns'],o.helpers['metadata_after'].lifecycle[0]['started_ns'])
                self.assertIsNotNone(o.before_bracket);self.assertIsNotNone(o.after_bracket)

    def test_changed_abi_peer_start_and_field_never_issue_receipt_then_fresh_succeeds(self):
        for change in ('abi','peer','start','field'):
            with self.subTest(change=change):
                g,o,r=self.observed(changed=change)
                self.assertIsNone(r);self.assertIsNone(g[2]._host_receipt);self.assertIsNone(o._receipt)
                self.assertIsNotNone(g[2]._failure)
                self.assertTrue(all(h.closed and h.reaped for h in o.helpers.values()))
        self.assertIsNotNone(self.observed()[2])

    def test_equal_foreign_receipt_lease_or_native_slot_is_not_origin(self):
        g,o,r=self.observed()
        equal=native(host.ParentHostObservationReceipt,**{x.name:getattr(r,x.name) for x in fields(r)})
        self.assertFalse(host._issued_parent_observation(equal,g[2],g[5]))
        self.assertFalse(host._issued_parent_observation(r,g[2],copy.copy(g[5])))
        g[0]._observations.clear();self.assertFalse(host._issued_parent_observation(r,g[2],g[5]))

    def test_field_parser_reads_exact_native_receipts_and_tampering_denies(self):
        abi,maps=rf.fixture();begin=rf.begin(maps);head,raw=field_wire(begin,maps)
        admit,reads,state=witness.field_receipts(raw,begin,maps,abi)
        self.assertEqual(len(reads),14);self.assertEqual(sum(x['length'] for x in reads),104)
        self.assertEqual(witness.field_receipts(head,begin,maps,abi,head_only=True),admit)
        self.assertTrue(state['cs64'] and state['lma'])
        for bad in (raw+raw,raw[:-10],field_wire(begin,maps,changed=True)[1]):
            with self.assertRaises(ProbeError):witness.field_receipts(bad,begin,maps,abi)


    def step_fixture(self, limit=3):
        g=self.graph();budget=host._ParentBudget(g[1])
        helper=host._ParentHostHelper('c0_fields',0,g[5].deadline_ns,g[0].deadlines,budget=budget)
        helper.selector.close();data=bytearray()
        key=SimpleNamespace(data=('stdout',data,limit),fd=101,fileobj='stdout')
        class Selector:
            def __init__(self):self.live=True
            def select(self,timeout):return [(key,1)] if self.live else []
            def unregister(self,stream):self.live=False
        helper.selector=Selector()
        return g,helper,data

    def test_step_prepaid_before_readv_and_actual_copy_then_eof(self):
        g,h,data=self.step_fixture();initial=g[0].accounting.view()['actual_bytes']
        def readv(fd,buffers):
            self.assertEqual((fd,len(buffers),len(buffers[0])),(101,1,4))
            self.assertEqual(g[0].accounting.view()['actual_bytes'],initial+65536)
            buffers[0][:2]=b'xy'
            return 2
        with patch.object(host.os,'readv',readv,create=True):h._step(time.monotonic()+1)
        self.assertEqual(data,b'xy');self.assertEqual(h.eofs,set())
        charged=g[0].accounting.view()['actual_bytes']
        self.assertEqual(charged,initial+65536+4)
        with patch.object(host.os,'readv',return_value=0,create=True):h._step(time.monotonic()+1)
        self.assertEqual(h.eofs,{'stdout'});self.assertEqual(data,b'xy')
        self.assertEqual(g[0].accounting.view()['actual_bytes'],charged)

    def test_step_overflow_retains_only_prefix_and_no_false_eof(self):
        g,h,data=self.step_fixture()
        def readv(fd,buffers):buffers[0][:4]=b'abcd';return 4
        with patch.object(host.os,'readv',readv,create=True):
            with self.assertRaisesRegex(ProbeError,'helper_output_limit'):h._step(time.monotonic()+1)
        self.assertEqual(data,b'abc');self.assertEqual(h.eofs,set())
        self.assertEqual(h.io_errors[-1]['observed_overflow_bytes'],1)
        self.assertFalse(h.selector.live)

    def test_step_eintr_and_eagain_keep_credit_and_next_fresh_read_succeeds(self):
        for error in (InterruptedError(),BlockingIOError()):
            g,h,data=self.step_fixture();before=g[0].accounting.view()['actual_bytes']
            with patch.object(host.os,'readv',side_effect=error,create=True):h._step(time.monotonic()+1)
            self.assertGreater(g[0].accounting.view()['actual_bytes'],before)
            self.assertEqual(data,b'');self.assertEqual(h.io_errors,[]);self.assertTrue(h.selector.live)
            def readv(fd,buffers):buffers[0][:3]=b'yes';return 3
            with patch.object(host.os,'readv',readv,create=True):h._step(time.monotonic()+1)
            self.assertEqual(data,b'yes')

    def test_step_budget_refuses_before_read_and_partial_eof_is_not_complete_fields(self):
        g,h,data=self.step_fixture()
        g[0].accounting.reserve_output(REGULAR_BYTES-2)
        with patch.object(host.os,'readv',create=True) as read:
            with self.assertRaisesRegex(ProbeError,'call_budget_storage'):h._step(time.monotonic()+1)
        read.assert_not_called();self.assertEqual(data,b'')
        abi,maps=rf.fixture();begin=rf.begin(maps);_,raw=field_wire(begin,maps)
        g,h,data=self.step_fixture(limit=len(raw))
        def readv(fd,buffers):buffers[0][:15]=raw[:15];return 15
        with patch.object(host.os,'readv',readv,create=True):h._step(time.monotonic()+1)
        with patch.object(host.os,'readv',return_value=0,create=True):h._step(time.monotonic()+1)
        self.assertEqual(h.eofs,{'stdout'})
        with self.assertRaises(ProbeError):witness.field_receipts(bytes(data),begin,maps,abi)

    def test_registration_failure_after_failed_start_preserves_original_cause(self):
        g=self.graph();o=self.observation(g)
        with self.admitted(g):
            o._lease=g[2].begin_host_observation(g[3],g[4]);o.deadline_ns=g[5].deadline_ns
            first=ProbeError('INCOMPLETE','first_start_failure')
            def start(h,*args):h.child=child();raise first
            result,out=os.pipe()
            try:
                with patch.object(ParentOwnedHelper,'start',start),patch.object(capture._OwnedCallRuntime,
                    '_register_host_helper',side_effect=ProbeError('INCOMPLETE','later_registration_failure')):
                    with self.assertRaises(ProbeError) as caught:o._helper('fields',result,out,{},[],64)
                self.assertIs(caught.exception,first)
                self.assertEqual(o.secondary_failures,['host_helper_registration_failed'])
            finally:o.helpers['fields'].selector.close();os.close(result);os.close(out)

    def test_malformed_native_register_tuple_is_typed_before_effect(self):
        g=self.graph();object.__setattr__(g[4],'values',((1,8,0,1),))
        with patch.object(host.os,'open') as opened:
            with self.assertRaises(ProbeError):self.observation(g)
        opened.assert_not_called()

    def test_missing_helper_registration_denies_whole_observe_before_io(self):
        g=self.graph();o=self.observation(g)
        with self.admitted(g),patch.object(capture._OwnedCallRuntime,'_register_host_helper',None), \
             patch.object(host.os,'open') as opened:
            with self.assertRaisesRegex(ProbeError,'call_host_helper_registration_pending'):o.observe()
        opened.assert_not_called();self.assertIsNone(g[2]._host_lease)

    def test_cleanup_failure_does_not_replace_first_cause(self):
        g=self.graph();o=self.observation(g)
        helper=host._ParentHostHelper('c0_fields',0,g[5].deadline_ns,g[0].deadlines,
            budget=host._ParentBudget(g[1]));helper.selector.close()
        first=ProbeError('INCOMPLETE','original_field_failure')
        with patch.object(host._ParentHostHelper,'close',side_effect=ProbeError('INCOMPLETE','later_cleanup')):
            try:raise first
            except ProbeError:
                o._close_helper(helper)
                self.assertIs(sys.exception(),first)
        self.assertEqual(o.secondary_failures,['parent_helper_cleanup_failure'])
        with patch.object(host._ParentHostHelper,'close',side_effect=ProbeError('INCOMPLETE','normal_cleanup')):
            with self.assertRaisesRegex(ProbeError,'normal_cleanup'):o._close_helper(helper)

    def test_reused_observation_cannot_renew_lease_or_issue_again(self):
        g,o,r=self.observed();lease=o._lease
        with self.admitted(g),patch.object(host.os,'open') as opened:
            with self.assertRaisesRegex(ProbeError,'owned_observation_state'):o.observe()
        opened.assert_not_called();self.assertIs(o._lease,lease);self.assertIs(o._receipt,r)

    def test_finish_failure_rolls_back_receipt_and_preserves_attempt_cause(self):
        original=self.admitted
        @contextmanager
        def fail_finish(g):
            with original(g),patch.object(wiremod.CallWire,'finish_host_observation',
                    side_effect=ProbeError('INCOMPLETE','fixture_finish_failed')):
                yield
        with patch.object(self,'admitted',fail_finish):
            g,o,r=self.observed(changed='finish')
        self.assertIsNone(r);self.assertFalse(o._finished);self.assertIsNone(o._receipt)
        self.assertEqual(g[2]._failure.reason,'fixture_finish_failed')
        self.assertTrue(all(h.closed and h.reaped for h in o.helpers.values()))

    def fragmented_stream(self, chunks, *, interruptions=0):
        g,h,data=self.step_fixture(limit=1 << 20)
        pending=list(chunks)+[b''];calls=[];remaining=[interruptions]
        deadline=time.monotonic()+1
        def piece(count):
            calls.append(count)
            if remaining[0]:
                remaining[0]-=1
                raise BlockingIOError()
            raw=pending.pop(0)
            self.assertLessEqual(len(raw),count)
            return raw
        def read(fd,count):return piece(count)
        def readv(fd,buffers):
            self.assertEqual(len(buffers),1)
            raw=piece(len(buffers[0]));buffers[0][:len(raw)]=raw
            return len(raw)
        with patch.object(host.os,'read',read),patch.object(host.os,'readv',readv,create=True):
            while h.selector.live:h._step(deadline)
        return g,h,data,calls

    def test_fragmented_300bytes_matches_bulk_cost_and_original_deadline(self):
        fragmented=self.fragmented_stream([b'x']*300)
        bulk=self.fragmented_stream([b'x'*300])
        for g,h,data,calls in (fragmented,bulk):
            self.assertEqual(data,b'x'*300);self.assertEqual(h.eofs,{'stdout'})
            self.assertEqual(g[0].accounting.view()['actual_bytes'],65536+2*300)
        self.assertEqual(fragmented[0][0].accounting.view()['actual_bytes'],
                         bulk[0][0].accounting.view()['actual_bytes'])
        self.assertEqual(len(fragmented[3]),301);self.assertEqual(len(bulk[3]),2)

    def test_readv_eagain_eintr_and_eof_never_charge_request_sized_credit(self):
        g,h,data,calls=self.fragmented_stream([b'ok'],interruptions=100)
        self.assertEqual(data,b'ok');self.assertEqual(h.eofs,{'stdout'})
        self.assertEqual(g[0].accounting.view()['actual_bytes'],65536+4)
        self.assertEqual(len(calls),102)
        # A separate fresh stream remains usable after cancelled reads.
        self.assertEqual(self.fragmented_stream([b'fresh'])[2],b'fresh')


if __name__=='__main__':unittest.main()
