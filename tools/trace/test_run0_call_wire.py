"""Private socket mechanics only; patched Root guard supplies no live origin."""
from contextlib import ExitStack
import json
import os
import socket
import threading
import time
import unittest
from unittest.mock import patch

from boot_profile_capture import ProbeError
from run0_call_budget import ParentAccounting
from run0_call_owner import ParentDeadlines
import run0_call_capture as root
import run0_call_wire as w
from test_run0_c0_wire import frame,GREETING,COMMANDS,REQUESTS,REPLIES

class ParentWireTests(unittest.TestCase):
    def setUp(self):
        self.stack=ExitStack();self.addCleanup(self.stack.close)
    def endpoints(self):
        a,b=socket.socketpair();self.stack.enter_context(a);self.stack.enter_context(b)
        a.setblocking(False);b.settimeout(1);return a,b
    def wire(self):
        q,p=self.endpoints();streams={};peers={}
        for name in ('rsp','serial','debug','qemu_stdout','qemu_stderr'):
            streams[name],peers[name]=self.endpoints()
        now=time.monotonic_ns();r=object.__new__(root.ClosedOwnedCallRegistration)
        obj=object.__new__(w.CallWire)
        fields=dict(_owner=None,prepared=None,qemu_owner=None,wire=obj,deadlines=ParentDeadlines(now),
            accounting=ParentAccounting(now),inventory=None,parent_identity=object(),transition_owner=None,
            read_attempts={},read_operations={})
        for k,v in fields.items():object.__setattr__(r,k,v)
        obj._init_inert(r,q,streams);self.addCleanup(obj.close)
        return obj,p,peers
    def task(self,fn):
        errors=[]
        def run():
            try:fn()
            except BaseException as e:errors.append(e)
        t=threading.Thread(target=run,daemon=True);t.start()
        def check():
            t.join(2);self.assertFalse(t.is_alive(),'private peer remained alive')
            if errors:raise errors[0]
        self.addCleanup(check);return check
    def recv(self,peer,expected):
        raw=bytearray()
        while len(raw)<len(expected):
            chunk=peer.recv(len(expected)-len(raw));self.assertTrue(chunk);raw.extend(chunk)
        self.assertEqual(bytes(raw),expected)
    def fixture(self,obj,peer,replies=REPLIES):
        def run():
            peer.sendall(GREETING)
            for request,response in zip(REQUESTS,replies):
                self.recv(peer,request);peer.sendall(response)
        self.task(run)
        return obj.prelaunch()
    def no_send(self,peer):
        peer.setblocking(False)
        with self.assertRaises(BlockingIOError):peer.recv(1)
    def test_constructor_is_disabled_and_initialization_inert(self):
        with self.assertRaises(TypeError):w.CallWire()
        with patch('selectors.DefaultSelector',side_effect=AssertionError('constructor IO')):
            obj,peer,_=self.wire()
        self.assertIsNone(obj._selector);self.no_send(peer)
    def test_missing_genuine_root_refuses_before_read_or_send(self):
        obj,peer,_=self.wire();peer.sendall(GREETING)
        with self.assertRaises(ProbeError) as caught:obj.prelaunch()
        self.assertEqual(caught.exception.status,'INCOMPLETE')
        self.assertEqual(caught.exception.reason,'call_runtime_registration_pending')
        self.no_send(peer);self.assertIsNone(obj._selector)
    def test_actual_fixed_prelaunch_and_fresh_after_rejection(self):
        obj,peer,_=self.wire()
        with patch.object(w,'_root_guard',return_value=None):
            result=self.fixture(obj,peer)
        self.assertEqual(result.commands,tuple(COMMANDS))
        self.assertEqual(obj.raw('qmp-out'),b''.join(REQUESTS))
        self.assertEqual([r.seq for r in obj.operations],[1,2,3])
        self.assertEqual([r.charged_epoch for r in obj.operations],['C0']*3)
        self.assertTrue(all(r.result=='ok' for r in obj.operations))
    def test_wrong_boolean_qmp_id_denies_and_fresh_succeeds(self):
        obj,peer,_=self.wire()
        with patch.object(w,'_root_guard',return_value=None):
            with self.assertRaises(ProbeError):self.fixture(obj,peer,[frame({'return':{},'id':True})])
        self.assertEqual(obj.operations[0].result,'error');self.no_send(peer)
        self.test_actual_fixed_prelaunch_and_fresh_after_rejection()
    def test_prelaunch_event_retained_never_allows_next_request(self):
        obj,peer,_=self.wire();event=frame({'event':'RESUME','timestamp':{'seconds':1,'microseconds':0}})
        with patch.object(w,'_root_guard',return_value=None):
            with self.assertRaises(ProbeError):self.fixture(obj,peer,[REPLIES[0]+event])
        self.assertEqual(len(obj.events),1);self.no_send(peer)
        self.test_actual_fixed_prelaunch_and_fresh_after_rejection()

    def script(self,peer,rows):
        from test_run0_rsp import packet
        def run():
            for request,response in rows:
                self.recv(peer,packet(request));peer.sendall(b'+'+packet(response));self.recv(peer,b'+')
        return self.task(run)
    def test_real_reset_sequence_preserves_physical_mode_and_history(self):
        from test_run0_c0_rsp import reset_script
        obj,peer,peers=self.wire()
        with patch.object(w,'_root_guard',return_value=None):
            self.fixture(obj,peer);rows=reset_script();done=self.script(peers['rsp'],rows)
            result=obj.prepare_reset();done()
        self.assertEqual(result.physical_mode,1);self.assertEqual(result.registers.values[16],0xfff0)
        self.assertEqual(len(obj.operations),3+len(rows))
        self.assertEqual(obj._accounting.view()['allocated_operations'],len(obj.operations))
    def test_reset_wrong_rip_stops_before_mode_enable_and_fresh_succeeds(self):
        from test_run0_c0_rsp import reset_script
        obj,peer,peers=self.wire()
        with patch.object(w,'_root_guard',return_value=None):
            self.fixture(obj,peer);done=self.script(peers['rsp'],reset_script(rip=0x1234)[:-4])
            with self.assertRaises(ProbeError) as caught:obj.prepare_reset()
            done()
        self.assertEqual(caught.exception.reason,'rsp_reset_rip');self.no_send(peers['rsp'])
        self.test_real_reset_sequence_preserves_physical_mode_and_history()

    def prior(self):
        from run0_c0_entry import ValidatedPriorEntry
        from boot_profile_capture import VAPIC_OFF_INVOCATION_PROFILE
        token=object.__new__(ValidatedPriorEntry)
        values=dict(profile_ref=('profile.json','0'*64,1),probe_profile_sha256='0'*64,
            prior_admission_ref=('admission.json','1'*64,1),profile_mapping_ref=('mapping.json','2'*64,1),
            entry_address=0x2000,loaded_base=0x1000,diagnostic_ref=('diagnostic.txt','3'*64,1),
            diagnostic_line=1,prior_run_id='private-fixture',expected_entry_hex='0'*64,
            invocation_profile=VAPIC_OFF_INVOCATION_PROFILE,scope='prior-run-hint-only')
        for key,value in values.items():object.__setattr__(token,key,value)
        return token
    def ready(self):
        from test_run0_c0_rsp import reset_script
        obj,peer,peers=self.wire();self.fixture(obj,peer);done=self.script(peers['rsp'],reset_script())
        obj.prepare_reset();done();return obj,peer,peers
    def entry_peer(self,peer,rpeer,*,rsp_first=False,tail=b'',rtc=False):
        from test_run0_rsp import packet
        resume=frame({'event':'RESUME','timestamp':{'seconds':1,'microseconds':0}})
        stop=frame({'event':'STOP','timestamp':{'seconds':1,'microseconds':1}})
        rtc_frame=frame({'event':'RTC_CHANGE','timestamp':{'seconds':1,'microseconds':2},
            'data':{'offset':0,'qom-path':'/machine/unattached/device[1]/rtc'}}) if rtc else b''
        def run():
            self.recv(rpeer,packet(b'Z1,2000,1'));rpeer.sendall(b'+'+packet(b'OK'));self.recv(rpeer,b'+')
            self.recv(rpeer,packet(b'c'))
            if rsp_first:rpeer.sendall(b'+'+packet(b'T05thread:01;')+tail)
            peer.sendall(resume+stop+rtc_frame)
            if not rsp_first:rpeer.sendall(b'+'+packet(b'T05thread:01;')+tail)
            if tail:return
            self.recv(rpeer,b'+')
            self.recv(peer,frame({'execute':'query-status','id':4}))
            peer.sendall(frame({'return':{'status':'debug','running':False,'singlestep':False},'id':4}))
        return self.task(run)
    def test_initial_flight_cross_channel_orders_and_rtc_context(self):
        for rsp_first in (False,True):
            with self.subTest(rsp_first=rsp_first),patch.object(w,'_root_guard',return_value=None):
                obj,peer,peers=self.ready();done=self.entry_peer(peer,peers['rsp'],rsp_first=rsp_first,rtc=True)
                stop=obj.stop_at_entry(self.prior());done()
                self.assertIs(type(stop),w.EpochStopReceipt);self.assertEqual(stop.epoch,'C0')
                self.assertEqual(obj._state,'STOPPED');self.assertEqual(obj.operations[-1].operation,'query_status')
                names=[e.name for e in obj.events];self.assertEqual(names.count('RESUME'),1);self.assertEqual(names.count('STOP'),1)
                self.assertEqual(names.count('T05thread:01;'),1)
                event=next(e for e in obj.events if e.name=='RTC_CHANGE');self.assertIsNone(event.cause_epoch);self.assertIsNone(event.flight_id)
                self.assertEqual(obj.flights[0].result,'ok');self.assertEqual(obj.flights[0].debug_operation_seq,stop.debug_operation_seq)
    def test_extra_stop_tail_refuses_outgoing_ack_then_fresh_succeeds(self):
        with patch.object(w,'_root_guard',return_value=None):
            obj,peer,peers=self.ready();done=self.entry_peer(peer,peers['rsp'],tail=b'$')
            with self.assertRaises(ProbeError):obj.stop_at_entry(self.prior())
            done();self.no_send(peers['rsp']);self.assertEqual(obj._state,'FAILED')
        self.test_initial_flight_cross_channel_orders_and_rtc_context()

    def stopped(self):
        obj,peer,peers=self.ready();done=self.entry_peer(peer,peers['rsp'])
        stop=obj.stop_at_entry(self.prior());done();return obj,peer,peers,stop
    def mode_registers(self,obj,peers,stop):
        from run0_c0_acquire import REGISTER_WIDTHS
        values={n:0 for n,_ in REGISTER_WIDTHS}
        values.update({16:0x2000,17:2,18:0x38,27:0x80000011,29:0x1000,30:0x20,32:0x500})
        script=[(b'qqemu.PhyMemMode',b'1')]+[(f'p{n:x}'.encode(),values[n].to_bytes(width,'little').hex().encode()) for n,width in REGISTER_WIDTHS]
        done=self.script(peers['rsp'],script);obj.confirm_stopped_physical_mode(stop)
        registers=obj.read_selected_registers(stop,'before');done();return registers,values
    def test_host_lease_exact_before_and_original_deadline(self):
        with patch.object(w,'_root_guard',return_value=None):
            obj,peer,peers,stop=self.stopped();registers,values=self.mode_registers(obj,peers,stop)
            lease=obj.begin_host_observation(stop,registers)
            self.assertIs(type(registers),w.SelectedEpochRegisters)
            self.assertEqual(len(registers.values),29);self.assertTrue(all(len(r)==4 for r in registers.values))
            self.assertIs(type(lease),w.ParentHostLease);self.assertIs(lease.stop,stop)
            self.assertLessEqual(lease.deadline_ns-lease.started_ns,5_000_000_000)
            obj.pump_host_observation(lease)
            with self.assertRaises(ProbeError):obj.begin_host_observation(stop,registers)
            with patch.object(w.time,'monotonic_ns',return_value=lease.deadline_ns):
                with self.assertRaises(ProbeError):obj.pump_host_observation(lease)
            self.no_send(peers['rsp'])
        # Separate fresh real prefix after failed/expired original observation.
        with patch.object(w,'_root_guard',return_value=None):
            fresh,qp,rp,stop=self.stopped();regs,_=self.mode_registers(fresh,rp,stop)
            self.assertIs(fresh.begin_host_observation(stop,regs).stop,stop)

    def synthetic_closed(self,obj):
        # Only private socket-mechanics setup: this ledger prefix/closure has no
        # runtime registration, host/RAM issuer, real captured bytes or PASS claim.
        from run0_call_budget import BEFORE,AFTER
        from run0_call_owner import ClosedEpochReceipt
        ledger=obj._accounting;epoch=obj._epoch
        while ledger._before<len(BEFORE[epoch]):ledger.reserve_operation(epoch,BEFORE[epoch][ledger._before])
        while ledger._after<len(AFTER[epoch])- (1 if epoch=='C2' else 2)-1:
            ledger.reserve_operation(epoch,AFTER[epoch][ledger._after])
        c=object.__new__(ClosedEpochReceipt)
        for name,value in dict(_owner=obj._registration.transition_owner,_wire=obj,_epoch=epoch,_memory_revoked=True).items():
            object.__setattr__(c,name,value)
        return c
    def synthetic_target(self,obj,closed,address):
        target=object.__new__(root.BoundCallTarget)
        fields=dict(_owner=None,registration=obj._registration,closed=closed,source_fact=object(),
            source_epoch=obj._epoch,target_epoch='C1' if obj._epoch=='C0' else 'C2',address=address,
            source_closure_ref=(f'epochs/{obj._epoch}/closure.json','4'*64,2))
        for name,value in fields.items():object.__setattr__(target,name,value)
        return target
    def transition_guard(self,obj,name,*args,**kwargs):
        if name!='_issue_wire_transition':return None
        from run0_call_owner import (NativeTransitionOwner,ClosedEpochReceipt,BreakpointClearReceipt,
            BreakpointSetReceipt,TransitionReservation,QuietReceipt,TransitionJournalReceipt)
        closed,target=args;owner=obj._registration.transition_owner
        if owner is None:
            owner=object.__new__(NativeTransitionOwner)
            for n,v in dict(_policy=obj._policy,_wire=obj,_ledger=obj._accounting,_tickets=[],_registered=True).items():setattr(owner,n,v)
            object.__setattr__(obj._registration,'transition_owner',owner);obj._policy._owner=owner
        owner._epoch=obj._epoch;owner._source_stop_ns=obj._stop.received_ns
        owner._admission_started_ns=obj._transition_started_ns;owner._used=False;owner._held={}
        closed._owner=owner
        for kind in (ClosedEpochReceipt,BreakpointClearReceipt,BreakpointSetReceipt,TransitionReservation,QuietReceipt,TransitionJournalReceipt):
            proof=closed if kind is ClosedEpochReceipt else object.__new__(kind)
            for n,v in dict(_owner=owner,_wire=obj,_epoch=obj._epoch).items():setattr(proof,n,v)
            if kind is TransitionReservation:proof._ledger=obj._accounting
            if kind is QuietReceipt:proof._observed_ns=obj._transition_quiet_ns
            if kind is TransitionJournalReceipt:
                proof._ref=(f'transitions/{obj._epoch}.json','5'*64,2);proof._flushed_ns=time.monotonic_ns()
            owner._held[kind]=proof
        return owner.issue_admission(*owner._held.values(),now_ns=time.monotonic_ns())
    def next_peer(self,peer,rpeer,old,new,qid,*,quit=False,reply=True):
        from test_run0_rsp import packet
        def run():
            self.recv(rpeer,packet(f'z1,{old:x},1'.encode()));rpeer.sendall(b'+'+packet(b'OK'));self.recv(rpeer,b'+')
            if quit:
                self.recv(peer,json.dumps({'execute':'quit','id':qid},separators=(',',':')).encode())
                if reply:peer.sendall(frame({'return':{},'id':qid}))
                peer.shutdown(socket.SHUT_WR)
                for endpoint in self._closing_peers.values():endpoint.shutdown(socket.SHUT_WR)
                return
            self.recv(rpeer,packet(f'Z1,{new:x},1'.encode()));rpeer.sendall(b'+'+packet(b'OK'));self.recv(rpeer,b'+')
            self.recv(rpeer,packet(b'c'))
            peer.sendall(frame({'event':'RESUME','timestamp':{'seconds':2,'microseconds':0}})+
                frame({'event':'STOP','timestamp':{'seconds':2,'microseconds':1}}))
            rpeer.sendall(b'+'+packet(b'T05thread:01;'));self.recv(rpeer,b'+')
            self.recv(peer,frame({'execute':'query-status','id':qid}))
            peer.sendall(frame({'return':{'status':'debug','running':False,'singlestep':False},'id':qid}))
        return self.task(run)
    def three_flights(self):
        obj,peer,peers,stop=self.stopped()
        initial_hard=obj._policy.effective_hard_ns
        for old,new,qid in ((0x2000,0x3000,5),(0x3000,0x4000,6)):
            closed=self.synthetic_closed(obj);target=self.synthetic_target(obj,closed,new)
            done=self.next_peer(peer,peers['rsp'],old,new,qid)
            ticket=obj.prepare_transition(closed,target);stop=obj.resume_to_next(ticket);done()
            self.assertIs(stop.target,target);self.assertEqual(stop.epoch,target.target_epoch)
            self.assertEqual(obj.flights[-1].source_closure_ref,target.source_closure_ref)
            self.assertEqual(obj._policy.effective_hard_ns,initial_hard+90_000_000_000)
        return obj,peer,peers,stop
    def test_three_flights_one_owner_and_strict_quit(self):
        with patch.object(w,'_root_guard',side_effect=self.transition_guard):
            obj,peer,peers,stop=self.three_flights();owner=obj._registration.transition_owner
            self.assertIs(owner,obj._policy._first_owner);self.assertEqual(len(owner._tickets),2)
            closed=self.synthetic_closed(obj);self._closing_peers=peers
            done=self.next_peer(peer,peers['rsp'],0x4000,None,7,quit=True)
            receipt=obj.terminate_parent(closed);done()
            self.assertIs(type(receipt),w.ParentDrainReceipt);self.assertEqual(len(receipt.eofs),6)
            self.assertIsNone(receipt.failure);self.assertEqual(receipt.quit_operation.result,'ok')
            self.assertFalse(obj.raw('qmp-out').endswith(b'\r\n'));self.assertEqual(len(obj.flights),3)
    def test_failure_only_drain_zero_send_preserves_cause(self):
        with patch.object(w,'_root_guard',return_value=None):
            obj,peer,peers=self.ready();obj._latch_failure(w.Failure('DENY','original'))
            before=len(obj.raw('rsp-out'));qbefore=len(obj.raw('qmp-out'))
            peer.sendall(b'partial');peer.shutdown(socket.SHUT_WR)
            for name,p in peers.items():p.sendall(b'bad' if name=='rsp' else b'tail');p.shutdown(socket.SHUT_WR)
            receipt=obj._drain_failed_owner(obj._policy.effective_hard_ns)
            self.assertEqual(len(receipt.eofs),6);self.assertEqual(obj.failure.reason,'original')
            self.assertEqual(len(obj.raw('rsp-out')),before);self.assertEqual(len(obj.raw('qmp-out')),qbefore)
            self.assertTrue(obj.raw('rsp').endswith(b'bad'));self.no_send(peer);self.no_send(peers['rsp'])
        self.test_actual_fixed_prelaunch_and_fresh_after_rejection()

    def test_quit_eof_without_matching_reply_refuses_then_fresh_succeeds(self):
        with patch.object(w,'_root_guard',side_effect=self.transition_guard):
            obj,peer,peers,stop=self.three_flights();closed=self.synthetic_closed(obj);self._closing_peers=peers
            done=self.next_peer(peer,peers['rsp'],0x4000,None,7,quit=True,reply=False)
            with self.assertRaises(ProbeError):obj.terminate_parent(closed)
            done();self.assertIsNone(obj._quit_reply);self.assertEqual(obj._quit.result,'error')
            obj._drain_failed_owner(obj._policy.effective_hard_ns)
            self.assertEqual(len(obj.eofs),6);self.assertIsNotNone(obj.failure)
        self.test_three_flights_one_owner_and_strict_quit()
    def test_post_quit_rsp_exit_packet_is_failure_not_whitelisted(self):
        from test_run0_rsp import packet
        with patch.object(w,'_root_guard',side_effect=self.transition_guard):
            obj,peer,peers,stop=self.three_flights();closed=self.synthetic_closed(obj)
            def run():
                self.recv(peers['rsp'],packet(b'z1,4000,1'));peers['rsp'].sendall(b'+'+packet(b'OK'));self.recv(peers['rsp'],b'+')
                self.recv(peer,b'{"execute":"quit","id":7}');peer.sendall(frame({'return':{},'id':7}));peer.shutdown(socket.SHUT_WR)
                peers['rsp'].sendall(packet(b'W00'))
                for endpoint in peers.values():endpoint.shutdown(socket.SHUT_WR)
            done=self.task(run)
            with self.assertRaises(ProbeError):obj.terminate_parent(closed)
            done();self.assertIsNotNone(obj.failure);self.assertTrue(obj.raw('rsp').endswith(packet(b'W00')))
        self.test_three_flights_one_owner_and_strict_quit()

    def read_setup(self,obj,*,prepay=True):
        import tempfile
        from pathlib import Path
        import run0_call_read as r
        from test_run0_call_budget import frame_charges
        from test_run0_call_read import private
        from run0_call_budget import BEFORE
        # The missing live host/session producer is patched ONLY at Root guard.
        # These setup rows are explicit fixture facts, never protocol evidence.
        ledger=obj._accounting
        while ledger._before<len(BEFORE['C0']):
            name=BEFORE['C0'][ledger._before];ledger.reserve_operation('C0',name)
            obj._operations.append(w.Operation(len(obj._operations)+1,'C0','fixture',name,time.monotonic_ns(),result='fixture-only'))
        batch=ledger.reserve_reads('C0',frame_charges())
        if prepay:ledger.reserve_wire_batch(batch)
        temp=tempfile.TemporaryDirectory(prefix='call-wire-physical-');self.addCleanup(temp.cleanup)
        session,binding=object(),object();retainer=private(r._ReadRetainer,
            _parent=obj._registration.parent_identity,_wire=obj,_session=session,_binding=binding,
            _transport=('rsp',1,2),_accounting=ledger,_root=Path(temp.name),_raw={n:obj._raw[n] for n in ('rsp','rsp-out')},
            _operations=obj._read_operations,_attempts=obj._read_attempts,
            _pending=None,_receipts={},_rows={},_inventory={},_slots={},_retained_pending={},
            _prepared={},_failures={},_deadline_ns=obj._limit(),_revoked=False,
            _origin='synthetic_fixture',_plan_ref=r.BlobRef('plan.json','0'*64,2))
        registered=private(root.RegisteredCurrentEpochBinding,_owner=None,registration=obj._registration,
            binding=binding,session=session,retainer=retainer,host_receipt=object(),layout_receipt=object())
        obj._host_receipt=registered.host_receipt;obj._layout_before=registered.layout_receipt
        grants=[object() for _ in batch.charges];state={'index':0,'revoked':False,'commits':0,'seal_error':False,'commit_interrupt':False}
        def guard(wire,name,*args,**kwargs):
            self.assertIs(wire,obj)
            if name=='_prepare_wire_read':
                self.assertIs(args[0],grants[state['index']]);key=r.ReadKey('C0',state['index']+1,state['index'],kwargs['operation_seq'])
                return retainer.prepare(batch,state['index'],key,batch.charges[state['index']].target)
            if name=='_commit_wire_read':
                grant,pending=args;self.assertIs(grant,grants[state['index']]);self.assertFalse(state['revoked'])
                attempt=private(r._HeldReadAttempt,_parent=obj._registration.parent_identity,_wire=obj,
                    key=pending.key,target=pending.target,started_ns=obj.operations[-1].started_ns,finished_ns=None,result='pending')
                obj._read_attempts[pending.key.operation_seq]=attempt;state['commits']+=1
                if state['commit_interrupt']:raise KeyboardInterrupt()
                return attempt
            if name=='_recheck_wire_read':
                if state['revoked']:raise ProbeError('DENY','fixture_revoked')
                self.assertIs(obj._read_attempts[args[0].key.operation_seq],args[0])
            if name=='_seal_wire_read':
                pending,op=args
                if state['seal_error']:raise ProbeError('INCOMPLETE','fixture_retention_failure')
                result=retainer.seal(pending,operation=op,request_position=op.request_position,
                    request_ack_position=op.request_ack_position,response_position=op.response_position,
                    response_ack_position=op.response_ack_position,request_bytes=kwargs['request_bytes'],
                    response_bytes=kwargs['response_bytes'],started_ns=op.started_ns,
                    response_received_ns=op.response_received_ns,ack_finished_ns=op.ack_finished_ns)
                state['index']+=1;return result
        return registered,session,retainer,grants,state,guard
    def test_physical_actual_raw_ack_data_files_and_final_commit(self):
        with patch.object(w,'_root_guard',return_value=None):obj,peer,peers,stop=self.stopped()
        registered,session,retainer,grants,state,guard=self.read_setup(obj)
        with patch.object(w,'_root_guard',side_effect=guard):
            obj.bind_acquisition(registered,session)
            target=retainer._accounting._batches[next(iter(retainer._accounting._batches))]['reservation'].charges[0].target
            done=self.script(peers['rsp'],[(f'm{target.gpa:x},{target.length:x}'.encode(),b'42'*2048)])
            receipt=obj.read_physical(grants[0]);done()
            self.assertEqual(receipt.data,b'B'*2048);self.assertEqual(state['commits'],1)
            self.assertEqual(obj.operations[-1].finished_ns,receipt.finished_ns)
            self.assertEqual(obj.operations[-1].result,'ok');self.assertEqual(len(retainer.inventory()),3)
            ack=obj._read_operations[receipt.operation_seq];self.assertIs(ack.attempt,obj._read_attempts[receipt.operation_seq])
            self.assertLessEqual(ack.ack_finished_ns,receipt.finished_ns)
            self.assertEqual(receipt.response_payload,b'42'*2048)
    def test_unpaid_physical_copy_refuses_before_any_request_or_admission(self):
        with patch.object(w,'_root_guard',return_value=None):obj,peer,peers,stop=self.stopped()
        registered,session,retainer,grants,state,guard=self.read_setup(obj,prepay=False)
        with patch.object(w,'_root_guard',side_effect=guard):
            obj.bind_acquisition(registered,session)
            with self.assertRaises(ProbeError):obj.read_physical(grants[0])
        self.assertEqual(state['commits'],0);self.no_send(peers['rsp']);self.assertEqual(retainer.inventory(),())
        self.test_physical_actual_raw_ack_data_files_and_final_commit()

    def test_admitted_zero_partial_and_interrupted_sends_keep_same_attempt(self):
        for mode in ('revoke_after_eagain','interrupt','partial','commit_interrupt'):
            with self.subTest(mode=mode),patch.object(w,'_root_guard',return_value=None):
                obj,peer,peers,stop=self.stopped()
            registered,session,retainer,grants,state,guard=self.read_setup(obj)
            endpoint=obj._rsp_socket
            class Boundary:
                calls=0
                def fileno(self):return endpoint.fileno()
                def send(self,data):
                    self.calls+=1
                    if mode=='revoke_after_eagain':state['revoked']=True;raise BlockingIOError()
                    if mode=='interrupt':raise KeyboardInterrupt()
                    if self.calls==1:return endpoint.send(data[:1])
                    raise BrokenPipeError(32,'private boundary')
            obj._rsp_socket=Boundary();state['commit_interrupt']=mode=='commit_interrupt'
            with patch.object(w,'_root_guard',side_effect=guard):
                obj.bind_acquisition(registered,session)
                with self.assertRaises((ProbeError,KeyboardInterrupt)):obj.read_physical(grants[0])
                row=obj.operations[-1];held=obj._read_attempts[row.seq]
                self.assertEqual(state['commits'],1);self.assertNotEqual(held.result,'pending')
                self.assertEqual(row.request.length if row.request else 0,1 if mode=='partial' else 0)
                self.assertEqual(retainer.inventory(),());self.assertNotIn(row.seq,obj._read_operations)
                with self.assertRaises(ProbeError):obj.read_physical(grants[0])
                self.assertEqual(state['commits'],1)
            if mode=='partial':self.recv(peers['rsp'],b'$')
            self.no_send(peers['rsp'])
        self.test_physical_actual_raw_ack_data_files_and_final_commit()
    def test_ack_success_retention_failure_preserves_ack_fact(self):
        with patch.object(w,'_root_guard',return_value=None):obj,peer,peers,stop=self.stopped()
        registered,session,retainer,grants,state,guard=self.read_setup(obj);state['seal_error']=True
        with patch.object(w,'_root_guard',side_effect=guard):
            obj.bind_acquisition(registered,session)
            target=next(iter(obj._accounting._batches.values()))['reservation'].charges[0].target
            done=self.script(peers['rsp'],[(f'm{target.gpa:x},{target.length:x}'.encode(),b'42'*2048)])
            with self.assertRaises(ProbeError) as caught:obj.read_physical(grants[0])
            done();self.assertEqual(caught.exception.reason,'fixture_retention_failure')
            row=obj.operations[-1];self.assertEqual(row.result,'error')
            self.assertEqual(obj._read_attempts[row.seq].result,'ok');self.assertEqual(obj._read_operations[row.seq].result,'ok')
            self.assertEqual(retainer.inventory(),())
        self.test_physical_actual_raw_ack_data_files_and_final_commit()
    def test_first_half_survives_later_bad_hex_without_frame_assembly(self):
        from test_run0_rsp import packet
        with patch.object(w,'_root_guard',return_value=None):obj,peer,peers,stop=self.stopped()
        registered,session,retainer,grants,state,guard=self.read_setup(obj)
        with patch.object(w,'_root_guard',side_effect=guard):
            obj.bind_acquisition(registered,session);batch=next(iter(obj._accounting._batches.values()))['reservation']
            t=batch.charges[0].target;done=self.script(peers['rsp'],[(f'm{t.gpa:x},{t.length:x}'.encode(),b'42'*2048)])
            first=obj.read_physical(grants[0]);done();t=batch.charges[1].target
            def bad():
                self.recv(peers['rsp'],packet(f'm{t.gpa:x},{t.length:x}'.encode()))
                peers['rsp'].sendall(b'+'+packet(b'g0'*2048))
            done=self.task(bad)
            with self.assertRaises(ProbeError):obj.read_physical(grants[1])
            done();self.no_send(peers['rsp']);self.assertEqual(len(retainer.inventory()),3)
            self.assertEqual((retainer._root/first.decoded_data_ref.path).read_bytes(),b'B'*2048)
            self.assertFalse((retainer._root/'epochs/C0/frames/00-first.bin').exists())
        self.test_physical_actual_raw_ack_data_files_and_final_commit()
    def test_physical_fragmented_growth_stays_inside_separate_credit(self):
        with patch.object(w,'_root_guard',return_value=None):obj,peer,peers,stop=self.stopped()
        registered,session,retainer,grants,state,guard=self.read_setup(obj)
        endpoint=obj._rsp_socket
        class OneByte:
            def fileno(self):return endpoint.fileno()
            def send(self,data):return endpoint.send(data[:1])
        obj._rsp_socket=OneByte()
        with patch.object(w,'_root_guard',side_effect=guard),patch.object(w,'READ_CHUNK',1):
            obj.bind_acquisition(registered,session);batch=next(iter(obj._accounting._batches.values()))['reservation'];t=batch.charges[0].target
            done=self.script(peers['rsp'],[(f'm{t.gpa:x},{t.length:x}'.encode(),b'42'*2048)])
            receipt=obj.read_physical(grants[0]);done();self.assertEqual(receipt.data,b'B'*2048)
            remaining=obj._accounting._wire_batches[id(batch)]['remaining'][0]
            self.assertGreaterEqual(remaining,726)
            self.assertEqual(obj._physical_frames,2)
    def test_physical_malformed_frame_flood_capped_before_fourth_row(self):
        from test_run0_rsp import packet
        with patch.object(w,'_root_guard',return_value=None):obj,peer,peers,stop=self.stopped()
        registered,session,retainer,grants,state,guard=self.read_setup(obj)
        with patch.object(w,'_root_guard',side_effect=guard):
            obj.bind_acquisition(registered,session);batch=next(iter(obj._accounting._batches.values()))['reservation'];t=batch.charges[0].target
            def flood():
                self.recv(peers['rsp'],packet(f'm{t.gpa:x},{t.length:x}'.encode()));peers['rsp'].sendall(b'+'*4102)
            done=self.task(flood)
            with self.assertRaises(ProbeError):obj.read_physical(grants[0])
            done();self.assertEqual(obj._physical_frames,3);self.no_send(peers['rsp'])
            self.assertGreaterEqual(obj._accounting._wire_batches[id(batch)]['remaining'][0],726)
        self.test_physical_actual_raw_ack_data_files_and_final_commit()

    def qmp_script(self,obj,peer,rows):
        first=obj._qmp_identifier+1
        def run():
            for ident,(command,args,response) in enumerate(rows,first):
                request={'execute':command,'id':ident}
                if args is not None:request['arguments']=args
                self.recv(peer,frame(request));peer.sendall(frame({'return':response,'id':ident}))
        return self.task(run)
    def bracket_rows(self,values,tid=123):
        from test_run0_c0_decode import synthetic_c0_hmp
        path='/machine/unattached/device[0]'
        return [('query-status',None,{'status':'debug','running':False,'singlestep':False}),
            ('query-cpus-fast',None,[{'cpu-index':0,'qom-path':path,'target':'x86_64','thread-id':tid,'props':{}}]),
            ('qom-get',{'path':path,'property':'realized'},True),
            ('qom-get',{'path':path,'property':'phys-bits'},40),
            ('human-monitor-command',{'command-line':'info registers'},synthetic_c0_hmp(values))]
    def host_fixture(self,obj,peer,peers,stop):
        import struct
        from test_run0_call_read import private
        import run0_call_host as host
        regs,values=self.mode_registers(obj,peers,stop);lease=obj.begin_host_observation(stop,regs)
        # Synthetic Linux credential bytes on portable private sockets, not a PID
        # or real helper-origin claim. No production fixture path exists.
        with patch.object(socket.socket,'getsockopt',return_value=struct.pack('=iii',123,456,789)):
            obj.host_peer_credentials(lease)
        for phase in ('before','after'):
            done=self.qmp_script(obj,peer,self.bracket_rows(values));obj.host_bracket(lease,phase);done()
        runtime=object.__new__(root._OwnedCallRuntime);runtime._registration=obj._registration;runtime._wire=obj
        object.__setattr__(obj._registration,'_owner',runtime)
        observation=object.__new__(host._OwnedParentObservation)
        receipt=private(host.ParentHostObservationReceipt,_owner=observation,_registration=obj._registration,
            _wire=obj,epoch=stop.epoch,stop=stop,lease=lease,before_registers=regs,before_bracket=obj._host_before,
            after_bracket=obj._host_after,finished_ns=time.monotonic_ns(),process_identity=(),field_state=(),
            field_reads=(),helper_lifecycles=())
        for n,v in dict(_receipt=receipt,_finished=True,_registration=obj._registration,_wire=obj,
            _lease=lease,_confirmed=stop,_registers=regs).items():setattr(observation,n,v)
        runtime._observations={stop.epoch:observation};obj.finish_host_observation(lease,receipt)
        return values,receipt
    def test_actual_host_brackets_and_closed_after_suffix(self):
        from test_run0_rsp_capability import ACTUAL_ENTRY_LAYOUT
        from test_run0_c0_decode import synthetic_c0_hmp
        from run0_c0_acquire import REGISTER_WIDTHS
        from test_run0_call_read import private
        with patch.object(w,'_root_guard',return_value=None):
            obj,peer,peers,stop=self.stopped();values,host=self.host_fixture(obj,peer,peers,stop)
            before=obj._host_before;after=obj._host_after
            self.assertEqual(tuple(k for k,_ in before.operations),('status_seq','cpu_seq','realized_seq','phys_bits_seq','hmp_seq'))
            self.assertGreater(after.operations[0][1],before.operations[-1][1])
            done=self.qmp_script(obj,peer,[('human-monitor-command',{'command-line':'info mtree -f'},ACTUAL_ENTRY_LAYOUT)])
            layout=obj.read_current_layout(stop,'before');done()
            self.assertEqual(layout.ranges,((0,0xa0000),(0x100000,0x20000000)))
            session=object();registered=private(root.RegisteredCurrentEpochBinding,_owner=None,
                registration=obj._registration,binding=object(),session=session,retainer=None,
                host_receipt=host,layout_receipt=layout)
            obj.bind_acquisition(registered,session)
            rdone=self.script(peers['rsp'],[(f'p{n:x}'.encode(),values[n].to_bytes(width,'little').hex().encode()) for n,width in REGISTER_WIDTHS])
            qdone=self.qmp_script(obj,peer,[('human-monitor-command',{'command-line':'info registers'},synthetic_c0_hmp(values)),
                ('human-monitor-command',{'command-line':'info mtree -f'},ACTUAL_ENTRY_LAYOUT)])
            complete=object();receipt=obj.complete_phase(complete);rdone();qdone()
            self.assertIs(receipt,obj._after_receipt);self.assertIs(receipt.reads_complete,complete)
            self.assertIs(receipt.stop,stop);self.assertEqual(receipt.layout.raw_bytes,layout.raw_bytes)
            self.assertGreater(receipt.hmp.operation_seq,receipt.registers.values[-1][3])
            self.assertGreater(receipt.layout.operation_seq,receipt.hmp.operation_seq)
            with self.assertRaises(ProbeError):obj.complete_phase(complete)
            self.no_send(peer);self.no_send(peers['rsp'])
    def test_changed_host_tid_refuses_completion_then_fresh_succeeds(self):
        import struct
        with patch.object(w,'_root_guard',return_value=None):
            obj,peer,peers,stop=self.stopped();regs,values=self.mode_registers(obj,peers,stop)
            lease=obj.begin_host_observation(stop,regs)
            with patch.object(socket.socket,'getsockopt',return_value=struct.pack('=iii',123,456,789)):obj.host_peer_credentials(lease)
            done=self.qmp_script(obj,peer,self.bracket_rows(values));obj.host_bracket(lease,'before');done()
            done=self.qmp_script(obj,peer,self.bracket_rows(values,124))
            with self.assertRaises(ProbeError) as caught:obj.host_bracket(lease,'after')
            done();self.assertEqual(caught.exception.reason,'call_host_bracket_changed');self.assertIsNone(obj._host_after)
            self.no_send(peer);self.no_send(peers['rsp'])
        self.test_actual_host_brackets_and_closed_after_suffix()

    def test_blocked_stop_ack_rechecks_partial_tail_before_eventual_plus(self):
        from test_run0_rsp import packet
        with patch.object(w,'_root_guard',return_value=None):
            obj,peer,peers=self.ready();endpoint=obj._rsp_socket
            def run():
                self.recv(peers['rsp'],packet(b'Z1,2000,1'));peers['rsp'].sendall(b'+'+packet(b'OK'));self.recv(peers['rsp'],b'+')
                self.recv(peers['rsp'],packet(b'c'))
                peer.sendall(frame({'event':'RESUME','timestamp':{'seconds':1,'microseconds':0}})+frame({'event':'STOP','timestamp':{'seconds':1,'microseconds':1}}))
                peers['rsp'].sendall(b'+'+packet(b'T05thread:01;'))
            done=self.task(run)
            class BlockAck:
                def fileno(self):return endpoint.fileno()
                def send(self,data):
                    if obj._state=='STOP_ACK':peers['rsp'].sendall(b'$');raise BlockingIOError()
                    return endpoint.send(data)
            obj._rsp_socket=BlockAck()
            with self.assertRaises(ProbeError):obj.stop_at_entry(self.prior())
            done();self.no_send(peers['rsp']);self.assertEqual(obj.operations[-1].operation,'stop_ack')
            self.assertIsNone(obj.operations[-1].request);self.assertTrue(obj.raw('rsp').endswith(b'$'))
        self.test_initial_flight_cross_channel_orders_and_rtc_context()
    def test_stop_after_debug_reply_cannot_retroactively_close_fence(self):
        from test_run0_rsp import packet
        with patch.object(w,'_root_guard',return_value=None):
            obj,peer,peers=self.ready()
            def run():
                self.recv(peers['rsp'],packet(b'Z1,2000,1'));peers['rsp'].sendall(b'+'+packet(b'OK'));self.recv(peers['rsp'],b'+')
                self.recv(peers['rsp'],packet(b'c'));peer.sendall(frame({'event':'RESUME','timestamp':{'seconds':1,'microseconds':0}}))
                peers['rsp'].sendall(b'+'+packet(b'T05thread:01;'));self.recv(peers['rsp'],b'+')
                self.recv(peer,frame({'execute':'query-status','id':4}))
                peer.sendall(frame({'return':{'status':'debug','running':False,'singlestep':False},'id':4})+
                    frame({'event':'STOP','timestamp':{'seconds':1,'microseconds':1}}))
            done=self.task(run)
            with self.assertRaises(ProbeError) as caught:obj.stop_at_entry(self.prior())
            done();self.assertEqual(caught.exception.reason,'call_debug_fence_order');self.assertIsNone(obj._stop)
        self.test_initial_flight_cross_channel_orders_and_rtc_context()
    def test_failed_transition_journal_never_resumes_or_selects_parent_deadline(self):
        with patch.object(w,'_root_guard',return_value=None):obj,peer,peers,stop=self.stopped()
        closed=self.synthetic_closed(obj);target=self.synthetic_target(obj,closed,0x3000);hard=obj._policy.effective_hard_ns
        def guard(obj,name,*args,**kwargs):
            if name=='_issue_wire_transition':raise ProbeError('INCOMPLETE','fixture_journal_write')
        with patch.object(w,'_root_guard',side_effect=guard):
            done=self.script(peers['rsp'],[(b'z1,2000,1',b'OK'),(b'Z1,3000,1',b'OK')])
            with self.assertRaises(ProbeError):obj.prepare_transition(closed,target)
            done();self.assertEqual(obj._policy.effective_hard_ns,hard);self.assertIsNone(obj._ticket)
            self.assertEqual(len(obj.flights),1);self.no_send(peers['rsp'])
        self.test_three_flights_one_owner_and_strict_quit()
    def test_committed_transition_partial_c_keeps_selected_hard_and_no_stop(self):
        with patch.object(w,'_root_guard',side_effect=self.transition_guard):
            obj,peer,peers,stop=self.stopped();closed=self.synthetic_closed(obj);target=self.synthetic_target(obj,closed,0x3000)
            hard=obj._policy.effective_hard_ns;done=self.script(peers['rsp'],[(b'z1,2000,1',b'OK'),(b'Z1,3000,1',b'OK')])
            ticket=obj.prepare_transition(closed,target);done();endpoint=obj._rsp_socket
            class Partial:
                calls=0
                def fileno(self):return endpoint.fileno()
                def send(self,data):
                    self.calls+=1
                    if self.calls==1:return endpoint.send(data[:1])
                    raise BrokenPipeError(32,'private partial c')
            obj._rsp_socket=Partial()
            with self.assertRaises(ProbeError):obj.resume_to_next(ticket)
            self.assertTrue(ticket._consumed);self.assertEqual(obj._policy.effective_hard_ns,hard+90_000_000_000)
            flight=obj.flights[-1];self.assertEqual(flight.c_sent_slice.length,1);self.assertIsNone(flight.c_complete_ns)
            self.assertEqual(flight.result,'error');self.assertEqual(obj._state,'FAILED');self.recv(peers['rsp'],b'$');self.no_send(peers['rsp'])
        self.test_three_flights_one_owner_and_strict_quit()

    def test_control_ack_headroom_refuses_before_z1_bytes(self):
        for available in (0,1):
            with self.subTest(available=available),patch.object(w,'_root_guard',return_value=None):
                obj,peer,peers,stop=self.stopped();closed=self.synthetic_closed(obj)
                obj._rsp_acks=w.MAX_RSP_ACKS-available
                before=len(obj.operations);raw_before=obj.raw('rsp-out');error=None
                # Stop the old implementation immediately AFTER its actual first
                # socket send, rather than wait five seconds for an unowned reply.
                with patch.object(w.CallWire,'_next_rsp',side_effect=AssertionError('reply wait after forbidden request')):
                    try:obj._clear_breakpoint()
                    except BaseException as caught:error=caught
                self.assertEqual(obj.raw('rsp-out'),raw_before,'z1 bytes escaped ACK preflight')
                self.no_send(peers['rsp']);self.assertEqual(len(obj.operations),before)
                self.assertIsInstance(error,ProbeError);self.assertEqual(error.reason,'rsp_ack_limit')
        # Exactly two credits permit the genuine request ACK + response ACK.
        with patch.object(w,'_root_guard',return_value=None):
            obj,peer,peers,stop=self.stopped();self.synthetic_closed(obj)
            obj._rsp_acks=w.MAX_RSP_ACKS-2
            done=self.script(peers['rsp'],[(b'z1,2000,1',b'OK')]);obj._clear_breakpoint();done()
            self.assertEqual(obj._rsp_acks,w.MAX_RSP_ACKS)
            self.assertEqual(obj.operations[-1].result,'ok');self.assertIsNone(obj._breakpoint)

    def test_continue_ack_headroom_refuses_before_consumption_or_c(self):
        with patch.object(w,'_root_guard',side_effect=self.transition_guard):
            obj,peer,peers,stop=self.stopped();closed=self.synthetic_closed(obj)
            target=self.synthetic_target(obj,closed,0x3000)
            done=self.script(peers['rsp'],[(b'z1,2000,1',b'OK'),(b'Z1,3000,1',b'OK')])
            ticket=obj.prepare_transition(closed,target);done()
            obj._rsp_acks=w.MAX_RSP_ACKS;raw_before=obj.raw('rsp-out');before=len(obj.operations);error=None
            with patch.object(w.CallWire,'_next_rsp',side_effect=AssertionError('reply wait after forbidden c')):
                try:obj.resume_to_next(ticket)
                except BaseException as caught:error=caught
            self.assertEqual(obj.raw('rsp-out'),raw_before,'c bytes escaped ACK preflight')
            self.no_send(peers['rsp']);self.assertFalse(ticket._consumed)
            self.assertEqual(len(obj.operations),before);self.assertIsInstance(error,ProbeError)
            self.assertEqual(error.reason,'rsp_ack_limit')
            self.assertIsNone(obj.flights[-1].resume_operation_seq)
        self.test_three_flights_one_owner_and_strict_quit()

    def test_stop_ack_headroom_refuses_before_allocation_or_plus(self):
        from test_run0_rsp import packet
        with patch.object(w,'_root_guard',return_value=None):
            obj,peer,peers=self.ready();old_ack=w.CallWire._ack_stop;before=[]
            def exhaust(current,observed):
                before.append(len(current.operations));current._rsp_acks=w.MAX_RSP_ACKS
                return old_ack(current,observed)
            def remote():
                self.recv(peers['rsp'],packet(b'Z1,2000,1'))
                peers['rsp'].sendall(b'+'+packet(b'OK'));self.recv(peers['rsp'],b'+')
                self.recv(peers['rsp'],packet(b'c'))
                peer.sendall(frame({'event':'RESUME','timestamp':{'seconds':1,'microseconds':0}})+
                    frame({'event':'STOP','timestamp':{'seconds':1,'microseconds':1}}))
                peers['rsp'].sendall(b'+'+packet(b'T05thread:01;'))
            done=self.task(remote)
            with patch.object(w.CallWire,'_ack_stop',exhaust):
                with self.assertRaises(ProbeError) as caught:obj.stop_at_entry(self.prior())
            done();self.no_send(peers['rsp']);self.assertEqual(caught.exception.reason,'rsp_ack_limit')
            self.assertEqual(len(obj.operations),before[0]);self.assertIsNone(obj.flights[-1].stop_ack_operation_seq)
        self.test_initial_flight_cross_channel_orders_and_rtc_context()

    def test_stale_flight_event_keeps_context_without_false_cause(self):
        for name in ('RESUME','STOP'):
            with self.subTest(name=name),patch.object(w,'_root_guard',return_value=None):
                obj,peer,peers,stop=self.stopped();before=obj.raw('rsp-out')
                raw=frame({'event':name,'timestamp':{'seconds':3,'microseconds':0}});peer.sendall(raw)
                with self.assertRaises(ProbeError) as caught:obj.confirm_stopped_physical_mode(stop)
                self.assertEqual(caught.exception.reason,'call_flight_event')
                self.assertEqual(obj.raw('rsp-out'),before);self.no_send(peers['rsp'])
                event=obj.events[-1];self.assertEqual(event.name,name);self.assertEqual(event.state,'STOPPED')
                self.assertEqual(event.confirmed_epoch,'C0');self.assertIsNone(event.target_epoch)
                self.assertIsNone(event.cause_epoch);self.assertIsNone(event.flight_id)
                self.assertTrue(obj.raw('qmp-in').endswith(raw))
        self.test_initial_flight_cross_channel_orders_and_rtc_context()

if __name__=='__main__':unittest.main()
