"""Private runtime receiving controls; no VM/helper/guest execution."""
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
import os
import socket
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from boot_profile_capture import ProbeError
import run0_call_capture as capture
import run0_call_runtime as runtime
import run0_call_host as host
from run0_call_owner import ParentDeadlines,ParentOwnedWait
from run0_call_budget import ParentAccounting


def native(cls,**fields):
    value=object.__new__(cls)
    for key,item in fields.items():object.__setattr__(value,key,item)
    return value

class RuntimeControls(unittest.TestCase):
    def test_public_guard_precedes_any_mutation_or_spawn(self):
        with tempfile.TemporaryDirectory(prefix='call-runtime-guard-') as parent:
            path=Path(parent)/'absent'
            prepared=native(capture.PreparedCallInputs,plan_bytes=b'{}')
            with patch.object(capture,'require_call_runtime_registration',side_effect=ProbeError('INCOMPLETE','held')) as guard,\
                 patch.object(Path,'mkdir',side_effect=AssertionError('directory effect')),\
                 patch.object(subprocess,'Popen',side_effect=AssertionError('process effect')):
                with self.assertRaises(ProbeError) as caught:runtime._run_call_capture(prepared,path)
                self.assertEqual(caught.exception.reason,'held');guard.assert_called_once()
            self.assertFalse(path.exists())
    def test_inert_owner_has_no_registration_current_or_process(self):
        policy=ParentDeadlines(time.monotonic_ns());ledger=ParentAccounting(policy.started_ns)
        prepared=native(capture.PreparedCallInputs);inventory=native(capture.RootRawInventory)
        with patch.object(subprocess,'Popen',side_effect=AssertionError('constructor process')):
            owner=runtime._new_inert_runtime(prepared,policy,ledger,inventory,object())
        self.assertIs(type(owner),capture._OwnedCallRuntime)
        self.assertIsNone(owner._registration);self.assertIsNone(owner._current)
        self.assertIsNone(owner.qemu_owner.child);self.assertIs(owner.deadlines,policy)
        self.assertIs(owner.accounting,ledger);self.assertEqual(owner.read_attempts,{})
    def test_complete_lifecycle_requires_all_ten_distinct_children_and24_eofs(self):
        owner=self.completed_owner()
        runtime._validate_complete_lifecycle(owner)
        owner._children['c2_fields'].returncode=1
        with self.assertRaises(ProbeError):runtime._validate_complete_lifecycle(owner)
        runtime._validate_complete_lifecycle(self.completed_owner())
    def test_lifecycle_same_pid_or_missing_eof_cannot_be_counted_twice(self):
        for issue in ('pid','eof','wait','close'):
            with self.subTest(issue=issue):
                owner=self.completed_owner();helper=owner._children['c1_fields']
                if issue=='pid':helper.child.pid=owner.qemu_owner.child.pid
                elif issue=='eof':helper.eofs={'stdout'}
                else:helper.lifecycle=[row for row in helper.lifecycle if row['operation']!=issue]
                with self.assertRaises(ProbeError):runtime._validate_complete_lifecycle(owner)
                runtime._validate_complete_lifecycle(self.completed_owner())
    def wire_fixture(self,h):
        # The session fixture intentionally has no real socket authority. Replace
        # its inert identity consistently, not the session's validation methods.
        h.wire=SimpleNamespace()
        h.runtime._wire=h.wire;h.retainer._wire=h.wire
        object.__setattr__(h.runtime._registration,'wire',h.wire)
        object.__setattr__(h.binding,'wire',h.wire)
        for value in (h.binding.stop,h.binding.mode,h.binding.before_registers,h.binding.layout_receipt):
            object.__setattr__(value,'_wire',h.wire)

    def test_physical_prepare_is_not_admission_and_commit_is_shared_once(self):
        from test_run0_call_session import ScriptedEpoch
        import run0_call_wire as w
        with ExitStack() as stack:
            h=ScriptedEpoch(stack)
            self.wire_fixture(h)
            stack.enter_context(patch.object(runtime,'_require_wire_binding',lambda *a:None))
            g=h.session.next_request();n=h.ledger.view()['allocated_operations']+1
            h.wire._operations=[w.Operation(i,'C1','rsp','synthetic_prior',time.monotonic_ns()) for i in range(1,n)]
            row=w.Operation(n,'C1','rsp','physical_read',time.monotonic_ns());h.wire._operations.append(row)
            h.wire._epoch='C1';h.wire._active_pending=None
            p=runtime._prepare_wire_read(h.runtime,h.wire,g,operation_seq=n)
            self.assertFalse(h.runtime.read_attempts)
            self.assertEqual(h.ledger.view()['physical_claimed'],1)
            h.wire._active_pending=p
            a=runtime._commit_wire_read(h.runtime,h.wire,g,p)
            self.assertIs(h.runtime.read_attempts[n],a)
            self.assertIs(h.retainer._attempts[n],a)
            runtime._recheck_wire_read(h.runtime,h.wire,a)
            with self.assertRaises(ProbeError):runtime._commit_wire_read(h.runtime,h.wire,g,p)
            object.__setattr__(a,'started_ns',time.monotonic_ns()-6_000_000_000)
            with self.assertRaises(ProbeError):runtime._recheck_wire_read(h.runtime,h.wire,a)
        # Fresh separate genuine planner/ledger remains usable after a denial.
        with ExitStack() as stack:
            self.assertEqual(ScriptedEpoch(stack).drive().binding.epoch,'C1')

    def test_physical_wrong_allocated_row_refuses_before_claim(self):
        from test_run0_call_session import ScriptedEpoch
        import run0_call_wire as w
        with ExitStack() as stack:
            h=ScriptedEpoch(stack)
            self.wire_fixture(h)
            stack.enter_context(patch.object(runtime,'_require_wire_binding',lambda *a:None))
            g=h.session.next_request();n=h.ledger.view()['allocated_operations']+1
            h.wire._operations=[w.Operation(i,'C1','rsp','synthetic_prior',time.monotonic_ns()) for i in range(1,n)]
            h.wire._operations.append(w.Operation(n,'C1','rsp','p0',time.monotonic_ns()))
            h.wire._epoch='C1';h.wire._active_pending=None
            with self.assertRaises(ProbeError):runtime._prepare_wire_read(h.runtime,h.wire,g,operation_seq=n)
            self.assertFalse(h.runtime.read_attempts);self.assertEqual(h.ledger.view()['physical_claimed'],0)

    def test_whole_rsp_stream_rejects_extra_ack_and_partial_tail(self):
        import run0_rsp as rsp
        from run0_call_wire import Operation,WirePosition as P,Event
        query=rsp.encode_packet(b'qC');reply=rsp.encode_packet(b'QC01')
        cont=rsp.encode_packet(b'c');stop=rsp.encode_packet(b'T05thread:01;')
        incoming=b'+'+reply+b'+'+stop;outgoing=query+b'+'+cont+b'+'
        start=1+len(reply)
        rows=[Operation(1,'C0','rsp','thread_current',1,2,P('rsp-out',0,len(query)),P('rsp',1,len(reply)),'ok'),
            Operation(2,'C0','rsp','continue',3,4,P('rsp-out',len(query)+1,len(cont)),P('rsp',start,1),'ok'),
            Operation(3,'C0','rsp','stop_ack',6,7,P('rsp-out',len(outgoing)-1,1),None,'ok')]
        events=[Event(1,'rsp','T05thread:01;',P('rsp',start+1,len(stop)),5,4,'FLIGHT',None,'C0','C0','C0')]
        def fixture(raw):
            codec=rsp.AckDecoder();frames=codec.feed(raw);positions=[];offset=0
            for n,frame in enumerate(frames):
                positions.append((frame.kind,P('rsp',offset,len(frame.raw)),n+1,n+1));offset+=len(frame.raw)
            return SimpleNamespace(_operations=rows,_events=events,_rsp_frame_rows=positions,
                _rsp_segment_rows=[(P('rsp-out',0,len(outgoing)),1)])
        runtime._validate_rsp_history(fixture(incoming),incoming,outgoing)
        for changed in (incoming+b'+',incoming+b'$unfinished',incoming.replace(b'QC01',b'QC02')):
            with self.assertRaises((ProbeError,rsp.RSPError)):
                runtime._validate_rsp_history(fixture(changed),changed,outgoing)
            runtime._validate_rsp_history(fixture(incoming),incoming,outgoing)
        with self.assertRaises(ProbeError):runtime._validate_rsp_history(fixture(incoming),incoming,outgoing+b'+')

    def test_whole_qmp_stream_checks_unfiltered_ids_and_delimiters(self):
        from run0_call_wire import Operation,WirePosition as P
        greeting=b'{"QMP":{}}\r\n';reply=b'{"return":{},"id":1}\r\n'
        incoming=greeting+reply;request=b'{"execute":"quit","id":1}'
        def fixture(data):
            return SimpleNamespace(_operations=[Operation(1,'C2','qmp','quit',1,2,
                P('qmp-out',0,len(request)),P('qmp-in',len(greeting),len(reply)-2),'ok')],
                _events=[],_qmp_frame_rows=[(P('qmp-in',0,len(greeting)),1,1),
                    (P('qmp-in',len(greeting),len(reply)),2,2)])
        runtime._validate_qmp_history(fixture(incoming),incoming,request)
        for changed in (incoming+b'{"return":{},"id":2}\r\n',incoming.replace(b'"id":1',b'"id":2'),incoming[:-1]):
            with self.assertRaises(ProbeError):runtime._validate_qmp_history(fixture(changed),changed,request)
            runtime._validate_qmp_history(fixture(incoming),incoming,request)

    def test_parent_json_inventory_bound_is_precomputed_exactly(self):
        value={'schema_version':1,'rows':[{'path':'x/'+str(i),'length':i,'flag':False} for i in range(1024)]}
        self.assertEqual(runtime._json_size(value),len(runtime.witness.canonical(value)))
        with self.assertRaises(ProbeError):runtime._json_size({'bad':1.0})

    def test_lifecycle_reversed_close_wait_refuses(self):
        owner=self.completed_owner();rows=owner._children['c0_fields'].lifecycle
        rows[2]['started_ns']=rows[0]['started_ns'];rows[2]['finished_ns']=rows[0]['finished_ns']
        with self.assertRaises(ProbeError):runtime._validate_complete_lifecycle(owner)
        runtime._validate_complete_lifecycle(self.completed_owner())

    def test_closed_epoch_artifact_order_uses_real_pure_projection(self):
        from test_run0_call_session import ScriptedEpoch
        import run0_call_session as ss
        import run0_call_read as rd
        import run0_call_owner as own
        for epoch in ('C0','C1','C2'):
            with self.subTest(epoch=epoch),ExitStack() as stack:
                h=ScriptedEpoch(stack,epoch=epoch);done=h.drive();after=h.after(done)
                rt=h.runtime;current=rt._current
                rt._epochs={epoch:runtime._EpochArchive(current)}
                rt.transition_owner=native(own.NativeTransitionOwner)
                if epoch!='C0':rt._fact_receipts['C0']=h.c0
                if epoch=='C2':rt._fact_receipts['C1']=h.binding.source_fact
                old_inventory=rt.inventory
                inv=capture.RootRawInventory(h.path,h.ledger);rt.inventory=inv
                object.__setattr__(rt._registration,'inventory',inv)
                object.__setattr__(rt.prepared,'prior_blobs',tuple(h.blobs.items()))
                r=h.data.pinned.manifest_ref
                object.__setattr__(rt.prepared,'caller_manifest_ref',(r.path,r.sha256,r.length))
                # Private setup records actual fixture files already created by
                # the session; it is not a runtime adoption/registration issuer.
                def adopt(_owner,retainer):
                    for row in retainer.inventory():
                        data=(h.path/row.blob.path).read_bytes()
                        inv._record(row.blob,data,row.family,row.epoch,row.state)
                for name,pair in old_inventory.items():
                    if name.startswith('$'):continue
                    ref,data=pair
                    if name.startswith('epochs/') or name in ('selected-call.json','map-extent.json'):
                        family,ep=capture._output_role(name);inv._record(ref,data,family,ep,'complete')
                stack.enter_context(patch.object(runtime,'_graph',lambda owner,wire=None:owner._registration))
                stack.enter_context(patch.object(runtime,'_require_wire_binding',lambda *a:None))
                stack.enter_context(patch.object(runtime,'_adopt_retainer',adopt))
                stack.enter_context(patch.object(capture._OwnedCallRuntime,'_require_epoch_after',
                    lambda owner,session,actual: self.assertIs(actual,after),create=True))
                for name in ('_require_closed_projection','_publish_c0_facts','_publish_selected_call'):
                    stack.enter_context(patch.object(capture._OwnedCallRuntime,name,getattr(runtime,name),create=True))
                closed=runtime._close_epoch(rt,current,done,after)
                self.assertIs(rt._closed_epochs[epoch],closed);self.assertIsNone(rt._current)
                self.assertTrue(h.retainer._revoked)
                self.assertEqual(rt._epochs[epoch].copied.epoch_ref.path,f'epochs/{epoch}/epoch.json')
                self.assertTrue((h.path/f'epochs/{epoch}/closure.json').is_file())
                if epoch=='C2':
                    self.assertFalse(rt._fact_receipts['C2'][0].atomic_snapshot)
                    self.assertTrue((h.path/'map-facts.json').is_file())
                else:self.assertIs(rt._fact_receipts[epoch].closed,closed)

    def graph_fixture(self,stack):
        path=Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='call-graph-'))).resolve()
        path.chmod(0o700);now=time.monotonic_ns();policy=ParentDeadlines(now);ledger=ParentAccounting(now)
        inv=capture.RootRawInventory(path,ledger)
        prepared=native(capture.PreparedCallInputs,plan_bytes=b'{}',run=str(path))
        rt=runtime._new_inert_runtime(prepared,policy,ledger,inv,object())
        rt._plan=runtime._freeze_plan({},ledger)
        streams={}
        for name in ('qmp-in','rsp','serial','debug'):
            local,peer=socket.socketpair();stack.callback(local.close);stack.callback(peer.close)
            local.setblocking(False);streams[name]=local
        for name in ('qemu_stdout','qemu_stderr'):
            r,w=os.pipe();stream=os.fdopen(r,'rb',buffering=0)
            stack.callback(stream.close);stack.callback(os.close,w);streams[name]=stream
        rt.qemu_owner.child=native(subprocess.Popen,pid=os.getpid()+100000,returncode=None,
            stdout=streams['qemu_stdout'],stderr=streams['qemu_stderr'],_child_created=False)
        stack.enter_context(patch.object(capture,'require_call_runtime_registration',lambda *a:None))
        return rt,streams

    def test_graph_publication_aliases_and_archival_after_close(self):
        with ExitStack() as stack:
            rt,streams=self.graph_fixture(stack)
            wire=runtime._publish_owned_graph(rt,streams);stack.callback(wire.close)
            self.assertTrue(runtime._issued_call_registration(rt._registration,wire))
            self.assertIs(wire._read_attempts,rt.read_attempts)
            self.assertIs(wire._read_operations,rt.read_operations)
            runtime._require_wire_bootstrap(rt,wire)
            rt.qemu_owner.reaped=True;rt.qemu_owner.returncode=0;rt.qemu_owner.child.returncode=0
            for source in streams.values():source.close()
            self.assertTrue(runtime._issued_call_registration(rt._registration,wire))
            with self.assertRaises(ProbeError):runtime._require_wire_bootstrap(rt,wire)
            object.__setattr__(rt._registration,'read_attempts',{})
            self.assertFalse(runtime._issued_call_registration(rt._registration,wire))

    def test_graph_rejects_unowned_stdout_endpoint(self):
        with ExitStack() as stack:
            rt,streams=self.graph_fixture(stack)
            r,w=os.pipe();foreign=os.fdopen(r,'rb',buffering=0)
            stack.callback(foreign.close);stack.callback(os.close,w)
            streams['qemu_stdout']=foreign
            with self.assertRaises(ProbeError):runtime._publish_owned_graph(rt,streams)
            self.assertIsNone(rt._registration)
        with ExitStack() as stack:
            rt,streams=self.graph_fixture(stack)
            wire=runtime._publish_owned_graph(rt,streams);stack.callback(wire.close)
            self.assertTrue(runtime._issued_call_registration(rt._registration,wire))

    def test_register_values_are_bound_to_actual_packets_and_exact_widths(self):
        from run0_c0_acquire import REGISTER_WIDTHS
        from run0_call_wire import Operation,WirePosition as P,SelectedEpochRegisters,EpochStopReceipt
        import run0_rsp as rsp
        from dataclasses import replace
        incoming=bytearray();outgoing=bytearray();operations=[];rows=[]
        stop=native(EpochStopReceipt,epoch='C1')
        for seq,(number,width) in enumerate(REGISTER_WIDTHS,1):
            value=number+7;request=rsp.encode_packet(f'p{number:x}'.encode())
            response=rsp.encode_packet(value.to_bytes(width,'little').hex().encode())
            request_pos=P('rsp-out',len(outgoing),len(request));outgoing.extend(request)
            response_pos=P('rsp',len(incoming),len(response));incoming.extend(response)
            operations.append(Operation(seq,'C1','rsp',f'p{number:x}',seq,seq+1,request_pos,response_pos,'ok'))
            rows.append((number,width,value,seq))
        wire=SimpleNamespace(_operations=operations);raw={'rsp':bytes(incoming),'rsp-out':bytes(outgoing)}
        good=native(SelectedEpochRegisters,stop=stop,values=tuple(rows))
        runtime._validate_register_bytes(wire,good,raw)
        for field,value in ((1,float(rows[0][1])),(2,999),(0,False)):
            changed=list(rows);row=list(changed[0]);row[field]=value;changed[0]=tuple(row)
            bad=native(SelectedEpochRegisters,stop=stop,values=tuple(changed))
            with self.assertRaises(ProbeError):runtime._validate_register_bytes(wire,bad,raw)
            runtime._validate_register_bytes(wire,good,raw)

    def test_fixed_path_closure_rejects_unindexed_regular_and_symlink(self):
        for mutation in ('extra','symlink'):
            with ExitStack() as stack:
                rt,streams=self.graph_fixture(stack)
                rt.inventory.put('plan.json',b'{}\n')
                runtime._validate_path_closure(rt)
                path=rt.inventory.run/'unindexed'
                if mutation=='extra':path.write_bytes(b'actual unindexed bytes');path.chmod(0o600)
                else:path.symlink_to('/dev/null')
                with self.assertRaises(ProbeError):runtime._validate_path_closure(rt)
            with ExitStack() as stack:
                fresh,_=self.graph_fixture(stack);fresh.inventory.put('plan.json',b'{}\n')
                runtime._validate_path_closure(fresh)

    def cleanup_socket_fixture(self,stack):
        path=Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='call-cleanup-'))).resolve()
        path.chmod(0o700);now=time.monotonic_ns();policy=ParentDeadlines(now);ledger=ParentAccounting(now)
        inv=capture.RootRawInventory(path,ledger);prepared=native(capture.PreparedCallInputs,plan_bytes=b'{}',run=str(path))
        rt=runtime._new_inert_runtime(prepared,policy,ledger,inv,object());rt._plan=runtime._freeze_plan({},ledger)
        streams={};peers={}
        for name in ('qmp-in','rsp','serial','debug','qemu_stdout','qemu_stderr'):
            local,peer=socket.socketpair();stack.callback(local.close);stack.callback(peer.close)
            local.setblocking(False);peer.setblocking(False);streams[name]=local;peers[name]=peer
        rt.qemu_owner.child=native(subprocess.Popen,pid=os.getpid()+100000,returncode=None,
            stdout=streams['qemu_stdout'],stderr=streams['qemu_stderr'],_child_created=False)
        stack.enter_context(patch.object(capture,'require_call_runtime_registration',lambda *a:None))
        wire=runtime._publish_owned_graph(rt,streams);stack.callback(wire.close);wire._activate_io()
        rt._failure=runtime.wiremod.Failure('DENY','original_failure');wire._latch_failure(rt._failure)
        return rt,wire,streams,peers

    def test_failed_cleanup_polls_live_writer_then_drains_reaped_eof(self):
        import signal
        with ExitStack() as stack:
            rt,wire,streams,peers=self.cleanup_socket_fixture(stack);failures=[dict(status='DENY',reason='original_failure')]
            events=[]
            for name,p in peers.items():p.sendall(b'tail' if name!='qmp-in' else b'partial')
            def wait(owner,deadline=None,*,pump=None):
                if pump:pump()
                events.append(('wait',len(wire.eofs),wire._drain))
                if not any(x[0]=='term' for x in events):return None
                owner.reaped=True;owner.returncode=0;owner.child.returncode=0;return 0
            def send(owner,sig,name):
                self.assertEqual(sig,signal.SIGTERM);events.append(('term',len(wire.eofs),wire._drain))
                for peer in peers.values():peer.shutdown(socket.SHUT_WR)
                owner._receipt('signal_term',time.monotonic_ns(),'ok')
            stack.enter_context(patch.object(ParentOwnedWait,'wait',wait))
            stack.enter_context(patch.object(ParentOwnedWait,'_signal',send))
            runtime._cleanup(rt,streams,failures)
            self.assertEqual(failures,[dict(status='DENY',reason='original_failure')])
            self.assertIsNone(events[0][2]);self.assertEqual(events[0][1],0)
            self.assertEqual(events[1][0],'term');self.assertIsNone(events[1][2])
            self.assertEqual(len(wire.eofs),6);self.assertIsNotNone(wire._drain)
            self.assertEqual(wire._drain.failure.reason,'original_failure')
            self.assertEqual(bytes(wire._raw['qmp-out']),b'');self.assertEqual(bytes(wire._raw['rsp-out']),b'')
        with ExitStack() as fresh:
            other,wire,streams,peers=self.cleanup_socket_fixture(fresh)
            self.assertIsNone(wire._drain);self.assertEqual(len(wire.eofs),0)

    def test_failed_cleanup_retains_read_error_and_original_failure(self):
        import errno
        with ExitStack() as stack:
            rt,wire,streams,peers=self.cleanup_socket_fixture(stack);failures=[dict(status='DENY',reason='original_failure')]
            peers['serial'].sendall(b'pending');original_read=os.readv
            def readv(fd,buffers):
                if fd==streams['serial'].fileno():raise OSError(errno.EIO,'synthetic read error')
                return original_read(fd,buffers)
            def wait(owner,deadline=None,*,pump=None):
                if pump:pump()
                if not owner.actions:return None
                owner.reaped=True;owner.returncode=0;owner.child.returncode=0;return 0
            def signal_owner(owner,sig,name):
                owner.actions.append(name)
                for peer in peers.values():peer.shutdown(socket.SHUT_WR)
            stack.enter_context(patch.object(os,'readv',readv));stack.enter_context(patch.object(ParentOwnedWait,'wait',wait))
            stack.enter_context(patch.object(ParentOwnedWait,'_signal',signal_owner))
            runtime._cleanup(rt,streams,failures)
            self.assertEqual(failures[0]['reason'],'original_failure')
            self.assertTrue(any(x['reason']=='call_io_error' for x in failures))
            self.assertTrue(any(x.stream=='serial' and x.errno==errno.EIO for x in wire._io_errors))
            self.assertIsNone(wire._drain)
        with ExitStack() as fresh:
            rt,wire,_,_=self.cleanup_socket_fixture(fresh);self.assertIsNone(wire._drain)

    def test_lost_owner_polls_without_signalling_or_claiming_complete(self):
        with ExitStack() as stack:
            rt,wire,streams,peers=self.cleanup_socket_fixture(stack);rt.qemu_owner.ownership_lost=True
            failures=[dict(status='DENY',reason='original_failure')];peers['serial'].sendall(b'tail')
            with patch.object(ParentOwnedWait,'_signal',side_effect=AssertionError('signal lost owner')):
                runtime._cleanup(rt,streams,failures)
            self.assertEqual(failures[0]['reason'],'original_failure')
            self.assertTrue(wire.raw('serial').endswith(b'tail'));self.assertIsNone(wire._drain)
            self.assertEqual(len(wire.eofs),0)
        with ExitStack() as fresh:
            rt,wire,_,_=self.cleanup_socket_fixture(fresh);self.assertIsNone(wire._drain)

    def test_hard_expiry_is_retained_during_failure_cleanup(self):
        with ExitStack() as stack:
            rt,wire,streams,peers=self.cleanup_socket_fixture(stack);rt.qemu_owner.ownership_lost=True
            failures=[dict(status='DENY',reason='original_failure')]
            with patch.object(runtime.time,'monotonic_ns',return_value=rt.deadlines.effective_hard_ns), \
                 patch.object(ParentOwnedWait,'_signal',side_effect=AssertionError('signal lost owner')):
                runtime._cleanup(rt,streams,failures)
            self.assertEqual(failures[0]['reason'],'original_failure')
            self.assertTrue(any(x['reason']=='call_runtime_cleanup_deadline' for x in failures))
            self.assertIsNone(wire._drain)
        with ExitStack() as fresh:
            rt,wire,_,_=self.cleanup_socket_fixture(fresh);self.assertIsNone(wire._drain)

    def test_cleanup_retains_original_cause_and_owned_attempts_after_interrupt(self):
        import signal
        with ExitStack() as stack:
            rt,streams=self.graph_fixture(stack)
            rt._failure=runtime.wiremod.Failure('DENY','original_read_failure')
            failures=[{'status':'DENY','reason':'original_read_failure'}]
            calls=[]
            def wait(_owner,deadline=None,**kwargs):
                calls.append('wait')
                if calls.count('wait')==1:raise InterruptedError('synthetic wait interruption')
                if calls.count('wait')==2:return None
                _owner.reaped=True;_owner.returncode=0;_owner.child.returncode=0;return 0
            def send(_owner,sig,name):
                calls.append(sig)
                _owner._receipt('signal_term' if sig==signal.SIGTERM else 'signal_kill',time.monotonic_ns(),'ok')
            stack.enter_context(patch.object(ParentOwnedWait,'wait',wait))
            stack.enter_context(patch.object(ParentOwnedWait,'_signal',send))
            runtime._cleanup_wait(rt,lambda:None,failures)
            self.assertEqual(calls.count(signal.SIGTERM),1);self.assertEqual(calls.count(signal.SIGKILL),1)
            self.assertTrue(rt.qemu_owner.reaped)
            self.assertEqual(failures[0]['reason'],'original_read_failure')
            self.assertEqual(rt._failure.reason,'original_read_failure')

    def transition_fixture(self,stack,epoch='C0',*,ticket=True,committed=True,consumed=True,c_bytes=0,owner=None):
        import run0_call_owner as own
        import run0_call_wire as w
        if owner is None:
            rt,streams=self.graph_fixture(stack);wire=runtime._publish_owned_graph(rt,streams);stack.callback(wire.close)
        else:rt=owner;wire=rt._wire
        target_epoch='C1' if epoch=='C0' else 'C2';at=rt.deadlines.started_ns
        closure,_=runtime._json(rt,f'epochs/{epoch}/closure.json',{'epoch':epoch,'synthetic':True})
        closed=native(own.ClosedEpochReceipt,_owner=rt.transition_owner,_wire=wire,_epoch=epoch,_memory_revoked=True)
        binding=SimpleNamespace(stop_ns=at+1)
        archive=runtime._EpochArchive(native(capture.RegisteredCurrentEpochBinding,
            _owner=rt,registration=rt._registration,binding=binding),closed=closed,refs={'closure_ref':closure})
        rt._epochs[epoch]=archive;rt._closed_epochs[epoch]=closed
        target=native(capture.BoundCallTarget,_owner=rt,registration=rt._registration,closed=closed,
            source_fact=object(),source_epoch=epoch,target_epoch=target_epoch,address=0x3000,source_closure_ref=closure)
        rt._fact_receipts[('target',epoch)]=target
        wire._transition_target=target;wire._transition_started_ns=at+2
        seq=len(wire._operations)+1
        clear=w.Operation(seq,epoch,'rsp','hardware_breakpoint_clear',at+3,at+4,result='ok')
        setrow=w.Operation(seq+1,epoch,'rsp','hardware_breakpoint_set',at+5,at+6,result='ok')
        wire._operations.extend([clear,setrow]);wire._transition_clear=clear;wire._transition_set=setrow
        journal,_=runtime._json(rt,f'transitions/{epoch}-{target_epoch}.json',dict(schema_version=1,
            source_epoch=epoch,target_epoch=target_epoch,source_closure_ref=closure.as_json(),target=0x3000,
            clear_operation_seq=seq,set_operation_seq=seq+1,quiet_received_ns=at+7,admission_started_ns=at+2))
        if ticket:
            row=native(own.TransitionAdmission,_owner=rt.transition_owner,_wire=wire,_epoch=epoch,
                _policy=rt.deadlines,_source_epoch=epoch,_target_epoch=target_epoch,_admitted_ns=at+8,
                _response_deadline_ns=at+2+5_000_000_000,_next_stop_deadline_ns=at+2+60_000_000_000,
                _journal_ref=(journal.path,journal.sha256,journal.length),_committed=committed,_consumed=consumed)
            rt.transition_owner._tickets.append(row)
        if consumed:wire._flights.append(w.FlightRecord(target_epoch,epoch,closure,seq,seq+1,
            (journal.path,journal.sha256,journal.length),resume_operation_seq=seq+2,
            c_sent_slice=w.WirePosition('rsp-out',0,c_bytes) if c_bytes else None))
        return rt,journal

    def test_transition_projection_keeps_uncommitted_candidate_and_null_unobserved(self):
        with ExitStack() as stack:
            rt,journal=self.transition_fixture(stack,ticket=False,consumed=False)
            before=runtime._held_blob(rt,journal.path)[1];row=runtime._transition_projection(rt)[0]
            self.assertEqual(row['journal_ref'],journal.as_json())
            for key in ('admitted_ns','response_deadline_ns','next_stop_deadline_ns','committed','consumed'):
                self.assertIsNone(row[key])
            self.assertEqual(runtime._held_blob(rt,journal.path)[1],before)
        with ExitStack() as stack:
            rt,journal=self.transition_fixture(stack,committed=False,consumed=False)
            row=runtime._transition_projection(rt)[0]
            self.assertFalse(row['committed']);self.assertFalse(row['consumed'])
            self.assertIs(type(row['admitted_ns']),int)

    def test_transition_projection_zero_partial_c_never_invents_completion(self):
        keys={'source_epoch','target_epoch','journal_ref','source_closure_ref','clear_operation_seq',
            'set_operation_seq','source_stop_received_ns','admission_started_ns','admitted_ns',
            'response_deadline_ns','next_stop_deadline_ns','committed','consumed'}
        for count in (0,1,5):
            with self.subTest(sent=count),ExitStack() as stack:
                rt,journal=self.transition_fixture(stack,c_bytes=count)
                row=runtime._transition_projection(rt)[0]
                self.assertEqual(set(row),keys);self.assertTrue(row['committed']);self.assertTrue(row['consumed'])
                self.assertNotIn('c_complete_ns',row);self.assertIsNone(rt._wire._flights[0].c_complete_ns)
                runtime._validate_transition_projection(rt,[row],complete=False)
                bad=dict(row);bad['admitted_ns']=float(bad['admitted_ns'])
                with self.assertRaises(ProbeError):runtime._validate_transition_projection(rt,[bad],complete=False)
                with self.assertRaises(ProbeError):runtime._validate_transition_projection(rt,[row],complete=True)
        with ExitStack() as stack:
            rt,streams=self.graph_fixture(stack);runtime._publish_owned_graph(rt,streams)
            stack.callback(rt._wire.close);self.assertEqual(runtime._transition_projection(rt),[])

    def test_complete_transition_projection_requires_exact_two_native_flights(self):
        from dataclasses import replace
        with ExitStack() as stack:
            rt,_=self.transition_fixture(stack)
            self.transition_fixture(stack,'C1',owner=rt)
            for index,ticket in enumerate(rt.transition_owner._tickets):
                rt._wire._flights[index]=replace(rt._wire._flights[index],result='ok',
                    response_deadline_ns=ticket.response_deadline_ns,stop_deadline_ns=ticket.next_stop_deadline_ns)
            rows=runtime._transition_projection(rt)
            runtime._validate_transition_projection(rt,rows,complete=True)
            original=rt._wire._flights[1]
            rt._wire._flights[1]=replace(original,admission_ref=rt._wire._flights[0].admission_ref)
            with self.assertRaises(ProbeError):runtime._validate_transition_projection(rt,rows,complete=True)
            rt._wire._flights[1]=original
            runtime._validate_transition_projection(rt,rows,complete=True)

    def test_live_guard_uses_immutable_held_plan_without_reparsing(self):
        from types import MappingProxyType
        with ExitStack() as stack:
            rt,streams=self.graph_fixture(stack)
            rt._plan=runtime._freeze_plan({'argv':['fixed','-S'],'nested':{'value':1}},rt.accounting)
            wire=runtime._publish_owned_graph(rt,streams);stack.callback(wire.close)
            self.assertIs(type(rt._plan),MappingProxyType);self.assertIs(type(rt._plan['argv']),tuple)
            with self.assertRaises(TypeError):rt._plan['nested']['value']=2
            with patch.object(capture.PreparedCallInputs,'plan',property(lambda _: (_ for _ in ()).throw(AssertionError('reparse')))),                 patch.object(capture,'require_call_runtime_registration') as guard:
                runtime._live(rt,wire)
                self.assertIs(guard.call_args.args[1],rt._plan)

    def test_epoch_prefix_is_exact_final_stream_prefix_and_history(self):
        import run0_call_wire as w
        with ExitStack() as stack:
            rt,streams=self.graph_fixture(stack);wire=runtime._publish_owned_graph(rt,streams);stack.callback(wire.close)
            raw={'qmp-in':b'abc','qmp-out':b'de','rsp':b'+','rsp-out':b'$x#78'}
            refs={}
            for name,data in raw.items():
                refs[name]=runtime._put(rt,'epochs/C0/prefix/'+runtime.RAW_FILES[name],data)
            runtime._json(rt,'epochs/C0/prefix/index.json',dict(schema_version=1,epoch='C0',
                raw_refs=[r.as_json() for r in refs.values()],operations=[],events=[]))
            runtime._validate_epoch_prefix(rt,'C0',{k:v+b'future' for k,v in raw.items()})
            bad=dict(raw);bad['rsp']=b'-'
            with self.assertRaises(ProbeError):runtime._validate_epoch_prefix(rt,'C0',bad)
            runtime._validate_epoch_prefix(rt,'C0',raw)

    def completed_owner(self):
        # Deliberately synthetic actual-type lifecycle records, never a native
        # launch/admission. This pure checker must reject their malformed joins.
        now=time.monotonic_ns();policy=ParentDeadlines(now)
        owner=object.__new__(capture._OwnedCallRuntime);children={}
        roles=('qemu',)+tuple(f'{e}_{r}' for e in ('c0','c1','c2') for r in host.LOCAL_ROLES)
        for i,role in enumerate(roles):
            child=native(subprocess.Popen,pid=100+i,returncode=0,_child_created=False)
            if role=='qemu':helper=ParentOwnedWait('qemu',policy)
            else:helper=object.__new__(host._ParentHostHelper)
            helper.child=child;helper.returncode=0;helper.reaped=True;helper.ownership_lost=False
            helper.role=role;helper.closed=True;helper.io_errors=[];helper.eofs={'stdout','stderr'}
            helper.lifecycle=[dict(role=role,pid=100+i,operation=op,started_ns=now+j,finished_ns=now+j+1,
                result='ok',returncode=0 if op=='wait' else None,errno=None) for j,op in enumerate(('spawn','wait','close'))]
            children[role]=helper
        owner.qemu_owner=children['qemu'];owner._children=children;owner.deadlines=policy
        from run0_call_wire import EndOfStream
        owner._wire=SimpleNamespace(_eofs=[EndOfStream(n,now+2) for n in ('qmp-in','rsp','serial','debug','qemu_stdout','qemu_stderr')],_io_errors=[])
        return owner

if __name__=='__main__':unittest.main()
