"""Synthetic private session controls; no public fixture or live wire issuer."""
from contextlib import ExitStack
from dataclasses import fields, replace
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import time
import unittest
from unittest.mock import patch
import boot_profile_capture as base
import run0_call_capture as root
import run0_call_budget as budget
import run0_call_decode as pure
import run0_call_read as read
import run0_call_owner as owner
import run0_rsp as rsp
from test_run0_call_decode import Fixture as CopiedFixture, CALLER, HELPER, canonical
from test_run0_call_read import private
from test_run0_call_budget import memory_ledger
try:
    import run0_call_session as session
except ModuleNotFoundError as error:
    if error.name != 'run0_call_session':raise
    session=None

class SessionTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(session,'parent epoch behavior absent: gate-first RED')
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        self.h=ScriptedEpoch(self.stack)
    def denied(self,fn):
        with self.assertRaises((base.ProbeError,pure.C0DecodeError)):fn()
    def fresh(self):
        self.assertEqual(ScriptedEpoch(self.stack).drive().binding.epoch,'C1')
    def test_origin(self):
        for cls in (session.CurrentEpochRamBinding,session.ParentAcquisitionSession,
                    session.EpochReadGrant,session.PhaseReadsComplete,session.ClosedEpochSnapshot,
                    session.FreshC0FactsReceipt,session.SelectedCallReceipt):
            with self.assertRaises(TypeError):cls()
        self.denied(lambda:session._initialize_owned_epoch(None,None,None));self.fresh()
    def test_inert_publication(self):
        self.h.runtime._current=None;self.denied(self.h.session.next_request);self.fresh()
    def test_one_admission(self):
        g=self.h.session.next_request();p=self.h.prepare(g)
        self.assertFalse(self.h.retainer._attempts)
        a=self.h.admit(g,p)
        self.denied(lambda:self.h.session._validate_dispatch(g,p,now_ns=time.monotonic_ns()))
        self.assertIs(self.h.retainer._attempts[p.key.operation_seq],a);self.fresh()
        # Actual zero-byte admitted next-half failure retains its exact target
        # and first decoded sidefile, with no fake completed4096 frame.
        h=ScriptedEpoch(self.stack);h.step();first=h.retainer._receipts[0]
        g=h.session.next_request();p=h.prepare(g);a=h.admit(g,p)
        object.__setattr__(a,'result','timeout');object.__setattr__(a,'finished_ns',time.monotonic_ns())
        h.retainer._failures[p.key.physical_ordinal]=private(read._ReadRetentionFailure,
            owner=h.retainer,attempt=a,status='INCOMPLETE',reason='synthetic_zero_send_failure')
        h.session.abort(base.ProbeError('INCOMPLETE','synthetic_zero_send_failure'))
        partial=h.retainer.partial_assembly((first,),4096,failure_operation_seq=p.key.operation_seq)
        self.assertEqual(partial.next_logical_offset,2048)
        self.assertTrue((h.path/first.decoded_data_ref.path).is_file())
        self.assertFalse(list(h.path.glob('epochs/**/frames/*.bin')))
        self.fresh()
    def test_grant_identity(self):
        g=self.h.session.next_request();foreign=private(type(g),**{f.name:getattr(g,f.name) for f in fields(g)})
        self.denied(lambda:self.h.session._validate_prepare(foreign,now_ns=time.monotonic_ns()))
        h=ScriptedEpoch(self.stack);g=h.session.next_request();p=h.prepare(g);a=h.admit(g,p)
        for _ in range(2):h.session._recheck_admitted(g,p,a,now_ns=time.monotonic_ns())
        self.assertIs(h.retainer._attempts[p.key.operation_seq],a)
        late=ScriptedEpoch(self.stack,age=10);g=late.session.next_request();p=late.prepare(g);a=late.admit(g,p)
        object.__setattr__(a,'started_ns',time.monotonic_ns()-6_000_000_000)
        self.denied(lambda:late.session._recheck_admitted(g,p,a,now_ns=time.monotonic_ns()))
        self.assertIs(late.retainer._attempts[p.key.operation_seq],a)
        self.fresh()
    def test_retained_receipt(self):
        self.h.session.next_request();self.denied(lambda:self.h.session.accept({'result':'ok'}))
        h=ScriptedEpoch(self.stack);h.step();self.assertEqual(len(h.retainer._receipts),1)
        self.assertFalse(list(h.path.glob('epochs/**/frames/*.bin')))
        h.step();self.assertEqual(len(list(h.path.glob('epochs/**/frames/*first.bin'))),1)
    def test_epoch_cache(self):
        self.h.drive();h=ScriptedEpoch(self.stack);h.drive()
        self.assertIsNot(self.h.binding,h.binding);self.assertTrue(h.retainer._receipts)
        self.assertEqual(h.session._frames[0x1000]['first'].blob.length,4096)
    def test_C0_semantics(self):
        h=ScriptedEpoch(self.stack,epoch='C0');done=h.drive()
        # The existing synthetic PE has two sections (968 first bytes);
        # the authenticated production PE has five (frozen1088), not fabricated here.
        self.assertEqual((len(done.objects),sum(o.length for o in done.objects)),(8,968))
        closed,copied=h.close_and_copy(done)
        facts=h.session._project_closed_facts(h.session._snapshot,closed,copied)
        self.assertEqual(facts.get_memory_map,h.expected_gmm)
        for which in ('header','crc'):
            bad=ScriptedEpoch(self.stack,epoch='C0')
            address=bad.session._prepared.prior.loaded_base if which=='header' else bad.values[3]+16
            bad.memory[address]^=1;self.denied(bad.drive)
            self.assertIsNone(bad.session._snapshot)
            self.assertFalse(bad.runtime._fact_receipts)
        self.assertEqual(len(ScriptedEpoch(self.stack,epoch='C0').drive().objects),8)
    def test_C1_source(self):
        done=self.h.drive();closed,copied=self.h.close_and_copy(done)
        facts=self.h.session._project_closed_facts(self.h.session._snapshot,closed,copied)
        self.assertEqual(facts.saved_return,self.h.data.base+0x6350)
        self.assertNotEqual(facts.boot_services,self.h.c0.facts.boot_services)
        h=ScriptedEpoch(self.stack);h.memory[h.data.s]^=1
        self.denied(h.drive);self.fresh()
        args=ScriptedEpoch(self.stack);args.memory[args.data.s+0x28]^=1
        self.denied(args.drive);self.assertIsNone(args.session._complete)
        self.fresh()
    def test_C2_barrier(self):
        h=ScriptedEpoch(self.stack,epoch='C2');h.to_barrier()
        self.assertTrue(h.session.map_extent_pending)
        self.assertEqual(len(h.session.scalar_evidence().scalar_objects),4)
        self.assertFalse(any(r.target_ordinal==6 and r.target_kind=='object' for r in h.retainer._receipts.values()))
        h.install();self.assertEqual(h.drive().binding.epoch,'C2')
        changed=ScriptedEpoch(self.stack,epoch='C2',volatile=True)
        changed.to_barrier();changed.install();self.assertEqual(changed.drive().map_extent.map_pointer,
                                                              changed.selected.map_pointer)
        rejected=ScriptedEpoch(self.stack,epoch='C2',status=1)
        self.denied(rejected.drive)
        self.assertFalse(rejected.retainer._receipts)
        self.assertIsNone(rejected.session._map_extent)
        self.fresh()
    def test_extent_seal(self):
        h=ScriptedEpoch(self.stack,epoch='C2');h.to_barrier()
        e=pure.validate_c2_scalars(h.selected,h.session.scalar_evidence())
        self.denied(lambda:h.session.install_map_extent(e))
        h=ScriptedEpoch(self.stack,epoch='C2');h.to_barrier();h.install();h.drive()
        self.assertIsNotNone(h.session._map_plan)
        bad=ScriptedEpoch(self.stack,epoch='C2');bad.to_barrier()
        actual=pure.validate_c2_scalars(bad.selected,bad.session.scalar_evidence())
        raw=canonical(replace(actual,map_key=1));ref=bad.add('map-extent.json',raw)
        bad.session._attach_extent_record(ref,raw)
        self.denied(lambda:bad.session.install_map_extent(actual))
        self.assertIsNone(bad.session._map_plan)
        self.assertFalse(any(r.target_kind=='object' and r.target_ordinal==6 for r in bad.retainer._receipts.values()))
    def test_whole_M_escrow(self):
        h=ScriptedEpoch(self.stack,epoch='C2',small=True,m=32768,stride=128)
        h.to_barrier()
        # Independently observe the two real budget API deltas on an otherwise
        # equivalent ledger, without replacing either API or guessing addresses.
        probe=memory_ledger('C2')
        for row in h.ledger._batches.values():
            batch=probe.reserve_reads('C2',row['reservation'].charges)
            probe.reserve_wire_batch(batch)
        prior=probe.view();cap=probe.reserve_c2_discovery_capacity(map_virtual=h.selected.map_pointer,map_length=32768)
        probe.reserve_wire_discovery(cap);later=probe.view()
        expected_delta=(later['committed_operations']-prior['committed_operations'],
                        later['committed_bytes']-prior['committed_bytes'])
        h.install();done=h.drive()
        self.assertEqual(h.session._discovery_commitment,expected_delta)
        self.assertEqual((h.session._map_plan.reserved_read_operations,h.session._map_plan.reserved_bytes),
                         h.session._discovery_commitment)
        self.assertGreater(h.session._map_plan.reserved_read_operations,len(h.session._objects[6]['batch'].charges))
        self.assertEqual(len(done.objects[6].parts),17)
        self.assertEqual(h.ledger.view()['discovery_state'],'sealed')
        self.assertEqual(h.ledger._reserved_reads,0)
        self.assertGreater(h.ledger.view()['potential_reads'],0)
        # Last leaf is absent in the already captured PT: no map data grant
        # may escape while proving the full extent, even though early leaves fit.
        bad=ScriptedEpoch(self.stack,epoch='C2',small=True,m=32768,stride=128)
        last=(bad.data.base+0x7f998+32768-1-bad.data.base)//4096
        for i in range(8):bad.memory[0x4000+last*8+i]=0
        bad.to_barrier();self.denied(bad.install)
        self.assertFalse(any(r.target_kind=='object' and r.target_ordinal==6 for r in bad.retainer._receipts.values()))
        self.assertIsNone(bad.session._map_plan)
        fresh=ScriptedEpoch(self.stack,epoch='C2');fresh.to_barrier();fresh.install();fresh.drive()
    def test_frozen_rechecks(self):
        self.h.mutate_recheck=True;self.denied(self.h.drive);self.fresh()
    def test_after_closure(self):
        done=self.h.drive()
        self.assertIs(self.h.session.require_reads_complete(done,actual_wire_identity=self.h.wire,
            actual_transport_identity=('rsp',1,2),actual_epoch_nonce=self.h.binding.epoch_nonce,
            now_ns=time.monotonic_ns()),self.h.binding)
        snapshot=self.h.session.finish(self.h.after(done))
        self.assertEqual(len(snapshot.objects),8);self.denied(self.h.session.next_request)
        h=ScriptedEpoch(self.stack);complete=h.drive();after=h.after(complete)
        clone=private(type(after),**{f.name:getattr(after,f.name) for f in fields(after)})
        self.denied(lambda:h.session.finish(clone));self.fresh()
    def test_acyclic_facts(self):
        done=self.h.drive();closed,copied=self.h.close_and_copy(done)
        facts=self.h.session._project_closed_facts(self.h.session._snapshot,closed,copied)
        self.assertEqual(facts.C0_epoch_ref,self.h.c0.facts.epoch_ref)
        ref=self.h.add('selected-call.json',canonical(facts))
        receipt=session._register_selected_call(self.h.session,self.h.session._snapshot,closed,copied,
            facts,ref,self.h.blobs[ref.path])
        self.assertIs(receipt.facts,facts)
    def test_archive(self):
        done=self.h.drive();self.h.close_and_copy(done)
        self.denied(self.h.session.next_request)
        self.assertTrue(self.h.retainer.export_row(done.receipts[0]).canonical_bytes)
        self.assertEqual(len(self.h.retainer.inventory()),len(set(x.blob.path for x in self.h.retainer.inventory())))
    def test_budget_deadlines(self):
        self.h.ledger.reserve_output(budget.REGULAR_BYTES-self.h.ledger._regular)
        self.denied(self.h.session.next_request);self.fresh()
    def test_C0_input_acyclic_overload(self):
        h=ScriptedEpoch(self.stack,epoch='C0');done=h.drive();closed,copied=h.close_and_copy(done)
        self.assertIs(type(copied),session.ClosedC0CopiedInput)
        self.assertNotIn('c0_facts',{f.name for f in fields(copied)})
        facts=h.session._project_closed_facts(h.session._snapshot,closed,copied)
        receipt=session._register_closed_c0_facts(h.session,h.session._snapshot,closed,copied,facts)
        self.assertIs(receipt.facts,facts)
        # A1's C1 context is never a candidate/placeholder input to C0.
        bad=ScriptedEpoch(self.stack,epoch='C0');done=bad.drive();closed,copied=bad.close_and_copy(done)
        self.denied(lambda:bad.session._project_closed_facts(bad.session._snapshot,closed,
                                                            CopiedFixture('C1').context))
        fresh=ScriptedEpoch(self.stack,epoch='C0');complete=fresh.drive()
        closed,copied=fresh.close_and_copy(complete)
        self.assertIs(type(fresh.session._project_closed_facts(fresh.session._snapshot,closed,copied)),pure.C0CopiedFacts)


class ScriptedEpoch:
    """Private byte/packet fixture. No sockets, helpers, real wire or issuer."""
    def __init__(self,stack,epoch='C1',small=False,m=384,stride=48,age=0,volatile=False,status=0):
        import run0_call_wire as wire
        self.w=wire;self.epoch=epoch;self.mutate_recheck=False
        temp=stack.enter_context(tempfile.TemporaryDirectory(prefix='epoch-session-'))
        self.path=Path(temp).resolve();self.path.chmod(0o700)
        self.ledger=memory_ledger(epoch);self.memory={};self.blobs={};self.refs={}
        self.runtime=object.__new__(root._OwnedCallRuntime)
        self.wire=object();self.parent=object();self.buffers={'rsp':bytearray(),'rsp-out':bytearray()}
        rt=self.runtime;rt.parent_identity=self.parent;rt.accounting=self.ledger;rt._wire=self.wire
        rt.read_attempts={};rt.read_operations={};rt.inventory={};rt._fact_receipts={};rt._closed_epochs={}
        rt._failure=None;rt._closed=False
        one=CopiedFixture('C1')
        self.c0_data=one.data[one.c0.epoch_ref.path]
        self.selected=pure.validate_c1_entry(one.context,one.objects,one.pinned)
        self.data=CopiedFixture('C2',one,small=small,m=m,stride=stride,volatile=volatile,status=status) if epoch=='C2' else one
        self.values=dict(self.data.values)
        state=self.data.state;hmp=self.data.hmp;layout=self.data.layout
        prior=None;pinned=b''
        if epoch=='C0':
            from test_run0_c0_decode import full_fixture
            import run0_c0_entry as token
            import run0_c0_decode as c0
            report,_,blobs,_,_=full_fixture(self.path,base.VAPIC_OFF_INVOCATION_PROFILE)
            host=json.loads(blobs['host-report.json'])
            replay=c0.validate_c0_rsp(json.loads(blobs[host['control_ref']['path']]),blobs)
            prior=token.validate_prior_entry(report['profile_ref'],report['prior_admission_ref'],
                                             report['profile_mapping_ref'],blobs)
            pinned=blobs['efi'];self.values=dict(replay['before_registers'])
            cp=report['checkpoint'];hmp=blobs[cp['hmp_before_ref']['path']]
            layout=blobs[cp['layout_before_ref']['path']]
            for row in cp['tables']:
                self.memory.update((row['physical']+i,b) for i,b in enumerate(blobs[row['first_ref']['path']]))
            for row in cp['objects']:
                self.memory.update((row['virtual']+i,b) for i,b in enumerate(blobs[row['first_ref']['path']]))
            self.expected_gmm=cp['get_memory_map']
        else:
            for physical,raw in self.data.tables.items():
                self.memory.update((physical+i,b) for i,b in enumerate(raw))
            for obj in self.data.objects:
                self.memory.update((obj.virtual+i,b) for i,b in enumerate(self.data.data[obj.first_ref.path]))
        prepared=private(root.PreparedCallInputs,**{name:None for name in root.PreparedCallInputs.__dataclass_fields__})
        object.__setattr__(prepared,'prior',prior);object.__setattr__(prepared,'pinned_efi',pinned)
        object.__setattr__(prepared,'pinned_caller',self.data.pinned)
        rt.prepared=prepared
        rt._registration=private(root.ClosedOwnedCallRegistration,_owner=rt,prepared=prepared,
            qemu_owner=object(),wire=self.wire,deadlines=object(),accounting=self.ledger,inventory=rt.inventory,
            parent_identity=self.parent,transition_owner=object(),read_attempts=rt.read_attempts,
            read_operations=rt.read_operations)
        reg=rt._registration
        self.c0=private(session.FreshC0FactsReceipt,_owner=rt,registration=reg,session=object(),
            snapshot=object(),closed=object(),facts=one.c0,epoch_bytes=self.c0_data)
        selected_ref=self.add('selected-call.json',canonical(self.selected)) if epoch=='C2' else None
        source=self.c0 if epoch=='C1' else private(session.SelectedCallReceipt,_owner=rt,registration=reg,
            session=object(),snapshot=object(),closed=object(),c0_receipt=self.c0,facts=self.selected,
            facts_ref=selected_ref,facts_bytes=self.blobs[selected_ref.path]) if epoch=='C2' else None
        if epoch!='C0':self.add(one.c0.epoch_ref.path,self.c0_data)
        self.add(self.data.pinned.manifest_ref.path,self.data.data[self.data.pinned.manifest_ref.path])
        prefix=f'epochs/{epoch}/';now=time.monotonic_ns()-age*1_000_000_000;last=self.ledger.view()['allocated_operations']
        from run0_c0_acquire import REGISTER_WIDTHS
        seqstart=last-len(budget.BEFORE[epoch])+4+(2 if epoch=='C0' else 0)
        before=tuple((n,width,self.values[n],seqstart+i) for i,(n,width) in enumerate(REGISTER_WIDTHS))
        self.add(prefix+'stop.bin',b'$T05thread:01;#00')
        self.add(prefix+'before-registers.json',canonical({'schema_version':1,'operations':[r[3] for r in before]}))
        self.add(prefix+'hmp-before.txt',hmp);self.add(prefix+'layout-before.txt',layout)
        self.add(prefix+'host-phase.json',b'{"synthetic":"no helpers or host reads"}\n')
        stop=private(wire.EpochStopReceipt,_registration=reg,_wire=self.wire,epoch=epoch,
            stop_nonce=object(),flight=object(),target=source,stop_event_seq=1,stop_ack_operation_seq=2,
            debug_operation_seq=3,received_ns=now,confirmed_ns=now,stop_deadline_ns=now+60_000_000_000)
        regs=private(wire.SelectedEpochRegisters,_registration=reg,_wire=self.wire,stop=stop,
                     phase='before',values=before)
        mode=private(wire.CurrentEpochMode,_registration=reg,_wire=self.wire,stop=stop,operation_seq=3,value=1)
        import run0_c0_decode as c0
        lr=private(wire.EpochLayoutReceipt,_registration=reg,_wire=self.wire,stop=stop,phase='before',
            operation_seq=last,wire=wire.WirePosition('qmp',0,len(layout)),raw_bytes=layout,ranges=c0._layout(layout))
        self.binding=private(session.CurrentEpochRamBinding,_owner=rt,registration=reg,parent_identity=self.parent,
            wire=self.wire,epoch=epoch,epoch_nonce=stop.stop_nonce,stop=stop,mode=mode,before_registers=regs,
            host_receipt=object(),layout_receipt=lr,transport_identity=('rsp',1,2),state=tuple(state.items()),
            registers=before,hmp_raw=hmp,layout_raw=layout,ranges=lr.ranges,
            prefix_blobs=tuple(pure.CopiedBlob(self.refs[k],v) for k,v in self.blobs.items()),
            source_fact=source,stop_ns=now,work_deadline_ns=now+85_000_000_000,
            stop_deadline_ns=now+60_000_000_000)
        self.retainer=private(read._ReadRetainer,_parent=self.parent,_wire=self.wire,_session=None,
            _binding=self.binding,_transport=('rsp',1,2),_accounting=self.ledger,_root=self.path,_raw=self.buffers,
            _operations=rt.read_operations,_pending=None,_receipts={},_rows={},_inventory={},_slots={},
            _retained_pending={},_attempts=rt.read_attempts,_prepared={},_failures={},
            _deadline_ns=self.binding.stop_deadline_ns,_revoked=False,_origin='synthetic_fixture',
            _plan_ref=read.BlobRef('plan.json',hashlib.sha256(b'plan').hexdigest(),4))
        def live(runtime,wire,current,ss):
            base.deny(runtime._current is current and current.session is ss and current.binding is ss.binding
                and current.retainer is ss.retainer and wire is runtime._wire,'synthetic_current_identity')
        def archival(runtime,ss):
            base.deny(ss._owner is runtime and ss._registration is runtime._registration,'synthetic_archive')
        def extent(runtime,ss,ref,data):
            base.deny(runtime.inventory.get('map-extent.json')==(ref,data),'synthetic_extent_seal')
        def after_guard(runtime,ss,after):
            base.deny(runtime.inventory.get('$after') is after and after.reads_complete is ss._complete,
                      'synthetic_after_receipt')
        def project(runtime,ss,snap,closed,copied):
            base.deny(runtime._closed_epochs.get(ss.binding.epoch) is closed and snap is ss._snapshot,
                      'synthetic_closed_projection')
        def pubc0(runtime,receipt):runtime._fact_receipts['C0']=receipt
        def pubselected(runtime,receipt):
            base.deny(runtime.inventory.get('selected-call.json')==(receipt.facts_ref,receipt.facts_bytes),
                      'synthetic_selected_seal')
            runtime._fact_receipts['C1']=receipt
        hooks={'_require_epoch_initialization':lambda *_:None,'_require_wire_binding':live,
            '_require_session_archival':archival,'_require_extent_record':extent,
            '_require_epoch_after':after_guard,'_require_closed_projection':project,
            '_publish_c0_facts':pubc0,'_publish_selected_call':pubselected}
        for name,fn in hooks.items():stack.enter_context(patch.object(root._OwnedCallRuntime,name,fn,create=True))
        self.session=session._initialize_owned_epoch(self.binding,rt,self.retainer)
        self.retainer._session=self.session
        rt._current=private(root.RegisteredCurrentEpochBinding,_owner=rt,registration=reg,binding=self.binding,
            session=self.session,retainer=self.retainer,host_receipt=self.binding.host_receipt,
            layout_receipt=self.binding.layout_receipt)

    def add(self,name,data):
        ref=read.BlobRef(name,hashlib.sha256(data).hexdigest(),len(data))
        if name in self.blobs:
            if self.blobs[name]!=data:raise AssertionError('fixture replacement forbidden')
            return self.refs[name]
        self.ledger.reserve_output(2*len(data)+256)
        path=self.path/name;parent=self.path
        for part in Path(name).parent.parts:
            parent=parent/part;parent.mkdir(mode=0o700,exist_ok=True);parent.chmod(0o700)
        if path.exists():
            if path.read_bytes()!=data:raise AssertionError('fixture file collision')
        else:
            with path.open('xb') as file:file.write(data)
        self.blobs[name]=data;self.refs[name]=ref;self.runtime.inventory[name]=(ref,data)
        return ref

    def prepare(self,grant):
        batch,index,target=self.session._validate_prepare(grant,now_ns=time.monotonic_ns())
        request=self.ledger.view()['physical_claimed']+1
        key=read.ReadKey(self.epoch,request,request-1,self.ledger.view()['allocated_operations']+1)
        return self.retainer.prepare(batch,index,key,target)

    def admit(self,grant,pending):
        self.session._validate_dispatch(grant,pending,now_ns=time.monotonic_ns())
        attempt=private(read._HeldReadAttempt,_parent=self.parent,_wire=self.wire,key=pending.key,
            target=pending.target,started_ns=time.monotonic_ns(),finished_ns=None,result='pending')
        self.retainer._attempts[pending.key.operation_seq]=attempt
        self.session._recheck_admitted(grant,pending,attempt,now_ns=time.monotonic_ns())
        return attempt

    def step(self):
        grant=self.session.next_request()
        if type(grant) is session.PhaseReadsComplete:return grant
        pending=self.prepare(grant);attempt=self.admit(grant,pending);target=pending.target
        data=bytes(self.memory[target.gpa+i] for i in range(target.length))
        if self.mutate_recheck and target.pass_index==1:data=bytes([data[0]^1])+data[1:]
        self.ledger.debit_wire_read(pending.reservation,pending.key,6*target.length+256)
        request=rsp.encode_packet(f'm{target.gpa:x},{target.length:x}'.encode())
        response=rsp.encode_packet(data.hex().encode())
        def append(stream,raw):
            self.ledger.reserve_output(len(raw));position=read.LiveWirePosition(stream,len(self.buffers[stream]),len(raw))
            self.buffers[stream].extend(raw);return position
        req=append('rsp-out',request);ack=append('rsp',b'+');res=append('rsp',response)
        received=time.monotonic_ns();outack=append('rsp-out',b'+');finished=time.monotonic_ns()
        object.__setattr__(attempt,'finished_ns',finished);object.__setattr__(attempt,'result','ok')
        operation=private(read._HeldReadOperation,_parent=self.parent,_wire=self.wire,attempt=attempt,
            key=pending.key,target=target,request_position=req,request_ack_position=ack,response_position=res,
            response_ack_position=outack,started_ns=attempt.started_ns,response_received_ns=received,
            ack_finished_ns=finished,result='ok')
        self.retainer._operations[pending.key.operation_seq]=operation
        receipt=self.retainer.seal(pending,operation=operation,request_position=req,request_ack_position=ack,
            response_position=res,response_ack_position=outack,request_bytes=request,response_bytes=response,
            started_ns=attempt.started_ns,response_received_ns=received,ack_finished_ns=finished)
        self.session.accept(receipt)
        return grant

    def to_barrier(self):
        for _ in range(506):
            if self.session.map_extent_pending:return
            self.step()
        raise AssertionError('fixture scalar barrier not reached')

    def install(self):
        evidence=self.session.scalar_evidence();extent=pure.validate_c2_scalars(self.selected,evidence)
        raw=canonical(extent);ref=self.add('map-extent.json',raw)
        self.session._attach_extent_record(ref,raw);self.session.install_map_extent(extent)

    def drive(self):
        for _ in range(507):
            if self.session.map_extent_pending:self.install()
            result=self.step()
            if type(result) is session.PhaseReadsComplete:return result
        raise AssertionError('bounded fixture did not complete')

    def after(self,done):
        start=self.ledger.view()['allocated_operations']+1
        from run0_c0_acquire import REGISTER_WIDTHS
        values=tuple((n,width,self.values[n],start+i) for i,(n,width) in enumerate(REGISTER_WIDTHS))
        for name in budget.AFTER[self.epoch][:31]:self.ledger.reserve_operation(self.epoch,name)
        regs=private(self.w.SelectedEpochRegisters,_registration=self.runtime._registration,_wire=self.wire,
            stop=self.binding.stop,phase='after',values=values)
        hmp=private(self.w.EpochRegisterView,_registration=self.runtime._registration,_wire=self.wire,
            stop=self.binding.stop,registers=regs,operation_seq=start+29,
            wire=self.w.WirePosition('qmp',0,len(self.binding.hmp_raw)),raw_bytes=self.binding.hmp_raw,
            parsed_state=())
        layout=private(self.w.EpochLayoutReceipt,_registration=self.runtime._registration,_wire=self.wire,
            stop=self.binding.stop,phase='after',operation_seq=start+30,
            wire=self.w.WirePosition('qmp',0,len(self.binding.layout_raw)),raw_bytes=self.binding.layout_raw,
            ranges=self.binding.ranges)
        after=private(self.w.EpochAfterReceipt,_registration=self.runtime._registration,_wire=self.wire,
            stop=self.binding.stop,reads_complete=done,registers=regs,hmp=hmp,layout=layout)
        self.runtime.inventory['$after']=after;return after

    def close_and_copy(self,done):
        after=self.after(done);snapshot=self.session.finish(after);ep=self.epoch;prefix=f'epochs/{ep}/'
        closed=private(owner.ClosedEpochReceipt,_owner=object(),_wire=self.wire,_epoch=ep,_memory_revoked=True)
        self.runtime._closed_epochs[ep]=closed;self.retainer._revoked=True
        for path,(ref,data) in self.session._blobs.items():
            self.blobs[path]=data;self.refs[path]=ref
        ar=self.add(prefix+'after-registers.json',canonical({'schema_version':1,'operations':[r[3] for r in after.registers.values]}))
        hr=self.add(prefix+'hmp-after.txt',after.hmp.raw_bytes);lr=self.add(prefix+'layout-after.txt',after.layout.raw_bytes)
        plan=self.add(prefix+'read-plan.json',b'{"synthetic":"copied plan"}\n')
        completion=self.add(prefix+'completion.json',b'{"synthetic":"copied completion"}\n')
        closure=self.add(prefix+'closure.json',b'{"synthetic":"copied closure"}\n')
        get=lambda name:self.refs[prefix+name]
        epoch=dict(phase=ep,epoch=ep,firmware_phase='firmware_active',stop_ref=get('stop.bin'),
            before_registers_ref=get('before-registers.json'),host_phase_ref=get('host-phase.json'),
            layout_before_ref=get('layout-before.txt'),read_plan_ref=plan,table_snapshots=snapshot.frames,
            objects=snapshot.objects,translations=tuple(p for o in snapshot.objects for p in o.parts),
            completion_ref=completion,after_registers_ref=ar,hmp_after_ref=hr,layout_after_ref=lr,closure_ref=closure)
        er=self.add(prefix+'epoch.json',canonical(epoch))
        common=(ep,er,get('stop.bin'),get('before-registers.json'),self.binding.registers,
            after.registers.values,self.binding.state,get('hmp-before.txt'),hr,get('layout-before.txt'),lr,
            get('host-phase.json'))
        blobs=tuple(pure.CopiedBlob(self.refs[k],raw) for k,raw in self.blobs.items())
        if ep=='C0':copied=session.ClosedC0CopiedInput(*common,snapshot.frames,blobs)
        else:copied=pure.CopiedEpochBinding(*common,self.c0.facts,snapshot.frames,blobs,
            self.session._extent_record[0] if ep=='C2' else None)
        return closed,copied

if __name__=='__main__':unittest.main()
