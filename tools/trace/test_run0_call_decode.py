"""Portable synthetic copied-data controls; never stop/RAM/runtime authority."""
import base64
from dataclasses import fields, is_dataclass, replace
import hashlib
import json
import struct
import unittest

import run0_call_decode as d
from run0_c0_acquire import REGISTER_WIDTHS
from test_run0_c0_decode import frame, mode, efi, synthetic_c0_hmp

CALLER = base64.b85decode('NP+D50000?iA*F&Oo>D!P)Lc;NQ+b?NJxo9Brr*d$ViJ!Bv4F=L?k#&i9{qoNQs0br~m)}NQsOjumAu6NQsmrxBvhENQqP=Sm+)J002yjOe9E5i$o+)Oo@af=l}o!Oo@yn@Bjb+Oo@af-~a#sOo@afzyJUMNXJAZU;qFB07%C~BxnEt0075CBy<1(006iM0000;gZKb+I!KE|Bv43$;0H*FL?n1fjYK4PNQs0b$N&HUNR0)BNdy2$iG(E30000;i$o-NNIL~_Ndy3NQR@syjSWso1OVvyF$4g{ge2bp0000;jSX5!1OU1^0002!aOVI3Nr}NpiPAC2NR3n^cub82G)V*iNR0(`Ndy2)iBu#YNQp!wDCn^*1OP~jR3uPHi$o+aNR3P+SWJyXBw$R9OeAPbjZ`FbOo>z^ApcM}Op8P$P)LhRBsfTk!bpomBuGq)Oe9!LiHszW0000?i%cYFOo@ynm;e9(Op8n;U`&aOB%lBQ08EL5B!B<_07!|1B!~b208EX9B!B<_0O;y0002mfL?l2+fyDR#006@')
HELPER = base64.b85decode('xL6qg0O-nn1OP}W#7K!$Bq&IU$ViJ!Bq&IUL?kdsi9{qgNQsOjI2ix{=-*EO07!{MBtS@sgd|8A002mh1w-Kn07!%Q01uSFB>y!3r~!2X>vKqpR3t!1jRhv*2LMQkgd|WI002mhj3mGS002yl1rOl|071C`fB*pKY)JqBNR5mnm;e9(NR5;vzyJUM=ocLT07#8YBydQLlq8q{008La6#xK8i&P|VF~GS20000;gZcnS4@AL8sQ~~00Cf)Q7)Xr`@Q4He=#Y8@07#2WBrxcK7XSe3Zb*%cB<KJD07#8gByd5vC;$Ke=+`g-07#8YBuGe&lqBc?002R_C;$Ke=)W)l07#8YBuMDxPXGW&iNWaYJpcemi9{qINr})%i&P{aNR5mn5CH%H=mRtW07#2WBrr&glq3)V008K58vp=Ei$o+iNP)yy82|vo')


def js(value):
    if type(value) is bytes:
        return value.hex()
    if type(value) in (d.BlobRef, d.RawSlice):
        return value.as_json()
    if is_dataclass(value):
        return {f.name: js(getattr(value, f.name)) for f in fields(value) if f.name != 'context'}
    if type(value) is dict:
        return {k:js(v) for k,v in value.items()}
    if type(value) is tuple:
        return [js(v) for v in value]
    return value


def canonical(value):
    return (json.dumps(js(value), sort_keys=True, separators=(',', ':'))+'\n').encode('ascii')


def map_bytes(m=384, stride=48, *, split=False):
    rows = []
    for i in range(m//stride):
        if split and i < 2:
            physical, pages = ((0, 0x280000//4096) if i == 0 else (0x280000, 0x180000//4096))
        elif i == 0:
            physical, pages = 0, 1024
        else:
            physical, pages = 0x400000+(i-(2 if split else 1))*4096, 1
        kind = (1 if i == 0 else 6) if split and i < 2 else (7 if i == 0 else 15)
        rows.append(struct.pack('<I4sQQQQ', kind, b'PADD', physical, 0x123,
                                pages, 0x8000000000000001) + b'E'*(stride-40))
    return b''.join(rows)


class Fixture:
    """Private facts and exact copied files; no native receipt constructors."""
    def __init__(self, epoch, c1=None, m=384, stride=48, small=False, raw=None, return_delta=0, changed=False, status=0, volatile=False):
        self.epoch = epoch
        self.data = {} if c1 is None else dict(c1.data)
        self.seq = 100 if epoch == 'C1' else 300
        self.physical_ordinal = 0 if c1 is None else c1.physical_ordinal
        self.base, self.s, self.system, self.boot, self.gmm = 0x200000, 0x380008, 0x300000, 0x301000, 0x280000
        self.state = mode()
        self.tables = {0x1000: frame({0:0x2007}), 0x2000: frame({0:0x3007}),
                       0x3000: frame({1:0x4007 if small else 0x200087})}
        self.levels = (4,3,2,1) if small else (4,3,2)
        if small:
            self.tables[0x4000] = frame({i:(0x200000+i*4096)|7 for i in range(512)})
        c0ref = self.add('epochs/C0/epoch.json', b'{"synthetic":"C0 copied fact"}\n')
        self.c0 = d.C0CopiedFacts(c0ref,self.base,self.base+0x2090,1,self.system,0x302000,self.gmm)
        self.pinned = d.PinnedCaller(self.add('caller-manifest.json', b'{"synthetic":"static input identity"}\n'),
            d.EFI_HASH,d.PDB_HASH,d.GUID,1,CALLER,HELPER)
        self.values = {n:0 for n,_ in REGISTER_WIDTHS}
        self.values.update({0:self.boot if epoch=='C1' else status, 2:self.s+0x60, 3:self.base+0x7f998,
                           7:self.s if epoch=='C1' else self.s+8, 8:self.s+0x68,9:self.s+0x70,
                           16:self.gmm if epoch=='C1' else self.base+0x6350,17:2,27:self.state['cr0'],
                           29:self.state['cr3'],30:self.state['cr4'],32:self.state['efer']})
        if volatile:
            self.values.update({n:0x100 for n in (2,3,8,9)})
        start = 1 if epoch == 'C1' else 201
        self.before = tuple((n,w,self.values[n],start+i) for i,(n,w) in enumerate(REGISTER_WIDTHS))
        self.after = tuple((n,w,self.values[n],500+i if epoch=='C1' else 700+i)
                           for i,(n,w) in enumerate(REGISTER_WIDTHS))
        self.hmp = synthetic_c0_hmp(self.values).encode()
        self.layout = (b'FlatView #0\n AS "memory", root: system\n AS "cpu-memory-0", root: system\n'
                       b' Root memory region: system\n  0000000000000000-00000000003fffff (prio 0, ram): pc.ram\n')
        self.frames = []
        for i, ((physical, value), level) in enumerate(zip(self.tables.items(),self.levels)):
            first = self.add(f'epochs/{epoch}/frames/{i:02d}-first.bin',value)
            contributions = self.contributions(value, (2048,2048))
            self.frames.append(d.FrameEvidence(i,physical,level,first,None,
                tuple(c.operation_seq for c in contributions),(),contributions,()))
        if epoch == 'C1':
            definitions=[(self.system,efi('system',self.boot)),(self.boot,efi('boot',self.gmm)),
                (self.gmm,b'G'*32),(self.base+0x6200,CALLER),(self.base+0x1810,HELPER),
                (self.s,struct.pack('<Q',self.base+0x6350+return_delta)),(self.s+0x28,struct.pack('<Q',self.s+0x7c)),
                (self.s+0x60,struct.pack('<Q',32768))]
            roles=d.C1_ROLES
        else:
            raw = map_bytes(m,stride) if raw is None else raw
            definitions=[(self.base+0x6200,CALLER),(self.base+0x1810,HELPER),
                (self.s+0x60,struct.pack('<Q',m)),(self.s+0x68,struct.pack('<Q',0)),
                (self.s+0x70,struct.pack('<Q',stride)),(self.s+0x7c,struct.pack('<I',1)),
                (self.base+0x7f998,raw)]
            roles=d.C2_ROLES
        walker=d.c0._Walker(self.state,self.tables,((0,0x400000),))
        self.objects=[]
        for ordinal, ((virtual, value), role) in enumerate(zip(definitions,roles)):
            translated=walker.translate(virtual,len(value));lengths=tuple(x['translation']['length'] for x in translated)
            contrib=self.contributions(value,lengths)
            parts=[]; offset=0
            for j,(t,c) in enumerate(zip(translated,contrib)):
                t=t['translation'];parts.append(d.ObjectPart(j,ordinal,offset,t['virtual'],t['physical'],t['length'],
                    t['page_bytes'],tuple(d.PageEntry(**v) for v in t['path']),t['writable'],t['executable'],t['user'],c.operation_seq,None))
                offset+=t['length']
            first=self.add(f'epochs/{epoch}/objects/{ordinal:02d}-first.bin',value)
            self.objects.append(d.ObjectEvidence(epoch,ordinal,role,virtual,len(value),first,tuple(parts),
                tuple(c.operation_seq for c in contrib),contrib,first,(),()))
        for i,f in enumerate(self.frames):
            value=self.data[f.first_ref.path]; recheck=self.add(f'epochs/{epoch}/frames/{i:02d}-recheck.bin',value)
            cs=self.contributions(value,(2048,2048));self.frames[i]=replace(f,recheck_ref=recheck,
                recheck_read_sequences=tuple(c.operation_seq for c in cs),recheck_contributions=cs)
        for i,o in enumerate(self.objects):
            value=self.data[o.first_ref.path]
            if changed and i == 0:
                value=bytes([value[0]^1])+value[1:]
            r=self.add(f'epochs/{epoch}/objects/{i:02d}-recheck.bin',value)
            cs=self.contributions(value,tuple(p.length for p in o.parts));self.objects[i]=replace(o,recheck_ref=r,
                recheck_read_sequences=tuple(c.operation_seq for c in cs),recheck_contributions=cs,
                parts=tuple(replace(p,recheck_read_seq=c.operation_seq) for p,c in zip(o.parts,cs)))
        self.frames=tuple(self.frames);self.objects=tuple(self.objects)
        self.context=self.context_for()

    def add(self,name,value):
        assert name not in self.data or self.data[name]==value
        self.data[name]=value
        return d.BlobRef(name,hashlib.sha256(value).hexdigest(),len(value))

    def contributions(self,value,lengths):
        result=[];offset=0
        for length in lengths:
            ordinal=self.physical_ordinal;self.physical_ordinal+=1
            r=self.add(f'memory/read-{ordinal:03d}.bin',value[offset:offset+length])
            result.append(d.AssemblyContribution(ordinal,self.seq,offset,length,r));self.seq+=1;offset+=length
        assert offset==len(value)
        return tuple(result)

    def context_for(self):
        prefix=f'epochs/{self.epoch}/'
        rr=self.add(prefix+'before-registers.json',canonical({'schema_version':1,'operations':[r[3] for r in self.before]}))
        self.add(prefix+'after-registers.json',canonical({'schema_version':1,'operations':[r[3] for r in self.after]}))
        hb=self.add(prefix+'hmp-before.txt',self.hmp);ha=self.add(prefix+'hmp-after.txt',self.hmp)
        lb=self.add(prefix+'layout-before.txt',self.layout);la=self.add(prefix+'layout-after.txt',self.layout)
        host=self.add(prefix+'host-phase.json',b'{"synthetic":"no native host authority"}\n')
        stop=self.add(prefix+'stop.bin',b'T05thread:01;')
        # Exact002 epoch fields, with logical closed aliases for RowRef lookup.
        epoch={key:None for key in ('phase','epoch','firmware_phase','stop_ref','before_registers_ref','host_phase_ref',
            'layout_before_ref','read_plan_ref','table_snapshots','objects','translations','completion_ref',
            'after_registers_ref','hmp_after_ref','layout_after_ref','closure_ref')}
        epoch.update(phase=self.epoch,epoch=self.epoch,firmware_phase='firmware_active',stop_ref=stop,
            before_registers_ref=rr,host_phase_ref=host,layout_before_ref=lb,table_snapshots=self.frames,
            objects=self.objects,translations=tuple(p for o in self.objects for p in o.parts),
            after_registers_ref=self.ref(prefix+'after-registers.json'),hmp_after_ref=ha,layout_after_ref=la)
        for key,file in (('read_plan_ref','read-plan.json'),('completion_ref','completion.json'),('closure_ref','closure.json')):
            epoch[key]=self.add(prefix+file,b'{"synthetic":"copied record, no native authority"}\n')
        er=self.add(prefix+'epoch.json',canonical(epoch))
        return d.CopiedEpochBinding(self.epoch,er,stop,rr,self.before,self.after,tuple(self.state.items()),
            hb,ha,lb,la,host,self.c0,self.frames,tuple(d.CopiedBlob(self.ref(k),v) for k,v in self.data.items()))

    def ref(self,name):
        value=self.data[name];return d.BlobRef(name,hashlib.sha256(value).hexdigest(),len(value))

    def scalar(self,selected):
        sr=self.add('selected-call.json',canonical(selected))
        ctx=replace(self.context,blobs=tuple(d.CopiedBlob(self.ref(k),v) for k,v in self.data.items()))
        first=lambda o:d.ObjectFirstEvidence(*(getattr(o,f.name) for f in fields(d.ObjectFirstEvidence)))
        return d.C2ScalarEvidence(sr,ctx.stop_ref,ctx.registers_ref,tuple(first(o) for o in self.objects[:2]),
                                  tuple(first(o) for o in self.objects[2:6]),ctx)

    def final_context(self,extent,projection=None):
        er=self.add('map-extent.json',canonical(extent))
        ir=cr=None
        if projection is not None:
            ir=self.add('map-index.json',projection.descriptor_index_bytes)
            cr=self.add('coverage.json',projection.coverage_bytes)
        return replace(self.context,extent_ref=er,descriptor_index_ref=ir,coverage_ref=cr,
            blobs=tuple(d.CopiedBlob(self.ref(k),v) for k,v in self.data.items()))


class PureCallTests(unittest.TestCase):
    def c1(self):
        f=Fixture('C1');return f,d.validate_c1_entry(f.context,f.objects,f.pinned)

    def c2(self,**kw):
        one,selected=self.c1();two=Fixture('C2',one,**kw);evidence=two.scalar(selected)
        return two,selected,d.validate_c2_scalars(selected,evidence)

    def failure(self,status,call):
        with self.assertRaises(d.C0DecodeError) as caught:call()
        self.assertEqual(caught.exception.status,status)
        return caught.exception.reason

    def test_positive_c1(self):
        f,s=self.c1();self.assertEqual((s.saved_return,s.input_capacity,s.version_pointer),
            (f.base+0x6350,32768,f.s+0x7c));self.assertEqual(s.version_pointer%8,4)

    def test_wrong_first_caller(self):
        f=Fixture('C1',return_delta=1)
        self.failure('INCOMPLETE',lambda:d.validate_c1_entry(f.context,f.objects,f.pinned))

    def test_bad_refs_shapes(self):
        f=Fixture('C1')
        for bad in [replace(f.context,before_registers=[]),replace(f.context,frames=[]),
                    replace(f.context,epoch=True),replace(f.context,blobs=[])]:
            self.failure('DENY',lambda:d.validate_c1_entry(bad,f.objects,f.pinned))

        badframe=replace(f.frames[0],level=True)
        self.failure('DENY',lambda:d.validate_c1_entry(replace(f.context,frames=(badframe,)+f.frames[1:]),f.objects,f.pinned))
        part=f.objects[0].parts[0];entry=replace(part.path[0],index=False)
        obj=replace(f.objects[0],parts=(replace(part,path=(entry,)+part.path[1:]),))
        self.failure('DENY',lambda:d.validate_c1_entry(f.context,(obj,)+f.objects[1:],f.pinned))
        self.failure('DENY',lambda:d.validate_c1_entry(f.context,(replace(f.objects[0],first_read_sequences=()),)+f.objects[1:],f.pinned))
        class Trap:
            def __eq__(self,other):raise AssertionError('callback must not execute')
        self.failure('DENY',lambda:d.validate_c1_entry(f.context,f.objects,replace(f.pinned,efi_sha256=Trap())))
        # Existing register-index schema binds exact sequence order, and rejects
        # malicious JSON before the allocating parser can grow deeply.
        for raw in (canonical({'schema_version':1,'operations':[1]*29}),b'['*13+b']'*13):
            ref=d.BlobRef(f.context.registers_ref.path,hashlib.sha256(raw).hexdigest(),len(raw))
            blobs=tuple(d.CopiedBlob(ref,raw) if b.ref.path==ref.path else b for b in f.context.blobs)
            self.failure('DENY',lambda:d.validate_c1_entry(replace(f.context,registers_ref=ref,blobs=blobs),f.objects,f.pinned))

        # Equal Python numeric values are not equal closed JSON types. This
        # changes only the serialized copy, keeping every native fact intact.
        for field,value in (('physical',4096.0),('ordinal',False)):
            record=json.loads(f.data[f.context.epoch_ref.path])
            record['table_snapshots'][0][field]=value
            raw=canonical(record);old=f.context.epoch_ref
            ref=d.BlobRef(old.path,hashlib.sha256(raw).hexdigest(),len(raw))
            blobs=tuple(d.CopiedBlob(ref,raw) if b.ref.path==ref.path else b for b in f.context.blobs)
            self.failure('DENY',lambda:d.validate_c1_entry(replace(f.context,epoch_ref=ref,blobs=blobs),f.objects,f.pinned))

    def test_wrong_actual_arguments(self):
        f=Fixture('C1');rows=list(f.before);rows[2]=(2,rows[2][1],f.s+0x61,rows[2][3])
        self.failure('DENY',lambda:d.validate_c1_entry(replace(f.context,before_registers=tuple(rows)),f.objects,f.pinned))

    def test_changed_bytes(self):
        f=Fixture('C1',changed=True)
        self.failure('INCOMPLETE',lambda:d.validate_c1_entry(f.context,f.objects,f.pinned))

    def test_positive_c2_extent(self):
        f,s,e=self.c2();self.assertEqual((e.map_size,e.descriptor_count,e.map_key),(384,8,0))
        class Trap:
            def __eq__(self,other):raise AssertionError('callback must not execute')
        ev=f.scalar(s)
        self.failure('DENY',lambda:d.validate_c2_scalars(s,replace(ev,stop_ref=Trap())))
        # Before-only context and only six first objects suffice; no map read dependency.
        ev=f.scalar(s)
        map_paths={c.decoded_data_ref.path for c in f.objects[6].first_contributions+f.objects[6].recheck_contributions}
        ctx=replace(ev.context,epoch_ref=None,after_registers=None,hmp_after_ref=None,layout_after_ref=None,
            blobs=tuple(b for b in ev.context.blobs if b.ref.path not in map_paths
                        and '/objects/06-' not in b.ref.path and b.ref.path!='epochs/C2/epoch.json'))
        self.assertEqual(d.validate_c2_scalars(s,replace(ev,context=ctx)),e)
        record=json.loads(f.data[ev.selected_call_ref.path]);record['input_capacity']=32768.0
        raw=canonical(record);old=ev.selected_call_ref
        ref=d.BlobRef(old.path,hashlib.sha256(raw).hexdigest(),len(raw))
        blobs=tuple(d.CopiedBlob(ref,raw) if b.ref.path==ref.path else b for b in ev.context.blobs)
        self.failure('DENY',lambda:d.validate_c2_scalars(s,replace(ev,selected_call_ref=ref,
            context=replace(ev.context,blobs=blobs))))

    def test_unexpected_return_status(self):
        one,s=self.c1();f=Fixture('C2',one,status=1)
        self.failure('INCOMPLETE',lambda:d.validate_c2_scalars(s,f.scalar(s)))

    def test_same_extent_final(self):
        f,s,e=self.c2();ctx=f.final_context(e)
        self.failure('DENY',lambda:d.project_c2_return(ctx,s,replace(e,map_key=1),f.objects,f.frames))
        record=json.loads(f.data[ctx.extent_ref.path]);record['map_key']=False
        raw=canonical(record);old=ctx.extent_ref
        ref=d.BlobRef(old.path,hashlib.sha256(raw).hexdigest(),len(raw))
        blobs=tuple(d.CopiedBlob(ref,raw) if b.ref.path==ref.path else b for b in ctx.blobs)
        self.failure('DENY',lambda:d.project_c2_return(replace(ctx,extent_ref=ref,blobs=blobs),s,e,f.objects,f.frames))

    def test_max17_map_parts(self):
        f,s,e=self.c2(m=32768,stride=128,small=True)
        self.assertEqual(len(f.objects[6].parts),17)
        p=d.project_c2_return(f.final_context(e),s,e,f.objects,f.frames)
        self.assertEqual(p.descriptor_count,256)

    def test_map_translation_complete(self):
        f,s,e=self.c2();ctx=f.final_context(e)
        self.failure('INCOMPLETE',lambda:d.project_c2_return(replace(ctx,frames=ctx.frames[:-1]),s,e,f.objects,ctx.frames[:-1]))

    def test_descriptor_roundtrip(self):
        f,s,e=self.c2();ctx=f.final_context(e);p=d.project_c2_return(ctx,s,e,f.objects,f.frames)
        self.assertEqual(p.descriptors[0].padding4,b'PADD');self.assertEqual(p.descriptors[0].extension,b'E'*8)
        self.assertEqual(p.descriptors[0].virtual_start,0x123)
        self.assertEqual(p.physical_order,tuple(range(8)))

    def test_descriptor_overlap_overflow(self):
        for offset,value in ((48+8,0),(48+8,0x400001),(48+24,d.U64)):
            with self.subTest(offset=offset,value=value):
                raw=bytearray(map_bytes());struct.pack_into('<Q',raw,offset,value)
                f,s,e=self.c2(raw=bytes(raw))
                self.failure('DENY',lambda:d.project_c2_return(f.final_context(e),s,e,f.objects,f.frames))

    def test_descriptor_zero_or_gap(self):
        for offset,fmt,value in ((24,'<Q',0),(8,'<Q',0x2000),(0,'<I',0)):
            with self.subTest(offset=offset,value=value):
                raw=bytearray(map_bytes());struct.pack_into(fmt,raw,offset,value)
                if offset==8:struct.pack_into('<Q',raw,24,1022)
                f,s,e=self.c2(raw=bytes(raw))
                self.failure('INCOMPLETE',lambda:d.project_c2_return(f.final_context(e),s,e,f.objects,f.frames))

    def test_adjacent_union(self):
        f,s,e=self.c2(m=4096,stride=64,raw=map_bytes(4096,64,split=True))
        p=d.project_c2_return(f.final_context(e),s,e,f.objects,f.frames)
        self.assertTrue(any(len(row.descriptor_ordinals)==2 for row in p.coverage))
        self.assertTrue(all(len(row.descriptor_ordinals)==1 for row in p.coverage if row.extent.kind=='frame'))

    def test_exact_named_set(self):
        f,s,e=self.c2();p=d.project_c2_return(f.final_context(e),s,e,f.objects,f.frames)
        self.assertEqual(len(p.coverage),len(f.frames)+sum(len(o.parts) for o in f.objects))
        self.failure('DENY',lambda:d.project_c2_return(f.final_context(e),s,e,f.objects,f.frames+(f.frames[0],)))

        er=f.context.epoch_ref;record=json.loads(f.data[er.path]);record['after_registers_ref']=js(f.context.registers_ref)
        raw=canonical(record);newref=d.BlobRef(er.path,hashlib.sha256(raw).hexdigest(),len(raw))
        blobs=tuple(d.CopiedBlob(newref,raw) if b.ref.path==er.path else b for b in f.final_context(e).blobs)
        badctx=replace(f.final_context(e),epoch_ref=newref,blobs=blobs)
        self.failure('DENY',lambda:d.project_c2_return(badctx,s,e,f.objects,f.frames))

    def test_fresh_next_fixture(self):
        f=Fixture('C1');self.failure('DENY',lambda:d.validate_c1_entry(f.context,f.objects,replace(f.pinned,caller_code=b'X'*435)))
        self.assertEqual(self.c1()[1].input_capacity,32768)

    def test_malformed_extent(self):
        f,s,e=self.c2()
        for v in [replace(e,map_size=0),replace(e,map_size=True),replace(e,map_pointer=d.U64),
                  replace(e,map_size=383),replace(e,descriptor_stride=0),replace(e,saved_capacity=8192)]:
            self.failure('DENY',lambda:d.projection_size_bound(v,f.objects,f.frames))

    def test_unsupported_extent(self):
        f,s,e=self.c2()
        self.failure('INCOMPLETE',lambda:d.projection_size_bound(replace(e,map_size=32760,descriptor_stride=40,
            descriptor_count=819),f.objects,f.frames))
        for v in (replace(e,descriptor_version=2),replace(e,map_size=32769),replace(e,descriptor_stride=264)):
            self.failure('INCOMPLETE',lambda:d.projection_size_bound(v,f.objects,f.frames))

    def test_volatile_c2_args_can_change(self):
        f,s,e=self.c2(volatile=True)
        self.assertEqual(f.values[3],0x100);self.assertEqual(e.map_pointer,s.map_pointer)

    def test_volatile_pointer_substitution(self):
        f,s,e=self.c2();ev=f.scalar(s);bad=replace(ev.scalar_objects[0],virtual=0x100)
        self.failure('DENY',lambda:d.validate_c2_scalars(s,replace(ev,scalar_objects=(bad,)+ev.scalar_objects[1:])))

    def test_fresh_c1_bs_can_change(self):
        f,s=self.c1();self.assertNotEqual(s.boot_services,f.c0.boot_services);self.assertEqual(s.boot_services,f.values[0])

    def test_projection_real_refs_only(self):
        f,s,e=self.c2();ctx=f.final_context(e);p=d.project_c2_return(ctx,s,e,f.objects,f.frames)
        self.failure('DENY',lambda:d.validate_c2_return(ctx,s,e,f.objects,f.frames))
        facts=d.validate_c2_return(f.final_context(e,p),s,e,f.objects,f.frames)
        self.assertEqual((facts.object_count,facts.coverage_scope,facts.atomic_snapshot),(7,d.SCOPE,False))
        good=f.final_context(e,p);rows=json.loads(p.coverage_bytes);raw=canonical(rows[:-1])
        badref=d.BlobRef('coverage.json',hashlib.sha256(raw).hexdigest(),len(raw))
        blobs=tuple(d.CopiedBlob(badref,raw) if b.ref.path=='coverage.json' else b for b in good.blobs)
        self.failure('DENY',lambda:d.validate_c2_return(replace(good,coverage_ref=badref,blobs=blobs),s,e,f.objects,f.frames))

    def test_projection_bound_prepaid(self):
        f,s,e=self.c2();b=d.projection_size_bound(e,f.objects,f.frames)
        self.assertEqual((b.descriptor_json_bound,b.coverage_json_bound,b.pure_call_credit),(16524,20562,186102))
        p=d.project_c2_return(f.final_context(e),s,e,f.objects,f.frames)
        self.assertLessEqual(len(p.descriptor_index_bytes),b.descriptor_json_bound)
        self.assertLessEqual(len(p.coverage_bytes),b.coverage_json_bound)


if __name__=='__main__':unittest.main()
