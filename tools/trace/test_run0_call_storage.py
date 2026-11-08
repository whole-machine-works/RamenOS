"""Private file/native fixtures only; no live registration, child or guest reads."""
from contextlib import ExitStack
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import boot_profile_capture as base
import run0_call_capture as root
import run0_call_owner as owner
import run0_call_read as read
import run0_call_session as session
from test_run0_call_read import Harness, private
from test_run0_call_budget import memory_ledger
try:
    import run0_call_storage as storage
except ModuleNotFoundError as error:
    if error.name != 'run0_call_storage':raise
    storage=None


class StorageControls(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(storage,'fixed parent storage module missing: expected RED')
        self.temp=tempfile.TemporaryDirectory(prefix='call-storage-')
        self.addCleanup(self.temp.cleanup)
        self.run=Path(self.temp.name).resolve();self.run.chmod(0o700)
        self.stack=ExitStack();self.addCleanup(self.stack.close)

    def graph(self,h=None):
        ledger=memory_ledger() if h is None else h.ledger
        inventory=root.RootRawInventory(self.run,ledger)
        prepared=private(root.PreparedCallInputs,run=str(self.run),profile_bytes=b'private profile fixture')
        runtime=private(root._OwnedCallRuntime,prepared=prepared,inventory=inventory,accounting=ledger,
            _wire=None,parent_identity=object(),read_attempts={},read_operations={})
        registration=private(root.ClosedOwnedCallRegistration,_owner=runtime,prepared=prepared,
            inventory=inventory,accounting=ledger,parent_identity=runtime.parent_identity,
            wire=None,read_attempts=runtime.read_attempts,read_operations=runtime.read_operations)
        runtime._registration=registration
        policy=owner.ParentDeadlines(1)
        child=owner.ParentOwnedWait('qemu',policy)
        proc=object.__new__(subprocess.Popen);proc._child_created=False;proc.pid=12345;proc.returncode=0
        child.child=proc;child.reaped=True;child.returncode=0
        child.lifecycle=[dict(role='qemu',pid=12345,operation='wait',started_ns=1,finished_ns=2,
                             result='ok',returncode=0,errno=None)]
        runtime.qemu_owner=child;registration.__class__
        object.__setattr__(registration,'qemu_owner',child)
        self.stack.enter_context(patch.object(root,'_issued_call_registration',return_value=True))
        self.stack.enter_context(patch.object(root.witness,'decode_pinned_profile',return_value={
            'inputs':{'initial_vars':{'length':16,'sha256':'0'*64}}}))
        if h is not None:
            import run0_call_wire
            wire=object.__new__(run0_call_wire.CallWire);wire._raw=h.buffers
            h.wire=wire;h.retainer._wire=wire
            for attempt in h.retainer._attempts.values():object.__setattr__(attempt,'_wire',wire)
            for operation in h.retainer._operations.values():object.__setattr__(operation,'_wire',wire)
            binding=private(session.CurrentEpochRamBinding,_owner=runtime,registration=registration,
                parent_identity=h.parent,wire=h.wire,epoch='C0')
            native_session=object.__new__(session.ParentAcquisitionSession)
            native_session._owner=runtime;native_session._registration=registration
            native_session.binding=binding;native_session.retainer=h.retainer;native_session._blobs={}
            runtime._wire=h.wire;runtime.parent_identity=h.parent
            runtime.read_attempts=h.retainer._attempts;runtime.read_operations=h.retainer._operations
            for key,value in dict(wire=h.wire,parent_identity=h.parent,
                read_attempts=runtime.read_attempts,read_operations=runtime.read_operations).items():
                object.__setattr__(registration,key,value)
            ret=h.retainer;ret._origin=None;ret._registration=registration;ret._binding=binding;ret._session=native_session
            for receipt in ret._receipts.values():
                object.__setattr__(receipt,'session',native_session);object.__setattr__(receipt,'binding',binding)
            self.stack.enter_context(patch.object(read,'_retainer_guard',return_value=None))
        return inventory,runtime

    def seeded(self,complete=True):
        h=Harness(self.run);first=h.sealed(0)
        assembly=None
        if complete:
            second=h.sealed(1);assembly=h.retainer.assemble((first,second),target_length=4096)
        inventory,runtime=self.graph(h)
        if assembly is not None:
            h.retainer._session._blobs[assembly.blob.path]=(assembly.blob,assembly.data)
        return h,inventory,runtime

    def fresh(self):
        with tempfile.TemporaryDirectory(prefix='storage-fresh-') as folder:
            p=Path(folder).resolve();p.chmod(0o700);h=Harness(p);h.sealed(0)
            # Independent fixture uses the same private graph helper with a new root.
            old=self.run;self.run=p
            try:
                inv,_=self.graph(h);rows=storage.adopt_retainer(inv,h.retainer)
                self.assertEqual(len(rows),3)
            finally:self.run=old

    def test_01_wrong_types_deny_before_file_io(self):
        with patch.object(os,'open',side_effect=AssertionError('IO')):
            for args in ((None,None),({},{})):
                with self.assertRaises(base.ProbeError):storage.adopt_retainer(*args)
                with self.assertRaises(base.ProbeError):storage.seal_final_vars(*args)
        self.fresh()

    def test_02_adopt_exact_receipt_and_assembly_bytes_without_second_write(self):
        h,inv,_=self.seeded();before=inv.accounting.view()['actual_bytes']
        with patch.object(os,'write',side_effect=AssertionError('second write')):
            rows=storage.adopt_retainer(inv,h.retainer)
        self.assertEqual(len(rows),7)
        for native in h.retainer.inventory():
            slot=inv._slots[native.blob.path];self.assertIs(slot.ref,native.blob)
            self.assertEqual(slot.state,'complete')
        receipt=h.retainer._receipts[0]
        self.assertIs(inv._slots[receipt.decoded_data_ref.path].data,receipt.data)
        self.assertGreater(inv.accounting.view()['actual_bytes'],before)

    def test_03_repeated_adoption_is_immutable_and_no_payload_redebit(self):
        h,inv,_=self.seeded();storage.adopt_retainer(inv,h.retainer)
        before=dict(inv._slots)
        storage.adopt_retainer(inv,h.retainer)
        self.assertTrue(all(inv._slots[k] is v for k,v in before.items()))
        name=next(iter(h.retainer._inventory));slot=inv._slots[name]
        object.__setattr__(slot,'state','incomplete_write')
        with self.assertRaises(base.ProbeError):storage.adopt_retainer(inv,h.retainer)
        self.fresh()

    def test_04_synthetic_origin_or_missing_producer_never_adopts(self):
        h,inv,_=self.seeded(False);h.retainer._origin='synthetic_fixture'
        with patch.object(os,'open',side_effect=AssertionError('IO')):
            with self.assertRaises(base.ProbeError):storage.adopt_retainer(inv,h.retainer)
        h.retainer._origin=None
        with patch.object(read,'_retainer_guard',side_effect=base.ProbeError('INCOMPLETE','producer_pending')):
            with self.assertRaises(base.ProbeError) as e:storage.adopt_retainer(inv,h.retainer)
            self.assertEqual(e.exception.status,'INCOMPLETE')
        self.fresh()

    def test_05_wrong_root_ledger_raw_attempt_and_session_aliases_deny(self):
        h,inv,_=self.seeded(False)
        for name,value in (('_root',Path('/tmp')),('_accounting',memory_ledger()),('_raw',{}),
                           ('_attempts',{}),('_operations',{}),('_session',object())):
            with self.subTest(name=name):
                old=getattr(h.retainer,name);setattr(h.retainer,name,value)
                with self.assertRaises(base.ProbeError):storage.adopt_retainer(inv,h.retainer)
                setattr(h.retainer,name,old)
        storage.adopt_retainer(inv,h.retainer);self.fresh()

    def test_06_changed_file_symlink_or_public_file_denies_then_fresh(self):
        h,inv,_=self.seeded(False);row=next(iter(h.retainer._inventory.values()));path=self.run/row.blob.path
        old=path.read_bytes();path.write_bytes(b'x'*len(old))
        with self.assertRaises(base.ProbeError):storage.adopt_retainer(inv,h.retainer)
        path.write_bytes(old);path.chmod(0o644)
        with self.assertRaises(base.ProbeError):storage.adopt_retainer(inv,h.retainer)
        path.chmod(0o600);storage.adopt_retainer(inv,h.retainer);self.fresh()

    def test_07_partial_write_retained_without_success_or_rewrite(self):
        h=Harness(self.run);pending=h.pending();op=h.operation(pending);real=os.write
        def short(fd,data):return real(fd,memoryview(data)[:3])
        with patch.object(os,'write',side_effect=short):
            with self.assertRaises(base.ProbeError):h.retainer.seal(pending,**op)
        inv,_=self.graph(h)
        with patch.object(os,'write',side_effect=AssertionError('rewrite')):
            rows=storage.adopt_retainer(inv,h.retainer)
        self.assertEqual(len(rows),1);self.assertEqual(rows[0]['state'],'incomplete_write')
        self.assertEqual(rows[0]['length'],3);self.assertIsNone(inv._slots[rows[0]['path']].data)
        with self.assertRaises(base.ProbeError):inv.audit()
        self.fresh()

    def test_08_fixed_role_and_full_length_guards_precede_adoption(self):
        h,inv,_=self.seeded(False);row=next(iter(h.retainer._inventory.values()))
        wrong=read._InventoryRow(read.BlobRef('caller-chosen.bin',row.blob.sha256,row.blob.length),row.family,row.epoch,row.state)
        h.retainer._inventory={wrong.blob.path:wrong}
        with self.assertRaises(base.ProbeError):storage.adopt_retainer(inv,h.retainer)
        self.fresh()

    def test_09_prepaid_metadata_failure_precedes_any_host_read(self):
        h,inv,_=self.seeded(False)
        with patch.object(type(inv.accounting),'reserve_output',side_effect=base.ProbeError('INCOMPLETE','budget')):
            with patch.object(os,'open',side_effect=AssertionError('unpaid IO')):
                with self.assertRaises(base.ProbeError):storage.adopt_retainer(inv,h.retainer)
        self.fresh()

    def test_15_later_invalid_row_denied_before_any_file_read(self):
        h,inv,_=self.seeded(False)
        last=next(reversed(h.retainer._inventory))
        row=h.retainer._inventory[last]
        h.retainer._inventory[last]=read._InventoryRow(row.blob,'wrong family',row.epoch,row.state)
        with patch.object(os,'open',side_effect=AssertionError('IO before validation')):
            with self.assertRaises(base.ProbeError):storage.adopt_retainer(inv,h.retainer)
        h.retainer._inventory[last]=row
        storage.adopt_retainer(inv,h.retainer)

    def test_16_unheld_complete_copy_prepaid_before_read(self):
        h,inv,_=self.seeded(False)
        h.retainer._receipts.clear()
        real=type(inv.accounting).reserve_output
        calls=[]
        def reserve(accounting,amount):
            calls.append(amount)
            if len(calls)==2:raise base.ProbeError('INCOMPLETE','copy budget')
            return real(accounting,amount)
        with patch.object(type(inv.accounting),'reserve_output',reserve):
            with patch.object(storage,'_read_existing',side_effect=AssertionError('unpaid copy')):
                with self.assertRaises(base.ProbeError) as e:storage.adopt_retainer(inv,h.retainer)
        self.assertEqual(e.exception.status,'INCOMPLETE')
        rows=storage.adopt_retainer(inv,h.retainer)
        self.assertEqual(len(rows),3)
        for row in rows:self.assertEqual(inv._slots[row['path']].data,(self.run/row['path']).read_bytes())

    def test_17_vars_copy_budget_failure_before_open_then_success(self):
        inv,runtime,_=self.vars()
        real=type(inv.accounting).reserve_output
        calls=[]
        def reserve(accounting,amount):
            calls.append(amount)
            if len(calls)==2:raise base.ProbeError('INCOMPLETE','copy budget')
            return real(accounting,amount)
        with patch.object(type(inv.accounting),'reserve_output',reserve):
            with patch.object(os,'open',side_effect=AssertionError('unpaid IO')):
                with self.assertRaises(base.ProbeError) as e:storage.seal_final_vars(inv,runtime)
        self.assertEqual(e.exception.status,'INCOMPLETE')
        self.assertEqual(storage.seal_final_vars(inv,runtime)[1],b'v'*16)

    def test_18_partial_object_obeys_fixed_path_upper_bound_before_io(self):
        h,inv,_=self.seeded()
        name=next(k for k in h.retainer._inventory if '/frames/' in k)
        row=h.retainer._inventory[name]
        object_name='epochs/C0/objects/00-first.bin'
        pending=h.retainer._prepared[0]
        object.__setattr__(pending.target,'kind','object')
        object.__setattr__(pending.target,'target_ordinal',0)
        h.retainer._inventory.pop(name)
        h.retainer._inventory[object_name]=read._InventoryRow(
            read.BlobRef(object_name,row.blob.sha256,65),'object assemblies','C0','incomplete_write')
        h.retainer._slots[object_name]=h.retainer._slots[name]
        with patch.object(os,'open',side_effect=AssertionError('IO before bound')):
            with self.assertRaises(base.ProbeError):storage.adopt_retainer(inv,h.retainer)
        self.fresh()

    def vars(self):
        inv,runtime=self.graph();p=self.run/'vars.fd';p.write_bytes(b'v'*16);p.chmod(0o600)
        return inv,runtime,p

    def test_10_final_vars_requires_actual_reap_not_lost_and_wait_record(self):
        inv,runtime,p=self.vars()
        for name,value in (('reaped',False),('ownership_lost',True),('returncode',None),('lifecycle',[])):
            old=getattr(runtime.qemu_owner,name);setattr(runtime.qemu_owner,name,value)
            with self.assertRaises(base.ProbeError):storage.seal_final_vars(inv,runtime)
            setattr(runtime.qemu_owner,name,old)
        ref,data=storage.seal_final_vars(inv,runtime);self.assertEqual(data,b'v'*16)

    def test_11_final_vars_fixed_size_private_regular_no_rewrite(self):
        inv,runtime,p=self.vars();p.write_bytes(b'short')
        with self.assertRaises(base.ProbeError):storage.seal_final_vars(inv,runtime)
        p.write_bytes(b'v'*16);p.chmod(0o644)
        with self.assertRaises(base.ProbeError):storage.seal_final_vars(inv,runtime)
        p.chmod(0o600)
        with patch.object(os,'write',side_effect=AssertionError('rewrite')):
            ref,data=storage.seal_final_vars(inv,runtime)
        self.assertEqual(ref.path,'vars.fd');self.assertEqual(ref.sha256,hashlib.sha256(data).hexdigest())
        inv.require_exact(ref,data)

    def test_12_final_vars_no_registration_before_effect_and_next_success(self):
        inv,runtime,p=self.vars()
        with patch.object(root,'_issued_call_registration',return_value=False):
            with patch.object(os,'open',side_effect=AssertionError('IO')):
                with self.assertRaises(base.ProbeError) as e:storage.seal_final_vars(inv,runtime)
                self.assertEqual(e.exception.status,'INCOMPLETE')
        storage.seal_final_vars(inv,runtime)

    def test_13_final_vars_no_second_seal_and_charged_before_read(self):
        inv,runtime,p=self.vars();storage.seal_final_vars(inv,runtime)
        with self.assertRaises(base.ProbeError):storage.seal_final_vars(inv,runtime)

    def test_14_no_source_callback_or_public_fixture_origin(self):
        import inspect
        self.assertEqual(tuple(inspect.signature(storage.adopt_retainer).parameters),('inventory','retainer'))
        self.assertEqual(tuple(inspect.signature(storage.seal_final_vars).parameters),('inventory','runtime'))
        self.assertNotIn('callback',inspect.getsource(storage))

if __name__=='__main__':unittest.main()
