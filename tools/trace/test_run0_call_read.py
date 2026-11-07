"""Private retained-byte fixtures only; no public issuer or guest-memory I/O."""
from dataclasses import fields, replace
import hashlib
import inspect
import os
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import patch

from boot_profile_capture import ProbeError
import run0_rsp as rsp

try:
    import run0_call_read as r
    import run0_call_budget as b
except ModuleNotFoundError as error:
    if error.name not in ('run0_call_read', 'run0_call_budget'):
        raise
    r = b = None


def private(cls, **values):
    """No fixture construction lives in the production modules."""
    value = object.__new__(cls)
    for key, item in values.items():
        object.__setattr__(value, key, item)
    return value


class Harness:
    def __init__(self, root):
        from test_run0_call_budget import memory_ledger, frame_charges
        self.ledger = memory_ledger()
        self.batch = self.ledger.reserve_reads('C0', frame_charges())
        self.buffers = {'rsp': bytearray(), 'rsp-out': bytearray()}
        self.parent, self.wire, self.session, self.binding = (object() for _ in range(4))
        self.retainer = private(r._ReadRetainer, _parent=self.parent, _wire=self.wire,
            _session=self.session, _binding=self.binding, _transport=('rsp', 1, 2),
            _accounting=self.ledger, _root=Path(root), _raw=self.buffers,
            _operations={}, _pending=None, _receipts={}, _rows={}, _inventory={}, _slots={},
            _retained_pending={}, _attempts={}, _prepared={}, _failures={},
            _deadline_ns=10**18, _revoked=False, _origin='synthetic_fixture',
            _plan_ref=r.BlobRef('plan.json', hashlib.sha256(b'plan').hexdigest(), 4))

    def pending(self, index=0):
        target = self.batch.charges[index].target
        request_id = self.ledger.view()['physical_claimed']+1
        key = r.ReadKey(self.batch.epoch, request_id, request_id-1,
                        self.ledger.view()['actual_operations']+1)
        return self.retainer.prepare(self.batch, index, key, target)

    def operation(self, pending, data=None):
        target, key = pending.target, pending.key
        data = bytes([key.request_id])*target.length if data is None else data
        request = rsp.encode_packet(f'm{target.gpa:x},{target.length:x}'.encode())
        response = rsp.encode_packet(data.hex().encode())
        def append(stream, raw):
            pos = r.LiveWirePosition(stream, len(self.buffers[stream]), len(raw))
            self.ledger.reserve_output(len(raw))
            self.buffers[stream].extend(raw)
            return pos
        req = append('rsp-out', request)
        reqack = append('rsp', b'+')
        res = append('rsp', response)
        resack = append('rsp-out', b'+')
        attempt = private(r._HeldReadAttempt, _parent=self.parent, _wire=self.wire,
            key=key, target=target, started_ns=10, finished_ns=12, result='ok')
        self.retainer._attempts[key.operation_seq] = attempt
        op = private(r._HeldReadOperation, _parent=self.parent, _wire=self.wire, attempt=attempt,
            key=key, target=target, request_position=req, request_ack_position=reqack,
            response_position=res, response_ack_position=resack,
            started_ns=10, response_received_ns=11, ack_finished_ns=12, result='ok')
        self.retainer._operations[key.operation_seq] = op
        return dict(operation=op, request_position=req, request_ack_position=reqack,
                    response_position=res, response_ack_position=resack,
                    request_bytes=request, response_bytes=response, started_ns=10,
                    response_received_ns=11, ack_finished_ns=12)

    def sealed(self, index=0):
        pending = self.pending(index)
        return self.retainer.seal(pending, **self.operation(pending))


class ParentReadTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(r, 'parent read implementation is required')
        self.temp = tempfile.TemporaryDirectory(prefix='parent-read-')
        self.addCleanup(self.temp.cleanup)
        self.h = Harness(self.temp.name)

    def test_public_constructors_cannot_issue_native_receipts(self):
        for cls in (r.NativePhysicalReadReceipt, r._ReadRetainer,
                    r.PendingReadRetention, r._HeldReadOperation):
            with self.assertRaises(TypeError):
                cls()

    def test_exact_packet_data_and_export_row_join(self):
        receipt = self.h.sealed()
        self.assertEqual(receipt.data, bytes([1])*2048)
        self.assertEqual(receipt.decoded_data_ref.path, 'memory/read-000.bin')
        self.assertEqual((Path(self.temp.name)/receipt.decoded_data_ref.path).read_bytes(), receipt.data)
        self.assertEqual(len(self.h.retainer.inventory()), 3)
        row = self.h.retainer.export_row(receipt)
        self.assertEqual(row.operation_seq, 46)
        self.assertEqual(row.payload_ref.offset, 1)
        self.assertEqual(row.payload_ref.length, 4096)
        self.assertLessEqual(len(row.canonical_bytes), 8192)

    def test_public_operation_fact_is_not_native_authority(self):
        pending = self.h.pending()
        values = self.h.operation(pending)
        values['operation'] = {'seq': 46, 'result': 'ok'}
        with self.assertRaises(ProbeError):
            self.h.retainer.seal(pending, **values)
        self.assertEqual(self.h.retainer.inventory(), ())

    def test_unheld_operation_of_same_shape_is_rejected(self):
        pending = self.h.pending()
        values = self.h.operation(pending)
        old = values['operation']
        values['operation'] = private(r._HeldReadOperation,
            **{f.name: getattr(old, f.name) for f in fields(old)})
        with self.assertRaises(ProbeError):
            self.h.retainer.seal(pending, **values)

    def test_checksum_corruption_retains_no_success(self):
        pending = self.h.pending()
        values = self.h.operation(pending)
        actual = values['response_bytes']
        bad = actual[:-1]+(b'1' if actual[-1:] != b'1' else b'2')
        self.h.buffers['rsp'][1:] = bad
        values['response_bytes'] = bad
        with self.assertRaises(ProbeError):
            self.h.retainer.seal(pending, **values)
        self.assertFalse(self.h.retainer._receipts)

    def test_missing_actual_ack_cannot_seal(self):
        pending = self.h.pending()
        values = self.h.operation(pending)
        self.h.buffers['rsp-out'][-1] = ord('-')
        with self.assertRaises(ProbeError):
            self.h.retainer.seal(pending, **values)
        self.assertFalse(self.h.retainer._receipts)

    def test_first_half_survives_second_failure(self):
        first = self.h.sealed()
        pending = self.h.pending(1)
        values = self.h.operation(pending)
        values['ack_finished_ns'] = 9
        with self.assertRaises(ProbeError):
            self.h.retainer.seal(pending, **values)
        partial = self.h.retainer.partial_assembly((first,), 4096, failure_operation_seq=47)
        self.assertEqual(partial.next_logical_offset, 2048)
        self.assertEqual(len(partial.completed_contributions), 1)
        self.assertFalse(list(Path(self.temp.name).glob('epochs/**/frames/*.bin')))
        self.assertTrue((Path(self.temp.name)/first.decoded_data_ref.path).is_file())

    def test_short_write_preserves_actual_prefix_no_retry(self):
        pending = self.h.pending()
        values = self.h.operation(pending)
        original = os.write
        calls = []
        def short(fd, data):
            calls.append(len(data))
            return original(fd, memoryview(data)[:3])
        with patch.object(r.os, 'write', short):
            with self.assertRaises(ProbeError):
                self.h.retainer.seal(pending, **values)
        self.assertEqual(len(calls), 1)
        row, = self.h.retainer.inventory()
        self.assertEqual((row.state, row.blob.length), ('incomplete_write', 3))
        self.assertFalse(self.h.retainer._receipts)
        with self.assertRaises(ProbeError):
            self.h.retainer.seal(pending, **values)
        self.assertEqual(len(calls), 1)

    def test_final_stream_join_checks_actual_ack_coordinates(self):
        receipt = self.h.sealed()
        raw = tuple((name, bytes(value)) for name, value in self.h.buffers.items())
        refs = tuple((name, r.BlobRef('raw/rsp.bin' if name == 'rsp' else 'raw/rsp-requests.bin',
                                    hashlib.sha256(value).hexdigest(), len(value)))
                     for name, value in raw)
        self.assertEqual(len(self.h.retainer.resolve_positions((receipt,), refs, raw)), 1)
        changed = tuple((name, value[:-1]+b'-' if name == 'rsp-out' else value) for name, value in raw)
        with self.assertRaises(ProbeError):
            self.h.retainer.resolve_positions((receipt,), refs, changed)

    def test_reuse_and_cross_epoch_assembly_denied_then_fresh_success(self):
        first = self.h.sealed()
        with self.assertRaises(ProbeError):
            self.h.retainer.partial_assembly((first, first), 4096, failure_operation_seq=None)
        with self.assertRaises(ProbeError):
            self.h.retainer.prepare(self.h.batch, 0, r.ReadKey('C1', 2, 1, 47),
                                    self.h.batch.charges[0].target)
        with tempfile.TemporaryDirectory(prefix='parent-read-next-') as root:
            self.assertEqual(Harness(root).sealed().result, 'ok')

    def test_strict_positions_and_runtime_guard(self):
        for position in (('rsp', True, 1), ('unknown', 0, 1), ('rsp', 0, 0)):
            with self.assertRaises(ProbeError):
                r.LiveWirePosition(*position)
        receipt = self.h.sealed()
        with self.assertRaises(ProbeError):
            r.require_runtime_receipt(receipt)

    def test_complete_assembly_debits_distinct_existing_file_credit(self):
        first, second = self.h.sealed(0), self.h.sealed(1)
        before = dict(self.h.ledger.view())
        result = self.h.retainer.assemble((first, second), target_length=4096)
        self.assertEqual(result.data, bytes([1])*2048+bytes([2])*2048)
        self.assertEqual(result.blob.path, 'epochs/C0/frames/00-first.bin')
        self.assertEqual((Path(self.temp.name)/result.blob.path).read_bytes(), result.data)
        after = dict(self.h.ledger.view())
        self.assertEqual(after['committed_bytes'], before['committed_bytes'])
        self.assertGreaterEqual(after['actual_bytes']-before['actual_bytes'], 8192)
        with self.assertRaises(ProbeError):
            self.h.retainer.assemble((first, second), target_length=4096)

    def test_incomplete_or_reordered_assembly_cannot_write(self):
        first, second = self.h.sealed(0), self.h.sealed(1)
        for receipts, length in (((first,), 4096), ((second, first), 4096),
                                 ((first, second), 4095), ((first, first), 4096)):
            with self.assertRaises(ProbeError):
                self.h.retainer.assemble(receipts, target_length=length)
        self.assertFalse((Path(self.temp.name)/'epochs').exists())
        self.assertEqual(self.h.retainer.assemble((first, second), target_length=4096).target_length, 4096)

    def test_completion_clock_follows_all_file_fsyncs(self):
        pending = self.h.pending()
        values = self.h.operation(pending)
        syncs = []
        original = os.fsync
        def sync(fd):
            original(fd)
            syncs.append(fd)
        def clock():
            self.assertEqual(len(syncs), 3)
            return 100
        with patch.object(r.os, 'fsync', sync), patch.object(r.time, 'monotonic_ns', clock):
            receipt = self.h.retainer.seal(pending, **values)
        self.assertEqual(receipt.finished_ns, 100)
        self.assertEqual(self.h.retainer.export_row(receipt).finished_ns, 100)

    def test_final_deadline_check_denies_after_row_preparation(self):
        pending = self.h.pending()
        values = self.h.operation(pending)
        self.h.retainer._deadline_ns = 35
        with patch.object(r.time, 'monotonic_ns', side_effect=(30, 40)):
            with self.assertRaises(ProbeError):
                self.h.retainer.seal(pending, **values)
        self.assertFalse(self.h.retainer._receipts)
        self.assertEqual(len(self.h.retainer.inventory()), 3)
        with tempfile.TemporaryDirectory(prefix='parent-read-after-deadline-') as root:
            self.assertEqual(Harness(root).sealed().result, 'ok')

    def test_unused_prepaid_capacity_is_not_reported_as_actual(self):
        receipt = self.h.sealed()
        view = self.h.ledger.view()
        self.assertLess(view['actual_bytes'], view['committed_bytes'])
        pending = self.h.retainer._retained_pending[receipt.physical_ordinal]
        remaining = self.h.ledger._claimed[pending.key]['remaining']
        self.assertEqual(remaining['assembly_file'], receipt.length)
        self.assertEqual(remaining['read'], 8*receipt.length+2048)
        self.assertEqual(remaining['decoded_file'], 0)

    def test_final_export_cannot_filter_success_receipts(self):
        first, second = self.h.sealed(0), self.h.sealed(1)
        raw = tuple((name, bytes(value)) for name, value in self.h.buffers.items())
        refs = tuple((name, r.BlobRef('raw/rsp.bin' if name == 'rsp' else 'raw/rsp-requests.bin',
                                    hashlib.sha256(value).hexdigest(), len(value))) for name, value in raw)
        with self.assertRaises(ProbeError):
            self.h.retainer.resolve_positions((first,), refs, raw)
        self.assertEqual(len(self.h.retainer.resolve_positions((first, second), refs, raw)), 2)

    def test_primary_short_write_not_replaced_by_close_failure(self):
        pending = self.h.pending()
        values = self.h.operation(pending)
        write, close = os.write, os.close
        def short(fd, data):
            return write(fd, memoryview(data)[:3])
        def close_error(fd):
            close(fd)
            raise OSError('secondary close error')
        with patch.object(r.os, 'write', short), patch.object(r.os, 'close', close_error):
            with self.assertRaises(ProbeError) as caught:
                self.h.retainer.seal(pending, **values)
        self.assertEqual(caught.exception.reason, 'call_read_short_write')
        self.assertEqual(self.h.retainer.inventory()[0].state, 'incomplete_write')

    def test_complete_object_cannot_be_relabelled_partial_larger_target(self):
        charges = tuple(b.ReadCharge.for_target(r.ReadTarget('object', p, 0, 0, 0x3000, 4))
                        for p in (0, 1))
        self.h.batch = self.h.ledger.reserve_reads('C0', charges)
        receipt = self.h.sealed(0)
        with self.assertRaises(ProbeError):
            self.h.retainer.partial_assembly((receipt,), 8, failure_operation_seq=None)
        result = self.h.retainer.assemble((receipt,), target_length=4)
        self.assertEqual(result.blob.path, 'epochs/C0/objects/00-first.bin')

    def test_existing_symlink_output_is_not_followed(self):
        pending = self.h.pending()
        values = self.h.operation(pending)
        directory = Path(self.temp.name)/'operations'
        directory.mkdir(mode=0o700)
        victim = Path(self.temp.name)/'victim'
        victim.write_bytes(b'original')
        (directory/'0046-request.bin').symlink_to(victim)
        with self.assertRaises(OSError):
            self.h.retainer.seal(pending, **values)
        self.assertEqual(victim.read_bytes(), b'original')
        self.assertFalse(self.h.retainer._receipts)

    def test_partial_cannot_invent_failed_operation_ordinal(self):
        receipt = self.h.sealed()
        with self.assertRaises(ProbeError):
            self.h.retainer.partial_assembly((receipt,), 4096, failure_operation_seq=1024)
        self.assertIsNone(self.h.retainer.partial_assembly((receipt,), 4096,
                          failure_operation_seq=None).failure_operation_seq)

    def test_valid_unaligned_map_has_seventeen_parts(self):
        from test_run0_call_budget import memory_ledger
        self.h.ledger = memory_ledger('C2')
        self.h.retainer._accounting = self.h.ledger
        lengths = (1,)+(2048,)*15+(2047,)
        targets = []
        for pass_index in (0, 1):
            offset = 0
            for length in lengths:
                targets.append(r.ReadTarget('object', pass_index, 6, offset, 0x3fff+offset, length))
                offset += length
        self.h.batch = self.h.ledger.reserve_reads('C2', tuple(b.ReadCharge.for_target(t) for t in targets))
        receipts = tuple(self.h.sealed(i) for i in range(17))
        result = self.h.retainer.assemble(receipts, target_length=32768)
        self.assertEqual((result.target_length, len(result.contributions)), (32768, 17))
        rechecks = []
        for index in range(17, 33):
            pending = self.h.pending(index)
            rechecks.append(self.h.retainer.seal(pending, **self.h.operation(pending,
                            data=receipts[index-17].data)))
        partial = self.h.retainer.partial_assembly(tuple(rechecks), 32768, failure_operation_seq=None)
        self.assertEqual(len(partial.completed_contributions), 16)
        pending = self.h.pending(33)
        rechecks.append(self.h.retainer.seal(pending, **self.h.operation(pending, data=receipts[-1].data)))
        again = self.h.retainer.assemble(tuple(rechecks), target_length=32768)
        self.assertEqual(result.data, again.data)

    def test_partial_cannot_omit_already_successful_next_receipt(self):
        first, second = self.h.sealed(0), self.h.sealed(1)
        with self.assertRaises(ProbeError):
            self.h.retainer.partial_assembly((first,), 4096,
                                             failure_operation_seq=second.operation_seq)

    def test_decoder_all_five_live_payload_copies_are_prepaid(self):
        pending = self.h.pending()
        values = self.h.operation(pending)
        before = self.h.ledger.view()['actual_bytes']
        source, start = inspect.getsourcelines(rsp._AckCodec.feed)
        line = start+next(i for i, text in enumerate(source) if 'self._buffer.clear()' in text)
        seen = []
        def trace(frame, event, arg):
            if event == 'line' and frame.f_code is rsp._AckCodec.feed.__code__ and frame.f_lineno == line:
                values = frame.f_locals
                copies = (values['self']._buffer, values['raw'], values['encoded'],
                          values['decoded'], values['frames'][0].payload)
                self.assertEqual(len(set(map(id, copies))), 5)
                observed = sum(map(len, copies))
                seen.append(observed)
                self.assertGreaterEqual(self.h.ledger.view()['actual_bytes']-before, observed)
            return trace
        previous = sys.gettrace()
        sys.settrace(trace)
        try:
            self.h.retainer.seal(pending, **values)
        finally:
            sys.settrace(previous)
        self.assertEqual(seen, [20488])

    def test_admitted_ack_without_recorded_retention_failure_cannot_be_failed(self):
        first = self.h.sealed()
        pending = self.h.pending(1)
        values = self.h.operation(pending)
        for sequence in (None, values['operation'].key.operation_seq):
            with self.assertRaises(ProbeError):
                self.h.retainer.partial_assembly((first,), 4096, failure_operation_seq=sequence)
        self.h.retainer.seal(pending, **values)

    def test_other_targets_failure_does_not_certify_missing_half(self):
        from test_run0_call_budget import frame_charges
        first = self.h.sealed()
        self.h.batch = self.h.ledger.reserve_reads('C0', frame_charges(0x5000, ordinal=1))
        pending = self.h.pending(0)
        values = self.h.operation(pending)
        values['ack_finished_ns'] = 9
        with self.assertRaises(ProbeError):
            self.h.retainer.seal(pending, **values)
        with self.assertRaises(ProbeError):
            self.h.retainer.partial_assembly((first,), 4096,
                                             failure_operation_seq=pending.key.operation_seq)

    def test_pending_protocol_attempt_cannot_create_retention_failure_proof(self):
        first = self.h.sealed()
        pending = self.h.pending(1)
        values = self.h.operation(pending)
        old = values['operation'].attempt
        self.h.retainer._attempts[pending.key.operation_seq] = private(r._HeldReadAttempt,
            **{field.name: ('pending' if field.name == 'result' else getattr(old, field.name))
               for field in fields(old)})
        with self.assertRaises(ProbeError):
            self.h.retainer.seal(pending, **values)
        self.assertFalse(self.h.retainer._failures)
        with self.assertRaises(ProbeError):
            self.h.retainer.partial_assembly((first,), 4096,
                                             failure_operation_seq=pending.key.operation_seq)

    def test_prepared_allocation_is_not_native_admission(self):
        first = self.h.sealed()
        before = self.h.ledger.view()['allocated_operations']
        pending = self.h.pending(1)
        view = self.h.ledger.view()
        self.assertEqual(view['allocated_operations'], before+1)
        self.assertEqual(view['actual_operations'], view['allocated_operations'])
        partial = self.h.retainer.partial_assembly((first,), 4096, failure_operation_seq=None)
        self.assertIsNone(partial.failure_operation_seq)
        values = self.h.operation(pending)  # fixture now installs native admission.
        with self.assertRaises(ProbeError):
            self.h.retainer.partial_assembly((first,), 4096, failure_operation_seq=None)
        self.assertEqual(self.h.retainer.seal(pending, **values).result, 'ok')


if __name__ == '__main__':
    unittest.main()
