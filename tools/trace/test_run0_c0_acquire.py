"""AC01–AC10 pure synthetic controls; no production issuer or socket adapter.

The private construction fixtures below are deliberately test-local. Their
origin is always synthetic_fixture; no real wire is created or activated.
Actual owned-launch/current-host join, final wire hook and cleanup remain pending.
"""
import copy
from dataclasses import fields, replace, FrozenInstanceError
import hashlib
import json
from pathlib import Path
import struct
import tempfile
from types import MappingProxyType
import unittest
from unittest.mock import patch

import boot_profile_capture as capture
import run0_c0_decode as d
import run0_c0_entry as token
import run0_c0_wire as wire
from test_run0_c0_decode import full_fixture, frame, mode

try:
    import run0_c0_acquire as a
except ModuleNotFoundError as error:
    if error.name != 'run0_c0_acquire':
        raise
    a = None


def fixture_value(cls, original=None, **changes):
    """Trusted test-only private construction, never an imported runtime factory."""
    result = object.__new__(cls)
    values = {} if original is None else {f.name: getattr(original, f.name) for f in fields(cls)}
    values.update(changes)
    for name, value in values.items():
        object.__setattr__(result, name, value)
    return result


def frozen_ref(ref):
    return tuple(ref[name] for name in ('path', 'sha256', 'length'))


def raw_ref(name, raw):
    return (name, hashlib.sha256(raw).hexdigest(), len(raw))


class Harness:
    """Native memory fixture and independent exact packet/slice receipt builder."""
    def __init__(self, session, memory, template=None, blobs=None):
        self.session, self.memory = session, dict(memory)
        self.seq = session.binding.proof_prefix[-1][1]
        self.stamp = session.binding.stop_ns+1000
        self.offsets = {'rsp': 0, 'rsp-out': 0}
        self.grants, self.receipts = [], []
        self.template = template
        self.blobs = blobs

    def receipt(self, grant, data=None, **changes):
        self.seq += 1
        if self.template:
            op = self.template[self.seq]
            self.stamp = op['started_ns']
        admitted = self.session.consume_for_dispatch(grant, self.session.binding.transport_identity,
            self.session.binding.admission_epoch, self.seq, self.stamp)
        intent = grant.intent
        data = bytes(self.memory.get(intent.physical+i, 0) for i in range(intent.length)) if data is None else data
        payload = data.hex().encode('ascii')
        request, response = d.rsp.encode_packet(admitted.request_payload), d.rsp.encode_packet(payload)
        slices = []
        for stream, raw, key in (('rsp-out', request, 'request'), ('rsp', response, 'response')):
            if self.template:
                ref = op[key]
                original = self.blobs[ref['blob']['path']][ref['offset']:ref['offset']+ref['length']]
                if original != raw:
                    raise AssertionError('fixture operation differs from actual generated request/response')
                offset = ref['offset']
            else:
                offset = self.offsets[stream]
            slices.append(wire.WireSlice(stream, offset, len(raw)))
            self.offsets[stream] = offset+len(raw)+1  # reserve independent ACK byte
        finish = op['finished_ns'] if self.template else self.stamp+1
        result = a.PhysicalReadReceipt(intent.request_id, self.session.binding.transport_identity,
            self.session.binding.admission_epoch, self.seq, *slices, request, response, payload, data,
            self.stamp, finish, 'ok')
        self.stamp = finish+1
        self.grants.append(grant); self.receipts.append(result)
        return replace(result, **changes)

    def step(self, **receipt_changes):
        grant = self.session.next_request()
        if type(grant) is a.ReadsComplete:
            return grant
        receipt = self.receipt(grant, **receipt_changes)
        self.session.accept(grant, receipt)
        return grant

    def complete(self):
        for _ in range(512):
            value = self.step()
            if type(value) is a.ReadsComplete:
                return value
        raise AssertionError('bounded planner did not finish')


class AcquisitionControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if a is None:
            return
        cls.tmp = tempfile.TemporaryDirectory(prefix='pure-acquisition-')
        cls.report, _, cls.blobs, cls.host, _ = full_fixture(Path(cls.tmp.name),
            capture.VAPIC_OFF_INVOCATION_PROFILE)
        cls.prior = token.validate_prior_entry(cls.report['profile_ref'],
            cls.report['prior_admission_ref'], cls.report['profile_mapping_ref'], cls.blobs)
        cls.pinned = cls.blobs['efi']
        host = json.loads(cls.blobs['host-report.json'])
        cls.host_record = host
        cls.control = json.loads(cls.blobs[host['control_ref']['path']])
        cls.replay = d.validate_c0_rsp(cls.control, cls.blobs)

    @classmethod
    def tearDownClass(cls):
        if a is not None:
            cls.tmp.cleanup()

    def setUp(self):
        self.assertIsNotNone(a, 'typed current-binding driver is absent: expected gate-first RED')

    def operation_slices(self, seqs):
        rows = {row['seq']: row for row in self.control['operations']}
        def segment(value):
            return None if value is None else (frozen_ref(value['blob']), value['offset'], value['length'])
        return tuple((seq, segment(rows[seq]['request']), segment(rows[seq]['response'])) for seq in seqs)

    def binding(self, **changes):
        cp, regs = self.report['checkpoint'], self.replay['before_registers']
        identity = object()
        stop_stamp = self.replay['stop_event']['received_ns']
        stop = wire.EntryStop(identity, self.prior.entry_address, 23, 24, 1, 25, stop_stamp)
        status = next(row for row in self.control['operations'] if row['seq'] == 56)
        confirmed = wire.ConfirmedEntryStop(stop, 56, status['finished_ns'])
        names = a.REF_NAMES
        values = (cp['stop_ref'], cp['registers_before_ref'], cp['hmp_before_ref'],
                  cp['layout_before_ref'], self.host_record['reads_ref'], self.host_record['abi_ref'],
                  self.host_record['source_ref'], self.host_record['source_ref'],
                  self.host_record['control_ref'], self.host_record['control_ref'])
        result = fixture_value(a.CurrentC0RamBinding, origin='synthetic_fixture', prior=self.prior,
            confirmed_stop=confirmed, wire_identity=identity, transport_identity=('fixture-only', 7, 11),
            admission_epoch=1, physical_mode=1, run_id='witness', profile_ref=self.prior.profile_ref,
            profile_sha256=self.prior.probe_profile_sha256, invocation_profile=self.prior.invocation_profile,
            owner_identity=(123, 456, 123), cpu=0, thread='01',
            pinned_efi_ref=raw_ref('efi', self.pinned), state=tuple(mode().items()),
            registers=tuple((n, w, regs[n], seq) for (n, w), seq in
                            zip(a.REGISTER_WIDTHS, self.replay['before_sequences'])),
            hmp_raw=self.blobs[cp['hmp_before_ref']['path']],
            layout_raw=self.blobs[cp['layout_before_ref']['path']],
            ranges=d._layout(self.blobs[cp['layout_before_ref']['path']]),
            proof_prefix=tuple(zip(a.PROOF_NAMES, (23, 24, 25, 56, 26, 57, 62, 64))),
            evidence_refs=tuple((name, frozen_ref(value)) for name, value in zip(names, values)),
            raw_operation_slices=self.operation_slices(tuple(sorted((23,24,25,56,26,57,62,64,
                *self.replay['before_sequences'])))),
            stop_event_slice=(frozen_ref(self.replay['stop_event']['wire']['blob']),
                self.replay['stop_event']['wire']['offset'], self.replay['stop_event']['wire']['length']),
            host_read_sizes=(8,)*12+(4,)*2, stop_ns=stop_stamp,
            vm_deadline_ns=stop_stamp+80_000_000_000,
            stop_deadline_ns=stop_stamp+60_000_000_000)
        return fixture_value(type(result), result, **changes)

    def memory(self, four_k=False):
        cp = self.report['checkpoint']
        memory = {}
        for row in cp['tables']:
            raw = self.blobs[row['first_ref']['path']]
            if four_k and row['physical'] == 0x3000:
                raw = frame({1: 0x4007})
            memory.update((row['physical']+i, b) for i, b in enumerate(raw))
        if four_k:
            raw = frame({n: 0x200000+n*4096+7 for n in range(512)})
            memory.update((0x4000+i, b) for i, b in enumerate(raw))
        for row in cp['objects']:
            memory.update((row['virtual']+i, b) for i, b in enumerate(self.blobs[row['first_ref']['path']]))
        return memory

    def session(self, binding=None, ledger=None, pinned=None):
        return a.AcquisitionSession(self.prior, self.pinned if pinned is None else pinned,
            self.binding() if binding is None else binding,
            a.AcquisitionLedger() if ledger is None else ledger)

    def after(self, session, last_seq=None, **changes):
        cp = self.report['checkpoint']
        actual = last_seq is None and session._last_seq == 92
        seqs = self.replay['after_sequences'] if actual else tuple(range(
            session._last_seq+1 if last_seq is None else last_seq+1,
            (session._last_seq if last_seq is None else last_seq)+30))
        result = fixture_value(a.AfterC0Binding, binding=session.binding, state=session.binding.state,
            registers=tuple((n, w, self.replay['after_registers'][n], seq)
                            for (n, w), seq in zip(a.REGISTER_WIDTHS, seqs)),
            hmp_raw=session.binding.hmp_raw, layout_raw=session.binding.layout_raw,
            hmp_seq=seqs[-1]+2, layout_seq=seqs[-1]+3,
            finished_ns=session.binding.stop_ns+50_000_000_000,
            evidence_refs=tuple((name, frozen_ref(cp[name+'_ref']))
                for name in ('registers_after', 'hmp_after', 'layout_after')),
            raw_operation_slices=(self.operation_slices((*seqs, seqs[-1]+2, seqs[-1]+3)) if actual
                else tuple((seq, (raw_ref(f'after-{seq}-request.bin', b'$p#00'), 0, 5),
                            (raw_ref(f'after-{seq}-response.bin', b'$0#30'), 0, 5))
                           for seq in (*seqs, seqs[-1]+2, seqs[-1]+3))))
        return fixture_value(type(result), result, **changes)

    def reject(self, reason, function, *args, status=None, **kwargs):
        with self.assertRaises(d.C0DecodeError) as failure:
            function(*args, **kwargs)
        self.assertIn(reason, failure.exception.reason)
        if status is not None:
            self.assertEqual(failure.exception.status, status)
        return failure.exception

    def test_ac01_current_binding_required_before_any_requests(self):
        for binding in (None, self.prior, self.host, {}, object(), object.__new__(a.CurrentC0RamBinding)):
            self.reject('current_binding', a.AcquisitionSession, self.prior, self.pinned, binding,
                        a.AcquisitionLedger())
        for cls in (a.CurrentC0RamBinding, a.AfterC0Binding, a.RamReadGrant,
                    a.AdmittedPhysicalRead, a.ReadsComplete, a.AcquiredC0Snapshot):
            with self.assertRaises(TypeError):
                cls(admitted=True)
        self.reject('runtime_binding_required', a.require_runtime_binding, self.binding())

    def test_ac02_native_immutable_binding_rejects_mismatches(self):
        for changes, reason in (({'profile_sha256': '0'*64}, 'profile_identity'),
                ({'profile_ref': ('elsewhere', '0'*64, 0)}, 'profile_identity'),
                ({'invocation_profile': capture.INVOCATION_PROFILE}, 'profile_identity'),
                ({'run_id': ''}, 'run_id'), ({'owner_identity': (0, 1, 2)}, 'owner_identity'),
                ({'cpu': True}, 'cpu_thread'), ({'thread': '02'}, 'cpu_thread'),
                ({'physical_mode': 0}, 'physical_mode'), ({'admission_epoch': True}, 'integer'),
                ({'ranges': ((0, 0x1000),)}, 'layout_identity'),
                ({'pinned_efi_ref': raw_ref('efi', b'other')}, 'pinned_efi'),
                ({'state': tuple(mode(a20=0).items())}, 'mode_unsupported'),
                ({'stop_deadline_ns': 1}, 'stop_deadline'),
                ({'host_read_sizes': (8,)*14}, 'host_read_accounting')):
            with self.subTest(changes=changes):
                self.reject(reason, self.session, self.binding(**changes))
        b = self.binding()
        self.reject('stop_session', self.session, fixture_value(type(b), b, wire_identity=object()))
        other_stop = replace(b.confirmed_stop, stop=replace(b.confirmed_stop.stop, entry_address=0x1234))
        self.reject('stop_candidate', self.session, fixture_value(type(b), b, confirmed_stop=other_stop))
        regs = list(b.registers); regs[16] = (*regs[16][:2], self.prior.entry_address+1, regs[16][3])
        self.reject('stopped_rip', self.session, fixture_value(type(b), b, registers=tuple(regs)))
        for malformed in (b.registers[:-1], ((0, 4, 0, 27),)+b.registers[1:]):
            self.reject('register', self.session, fixture_value(type(b), b, registers=malformed))
        self.reject('pinned_efi', self.session, b, pinned=bytearray(self.pinned))
        with self.assertRaises(FrozenInstanceError):
            b.physical_mode = 1
        s = self.session()
        self.reject('ledger_owner', self.session, ledger=s.ledger)

    def test_ac02_proxy_rejection_does_not_call_user_code(self):
        calls = []
        class Callback(tuple):
            def __iter__(self):
                calls.append('iter'); raise AssertionError('callback')
            def __eq__(self, other):
                calls.append('eq'); raise AssertionError('callback')
        for field in ('profile_ref', 'state', 'registers', 'transport_identity', 'ranges', 'raw_operation_slices', 'stop_event_slice'):
            b = self.binding()
            self.reject('', self.session, fixture_value(type(b), b, **{field: Callback(getattr(b, field))}))
        self.assertEqual(calls, [])

    def test_ac02_raw_slice_inventory_identity_bounds_and_reuse(self):
        b = self.binding()
        rows = b.raw_operation_slices
        for malformed, reason in ((rows[:-1], 'operation_slices'),
                (((999, *rows[0][1:]), *rows[1:]), 'slice_identity'),
                (((rows[0][0], rows[0][1], None), *rows[1:]), 'response_missing'),
                (((rows[0][0], (rows[0][1][0], 1 << 40, 1), rows[0][2]), *rows[1:]), 'slice_bounds'),
                (((rows[0][0], rows[1][1], rows[0][2]), *rows[1:]), 'slice_reuse')):
            self.reject(reason, self.session, fixture_value(type(b), b, raw_operation_slices=malformed))
        s = self.session(); Harness(s, self.memory()).complete()
        after = self.after(s)
        self.reject('operation_slices', s.finish,
            fixture_value(type(after), after, raw_operation_slices=after.raw_operation_slices[:-1]))

    def test_ac03_identity_single_use_and_pending_sequence(self):
        for variant in ('clone', 'epoch', 'transport', 'sequence', 'double_consume', 'before_consume'):
            with self.subTest(variant=variant):
                s = self.session(); h = Harness(s, self.memory()); g = s.next_request()
                if variant == 'clone':
                    self.reject('grant_identity', s.consume_for_dispatch,
                        fixture_value(type(g), g), s.binding.transport_identity, 1, 65, h.stamp)
                elif variant == 'epoch':
                    self.reject('stale_epoch', s.consume_for_dispatch, g,
                                s.binding.transport_identity, 2, 65, h.stamp)
                elif variant == 'transport':
                    self.reject('transport_mismatch', s.consume_for_dispatch, g, ('foreign', 7, 11), 1, 65, h.stamp)
                elif variant == 'sequence':
                    receipt = h.receipt(g)
                    self.reject('receipt_identity', s.accept, g, replace(receipt, operation_seq=66))
                elif variant == 'before_consume':
                    receipt = a.PhysicalReadReceipt(1, (), 1, 65, None, None, b'', b'', b'', b'', 0, 1, 'ok')
                    self.reject('receipt_pending', s.accept, g, receipt)
                else:
                    h.receipt(g)
                    self.reject('grant_consumed', s.consume_for_dispatch, g,
                                s.binding.transport_identity, 1, 65, h.stamp)
                first = s.failure
                self.reject(first.reason, s.next_request)
                self.assertIs(s.failure, first)
        s = self.session(); h = Harness(s, self.memory()); old = h.step(); new = s.next_request()
        self.reject('receipt_pending', s.accept, old, h.receipts[0])
        self.assertIs(s.pending, new)

    def test_ac04_final_check_after_reservation_prevents_send(self):
        for change in ('deadline', 'cancellation', 'foreign_operation', 'mode_change', 'reconnect'):
            s = self.session(); g = s.next_request(); sent = []
            # Simulate pending row/output reservation then a potentially blocking wait.
            pending = 65
            now = s.binding.stop_ns+1
            if change == 'deadline':
                now = s.binding.stop_deadline_ns
            else:
                s.abort(wire.Failure('INCOMPLETE', change))
            with self.assertRaises(d.C0DecodeError):
                admitted = s.consume_for_dispatch(g, s.binding.transport_identity, 1, pending, now)
                sent.append(admitted.request_bytes)
            self.assertEqual(sent, [])
        # A fresh independent stopped session remains usable after an abort.
        self.assertIsInstance(Harness(self.session(), self.memory()).step(), a.RamReadGrant)

    def test_ac04_consumed_failures_never_retry_or_refund(self):
        for changes, reason in (({'result': 'timeout'}, 'read_failed'),
                ({'response_payload': b'00'}, 'response_hex'),
                ({'response_payload': b' '*4096}, 'response_hex'),
                ({'request_bytes': b'$m1000,0800#00'}, 'request_bytes'),
                ({'response_slice': wire.WireSlice('rsp', 0, 1)}, 'response_slice')):
            s = self.session(); h = Harness(s, self.memory()); g = s.next_request()
            charges = dict(s.ledger.values); receipt = h.receipt(g, **changes)
            error = self.reject(reason, s.accept, g, receipt)
            s.abort(d.C0DecodeError('DENY', 'later'))
            self.assertEqual(s.failure.reason, error.reason)
            self.assertEqual(dict(s.ledger.values), charges)
            self.reject(error.reason, s.next_request)
        for mutate, reason in ((lambda r: replace(r, data=b'\0'*2047), 'response_data'),
                               (lambda r: replace(r, response_bytes=r.response_bytes[:-1]+b'z'), 'rsp_checksum')):
            s = self.session(); h = Harness(s, self.memory()); g = s.next_request()
            self.reject(reason, s.accept, g, mutate(h.receipt(g)))
        s = self.session(); h = Harness(s, self.memory()); h.step(); g = s.next_request()
        receipt = h.receipt(g)
        self.reject('response_slice', s.accept, g,
            replace(receipt, response_slice=h.receipts[0].response_slice))

    def test_ac05_whole_frame_rejected_before_chunks_or_cache(self):
        for cut in (0x1800, 0x1fff):
            s = self.session()
            # Root is already checked at construction. Model a later denied child.
            s._guard.ranges = ((0, 0x2000+cut-0x1000), (0x3000, 0x20000000))
            h = Harness(s, self.memory()); h.step()
            self.reject('ram_hole', h.step)
            self.assertEqual(len(h.grants), 2)
            self.reject('ram_hole', s.next_request)
        s = self.session(); s._guard.ranges = ((0x1000, 0x1800),)
        self.reject('ram_backing', s.next_request)
        self.assertEqual(s.ledger.values['frames'], 0)

    def test_ac05_malformed_parent_stops_before_child_demand(self):
        for value, reason in ((0, 'unmapped'), (0x2087, 'entry_reserved'), (0x1007, 'frame_level')):
            s = self.session(); memory = self.memory()
            memory.update((0x1000+i, byte) for i, byte in enumerate(frame({0: value})))
            h = Harness(s, memory); h.step()
            self.reject(reason, h.step)
            self.assertEqual(len(h.grants), 2)
            self.assertEqual(s.ledger.values['frames'], 1)
        s = self.session(); memory = self.memory()
        memory.update((0x2000+i, byte) for i, byte in enumerate(frame({0: 0x87})))
        h = Harness(s, memory); h.step(); h.step(); h.step()
        self.reject('one_gib_unsupported', h.step, status='INCOMPLETE')
        self.assertEqual(s.ledger.values['frames'], 2)

    def test_ac06_fixed_objects_shared_graph_and_exact_schedule(self):
        for four_k in (False, True):
            s = self.session(); h = Harness(s, self.memory(four_k))
            with patch.object(d._Walker, 'translate', side_effect=AssertionError('synchronous walk')):
                complete = h.complete()
            self.assertIsInstance(complete, a.ReadsComplete)
            first = [g.intent for g in h.grants if g.intent.pass_number == 0]
            objects = [row for row in first if row.role != 'frame']
            self.assertEqual([row.role for row in objects], ['pe_header']*4+[
                'entry_code', 'system_table', 'boot_services', 'get_memory_map_code'])
            self.assertEqual([row.virtual for row in objects], [row['virtual'] for row in self.report['checkpoint']['objects']])
            self.assertNotIn(self.replay['before_registers'][2], [row.virtual for row in first])
            self.assertEqual(s.ledger.values['frames'], 4 if four_k else 3)
            first_mem = [(row.role, row.physical, row.length) for row in first]
            again = [(g.intent.role, g.intent.physical, g.intent.length) for g in h.grants if g.intent.pass_number == 1]
            self.assertEqual(again, first_mem)
            snapshot = s.finish(self.after(s))
            self.assertEqual(snapshot.origin, 'synthetic_fixture')
            self.assertFalse(snapshot.record['atomic_snapshot'])
            self.assertFalse(hasattr(snapshot, 'final_status'))
            self.replay_snapshot(snapshot)

    def replay_snapshot(self, snapshot):
        cp = snapshot.export_record()
        replay = {'before_registers': self.replay['before_registers'], 'operations': {}}
        for row in snapshot.receipts:
            replay['operations'][row.operation_seq] = {'operation': 'physical_read',
                'request_payload': d._rsp_tokens(row.request_bytes)[0].payload,
                'response_payload': row.response_payload, 'started_ns': row.started_ns,
                'finished_ns': row.finished_ns}
        values, translations = d._decode_objects(cp, d._Blobs(dict(snapshot.blobs)), replay,
            mode(), self.binding().ranges, self.pinned,
            {'loaded_base': self.prior.loaded_base, 'entry_address': self.prior.entry_address})
        self.assertEqual(values['get_memory_map'], 0x212003)
        self.assertEqual(len(translations), len(cp['translations']))
        return cp

    def test_ac06_backing_boundary_split_frozen_before_object_data(self):
        b = self.binding()
        layout = b.layout_raw.replace(
            b'0000000000000000-000000001fffffff (prio 0, ram): pc.ram',
            b'0000000000000000-000000000020001f (prio 0, ram): pc.ram\n'
            b'  0000000000200020-000000001fffffff (prio 0, ram): pc.ram @0000000000200020')
        refs = tuple((n, raw_ref('split-layout.txt', layout) if n == 'layout_before' else r)
                     for n, r in b.evidence_refs)
        b = fixture_value(type(b), b, layout_raw=layout, ranges=d._layout(layout), evidence_refs=refs)
        s = self.session(b); h = Harness(s, self.memory())
        for _ in range(6):
            h.step()
        g = s.next_request()
        self.assertEqual(g.intent.length, 32)
        self.assertEqual(len(s._objects[0]['parts']), 2)
        self.assertEqual([p['length'] for p, _ in s._objects[0]['parts']], [32, 32])
        h.session.accept(g, h.receipt(g))
        self.assertEqual(s.next_request().intent.length, 32)

    def test_ac07_no_partial_pointer_chase_or_new_recheck_walk(self):
        s = self.session(); h = Harness(s, self.memory())
        while True:
            g = s.next_request()
            if g.intent.role == 'system_table':
                break
            s.accept(g, h.receipt(g))
        self.assertIsNone(s._boot)
        bad = bytearray(bytes(h.memory[g.intent.physical+i] for i in range(g.intent.length)))
        bad[96:104] = (0xdeadbeef).to_bytes(8, 'little')
        self.reject('efi_crc', s.accept, g, h.receipt(g, data=bytes(bad)))
        self.assertEqual(len(s._objects), 6)
        # Rechecks retain their original graph and parse no pointers again.
        s = self.session(); h = Harness(s, self.memory())
        while True:
            g = s.next_request()
            if g.intent.pass_number == 1:
                break
            s.accept(g, h.receipt(g))
        frozen = tuple(s._frozen_frames)
        with patch.object(a, 'PageWalk', side_effect=AssertionError('recheck walk')), \
             patch.object(d, '_efi', side_effect=AssertionError('recheck pointer chase')):
            s.accept(g, h.receipt(g)); h.complete()
        self.assertEqual(frozen, tuple(s._frames))

    def test_ac06_entire_canonical_object_translates_before_any_data(self):
        from test_run0_c0_decode import synthetic_c0_hmp
        b = self.binding()
        regs = list(b.registers)
        regs[3] = (*regs[3][:2], 0x213ff8, regs[3][3])
        values = {row[0]: row[2] for row in regs}
        hmp = synthetic_c0_hmp(values).encode()
        refs = tuple((n, raw_ref('cross-page-hmp.txt', hmp) if n == 'hmp_before' else r)
                     for n, r in b.evidence_refs)
        b = fixture_value(type(b), b, registers=tuple(regs), hmp_raw=hmp, evidence_refs=refs)
        s = self.session(b); memory = self.memory(four_k=True)
        # SystemTable spans pages 0x213000/0x214000. Deny the second mapping.
        memory.update((0x4000+20*8+i, 0) for i in range(8))
        h = Harness(s, memory)
        self.reject('unmapped', h.complete, status='INCOMPLETE')
        self.assertNotIn('system_table', [g.intent.role for g in h.grants])
        self.assertEqual(len(s._objects), 5)
        self.assertIsNone(s._boot)

    def test_ac07_changed_frame_or_object_stops_on_completing_receipt(self):
        for role in ('frame', 'system_table', 'boot_services'):
            s = self.session(); h = Harness(s, self.memory())
            while True:
                g = s.next_request()
                if g.intent.pass_number == 1 and g.intent.role == role:
                    if role == 'frame' and g.intent.physical % 4096 == 0:
                        s.accept(g, h.receipt(g)); g = s.next_request()
                    break
                s.accept(g, h.receipt(g))
            data = bytearray(h.memory[g.intent.physical+i] for i in range(g.intent.length)); data[-1] ^= 1
            error = self.reject('frame_changed' if role == 'frame' else 'object_changed',
                s.accept, g, h.receipt(g, data=bytes(data)), status='INCOMPLETE')
            count = len(h.grants)
            self.reject(error.reason, s.next_request)
            self.assertEqual(len(h.grants), count)

    def test_ac08_after_binding_exact_identity_raw_state_and_deadline(self):
        for field, value, reason in (('binding', self.binding(), 'after_binding'),
                ('state', tuple(mode(cr3=0x2000).items()), 'state_changed'),
                ('layout_raw', b'invalid', 'bracket_changed'),
                ('finished_ns', 1, 'after_deadline')):
            s = self.session(); h = Harness(s, self.memory()); h.complete()
            self.reject(reason, s.finish, self.after(s, **{field: value}))
        s = self.session()
        self.reject('reads_incomplete', s.finish, {})
        s = self.session(); Harness(s, self.memory()).complete()
        self.reject('after_binding', s.finish, {'admitted': True})
        s = self.session(); Harness(s, self.memory()).complete()
        snapshot = s.finish(self.after(s))
        self.reject('already_finished', s.finish, self.after(s))
        exported = snapshot.export_record(); exported['objects'].clear()
        self.assertEqual(len(snapshot.record['objects']), 8)

    def test_ac08_completion_singleton_rechecks_original_stop_before_after_queries(self):
        for change, reason in (('clone', 'completion_identity'), ('transport', 'transport_mismatch'),
                               ('epoch', 'stale_epoch'), ('deadline', 'deadline'),
                               ('cancelled', 'cancelled')):
            s = self.session(); receipt = Harness(s, self.memory()).complete()
            self.assertIs(s.next_request(), receipt)
            transport, epoch, now = s.binding.transport_identity, 1, s._receipts[-1].finished_ns
            self.assertIs(s.require_reads_complete(receipt, transport, epoch, now), s.binding)
            if change == 'clone':
                receipt = fixture_value(type(receipt), receipt)
            elif change == 'transport':
                transport = ('foreign', 7, 11)
            elif change == 'epoch':
                epoch = 2
            elif change == 'deadline':
                now = s.binding.stop_deadline_ns
            else:
                s.abort(wire.Failure('INCOMPLETE', 'cancelled'))
            sent = []
            with self.assertRaises(d.C0DecodeError) as failure:
                s.require_reads_complete(receipt, transport, epoch, now)
                sent.append(b'p0')
            self.assertIn(reason, failure.exception.reason)
            self.assertEqual(sent, [])
        s = self.session()
        self.reject('completion_identity', s.require_reads_complete, {},
                    s.binding.transport_identity, 1, s.binding.stop_ns+1)

    def test_ac09_shared_limits_boundary_atomic_no_growth_and_tail_reserve(self):
        self.assertEqual(a.OPERATION_RESERVE, 33)
        for name, maximum in d.LIMITS.items():
            maximum -= a.OPERATION_RESERVE if name == 'operations' else (
                a.STORAGE_RESERVE if name == 'retained_bytes' else 0)
            ledger = a.AcquisitionLedger()
            ledger.reserve(**{name: maximum})
            before = dict(ledger.values)
            self.reject(name+'_limit', ledger.reserve, **{name: 1}, status='INCOMPLETE')
            self.assertEqual(dict(ledger.values), before)
        ledger = a.AcquisitionLedger((('frames', 31),))
        self.reject('frames_limit', ledger.reserve, frames=2, objects=1)
        self.assertEqual(ledger.values['objects'], 0)
        # Existing traffic counts against the same limit, with no fresh allowance.
        for name, used in (('frames', 32), ('objects', 32), ('translations', 128),
                           ('operations', 512-33), ('other_bytes', 65536),
                           ('retained_bytes', (32 << 20)-a.STORAGE_RESERVE)):
            ledger = a.AcquisitionLedger(((name, used),))
            s = self.session(ledger=ledger)
            self.reject(name+'_limit', s.next_request, status='INCOMPLETE')
            self.assertEqual(len(s._frames), 0)
        s = self.session(); Harness(s, self.memory()).complete()
        self.assertEqual(s.ledger.values['objects'], 8)
        self.assertEqual(s.ledger.values['operations'], 28)
        self.assertEqual(s.ledger.values['other_bytes'], 2*sum(
            row['length'] for row in self.report['checkpoint']['objects']))

    def test_ac10_actual_receipts_replay_unchanged_full_synthetic_envelope(self):
        s = self.session()
        template = {row['seq']: row for row in self.control['operations']}
        h = Harness(s, self.memory(), template, self.blobs)
        h.complete(); snapshot = s.finish(self.after(s))
        checkpoint = self.replay_snapshot(snapshot)
        report, blobs = copy.deepcopy(self.report), dict(self.blobs)
        report['checkpoint'] = checkpoint
        blobs.update(snapshot.blobs)
        raw = json.dumps(report, sort_keys=True, separators=(',', ':')).encode()
        ref = d._ref(dict(zip(('path', 'sha256', 'length'), raw_ref('acquired-report.json', raw))), d.REPORT_LIMIT)
        blobs[ref['path']] = raw
        decoded = d.decode_c0('synthetic_fixture', ref, blobs, self.host)
        self.assertEqual(decoded['status'], 'PASS', decoded)
        # The full fixture replay is still explicitly synthetic.
        runtime = d.decode_c0('retained_runtime', ref, blobs, self.host)
        self.assertNotEqual(runtime['status'], 'PASS')
        self.assertEqual(len(snapshot.receipts), 28)
        self.assertEqual(len({(r.response_slice.offset, r.response_slice.length)
                              for r in snapshot.receipts}), 28)


if __name__ == '__main__':
    unittest.main()
