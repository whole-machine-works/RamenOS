"""Synthetic parent accounting controls; these issue no RAM authority."""
from dataclasses import replace
import time
import unittest

from boot_profile_capture import ProbeError

try:
    import run0_call_budget as b
    import run0_call_read as r
except ModuleNotFoundError as error:
    if error.name not in ('run0_call_budget', 'run0_call_read'):
        raise
    b = r = None


def memory_ledger(epoch='C0'):
    ledger = b.ParentAccounting(time.monotonic_ns())
    for current in ('C0', 'C1', 'C2'):
        for name in b.BEFORE[current]:
            ledger.reserve_operation(current, name)
        if current == epoch:
            return ledger
        for name in b.AFTER[current]:
            ledger.reserve_operation(current, name)


def frame_charges(physical=0x2000, ordinal=0):
    return tuple(b.ReadCharge.for_target(r.ReadTarget('frame', p, ordinal, off,
                                                     physical+off, 2048))
                 for p in (0, 1) for off in (0, 2048))


class ParentBudgetTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(b, 'parent budget implementation is required')

    def test_fixed_control_suffix_and_phase_costs(self):
        self.assertEqual(tuple(map(len, (b.BEFORE['C0'], b.BEFORE['C1'], b.BEFORE['C2']))),
                         (45, 43, 43))
        self.assertEqual(tuple(map(len, (b.AFTER['C0'], b.AFTER['C1'], b.AFTER['C2']))),
                         (34, 34, 33))
        self.assertEqual(sum(map(len, b.BEFORE.values()))+sum(map(len, b.AFTER.values())), 232)
        for epoch, suffix in zip(('C0', 'C1', 'C2'), (187, 110, 33)):
            self.assertEqual(memory_ledger(epoch).view()['remaining_controls'], suffix)

    def test_batch_extra_data_and_metadata_credit_is_atomic(self):
        ledger = memory_ledger()
        charges = frame_charges()
        required = sum(8*x.target.length+2048+2*x.target.length+
                       x.packet_copy_bound+x.metadata_bound for x in charges)
        ledger.reserve_output(b.REGULAR_BYTES-required+1)
        before = dict(ledger.view())
        with self.assertRaises(ProbeError):
            ledger.reserve_reads('C0', charges)
        self.assertEqual(dict(ledger.view()), before)
        fresh = memory_ledger()
        batch = fresh.reserve_reads('C0', charges)
        self.assertIs(type(batch), b.ReadBatchReservation)
        self.assertEqual(fresh.view()['committed_bytes'], required)

    def test_exact_slot_claim_once_and_no_operation_double_count(self):
        ledger = memory_ledger()
        batch = ledger.reserve_reads('C0', frame_charges())
        reserved = ledger.view()['committed_operations']
        key = r.ReadKey('C0', 1, 0, ledger.view()['actual_operations']+1)
        ledger._claim(batch, 0, key, batch.charges[0].target)
        self.assertEqual(ledger.view()['committed_operations'], reserved)
        with self.assertRaises(ProbeError):
            ledger._claim(batch, 0, key, batch.charges[0].target)

    def test_credit_never_borrows_or_refunds(self):
        ledger = memory_ledger()
        batch = ledger.reserve_reads('C0', frame_charges())
        key = r.ReadKey('C0', 1, 0, 46)
        ledger._claim(batch, 0, key, batch.charges[0].target)
        ledger.debit_read(batch, key, 2048, purpose='decoded_file')
        before = dict(ledger.view())
        with self.assertRaises(ProbeError):
            ledger.debit_read(batch, key, 1, purpose='decoded_file')
        self.assertEqual(dict(ledger.view()), before)
        with self.assertRaises(ProbeError):
            ledger.debit_read(batch, replace(key, request_id=2, physical_ordinal=1), 1,
                              purpose='metadata')

    def test_unfinished_reserved_reads_block_tail(self):
        ledger = memory_ledger()
        ledger.reserve_reads('C0', frame_charges())
        with self.assertRaises(ProbeError):
            ledger.reserve_operation('C0', b.AFTER['C0'][0])

    def test_wrong_control_and_epoch_cannot_change_counters(self):
        ledger = memory_ledger()
        before = dict(ledger.view())
        for epoch, name in [('C1', b.AFTER['C0'][0]), ('C0', 'quit'), ('C0', 'm')]:
            with self.assertRaises(ProbeError):
                ledger.reserve_operation(epoch, name)
            self.assertEqual(dict(ledger.view()), before)

    def test_complete_frozen_read_plan_required(self):
        ledger = memory_ledger()
        for charges in (frame_charges()[:1], frame_charges()[:-1]):
            with self.assertRaises(ProbeError):
                ledger.reserve_reads('C0', charges)
        with self.assertRaises(ProbeError):
            replace(frame_charges()[0], metadata_bound=1)
        self.assertEqual(ledger.view()['physical_reserved'], 0)

    def test_frames_and_parts_are_phase_bounded(self):
        ledger = memory_ledger()
        all_frames = tuple(c for ordinal in range(32) for c in frame_charges(ordinal=ordinal))
        ledger.reserve_reads('C0', all_frames)
        with self.assertRaises(ProbeError):
            ledger.reserve_reads('C0', frame_charges(ordinal=32))
        with self.assertRaises(ProbeError):
            ledger.reserve_reads('C0', frame_charges(ordinal=0))

    def test_terminal_reserves_are_cumulative_and_separate(self):
        ledger = memory_ledger()
        ledger.reserve_output(b.REGULAR_BYTES)
        ledger.redeem_terminal(12, purpose='report')
        ledger.redeem_terminal(b.REPORT_BYTES-12, purpose='report')
        with self.assertRaises(ProbeError):
            ledger.redeem_terminal(1, purpose='report')
        ledger.redeem_terminal(b.FAILURE_BYTES, purpose='failure')
        self.assertEqual(ledger.view()['actual_bytes'], b.MAX_BYTES)

    def test_strict_scalars_and_no_generic_reserve_allowance(self):
        ledger = memory_ledger()
        for value in (True, -1, 1.0):
            with self.assertRaises(ProbeError):
                ledger.reserve_output(value)
        with self.assertRaises(ProbeError):
            ledger.reserve_output(1, purpose='read')
        with self.assertRaises(TypeError):
            b.ReadBatchReservation()

    def test_full_map_first_and_recheck_reservation_precedes_any_claim(self):
        ledger = memory_ledger('C2')
        charges = tuple(b.ReadCharge.for_target(r.ReadTarget('object', p, 6, i*2048,
                                                           0x30000+i*2048, 2048))
                        for p in (0, 1) for i in range(16))
        batch = ledger.reserve_reads('C2', charges)
        self.assertEqual(ledger.view()['physical_claimed'], 0)
        self.assertEqual(ledger.view()['physical_reserved'], 32)
        self.assertEqual(ledger.view()['first_parts'], (0, 0, 16))
        with self.assertRaises(ProbeError):
            ledger._claim(batch, 31, r.ReadKey('C2', 1, 0, ledger.view()['actual_operations']+1),
                          charges[31].target)
        ledger._claim(batch, 0, r.ReadKey('C2', 1, 0, ledger.view()['actual_operations']+1),
                      charges[0].target)
        self.assertEqual(ledger.view()['physical_claimed'], 1)

    def test_bootstrap_is_charged_without_empirical_B_allowance(self):
        ledger = b.ParentAccounting(time.monotonic_ns())
        ledger.reserve_operation('C0', 'bootstrap:qmp_capabilities')
        self.assertEqual(ledger.view()['actual_operations'], 1)
        self.assertEqual(ledger.view()['committed_operations'], 233)
        ledger.reserve_operation('C0', b.BEFORE['C0'][0])
        with self.assertRaises(ProbeError):
            ledger.reserve_operation('C0', 'bootstrap:target_read')

    def test_global_and_phase_limits_fail_before_counter_growth(self):
        ledger = memory_ledger()
        ledger._operations = 1024-ledger.view()['remaining_controls']
        before = dict(ledger.view())
        with self.assertRaises(ProbeError):
            ledger.reserve_reads('C0', frame_charges())
        self.assertEqual(dict(ledger.view()), before)
        fresh = memory_ledger()
        fresh._phase_ops[0] = 512-len(b.AFTER['C0'])
        before = dict(fresh.view())
        with self.assertRaises(ProbeError):
            fresh.reserve_reads('C0', frame_charges())
        self.assertEqual(dict(fresh.view()), before)

    def test_frame_halves_must_share_one_physical_base(self):
        ledger = memory_ledger()
        charges = tuple(b.ReadCharge.for_target(replace(charge.target,
            gpa=charge.target.gpa+0x1000 if charge.target.logical_offset else charge.target.gpa))
            for charge in frame_charges())
        before = dict(ledger.view())
        with self.assertRaises(ProbeError):
            ledger.reserve_reads('C0', charges)
        self.assertEqual(dict(ledger.view()), before)

    def test_eighteen_map_parts_refused_atomically(self):
        ledger = memory_ledger('C2')
        lengths = (1, 1)+(2048,)*15+(2046,)
        targets = []
        for p in (0, 1):
            offset = 0
            for length in lengths:
                targets.append(r.ReadTarget('object', p, 6, offset, 0x3fff+offset, length))
                offset += length
        before = dict(ledger.view())
        with self.assertRaises(ProbeError):
            ledger.reserve_reads('C2', tuple(b.ReadCharge.for_target(t) for t in targets))
        self.assertEqual(dict(ledger.view()), before)

    def test_copy_plan_covers_full_codec_decode_generation_and_files(self):
        for gpa, length in ((0, 1), (0x2000, 2048), ((1 << 64)-1, 1)):
            target = r.ReadTarget('object', 0, 0, 0, gpa, length)
            phases = dict((name, sum(size for _, size in copies))
                          for name, copies in r._verification_copy_plan(target))
            q = len(f'm{gpa:x},{length:x}')
            self.assertEqual(phases['codec'], 2*(2*length+4)+3*(2*length)+2)
            self.assertEqual(phases['hex_decode'], 3*length)
            self.assertEqual(phases['payload_comparison'], 2*length)
            self.assertEqual(phases['packet_files'], q+4+2*length+4)
            self.assertEqual(r.packet_copy_bound(target), sum(phases.values()))


if __name__ == '__main__':
    unittest.main()
