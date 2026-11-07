"""Synthetic parent accounting controls; these issue no RAM authority."""
from dataclasses import replace
import time
import unittest
from unittest.mock import patch

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


def map_charges(lengths, physical=0x800000):
    targets = []
    for pass_index in (0, 1):
        offset = 0
        for length in lengths:
            targets.append(r.ReadTarget('object', pass_index, 6, offset,
                                        physical+offset, length))
            offset += length
    return tuple(b.ReadCharge.for_target(target) for target in targets)


def claim_all(ledger, batch):
    for index, charge in enumerate(batch.charges):
        view = ledger.view()
        request = view['physical_claimed']+1
        ledger._claim(batch, index, r.ReadKey('C2', request, request-1,
                                             view['allocated_operations']+1), charge.target)


class DiscoveryCapacityTests(unittest.TestCase):
    def fresh(self, length=384):
        ledger = memory_ledger('C2')
        cap = ledger.reserve_c2_discovery_capacity(map_virtual=0x7f998, map_length=length)
        return ledger, cap

    def success(self):
        ledger, cap = self.fresh()
        batch = ledger.materialize_c2_map(cap, requests=map_charges((384,)))
        claim_all(ledger, batch)
        for name in b.AFTER['C2']:
            ledger.reserve_operation('C2', name)
        self.assertEqual(ledger.view()['stage'], 'done')
        return ledger

    def test_unknown_address_reservation_issues_no_targets_keys_or_claims(self):
        ledger = memory_ledger('C2')
        before = dict(ledger.view())
        with patch.object(b.ReadCharge, 'for_target', side_effect=AssertionError('fake GPA')):
            cap = ledger.reserve_c2_discovery_capacity(map_virtual=0x7f998, map_length=384)
        self.assertIs(type(cap), b.C2DiscoveryCapacity)
        self.assertEqual(ledger.view()['physical_reserved'], 0)
        self.assertEqual(ledger.view()['physical_claimed'], 0)
        self.assertEqual(ledger.view()['allocated_operations'], before['allocated_operations'])
        self.assertEqual(ledger.view()['potential_reads'], 32*4+34)
        self.assertEqual(ledger.view()['potential_frames'], 32)
        self.assertEqual(ledger.view()['potential_parts'], 17)
        self.assertEqual(ledger.view()['discovery_state'], 'open')
        self.assertEqual(ledger.view()['committed_operations'],
                         before['committed_operations']+162)

    def test_symbolic_copy_bound_matches_original_plan_without_fake_target(self):
        for length in (1, 15, 16, 255, 256, 2048):
            for gpa in (0, 0xff, (1 << 64)-length):
                target = r.ReadTarget('object', 0, 6, 0, gpa, length)
                actual = sum(n for _, copies in r._verification_copy_plan(target)
                             for _, n in copies)
                a = len(f'{gpa:x}')
                d = len(f'{length:x}')
                self.assertEqual(actual, 17*length+8*a+8*d+43)
                self.assertLessEqual(actual, r.packet_copy_upper_bound(length))
                self.assertEqual(r.packet_copy_upper_bound(length), 17*length+195)
                self.assertEqual(r.metadata_copy_bound(), r.metadata_bound(target))
        for bad in (True, 0, 2049):
            with self.assertRaises(ProbeError):
                r.packet_copy_upper_bound(bad)

    def test_prepaid_bytes_materialization_and_claim_never_double_charge(self):
        ledger, cap = self.fresh(2048)
        k = r.metadata_copy_bound()
        expected = 32*4*(27*2048+2243+k)+54*2048+34*(2243+k)
        self.assertEqual(ledger.view()['committed_bytes'], expected)
        frame = ledger.materialize_c2_frame(cap, ordinal=0, physical=0x2000)
        self.assertEqual(frame.charges, frame_charges())
        claim_all(ledger, frame)
        batch = ledger.materialize_c2_map(cap, requests=map_charges((1024, 1024)))
        claim_all(ledger, batch)
        self.assertEqual(ledger.view()['committed_bytes'], expected)
        self.assertEqual(ledger.view()['potential_reads'], 31*4+30)
        self.assertEqual(ledger.view()['physical_claimed'], 8)
        self.assertEqual(ledger.view()['actual_bytes'], 0)

    def test_existing_frame_reservation_is_excluded_once(self):
        ledger = memory_ledger('C2')
        old = ledger.reserve_reads('C2', frame_charges())
        before = ledger.view()['committed_bytes']
        cap = ledger.reserve_c2_discovery_capacity(map_virtual=0x7f998, map_length=1)
        k = r.metadata_copy_bound()
        self.assertEqual(ledger.view()['committed_bytes']-before,
                         31*4*(27*2048+2243+k)+54+2*(2243+k))
        self.assertEqual(ledger.view()['potential_frames'], 31)
        with self.assertRaises(ProbeError):
            ledger.materialize_c2_frame(cap, ordinal=0, physical=0x2000)
        claim_all(ledger, old)
        self.success()

    def test_valid_refinement_and_seventeen_parts_use_same_capacity(self):
        for lengths in ((1024, 1024), (1,)+(2048,)*15+(2047,)):
            ledger, cap = self.fresh(sum(lengths))
            batch = ledger.materialize_c2_map(cap, requests=map_charges(lengths))
            self.assertEqual(len(batch.charges), 2*len(lengths))
            self.assertEqual(ledger.view()['first_parts'][2], len(lengths))
            self.assertEqual(ledger.view()['discovery_state'], 'sealed')

    def test_exclusive_window_blocks_direct_frame_and_map_even_after_seal(self):
        ledger, cap = self.fresh()
        for sealed in (False, True):
            if sealed:
                ledger.materialize_c2_map(cap, requests=map_charges((384,)))
            before = dict(ledger.view())
            for requests in (frame_charges(), map_charges((384,))):
                with self.assertRaises(ProbeError):
                    ledger.reserve_reads('C2', requests)
                self.assertEqual(dict(ledger.view()), before)
        self.success()

    def test_open_and_concrete_unclaimed_block_after_but_unused_does_not(self):
        ledger, cap = self.fresh()
        with self.assertRaises(ProbeError):
            ledger.reserve_operation('C2', b.AFTER['C2'][0])
        batch = ledger.materialize_c2_map(cap, requests=map_charges((384,)))
        with self.assertRaises(ProbeError):
            ledger.reserve_operation('C2', b.AFTER['C2'][0])
        claim_all(ledger, batch)
        locked = ledger.view()['potential_reads']
        self.assertGreater(locked, 0)
        for name in b.AFTER['C2']:
            ledger.reserve_operation('C2', name)
        self.assertEqual(ledger.view()['potential_reads'], locked)
        self.assertEqual(ledger.view()['committed_operations'],
                         ledger.view()['allocated_operations']+locked)

    def test_invalid_map_shape_and_order_refuse_without_state_change(self):
        good = map_charges((192, 192))
        bad = [good[::-1], (good[0], good[2], good[1], good[3]),
               map_charges((383,)), map_charges((1,)*18),
               tuple(b.ReadCharge.for_target(replace(c.target, target_ordinal=5)) for c in good),
               tuple(b.ReadCharge.for_target(replace(c.target, gpa=c.target.gpa+1))
                     if c.target.pass_index else c for c in good)]
        for requests in bad:
            ledger, cap = self.fresh()
            before = dict(ledger.view())
            with self.assertRaises(ProbeError):
                ledger.materialize_c2_map(cap, requests=requests)
            self.assertEqual(dict(ledger.view()), before)
            self.success()

    def test_foreign_replayed_and_out_of_order_tokens_do_not_mutate(self):
        ledger, cap = self.fresh()
        other, foreign = self.fresh()
        for token, ordinal in ((foreign, 0), (cap, 1)):
            before = dict(ledger.view())
            with self.assertRaises(ProbeError):
                ledger.materialize_c2_frame(token, ordinal=ordinal, physical=0x2000)
            self.assertEqual(dict(ledger.view()), before)
        ledger.materialize_c2_frame(cap, ordinal=0, physical=0x2000)
        with self.assertRaises(ProbeError):
            ledger.materialize_c2_frame(cap, ordinal=0, physical=0x2000)
        ledger.materialize_c2_map(cap, requests=map_charges((384,)))
        for call in (lambda: ledger.materialize_c2_map(cap, requests=map_charges((384,))),
                     lambda: ledger.materialize_c2_frame(cap, ordinal=1, physical=0x3000),
                     lambda: ledger.reserve_c2_discovery_capacity(map_virtual=0x1000, map_length=1)):
            with self.assertRaises(ProbeError):
                call()
        with self.assertRaises(TypeError):
            b.C2DiscoveryCapacity()
        self.success()

    def test_scalar_epoch_and_address_validation_precedes_reservation(self):
        for epoch in ('C0', 'C1'):
            ledger = memory_ledger(epoch)
            with self.assertRaises(ProbeError):
                ledger.reserve_c2_discovery_capacity(map_virtual=0x1000, map_length=384)
        for address, length in ((True, 384), (0x1000, True), (0x1000, 0),
                                (0x1000, 32769), ((1 << 47)-1, 2), ((1 << 64)-1, 2)):
            ledger = memory_ledger('C2')
            before = dict(ledger.view())
            with self.assertRaises(ProbeError):
                ledger.reserve_c2_discovery_capacity(map_virtual=address, map_length=length)
            self.assertEqual(dict(ledger.view()), before)
            self.success()

    def test_all_limits_include_potential_before_any_mutation(self):
        for field, value in (('_regular', b.REGULAR_BYTES), ('_operations', 900),
                             ('_phase_ops', [0, 0, 400])):
            ledger = memory_ledger('C2')
            setattr(ledger, field, value)  # explicit synthetic exhausted ledger
            before = dict(ledger.view())
            with self.assertRaises(ProbeError):
                ledger.reserve_c2_discovery_capacity(map_virtual=0x1000, map_length=384)
            self.assertEqual(dict(ledger.view()), before)
            self.success()

    def test_unused_capacity_stays_unavailable_to_later_allocations(self):
        ledger, cap = self.fresh()
        batch = ledger.materialize_c2_map(cap, requests=map_charges((384,)))
        claim_all(ledger, batch)
        # Synthetic near-bound state must still include locked potential slots.
        ledger._operations = b.MAX_OPERATIONS-ledger.view()['remaining_controls']
        before = dict(ledger.view())
        with self.assertRaises(ProbeError):
            ledger.reserve_operation('C2', b.AFTER['C2'][0])
        self.assertEqual(dict(ledger.view()), before)
        self.success()

    def test_potential_parts_and_phase_slots_still_bound_scalar_batches(self):
        for sealed in (False, True):
            ledger, cap = self.fresh()
            if sealed:
                ledger.materialize_c2_map(cap, requests=map_charges((384,)))
            # Existing exact-target scalar intake cannot borrow unused map parts.
            scalar = tuple(b.ReadCharge.for_target(r.ReadTarget('object', p, 0, i,
                                                                0x9000+i, 1))
                           for p in (0, 1) for i in range(13))
            before = dict(ledger.view())
            with self.assertRaises(ProbeError):
                ledger.reserve_reads('C2', scalar)
            self.assertEqual(dict(ledger.view()), before)
        ledger, cap = self.fresh()
        batch = ledger.materialize_c2_map(cap, requests=map_charges((384,)))
        claim_all(ledger, batch)
        ledger._phase_ops[2] = 512-len(b.AFTER['C2'])
        before = dict(ledger.view())
        with self.assertRaises(ProbeError):
            ledger.reserve_operation('C2', b.AFTER['C2'][0])
        self.assertEqual(dict(ledger.view()), before)
        self.success()

    def test_one_byte_map_does_not_reserve_seventeen_nonempty_parts(self):
        ledger, cap = self.fresh(1)
        self.assertEqual(ledger.view()['potential_parts'], 1)
        self.assertEqual(ledger.view()['potential_reads'], 130)
        batch = ledger.materialize_c2_map(cap, requests=map_charges((1,)))
        claim_all(ledger, batch)
        self.assertEqual(ledger.view()['potential_parts'], 0)
        self.assertEqual(ledger.view()['potential_reads'], 128)
        for name in b.AFTER['C2']:
            ledger.reserve_operation('C2', name)

    def test_reservation_exhaustion_leaves_no_partial_token_or_refund(self):
        ledger = memory_ledger('C2')
        ledger._parts[2] = 13  # explicit synthetic shape exhaustion
        before = dict(ledger.view())
        with self.assertRaises(ProbeError):
            ledger.reserve_c2_discovery_capacity(map_virtual=0x1000, map_length=384)
        self.assertEqual(dict(ledger.view()), before)
        self.assertIsNone(ledger._capacity)
        self.success()

    def test_interrupt_during_capacity_commit_irrevocably_aborts(self):
        ledger = memory_ledger('C2')
        original = object.__setattr__
        def interrupted(obj, name, value):
            if obj is ledger and name == '_potential_reads':
                raise KeyboardInterrupt('actual commit boundary')
            original(obj, name, value)
        with patch.object(b.ParentAccounting, '__setattr__', interrupted):
            with self.assertRaises(KeyboardInterrupt):
                ledger.reserve_c2_discovery_capacity(map_virtual=0x1000, map_length=384)
        self.assertTrue(ledger.view()['aborted'])
        for call in (lambda: ledger.reserve_c2_discovery_capacity(map_virtual=0x1000, map_length=1),
                     lambda: ledger.reserve_reads('C2', frame_charges()),
                     lambda: ledger.reserve_operation('C2', b.AFTER['C2'][0])):
            with self.assertRaises(ProbeError):
                call()
        ledger.reserve_output(1)
        ledger.redeem_terminal(1, purpose='failure')
        self.success()

    def test_interrupt_during_materialization_blocks_claim_and_reuse(self):
        ledger = memory_ledger('C2')
        old = ledger.reserve_reads('C2', frame_charges())
        cap = ledger.reserve_c2_discovery_capacity(map_virtual=0x7f998, map_length=384)
        original = object.__setattr__
        def interrupted(obj, name, value):
            if obj is ledger and name == '_batches':
                raise KeyboardInterrupt('materialization publication')
            original(obj, name, value)
        before = ledger.view()['committed_bytes']
        with patch.object(b.ParentAccounting, '__setattr__', interrupted):
            with self.assertRaises(KeyboardInterrupt):
                ledger.materialize_c2_frame(cap, ordinal=1, physical=0x3000)
        self.assertTrue(ledger.view()['aborted'])
        self.assertEqual(ledger.view()['committed_bytes'], before)
        with self.assertRaises(ProbeError):
            ledger.materialize_c2_map(cap, requests=map_charges((384,)))
        with self.assertRaises(ProbeError):
            ledger._claim(old, 0, r.ReadKey('C2', 1, 0,
                                           ledger.view()['allocated_operations']+1),
                          old.charges[0].target)
        ledger.redeem_terminal(1, purpose='failure')
        self.success()


class DiscoveryMutationTests(unittest.TestCase):
    fresh = DiscoveryCapacityTests.fresh
    success = DiscoveryCapacityTests.success

    def interrupt(self, ledger, field, operation):
        def inject(obj, name, value):
            if obj is ledger and name == field:
                raise KeyboardInterrupt('review mutation boundary '+field)
            object.__setattr__(obj, name, value)
        with patch.object(b.ParentAccounting, '__setattr__', inject):
            with self.assertRaises(KeyboardInterrupt):
                operation()

    def refuse_after_abort(self, ledger, cap, batch=None, key=None):
        self.assertTrue(ledger.view()['aborted'])
        calls = [lambda: ledger.reserve_c2_discovery_capacity(map_virtual=0x1000, map_length=1),
                 lambda: ledger.materialize_c2_frame(cap, ordinal=0, physical=0x2000),
                 lambda: ledger.materialize_c2_map(cap, requests=map_charges((384,))),
                 lambda: ledger.reserve_reads('C2', frame_charges()),
                 lambda: ledger.reserve_operation('C2', b.AFTER['C2'][0])]
        if batch is not None:
            calls += [lambda: ledger._claim(batch, 0, key, batch.charges[0].target),
                      lambda: ledger.debit_read(batch, key, 1, purpose='read')]
        for operation in calls:
            with self.assertRaises(ProbeError):
                operation()
        ledger.reserve_output(1)
        ledger.redeem_terminal(1, purpose='failure')
        self.success()

    def test_claim_interrupted_after_credit_publication_aborts(self):
        ledger, cap = self.fresh()
        batch = ledger.materialize_c2_frame(cap, ordinal=0, physical=0x2000)
        key = r.ReadKey('C2', 1, 0, ledger.view()['allocated_operations']+1)
        self.interrupt(ledger, '_next_request',
                       lambda: ledger._claim(batch, 0, key, batch.charges[0].target))
        self.assertIn(key, ledger._claimed)
        self.assertEqual(ledger._batches[id(batch)]['claimed'], {0})
        self.refuse_after_abort(ledger, cap, batch, key)

    def test_scalar_reservation_interrupted_after_byte_commit_aborts(self):
        ledger, cap = self.fresh()
        charges = tuple(b.ReadCharge.for_target(r.ReadTarget('object', p, 0, 0, 0x9000, 1))
                        for p in (0, 1))
        before = ledger.view()['committed_bytes']
        self.interrupt(ledger, '_reserved_reads', lambda: ledger.reserve_reads('C2', charges))
        self.assertGreater(ledger.view()['committed_bytes'], before)
        self.refuse_after_abort(ledger, cap)
        with self.assertRaises(ProbeError):
            ledger.reserve_reads('C2', charges)

    def test_after_control_interrupted_after_counter_growth_aborts(self):
        ledger, cap = self.fresh(1)
        batch = ledger.materialize_c2_map(cap, requests=map_charges((1,)))
        claim_all(ledger, batch)
        before = ledger.view()['allocated_operations']
        self.interrupt(ledger, '_after',
                       lambda: ledger.reserve_operation('C2', b.AFTER['C2'][0]))
        self.assertEqual(ledger.view()['allocated_operations'], before+1)
        self.refuse_after_abort(ledger, cap)

    def test_debit_interrupted_after_credit_decrement_aborts(self):
        ledger, cap = self.fresh()
        batch = ledger.materialize_c2_frame(cap, ordinal=0, physical=0x2000)
        key = r.ReadKey('C2', 1, 0, ledger.view()['allocated_operations']+1)
        ledger._claim(batch, 0, key, batch.charges[0].target)
        before = ledger._claimed[key]['remaining']['read']
        self.interrupt(ledger, '_actual_bytes',
                       lambda: ledger.debit_read(batch, key, 1, purpose='read'))
        self.assertEqual(ledger._claimed[key]['remaining']['read'], before-1)
        self.refuse_after_abort(ledger, cap, batch, key)


class WireCopyCreditTests(unittest.TestCase):
    def claim(self, ledger, batch, item):
        request=ledger.view()['physical_claimed']+1
        key=r.ReadKey(batch.epoch,request,request-1,ledger.view()['allocated_operations']+1)
        ledger._claim(batch,item,key,batch.charges[item].target)
        return key

    def test_wire01_additional_credit_preserves_all_legacy_read_costs(self):
        ledger=memory_ledger()
        batch=ledger.reserve_reads('C0',frame_charges())
        original=ledger.view()['committed_bytes']
        ledger.reserve_wire_batch(batch)
        amount=4*(14*2048+9216)
        self.assertEqual(ledger.view()['committed_bytes'],original+amount)
        self.assertEqual(ledger.view()['wire_committed_bytes'],amount)
        key=self.claim(ledger,batch,0)
        self.assertEqual(ledger._claimed[key]['remaining']['read'],8*2048+2048)
        ledger.debit_wire_read(batch,key,14*2048+9216)
        self.assertEqual(ledger.view()['wire_debited_bytes'],14*2048+9216)
        self.assertEqual(ledger._claimed[key]['remaining']['read'],8*2048+2048)

    def test_wire02_no_borrow_foreign_batch_or_future_key(self):
        ledger=memory_ledger()
        batch=ledger.reserve_reads('C0',frame_charges())
        ledger.reserve_wire_batch(batch)
        future=r.ReadKey('C0',1,0,ledger.view()['allocated_operations']+1)
        with self.assertRaises(ProbeError):ledger.debit_wire_read(batch,future,1)
        key=self.claim(ledger,batch,0)
        ledger.debit_wire_read(batch,key,14*2048+9216)
        before=dict(ledger.view())
        with self.assertRaises(ProbeError):ledger.debit_wire_read(batch,key,1)
        self.assertEqual(dict(ledger.view()),before)
        foreign=memory_ledger().reserve_reads('C0',frame_charges())
        with self.assertRaises(ProbeError):ledger.debit_wire_read(foreign,key,0)
        fresh=memory_ledger();next_batch=fresh.reserve_reads('C0',frame_charges())
        fresh.reserve_wire_batch(next_batch)
        next_key=self.claim(fresh,next_batch,0)
        fresh.debit_wire_read(next_batch,next_key,1)

    def test_wire03_discovery_transfer_neither_recharges_nor_refunds_unused_credit(self):
        ledger=memory_ledger('C2')
        cap=ledger.reserve_c2_discovery_capacity(map_virtual=0x7f998,map_length=384)
        before=ledger.view()['committed_bytes']
        ledger.reserve_wire_discovery(cap)
        amount=14*(4*32*2048+2*384)+9216*(4*32+2*17)
        self.assertEqual(ledger.view()['committed_bytes'],before+amount)
        frame=ledger.materialize_c2_frame(cap,ordinal=0,physical=0x2000)
        mapped=ledger.materialize_c2_map(cap,requests=map_charges((1,)*16+(368,)))
        self.assertEqual(ledger.view()['committed_bytes'],before+amount)
        used=0
        for batch in (frame,mapped):
            for item,charge in enumerate(batch.charges):
                key=self.claim(ledger,batch,item)
                cost=14*charge.target.length+9216
                ledger.debit_wire_read(batch,key,cost)
                used+=cost
        self.assertEqual(ledger.view()['wire_debited_bytes'],used)
        self.assertEqual(ledger.view()['wire_discovery_remaining'],amount-used)
        self.assertGreater(amount-used,0)
        for name in b.AFTER['C2']:ledger.reserve_operation('C2',name)
        self.assertEqual(ledger.view()['committed_bytes'],before+amount)

    def test_wire04_late_duplicate_and_claimed_prepay_refuse_without_mutation(self):
        ledger=memory_ledger('C2')
        cap=ledger.reserve_c2_discovery_capacity(map_virtual=0x7f998,map_length=384)
        frame=ledger.materialize_c2_frame(cap,ordinal=0,physical=0x2000)
        before=dict(ledger.view())
        with self.assertRaises(ProbeError):ledger.reserve_wire_discovery(cap)
        with self.assertRaises(ProbeError):ledger.reserve_wire_batch(frame)
        self.assertEqual(dict(ledger.view()),before)
        fresh=memory_ledger();batch=fresh.reserve_reads('C0',frame_charges())
        fresh.reserve_wire_batch(batch)
        before=dict(fresh.view())
        with self.assertRaises(ProbeError):fresh.reserve_wire_batch(batch)
        self.assertEqual(dict(fresh.view()),before)
        key=self.claim(fresh,batch,0)
        with self.assertRaises(ProbeError):fresh.reserve_wire_batch(batch)
        fresh.debit_wire_read(batch,key,1)

    def test_wire05_insufficient_capacity_is_unchanged_and_no_key_is_invented(self):
        ledger=memory_ledger();batch=ledger.reserve_reads('C0',frame_charges())
        required=4*(14*2048+9216)
        ledger.reserve_output(b.REGULAR_BYTES-ledger._regular-required+1)
        before=dict(ledger.view())
        with self.assertRaises(ProbeError):ledger.reserve_wire_batch(batch)
        self.assertEqual(dict(ledger.view()),before)
        self.assertEqual(ledger.view()['physical_claimed'],0)
        self.assertEqual(ledger._wire_batches,{})

    def test_wire06_interrupted_initial_credit_commit_aborts_without_legacy_cap(self):
        class Interrupted(dict):
            def __setitem__(self,key,value):
                super().__setitem__(key,value)
                raise KeyboardInterrupt
        ledger=memory_ledger();batch=ledger.reserve_reads('C0',frame_charges())
        ledger._wire_batches=Interrupted()
        with self.assertRaises(KeyboardInterrupt):ledger.reserve_wire_batch(batch)
        self.assertTrue(ledger.view()['aborted'])
        with self.assertRaises(ProbeError):self.claim(ledger,batch,0)
        ledger.reserve_output(0)
        ledger.redeem_terminal(1,purpose='failure')

    def test_wire07_interrupted_wire_debit_aborts_and_cannot_borrow_again(self):
        class Interrupted(list):
            def __setitem__(self,key,value):
                super().__setitem__(key,value)
                raise KeyboardInterrupt
        ledger=memory_ledger();batch=ledger.reserve_reads('C0',frame_charges())
        ledger.reserve_wire_batch(batch);key=self.claim(ledger,batch,0)
        row=ledger._wire_batches[id(batch)]
        row['remaining']=Interrupted(row['remaining'])
        with self.assertRaises(KeyboardInterrupt):ledger.debit_wire_read(batch,key,1)
        self.assertTrue(ledger.view()['aborted'])
        with self.assertRaises(ProbeError):ledger.debit_wire_read(batch,key,1)

    def test_wire08_interrupted_discovery_transfer_never_reopens_capacity(self):
        class Interrupted(dict):
            def __setitem__(self,key,value):
                super().__setitem__(key,value)
                raise KeyboardInterrupt
        ledger=memory_ledger('C2')
        cap=ledger.reserve_c2_discovery_capacity(map_virtual=0x7f998,map_length=384)
        ledger.reserve_wire_discovery(cap)
        ledger._wire_capacity=Interrupted(ledger._wire_capacity)
        with self.assertRaises(KeyboardInterrupt):
            ledger.materialize_c2_frame(cap,ordinal=0,physical=0x2000)
        self.assertTrue(ledger.view()['aborted'])
        with self.assertRaises(ProbeError):
            ledger.materialize_c2_map(cap,requests=map_charges((384,)))


if __name__ == '__main__':
    unittest.main()
