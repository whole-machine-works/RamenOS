"""Parent lifetime controls; private fixtures supply no runtime registration."""
import os
import itertools
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

import boot_profile_capture as base
import run0_host_cpu_witness as witness

try:
    import run0_call_owner as owner
except ModuleNotFoundError as error:
    if error.name != 'run0_call_owner':
        raise
    owner = None


def native(cls, **fields):
    """Test-only inert native state. Never exported by the implementation."""
    value = object.__new__(cls)
    for key, item in fields.items():
        object.__setattr__(value, key, item)
    return value


class ParentOwnerControls(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(owner, 'parent owner is absent: gate-first RED')

    def fixture(self, policy, epoch='C0', reuse=None):
        now = time.monotonic_ns()
        value = reuse or native(owner.NativeTransitionOwner, _policy=policy, _wire=object(),
                                _ledger=object(), _tickets=[])
        value._epoch, value._source_stop_ns, value._admission_started_ns = epoch, now, now
        value._registered, value._held, value._used = True, {}, False
        policy._owner = value
        classes = (owner.ClosedEpochReceipt, owner.BreakpointClearReceipt,
                   owner.BreakpointSetReceipt, owner.TransitionReservation,
                   owner.QuietReceipt, owner.TransitionJournalReceipt)
        proofs = []
        for cls in classes:
            proof = native(cls, _owner=value, _wire=value._wire, _epoch=epoch)
            value._held[cls] = proof
            proofs.append(proof)
        object.__setattr__(proofs[0], '_memory_revoked', True)
        object.__setattr__(proofs[3], '_ledger', value._ledger)
        object.__setattr__(proofs[4], '_observed_ns', now)
        object.__setattr__(proofs[5], '_flushed_ns', now)
        object.__setattr__(proofs[5], '_ref', ('admission.json', 'a'*64, 128))
        return value, proofs

    def test_deadlines_are_created_once_and_public_constructors_do_not_issue_receipts(self):
        started = time.monotonic_ns()
        policy = owner.ParentDeadlines(started)
        self.assertEqual(policy.effective_work_ns, started+85_000_000_000)
        self.assertEqual(policy.effective_hard_ns, started+90_000_000_000)
        for cls in owner.TRANSITION_NATIVE_TYPES:
            with self.subTest(cls=cls.__name__), self.assertRaises(TypeError):
                cls()
        for bad in (True, -1, time.monotonic_ns()+1_000_000_000, 1.5):
            with self.assertRaises(base.ProbeError):
                owner.ParentDeadlines(bad)
        with self.assertRaises(AttributeError):
            policy.effective_hard_ns = started+999_000_000_000

    def test_only_sealed_registered_admission_switches_and_does_not_claim_send(self):
        policy = owner.ParentDeadlines(time.monotonic_ns())
        native_owner, proofs = self.fixture(policy)
        before = policy.effective_hard_ns
        self.assertEqual(before, policy.started_ns+90_000_000_000)
        ticket = native_owner.issue_admission(*proofs, now_ns=time.monotonic_ns())
        self.assertEqual(policy.effective_hard_ns, policy.started_ns+180_000_000_000)
        self.assertEqual(policy.effective_work_ns, policy.started_ns+175_000_000_000)
        self.assertEqual(ticket.source_epoch, 'C0')
        self.assertEqual(ticket.target_epoch, 'C1')
        self.assertFalse(hasattr(ticket, 'sent_ns'))
        native_owner.consume_for_send(ticket, now_ns=time.monotonic_ns())
        with self.assertRaises(base.ProbeError):
            native_owner.consume_for_send(ticket, now_ns=time.monotonic_ns())
        with self.assertRaises(base.ProbeError):
            native_owner.issue_admission(*proofs, now_ns=time.monotonic_ns())
        with self.assertRaises(base.ProbeError):
            policy._activate(ticket, now_ns=time.monotonic_ns())

    def test_foreign_unregistered_unflushed_and_expired_admissions_keep_original_limits(self):
        for mutation in ('foreign', 'unregistered', 'unflushed', 'stop_expired', 'work_expired'):
            with self.subTest(mutation=mutation):
                policy = owner.ParentDeadlines(time.monotonic_ns())
                value, proofs = self.fixture(policy)
                if mutation == 'foreign':
                    object.__setattr__(proofs[1], '_owner', object())
                elif mutation == 'unregistered':
                    value._registered = False
                elif mutation == 'unflushed':
                    object.__setattr__(proofs[5], '_flushed_ns', None)
                elif mutation == 'stop_expired':
                    value._source_stop_ns = time.monotonic_ns()-60_000_000_001
                else:
                    policy = owner.ParentDeadlines(time.monotonic_ns()-85_000_000_001)
                    value, proofs = self.fixture(policy)
                with self.assertRaises(base.ProbeError):
                    value.issue_admission(*proofs, now_ns=time.monotonic_ns())
                self.assertEqual(policy.effective_hard_ns, policy.started_ns+90_000_000_000)
        fresh = owner.ParentDeadlines(time.monotonic_ns())
        value, proofs = self.fixture(fresh)
        value.issue_admission(*proofs, now_ns=time.monotonic_ns())
        self.assertEqual(fresh.effective_hard_ns, fresh.started_ns+180_000_000_000)

    def test_second_transition_does_not_renew_parent_deadlines(self):
        policy = owner.ParentDeadlines(time.monotonic_ns())
        first, proofs = self.fixture(policy)
        first_ticket = first.issue_admission(*proofs, now_ns=time.monotonic_ns())
        first.consume_for_send(first_ticket, now_ns=time.monotonic_ns())
        work, hard = policy.effective_work_ns, policy.effective_hard_ns
        # Changing the native parent identity after admission is not permitted.
        second, proofs = self.fixture(policy, 'C1')
        with self.assertRaises(base.ProbeError):
            second.issue_admission(*proofs, now_ns=time.monotonic_ns())
        self.assertEqual((policy.effective_work_ns, policy.effective_hard_ns), (work, hard))
        same, proofs = self.fixture(policy, 'C1', reuse=first)
        ticket = same.issue_admission(*proofs, now_ns=time.monotonic_ns())
        self.assertEqual(ticket.target_epoch, 'C2')
        self.assertEqual((policy.effective_work_ns, policy.effective_hard_ns), (work, hard))

    def test_expired_first_send_is_consumed_without_renewal_or_send_claim(self):
        policy = owner.ParentDeadlines(time.monotonic_ns())
        value, proofs = self.fixture(policy)
        ticket = value.issue_admission(*proofs, now_ns=time.monotonic_ns())
        later = ticket.response_deadline_ns+1
        with patch.object(owner.time, 'monotonic_ns', return_value=later):
            with self.assertRaisesRegex(base.ProbeError, 'parent_transition_send_expired'):
                value.consume_for_send(ticket, now_ns=later)
            with self.assertRaisesRegex(base.ProbeError, 'parent_transition_send_identity'):
                value.consume_for_send(ticket, now_ns=later)
        self.assertEqual(policy.effective_hard_ns, policy.started_ns+180_000_000_000)
        self.assertFalse(hasattr(ticket, 'sent_ns'))

    def test_stale_supplied_timestamps_cannot_reopen_expired_real_windows(self):
        with patch.object(owner.time, 'monotonic_ns', return_value=11_000_000_000):
            policy = owner.ParentDeadlines(0)
            value, proofs = self.fixture(policy)
        with patch.object(owner.time, 'monotonic_ns', return_value=100_000_000_000):
            with self.assertRaises(base.ProbeError):
                value.issue_admission(*proofs, now_ns=11_000_000_000)
        self.assertEqual(policy.effective_hard_ns, 90_000_000_000)
        with patch.object(owner.time, 'monotonic_ns', return_value=11_000_000_000):
            policy = owner.ParentDeadlines(0)
            value, proofs = self.fixture(policy)
            ticket = value.issue_admission(*proofs, now_ns=11_000_000_000)
        with patch.object(owner.time, 'monotonic_ns', return_value=100_000_000_000):
            with self.assertRaises(base.ProbeError):
                value.consume_for_send(ticket, now_ns=12_000_000_000)
        self.assertEqual(policy.effective_hard_ns, 180_000_000_000)
        fresh = owner.ParentDeadlines(time.monotonic_ns())
        value, proofs = self.fixture(fresh)
        ticket = value.issue_admission(*proofs, now_ns=time.monotonic_ns())
        value.consume_for_send(ticket, now_ns=time.monotonic_ns())

    def test_interrupt_after_registration_keeps_commit_and_lifetime_consistent(self):
        policy = owner.ParentDeadlines(time.monotonic_ns())
        value, proofs = self.fixture(policy)
        activate = policy._activate
        def interrupted(policy_self, ticket, *, now_ns):
            activate(ticket, now_ns=now_ns)
            raise KeyboardInterrupt
        with patch.object(owner.ParentDeadlines, '_activate', interrupted):
            with self.assertRaises(KeyboardInterrupt):
                value.issue_admission(*proofs, now_ns=time.monotonic_ns())
        self.assertEqual(policy.effective_hard_ns, policy.started_ns+180_000_000_000)
        self.assertTrue(value._tickets[0]._committed)
        self.assertFalse(value._tickets[0]._consumed)

    def test_repeated_cleanup_skips_attempted_term_and_completes_kill_and_wait(self):
        policy = owner.ParentDeadlines(time.monotonic_ns())
        process = owner.ParentOwnedWait('qemu', policy)
        process.child = type('Child', (), {'pid': 1234})()
        answers = iter([(0, 0), InterruptedError(), (0, 0), (0, 0), (1234, 0)])
        def waitpid(pid, flags):
            item = next(answers)
            if isinstance(item, BaseException):
                raise item
            return item
        with patch.object(witness.os, 'waitpid', side_effect=waitpid), \
             patch.object(witness.os, 'killpg') as signals, \
             patch.object(witness.time, 'sleep'), \
             patch.object(witness.time, 'monotonic', side_effect=itertools.count(time.monotonic())):
            with self.assertRaises(InterruptedError):
                process.terminate()
            process.terminate()
        self.assertEqual([args.args[1] for args in signals.call_args_list],
                         [owner.signal.SIGTERM, owner.signal.SIGKILL])
        self.assertTrue(process.reaped)
        self.assertEqual(process.wait_summary['errors'], 1)
        self.assertLessEqual(len(process.lifecycle), 5)

    def test_wait_default_and_explicit_deadlines_are_phase_clipped(self):
        policy = owner.ParentDeadlines(time.monotonic_ns())
        process = owner.ParentOwnedWait('qemu', policy)
        process.child = type('Child', (), {'pid': 1234})()
        for active in (False, True):
            if active:
                value, proofs = self.fixture(policy)
                value.issue_admission(*proofs, now_ns=time.monotonic_ns())
            hard = policy.effective_hard_ns/1e9
            self.assertEqual(process.deadline, hard)
            # No real child or signals: observe the bound passed to the retained
            # actual wait loop, including default and oversized caller limits.
            for requested, expected in ((None, hard-.75), (hard+100, hard)):
                with patch.object(witness.time, 'monotonic', return_value=expected+.1), \
                     patch.object(witness.os, 'waitpid', return_value=(0, 0)), \
                     patch.object(witness.time, 'sleep', side_effect=AssertionError('wait exceeded bound')):
                    self.assertIsNone(process.wait(requested))
                self.assertEqual(process.lifecycle[-1]['result'], 'timeout')
        for invalid in (True, float('nan'), float('inf')):
            with self.assertRaises(base.ProbeError):
                process.wait(invalid)

    def test_wait_and_terminate_clip_even_the_inherited_final_wait(self):
        policy = owner.ParentDeadlines(time.monotonic_ns())
        process = owner.ParentOwnedWait('qemu', policy)
        process.child = subprocess.Popen([sys.executable, '-B', '-c', 'pass'],
                                         start_new_session=True)
        try:
            code = process.wait(time.monotonic()+2)
            self.assertEqual(code, 0)
            self.assertTrue(process.reaped)
            self.assertTrue(any(r['operation'] == 'wait' and r['result'] == 'ok'
                                for r in process.lifecycle))
        finally:
            process.terminate()
        process = owner.ParentOwnedWait('qemu', policy)
        process.child = type('Child', (), {'pid': 1234})()
        requested = []
        def timed_out(deadline=None, **kwargs):
            requested.append(deadline)
            return None
        with patch.object(process, 'wait', side_effect=timed_out), patch.object(process, '_signal'):
            process.terminate()
        self.assertEqual(requested[-1], policy.effective_hard_ns/1e9)
        self.assertLess(process.io_deadline, process.deadline)
        with self.assertRaises(AttributeError):
            process.deadline = time.monotonic()+999
        self.assertIs(type(witness.OwnedWait('old', time.monotonic()+1)), witness.OwnedWait)

    def test_helper_owns_actual_eof_wait_and_close_and_keeps_original_lease(self):
        policy = owner.ParentDeadlines(time.monotonic_ns())
        read_fd, write_fd = os.pipe()
        lease = time.monotonic_ns()+3_000_000_000
        helper = owner.ParentOwnedHelper('fields', read_fd, lease, policy)
        try:
            helper.start([sys.executable, '-B', '-c',
                          f'import os; os.write({write_fd}, b"ok")'], (write_fd,), 64, 64)
            os.close(write_fd)
            write_fd = None
            helper.drain()
            self.assertEqual(helper.wait(), 0)
            self.assertEqual(bytes(helper.output), b'ok')
            self.assertEqual(helper.eofs, {'stdout', 'stderr'})
            value, proofs = self.fixture(policy)
            value.issue_admission(*proofs, now_ns=time.monotonic_ns())
            self.assertLessEqual(helper.io_deadline, lease/1e9)
            self.assertEqual(helper.deadline, policy.effective_hard_ns/1e9)
        finally:
            if write_fd is not None:
                os.close(write_fd)
            helper.close()
        self.assertTrue(helper.closed and helper.reaped)
        self.assertTrue(any(r['operation'] == 'close' for r in helper.lifecycle))

    def test_cleanup_never_dispatches_signals_after_effective_hard_expiry(self):
        policy = owner.ParentDeadlines(time.monotonic_ns())
        process = owner.ParentOwnedWait('qemu', policy)
        process.child = type('Child', (), {'pid': 1234})()
        with patch.object(owner.time, 'monotonic', return_value=policy.effective_hard_ns/1e9+1), \
             patch.object(owner.time, 'monotonic_ns', return_value=policy.effective_hard_ns+1), \
             patch.object(witness.os, 'waitpid', return_value=(0, 0)), \
             patch.object(witness.os, 'killpg') as signals:
            with self.assertRaises(base.ProbeError):
                process.terminate()
        signals.assert_not_called()
        self.assertFalse(process.reaped)

    def test_wait_polling_is_bounded_and_retains_real_aggregate_outcomes(self):
        policy = owner.ParentDeadlines(time.monotonic_ns())
        process = owner.ParentOwnedWait('qemu', policy)
        process.child = type('Child', (), {'pid': 1234})()
        with patch.object(owner.time, 'monotonic', return_value=policy.effective_hard_ns/1e9+1), \
             patch.object(witness.os, 'waitpid', return_value=(0, 0)):
            for _ in range(75):
                self.assertIsNone(process.wait())
        self.assertLessEqual(len(process.lifecycle), 5)
        self.assertEqual(process.wait_summary['attempts'], 75)
        self.assertEqual(process.wait_summary['timeouts'], 75)
        with patch.object(witness.os, 'waitpid', return_value=(1234, 0)):
            self.assertEqual(process.wait(), 0)
        self.assertEqual(process.wait_summary['attempts'], 76)
        self.assertTrue(process.reaped)
        self.assertEqual(sum(r['operation'] == 'wait' for r in process.lifecycle), 1)


if __name__ == '__main__':
    unittest.main()
