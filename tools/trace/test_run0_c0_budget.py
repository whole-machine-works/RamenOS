"""Single-envelope reservation/redemption controls; no launch or read authority."""
import time
import unittest

import run0_c0_acquire as acquire
from boot_profile_capture import ProbeError

try:
    import run0_c0_budget as budget
except ModuleNotFoundError as error:
    if error.name != 'run0_c0_budget':
        raise
    budget = None


class AccountingControls(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(budget, 'single accounting bridge absent: expected gate-first RED')

    def accounting(self):
        return budget.C0Accounting(time.monotonic_ns())

    def test_factory_seeds_actual_prefix_and_rejects_foreign_or_drifted_attachment(self):
        value = self.accounting()
        value.reserve_output(123, 'output')
        value._reserve_operation('query_status')
        ledger = value.make_acquisition_ledger()
        self.assertEqual((ledger.values['operations'], ledger.values['retained_bytes']), (1, 123))
        with self.assertRaises(ProbeError):
            value.attach_acquisition(acquire.AcquisitionLedger())
        value.reserve_output(1, 'output')
        with self.assertRaisesRegex(ProbeError, 'accounting_factory_drift'):
            value.attach_acquisition(ledger)

    def test_protected_ordered_tail_is_available_at_acquisition_operation_boundary(self):
        value = self.accounting()
        ledger = value.make_acquisition_ledger()
        value.attach_acquisition(ledger)
        ledger.reserve(operations=479)
        with self.assertRaises(Exception):
            ledger.reserve(operations=1)
        with self.assertRaises(ProbeError):
            value.redeem_tail('hmp_registers')
        for name in acquire.TAIL_OPERATIONS:
            value.redeem_tail(name)
        self.assertEqual(value.envelope_operations, 512)
        with self.assertRaises(ProbeError):
            value.redeem_tail('quit')

    def test_terminal_reserves_are_cumulative_across_files_without_reset(self):
        value = self.accounting()
        value.reserve_output(budget.REGULAR_BYTES, 'output')
        with self.assertRaises(ProbeError):
            value.reserve_output(1, 'output')
        value.redeem_terminal(17, 'report')
        value.redeem_terminal(budget.REPORT_BYTES-17, 'report')
        value.redeem_terminal(budget.FAILURE_BYTES, 'failure')
        self.assertEqual(value.actual_bytes, budget.MAX_BYTES)
        for purpose in ('report', 'failure', 'output'):
            with self.assertRaises(ProbeError):
                value.redeem_terminal(1, purpose)


if __name__ == '__main__':
    unittest.main()
