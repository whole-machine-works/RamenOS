"""One C0 usage/reservation envelope; this module issues no read authority."""
import time

from boot_profile_capture import ProbeError, deny, incomplete

MAX_BYTES = 32 * 1024 * 1024
REPORT_BYTES = 1024 * 1024
FAILURE_BYTES = 128 * 1024
REGULAR_BYTES = MAX_BYTES - REPORT_BYTES - FAILURE_BYTES
MAX_OPERATIONS = 512
TAIL_COUNT = 33


class C0Accounting:
    def __init__(self, started_ns):
        deny(type(started_ns) is int and 0 <= started_ns <= time.monotonic_ns(), 'accounting_start')
        self.started_ns = started_ns
        self.deadline_ns = started_ns + 90_000_000_000
        self._actual_bytes = self._operations = 0
        self._prefix_bytes = 0
        self._made = self._ledger = self._seed = None
        self._normal_after = self._allocated_read_bytes = self._allocated_read_ops = 0
        self._credits = {}
        self._tail = 0
        self._terminal = {}
        self._failure = None
        self._wire = None

    def _bind_wire(self, wire):
        deny(self._wire is None and self._made is None and self._operations == 0,
             'accounting_wire_owner')
        self._wire = wire

    @property
    def actual_bytes(self):
        return self._actual_bytes

    @property
    def committed_bytes(self):
        regular = self._prefix_bytes if self._ledger is None else self._ledger.values['retained_bytes']
        return regular + sum(self._terminal.values())

    @property
    def envelope_operations(self):
        return self._operations if self._ledger is None else self._ledger.values['operations'] + TAIL_COUNT

    @property
    def actual_operations(self):
        return self._operations

    def available(self, purpose='output'):
        regular = self._prefix_bytes if self._ledger is None else self._ledger.values['retained_bytes']
        remaining = REGULAR_BYTES - regular
        if type(purpose) is tuple:
            deny(purpose in self._credits, 'accounting_read_credit')
            remaining += self._credits[purpose]['remaining']
        else:
            deny(purpose == 'output', 'accounting_purpose')
        return remaining

    @staticmethod
    def _translate(call):
        import run0_c0_decode as decoder
        try:
            return call()
        except decoder.C0DecodeError as error:
            raise ProbeError(error.status, error.reason) from error

    def _extra(self, length):
        if self._ledger is None:
            incomplete(length <= REGULAR_BYTES-self._prefix_bytes, 'storage_limit')
            self._prefix_bytes += length
        else:
            self._translate(lambda: self._ledger.reserve(retained_bytes=length))
            self._normal_after += length

    def reserve_output(self, length, purpose='output'):
        deny(type(length) is int and length >= 0, 'accounting_length')
        if type(purpose) is tuple:
            deny(purpose in self._credits, 'accounting_read_credit')
            credit = self._credits[purpose]
            prepaid = min(length, credit['remaining'])
            self._extra(length-prepaid)
            credit['remaining'] -= prepaid
            credit['spent'] += length
        else:
            deny(purpose == 'output', 'accounting_purpose')
            self._extra(length)
        self._actual_bytes += length

    def _reserve_operation(self, name):
        deny(type(name) is str and self._ledger is None, 'accounting_operation_phase')
        incomplete(self._operations < MAX_OPERATIONS-TAIL_COUNT, 'c0_operation_limit')
        self._operations += 1

    def make_acquisition_ledger(self):
        import run0_c0_acquire as acquire
        deny(self._made is None and self._ledger is None, 'accounting_factory_once')
        if self._wire is not None:
            deny(len(self._wire.operations) == self._operations, 'accounting_operation_drift')
        self._seed = (self._operations, self._prefix_bytes)
        self._made = acquire.AcquisitionLedger((('operations', self._operations),
                                                ('retained_bytes', self._prefix_bytes)))
        return self._made

    def attach_acquisition(self, ledger):
        import run0_c0_acquire as acquire
        deny(type(ledger) is acquire.AcquisitionLedger and ledger is self._made
             and self._ledger is None, 'accounting_factory_identity')
        deny(self._seed == (self._operations, self._prefix_bytes)
             and ledger.values['operations'] == self._operations
             and ledger.values['retained_bytes'] == self._prefix_bytes
             and all(value == 0 for key, value in ledger.values.items()
                     if key not in ('operations', 'retained_bytes')), 'accounting_factory_drift')
        self._ledger = ledger

    def redeem_read(self, grant, operation_seq):
        import run0_c0_acquire as acquire
        deny(self._ledger is not None and type(grant) is acquire.RamReadGrant
             and grant.session is self._ledger._owner and grant.session.pending is grant,
             'accounting_read_owner')
        intent = grant.intent
        deny(type(intent) is acquire.PhysicalReadIntent and type(intent.length) is int
             and 1 <= intent.length <= 2048 and type(operation_seq) is int
             and operation_seq == self._operations+1 and self._tail == 0,
             'accounting_read_identity')
        key = ('read', intent.request_id, operation_seq)
        deny(key not in self._credits and all(row['grant'] is not grant for row in self._credits.values()),
             'accounting_read_reused')
        amount = 8*intent.length+2048
        values = self._ledger.values
        deny(values['operations'] >= self._seed[0]+self._allocated_read_ops+1
             and values['retained_bytes'] >= self._seed[1]+self._normal_after+
                 self._allocated_read_bytes+amount, 'accounting_read_not_reserved')
        self._credits[key] = {'grant': grant, 'remaining': amount, 'spent': 0}
        self._allocated_read_ops += 1
        self._allocated_read_bytes += amount
        self._operations += 1
        return key

    def redeem_tail(self, operation_name):
        import run0_c0_acquire as acquire
        deny(type(operation_name) is str and self._ledger is not None
             and self._tail < TAIL_COUNT, 'accounting_tail_state')
        if self._failure is not None and operation_name == 'quit':
            self._tail = TAIL_COUNT
        else:
            deny(operation_name == acquire.TAIL_OPERATIONS[self._tail], 'accounting_tail_order')
            self._tail += 1
        incomplete(self._operations < MAX_OPERATIONS, 'c0_operation_limit')
        self._operations += 1

    def _latch_failure(self, failure):
        if self._failure is None:
            self._failure = failure

    def redeem_terminal(self, length, purpose):
        deny(type(length) is int and length >= 0 and type(purpose) is str
             and purpose in ('report', 'failure'),
             'accounting_terminal_identity')
        prior = self._terminal.get(purpose, 0)
        incomplete(length <= (REPORT_BYTES if purpose == 'report' else FAILURE_BYTES)-prior,
                   'accounting_terminal_limit')
        self._terminal[purpose] = prior+length
        self._actual_bytes += length
