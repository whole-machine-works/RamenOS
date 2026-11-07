"""Parent-only deadlines and owned cleanup for the same-call capture.

These controls issue no VM registration or guest-memory authority. The opaque
transition objects have no public constructor or runtime registration factory.
A later reviewed collector must supply their authentic native held identities;
serialized facts cannot create them. Python observer internals are trusted host
scaffolding, not a security boundary.
"""
import math
from pathlib import PurePosixPath
import signal
import time

from boot_profile_capture import deny, incomplete
import run0_host_cpu_witness as witness


SECOND = 1_000_000_000


class _NativeTransition:
    __slots__ = ('_owner', '_wire', '_epoch')

    def __init__(self, *args, **kwargs):
        raise TypeError('only the registered native parent may retain this receipt')


class ClosedEpochReceipt(_NativeTransition):
    __slots__ = ('_memory_revoked',)


class BreakpointClearReceipt(_NativeTransition):
    __slots__ = ()


class BreakpointSetReceipt(_NativeTransition):
    __slots__ = ()


class TransitionReservation(_NativeTransition):
    __slots__ = ('_ledger',)


class QuietReceipt(_NativeTransition):
    __slots__ = ('_observed_ns',)


class TransitionJournalReceipt(_NativeTransition):
    __slots__ = ('_ref', '_flushed_ns')


class TransitionAdmission(_NativeTransition):
    __slots__ = ('_policy', '_source_epoch', '_target_epoch', '_admitted_ns',
                 '_response_deadline_ns', '_next_stop_deadline_ns', '_journal_ref',
                 '_consumed', '_committed')

    source_epoch = property(lambda self: self._source_epoch)
    target_epoch = property(lambda self: self._target_epoch)
    admitted_ns = property(lambda self: self._admitted_ns)
    response_deadline_ns = property(lambda self: self._response_deadline_ns)
    next_stop_deadline_ns = property(lambda self: self._next_stop_deadline_ns)
    journal_ref = property(lambda self: self._journal_ref)


class ParentDeadlines:
    """Four absolute launch-origin deadlines; one registered selection switch."""
    __slots__ = ('_started_ns', '_c0_work_ns', '_c0_hard_ns', '_parent_work_ns',
                 '_parent_hard_ns', '_ticket', '_owner', '_first_owner')

    def __init__(self, started_ns):
        deny(type(started_ns) is int and 0 <= started_ns <= time.monotonic_ns()
             and started_ns <= (1 << 63)-1-180*SECOND, 'parent_origin')
        self._started_ns = started_ns
        self._c0_work_ns = started_ns+85*SECOND
        self._c0_hard_ns = started_ns+90*SECOND
        self._parent_work_ns = started_ns+175*SECOND
        self._parent_hard_ns = started_ns+180*SECOND
        self._ticket = self._owner = self._first_owner = None

    started_ns = property(lambda self: self._started_ns)
    effective_work_ns = property(lambda self: self._c0_work_ns if self._ticket is None
                                 else self._parent_work_ns)
    effective_hard_ns = property(lambda self: self._c0_hard_ns if self._ticket is None
                                 else self._parent_hard_ns)

    def _activate(self, ticket, *, now_ns):
        deny(type(ticket) is TransitionAdmission and self._ticket is None,
             'parent_admission_once')
        value = ticket._owner
        deny(type(value) is NativeTransitionOwner and value is self._owner
             and value._policy is self and value._registered is True
             and value._used is True and any(row is ticket for row in value._tickets)
             and ticket._policy is self and ticket.source_epoch == 'C0'
             and ticket.target_epoch == 'C1', 'parent_admission_identity')
        current = time.monotonic_ns()
        deny(type(now_ns) is int and self.started_ns <= now_ns <= current
             and ticket.admitted_ns <= current, 'parent_admission_clock')
        incomplete(current < min(self._c0_work_ns, value._source_stop_ns+60*SECOND),
                   'parent_admission_expired')
        ticket._admitted_ns = current
        self._first_owner = value
        ticket._committed = True
        # This single final assignment commits selection. An interruption before
        # it retains85/90; an interruption after it retains a committed ticket.
        self._ticket = ticket


class NativeTransitionOwner:
    """Validate held transition evidence; no public registration/fixture issuer."""
    __slots__ = ('_policy', '_wire', '_ledger', '_epoch', '_source_stop_ns',
                 '_admission_started_ns', '_registered', '_held', '_tickets', '_used')

    def __init__(self, *args, **kwargs):
        raise TypeError('parent runtime and wire registration are not released')

    def issue_admission(self, closed, clear, set_receipt, reservation, quiet, journal_ref, *, now_ns):
        policy = self._policy
        deny(type(policy) is ParentDeadlines and policy._owner is self
             and self._registered is True and not self._used
             and self._epoch in ('C0', 'C1'), 'parent_transition_owner')
        if self._epoch == 'C0':
            deny(policy._ticket is None and not self._tickets, 'parent_transition_order')
        else:
            deny(policy._ticket is not None and policy._first_owner is self
                 and len(self._tickets) == 1 and self._tickets[0] is policy._ticket
                 and policy._ticket._consumed is True,
                 'parent_transition_order')
        proofs = (closed, clear, set_receipt, reservation, quiet, journal_ref)
        kinds = (ClosedEpochReceipt, BreakpointClearReceipt, BreakpointSetReceipt,
                 TransitionReservation, QuietReceipt, TransitionJournalReceipt)
        for proof, kind in zip(proofs, kinds):
            deny(type(proof) is kind and self._held.get(kind) is proof
                 and proof._owner is self and proof._wire is self._wire
                 and proof._epoch == self._epoch, 'parent_transition_receipt')
        deny(closed._memory_revoked is True and reservation._ledger is self._ledger,
             'parent_transition_revocation_or_reserve')
        deny(type(now_ns) is int and type(self._source_stop_ns) is int
             and type(self._admission_started_ns) is int
             and policy.started_ns <= self._source_stop_ns <= self._admission_started_ns
             <= now_ns <= time.monotonic_ns(), 'parent_transition_clock')
        deny(type(quiet._observed_ns) is int and type(journal_ref._flushed_ns) is int
             and self._admission_started_ns <= quiet._observed_ns
             <= journal_ref._flushed_ns <= now_ns, 'parent_transition_journal')
        ref = journal_ref._ref
        deny(type(ref) is tuple and len(ref) == 3 and type(ref[0]) is str
             and bool(ref[0]) and '\\' not in ref[0] and '\0' not in ref[0]
             and not PurePosixPath(ref[0]).is_absolute() and '..' not in PurePosixPath(ref[0]).parts
             and PurePosixPath(ref[0]).as_posix() == ref[0]
             and type(ref[1]) is str and len(ref[1]) == 64
             and all(c in '0123456789abcdef' for c in ref[1])
             and type(ref[2]) is int and 0 < ref[2] <= 32 << 20,
             'parent_transition_journal_ref')
        # A caller's earlier observation is not the present clock. Scheduling,
        # journal retention and validation may have consumed its whole window.
        current = time.monotonic_ns()
        source_work = policy.effective_work_ns
        source_stop = self._source_stop_ns+60*SECOND
        incomplete(current < min(source_work, source_stop), 'parent_transition_expired')
        ticket = object.__new__(TransitionAdmission)
        for key, value in dict(_owner=self, _wire=self._wire, _epoch=self._epoch,
                               _policy=policy, _source_epoch=self._epoch,
                               _target_epoch='C1' if self._epoch == 'C0' else 'C2',
                               _admitted_ns=current,
                               _response_deadline_ns=min(self._admission_started_ns+5*SECOND,
                                                         source_work, source_stop),
                               _next_stop_deadline_ns=min(self._admission_started_ns+60*SECOND,
                                                          policy._parent_work_ns),
                               _journal_ref=ref, _consumed=False, _committed=False).items():
            object.__setattr__(ticket, key, value)
        self._used = True
        self._held.clear()
        self._tickets.append(ticket)
        if self._epoch == 'C0':
            policy._activate(ticket, now_ns=now_ns)
        else:
            ticket._committed = True
        return ticket

    def consume_for_send(self, ticket, *, now_ns):
        deny(type(ticket) is TransitionAdmission and ticket._owner is self
             and ticket._wire is self._wire and ticket._policy is self._policy
             and self._registered is True and self._used
             and ticket._committed is True and self._policy._ticket is not None
             and self._policy._first_owner is self
             and ticket.source_epoch == self._epoch
             and any(row is ticket for row in self._tickets) and not ticket._consumed,
             'parent_transition_send_identity')
        deny(type(now_ns) is int and ticket.admitted_ns <= now_ns <= time.monotonic_ns(),
             'parent_transition_send_clock')
        # Consume even when the fixed c-response window has expired: no retry.
        ticket._consumed = True
        incomplete(time.monotonic_ns() < ticket.response_deadline_ns,
                   'parent_transition_send_expired')


TRANSITION_NATIVE_TYPES = (NativeTransitionOwner, ClosedEpochReceipt,
                          BreakpointClearReceipt, BreakpointSetReceipt,
                          TransitionReservation, QuietReceipt,
                          TransitionJournalReceipt, TransitionAdmission)


class ParentOwnedWait(witness.OwnedWait):
    """Reuse actual wait/signals with phase-selected, immutable-origin bounds."""

    def __init__(self, role, policy):
        deny(type(policy) is ParentDeadlines and type(role) is str and 0 < len(role) <= 64,
             'parent_wait_owner')
        self.role, self._policy, self._lease_deadline_ns = role, policy, None
        self.child = None
        self.reaped, self.returncode = False, None
        self.ownership_lost = False
        self.actions, self.lifecycle = [], []
        self.cancelled = False
        self.wait_summary = {'attempts': 0, 'timeouts': 0, 'errors': 0,
                             'first_started_ns': None, 'last_finished_ns': None,
                             'first_errno': None, 'last_errno': None}

    @property
    def deadline(self):
        return self._policy.effective_hard_ns/SECOND

    @property
    def io_deadline(self):
        bound = self._policy.effective_hard_ns
        if self._lease_deadline_ns is not None:
            bound = min(bound, self._lease_deadline_ns)
        return bound/SECOND-0.75

    def _receipt(self, operation, started, result, *, returncode=None, errno=None):
        deny(operation in ('spawn', 'wait', 'signal_term', 'signal_kill', 'close'),
             'parent_lifecycle_operation')
        finished = time.monotonic_ns()
        row = {'role': self.role, 'pid': self.child.pid, 'operation': operation,
               'started_ns': started, 'finished_ns': finished, 'result': result,
               'returncode': returncode, 'errno': errno}
        existing = next((item for item in self.lifecycle if item['operation'] == operation), None)
        if operation == 'wait':
            stats = self.wait_summary
            stats['attempts'] += 1
            stats['timeouts'] += result == 'timeout'
            stats['errors'] += result == 'error'
            if stats['first_started_ns'] is None:
                stats['first_started_ns'] = started
            stats['last_finished_ns'] = finished
            if result == 'error':
                if stats['first_errno'] is None:
                    stats['first_errno'] = errno
                stats['last_errno'] = errno
            row['started_ns'] = stats['first_started_ns']
            if existing is not None:
                existing.update(row)
                return
        deny(existing is None and len(self.lifecycle) < 5, 'parent_lifecycle_capacity')
        self.lifecycle.append(row)

    def _signal(self, sig, action):
        deny((sig, action) in ((signal.SIGTERM, 'SIGTERM'), (signal.SIGKILL, 'SIGKILL'))
             and action not in self.actions
             and not any(row['operation'] == ('signal_term' if sig == signal.SIGTERM else 'signal_kill')
                         for row in self.lifecycle), 'parent_signal_once')
        incomplete(time.monotonic_ns() < self._policy.effective_hard_ns,
                   'parent_signal_deadline')
        return super()._signal(sig, action)

    def wait(self, deadline=None, *, pump=None):
        if deadline is not None:
            deny(type(deadline) in (int, float) and math.isfinite(deadline),
                 'parent_wait_deadline')
        return super().wait(deadline, pump=pump)

    def terminate(self):
        if self.reaped or self.ownership_lost or self.child is None:
            return
        interrupted = [False]
        try:
            with witness.defer_cleanup_interrupt() as interrupted:
                if self.wait(time.monotonic()) is not None:
                    return
                if not any(row['operation'] == 'signal_term' for row in self.lifecycle):
                    self._signal(signal.SIGTERM, 'SIGTERM')
                if self.wait(time.monotonic()+0.25) is not None:
                    return
                if not any(row['operation'] == 'signal_kill' for row in self.lifecycle):
                    self._signal(signal.SIGKILL, 'SIGKILL')
                self.wait(self.deadline)
        finally:
            self.cancelled = self.cancelled or interrupted[0]


class ParentOwnedHelper(witness.OwnedHelper, ParentOwnedWait):
    """Actual helper lifecycle retains its original independent host lease."""

    def __init__(self, role, result_fd, lease_deadline_ns, policy, *, pump=None, budget=None):
        deny(type(policy) is ParentDeadlines and type(result_fd) is int and result_fd >= 0
             and type(lease_deadline_ns) is int and 0 < lease_deadline_ns
             <= min(time.monotonic_ns()+5*SECOND, policy.effective_work_ns),
             'parent_helper_lease')
        # OwnedHelper's super() resolves to ParentOwnedWait in this exact MRO;
        # inherited terminate/close and every wait/drain use the properties above.
        super().__init__(role, result_fd, policy, pump=pump, budget=budget)
        self._lease_deadline_ns = lease_deadline_ns
