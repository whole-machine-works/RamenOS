"""One monotone parent ledger; reservations are accounting, never RAM grants."""
from dataclasses import dataclass
import time
from types import MappingProxyType

from boot_profile_capture import deny, incomplete
from run0_c0_decode import SELECTED_REGISTERS
from run0_call_read import (ReadKey, ReadTarget, EPOCHS, MAX_READS, _int, _epoch,
                            packet_copy_bound, metadata_bound, target_part_limit)

MAX_BYTES = 32*1024*1024
REPORT_BYTES = 1024*1024
FAILURE_BYTES = 128*1024
REGULAR_BYTES = MAX_BYTES-REPORT_BYTES-FAILURE_BYTES
MAX_OPERATIONS = 1024
PHASE_OPERATIONS = 512
_SELECTED = tuple(f'p{n:x}' for n in SELECTED_REGISTERS)
_HOST = ('query_status', 'query_cpus_fast', 'qom_realized', 'qom_phys_bits', 'hmp_registers')
_COMMON_BEFORE = ('stop_ack', 'query_status', 'physical_mode_query')+_SELECTED+_HOST+_HOST+('hmp_flatview',)
BEFORE = MappingProxyType({'C0': ('hardware_breakpoint_set', 'continue')+_COMMON_BEFORE,
                           'C1': _COMMON_BEFORE, 'C2': _COMMON_BEFORE})
_AFTER = _SELECTED+('hmp_registers', 'hmp_flatview', 'hardware_breakpoint_clear')
AFTER = MappingProxyType({'C0': _AFTER+('hardware_breakpoint_set', 'continue'),
                          'C1': _AFTER+('hardware_breakpoint_set', 'continue'),
                          'C2': _AFTER+('quit',)})
# This is a closed name inventory, not proof of the actual bootstrap sequence.
# The future wire must validate that protocol; this ledger charges each real row.
BOOTSTRAP_NAMES = frozenset(('qmp_capabilities', 'query_commands', 'query_status',
    'supported', 'thread_first', 'thread_next', 'thread_current', 'thread_general',
    'thread_continue', 'target_read', 'core_read', 'reset_registers', 'qemu_supported',
    'physical_mode_query', 'physical_mode_enable'))


@dataclass(frozen=True, slots=True)
class ReadCharge:
    target: ReadTarget
    packet_copy_bound: int
    metadata_bound: int

    @classmethod
    def for_target(cls, target):
        return cls(target, packet_copy_bound(target), metadata_bound(target))

    def __post_init__(self):
        deny(type(self.target) is ReadTarget, 'call_budget_target')
        _int(self.packet_copy_bound, 1, 65536)
        _int(self.metadata_bound, 1, 65536)
        deny(self.packet_copy_bound == packet_copy_bound(self.target)
             and self.metadata_bound == metadata_bound(self.target), 'call_budget_copy_plan')


@dataclass(frozen=True, slots=True, init=False)
class ReadBatchReservation:
    owner: object
    epoch: str
    charges: tuple

    def __init__(self, *args, **kwargs):
        raise TypeError('accounting reservations are privately held, not read authority')


class ParentAccounting:
    """Monotone allocated-row/copy accounting, never admission/send evidence.

    A read row is allocated by _claim before protocol admission. The future
    exclusive wire must install its separate held attempt at admission before
    ANY first-byte send attempt, including zero/partial sends. No such issuer
    exists in this subset. Allocated rows are never refunded or replayed.
    """
    def __init__(self, started_ns):
        _int(started_ns)
        deny(started_ns <= time.monotonic_ns(), 'call_budget_start')
        self.started_ns = started_ns
        self._regular = self._actual_bytes = self._operations = self._reserved_reads = 0
        self._phase_ops = [0, 0, 0]
        self._epoch_index = 0
        self._before = self._after = 0
        self._stage = 'bootstrap'
        self._terminal = {'report': 0, 'failure': 0}
        self._batches = {}
        self._claimed = {}
        self._next_request = 1
        self._frames = [set(), set(), set()]
        self._objects = [set(), set(), set()]
        self._parts = [0, 0, 0]

    def _remaining_controls(self):
        if self._stage == 'done':
            return 0
        index = self._epoch_index
        current = len(BEFORE[EPOCHS[index]])-self._before+len(AFTER[EPOCHS[index]])-self._after
        return current+sum(len(BEFORE[e])+len(AFTER[e]) for e in EPOCHS[index+1:])

    def view(self):
        return MappingProxyType(dict(started_ns=self.started_ns,
            committed_bytes=self._regular+sum(self._terminal.values()),
            actual_bytes=self._actual_bytes, actual_operations=self._operations,
            allocated_operations=self._operations,
            committed_operations=self._operations+self._reserved_reads+self._remaining_controls(),
            remaining_controls=self._remaining_controls(), physical_reserved=sum(
                len(row['reservation'].charges) for row in self._batches.values()),
            physical_claimed=self._next_request-1, epoch=EPOCHS[self._epoch_index],
            stage=self._stage, phase_operations=tuple(self._phase_ops),
            frames=tuple(len(s) for s in self._frames), objects=tuple(len(s) for s in self._objects),
            first_parts=tuple(self._parts)))

    def reserve_output(self, length, *, purpose='output'):
        _int(length, 0, REGULAR_BYTES)
        deny(type(purpose) is str and purpose == 'output', 'call_budget_output_purpose')
        incomplete(length <= REGULAR_BYTES-self._regular, 'call_budget_storage')
        self._regular += length
        self._actual_bytes += length

    def reserve_operation(self, epoch, kind):
        _epoch(epoch)
        deny(type(kind) is str and epoch == EPOCHS[self._epoch_index], 'call_budget_operation_epoch')
        index = self._epoch_index
        bootstrap = kind.startswith('bootstrap:')
        if bootstrap:
            deny(index == 0 and self._stage == 'bootstrap'
                 and kind[10:] in BOOTSTRAP_NAMES, 'call_budget_bootstrap')
        elif self._stage in ('bootstrap', 'before'):
            deny(self._before < len(BEFORE[epoch]) and kind == BEFORE[epoch][self._before],
                 'call_budget_before_order')
        else:
            deny(self._stage in ('memory', 'after') and self._reserved_reads == 0
                 and self._after < len(AFTER[epoch]) and kind == AFTER[epoch][self._after],
                 'call_budget_after_order')
        # Controls consume one already-reserved control; bootstrap adds a new row.
        future = self._remaining_controls() if bootstrap else self._remaining_controls()-1
        incomplete(self._operations+1+self._reserved_reads+future <= MAX_OPERATIONS
                   and self._phase_ops[index]+1+sum(
                       len(row['reservation'].charges)-len(row['claimed'])
                       for row in self._batches.values() if row['reservation'].epoch == epoch)
                   + (len(BEFORE[epoch])-self._before+len(AFTER[epoch])-self._after
                      if bootstrap else len(BEFORE[epoch])-self._before+len(AFTER[epoch])-self._after-1)
                   <= PHASE_OPERATIONS, 'call_budget_operations')
        self._operations += 1
        self._phase_ops[index] += 1
        if bootstrap:
            return
        if self._stage in ('bootstrap', 'before'):
            self._before += 1
            self._stage = 'memory' if self._before == len(BEFORE[epoch]) else 'before'
        else:
            self._after += 1
            self._stage = 'after'
            if self._after == len(AFTER[epoch]):
                if index == 2:
                    self._stage = 'done'
                else:
                    self._epoch_index += 1
                    self._before = self._after = 0
                    self._stage = 'before'

    def reserve_reads(self, epoch, requests):
        _epoch(epoch)
        deny(epoch == EPOCHS[self._epoch_index] and self._stage == 'memory'
             and type(requests) is tuple and 0 < len(requests) <= MAX_READS
             and all(type(item) is ReadCharge for item in requests), 'call_budget_read_phase')
        index = self._epoch_index
        groups = {}
        for charge in requests:
            charge.__post_init__()
            target = charge.target
            deny(target.kind != 'object' or target.target_ordinal < (8, 8, 7)[index],
                 'call_budget_object_ordinal')
            groups.setdefault((target.kind, target.target_ordinal), []).append(target)
        frames, objects, parts = set(), set(), 0
        for (kind, ordinal), targets in groups.items():
            seen = self._frames[index] if kind == 'frame' else self._objects[index]
            deny(ordinal not in seen, 'call_budget_target_reused')
            first = [t for t in targets if t.pass_index == 0]
            recheck = [t for t in targets if t.pass_index == 1]
            deny(first and len(first) == len(recheck), 'call_budget_recheck_plan')
            deny(len(first) <= target_part_limit(epoch, kind, ordinal), 'call_budget_target_parts')
            offset = 0
            for a, z in zip(first, recheck):
                deny(a.logical_offset == offset and
                     (a.logical_offset, a.gpa, a.length) == (z.logical_offset, z.gpa, z.length),
                     'call_budget_frozen_parts')
                offset += a.length
            if kind == 'frame':
                deny(offset == 4096 and len(first) == 2
                     and all(part.gpa-part.logical_offset == first[0].gpa for part in targets),
                     'call_budget_frame_plan')
                frames.add(ordinal)
            else:
                deny(offset <= 32768, 'call_budget_object_length')
                objects.add(ordinal)
                parts += len(first)
        incomplete(len(self._frames[index])+len(frames) <= 32
                   and len(self._objects[index])+len(objects) <= (8, 8, 7)[index]
                   and self._parts[index]+parts <= (16, 16, 29)[index], 'call_budget_shape_limit')
        physical = sum(len(row['reservation'].charges) for row in self._batches.values())
        incomplete(physical+len(requests) <= MAX_READS, 'call_budget_physical_limit')
        amount = sum(8*c.target.length+2048+2*c.target.length+c.packet_copy_bound+c.metadata_bound
                     for c in requests)
        outstanding_phase = sum(len(row['reservation'].charges)-len(row['claimed'])
                                for row in self._batches.values() if row['reservation'].epoch == epoch)
        incomplete(amount <= REGULAR_BYTES-self._regular
                   and self._operations+self._reserved_reads+len(requests)+self._remaining_controls()
                   <= MAX_OPERATIONS
                   and self._phase_ops[index]+outstanding_phase+len(requests)+len(AFTER[epoch])
                   <= PHASE_OPERATIONS, 'call_budget_batch_limit')
        reservation = object.__new__(ReadBatchReservation)
        for name, value in (('owner', self), ('epoch', epoch), ('charges', requests)):
            object.__setattr__(reservation, name, value)
        self._regular += amount
        self._reserved_reads += len(requests)
        self._frames[index].update(frames)
        self._objects[index].update(objects)
        self._parts[index] += parts
        self._batches[id(reservation)] = dict(reservation=reservation, claimed=set())
        return reservation

    def _claim(self, reservation, item_ordinal, key, target):
        # Allocate/bind one accounting row, not a protocol capability admission.
        # view.actual_operations is retained as an alias of allocated_operations.
        deny(type(reservation) is ReadBatchReservation and reservation.owner is self
             and self._batches.get(id(reservation), {}).get('reservation') is reservation,
             'call_budget_reservation_identity')
        _int(item_ordinal, 0, len(reservation.charges)-1)
        deny(type(key) is ReadKey and type(target) is ReadTarget
             and self._stage == 'memory' and key.epoch == reservation.epoch == EPOCHS[self._epoch_index]
             and key.request_id == self._next_request and key.operation_seq == self._operations+1
             and target == reservation.charges[item_ordinal].target, 'call_budget_claim_identity')
        row = self._batches[id(reservation)]
        deny(item_ordinal == len(row['claimed']) and item_ordinal not in row['claimed'],
             'call_budget_claim_reused')
        charge = reservation.charges[item_ordinal]
        row['claimed'].add(item_ordinal)
        self._claimed[key] = dict(reservation=reservation, item=item_ordinal,
            remaining={'read': 8*target.length+2048, 'decoded_file': target.length,
                       'assembly_file': target.length,
                       'packet_copy': charge.packet_copy_bound, 'metadata': charge.metadata_bound})
        self._next_request += 1
        self._reserved_reads -= 1
        self._operations += 1
        self._phase_ops[self._epoch_index] += 1

    def debit_read(self, reservation, key, length, *, purpose):
        _int(length, 0, REGULAR_BYTES)
        deny(type(key) is ReadKey and key in self._claimed
             and self._claimed[key]['reservation'] is reservation
             and type(purpose) is str and purpose in self._claimed[key]['remaining'],
             'call_budget_credit_identity')
        remaining = self._claimed[key]['remaining']
        incomplete(length <= remaining[purpose], 'call_budget_credit_exhausted')
        remaining[purpose] -= length
        self._actual_bytes += length

    def redeem_terminal(self, length, *, purpose):
        _int(length, 0, MAX_BYTES)
        deny(type(purpose) is str and purpose in self._terminal, 'call_budget_terminal_purpose')
        cap = REPORT_BYTES if purpose == 'report' else FAILURE_BYTES
        incomplete(length <= cap-self._terminal[purpose], 'call_budget_terminal_limit')
        self._terminal[purpose] += length
        self._actual_bytes += length
