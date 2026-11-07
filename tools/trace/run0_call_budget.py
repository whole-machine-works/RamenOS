"""One monotone parent ledger; reservations are accounting, never RAM grants."""
from dataclasses import dataclass
from contextlib import contextmanager
import time
from types import MappingProxyType

from boot_profile_capture import deny, incomplete, ProbeError
from run0_c0_decode import SELECTED_REGISTERS
from run0_call_read import (ReadKey, ReadTarget, EPOCHS, MAX_READS, _int, _epoch,
                            packet_copy_bound, metadata_bound, target_part_limit,
                            packet_copy_upper_bound, metadata_copy_bound)
from run0_c0_paging import canonical_span, C0DecodeError

MAX_BYTES = 32*1024*1024
REPORT_BYTES = 1024*1024
FAILURE_BYTES = 128*1024
REGULAR_BYTES = MAX_BYTES-REPORT_BYTES-FAILURE_BYTES
MAX_OPERATIONS = 1024
PHASE_OPERATIONS = 512
WIRE_READ_PER_BYTE = 14
WIRE_READ_FIXED = 9216
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


@dataclass(frozen=True, slots=True, init=False)
class C2DiscoveryCapacity:
    owner: object
    map_virtual: int
    map_length: int
    max_parts: int
    frame_ordinals: tuple

    def __init__(self, *args, **kwargs):
        raise TypeError('discovery capacity is private accounting, not read authority')


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
        self._capacity = None
        self._discovery_state = 'none'
        self._potential_reads = self._potential_parts = self._potential_objects = 0
        self._potential_frames = ()
        self._wire_batches = {}
        self._wire_capacity = None
        self._wire_committed = self._wire_debited = 0
        self._aborted = False

    def _live(self):
        deny(not self._aborted, 'call_budget_aborted')

    @contextmanager
    def _mutation(self):
        """Once discovery exists, partial read/control commits cannot be reused.

        Set the latch before the first mutation and clear it only after the
        whole body completes. Exception propagation needs no later mutation
        to make the failure safe. Ordinary pre-discovery behavior is unchanged.
        """
        self._live()
        if self._capacity is None and not self._wire_committed:
            yield
            return
        self._aborted = True
        yield
        self._aborted = False

    def _discovery(self, capacity):
        self._live()
        deny(type(capacity) is C2DiscoveryCapacity and self._capacity is capacity
             and capacity.owner is self and self._epoch_index == 2
             and self._stage == 'memory' and self._discovery_state == 'open',
             'call_budget_discovery_identity')

    @staticmethod
    def _wire_read_cost(length):
        _int(length, 1, 2048)
        return WIRE_READ_PER_BYTE*length + WIRE_READ_FIXED

    def reserve_wire_batch(self, reservation):
        """Prepay additional runtime wire copies; issue no key or read grant.

        Legacy read/retention costs stay unchanged. This separate, permanent
        charge must precede a runtime batch's first grant and accounting claim.
        It does not prove the future wire's complete allocation schedule.
        """
        self._live()
        deny(type(reservation) is ReadBatchReservation and reservation.owner is self,
             'call_budget_wire_batch_identity')
        row = self._batches.get(id(reservation))
        deny(type(row) is dict and row.get('reservation') is reservation
             and not row['claimed'] and id(reservation) not in self._wire_batches
             and self._stage == 'memory' and reservation.epoch == EPOCHS[self._epoch_index],
             'call_budget_wire_batch_phase')
        if reservation.epoch == 'C2' and self._capacity is not None:
            # Discovery targets must have prepaid wire capacity before walking,
            # rather than paying for an already materialized batch afterward.
            deny(not any((charge.target.kind == 'frame'
                          and charge.target.target_ordinal in self._capacity.frame_ordinals)
                         or (charge.target.kind == 'object' and charge.target.target_ordinal == 6)
                         for charge in reservation.charges), 'call_budget_wire_discovery_late')
        credits = [self._wire_read_cost(charge.target.length) for charge in reservation.charges]
        amount = sum(credits)
        incomplete(amount <= REGULAR_BYTES-self._regular, 'call_budget_wire_storage')
        self._aborted = True
        try:
            self._regular += amount
            self._wire_committed += amount
            self._wire_batches[id(reservation)] = dict(reservation=reservation, remaining=credits)
            self._aborted = False
        except BaseException:
            self._aborted = True
            raise

    def reserve_wire_discovery(self, capacity):
        """Prepay unknown C2 wire targets in the same ledger before full-M walk."""
        self._discovery(capacity)
        deny(self._wire_capacity is None and self._potential_frames == capacity.frame_ordinals
             and self._potential_parts == capacity.max_parts and 6 not in self._objects[2],
             'call_budget_wire_discovery_phase')
        frames, parts = len(capacity.frame_ordinals), capacity.max_parts
        reads = 4*frames + 2*parts
        length = 4*frames*2048 + 2*capacity.map_length
        amount = WIRE_READ_PER_BYTE*length + WIRE_READ_FIXED*reads
        incomplete(amount <= REGULAR_BYTES-self._regular, 'call_budget_wire_storage')
        prepaid = dict(capacity=capacity, remaining=amount)
        self._aborted = True
        try:
            self._regular += amount
            self._wire_committed += amount
            self._wire_capacity = prepaid
            self._aborted = False
        except BaseException:
            self._aborted = True
            raise

    def debit_wire_read(self, reservation, key, count):
        """Spend only this actual claimed item's prepaid logical wire credit."""
        self._live()
        _int(count, 0, REGULAR_BYTES)
        deny(type(key) is ReadKey and key in self._claimed
             and self._claimed[key]['reservation'] is reservation,
             'call_budget_wire_claim_identity')
        row = self._wire_batches.get(id(reservation))
        deny(type(row) is dict and row.get('reservation') is reservation,
             'call_budget_wire_unreserved')
        item = self._claimed[key]['item']
        incomplete(count <= row['remaining'][item], 'call_budget_wire_credit_exhausted')
        with self._mutation():
            row['remaining'][item] -= count
            self._actual_bytes += count
            self._wire_debited += count

    @staticmethod
    def _unknown_read_cost(length):
        return (8*length+2048+2*length+packet_copy_upper_bound(length)
                + metadata_copy_bound())

    def reserve_c2_discovery_capacity(self, *, map_virtual, map_length):
        """Prepay possible discovery, without issuing a target, key or grant."""
        self._live()
        deny(self._epoch_index == 2 and self._stage == 'memory'
             and self._capacity is None and 6 not in self._objects[2],
             'call_budget_discovery_phase')
        _int(map_length, 1, 32768)
        _int(map_virtual, 0, (1 << 64)-1)
        try:
            canonical_span(map_virtual, map_length)
        except C0DecodeError as error:
            raise ProbeError(error.status, error.reason) from error
        frames = tuple(i for i in range(32) if i not in self._frames[2])
        parts = min(17, map_length)
        reads = 4*len(frames)+2*parts
        # Aggregate length is known; its eventual partition and GPAs are not.
        amount = (4*len(frames)*self._unknown_read_cost(2048)
                  +54*map_length+2*parts*(2243+metadata_copy_bound()))
        outstanding = sum(len(row['reservation'].charges)-len(row['claimed'])
                          for row in self._batches.values()
                          if row['reservation'].epoch == 'C2')
        physical = sum(len(row['reservation'].charges) for row in self._batches.values())
        incomplete(self._parts[2]+parts <= 29 and len(self._objects[2])+1 <= 7
                   and physical+reads <= MAX_READS
                   and self._operations+self._reserved_reads+reads+self._remaining_controls()
                   <= MAX_OPERATIONS
                   and self._phase_ops[2]+outstanding+reads+len(AFTER['C2']) <= PHASE_OPERATIONS
                   and amount <= REGULAR_BYTES-self._regular, 'call_budget_discovery_limit')
        cap = object.__new__(C2DiscoveryCapacity)
        for name, value in (('owner', self), ('map_virtual', map_virtual),
                            ('map_length', map_length), ('max_parts', parts),
                            ('frame_ordinals', frames)):
            object.__setattr__(cap, name, value)
        # The latch precedes every mutation. An interrupted partial commit
        # cannot be retried or mistaken for usable capacity. Output-only
        # cleanup accounting remains available even while aborted.
        self._aborted = True
        try:
            self._capacity = cap
            self._regular += amount
            self._potential_frames = frames
            self._potential_reads = reads
            self._potential_parts = parts
            self._potential_objects = 1
            self._discovery_state = 'open'
            self._aborted = False
            return cap
        except BaseException:
            self._aborted = True
            raise

    def materialize_c2_frame(self, capacity, *, ordinal, physical):
        self._discovery(capacity)
        _int(ordinal, 0, 31)
        _int(physical, 0, (1 << 64)-4096)
        deny(physical % 4096 == 0 and self._potential_frames
             and ordinal == self._potential_frames[0], 'call_budget_discovery_frame')
        requests = tuple(ReadCharge.for_target(ReadTarget('frame', p, ordinal, off,
                                                         physical+off, 2048))
                         for p in (0, 1) for off in (0, 2048))
        return self._materialize(capacity, requests, frame=ordinal)

    def materialize_c2_map(self, capacity, *, requests):
        self._discovery(capacity)
        deny(type(requests) is tuple and 0 < len(requests) <= 2*capacity.max_parts
             and len(requests) % 2 == 0, 'call_budget_discovery_map')
        count = len(requests)//2
        for charge in requests:
            deny(type(charge) is ReadCharge, 'call_budget_discovery_charge')
            charge.__post_init__()
            charge.target.__post_init__()
            deny(charge.target.kind == 'object' and charge.target.target_ordinal == 6,
                 'call_budget_discovery_map_role')
        offset = 0
        for first, recheck in zip(requests[:count], requests[count:]):
            a, z = first.target, recheck.target
            deny(a.pass_index == 0 and z.pass_index == 1 and a.logical_offset == offset
                 and (a.logical_offset, a.gpa, a.length) == (z.logical_offset, z.gpa, z.length),
                 'call_budget_discovery_map_parts')
            offset += a.length
        deny(offset == capacity.map_length, 'call_budget_discovery_map_length')
        return self._materialize(capacity, requests, frame=None)

    def _materialize(self, capacity, requests, *, frame):
        # Closed callers validate all native targets before any ledger mutation.
        self._discovery(capacity)
        exact = sum(10*c.target.length+2048+c.packet_copy_bound+c.metadata_bound
                    for c in requests)
        bound = (4*self._unknown_read_cost(2048) if frame is not None else
                 54*capacity.map_length+2*capacity.max_parts*(2243+metadata_copy_bound()))
        deny(exact <= bound and len(requests) <= self._potential_reads,
             'call_budget_discovery_transfer')
        batch = object.__new__(ReadBatchReservation)
        for name, value in (('owner', self), ('epoch', 'C2'), ('charges', requests)):
            object.__setattr__(batch, name, value)
        wire_batches, wire_amount = None, 0
        if self._wire_capacity is not None:
            deny(self._wire_capacity['capacity'] is capacity, 'call_budget_wire_capacity_identity')
            wire_credits = [self._wire_read_cost(charge.target.length) for charge in requests]
            wire_amount = sum(wire_credits)
            deny(wire_amount <= self._wire_capacity['remaining'], 'call_budget_wire_transfer')
            wire_batches = dict(self._wire_batches)
            wire_batches[id(batch)] = dict(reservation=batch, remaining=wire_credits)
        batches = dict(self._batches)
        batches[id(batch)] = dict(reservation=batch, claimed=set())
        frames = [set(items) for items in self._frames]
        objects = [set(items) for items in self._objects]
        parts = list(self._parts)
        if frame is not None:
            frames[2].add(frame)
            potential_frames = self._potential_frames[1:]
            potential_parts, potential_objects = self._potential_parts, self._potential_objects
            state = 'open'
        else:
            objects[2].add(6)
            count = len(requests)//2
            parts[2] += count
            potential_frames = self._potential_frames
            potential_parts, potential_objects = self._potential_parts-count, 0
            state = 'sealed'
        self._aborted = True
        try:
            # No additional regular-byte debit: unused upper credit stays held.
            self._batches = batches
            if wire_batches is not None:
                self._wire_batches = wire_batches
                self._wire_capacity['remaining'] -= wire_amount
            self._frames, self._objects, self._parts = frames, objects, parts
            self._potential_frames = potential_frames
            self._potential_parts, self._potential_objects = potential_parts, potential_objects
            self._potential_reads -= len(requests)
            self._reserved_reads += len(requests)
            self._discovery_state = state
            self._aborted = False
            return batch
        except BaseException:
            self._aborted = True
            raise

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
            committed_operations=self._operations+self._reserved_reads+self._potential_reads
                                 +self._remaining_controls(),
            remaining_controls=self._remaining_controls(), physical_reserved=sum(
                len(row['reservation'].charges) for row in self._batches.values()),
            physical_claimed=self._next_request-1, epoch=EPOCHS[self._epoch_index],
            stage=self._stage, phase_operations=tuple(self._phase_ops),
            frames=tuple(len(s) for s in self._frames), objects=tuple(len(s) for s in self._objects),
            first_parts=tuple(self._parts), potential_reads=self._potential_reads,
            potential_frames=len(self._potential_frames), potential_parts=self._potential_parts,
            potential_objects=self._potential_objects, discovery_state=self._discovery_state,
            wire_committed_bytes=self._wire_committed, wire_debited_bytes=self._wire_debited,
            wire_discovery_remaining=(0 if self._wire_capacity is None else
                                      self._wire_capacity['remaining']),
            aborted=self._aborted))

    def reserve_output(self, length, *, purpose='output'):
        _int(length, 0, REGULAR_BYTES)
        deny(type(purpose) is str and purpose == 'output', 'call_budget_output_purpose')
        incomplete(length <= REGULAR_BYTES-self._regular, 'call_budget_storage')
        self._regular += length
        self._actual_bytes += length

    def reserve_operation(self, epoch, kind):
        self._live()
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
                 and self._discovery_state != 'open'
                 and self._after < len(AFTER[epoch]) and kind == AFTER[epoch][self._after],
                 'call_budget_after_order')
        # Controls consume one already-reserved control; bootstrap adds a new row.
        future = self._remaining_controls() if bootstrap else self._remaining_controls()-1
        incomplete(self._operations+1+self._reserved_reads+self._potential_reads+future
                   <= MAX_OPERATIONS
                   and self._phase_ops[index]+1+sum(
                       len(row['reservation'].charges)-len(row['claimed'])
                       for row in self._batches.values() if row['reservation'].epoch == epoch)
                   + (self._potential_reads if index == 2 else 0)
                   + (len(BEFORE[epoch])-self._before+len(AFTER[epoch])-self._after
                      if bootstrap else len(BEFORE[epoch])-self._before+len(AFTER[epoch])-self._after-1)
                   <= PHASE_OPERATIONS, 'call_budget_operations')
        with self._mutation():
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
        self._live()
        _epoch(epoch)
        deny(epoch == EPOCHS[self._epoch_index] and self._stage == 'memory'
             and type(requests) is tuple and 0 < len(requests) <= MAX_READS
             and all(type(item) is ReadCharge for item in requests), 'call_budget_read_phase')
        index = self._epoch_index
        groups = {}
        for charge in requests:
            charge.__post_init__()
            target = charge.target
            deny(not (epoch == 'C2' and self._capacity is not None
                      and (target.kind == 'frame' or target.target_ordinal == 6)),
                 'call_budget_discovery_exclusive')
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
        incomplete(len(self._frames[index])+len(frames)
                   +(len(self._potential_frames) if index == 2 else 0) <= 32
                   and len(self._objects[index])+len(objects)
                   +(self._potential_objects if index == 2 else 0) <= (8, 8, 7)[index]
                   and self._parts[index]+parts+(self._potential_parts if index == 2 else 0)
                   <= (16, 16, 29)[index], 'call_budget_shape_limit')
        physical = sum(len(row['reservation'].charges) for row in self._batches.values())
        incomplete(physical+len(requests)+self._potential_reads <= MAX_READS,
                   'call_budget_physical_limit')
        amount = sum(8*c.target.length+2048+2*c.target.length+c.packet_copy_bound+c.metadata_bound
                     for c in requests)
        outstanding_phase = sum(len(row['reservation'].charges)-len(row['claimed'])
                                for row in self._batches.values() if row['reservation'].epoch == epoch)
        incomplete(amount <= REGULAR_BYTES-self._regular
                   and self._operations+self._reserved_reads+self._potential_reads
                   +len(requests)+self._remaining_controls()
                   <= MAX_OPERATIONS
                   and self._phase_ops[index]+outstanding_phase+len(requests)+len(AFTER[epoch])
                   +(self._potential_reads if index == 2 else 0)
                   <= PHASE_OPERATIONS, 'call_budget_batch_limit')
        reservation = object.__new__(ReadBatchReservation)
        for name, value in (('owner', self), ('epoch', epoch), ('charges', requests)):
            object.__setattr__(reservation, name, value)
        with self._mutation():
            self._regular += amount
            self._reserved_reads += len(requests)
            self._frames[index].update(frames)
            self._objects[index].update(objects)
            self._parts[index] += parts
            self._batches[id(reservation)] = dict(reservation=reservation, claimed=set())
        return reservation

    def _claim(self, reservation, item_ordinal, key, target):
        self._live()
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
        with self._mutation():
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
        self._live()
        _int(length, 0, REGULAR_BYTES)
        deny(type(key) is ReadKey and key in self._claimed
             and self._claimed[key]['reservation'] is reservation
             and type(purpose) is str and purpose in self._claimed[key]['remaining'],
             'call_budget_credit_identity')
        remaining = self._claimed[key]['remaining']
        incomplete(length <= remaining[purpose], 'call_budget_credit_exhausted')
        with self._mutation():
            remaining[purpose] -= length
            self._actual_bytes += length

    def redeem_terminal(self, length, *, purpose):
        _int(length, 0, MAX_BYTES)
        deny(type(purpose) is str and purpose in self._terminal, 'call_budget_terminal_purpose')
        cap = REPORT_BYTES if purpose == 'report' else FAILURE_BYTES
        incomplete(length <= cap-self._terminal[purpose], 'call_budget_terminal_limit')
        self._terminal[purpose] += length
        self._actual_bytes += length
