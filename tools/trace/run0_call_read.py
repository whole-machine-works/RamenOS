"""Parent retained-read subset; no guest reader or production receipt issuer.

The disabled native constructors are intentional. A later independently reviewed
owned CallWire/collector must register actual origins. Byte-verified retention
alone confers no current-stop or RAM authority. Test fixtures stay test-local.
"""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

from boot_profile_capture import deny, incomplete, ProbeError
import run0_rsp as rsp

EPOCHS = ('C0', 'C1', 'C2')
MAX_READS = 506
MAX_ROW_BYTES = 8192
MAX_BYTES = 32*1024*1024


def target_part_limit(epoch, kind, ordinal):
    """Per-target cap; the separate C2 phase total remains29, parent61."""
    _epoch(epoch)
    deny(type(kind) is str and kind in ('frame', 'object'), 'call_read_target_kind')
    _int(ordinal, 0, 31 if kind == 'frame' else (6 if epoch == 'C2' else 7))
    return 2 if kind == 'frame' else 17 if epoch == 'C2' and ordinal == 6 else 16


def _int(value, low=0, high=(1 << 63)-1):
    deny(type(value) is int and low <= value <= high, 'call_read_integer')
    return value


def _epoch(value):
    deny(type(value) is str and value in EPOCHS, 'call_read_epoch')
    return value


@dataclass(frozen=True, slots=True)
class BlobRef:
    path: str
    sha256: str
    length: int

    def __post_init__(self):
        deny(type(self.path) is str and len(self.path) <= 256 and self.path.isascii()
             and not any(c in self.path for c in ('\\', '\x00'))
             and all(part not in ('', '.', '..') for part in self.path.split('/')),
             'call_read_ref_path')
        deny(type(self.sha256) is str and re.fullmatch('[0-9a-f]{64}', self.sha256) is not None,
             'call_read_ref_hash')
        _int(self.length, 0, MAX_BYTES)

    def as_json(self):
        return dict(path=self.path, sha256=self.sha256, length=self.length)


@dataclass(frozen=True, slots=True)
class RawSlice:
    blob: BlobRef
    offset: int
    length: int

    def __post_init__(self):
        deny(type(self.blob) is BlobRef, 'call_read_slice_ref')
        _int(self.offset)
        _int(self.length, 1)
        deny(self.offset+self.length <= self.blob.length, 'call_read_slice_bounds')

    def as_json(self):
        return dict(blob=self.blob.as_json(), offset=self.offset, length=self.length)


@dataclass(frozen=True, slots=True)
class LiveWirePosition:
    stream: str
    offset: int
    length: int

    def __post_init__(self):
        deny(type(self.stream) is str and self.stream in ('rsp', 'rsp-out'),
             'call_read_live_stream')
        _int(self.offset, 0, MAX_BYTES)
        _int(self.length, 1, MAX_BYTES)
        deny(self.offset+self.length <= MAX_BYTES, 'call_read_live_bounds')

    def as_json(self):
        return dict(stream=self.stream, offset=self.offset, length=self.length)


@dataclass(frozen=True, slots=True)
class ReadKey:
    """Allocated accounting identity; only a held attempt proves admission."""
    epoch: str
    request_id: int
    physical_ordinal: int
    operation_seq: int

    def __post_init__(self):
        _epoch(self.epoch)
        _int(self.request_id, 1, MAX_READS)
        _int(self.physical_ordinal, 0, MAX_READS-1)
        _int(self.operation_seq, 1, 1024)
        deny(self.physical_ordinal == self.request_id-1, 'call_read_ordinal')


@dataclass(frozen=True, slots=True)
class ReadTarget:
    kind: str
    pass_index: int
    target_ordinal: int
    logical_offset: int
    gpa: int
    length: int

    def __post_init__(self):
        deny(type(self.kind) is str and self.kind in ('frame', 'object'), 'call_read_target')
        _int(self.pass_index, 0, 1)
        _int(self.target_ordinal, 0, 31 if self.kind == 'frame' else 7)
        _int(self.logical_offset, 0, 32767)
        _int(self.gpa, 0, (1 << 64)-1)
        _int(self.length, 1, 2048)
        deny(self.gpa+self.length <= (1 << 64), 'call_read_address_wrap')
        if self.kind == 'frame':
            deny(self.logical_offset in (0, 2048) and self.length == 2048
                 and (self.gpa-self.logical_offset) % 4096 == 0, 'call_read_frame_part')
        else:
            deny(self.logical_offset+self.length <= 32768, 'call_read_object_part')


@dataclass(frozen=True, slots=True, init=False)
class NativePhysicalReadReceipt:
    parent: object
    session: object
    binding: object
    transport_identity: tuple
    epoch: str
    request_id: int
    physical_ordinal: int
    operation_seq: int
    target_kind: str
    pass_index: int
    target_ordinal: int
    logical_offset: int
    physical: int
    length: int
    request_position: LiveWirePosition
    request_ack_position: LiveWirePosition
    response_position: LiveWirePosition
    response_ack_position: LiveWirePosition
    request_ref: BlobRef
    response_ref: BlobRef
    payload_ref: RawSlice
    decoded_data_ref: BlobRef
    request_bytes: bytes
    response_bytes: bytes
    response_payload: bytes
    data: bytes
    started_ns: int
    response_received_ns: int
    finished_ns: int
    result: str

    def __init__(self, *args, **kwargs):
        raise TypeError('actual owned CallWire receipt issuer is not registered')


@dataclass(frozen=True, slots=True, init=False)
class PendingReadRetention:
    owner: object
    reservation: object
    item_ordinal: int
    key: ReadKey
    target: ReadTarget

    def __init__(self, *args, **kwargs):
        raise TypeError('pending retention is private and is not a read grant')


@dataclass(frozen=True, slots=True, init=False)
class _HeldReadAttempt:
    """Actual protocol admission; no public or production issuer exists.

    Future exclusive wire installs this exact held identity at admission BEFORE
    ANY first-byte send attempt. Zero/partial send failures still have an actual
    attempt; prepare alone does not. ACK-stage proof must point to this identity.
    """
    _parent: object
    _wire: object
    key: ReadKey
    target: ReadTarget
    started_ns: int
    finished_ns: int | None
    result: str

    def __init__(self, *args, **kwargs):
        raise TypeError('actual owned CallWire attempt issuer is not registered')


@dataclass(frozen=True, slots=True, init=False)
class _HeldReadOperation:
    """Private ACK-stage proof, not a completed final OperationRow.

    Future actual wire finalization must use the measured retention commit for
    its final operation/receipt join. This module has no issuer for this proof.
    """
    _parent: object
    _wire: object
    attempt: _HeldReadAttempt
    key: ReadKey
    target: ReadTarget
    request_position: LiveWirePosition
    request_ack_position: LiveWirePosition
    response_position: LiveWirePosition
    response_ack_position: LiveWirePosition
    started_ns: int
    response_received_ns: int
    ack_finished_ns: int
    result: str

    def __init__(self, *args, **kwargs):
        raise TypeError('actual owned CallWire operation issuer is not registered')


@dataclass(frozen=True, slots=True, init=False)
class _ReadRetentionFailure:
    owner: object
    attempt: _HeldReadAttempt
    status: str
    reason: str

    def __init__(self, *args, **kwargs):
        raise TypeError('only an observed retained-byte failure supplies this fact')


@dataclass(frozen=True, slots=True, init=False)
class SerializedPhysicalReadRow:
    """Immutable tuple-backed exact external fields and their bounded encoding."""
    fields: tuple
    canonical_bytes: bytes

    def __init__(self, *args, **kwargs):
        raise TypeError('serialized rows require a held retained receipt')

    def __getattr__(self, name):
        for key, value in self.fields:
            if key == name:
                return value
        raise AttributeError(name)


@dataclass(frozen=True, slots=True)
class AssemblyContribution:
    physical_ordinal: int
    operation_seq: int
    logical_offset: int
    length: int
    decoded_data_ref: BlobRef

    def __post_init__(self):
        _int(self.physical_ordinal, 0, MAX_READS-1)
        _int(self.operation_seq, 1, 1024)
        _int(self.logical_offset, 0, 32767)
        _int(self.length, 1, 2048)
        deny(type(self.decoded_data_ref) is BlobRef and self.decoded_data_ref.length == self.length
             and self.decoded_data_ref.path == f'memory/read-{self.physical_ordinal:03d}.bin',
             'call_read_contribution_data')


@dataclass(frozen=True, slots=True)
class PartialAssembly:
    epoch: str
    target_kind: str
    target_ordinal: int
    pass_index: int
    target_length: int
    completed_contributions: tuple
    next_logical_offset: int
    failure_operation_seq: int | None

    def __post_init__(self):
        _epoch(self.epoch)
        deny(type(self.target_kind) is str and self.target_kind in ('frame', 'object'),
             'call_read_partial_kind')
        _int(self.target_ordinal, 0, 31 if self.target_kind == 'frame' else (7 if self.epoch != 'C2' else 6))
        _int(self.pass_index, 0, 1)
        _int(self.target_length, 1, 32768)
        _int(self.next_logical_offset, 1, self.target_length-1)
        deny(type(self.completed_contributions) is tuple
             and 0 < len(self.completed_contributions) < target_part_limit(
                 self.epoch, self.target_kind, self.target_ordinal)
             and all(type(item) is AssemblyContribution for item in self.completed_contributions),
             'call_read_partial_contributions')
        if self.target_kind == 'frame':
            deny(self.target_length == 4096, 'call_read_partial_frame')
        offset, seq, ordinals = 0, 0, set()
        for item in self.completed_contributions:
            deny(item.logical_offset == offset and item.operation_seq > seq
                 and item.physical_ordinal not in ordinals, 'call_read_partial_order')
            offset += item.length
            seq = item.operation_seq
            ordinals.add(item.physical_ordinal)
        deny(offset == self.next_logical_offset, 'call_read_partial_offset')
        if self.failure_operation_seq is not None:
            _int(self.failure_operation_seq, seq+1, 1024)


@dataclass(frozen=True, slots=True)
class AssemblyResult:
    epoch: str
    target_kind: str
    target_ordinal: int
    pass_index: int
    target_length: int
    contributions: tuple
    blob: BlobRef
    data: bytes


@dataclass(frozen=True, slots=True)
class _InventoryRow:
    blob: BlobRef
    family: str
    epoch: str
    state: str


def _native(cls, **values):
    # Deliberately private structural allocation. No origin registry is created.
    result = object.__new__(cls)
    for key, value in values.items():
        object.__setattr__(result, key, value)
    return result


def _canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n').encode('ascii')


def _encoded_size(value):
    """Size our bounded ASCII/native JSON without producing an encoded copy."""
    def size(item, depth):
        deny(depth <= 8, 'call_read_metadata_depth')
        if type(item) is str:
            deny(item.isascii() and len(item) <= MAX_ROW_BYTES, 'call_read_metadata_string')
            total = 2
            for char in item:
                total += (2 if char in ('"', '\\', '\b', '\f', '\n', '\r', '\t')
                          else 6 if ord(char) < 32 else 1)
            return total
        if type(item) is int:
            sign = int(item < 0)
            number = abs(item)
            digits = 1
            while number >= 10:
                number //= 10
                digits += 1
                deny(digits <= 20, 'call_read_metadata_integer')
            return digits+sign
        if item is None:
            return 4
        if type(item) is bool:
            return 4 if item else 5
        if type(item) in (tuple, list):
            deny(len(item) <= 64, 'call_read_metadata_vector')
            return 2+max(0, len(item)-1)+sum(size(child, depth+1) for child in item)
        deny(type(item) is dict and len(item) <= 64
             and all(type(key) is str for key in item), 'call_read_metadata_object')
        return 2+max(0, len(item)-1)+sum(size(key, depth+1)+1+size(child, depth+1)
                                       for key, child in item.items())
    return size(value, 0)+1  # canonical trailing newline


def _verification_copy_plan(target):
    """Logical byte copies in unchanged encode_packet/AckDecoder and this join.

    Count each distinct temporary/native payload, including codec bytearrays,
    checksum slices, ASCII conversion and concatenation intermediates. The
    caller's existing immutable packet aliases are not copied here. Metadata
    objects have their separate bound; this is not a Python heap/RSS limit.
    """
    deny(type(target) is ReadTarget, 'call_read_charge_target')
    address_digits = max(1, (target.gpa.bit_length()+3)//4)
    length_digits = (target.length.bit_length()+3)//4
    q = address_digits+length_digits+2  # m + address + comma + length
    p = 2*target.length
    packet = p+4
    return (
        ('request_generation', (('address_ascii', address_digits), ('length_ascii', length_digits),
            ('request_text', q), ('request_ascii', q), ('encode_buffer', q),
            ('checksum_text', 2), ('checksum_ascii', 2), ('dollar_concat', q+1),
            ('hash_concat', q+2), ('packet_concat', q+4))),
        ('codec', (('feed_buffer', packet), ('frame_raw', packet), ('encoded_payload', p),
            ('checksum_slice', 2), ('decoded_bytearray', p), ('frame_payload', p))),
        ('payload_comparison', (('actual_packet_payload_slice', p),)),
        ('hex_decode', (('payload_ascii_text', p), ('decoded_native_data', target.length))),
        ('packet_files', (('request_file', q+4), ('response_file', packet))))


def packet_copy_bound(target):
    return sum(length for _, copies in _verification_copy_plan(target) for _, length in copies)


def metadata_bound(target):
    deny(type(target) is ReadTarget, 'call_read_charge_target')
    return metadata_copy_bound()


def metadata_copy_bound():
    """The existing fixed metadata credit, without inventing a future target."""
    # One pending/native capacity plus three canonical serialization copies:
    # json.dumps text, text+newline, ASCII bytes. No encoder copy is used to size.
    # Four pending/completed inventory projections include the target assembly.
    example = dict(path='epochs/C2/objects/06-recheck.bin', sha256='f'*64,
                   length=4100, family='decoded physical read data', epoch='C2', state='incomplete_write')
    inventory_capacity = _encoded_size(example)
    return 4*MAX_ROW_BYTES+8*inventory_capacity


def packet_copy_upper_bound(length):
    """Upper bound of the unchanged copy plan for an as-yet unknown U64 GPA.

    Summing that plan gives 17L + 8*address_digits + 8*length_digits + 43.
    A real request has at most16 address digits and3 length digits. This is
    logical copy accounting, never a physical target or a Python RSS bound.
    """
    _int(length, 1, 2048)
    return 17*length+195


def require_runtime_receipt(receipt):
    """Retention is not actual guest/current-stop provenance; no issuer exists."""
    raise ProbeError('INCOMPLETE', 'call_read_runtime_issuer_unregistered')


class _ReadRetainer:
    def __init__(self, *args, **kwargs):
        raise TypeError('actual owned CallWire retainer registration is unavailable')

    def _ready(self):
        from run0_call_budget import ParentAccounting

        # There is intentionally no production branch or registration factory.
        deny(self._origin == 'synthetic_fixture' and not self._revoked,
             'call_read_retainer_unregistered')
        deny(type(self._accounting) is ParentAccounting and type(self._raw) is dict
             and tuple(self._raw) == ('rsp', 'rsp-out')
             and all(type(value) in (bytes, bytearray) for value in self._raw.values()),
             'call_read_held_storage')
        deny(type(self._root) is type(Path()) and self._root.is_absolute(), 'call_read_root')
        info = self._root.lstat()
        deny(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
             and info.st_mode & 0o077 == 0, 'call_read_root_private')
        deny(type(self._transport) is tuple and len(self._transport) == 3
             and self._transport[0] == 'rsp', 'call_read_transport')
        _int(self._transport[1])
        _int(self._transport[2])
        deny(type(self._plan_ref) is BlobRef and self._plan_ref.path == 'plan.json'
             and 0 < self._plan_ref.length <= 1024*1024, 'call_read_plan_ref')
        _int(self._deadline_ns, 1)

    def prepare(self, reservation, item_ordinal, key, target):
        """Claim an allocated row and retention slots; confer no admission.

        Order: full batch reserve -> prepare/_claim allocation -> future held
        protocol admission (before any send) -> ACK proof -> retained-byte seal.
        A prepared-only refusal may project a null failed-operation reference:
        null says no admitted attempt, never that no accounting row was allocated.
        """
        self._ready()
        deny(self._pending is None, 'call_read_pending')
        self._accounting._claim(reservation, item_ordinal, key, target)
        paths = (f'operations/{key.operation_seq:04d}-request.bin',
                 f'operations/{key.operation_seq:04d}-response.bin',
                 f'memory/read-{key.physical_ordinal:03d}.bin')
        deny(all(path not in self._slots for path in paths), 'call_read_slot_reused')
        self._accounting.debit_read(reservation, key, 2*_encoded_size(
            dict(epoch=key.epoch, request_id=key.request_id, physical_ordinal=key.physical_ordinal,
                 operation_seq=key.operation_seq, paths=paths)), purpose='metadata')
        for path in paths:
            self._slots[path] = (key, 'pending')
        if target.logical_offset == 0:
            assembly = self._assembly_path(key.epoch, target)
            deny(assembly not in self._slots, 'call_read_assembly_slot_reused')
            self._slots[assembly] = (key, 'pending')
        pending = _native(PendingReadRetention, owner=self, reservation=reservation,
                          item_ordinal=item_ordinal, key=key, target=target)
        # Prepaid native pending slots, without invented hashes/future bytes.
        self._pending = pending
        self._prepared[key.physical_ordinal] = pending
        return pending

    def _span(self, position, expected):
        deny(type(position) is LiveWirePosition, 'call_read_position_type')
        raw = self._raw[position.stream]
        deny(type(raw) in (bytes, bytearray) and position.offset+position.length <= len(raw)
             and position.length == len(expected)
             and memoryview(raw)[position.offset:position.offset+position.length] == expected,
             'call_read_actual_wire_bytes')

    def _write(self, pending, name, raw):
        deny(name not in self._inventory and self._slots.get(name) == (pending.key, 'pending'),
             'call_read_duplicate_path')
        path = self._root/name
        parent = path.parent
        current = self._root
        for part in parent.relative_to(self._root).parts:
            current = current/part
            try:
                current.mkdir(mode=0o700)
            except FileExistsError:
                pass
            info = current.lstat()
            deny(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                 and info.st_mode & 0o077 == 0, 'call_read_output_directory')
        fd = None
        count = 0
        complete = False
        primary = None
        family = ('actual operation copies' if name.startswith('operations/') else
                  'decoded physical read data' if name.startswith('memory/') else
                  'frame assemblies' if '/frames/' in name else 'object assemblies')
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
                         | os.O_NOFOLLOW, 0o600)
            info = os.fstat(fd)
            deny(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                 and info.st_uid == os.getuid() and info.st_mode & 0o077 == 0,
                 'call_read_output_file')
            count = os.write(fd, raw)
            incomplete(count == len(raw), 'call_read_short_write')
            os.fsync(fd)
            complete = True
        except BaseException as error:
            primary = error
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError as error:
                    complete = False
                    if primary is None:
                        primary = error
                try:
                    blob = BlobRef(name, hashlib.sha256(memoryview(raw)[:count]).hexdigest(), count)
                    self._accounting.debit_read(pending.reservation, pending.key, 2*_encoded_size(
                        dict(path=blob.path, length=blob.length, sha256=blob.sha256,
                             family=family, epoch=pending.key.epoch,
                             state='complete' if complete else 'incomplete_write')), purpose='metadata')
                    self._inventory[name] = _InventoryRow(blob, family, pending.key.epoch,
                                                         'complete' if complete else 'incomplete_write')
                except BaseException as error:
                    if primary is None:
                        primary = error
        if primary is not None:
            raise primary
        return self._inventory[name].blob

    def seal(self, pending, *, operation, request_position, request_ack_position,
             response_position, response_ack_position, request_bytes, response_bytes,
             started_ns, response_received_ns, ack_finished_ns):
        try:
            return self._seal(pending, operation=operation, request_position=request_position,
                request_ack_position=request_ack_position, response_position=response_position,
                response_ack_position=response_ack_position, request_bytes=request_bytes,
                response_bytes=response_bytes, started_ns=started_ns,
                response_received_ns=response_received_ns, ack_finished_ns=ack_finished_ns)
        except BaseException as original:
            # Retention can fail after an honest ACK-stage ok. Never relabel the
            # protocol attempt as failed, or infer failure merely from its seq.
            if (type(pending) is PendingReadRetention and pending.owner is self
                    and self._prepared.get(pending.key.physical_ordinal) is pending
                    and pending.key.physical_ordinal not in self._receipts
                    and pending.key.physical_ordinal not in self._failures):
                attempt = self._attempts.get(pending.key.operation_seq)
                ack = self._operations.get(pending.key.operation_seq)
                if (type(attempt) is _HeldReadAttempt and attempt._parent is self._parent
                        and attempt._wire is self._wire and attempt.key == pending.key
                        and attempt.target == pending.target and attempt.result == 'ok'
                        and type(ack) is _HeldReadOperation and ack.attempt is attempt
                        and ack._parent is self._parent and ack._wire is self._wire
                        and ack.key == pending.key and ack.target == pending.target
                        and ack.result == 'ok' and ack.started_ns == attempt.started_ns
                        and ack.ack_finished_ns == attempt.finished_ns):
                    status = original.status if isinstance(original, ProbeError) else 'INCOMPLETE'
                    reason = original.reason if isinstance(original, ProbeError) else type(original).__name__
                    try:
                        self._accounting.debit_read(pending.reservation, pending.key,
                            2*_encoded_size(dict(status=status, reason=reason,
                                operation_seq=pending.key.operation_seq)), purpose='metadata')
                        self._failures[pending.key.physical_ordinal] = _native(_ReadRetentionFailure,
                            owner=self, attempt=attempt, status=status, reason=reason)
                    except BaseException:
                        # Missing failure evidence can never authorize partial
                        # success; preserve the original exception regardless.
                        pass
            raise

    def _seal(self, pending, *, operation, request_position, request_ack_position,
              response_position, response_ack_position, request_bytes, response_bytes,
              started_ns, response_received_ns, ack_finished_ns):
        self._ready()
        deny(type(pending) is PendingReadRetention and pending is self._pending
             and pending.owner is self, 'call_read_pending_identity')
        # A failed attempt is consumed even if validation or the first write fails.
        self._pending = None
        self._revoked = True
        key, target = pending.key, pending.target
        deny(type(operation) is _HeldReadOperation
             and self._operations.get(key.operation_seq) is operation
             and operation._parent is self._parent and operation._wire is self._wire
             and operation.key == key and operation.target == target and operation.result == 'ok'
             and type(operation.attempt) is _HeldReadAttempt
             and self._attempts.get(key.operation_seq) is operation.attempt
             and operation.attempt._parent is self._parent and operation.attempt._wire is self._wire
             and operation.attempt.key == key and operation.attempt.target == target
             and operation.attempt.result == 'ok'
             and operation.attempt.started_ns == operation.started_ns
             and operation.attempt.finished_ns == operation.ack_finished_ns,
             'call_read_native_operation')
        positions = (request_position, request_ack_position, response_position, response_ack_position)
        deny(all(type(p) is LiveWirePosition for p in positions)
             and positions == (operation.request_position, operation.request_ack_position,
                           operation.response_position, operation.response_ack_position),
             'call_read_operation_positions')
        deny(tuple(p.stream for p in positions) == ('rsp-out', 'rsp', 'rsp', 'rsp-out'),
             'call_read_position_streams')
        for stamp in (started_ns, response_received_ns, ack_finished_ns):
            _int(stamp, 1)
        deny((started_ns, response_received_ns, ack_finished_ns) ==
             (operation.started_ns, operation.response_received_ns, operation.ack_finished_ns)
             and started_ns <= response_received_ns <= ack_finished_ns < self._deadline_ns,
             'call_read_operation_clock')
        deny(type(request_bytes) is bytes and type(response_bytes) is bytes,
             'call_read_packet_bytes')
        debit = lambda n, purpose: self._accounting.debit_read(pending.reservation, key, n,
                                                              purpose=purpose)
        plan = dict((phase, sum(length for _, length in copies))
                    for phase, copies in _verification_copy_plan(target))
        debit(plan['request_generation'], 'packet_copy')
        expected = rsp.encode_packet(f'm{target.gpa:x},{target.length:x}'.encode())
        deny(request_bytes == expected and len(response_bytes) == 2*target.length+4,
             'call_read_request_or_length')
        for pos, expected_bytes in zip(positions, (request_bytes, b'+', response_bytes, b'+')):
            self._span(pos, expected_bytes)
        deny(request_position.offset+request_position.length <= response_ack_position.offset
             and request_ack_position.offset+request_ack_position.length <= response_position.offset,
             'call_read_ack_order')
        debit(plan['codec'], 'packet_copy')
        codec = rsp.AckDecoder()
        frames = codec.feed(response_bytes)
        deny(not codec.pending and len(frames) == 1 and frames[0].kind == 'PACKET'
             and len(frames[0].payload) == 2*target.length
             and rsp.HEX.fullmatch(frames[0].payload) is not None,
             'call_read_reply_payload')
        payload = frames[0].payload
        debit(plan['payload_comparison'], 'packet_copy')
        deny(response_bytes[1:-3] == payload, 'call_read_escaped_hex')
        debit(plan['hex_decode'], 'packet_copy')
        data = bytes.fromhex(payload.decode('ascii'))
        debit(plan['packet_files'], 'packet_copy')
        request_ref = self._write(pending, f'operations/{key.operation_seq:04d}-request.bin', request_bytes)
        response_ref = self._write(pending, f'operations/{key.operation_seq:04d}-response.bin', response_bytes)
        debit(target.length, 'decoded_file')
        data_ref = self._write(pending, f'memory/read-{key.physical_ordinal:03d}.bin', data)
        # The measured commit follows actual data-file fsync/close. It does not
        # claim to follow formatting of a row that contains its own timestamp.
        finished_ns = time.monotonic_ns()
        incomplete(ack_finished_ns <= finished_ns < self._deadline_ns,
                   'call_read_retention_deadline')
        receipt = _native(NativePhysicalReadReceipt, parent=self._parent, session=self._session,
            binding=self._binding, transport_identity=self._transport, epoch=key.epoch,
            request_id=key.request_id, physical_ordinal=key.physical_ordinal,
            operation_seq=key.operation_seq, target_kind=target.kind,
            pass_index=target.pass_index, target_ordinal=target.target_ordinal,
            logical_offset=target.logical_offset, physical=target.gpa, length=target.length,
            request_position=request_position, request_ack_position=request_ack_position,
            response_position=response_position, response_ack_position=response_ack_position,
            request_ref=request_ref, response_ref=response_ref,
            payload_ref=RawSlice(response_ref, 1, 2*target.length), decoded_data_ref=data_ref,
            request_bytes=request_bytes, response_bytes=response_bytes, response_payload=payload,
            data=data, started_ns=started_ns, response_received_ns=response_received_ns,
            finished_ns=finished_ns, result='ok')
        row = self._make_row(receipt, pending)
        incomplete(time.monotonic_ns() < self._deadline_ns, 'call_read_retention_deadline')
        self._receipts[key.physical_ordinal] = receipt
        self._rows[key.physical_ordinal] = row
        self._retained_pending[key.physical_ordinal] = pending
        self._revoked = False
        return receipt

    def _make_row(self, receipt, pending):
        fields = [('parent_ref', self._plan_ref)]
        fields.extend((name, getattr(receipt, name)) for name in (
            'epoch', 'request_id', 'physical_ordinal', 'operation_seq', 'target_kind',
            'pass_index', 'target_ordinal', 'logical_offset', 'physical', 'length',
            'request_position', 'request_ack_position', 'response_position',
            'response_ack_position', 'request_ref', 'response_ref', 'payload_ref',
            'decoded_data_ref', 'started_ns', 'response_received_ns', 'finished_ns', 'result'))
        value = {name: item.as_json() if type(item) in (BlobRef, RawSlice, LiveWirePosition)
                 else item for name, item in fields}
        size = _encoded_size(value)
        incomplete(size <= MAX_ROW_BYTES, 'call_read_row_limit')
        self._accounting.debit_read(pending.reservation, pending.key, 3*size-1, purpose='metadata')
        raw = _canonical(value)
        deny(len(raw) == size, 'call_read_row_size')
        return _native(SerializedPhysicalReadRow, fields=tuple(fields), canonical_bytes=raw)

    def _receipt(self, receipt):
        deny(type(receipt) is NativePhysicalReadReceipt
             and self._receipts.get(receipt.physical_ordinal) is receipt
             and receipt.parent is self._parent and receipt.session is self._session
             and receipt.binding is self._binding, 'call_read_receipt_identity')

    def export_row(self, receipt):
        self._receipt(receipt)
        return self._rows[receipt.physical_ordinal]

    def inventory(self):
        return tuple(self._inventory.values())

    @staticmethod
    def _assembly_path(epoch, target):
        family = 'frames' if target.kind == 'frame' else 'objects'
        pass_name = 'first' if target.pass_index == 0 else 'recheck'
        return f'epochs/{epoch}/{family}/{target.target_ordinal:02d}-{pass_name}.bin'

    def assemble(self, receipts, *, target_length):
        """Retain exactly one frozen complete target; this issues no RAM grant."""
        deny(type(receipts) is tuple and 0 < len(receipts) <= 17, 'call_read_assembly_receipts')
        first = receipts[0]
        self._receipt(first)
        deny(len(receipts) <= target_part_limit(first.epoch, first.target_kind, first.target_ordinal),
             'call_read_target_parts')
        pending = self._retained_pending[first.physical_ordinal]
        target = pending.target
        expected = tuple(charge.target for charge in pending.reservation.charges
                         if (charge.target.kind, charge.target.target_ordinal, charge.target.pass_index)
                         == (first.target_kind, first.target_ordinal, first.pass_index))
        _int(target_length, 1, 32768)
        deny(target_length == sum(part.length for part in expected)
             and len(receipts) == len(expected), 'call_read_assembly_length')
        path = self._assembly_path(first.epoch, target)
        deny(path not in self._inventory, 'call_read_assembly_reused')
        offset, previous, contributions = 0, 0, []
        for receipt, part in zip(receipts, expected):
            self._receipt(receipt)
            item = self._retained_pending[receipt.physical_ordinal]
            deny(item.reservation is pending.reservation and item.target == part
                 and receipt.epoch == first.epoch and receipt.logical_offset == offset
                 and receipt.operation_seq > previous, 'call_read_assembly_join')
            if first.target_kind == 'frame':
                deny(receipt.physical-receipt.logical_offset == first.physical,
                     'call_read_assembly_frame_base')
            offset += receipt.length
            previous = receipt.operation_seq
        # Native join and separate file copy spend separately prepaid credits.
        for receipt in receipts:
            item = self._retained_pending[receipt.physical_ordinal]
            self._accounting.debit_read(item.reservation, item.key, receipt.length, purpose='read')
            self._accounting.debit_read(item.reservation, item.key, receipt.length,
                                       purpose='assembly_file')
            self._accounting.debit_read(item.reservation, item.key, 2*_encoded_size(dict(
                physical_ordinal=receipt.physical_ordinal, operation_seq=receipt.operation_seq,
                logical_offset=receipt.logical_offset, length=receipt.length,
                decoded_data_ref=receipt.decoded_data_ref.as_json())), purpose='metadata')
        data = b''.join(receipt.data for receipt in receipts)
        try:
            blob = self._write(pending, path, data)
        except BaseException:
            self._revoked = True
            raise
        for receipt in receipts:
            contributions.append(AssemblyContribution(receipt.physical_ordinal, receipt.operation_seq,
                receipt.logical_offset, receipt.length, receipt.decoded_data_ref))
        return AssemblyResult(first.epoch, first.target_kind, first.target_ordinal, first.pass_index,
                              target_length, tuple(contributions), blob, data)

    def resolve_positions(self, receipts, final_stream_refs, raw_bytes):
        deny(type(receipts) is tuple and len(receipts) <= MAX_READS
             and all(type(item) is NativePhysicalReadReceipt for item in receipts)
             and type(final_stream_refs) is tuple and len(final_stream_refs) == 2
             and type(raw_bytes) is tuple and len(raw_bytes) == 2
             and all(type(item) is tuple and len(item) == 2
                     for item in (*final_stream_refs, *raw_bytes)),
             'call_read_final_inventory')
        deny(tuple(receipt.physical_ordinal for receipt in receipts) == tuple(sorted(self._receipts)),
             'call_read_final_receipt_inventory')
        deny(tuple(k for k, _ in final_stream_refs) == ('rsp', 'rsp-out')
             and tuple(k for k, _ in raw_bytes) == ('rsp', 'rsp-out'), 'call_read_final_streams')
        refs, raw = dict(final_stream_refs), dict(raw_bytes)
        for stream in refs:
            ref, data = refs[stream], raw[stream]
            deny(type(ref) is BlobRef and type(data) is bytes and len(data) == ref.length
                 and ref.path == ('raw/rsp.bin' if stream == 'rsp' else 'raw/rsp-requests.bin')
                 and hashlib.sha256(data).hexdigest() == ref.sha256,
                 'call_read_final_identity')
        for receipt in receipts:
            self._receipt(receipt)
            pending = self._retained_pending[receipt.physical_ordinal]
            self._accounting.debit_read(pending.reservation, pending.key, 4*64, purpose='metadata')
        seen, spans = set(), {'rsp': [], 'rsp-out': []}
        for receipt in receipts:
            self._receipt(receipt)
            deny(receipt.physical_ordinal not in seen, 'call_read_final_duplicate')
            seen.add(receipt.physical_ordinal)
            for pos, expected in zip((receipt.request_position, receipt.request_ack_position,
                    receipt.response_position, receipt.response_ack_position),
                    (receipt.request_bytes, b'+', receipt.response_bytes, b'+')):
                high = pos.offset+pos.length
                deny(high <= len(raw[pos.stream])
                     and memoryview(raw[pos.stream])[pos.offset:high] == expected
                     and all(high <= lo or hi <= pos.offset for lo, hi in spans[pos.stream]),
                     'call_read_final_position')
                spans[pos.stream].append((pos.offset, high))
                RawSlice(refs[pos.stream], pos.offset, pos.length)
        return tuple(self.export_row(receipt) for receipt in receipts)

    def partial_assembly(self, receipts, target_length, *, failure_operation_seq):
        deny(type(receipts) is tuple and 0 < len(receipts) <= 16, 'call_read_partial_prefix')
        first = receipts[0]
        self._receipt(first)
        pending = self._retained_pending[first.physical_ordinal]
        expected = tuple(charge.target for charge in pending.reservation.charges
                         if (charge.target.kind, charge.target.target_ordinal, charge.target.pass_index)
                         == (first.target_kind, first.target_ordinal, first.pass_index))
        _int(target_length, 1, 32768)
        deny(target_length == sum(part.length for part in expected)
             and len(receipts) < len(expected), 'call_read_partial_target_plan')
        if first.target_kind == 'frame':
            deny(target_length == 4096, 'call_read_partial_frame_length')
        accepted = tuple(receipt for _, receipt in sorted(self._receipts.items())
                         if (receipt.epoch, receipt.target_kind, receipt.target_ordinal, receipt.pass_index)
                         == (first.epoch, first.target_kind, first.target_ordinal, first.pass_index))
        deny(len(accepted) == len(receipts) and all(a is z for a, z in zip(accepted, receipts)),
             'call_read_partial_omitted_success')
        next_target = expected[len(receipts)]
        attempts = tuple(attempt for attempt in self._attempts.values()
                         if type(attempt) is _HeldReadAttempt
                         and attempt._parent is self._parent and attempt._wire is self._wire
                         and attempt.key.epoch == first.epoch and attempt.target == next_target)
        if failure_operation_seq is not None:
            _int(failure_operation_seq, first.operation_seq+1, 1024)
            deny(len(attempts) == 1, 'call_read_partial_failure_operation')
            failed = attempts[0]
            failure = self._failures.get(failed.key.physical_ordinal)
            failed_pending = self._prepared.get(failed.key.physical_ordinal)
            deny(failed.key.operation_seq == failure_operation_seq
                 and type(failure) is _ReadRetentionFailure and failure.owner is self
                 and failure.attempt is failed and failed.key.physical_ordinal not in self._receipts
                 and type(failed_pending) is PendingReadRetention
                 and failed_pending.owner is self and failed_pending.reservation is pending.reservation,
                 'call_read_partial_failure_operation')
        else:
            # Allocation is not admission: a next prepared slot can exist here.
            # Future wire must register every admitted attempt before ANY send,
            # so zero-byte admission cannot be hidden behind this null case.
            deny(not attempts, 'call_read_partial_admitted_attempt')
        contributions, offset, seen = [], 0, set()
        previous = 0
        for receipt, part in zip(receipts, expected):
            self._receipt(receipt)
            item = self._retained_pending[receipt.physical_ordinal]
            deny((receipt.epoch, receipt.target_kind, receipt.target_ordinal, receipt.pass_index) ==
                 (first.epoch, first.target_kind, first.target_ordinal, first.pass_index)
                 and receipt.logical_offset == offset and receipt.physical_ordinal not in seen
                 and receipt.operation_seq > previous and item.reservation is pending.reservation
                 and item.target == part,
                 'call_read_partial_join')
            self._accounting.debit_read(item.reservation, item.key, 2*_encoded_size(dict(
                physical_ordinal=receipt.physical_ordinal, operation_seq=receipt.operation_seq,
                logical_offset=receipt.logical_offset, length=receipt.length,
                decoded_data_ref=receipt.decoded_data_ref.as_json())), purpose='metadata')
            seen.add(receipt.physical_ordinal)
            contributions.append(AssemblyContribution(receipt.physical_ordinal, receipt.operation_seq,
                receipt.logical_offset, receipt.length, receipt.decoded_data_ref))
            offset += receipt.length
            previous = receipt.operation_seq
        deny(offset < target_length, 'call_read_partial_not_proper_prefix')
        return PartialAssembly(first.epoch, first.target_kind, first.target_ordinal, first.pass_index,
                               target_length, tuple(contributions), offset, failure_operation_seq)
