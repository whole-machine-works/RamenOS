"""Suspended, bounded C0 RAM planner; no sockets or production binding issuer.

The collector must issue a current same-stop binding after its owned-host join.
This module deliberately supplies no such issuer. Synthetic bindings exercise
only this pure state machine and must be rejected by a production wire adapter.
The unchanged retained-byte decoder is the independent final replay consumer.
"""
from dataclasses import dataclass, fields
import hashlib
import re
import struct
from types import MappingProxyType

import run0_c0_decode as d
import run0_c0_entry as entry_token
import run0_c0_wire as wire
from run0_c0_paging import PageWalk, NeedFrame


# Names/order are part of the receiving interface, not optional witness flags.
PROOF_NAMES = ('breakpoint', 'resume', 'stop_ack', 'status', 'physical_mode',
               'host_before', 'host_after', 'layout')
REF_NAMES = ('stop', 'registers_before', 'hmp_before', 'layout_before',
             'host_state', 'host_abi', 'host_source', 'source_persistence',
             'control_before', 'control_after')
REGISTER_WIDTHS = tuple((n, 4 if 17 <= n <= 23 else 8) for n in d.SELECTED_REGISTERS)
TAIL_OPERATIONS = tuple(f'p{number:x}' for number in d.SELECTED_REGISTERS) + (
    'hmp_registers', 'hmp_flatview', 'hardware_breakpoint_clear', 'quit')
OPERATION_RESERVE = len(TAIL_OPERATIONS)  # exact required shared-wire control tail: 33
STORAGE_RESERVE = wire.REPORT_RESERVE + wire.FAILURE_RESERVE


@dataclass(frozen=True, slots=True, init=False)
class CurrentC0RamBinding:
    origin: str
    prior: entry_token.ValidatedPriorEntry
    confirmed_stop: wire.ConfirmedEntryStop
    wire_identity: object
    transport_identity: tuple
    admission_epoch: int
    physical_mode: int
    run_id: str
    profile_ref: tuple
    profile_sha256: str
    invocation_profile: str
    owner_identity: tuple  # exact owned PID, start identity, CPU0 QMP TID
    cpu: int
    thread: str
    pinned_efi_ref: tuple
    state: tuple
    registers: tuple  # (index, width, value, actual operation sequence)
    hmp_raw: bytes
    layout_raw: bytes
    ranges: tuple
    proof_prefix: tuple  # PROOF_NAMES -> actual operation sequence
    evidence_refs: tuple  # REF_NAMES -> immutable BlobRef tuple
    raw_operation_slices: tuple
    stop_event_slice: tuple
    host_read_sizes: tuple  # original same-stop 14 reads / 104 bytes
    stop_ns: int
    vm_deadline_ns: int
    stop_deadline_ns: int

    def __init__(self, *args, **kwargs):
        raise TypeError('current C0 binding requires the future owned collector join')


@dataclass(frozen=True, slots=True, init=False)
class AfterC0Binding:
    binding: CurrentC0RamBinding
    state: tuple
    registers: tuple
    hmp_raw: bytes
    layout_raw: bytes
    hmp_seq: int
    layout_seq: int
    finished_ns: int
    evidence_refs: tuple  # registers_after, hmp_after, layout_after
    raw_operation_slices: tuple

    def __init__(self, *args, **kwargs):
        raise TypeError('after C0 binding requires the future same-stop collector join')


def _shape(value, cls, reason):
    d._require(type(value) is cls, reason)
    try:
        for field in fields(cls):
            getattr(value, field.name)
    except AttributeError as error:
        raise d.C0DecodeError('DENY', reason) from error


def _ref(value, limit=d.LIMITS['retained_bytes']):
    d._require(type(value) is tuple and len(value) == 3, 'acquire_ref_type')
    return d._ref(dict(zip(('path', 'sha256', 'length'), value)), limit)


def _slice_ref(value):
    d._require(type(value) is tuple and len(value) == 3, 'acquire_slice_ref')
    ref = _ref(value[0])
    offset, length = d._integer(value[1]), d._integer(value[2], 1, 65536)
    d._require(offset <= ref['length'] and length <= ref['length']-offset,
               'acquire_slice_bounds')
    return ref['path'], offset, offset+length


def _operation_slices(value, sequences, extra=(), response_optional=()):
    # These immutable identities are retained, not treated as proof of raw bytes.
    # Only the future owning issuer may validate/register their live provenance.
    d._require(type(value) is tuple and len(value) <= d.LIMITS['operations'] and
               len(value) == len(sequences), 'acquire_operation_slices')
    spans = {}
    for segment in extra:
        name, low, high = _slice_ref(segment)
        spans.setdefault(name, []).append((low, high))
    for row, expected in zip(value, sequences):
        d._require(type(row) is tuple and len(row) == 3 and type(row[0]) is int and
                   row[0] == expected, 'acquire_operation_slice_identity')
        for segment in row[1:]:
            if segment is None:
                continue
            name, low, high = _slice_ref(segment)
            d._require(all(high <= a or b <= low for a, b in spans.get(name, ())),
                       'acquire_operation_slice_reuse')
            spans.setdefault(name, []).append((low, high))
        d._require(row[1] is not None, 'acquire_operation_request_missing')
        d._require(row[2] is not None or row[0] in response_optional,
                   'acquire_operation_response_missing')


def _named(value, names, reason):
    d._require(type(value) is tuple and len(value) == len(names), reason)
    for item, name in zip(value, names):
        d._require(type(item) is tuple and len(item) == 2 and
                   type(item[0]) is str and item[0] == name, reason)
    return dict(value)


def _state(value):
    names = ('phys_bits', 'cr0', 'cr3', 'cr4', 'efer', 'cpl', 'cs64',
             'a20', 'no_npt', 'no_svm_guest', 'no_smm')
    return d._mode(_named(value, names, 'acquire_state_tuple'))


def _registers(value):
    d._require(type(value) is tuple and len(value) == 29, 'acquire_register_count')
    result, sequences = {}, []
    for row, (number, width) in zip(value, REGISTER_WIDTHS):
        d._require(type(row) is tuple and len(row) == 4 and
                   type(row[0]) is int and row[0] == number and
                   type(row[1]) is int and row[1] == width, 'acquire_register_identity')
        result[number] = d._integer(row[2], 0, (1 << (8*width))-1)
        sequences.append(d._integer(row[3], 1))
    d._require(sequences == sorted(set(sequences)), 'acquire_register_sequence')
    return result, tuple(sequences)


def _transport(value):
    # Stable native connection/session identifier chosen by the owning adapter.
    d._require(type(value) is tuple and len(value) == 3 and
               type(value[0]) is str and 0 < len(value[0]) <= 128 and
               type(value[1]) is int and type(value[2]) is int and
               value[1] >= 0 and value[2] >= 0, 'acquire_transport_identity')
    return value


def require_runtime_binding(binding):
    """The future production adapter must call this before binding a session.

    This is a rejection check, never an issuer or proof of the missing join.
    Python internals are trusted observer code, as with ValidatedPriorEntry.
    """
    d._require(type(binding) is CurrentC0RamBinding and
               binding.origin == 'owned_current_c0', 'acquire_runtime_binding_required')


def _validate_binding(binding, prior, pinned):
    _shape(binding, CurrentC0RamBinding, 'acquire_current_binding_required')
    d._require(type(binding.origin) is str and binding.origin in (
        'synthetic_fixture', 'owned_current_c0'), 'acquire_binding_origin')
    candidate = entry_token.export_validated_prior_entry(prior)
    d._require(binding.prior is prior, 'acquire_prior_identity')
    reference = _ref(binding.profile_ref, 65536)
    d._require(binding.profile_ref == prior.profile_ref and
               reference == candidate['profile_ref'] and
               type(binding.profile_sha256) is str and
               binding.profile_sha256 == prior.probe_profile_sha256 and
               type(binding.invocation_profile) is str and
               binding.invocation_profile == prior.invocation_profile ==
               d.capture.VAPIC_OFF_INVOCATION_PROFILE, 'acquire_profile_identity')
    d._require(type(binding.run_id) is str and
               re.fullmatch('[a-z0-9-]{1,64}', binding.run_id) is not None, 'acquire_run_id')
    d._require(type(binding.owner_identity) is tuple and len(binding.owner_identity) == 3 and
               all(type(v) is int and v > 0 for v in binding.owner_identity), 'acquire_owner_identity')
    d._require(type(binding.cpu) is int and binding.cpu == 0 and
               type(binding.thread) is str and binding.thread == '01', 'acquire_cpu_thread')
    _transport(binding.transport_identity)
    d._integer(binding.admission_epoch, 1)
    d._require(type(binding.physical_mode) is int and binding.physical_mode == 1,
               'acquire_physical_mode')
    stop = binding.confirmed_stop
    d._require(type(stop) is wire.ConfirmedEntryStop and type(stop.stop) is wire.EntryStop,
               'acquire_stop_type')
    d._require(type(binding.wire_identity) is object and stop.stop._session is binding.wire_identity,
               'acquire_stop_session')
    for value in (stop.stop.entry_address, stop.stop.breakpoint_seq, stop.stop.resume_seq,
                  stop.stop.stop_event_seq, stop.stop.acknowledge_stop_seq, stop.observed_ns,
                  stop.query_status_seq, stop.stop.received_ns):
        d._integer(value, 1)
    d._require(stop.stop.entry_address == prior.entry_address, 'acquire_stop_candidate')
    for value in (binding.stop_ns, binding.vm_deadline_ns, binding.stop_deadline_ns):
        d._integer(value, 1)
    d._require(binding.stop_ns == stop.stop.received_ns and
               binding.stop_ns <= stop.observed_ns < min(binding.vm_deadline_ns,
                                                         binding.stop_deadline_ns),
               'acquire_stop_deadline')
    proof = _named(binding.proof_prefix, PROOF_NAMES, 'acquire_proof_prefix')
    for value in proof.values():
        d._integer(value, 1)
    d._require(proof['breakpoint'] < proof['resume'] < proof['stop_ack'] < proof['status'] and
               proof['stop_ack'] < proof['physical_mode'] and
               proof['status'] < proof['host_before'] < proof['host_after'] < proof['layout'] and
               (proof['breakpoint'], proof['resume'], proof['stop_ack'], proof['status']) ==
               (stop.stop.breakpoint_seq, stop.stop.resume_seq,
                stop.stop.acknowledge_stop_seq, stop.query_status_seq), 'acquire_stop_operations')
    values, seqs = _registers(binding.registers)
    d._require(proof['physical_mode'] < seqs[0] <= seqs[-1] < proof['host_before'],
               'acquire_before_order')
    inventory = (*proof.values(), *seqs)
    d._require(len(set(inventory)) == len(inventory), 'acquire_operation_sequence_reuse')
    _operation_slices(binding.raw_operation_slices, tuple(sorted(inventory)),
                      (binding.stop_event_slice,), (proof['stop_ack'],))
    d._require(values[16] == prior.entry_address, 'acquire_stopped_rip')
    state = _state(binding.state)
    d._require(all(values[number] == state[name] for number, name in (
        (27, 'cr0'), (29, 'cr3'), (30, 'cr4'), (32, 'efer'))), 'acquire_register_mode')
    hmp = d._hmp(binding.hmp_raw, values)
    d._require(hmp['cpl'] == state['cpl'] and hmp['cs64'] == state['cs64'] and
               hmp['a20'] == state['a20'] and hmp['smm'] == 0, 'acquire_hmp_mode')
    refs = _named(binding.evidence_refs, REF_NAMES, 'acquire_evidence_refs')
    for value in refs.values():
        _ref(value)
    for raw, name in ((binding.hmp_raw, 'hmp_before'), (binding.layout_raw, 'layout_before')):
        reference = _ref(refs[name], 65536)
        d._require(type(raw) is bytes and len(raw) == reference['length'] and
                   hashlib.sha256(raw).hexdigest() == reference['sha256'], 'acquire_raw_ref')
    ranges = d._layout(binding.layout_raw)
    d._require(type(binding.ranges) is tuple and all(type(p) is tuple and len(p) == 2 and
               all(type(x) is int for x in p) for p in binding.ranges) and
               binding.ranges == ranges, 'acquire_layout_identity')
    d._require(type(binding.host_read_sizes) is tuple and len(binding.host_read_sizes) == 14 and
               all(type(v) is int and v > 0 for v in binding.host_read_sizes) and
               sum(binding.host_read_sizes) == 104, 'acquire_host_read_accounting')
    reference = _ref(binding.pinned_efi_ref, d.entry.EFI_LIMIT)
    d._require(reference['path'] == 'efi' and type(pinned) is bytes and
               len(pinned) == reference['length'] and
               hashlib.sha256(pinned).hexdigest() == reference['sha256'], 'acquire_pinned_efi')
    return state, values, proof, refs


class AcquisitionLedger:
    """Shared envelope of existing consumption plus outstanding obligations.

    Values are reservations, never an additional allowance above wire counters.
    The receiving wire must share this object and reconcile its actual charges;
    no production adapter is supplied here. Reservations are never refunded.
    All increments are validated before any counter changes. Non-memory traffic
    uses reserve too, so after/failure/teardown capacity remains protected.
    """
    __slots__ = ('_values', '_owner')

    def __init__(self, used=()):
        d._require(type(used) is tuple and len(used) <= len(d.LIMITS), 'acquire_ledger_used')
        values = dict.fromkeys(d.LIMITS, 0)
        seen = set()
        for pair in used:
            d._require(type(pair) is tuple and len(pair) == 2 and
                       type(pair[0]) is str and pair[0] in values and pair[0] not in seen,
                       'acquire_ledger_used')
            seen.add(pair[0]); values[pair[0]] = d._integer(pair[1], 0, d.LIMITS[pair[0]])
        self._values, self._owner = values, None

    @property
    def values(self):
        return MappingProxyType(dict(self._values))

    def reserve(self, **charges):
        limits = dict(d.LIMITS)
        limits['operations'] -= OPERATION_RESERVE
        limits['retained_bytes'] -= STORAGE_RESERVE
        for name, amount in charges.items():
            d._require(type(name) is str and name in limits, 'acquire_counter_name')
            d._integer(amount)
            d._require(amount <= limits[name] - self._values[name], name+'_limit', 'INCOMPLETE')
        for name, amount in charges.items():
            self._values[name] += amount


@dataclass(frozen=True, slots=True)
class PhysicalReadIntent:
    request_id: int
    role: str
    pass_number: int
    object_ordinal: int | None
    virtual: int | None
    physical: int
    length: int
    frame_level: int | None
    ancestor_sequences: tuple

    def as_record(self):
        return {'request_id': self.request_id, 'role': self.role, 'pass': self.pass_number,
                'object_ordinal': self.object_ordinal, 'virtual': self.virtual,
                'physical': self.physical, 'length': self.length,
                'frame_level': self.frame_level, 'ancestor_sequences': self.ancestor_sequences}


@dataclass(frozen=True, slots=True, init=False)
class RamReadGrant:
    intent: PhysicalReadIntent
    session: object
    binding: CurrentC0RamBinding
    transport_identity: tuple
    admission_epoch: int
    layout_identity: tuple
    deadlines: tuple
    reserved_charges: tuple

    def __init__(self, *args, **kwargs):
        raise TypeError('only AcquisitionSession issues a pending grant')


@dataclass(frozen=True, slots=True, init=False)
class AdmittedPhysicalRead:
    intent: PhysicalReadIntent
    request_payload: bytes
    request_bytes: bytes
    expected_reply_length: int
    operation_seq: int
    deadline_ns: int

    def __init__(self, *args, **kwargs):
        raise TypeError('consume an exact pending grant immediately before dispatch')


@dataclass(frozen=True, slots=True)
class PhysicalReadReceipt:
    request_id: int
    transport_identity: tuple
    admission_epoch: int
    operation_seq: int
    request_slice: wire.WireSlice
    response_slice: wire.WireSlice
    request_bytes: bytes
    response_bytes: bytes
    response_payload: bytes
    data: bytes
    started_ns: int
    finished_ns: int
    result: str


@dataclass(frozen=True, slots=True, init=False)
class ReadsComplete:
    session: object
    binding: CurrentC0RamBinding
    last_read_seq: int

    def __init__(self, *args, **kwargs):
        raise TypeError('only AcquisitionSession finishes its fixed read schedule')


@dataclass(frozen=True, slots=True, init=False)
class AcquiredC0Snapshot:
    record: object
    blobs: object
    receipts: tuple
    origin: str

    def __init__(self, *args, **kwargs):
        raise TypeError('finish the same-stop after bracket')

    def export_record(self):
        def thaw(value):
            if type(value) is MappingProxyType:
                return {key: thaw(item) for key, item in value.items()}
            if type(value) is tuple:
                return [thaw(item) for item in value]
            return value
        return thaw(self.record)


def _make(cls, **values):
    d._require(cls in (RamReadGrant, AdmittedPhysicalRead, ReadsComplete, AcquiredC0Snapshot),
               'acquire_internal_issued_type')
    d._require(set(values) == {field.name for field in fields(cls)}, 'acquire_internal_issued_fields')
    value = object.__new__(cls)
    for name, item in values.items():
        object.__setattr__(value, name, item)
    return value


class AcquisitionSession:
    """One suspended walk, one pending grant, fixed eight-object acquisition."""
    def __init__(self, prior, pinned_efi, binding, ledger):
        state, registers, proof, refs = _validate_binding(binding, prior, pinned_efi)
        d._require(type(ledger) is AcquisitionLedger and ledger._owner is None,
                   'acquire_ledger_owner')
        self._guard = d._Walker(state, {}, binding.ranges)
        try:
            self._pe = d.entry.parse_pe(pinned_efi, 32)
            d.entry.loaded_extent(prior.loaded_base, self._pe.image_size)
            d._require(prior.entry_address == prior.loaded_base+self._pe.entry_rva,
                       'acquire_pe_candidate')
            d._require(d.entry.expected_entry(self._pe, prior.loaded_base).hex() ==
                       prior.expected_entry_hex, 'acquire_pe_prior_bytes')
        except d.entry.AdmissionError as error:
            raise d.C0DecodeError('DENY', 'acquire_pe_'+str(error)) from error
        self.prior, self.binding, self.ledger = prior, binding, ledger
        self._pinned, self._state, self._registers, self._proof, self._refs = (
            pinned_efi, state, registers, proof, refs)
        self._failure = self._pending = self._admitted = self._ready = None
        self._frames, self._objects, self._receipts = {}, [], []
        self._levels, self._request_id = {}, 0
        self._last_seq = proof['layout']
        self._last_end = {'rsp': 0, 'rsp-out': 0}
        self._complete = None
        self._finished = False
        self._boot = self._gmm = None
        self._driver = self._drive()
        self._driver_started = False
        ledger._owner = self

    @property
    def failure(self):
        return self._failure

    @property
    def pending(self):
        return self._pending

    def abort(self, first_failure):
        d._require(type(first_failure) in (d.C0DecodeError, wire.Failure), 'acquire_failure_type')
        d._require(type(first_failure.status) is str and first_failure.status in ('DENY', 'INCOMPLETE')
                   and type(first_failure.reason) is str and 0 < len(first_failure.reason) <= 240,
                   'acquire_failure_fields')
        if self._failure is None:
            self._failure = d.C0DecodeError(first_failure.status, first_failure.reason)

    def _live(self):
        if self._failure is not None:
            raise self._failure
        d._require(not self._finished, 'acquire_already_finished')

    def _fail(self, error):
        self.abort(error)
        raise self._failure

    def _reserve_reads(self, lengths):
        # Conservative shared retention reservation includes both raw hex replies,
        # decoded/chunk/assembled bytes, packets and bounded row metadata. Existing
        # wire/report storage remains in used and the protected reserve above.
        self.ledger.reserve(operations=len(lengths), retained_bytes=sum(
            8*length+2048 for length in lengths))

    def _intent(self, role, pass_number, ordinal, virtual, physical, length, level, ancestors):
        self._request_id += 1
        return PhysicalReadIntent(self._request_id, role, pass_number, ordinal, virtual,
                                  physical, length, level, tuple(ancestors))

    def _advance(self, result):
        self._driver_started = True
        try:
            self._ready = self._driver.send(result)
        except StopIteration:
            self._ready = None
            self._complete = _make(ReadsComplete, session=self, binding=self.binding,
                                   last_read_seq=self._last_seq)

    def next_request(self):
        try:
            self._live()
            d._require(self._pending is None, 'acquire_pending_request')
            if self._complete is not None:
                return self._complete
            if not self._driver_started:
                self._advance(None)
            if self._complete is not None:
                return self._complete
            intent, self._ready = self._ready, None
            self._pending = _make(RamReadGrant, intent=intent, session=self,
                binding=self.binding, transport_identity=self.binding.transport_identity,
                admission_epoch=self.binding.admission_epoch,
                layout_identity=self._refs['layout_before'],
                deadlines=(self.binding.vm_deadline_ns, self.binding.stop_deadline_ns),
                reserved_charges=(('operations', 1), ('payload_bytes', intent.length)))
            return self._pending
        except d.C0DecodeError as error:
            self._fail(error)

    def consume_for_dispatch(self, grant, transport_identity, admission_epoch,
                             pending_operation_seq, now_ns):
        """Final nonblocking check after pending-row/output reservation and quiet wait.

        The wire owner must revoke via abort for cancellation, mode change,
        reconnect, resume/reset, foreign operations or terminal events. Its epoch
        identifies a stop, not a changing operation count. No socket is called.
        """
        try:
            self._live()
            d._require(type(grant) is RamReadGrant and grant is self._pending and
                       grant.session is self and grant.binding is self.binding,
                       'acquire_grant_identity')
            d._require(self._admitted is None, 'acquire_grant_consumed')
            d._require(_transport(transport_identity) == grant.transport_identity,
                       'acquire_transport_mismatch')
            d._require(type(admission_epoch) is int and
                       admission_epoch == grant.admission_epoch == self.binding.admission_epoch,
                       'acquire_stale_epoch')
            d._integer(now_ns)
            d._require(max(self.binding.stop_ns, self._receipts[-1].finished_ns if self._receipts
                           else self.binding.stop_ns) <= now_ns < min(grant.deadlines),
                       'acquire_deadline', 'INCOMPLETE')
            d._integer(pending_operation_seq, self._last_seq+1)
            d._require(grant.layout_identity == self._refs['layout_before'] and
                       grant.deadlines == (self.binding.vm_deadline_ns,
                                           self.binding.stop_deadline_ns), 'acquire_binding_changed')
            self._guard._ram(grant.intent.physical, grant.intent.length)
            payload = f'm{grant.intent.physical:x},{grant.intent.length:x}'.encode('ascii')
            self._admitted = _make(AdmittedPhysicalRead, intent=grant.intent,
                request_payload=payload, request_bytes=d.rsp.encode_packet(payload),
                expected_reply_length=2*grant.intent.length,
                operation_seq=pending_operation_seq, deadline_ns=min(grant.deadlines))
            return self._admitted
        except d.C0DecodeError as error:
            self._fail(error)

    def accept(self, grant, receipt):
        try:
            self._live()
            d._require(type(grant) is RamReadGrant and grant is self._pending and
                       self._admitted is not None, 'acquire_receipt_pending')
            _shape(receipt, PhysicalReadReceipt, 'acquire_receipt_type')
            _transport(receipt.transport_identity)
            admitted, intent = self._admitted, grant.intent
            d._require(type(receipt.request_id) is int and receipt.request_id == intent.request_id and
                       receipt.transport_identity == grant.transport_identity and
                       type(receipt.admission_epoch) is int and
                       receipt.admission_epoch == grant.admission_epoch and
                       type(receipt.operation_seq) is int and
                       receipt.operation_seq == admitted.operation_seq, 'acquire_receipt_identity')
            d._require(type(receipt.result) is str and receipt.result == 'ok',
                       'acquire_read_failed', 'INCOMPLETE')
            d._integer(receipt.started_ns); d._integer(receipt.finished_ns)
            d._require(self.binding.stop_ns <= receipt.started_ns <= receipt.finished_ns <
                       admitted.deadline_ns and (not self._receipts or
                       self._receipts[-1].finished_ns <= receipt.started_ns),
                       'acquire_read_time', 'INCOMPLETE')
            d._require(type(receipt.request_bytes) is bytes and
                       receipt.request_bytes == admitted.request_bytes, 'acquire_request_bytes')
            d._require(type(receipt.response_payload) is bytes and
                       len(receipt.response_payload) == admitted.expected_reply_length and
                       re.fullmatch(rb'[0-9a-fA-F]+', receipt.response_payload) is not None,
                       'acquire_response_hex', 'INCOMPLETE')
            d._require(type(receipt.response_bytes) is bytes, 'acquire_response_bytes')
            tokens = d._rsp_tokens(receipt.response_bytes)
            d._require(len(tokens) == 1 and tokens[0].payload == receipt.response_payload,
                       'acquire_response_packet')
            d._require(type(receipt.data) is bytes and len(receipt.data) == intent.length and
                       bytes.fromhex(receipt.response_payload.decode('ascii')) == receipt.data,
                       'acquire_response_data')
            for segment, stream, raw in ((receipt.request_slice, 'rsp-out', receipt.request_bytes),
                                         (receipt.response_slice, 'rsp', receipt.response_bytes)):
                d._require(type(segment) is wire.WireSlice and type(segment.stream) is str and
                           segment.stream == stream and type(segment.offset) is int and
                           segment.offset >= self._last_end[stream] and
                           type(segment.length) is int and segment.length == len(raw),
                           'acquire_response_slice')
            for segment in (receipt.request_slice, receipt.response_slice):
                self._last_end[segment.stream] = segment.offset+segment.length
            self._last_seq = receipt.operation_seq
            self._receipts.append(receipt)
            result = d._MemoryRead(receipt.operation_seq, intent.physical, receipt.data)
            self._pending = self._admitted = None
            # Complete-object/frame validation runs on the completing receipt,
            # before accept returns and before any following grant is issued.
            self._advance(result)
        except d.C0DecodeError as error:
            self._fail(error)

    def _frame(self, need, ancestors):
        address, level = need.physical, need.level
        d._require(address % 4096 == 0, 'frame_alignment')
        self._guard._ram(address, 4096)  # always before cache/level lookup
        d._require(address not in self._levels or self._levels[address] == level, 'frame_level')
        self.ledger.reserve(frames=0)  # validate the shared bound before cache lookup
        if address in self._frames:
            return self._frames[address]['first']
        self.ledger.reserve(frames=1)
        self._reserve_reads((2048,)*4)
        self._levels[address] = level
        chunks = []
        for offset in (0, 2048):
            chunks.append((yield self._intent('frame', 0, None, None, address+offset,
                                               2048, level, ancestors)))
        data = b''.join(row.data for row in chunks)
        d._require(len(data) == 4096, 'frame_length', 'INCOMPLETE')
        d._require(chunks[1].seq == chunks[0].seq+1, 'frame_read_identity')
        self._frames[address] = {'level': level, 'first': data, 'first_reads': tuple(chunks),
                                 'recheck': None, 'recheck_reads': (), 'ancestors': tuple(ancestors)}
        return data

    def _object(self, role, virtual, length, executable=False):
        self.ledger.reserve(objects=1, other_bytes=2*length)
        d._span(virtual, length)
        d._integer(length, 1, 65536)
        ordinal = len(self._objects)
        cursor, remaining, parts = virtual, length, []
        while remaining:
            self.ledger.reserve(translations=1)
            walk = PageWalk(cursor, self._guard.root, self._state['phys_bits'],
                            bool(self._state['efer'] & (1 << 11)))
            step, ancestors = walk.next_frame, ()
            while type(step) is NeedFrame:
                raw = yield from self._frame(step, ancestors)
                parent = self._frames[step.physical]
                ancestors += tuple(row.seq for row in parent['first_reads'])
                step = walk.accept(raw)
            if executable:
                d._require(step.executable, 'code_not_executable')
            chunk = min(remaining, step.page_bytes-step.page_offset, 2048)
            boundary = self._guard._ram(step.physical, chunk)
            chunk = min(chunk, boundary-step.physical)
            translation = {'virtual': cursor, 'physical': step.physical, 'length': chunk,
                'path': [{'frame': item.frame, 'index': item.index, 'entry': item.entry}
                         for item in step.path], 'writable': step.writable,
                'executable': step.executable, 'user': step.user, 'page_bytes': step.page_bytes}
            parts.append((d._freeze(translation), ancestors))
            cursor += chunk; remaining -= chunk
        parts = tuple(parts)  # freeze entire extent before issuing object-data grants
        self._reserve_reads(tuple(part['length'] for part, _ in parts)*2)
        row = {'role': role, 'virtual': virtual, 'length': length, 'parts': parts,
               'first': None, 'first_reads': (), 'recheck': None, 'recheck_reads': ()}
        self._objects.append(row)
        chunks = []
        for part, ancestors in parts:
            chunks.append((yield self._intent(role, 0, ordinal, part['virtual'], part['physical'],
                                               part['length'], None, ancestors)))
        row['first_reads'] = tuple(chunks)
        row['first'] = b''.join(chunk.data for chunk in chunks)
        return row['first']

    def _drive(self):
        base, rip, pinned = self.prior.loaded_base, self.prior.entry_address, self._pinned
        pe_at = struct.unpack_from('<I', pinned, 60)[0]
        optional = struct.unpack_from('<H', pinned, pe_at+20)[0]
        sections = struct.unpack_from('<H', pinned, pe_at+6)[0]
        extents = ((0, 64), (pe_at, 24), (pe_at+24, optional),
                   (pe_at+24+optional, sections*40))
        headers = {}
        for offset, length in extents:
            headers[offset] = yield from self._object('pe_header', base+offset, length)
        code = yield from self._object('entry_code', rip, 32, executable=True)
        d._loaded_pe(pinned, base, rip, headers, code)
        system = self._registers[3]
        d._integer(system, 1); d._require(system % 8 == 0, 'efi_alignment'); d._span(system, 120)
        self._boot = d._efi('system', (yield from self._object('system_table', system, 120)), system)
        self._gmm = d._efi('boot', (yield from self._object('boot_services', self._boot, 376)), self._boot)
        yield from self._object('get_memory_map_code', self._gmm, 32, executable=True)
        # No walk or pointer parsing occurs beyond this point.
        self._frozen_frames = tuple(self._frames)
        self._frozen_objects = tuple(self._objects)
        for address in self._frozen_frames:
            row = self._frames[address]
            chunks = []
            for offset in (0, 2048):
                chunks.append((yield self._intent('frame', 1, None, None, address+offset,
                                                   2048, row['level'], row['ancestors'])))
            raw = b''.join(chunk.data for chunk in chunks)
            d._frame_bytes(address, row['first'], raw, (*row['first_reads'], *chunks))
            row['recheck'], row['recheck_reads'] = raw, tuple(chunks)
        for ordinal, row in enumerate(self._frozen_objects):
            chunks = []
            for part, ancestors in row['parts']:
                chunks.append((yield self._intent(row['role'], 1, ordinal, part['virtual'],
                    part['physical'], part['length'], None, ancestors)))
            raw = b''.join(chunk.data for chunk in chunks)
            d._require(raw == row['first'], 'object_changed', 'INCOMPLETE')
            row['recheck'], row['recheck_reads'] = raw, tuple(chunks)

    def require_reads_complete(self, receipt, transport_identity, admission_epoch, now_ns):
        """Final wire-side check immediately before the fixed after-state queries.

        The owning wire supplies its actual identity/epoch/clock and propagates
        every revocation with abort. This check neither renews the stop nor
        grants resume, final host PASS, or production binding issuance.
        """
        try:
            self._live()
            d._require(type(receipt) is ReadsComplete and receipt is self._complete and
                       receipt.session is self and receipt.binding is self.binding and
                       self._pending is None and receipt.last_read_seq == self._last_seq,
                       'acquire_completion_identity')
            d._require(_transport(transport_identity) == self.binding.transport_identity,
                       'acquire_transport_mismatch')
            d._require(type(admission_epoch) is int and
                       admission_epoch == self.binding.admission_epoch, 'acquire_stale_epoch')
            d._integer(now_ns)
            d._require(self._receipts[-1].finished_ns <= now_ns < min(self.binding.vm_deadline_ns,
                       self.binding.stop_deadline_ns), 'acquire_deadline', 'INCOMPLETE')
            return self.binding
        except d.C0DecodeError as error:
            self._fail(error)

    def finish(self, after_binding):
        try:
            self._live()
            d._require(self._complete is not None and self._pending is None,
                       'acquire_reads_incomplete', 'INCOMPLETE')
            after = after_binding
            _shape(after, AfterC0Binding, 'acquire_after_binding')
            d._require(after.binding is self.binding, 'acquire_after_binding')
            values, seqs = _registers(after.registers)
            d._require(self._last_seq < seqs[0] and seqs[-1] <
                       d._integer(after.hmp_seq, 1) < d._integer(after.layout_seq, 1),
                       'acquire_after_order')
            _operation_slices(after.raw_operation_slices, (*seqs, after.hmp_seq, after.layout_seq))
            d._require(values == self._registers and _state(after.state) == self._state,
                       'acquire_state_changed', 'INCOMPLETE')
            d._hmp(after.hmp_raw, values)
            d._require(type(after.hmp_raw) is bytes and after.hmp_raw == self.binding.hmp_raw and
                       type(after.layout_raw) is bytes and after.layout_raw == self.binding.layout_raw and
                       d._layout(after.layout_raw) == self.binding.ranges,
                       'acquire_bracket_changed', 'INCOMPLETE')
            d._integer(after.finished_ns)
            d._require(self._receipts[-1].finished_ns <= after.finished_ns <
                       min(self.binding.vm_deadline_ns, self.binding.stop_deadline_ns),
                       'acquire_after_deadline', 'INCOMPLETE')
            refs = _named(after.evidence_refs, ('registers_after', 'hmp_after', 'layout_after'),
                          'acquire_after_refs')
            for value in refs.values():
                _ref(value)
            for raw, name in ((after.hmp_raw, 'hmp_after'), (after.layout_raw, 'layout_after')):
                reference = _ref(refs[name], 65536)
                d._require(len(raw) == reference['length'] and
                           hashlib.sha256(raw).hexdigest() == reference['sha256'], 'acquire_after_raw_ref')
            blobs, tables, objects, translations = {}, [], [], []
            def blob(name, raw):
                blobs[name] = raw
                return {'path': name, 'sha256': hashlib.sha256(raw).hexdigest(), 'length': len(raw)}
            first, rechecks, claimed = [], [], set()
            def sequences(row):
                a = [item.seq for item in row['first_reads']]
                b = [item.seq for item in row['recheck_reads']]
                d._require(a and b and a+b == sorted(set(a+b)) and
                           not claimed.intersection(a+b), 'acquire_read_claims')
                claimed.update(a+b); first.extend(a); rechecks.extend(b)
                return a+b
            for address in self._frozen_frames:
                row = self._frames[address]
                d._frame_bytes(address, row['first'], row['recheck'],
                               (*row['first_reads'], *row['recheck_reads']))
                tables.append({'physical': address, 'level': row['level'],
                    'first_ref': blob(f'c0-acquired/frame-{address:x}-first.bin', row['first']),
                    'recheck_ref': blob(f'c0-acquired/frame-{address:x}-again.bin', row['recheck']),
                    'read_sequences': sequences(row)})
            for ordinal, row in enumerate(self._frozen_objects):
                d._require(row['first'] == row['recheck'], 'object_changed', 'INCOMPLETE')
                objects.append({'role': row['role'], 'virtual': row['virtual'], 'length': row['length'],
                    'first_ref': blob(f'c0-acquired/object-{ordinal}-first.bin', row['first']),
                    'recheck_ref': blob(f'c0-acquired/object-{ordinal}-again.bin', row['recheck']),
                    'read_sequences': sequences(row)})
                translations.extend(part for part, _ in row['parts'])
            d._require(claimed == {row.operation_seq for row in self._receipts} and
                       max(first) < min(rechecks), 'acquire_read_claims')
            checkpoint = {'id': 'C0', 'phase': 'firmware_active', 'rip': self.prior.entry_address,
                'loaded_base': self.prior.loaded_base, 'image_handle': self._registers[2],
                'system_table': self._registers[3], 'boot_services': self._boot, 'get_memory_map': self._gmm,
                'stop_ref': _ref(self._refs['stop']), 'resume_seq': self._proof['resume'],
                'breakpoint_seq': self._proof['breakpoint'],
                'registers_before_ref': _ref(self._refs['registers_before']),
                'registers_after_ref': _ref(refs['registers_after']),
                'hmp_before_ref': _ref(self._refs['hmp_before']), 'hmp_after_ref': _ref(refs['hmp_after']),
                'layout_before_ref': _ref(self._refs['layout_before']),
                'layout_after_ref': _ref(refs['layout_after']), 'tables': tables, 'objects': objects,
                'translations': translations, 'observed_consistent': True, 'atomic_snapshot': False,
                'device_quiescence_verified': False, 'call_ref': None}
            result = _make(AcquiredC0Snapshot, record=d._freeze(checkpoint),
                           blobs=MappingProxyType(blobs), receipts=tuple(self._receipts),
                           origin=self.binding.origin)
            self._finished = True
            return result
        except d.C0DecodeError as error:
            self._fail(error)
