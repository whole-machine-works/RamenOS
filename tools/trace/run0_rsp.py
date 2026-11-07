"""Bounded, ACK-mode, reset-only QEMU RSP client (RUN0 RSP1).

No launcher, resume, breakpoint, individual-register or guest-memory operations.
The owner supplies a fresh byte wire which drains and records the owned VM's
other streams under the same deadline. See run0-c0-inspection-v0.json.
"""
from collections import deque
from dataclasses import dataclass, replace
import hashlib
import re
import time
import xml.etree.ElementTree as ET

import boot_profile_capture as capture


MAX_PAYLOAD = 4096
MAX_PACKET = 8192
MAX_WIRE = 262144
MAX_ACKS = 256
MAX_XML = 16384
XML_CHUNK = 1024
CORE_SHA256 = '1b3acc75743d5cea86aadda52e75a9ecdcbaefa89050d1aae8c4d8f3dd880953'
TARGET_XML = (b'<?xml version="1.0"?>'
              b'<!DOCTYPE target SYSTEM "gdb-target.dtd">'
              b'<target><architecture>i386:x86-64</architecture>'
              b'<xi:include href="i386-64bit.xml"/></target>')
HEX = re.compile(rb'[0-9a-fA-F]+\Z')


class RSPError(capture.ProbeError):
    def __init__(self, status, reason, *, terminal=True):
        super().__init__(status, reason)
        self.terminal = terminal


def require(condition, reason, *, status='DENY', terminal=True):
    if not condition:
        raise RSPError(status, reason, terminal=terminal)


@dataclass(frozen=True)
class Frame:
    kind: str
    payload: bytes = b''
    raw: bytes = b''


@dataclass(frozen=True)
class RegisterSpec:
    regnum: int
    name: str
    bits: int
    offset_bytes: int


@dataclass(frozen=True)
class TargetDescription:
    architecture: str
    annexes: tuple
    registers: tuple
    packet_bytes: int
    target_xml: bytes
    core_xml: bytes


@dataclass(frozen=True)
class RegisterSnapshot:
    raw_payload: bytes
    raw_bytes: bytes
    values: tuple


@dataclass(frozen=True)
class RSPOperation:
    name: str
    request_packet: bytes
    response_packet: bytes | None
    response_payload: bytes | None
    started_ns: int
    finished_ns: int | None
    result: str


def encode_packet(payload):
    require(type(payload) is bytes and len(payload) <= MAX_PAYLOAD,
            'rsp_out_payload', terminal=False)
    encoded = bytearray()
    for value in payload:
        encoded.extend((125, value ^ 32) if value in b'#$}*' else (value,))
    require(len(encoded)+4 <= MAX_PACKET, 'rsp_out_packet', terminal=False)
    return b'$'+encoded+b'#'+f'{sum(encoded) & 255:02x}'.encode('ascii')


class _AckCodec:
    """Incremental strict packet codec; invalid input permanently closes it."""

    _wire_limit = MAX_WIRE
    _ack_limit = MAX_ACKS
    def __init__(self):
        self._buffer = bytearray()
        self._state = 'idle'
        self._payload_end = None
        self._wire_bytes = 0
        self._acks = 0
        self._failed = False

    @property
    def pending(self):
        return bool(self._buffer)

    def feed(self, chunk):
        require(not self._failed, 'rsp_codec_terminal')
        try:
            require(type(chunk) is bytes, 'rsp_chunk_type')
            require(len(chunk) <= self._wire_limit-self._wire_bytes, 'rsp_wire_limit', status='INCOMPLETE')
            self._wire_bytes += len(chunk)
            frames = []
            for value in chunk:
                if self._state == 'idle':
                    if value in (43, 45):
                        require(self._acks < self._ack_limit, 'rsp_ack_limit', status='INCOMPLETE')
                        self._acks += 1
                        frames.append(Frame('ACK' if value == 43 else 'NACK', raw=bytes([value])))
                        continue
                    require(value == 36, 'rsp_frame_start')
                    self._buffer.append(value)
                    self._state = 'payload'
                    continue
                require(len(self._buffer) < MAX_PACKET, 'rsp_packet_limit', status='INCOMPLETE')
                self._buffer.append(value)
                if self._state == 'payload':
                    require(value != 36, 'rsp_nested_packet')
                    if value == 35:
                        self._payload_end = len(self._buffer)-1
                        self._state = 'checksum1'
                elif self._state == 'checksum1':
                    require(value in b'0123456789abcdefABCDEF', 'rsp_checksum_digits')
                    self._state = 'checksum2'
                else:
                    require(value in b'0123456789abcdefABCDEF', 'rsp_checksum_digits')
                    raw = bytes(self._buffer)
                    encoded = raw[1:self._payload_end]
                    require((sum(encoded) & 255) == int(raw[-2:], 16), 'rsp_checksum')
                    decoded = bytearray()
                    escape = False
                    for byte in encoded:
                        if escape:
                            require(len(decoded) < MAX_PAYLOAD, 'rsp_payload_limit', status='INCOMPLETE')
                            decoded.append(byte ^ 32)
                            escape = False
                        elif byte == 125:
                            escape = True
                        else:
                            require(byte != 42, 'rsp_rle_unsupported', status='INCOMPLETE')
                            require(len(decoded) < MAX_PAYLOAD, 'rsp_payload_limit', status='INCOMPLETE')
                            decoded.append(byte)
                    require(not escape, 'rsp_escape_truncated')
                    frames.append(Frame('PACKET', bytes(decoded), raw))
                    self._buffer.clear()
                    self._state = 'idle'
                    self._payload_end = None
            return frames
        except RSPError:
            self._failed = True
            raise



class AckDecoder(_AckCodec):
    """The unchanged closed reset profile."""


class _C0AckDecoder(_AckCodec):
    _wire_limit = 32 * 1024 * 1024
    _ack_limit = 512


def _expected_registers():
    groups = [
        (64, 'rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15 rip'.split()),
        (32, 'eflags cs ss ds es fs gs'.split()),
        (64, 'fs_base gs_base k_gs_base cr0 cr2 cr3 cr4 cr8 efer'.split()),
        (80, [f'st{i}' for i in range(8)]),
        (32, 'fctrl fstat ftag fiseg fioff foseg fooff fop'.split()),
        (128, [f'xmm{i}' for i in range(16)]),
        (32, ['mxcsr']),
    ]
    result, offset = [], 0
    for bits, names in groups:
        for name in names:
            result.append(RegisterSpec(len(result), name, bits, offset))
            offset += bits//8
    return tuple(result)


def decode_target_description(target_xml, core_xml):
    require(type(target_xml) is bytes and type(core_xml) is bytes, 'rsp_xml_type')
    require(len(target_xml)+len(core_xml) <= MAX_XML, 'rsp_xml_limit', status='INCOMPLETE')
    # The generated target has an unbound xi prefix. Accept its exact known
    # grammar, never repair or resolve arbitrary XML namespaces/includes.
    require(target_xml == TARGET_XML, 'rsp_target_xml')
    require(hashlib.sha256(core_xml).hexdigest() == CORE_SHA256, 'rsp_core_xml_pin')
    # Only hash-authenticated, locally pinned XML reaches this parser. Its known
    # inert external DOCTYPE is never fetched by ElementTree.
    try:
        root = ET.fromstring(core_xml)
        require(root.tag == 'feature' and root.attrib == {'name': 'org.gnu.gdb.i386.core'}, 'rsp_feature')
        registers, offset, number = [], 0, 0
        for element in root.findall('reg'):
            if 'regnum' in element.attrib:
                number = int(element.attrib['regnum'])
            bits = int(element.attrib['bitsize'])
            registers.append(RegisterSpec(number, element.attrib['name'], bits, offset))
            number += 1
            offset += bits//8
    except (ET.ParseError, ValueError, KeyError) as error:
        raise RSPError('DENY', 'rsp_core_xml_parse') from error
    require(tuple(registers) == _expected_registers() and offset == 608, 'rsp_register_inventory')
    return TargetDescription('i386:x86-64', ('target.xml', 'i386-64bit.xml'),
                             tuple(registers), offset, target_xml, core_xml)


def decode_reset_registers(payload, target):
    require(type(target) is TargetDescription and target.registers == _expected_registers()
            and target.packet_bytes == 608 and target.architecture == 'i386:x86-64'
            and target.annexes == ('target.xml', 'i386-64bit.xml')
            and target.target_xml == TARGET_XML and type(target.core_xml) is bytes
            and hashlib.sha256(target.core_xml).hexdigest() == CORE_SHA256,
            'rsp_register_target')
    require(type(payload) is bytes and len(payload) == 1216 and HEX.fullmatch(payload) is not None,
            'rsp_register_bytes')
    raw = bytes.fromhex(payload.decode('ascii'))
    values = tuple(int.from_bytes(raw[item.offset_bytes:item.offset_bytes+item.bits//8], 'little')
                   for item in target.registers)
    return RegisterSnapshot(payload, raw, values)


class _ResetSequence:
    """Fixed reset semantics shared by the separate bounded wire backends."""

    def __init__(self):
        self._state, self._xml_bytes, self._target = 'new', 0, None

    def _require_state(self, *states):
        require(self._state != 'failed', 'rsp_session_terminal', status='INCOMPLETE')
        require(self._state in states, 'rsp_state', terminal=False)

    def _payload_allowed(self, name, payload):
        fixed = {
            ('new', 'supported'): b'qSupported:qXfer:features:read+',
            ('supported', 'thread_first'): b'qfThreadInfo',
            ('thread_first', 'thread_next'): b'qsThreadInfo',
            ('thread_next', 'thread_current'): b'qC',
            ('thread_current', 'thread_general'): b'Hg01',
            ('thread_general', 'thread_continue'): b'Hc01',
            ('described', 'reset_registers'): b'g',
            ('registers', 'qemu_supported'): b'qqemu.Supported',
            ('qemu_supported', 'physical_mode_query'): b'qqemu.PhyMemMode',
            ('physical_zero', 'physical_mode_enable'): b'Qqemu.PhyMemMode:1',
            ('physical_set', 'physical_mode_query'): b'qqemu.PhyMemMode',
        }
        if (self._state, name) in fixed:
            return payload == fixed[self._state, name]
        annex = {('thread_continue', 'feature_target'): b'target.xml',
                 ('target_read', 'feature_core'): b'i386-64bit.xml'}.get((self._state, name))
        if annex is None:
            return False
        match = re.fullmatch(rb'qXfer:features:read:'+re.escape(annex)+rb':([0-9a-f]{1,4}),400', payload)
        return match is not None and int(match[1], 16) < MAX_XML

    def query_supported(self):
        self._require_state('new')
        payload = self._exchange('supported', b'qSupported:qXfer:features:read+')
        self._semantic(all(32 <= value <= 126 for value in payload), 'rsp_feature_ascii')
        fields = payload.split(b';')
        keys, entries = set(), {}
        for field in fields:
            if b'=' in field:
                parts = field.split(b'=')
                self._semantic(len(parts) == 2 and bool(parts[1]) and
                               re.fullmatch(rb'[A-Za-z0-9_.:-]+', parts[1]) is not None,
                               'rsp_feature_syntax')
                key = parts[0]
            else:
                key = field[:-1] if field[-1:] in (b'+', b'-') else field
            self._semantic(re.fullmatch(rb'[A-Za-z0-9_.:-]+', key) is not None, 'rsp_feature_syntax')
            self._semantic(key not in keys, 'rsp_feature_duplicate')
            keys.add(key)
            entries[key] = field
        size = entries.get(b'PacketSize', b'')
        self._semantic(size.startswith(b'PacketSize='), 'rsp_packet_size_missing', status='INCOMPLETE')
        value = size[len(b'PacketSize='):]
        self._semantic(1 <= len(value) <= 8 and HEX.fullmatch(value) is not None, 'rsp_packet_size')
        self._semantic(int(value, 16) >= MAX_PAYLOAD, 'rsp_packet_size_unsupported', status='INCOMPLETE')
        self._semantic(entries.get(b'qXfer:features:read') == b'qXfer:features:read+',
                       'rsp_features_unsupported', status='INCOMPLETE')
        self._state = 'supported'
        return payload

    def query_threads(self):
        self._require_state('supported')
        replies = []
        for name, command, expected in [('thread_first', b'qfThreadInfo', b'm01'),
                                         ('thread_next', b'qsThreadInfo', b'l'),
                                         ('thread_current', b'qC', b'QC01')]:
            reply = self._exchange(name, command)
            self._semantic(reply == expected, 'rsp_thread_identity')
            replies.append(reply)
            self._state = name
        return tuple(replies)

    def select_thread(self):
        self._require_state('thread_current')
        replies = []
        for name, command in [('thread_general', b'Hg01'), ('thread_continue', b'Hc01')]:
            reply = self._exchange(name, command)
            self._semantic(reply == b'OK', 'rsp_thread_selection')
            replies.append(reply)
            self._state = name
        return tuple(replies)

    def _read_annex(self, annex, operation):
        chunks, offset = [], 0
        while True:
            reply = self._exchange(operation, b'qXfer:features:read:'+annex+b':'+f'{offset:x},400'.encode())
            self._semantic(reply[:1] in (b'm', b'l'), 'rsp_xml_marker')
            chunk = reply[1:]
            self._semantic(0 < len(chunk) <= XML_CHUNK, 'rsp_xml_progress')
            self._semantic(len(chunk) <= MAX_XML-self._xml_bytes, 'rsp_xml_limit', status='INCOMPLETE')
            self._xml_bytes += len(chunk)
            chunks.append(chunk)
            offset += len(chunk)
            if reply[:1] == b'l':
                return b''.join(chunks)
            self._semantic(offset < MAX_XML, 'rsp_xml_limit', status='INCOMPLETE')

    def read_target_description(self):
        self._require_state('thread_continue')
        target_xml = self._read_annex(b'target.xml', 'feature_target')
        # Do not request any included resource until the target itself is exact.
        self._semantic(target_xml == TARGET_XML, 'rsp_target_xml')
        self._state = 'target_read'
        core_xml = self._read_annex(b'i386-64bit.xml', 'feature_core')
        try:
            self._target = decode_target_description(target_xml, core_xml)
        except RSPError as error:
            self._semantic(False, error.reason, status=error.status)
        self._state = 'described'
        return self._target

    def read_reset_registers(self):
        self._require_state('described')
        reply = self._exchange('reset_registers', b'g')
        try:
            result = decode_reset_registers(reply, self._target)
        except RSPError as error:
            self._semantic(False, error.reason, status=error.status)
        self._state = 'registers'
        return result

    def query_qemu_supported(self):
        self._require_state('registers')
        reply = self._exchange('qemu_supported', b'qqemu.Supported')
        fields = reply.split(b';')
        self._semantic(all(re.fullmatch(rb'[A-Za-z0-9_]+', field) for field in fields), 'rsp_qemu_feature_syntax')
        self._semantic(len(fields) == len(set(fields)), 'rsp_qemu_feature_duplicate')
        self._semantic(b'PhyMemMode' in fields, 'rsp_physical_unsupported', status='INCOMPLETE')
        self._state = 'qemu_supported'
        return reply

    def query_physical_mode(self):
        self._require_state('qemu_supported', 'physical_set')
        expected = 0 if self._state == 'qemu_supported' else 1
        reply = self._exchange('physical_mode_query', b'qqemu.PhyMemMode')
        self._semantic(reply == str(expected).encode(), 'rsp_physical_mode')
        self._state = 'physical_zero' if expected == 0 else 'complete'
        return expected

    def enable_physical_mode(self):
        self._require_state('physical_zero')
        reply = self._exchange('physical_mode_enable', b'Qqemu.PhyMemMode:1')
        self._semantic(reply == b'OK', 'rsp_physical_set')
        self._state = 'physical_set'


class RSPClient(_ResetSequence):
    """Closed reset sequence. A local state denial emits no bytes.

    The supplied wire must enforce its passed absolute deadline, preserve raw
    incoming/outgoing bytes and drain other owned streams. No raw request API is
    public. Operation rows retain partial-write and semantic-failure evidence.
    """
    def __init__(self, wire, budget):
        super().__init__()
        self.wire, self.budget = wire, budget
        self._decoder, self._frames = AckDecoder(), deque()
        self._operations = []
        self._wire_bytes = self._acks = 0

    @property
    def operations(self):
        return tuple(self._operations)

    def _remaining(self, deadline):
        remaining = min(deadline, self.budget.deadline-capture.TEARDOWN_SECONDS)-time.monotonic()
        require(remaining > 0, 'rsp_deadline', status='INCOMPLETE')
        return remaining

    def _charge_wire(self, length):
        require(length <= MAX_WIRE-self._wire_bytes, 'rsp_wire_limit', status='INCOMPLETE')
        self._wire_bytes += length

    def _write(self, data, deadline):
        self._remaining(deadline)
        self._charge_wire(len(data))
        while True:
            try:
                self.wire.write_all(data, deadline)
                break
            except InterruptedError:
                # write_all owns partial-write accounting; retrying it could
                # duplicate a prefix. A write exception is uncertain, terminal.
                raise RSPError('INCOMPLETE', 'rsp_write_interrupted')
        self._remaining(deadline)

    def _next(self, deadline):
        while not self._frames:
            self._remaining(deadline)
            allowance = min(MAX_PACKET, MAX_WIRE-self._wire_bytes)
            require(allowance > 0, 'rsp_wire_limit', status='INCOMPLETE')
            try:
                chunk = self.wire.read_chunk(deadline, allowance)
            except (BlockingIOError, InterruptedError):
                continue
            self._remaining(deadline)
            require(type(chunk) is bytes, 'rsp_chunk_type')
            require(bool(chunk), 'rsp_eof', status='INCOMPLETE')
            self._charge_wire(len(chunk))
            self._frames.extend(self._decoder.feed(chunk))
        return self._frames.popleft()

    def _exchange(self, name, payload):
        self._require_state('new','supported','thread_first','thread_next','thread_current',
                            'thread_general','thread_continue','target_read','described',
                            'registers','qemu_supported','physical_zero','physical_set')
        require(type(payload) is bytes and self._payload_allowed(name, payload),
                'rsp_forbidden_operation', terminal=False)
        request = encode_packet(payload)
        index = None
        try:
            self.budget.message()
            deadline = min(time.monotonic()+capture.RESPONSE_SECONDS,
                           self.budget.deadline-capture.TEARDOWN_SECONDS)
            self._remaining(deadline)
            require(not self._frames and not self._decoder.pending, 'rsp_unsolicited')
            require(len(request) <= MAX_WIRE-self._wire_bytes, 'rsp_wire_limit', status='INCOMPLETE')
            index = len(self._operations)
            self._operations.append(RSPOperation(name, request, None, None,
                                                 time.monotonic_ns(), None, 'pending'))
            self._write(request, deadline)
            ack = self._next(deadline)
            require(ack.kind == 'ACK', 'rsp_request_ack', status='INCOMPLETE' if ack.kind == 'NACK' else 'DENY')
            require(self._acks < MAX_ACKS, 'rsp_ack_limit', status='INCOMPLETE')
            self._acks += 1
            response = self._next(deadline)
            require(response.kind == 'PACKET', 'rsp_response_packet')
            self._operations[index] = replace(self._operations[index], response_packet=response.raw,
                                               response_payload=response.payload)
            self.budget.message()
            require(self._acks < MAX_ACKS, 'rsp_ack_limit', status='INCOMPLETE')
            self._acks += 1
            self._write(b'+', deadline)
            require(not self._frames and not self._decoder.pending, 'rsp_unsolicited')
            require(response.payload != b'', 'rsp_unsupported', status='INCOMPLETE')
            require(not re.fullmatch(rb'E[0-9a-fA-F]{2}', response.payload),
                    'rsp_remote_error', status='INCOMPLETE')
            self._operations[index] = replace(self._operations[index], result='ok', finished_ns=time.monotonic_ns())
            return response.payload
        except (capture.ProbeError, OSError) as error:
            self._state = 'failed'
            timeout = isinstance(error, TimeoutError) or getattr(error, 'reason', '') in (
                'rsp_deadline', 'vm_deadline', 'rsp_request_timeout', 'rsp_response_timeout')
            if index is not None:
                self._operations[index] = replace(self._operations[index], result='timeout' if timeout else 'error',
                                                   finished_ns=time.monotonic_ns())
            if isinstance(error, RSPError):
                raise
            if isinstance(error, capture.ProbeError):
                raise RSPError(error.status, error.reason) from error
            raise RSPError('INCOMPLETE', 'rsp_timeout' if timeout else 'rsp_io') from error

    def _semantic(self, condition, reason, *, status='DENY'):
        if not condition:
            self._state = 'failed'
            if self._operations:
                self._operations[-1] = replace(self._operations[-1], result='error')
            raise RSPError(status, reason)
