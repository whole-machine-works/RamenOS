"""Bounded C0 wire and admitted-entry prefix; no guest-memory authority.

Borrowed sockets do not prove an owned launch/profile join. A future collector
must bind that join before releasing this fixture-qualified prefix on a VM.
"""

from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass, replace
import io
import json
import os
import selectors
import socket
import stat
import time

import run0_rsp as rsp

from boot_profile_capture import MAX_FRAME, ProbeError, decode_frame, deny, incomplete


MAX_RETAINED_BYTES = 32 * 1024 * 1024
REPORT_RESERVE = 1024 * 1024
FAILURE_RESERVE = 128 * 1024
MAX_OPERATIONS = 512
MAX_EVENTS = 128
MAX_RSP_ACKS = 1024
MAX_QMP_FRAMES = 128
MAX_QMP_BYTES = 1024 * 1024
OWNER_NS = 90_000_000_000
TEARDOWN_NS = RESPONSE_NS = 5_000_000_000
CONTINUE_NS = 60_000_000_000
READ_CHUNK = 65_536
_COMMANDS = ("qmp_capabilities", "query-commands", "query-status")
_REQUIRED_COMMANDS = (*_COMMANDS, "query-cpus-fast", "qom-get", "human-monitor-command", "quit")
_PASSIVE_STREAMS = frozenset(("rsp", "serial", "debug", "qemu_stdout", "qemu_stderr"))


@dataclass(frozen=True, slots=True)
class WireSlice:
    stream: str
    offset: int
    length: int


@dataclass(frozen=True, slots=True)
class Operation:
    seq: int
    protocol: str
    operation: str
    started_ns: int
    finished_ns: int | None = None
    request: WireSlice | None = None
    response: WireSlice | None = None
    result: str = "pending"


@dataclass(frozen=True, slots=True)
class Event:
    seq: int
    protocol: str
    name: str
    wire: WireSlice
    received_ns: int


@dataclass(frozen=True, slots=True)
class EndOfStream:
    stream: str
    observed_ns: int


@dataclass(frozen=True, slots=True)
class StreamError:
    stream: str
    operation: str
    errno: int | None
    observed_ns: int


@dataclass(frozen=True, slots=True)
class Failure:
    status: str
    reason: str


@dataclass(frozen=True, slots=True)
class Prelaunch:
    commands: tuple[str, ...]
    observed_ns: int


@dataclass(frozen=True, slots=True)
class EntryStop:
    _session: object
    entry_address: int
    breakpoint_seq: int
    resume_seq: int
    stop_event_seq: int
    acknowledge_stop_seq: int
    received_ns: int


@dataclass(frozen=True, slots=True)
class ConfirmedEntryStop:
    stop: EntryStop
    query_status_seq: int
    observed_ns: int


@dataclass(frozen=True, slots=True)
class CurrentPhysicalMode:
    _session: object
    stop_event_seq: int
    operation_seq: int
    value: int


@dataclass(frozen=True, slots=True)
class SelectedC0Registers:
    _session: object
    stop_event_seq: int
    phase: str
    values: tuple[tuple[int, int, int], ...]


@dataclass(frozen=True, slots=True)
class HostObservationLease:
    _session: object
    stop_event_seq: int
    deadline_ns: int


@dataclass(frozen=True, slots=True)
class PeerReceipt:
    _session: object
    raw_bytes: bytes
    observed_ns: int


@dataclass(frozen=True, slots=True)
class C0HostBracket:
    _session: object
    phase: str
    operations: tuple[tuple[str, int], ...]
    cpu_identity: tuple[str, int, int]
    hmp_bytes: bytes
    parsed_state: tuple


@dataclass(frozen=True, slots=True)
class C0RegisterView:
    _session: object
    operation_seq: int
    wire: WireSlice
    raw_bytes: bytes
    parsed_state: tuple


@dataclass(frozen=True, slots=True)
class C0LayoutReceipt:
    _session: object
    phase: str
    operation_seq: int
    wire: WireSlice
    raw_bytes: bytes
    ranges: tuple[tuple[int, int], ...]


class C0Wire:
    """One owner-thread wire. Endpoints stay borrowed, including after failure."""

    def __init__(self, qmp, streams, *, started_ns):
        deny(type(started_ns) is int and 0 <= started_ns <= time.monotonic_ns(),
             "c0_start_time")
        deny(type(qmp) is socket.socket and type(streams) is dict
             and all(type(name) is str and name in _PASSIVE_STREAMS for name in streams),
             "c0_stream_inventory")
        sources = {"qmp-in": qmp, **streams}
        deny(all(type(source) is socket.socket or (
                 name != "rsp" and type(source) is io.FileIO and source.readable())
                 for name, source in sources.items()), "c0_stream_type")
        identities = set()
        for source in sources.values():
            fd = source.fileno()
            deny(fd >= 0 and not os.get_blocking(fd), "c0_stream_descriptor")
            identity = os.fstat(fd)
            key = (identity.st_dev, identity.st_ino)
            if type(source) is socket.socket:
                valid = (stat.S_ISSOCK(identity.st_mode)
                         and source.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_STREAM)
            else:
                valid = stat.S_ISFIFO(identity.st_mode)
            deny(valid and key not in identities, "c0_stream_descriptor")
            identities.add(key)
        deny(qmp.gettimeout() == 0.0, "c0_stream_descriptor")

        self._deadline = started_ns + OWNER_NS - TEARDOWN_NS
        self._qmp = qmp
        self._rsp_socket = streams.get("rsp")
        self._rsp_active = self._rsp_eof = self._rsp_used = self._prelaunch_complete = False
        self._rsp_frames = deque()
        self._rsp_decoder = None
        self._rsp_offset = self._rsp_acks = 0
        self._raw = {name: bytearray() for name in (*sources, "qmp-out", "rsp-out")}
        self._charged = 0
        self._operations = []
        self._events = []
        self._eofs = []
        self._io_errors = []
        self._failure = None
        self._used = self._closed = self._greeted = self._qmp_eof = False
        self._frames = deque()
        self._frame_count = self._frame_start = self._scan_at = 0
        self._qmp_identifier = self._receive_ordinal = 0
        self._event_ordinals = []
        self._rsp_ready = self._boot_active = self._boot_resumed = self._boot_stopped = False
        self._entry_state = "new"
        self._entry = self._entry_stop = None
        self._confirmed_stop = self._current_mode = None
        self._before_registers = self._after_registers = self._final_register_view = None
        self._host_lease = self._host_peer = self._host_before = self._host_after = None
        self._host_receipt = self._layout_before = self._layout_after = None
        self._current_binding = self._current_acquisition = self._reads_complete = None
        self._ram_transport_identity = self._admission_epoch = None
        self._session = object()

        self._selector = selectors.DefaultSelector()
        try:
            for name, source in sources.items():
                self._selector.register(source, selectors.EVENT_READ, name)
        except BaseException:
            self._selector.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        if not self._closed:
            self._closed = True
            self._selector.close()

    @property
    def operations(self):
        return tuple(self._operations)

    @property
    def events(self):
        return tuple(self._events)

    @property
    def eofs(self):
        return tuple(self._eofs)

    @property
    def io_errors(self):
        return tuple(self._io_errors)

    @property
    def failure(self):
        return self._failure

    @property
    def _remaining_bytes(self):
        return MAX_RETAINED_BYTES - REPORT_RESERVE - FAILURE_RESERVE - self._charged

    def raw(self, stream):
        return bytes(self._raw[stream])

    def reserve_output(self, length):
        """Charge a separate owner artifact against the same retained-byte cap."""
        deny(type(length) is int and length >= 0, "c0_storage_length")
        incomplete(length <= self._remaining_bytes, "storage_limit")
        self._charged += length

    @staticmethod
    def _time_left(deadline, reason):
        remaining = deadline - time.monotonic_ns()
        incomplete(remaining > 0, reason)
        return remaining / 1_000_000_000

    def _qmp_frames(self, observed_ns):
        raw = self._raw["qmp-in"]
        while (end := raw.find(b"\n", self._scan_at)) >= 0:
            length = end - self._frame_start - 1
            deny(length > 0 and raw[end - 1] == 13
                 and raw.find(b"\r", self._frame_start, end - 1) < 0, "qmp_wire_framing")
            incomplete(length <= MAX_FRAME and self._frame_count < MAX_QMP_FRAMES,
                       "qmp_frame_limit")
            self._frame_count += 1
            wire = WireSlice("qmp-in", self._frame_start, length)
            value = self._decode(wire)
            self._receive_ordinal += 1
            if ("event" in value and set(value) <= {"event", "timestamp", "data"}
                    and type(value["event"]) is str and type(value.get("timestamp")) is dict):
                self._record_event("qmp", value["event"], wire, observed_ns)
            self._frames.append((value, wire, observed_ns))
            self._frame_start = self._scan_at = end + 1
        self._scan_at = len(raw)
        # One extra CR can be the first half of the delimiter.
        incomplete(len(raw) - self._frame_start <= MAX_FRAME + int(raw.endswith(b"\r")),
                   "qmp_frame_limit")

    def _read(self, key, deadline, reason):
        stream = key.data
        count = min(READ_CHUNK, self._remaining_bytes)
        incomplete(count > 0, "storage_limit")
        if stream == "qmp-in":
            count = min(count, MAX_QMP_BYTES - len(self._raw[stream]))
            incomplete(count > 0, "qmp_wire_limit")
        while True:
            self._time_left(deadline, reason)
            try:
                data = os.read(key.fd, count)
                break
            except InterruptedError:
                continue
            except BlockingIOError:
                return
            except OSError as error:
                self._io_errors.append(StreamError(stream, "read", error.errno, time.monotonic_ns()))
                raise ProbeError("INCOMPLETE", "c0_stream_read_error") from error
        observed = time.monotonic_ns()
        if not data:
            self._selector.unregister(key.fileobj)
            self._eofs.append(EndOfStream(stream, observed))
            if stream == "qmp-in":
                self._qmp_eof = True
            elif stream == "rsp":
                self._rsp_eof = True
            return
        self.reserve_output(len(data))
        self._raw[stream].extend(data)
        if stream == "qmp-in":
            self._qmp_frames(observed)
        elif stream == "rsp" and self._rsp_active:
            for frame in self._rsp_decoder.feed(data):
                wire = WireSlice("rsp", self._rsp_offset, len(frame.raw))
                self._rsp_offset += len(frame.raw)
                if frame.kind in ("ACK", "NACK"):
                    incomplete(self._rsp_acks < MAX_RSP_ACKS, "rsp_ack_limit")
                    self._rsp_acks += 1
                self._receive_ordinal += 1
                if self._boot_active and frame.kind == "PACKET":
                    name = frame.payload.decode("ascii") if frame.payload.isascii() else "invalid"
                    self._record_event("rsp", name, wire, observed)
                self._rsp_frames.append((frame, wire, observed))

    def _poll(self, deadline, reason, *, wait=True, writing=False):
        incomplete(not self._qmp_eof, "qmp_eof")
        endpoint = self._rsp_socket if writing == "rsp" else self._qmp
        label = "rsp" if writing == "rsp" else "qmp-in"
        if writing:
            self._selector.modify(endpoint, selectors.EVENT_READ | selectors.EVENT_WRITE, label)
        while True:
            timeout = self._time_left(deadline, reason)
            try:
                ready = self._selector.select(timeout if wait else 0)
                break
            except InterruptedError:
                continue
        for key, mask in ready:
            if mask & selectors.EVENT_READ:
                self._read(key, deadline, reason)
        if writing and not (self._rsp_eof if writing == "rsp" else self._qmp_eof):
            self._selector.modify(endpoint, selectors.EVENT_READ, label)

    def _decode(self, wire):
        return decode_frame(bytes(self._raw[wire.stream][wire.offset:wire.offset + wire.length]))

    def _record_event(self, protocol, name, wire, observed):
        """Assign order at complete-frame recognition, never later queue parsing."""
        incomplete(len(self._events) < MAX_EVENTS, "c0_event_limit")
        self._events.append(Event(len(self._events) + 1, protocol, name, wire, observed))
        self._event_ordinals.append(self._receive_ordinal)

    def _refuse_event(self, value, wire, observed):
        if "event" in value:
            raise ProbeError("DENY", "qmp_prelaunch_event")

    def _boot_event(self, value):
        from run0_host_cpu_witness import shared_qmp_boot_event
        deny(self._boot_active and shared_qmp_boot_event(value, self._entry["invocation_profile"]),
             "c0_boot_event")
        name = value["event"]
        if name == "RESUME":
            deny(not self._boot_resumed and self._entry_state != "confirmed", "c0_boot_event_order")
            self._boot_resumed = True
        elif name == "STOP":
            deny(self._boot_resumed and not self._boot_stopped
                 and self._entry_state != "confirmed", "c0_boot_event_order")
            self._boot_stopped = True
        else:
            deny(self._boot_resumed, "c0_boot_event_order")

    def _drain_boot_events(self):
        while self._frames and "event" in self._frames[0][0]:
            value, _, _ = self._frames.popleft()
            self._boot_event(value)

    def _next_frame(self, deadline):
        while True:
            if self._boot_active:
                self._drain_boot_events()
            if self._frames:
                break
            self._poll(deadline, "qmp_response_timeout")
        self._time_left(deadline, "qmp_response_timeout")
        value, wire, observed = self._frames.popleft()
        self._refuse_event(value, wire, observed)
        return value, wire, observed

    def _require_quiet(self, deadline, reason):
        if self._boot_active:
            self._poll(deadline, reason, wait=False)
            self._drain_boot_events()
            deny(not self._frames, "qmp_unsolicited")
            incomplete(not self._qmp_eof, "qmp_eof")
            return
        if not self._frames and self._frame_start == len(self._raw["qmp-in"]):
            self._poll(deadline, reason, wait=False)
        if self._frames:
            value, wire, observed = self._frames[0]
            self._refuse_event(value, wire, observed)
        deny(not self._frames and self._frame_start == len(self._raw["qmp-in"]),
             "qmp_unsolicited")
        incomplete(not self._qmp_eof, "qmp_eof")

    def _send(self, request, deadline):
        data = self._raw["qmp-out"]
        view = memoryview(request)
        while view:
            self._time_left(deadline, "qmp_request_timeout")
            try:
                sent = self._qmp.send(view)
            except (BlockingIOError, InterruptedError):
                self._poll(deadline, "qmp_request_timeout", writing=True)
                self._require_quiet(deadline, "qmp_request_timeout")
                continue
            except OSError as error:
                self._io_errors.append(StreamError("qmp-out", "write", error.errno,
                                                   time.monotonic_ns()))
                raise ProbeError("INCOMPLETE", "qmp_write_error") from error
            incomplete(sent > 0, "qmp_send_eof")
            data.extend(view[:sent])
            view = view[sent:]
            if view:
                self._require_quiet(deadline, "qmp_request_timeout")

    @staticmethod
    def _value(command, value, *, debug=False):
        if command == "qmp_capabilities":
            deny(value == {}, "qmp_capabilities_reply")
        elif command == "query-commands":
            deny(type(value) is list and all(type(row) is dict and set(row) == {"name"}
                 and type(row["name"]) is str for row in value), "qmp_command_inventory")
            names = tuple(row["name"] for row in value)
            deny(len(set(names)) == len(names) and set(_REQUIRED_COMMANDS) <= set(names),
                 "qmp_command_inventory")
            return names
        elif command == "query-status":
            incomplete(type(value) is dict and set(value) == {"running", "singlestep", "status"}
                       and value["running"] is False and value["singlestep"] is False
                       and value["status"] == ("debug" if debug else "prelaunch"),
                       "qmp_not_debug" if debug else "qmp_not_prelaunch")
        else:
            return value
        return None

    def _exchange(self, *, debug=False):
        index = self._qmp_identifier
        deny(self._greeted and not self._closed and self._failure is None
             and (debug and index == len(_COMMANDS) and self._entry_state == "stopped"
                  or not debug and index < len(_COMMANDS))
             and (not self._operations or self._operations[-1].result == "ok"), "qmp_session_state")
        command = "query-status" if debug else _COMMANDS[index]
        return self._qmp_exchange(command, command.replace("-", "_"), None,
                                  self._deadline, debug=debug)

    def _qmp_exchange(self, command, name, arguments, limit, *, debug=False):
        """Private engine; only closed bootstrap/observation operations call it."""
        deny(not self._closed and self._failure is None and
             (not self._operations or self._operations[-1].result == "ok"), "qmp_session_state")
        if self._rsp_active:
            self._rsp_quiet(limit)
        else:
            self._require_quiet(limit, "qmp_request_timeout")
        started = time.monotonic_ns()
        deadline = min(started + RESPONSE_NS, self._deadline, limit)
        identifier = self._qmp_identifier + 1
        request_value = {"execute": command, "id": identifier}
        if arguments is not None:
            request_value["arguments"] = arguments
        request = json.dumps(request_value, separators=(",", ":")).encode() + b"\r\n"
        offset = len(self._raw["qmp-out"])
        incomplete(len(self._operations) < MAX_OPERATIONS, "c0_operation_limit")
        incomplete(len(request) <= MAX_QMP_BYTES - offset, "qmp_wire_limit")
        self._time_left(deadline, "qmp_request_timeout")
        self.reserve_output(len(request))
        row = Operation(len(self._operations) + 1, "qmp", name, started)
        self._operations.append(row)
        self._qmp_identifier = identifier
        accepted, finished, result = None, None, "error"
        try:
            self._send(request, deadline)
            reply, wire, observed = self._next_frame(deadline)
            deny(set(reply) in ({"return", "id"}, {"error", "id"})
                 and type(reply["id"]) is int and reply["id"] == identifier,
                 "qmp_response_identity")
            incomplete("error" not in reply, "qmp_command_error")
            value = self._value(command, reply["return"], debug=debug)
            if debug:
                incomplete(self._boot_resumed and self._boot_stopped, "c0_boot_events_missing")
            self._time_left(deadline, "qmp_response_timeout")
            accepted, finished, result = wire, observed, "ok"
            return value, observed
        except ProbeError as error:
            if "timeout" in error.reason:
                result = "timeout"
            raise
        finally:
            length = len(self._raw["qmp-out"]) - offset
            prefix = WireSlice("qmp-out", offset, length) if length else None
            self._operations[-1] = replace(row, request=prefix, response=accepted, result=result,
                                           finished_ns=time.monotonic_ns() if finished is None
                                           else finished)

    def prelaunch(self):
        """Negotiate and check a paused prelaunch exactly once on this wire."""
        deny(not self._used and not self._closed, "qmp_session_state")
        self._used = True
        try:
            deadline = min(time.monotonic_ns() + RESPONSE_NS, self._deadline)
            greeting, _, _ = self._next_frame(deadline)
            deny(set(greeting) == {"QMP"} and type(greeting["QMP"]) is dict, "qmp_greeting")
            self._greeted = True
            self._exchange()
            commands, _ = self._exchange()
            _, observed = self._exchange()
            self._require_quiet(self._deadline, "qmp_response_timeout")
            self._prelaunch_complete = True
            return Prelaunch(commands, observed)
        except ProbeError as error:
            self._failure = Failure(error.status, error.reason)
            raise
        except OSError as error:
            self._failure = Failure("INCOMPLETE", "c0_selector_error")
            raise ProbeError(self._failure.status, self._failure.reason) from error
        except KeyboardInterrupt:
            self._failure = Failure("INCOMPLETE", "c0_cancelled")
            raise

    def _rsp_qmp_quiet(self):
        if self._boot_active:
            self._drain_boot_events()
            deny(not self._frames, "qmp_unsolicited")
            incomplete(not self._qmp_eof, "qmp_eof")
            return
        if self._frames:
            value, wire, observed = self._frames[0]
            self._refuse_event(value, wire, observed)
        deny(not self._frames and self._frame_start == len(self._raw["qmp-in"]),
             "qmp_unsolicited")
        incomplete(not self._qmp_eof, "qmp_eof")

    def _rsp_quiet(self, deadline):
        self._poll(deadline, "rsp_request_timeout", wait=False)
        self._rsp_qmp_quiet()
        deny(not self._rsp_frames and not self._rsp_decoder.pending, "rsp_unsolicited")
        incomplete(not self._rsp_eof, "rsp_eof")

    def _rsp_next(self, deadline, reason="rsp_response_timeout"):
        while not self._rsp_frames:
            incomplete(not self._rsp_eof, "rsp_eof")
            self._poll(deadline, reason)
            self._rsp_qmp_quiet()
        self._time_left(deadline, reason)
        return self._rsp_frames.popleft()

    def _rsp_send(self, request, deadline):
        view = memoryview(request)
        while view:
            self._time_left(deadline, "rsp_request_timeout")
            try:
                sent = self._rsp_socket.send(view)
            except (BlockingIOError, InterruptedError):
                self._poll(deadline, "rsp_request_timeout", writing="rsp")
                self._rsp_quiet(deadline)
                continue
            except OSError as error:
                self._io_errors.append(StreamError("rsp-out", "write", error.errno,
                                                   time.monotonic_ns()))
                raise ProbeError("INCOMPLETE", "rsp_write_error") from error
            incomplete(sent > 0, "rsp_send_eof")
            self._raw["rsp-out"].extend(view[:sent])
            view = view[sent:]
            if view:
                self._rsp_quiet(deadline)

    def _rsp_semantic(self, reason, status):
        self._operations[-1] = replace(self._operations[-1], result="error")
        raise ProbeError(status, reason)

    def _rsp_exchange(self, name, payload, *, limit=None):
        deny(self._rsp_active and self._failure is None and not self._closed,
             "rsp_session_state")
        limit = self._deadline if limit is None else min(limit, self._deadline)
        self._rsp_quiet(limit)
        started = time.monotonic_ns()
        deadline = min(started + RESPONSE_NS, limit)
        request = rsp.encode_packet(payload)
        incomplete(len(self._operations) < MAX_OPERATIONS, "c0_operation_limit")
        incomplete(self._rsp_acks <= MAX_RSP_ACKS - 2, "rsp_ack_limit")
        self._time_left(deadline, "rsp_request_timeout")
        self.reserve_output(len(request))
        row = Operation(len(self._operations) + 1, "rsp", name, started)
        self._operations.append(row)
        offset = len(self._raw["rsp-out"])
        accepted, result = None, "error"
        try:
            self._rsp_send(request, deadline)
            ack, _, _ = self._rsp_next(deadline)
            rsp.require(ack.kind == "ACK", "rsp_request_ack",
                        status="INCOMPLETE" if ack.kind == "NACK" else "DENY")
            response, wire, _ = self._rsp_next(deadline)
            rsp.require(response.kind == "PACKET", "rsp_response_packet")
            accepted = wire
            self._rsp_quiet(deadline)
            incomplete(self._rsp_acks < MAX_RSP_ACKS, "rsp_ack_limit")
            self.reserve_output(1)
            self._rsp_send(b"+", deadline)
            self._rsp_acks += 1
            self._time_left(deadline, "rsp_response_timeout")
            rsp.require(response.payload != b"", "rsp_unsupported", status="INCOMPLETE")
            rsp.require(not (len(response.payload) == 3 and response.payload[:1] == b"E"
                             and rsp.HEX.fullmatch(response.payload[1:])),
                        "rsp_remote_error", status="INCOMPLETE")
            result = "ok"
            return response.payload
        except ProbeError as error:
            if "timeout" in error.reason or "deadline" in error.reason:
                result = "timeout"
            raise
        finally:
            length = len(self._raw["rsp-out"]) - offset
            # Ordinary response ACKs are separate raw bytes, not request bytes.
            request_length = min(length, len(request))
            prefix = WireSlice("rsp-out", offset, request_length) if request_length else None
            self._operations[-1] = replace(row, request=prefix, response=accepted, result=result,
                                           finished_ns=time.monotonic_ns())

    def prepare_rsp_reset(self):
        """Run the fixed typed reset sequence after this wire's paused handshake."""
        deny(self._prelaunch_complete and not self._closed and self._failure is None
             and not self._rsp_used, "rsp_session_state")
        self._rsp_used = True
        try:
            deny(type(self._rsp_socket) is socket.socket
                 and self._rsp_socket.gettimeout() == 0.0, "rsp_endpoint")
            self._rsp_socket.getpeername()
            deny(not self._raw["rsp"], "rsp_unsolicited")
            incomplete(not self._rsp_eof, "rsp_eof")
            self._rsp_decoder = rsp._C0AckDecoder()
            self._rsp_active = True
            self._rsp_quiet(self._deadline)
            from run0_c0_rsp import _C0Reset
            self._rsp_reset = _C0Reset(self)
            result = self._rsp_reset.prepare()
            self._rsp_ready = True
            return result
        except ProbeError as error:
            self._failure = Failure(error.status, error.reason)
            raise
        except OSError as error:
            self._failure = Failure("INCOMPLETE", "c0_selector_error")
            raise ProbeError(self._failure.status, self._failure.reason) from error
        except KeyboardInterrupt:
            self._failure = Failure("INCOMPLETE", "c0_cancelled")
            raise

    @contextmanager
    def _entry_attempt(self):
        """Only admitted effects terminalize the session; retain the first cause."""
        try:
            yield
        except ProbeError as error:
            if self._failure is None:
                self._failure = Failure(error.status, error.reason)
            raise
        except OSError as error:
            if self._failure is None:
                self._failure = Failure("INCOMPLETE", "c0_selector_error")
            raise ProbeError(self._failure.status, self._failure.reason) from error
        except KeyboardInterrupt:
            if self._failure is None:
                self._failure = Failure("INCOMPLETE", "c0_cancelled")
            raise

    def _entry_local_state(self, state):
        deny(self._rsp_ready and self._failure is None and not self._closed
             and self._entry_state == state, "c0_entry_state")

    def install_entry_breakpoint(self, token):
        """Install one candidate-derived breakpoint after typed reset setup.

        The token proves retained prior inputs, not the borrowed sockets' launch
        identity. That same-profile owned-launch join remains a collector duty.
        """
        self._entry_local_state("new")
        from run0_c0_entry import export_validated_prior_entry
        from run0_c0_decode import C0DecodeError
        try:
            admitted = export_validated_prior_entry(token)
        except C0DecodeError as error:
            # A local bad argument has not admitted any operation or wire byte.
            raise ProbeError(error.status, error.reason) from error
        with self._entry_attempt():
            self._entry = admitted
            reply = self._rsp_exchange("hardware_breakpoint_set",
                                       f"Z1,{admitted['entry_address']:x},1".encode())
            if reply != b"OK":
                self._rsp_semantic("rsp_breakpoint_reply", "DENY")
            self._breakpoint_seq = self._operations[-1].seq
            self._entry_state = "installed"
            return self._operations[-1]

    def _continue_ack(self):
        self._rsp_quiet(self._deadline)
        started = time.monotonic_ns()
        ack_deadline = min(started + RESPONSE_NS, self._deadline)
        # The silent wait begins at the original c start, never at its ACK.
        self._stop_deadline = min(started + CONTINUE_NS, self._deadline)
        request = rsp.encode_packet(b"c")
        incomplete(len(self._operations) <= MAX_OPERATIONS - 2, "c0_operation_limit")
        incomplete(len(self._events) <= MAX_EVENTS - 3, "c0_event_limit")
        incomplete(self._rsp_acks <= MAX_RSP_ACKS - 2, "rsp_ack_limit")
        self._time_left(ack_deadline, "rsp_request_timeout")
        self.reserve_output(len(request))
        index, offset = len(self._operations), len(self._raw["rsp-out"])
        row = Operation(index + 1, "rsp", "resume", started)
        self._operations.append(row)
        accepted = finished = None
        result = "error"
        try:
            # While c is only a prefix, all incoming traffic is still forbidden.
            self._rsp_send(request, ack_deadline)
            self._boot_active = True
            self._entry_state = "continuing"
            ack, wire, observed = self._rsp_next(ack_deadline)
            rsp.require(ack.kind == "ACK", "rsp_request_ack",
                        status="INCOMPLETE" if ack.kind == "NACK" else "DENY")
            accepted, finished, result = wire, observed, "ok"
            return row.seq
        except ProbeError as error:
            if "timeout" in error.reason:
                result = "timeout"
            raise
        finally:
            length = len(self._raw["rsp-out"]) - offset
            prefix = WireSlice("rsp-out", offset, length) if length else None
            self._operations[index] = replace(row, request=prefix, response=accepted, result=result,
                finished_ns=time.monotonic_ns() if finished is None else finished)

    def _acknowledge_stop(self, stop_event):
        # Drain a coalesced or newly readable tail before any outgoing stop ACK.
        # Boot QMP events may arrive independently; only their own order matters.
        self._rsp_quiet(self._stop_deadline)
        started = time.monotonic_ns()
        deny(started > stop_event.received_ns, "rsp_stop_ack_clock")
        deadline = min(started + RESPONSE_NS, self._stop_deadline)
        incomplete(len(self._operations) < MAX_OPERATIONS, "c0_operation_limit")
        incomplete(self._rsp_acks < MAX_RSP_ACKS, "rsp_ack_limit")
        self._time_left(deadline, "rsp_request_timeout")
        self.reserve_output(1)
        index, offset = len(self._operations), len(self._raw["rsp-out"])
        row = Operation(index + 1, "rsp", "acknowledge_stop", started)
        self._operations.append(row)
        result = "error"
        try:
            self._rsp_send(b"+", deadline)
            self._rsp_acks += 1
            self._time_left(deadline, "rsp_request_timeout")
            result = "ok"
            return row.seq
        except ProbeError as error:
            if "timeout" in error.reason:
                result = "timeout"
            raise
        finally:
            length = len(self._raw["rsp-out"]) - offset
            self._operations[index] = replace(row, result=result,
                request=WireSlice("rsp-out", offset, length) if length else None,
                finished_ns=time.monotonic_ns())

    def resume_to_entry(self):
        """One c, real request ACK, silent stop wait, then one separate stop ACK.

        The returned receipt proves this transport prefix only. It supplies no
        breakpoint-cause, actual RIP, RAM, witness or live-read authority.
        """
        self._entry_local_state("installed")
        with self._entry_attempt():
            resume_seq = self._continue_ack()
            response, wire, observed = self._rsp_next(self._stop_deadline, "rsp_stop_timeout")
            rsp.require(response.kind == "PACKET", "rsp_stop_packet")
            rsp.require(response.payload == b"T05thread:01;", "rsp_stop_identity")
            stop_event = next(event for event in self._events
                              if event.protocol == "rsp" and event.wire == wire)
            deny(observed >= self._operations[resume_seq-1].finished_ns, "rsp_stop_clock")
            ack_seq = self._acknowledge_stop(stop_event)
            self._entry_stop = EntryStop(self._session, self._entry["entry_address"],
                self._breakpoint_seq, resume_seq, stop_event.seq, ack_seq, observed)
            self._entry_state = "stopped"
            return self._entry_stop

    def confirm_entry_stop(self):
        """Bind the separate fresh QMP debug reply to this wire's stop receipt."""
        self._entry_local_state("stopped")
        with self._entry_attempt():
            self._rsp_quiet(self._deadline)
            _, observed = self._exchange(debug=True)
            status_seq = self._operations[-1].seq
            self._entry_state = "confirmed"
            self._require_quiet(self._deadline, "qmp_response_timeout")
            # A QMP read can also receive unsolicited RSP bytes on the common
            # selector. Never publish a complete prefix with an unclaimed tail.
            deny(not self._rsp_frames and not self._rsp_decoder.pending, "rsp_unsolicited")
            incomplete(not self._rsp_eof, "rsp_eof")
            self._confirmed_stop = ConfirmedEntryStop(self._entry_stop, status_seq, observed)
            return self._confirmed_stop

    def _current_stop(self, confirmed):
        self._entry_local_state("confirmed")
        deny(type(confirmed) is ConfirmedEntryStop and confirmed is self._confirmed_stop
             and confirmed.stop is self._entry_stop and confirmed.stop._session is self._session,
             "c0_current_stop")

    def _current_deadline(self):
        return min(self._deadline, self._entry_stop.received_ns + CONTINUE_NS)

    def confirm_stopped_physical_mode(self, confirmed):
        self._current_stop(confirmed)
        deny(self._current_mode is None and self._before_registers is None, "c0_mode_state")
        with self._entry_attempt():
            from run0_c0_rsp import _current_physical_mode
            _current_physical_mode(self, self._current_deadline())
            self._current_mode = CurrentPhysicalMode(self._session, confirmed.stop.stop_event_seq,
                                                     self._operations[-1].seq, 1)
            return self._current_mode

    def _require_acquisition_complete(self):
        # No setter/issuer exists here. Only the separately reviewed real collector
        # may register these held objects after current owned RAM admission.
        deny(all(value is not None for value in (self._current_binding,
             self._current_acquisition, self._reads_complete, self._ram_transport_identity,
             self._admission_epoch)), "c0_current_acquisition_pending")
        import run0_c0_acquire as acquire
        import run0_c0_decode as decoder
        with self._entry_attempt():
            try:
                binding = self._current_binding
                acquire.require_runtime_binding(binding)
                deny(type(self._current_acquisition) is acquire.AcquisitionSession
                     and type(self._reads_complete) is acquire.ReadsComplete
                     and binding.confirmed_stop is self._confirmed_stop
                     and binding.wire_identity is self._session
                     and self._current_acquisition.binding is binding,
                     "c0_current_acquisition_identity")
                result = self._current_acquisition.require_reads_complete(self._reads_complete,
                    self._ram_transport_identity, self._admission_epoch, time.monotonic_ns())
                deny(result is binding, "c0_current_acquisition_identity")
            except decoder.C0DecodeError as error:
                raise ProbeError(error.status, error.reason) from error

    def read_selected_registers(self, confirmed, phase):
        self._current_stop(confirmed)
        deny(type(phase) is str and phase in ("before", "after"), "c0_register_phase")
        deny(self._current_mode is not None and (phase == "before" and self._before_registers is None
             and self._host_lease is None or phase == "after" and self._before_registers is not None
             and self._host_receipt is not None and self._layout_before is not None
             and self._after_registers is None), "c0_register_state")
        if phase == "after":
            self._require_acquisition_complete()
        with self._entry_attempt():
            from run0_c0_rsp import _selected_registers
            values = _selected_registers(self, self._current_deadline())
            if phase == "before":
                if dict((number, value) for number, value, _ in values)[16] != confirmed.stop.entry_address:
                    self._rsp_semantic("c0_entry_rip", "DENY")
            elif tuple((n, v) for n, v, _ in values) != tuple((n, v) for n, v, _ in self._before_registers.values):
                self._rsp_semantic("c0_registers_changed", "INCOMPLETE")
            result = SelectedC0Registers(self._session, confirmed.stop.stop_event_seq, phase, values)
            if phase == "before":
                self._before_registers = result
            else:
                self._after_registers = result
            return result

    def begin_host_observation(self, confirmed, before_registers):
        self._current_stop(confirmed)
        deny(type(before_registers) is SelectedC0Registers
             and before_registers is self._before_registers and self._host_lease is None,
             "c0_host_lease_state")
        with self._entry_attempt():
            deadline = min(time.monotonic_ns() + RESPONSE_NS, self._current_deadline())
            self._rsp_quiet(deadline)
            self._host_lease = HostObservationLease(self._session, confirmed.stop.stop_event_seq, deadline)
            return self._host_lease

    def _lease(self, lease):
        self._current_stop(self._confirmed_stop)
        deny(type(lease) is HostObservationLease and lease is self._host_lease
             and lease._session is self._session and self._host_receipt is None,
             "c0_host_lease_state")

    def host_peer_credentials(self, lease):
        self._lease(lease)
        deny(self._host_peer is None and self._host_before is None, "c0_host_peer_state")
        with self._entry_attempt():
            self._rsp_quiet(lease.deadline_ns)
            from run0_host_cpu_witness import NATIVE_LAYOUT
            raw = self._qmp.getsockopt(socket.SOL_SOCKET, NATIVE_LAYOUT["so_peercred"], 12)
            observed = time.monotonic_ns()
            self._time_left(lease.deadline_ns, "witness_deadline")
            deny(type(raw) is bytes and len(raw) == 12, "peer_credentials_shape")
            self.reserve_output(len(raw))
            self._host_peer = PeerReceipt(self._session, raw, observed)
            return self._host_peer

    @staticmethod
    def _hmp_state(raw, registers):
        from run0_host_cpu_witness import c0_registers
        import run0_c0_decode as decoder
        deny(type(raw) is str and raw.isascii() and 0 < len(raw) <= 65536, "hmp_shape")
        values = {number: value for number, value, _ in registers.values}
        c0_registers(raw, values)
        try:
            parsed = decoder._hmp(raw.encode("ascii"), values)
        except decoder.C0DecodeError as error:
            raise ProbeError(error.status, error.reason) from error
        return (parsed["cpl"], parsed["smm"], parsed["a20"], parsed["cs64"],
                tuple(sorted(parsed["descriptors"].items())))

    def host_bracket(self, lease, phase):
        self._lease(lease)
        deny(type(phase) is str and (phase == "before" and self._host_peer is not None
             and self._host_before is None or phase == "after" and self._host_before is not None
             and self._host_after is None), "c0_host_bracket_state")
        with self._entry_attempt():
            from run0_host_cpu_witness import cpu_path, realized_width, MAX_PID
            indices = []

            def request(command, name, key, arguments=None):
                value, _ = self._qmp_exchange(command, name, arguments, lease.deadline_ns,
                                              debug=command == "query-status")
                indices.append((key, self._operations[-1].seq))
                return value

            try:
                request("query-status", "query_status", "status_seq")
                cpus = request("query-cpus-fast", "query_cpus_fast", "cpu_seq")
                path = cpu_path(cpus)
                tid = cpus[0]["thread-id"]
                deny(type(tid) is int and 1 <= tid <= MAX_PID, "qmp_host_tid")
                realized = request("qom-get", "qom_realized", "realized_seq",
                                   {"path": path, "property": "realized"})
                width = request("qom-get", "qom_phys_bits", "phys_bits_seq",
                                {"path": path, "property": "phys-bits"})
                width = realized_width(realized, width)
                raw = request("human-monitor-command", "hmp_registers", "hmp_seq",
                              {"command-line": "info registers"})
                parsed = self._hmp_state(raw, self._before_registers)
                self._rsp_quiet(lease.deadline_ns)
                encoded = raw.encode("ascii")
                self.reserve_output(len(encoded))
                result = C0HostBracket(self._session, phase, tuple(indices),
                                       (path, tid, width), encoded, parsed)
                if phase == "before":
                    self._host_before = result
                else:
                    incomplete((result.cpu_identity, result.hmp_bytes, result.parsed_state) ==
                               (self._host_before.cpu_identity, self._host_before.hmp_bytes,
                                self._host_before.parsed_state), "c0_host_bracket_changed")
                    self._host_after = result
                return result
            except ProbeError:
                if indices and self._operations[-1].result == "ok":
                    self._operations[-1] = replace(self._operations[-1], result="error")
                raise

    def pump_host_observation(self, lease):
        self._lease(lease)
        with self._entry_attempt():
            self._time_left(lease.deadline_ns, "witness_deadline")
            self._rsp_quiet(lease.deadline_ns)
            deny(self._frame_start == len(self._raw["qmp-in"]), "qmp_observation_partial")

    def finish_host_observation(self, lease, actual_receipt):
        self._lease(lease)
        from run0_c0_host import _issued_observation
        deny(self._host_after is not None and _issued_observation(actual_receipt, self, lease),
             "c0_host_receipt_identity")
        with self._entry_attempt():
            self.pump_host_observation(lease)
            self._host_receipt = actual_receipt

    def read_final_register_view(self, confirmed, after_registers):
        self._current_stop(confirmed)
        deny(type(after_registers) is SelectedC0Registers and after_registers is self._after_registers
             and self._after_registers is not None and self._final_register_view is None,
             "c0_final_register_state")
        self._require_acquisition_complete()
        with self._entry_attempt():
            raw, _ = self._qmp_exchange("human-monitor-command", "hmp_registers",
                {"command-line": "info registers"}, self._current_deadline())
            try:
                parsed = self._hmp_state(raw, after_registers)
                encoded = raw.encode("ascii")
                incomplete(encoded == self._host_before.hmp_bytes, "c0_final_hmp_changed")
                self._rsp_quiet(self._current_deadline())
                self.reserve_output(len(encoded))
                row = self._operations[-1]
                self._final_register_view = C0RegisterView(self._session, row.seq, row.response, encoded, parsed)
                return self._final_register_view
            except ProbeError:
                self._operations[-1] = replace(self._operations[-1], result="error")
                raise

    def read_current_layout(self, confirmed, phase):
        self._current_stop(confirmed)
        deny(type(phase) is str and (phase == "before" and self._host_receipt is not None
             and self._layout_before is None or phase == "after" and self._layout_before is not None
             and self._final_register_view is not None and self._layout_after is None), "c0_layout_state")
        if phase == "after":
            self._require_acquisition_complete()
        with self._entry_attempt():
            raw, _ = self._qmp_exchange("human-monitor-command", "hmp_flatview",
                {"command-line": "info mtree -f"}, self._current_deadline())
            try:
                import run0_c0_decode as decoder
                from run0_rsp_capability import validate_profile_layout
                deny(type(raw) is str and raw.isascii() and 0 < len(raw) <= 65536, "layout_shape")
                encoded = raw.encode("ascii")
                ranges = decoder._layout(encoded)
                deny(ranges == validate_profile_layout(raw, self._entry["invocation_profile"]), "c0_layout_profile")
                if phase == "after":
                    incomplete(encoded == self._layout_before.raw_bytes, "c0_layout_changed")
                self._rsp_quiet(self._current_deadline())
                self.reserve_output(len(encoded))
                row = self._operations[-1]
                result = C0LayoutReceipt(self._session, phase, row.seq, row.response, encoded, tuple(ranges))
                if phase == "before":
                    self._layout_before = result
                else:
                    self._layout_after = result
                return result
            except (ProbeError, decoder.C0DecodeError) as error:
                self._operations[-1] = replace(self._operations[-1], result="error")
                raise ProbeError(error.status, error.reason) from error
