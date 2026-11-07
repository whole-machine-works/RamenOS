"""Bounded C0 wire ownership and the fixed QMP prelaunch handshake."""

from collections import deque
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
READ_CHUNK = 65_536
_COMMANDS = ("qmp_capabilities", "query-commands", "query-status")
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
            self._frames.append((WireSlice("qmp-in", self._frame_start, length), observed_ns))
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

    def _refuse_event(self, value, wire, observed):
        if "event" in value:
            if (set(value) <= {"event", "timestamp", "data"}
                    and type(value["event"]) is str and type(value.get("timestamp")) is dict):
                incomplete(len(self._events) < MAX_EVENTS, "c0_event_limit")
                self._events.append(Event(len(self._events) + 1, "qmp", value["event"], wire,
                                          observed))
            raise ProbeError("DENY", "qmp_prelaunch_event")

    def _next_frame(self, deadline):
        while not self._frames:
            self._poll(deadline, "qmp_response_timeout")
        self._time_left(deadline, "qmp_response_timeout")
        wire, observed = self._frames.popleft()
        value = self._decode(wire)
        self._refuse_event(value, wire, observed)
        return value, wire, observed

    def _require_quiet(self, deadline, reason):
        if not self._frames and self._frame_start == len(self._raw["qmp-in"]):
            self._poll(deadline, reason, wait=False)
        if self._frames:
            wire, observed = self._frames[0]
            self._refuse_event(self._decode(wire), wire, observed)
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
    def _value(command, value):
        if command == "qmp_capabilities":
            deny(value == {}, "qmp_capabilities_reply")
        elif command == "query-commands":
            deny(type(value) is list and all(type(row) is dict and set(row) == {"name"}
                 and type(row["name"]) is str for row in value), "qmp_command_inventory")
            names = tuple(row["name"] for row in value)
            deny(len(set(names)) == len(names) and set(_COMMANDS) <= set(names),
                 "qmp_command_inventory")
            return names
        else:
            incomplete(type(value) is dict and set(value) == {"running", "singlestep", "status"}
                       and value["running"] is False and value["singlestep"] is False
                       and value["status"] == "prelaunch", "qmp_not_prelaunch")
        return None

    def _exchange(self):
        index = len(self._operations)
        deny(self._greeted and not self._closed and self._failure is None
             and index < len(_COMMANDS)
             and (not index or self._operations[-1].result == "ok"), "qmp_session_state")
        identifier, command = index + 1, _COMMANDS[index]
        self._require_quiet(self._deadline, "qmp_request_timeout")
        started = time.monotonic_ns()
        deadline = min(started + RESPONSE_NS, self._deadline)
        request = json.dumps({"execute": command, "id": identifier},
                             separators=(",", ":")).encode() + b"\r\n"
        offset = len(self._raw["qmp-out"])
        incomplete(len(self._operations) < MAX_OPERATIONS, "c0_operation_limit")
        incomplete(len(request) <= MAX_QMP_BYTES - offset, "qmp_wire_limit")
        self._time_left(deadline, "qmp_request_timeout")
        self.reserve_output(len(request))
        row = Operation(len(self._operations) + 1, "qmp", command.replace("-", "_"), started)
        self._operations.append(row)
        accepted, finished, result = None, None, "error"
        try:
            self._send(request, deadline)
            reply, wire, observed = self._next_frame(deadline)
            deny(set(reply) in ({"return", "id"}, {"error", "id"})
                 and type(reply["id"]) is int and reply["id"] == identifier,
                 "qmp_response_identity")
            incomplete("error" not in reply, "qmp_command_error")
            value = self._value(command, reply["return"])
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
        if self._frames:
            wire, observed = self._frames[0]
            self._refuse_event(self._decode(wire), wire, observed)
        deny(not self._frames and self._frame_start == len(self._raw["qmp-in"]),
             "qmp_unsolicited")
        incomplete(not self._qmp_eof, "qmp_eof")

    def _rsp_quiet(self, deadline):
        self._poll(deadline, "rsp_request_timeout", wait=False)
        self._rsp_qmp_quiet()
        deny(not self._rsp_frames and not self._rsp_decoder.pending, "rsp_unsolicited")
        incomplete(not self._rsp_eof, "rsp_eof")

    def _rsp_next(self, deadline):
        while not self._rsp_frames:
            incomplete(not self._rsp_eof, "rsp_eof")
            self._poll(deadline, "rsp_response_timeout")
            self._rsp_qmp_quiet()
        self._time_left(deadline, "rsp_response_timeout")
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

    def _rsp_exchange(self, name, payload):
        deny(self._rsp_active and self._failure is None and not self._closed,
             "rsp_session_state")
        self._rsp_quiet(self._deadline)
        started = time.monotonic_ns()
        deadline = min(started + RESPONSE_NS, self._deadline)
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
            return self._rsp_reset.prepare()
        except ProbeError as error:
            self._failure = Failure(error.status, error.reason)
            raise
        except OSError as error:
            self._failure = Failure("INCOMPLETE", "c0_selector_error")
            raise ProbeError(self._failure.status, self._failure.reason) from error
        except KeyboardInterrupt:
            self._failure = Failure("INCOMPLETE", "c0_cancelled")
            raise
