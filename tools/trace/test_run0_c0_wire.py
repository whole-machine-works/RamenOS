"""Socket and pipe controls for the C0-only prelaunch transport."""

import json
import os
import socket
import threading
import time
import unittest
from contextlib import ExitStack
from unittest.mock import patch

from boot_profile_capture import ProbeError
from run0_c0_wire import C0Wire, MAX_RETAINED_BYTES, REPORT_RESERVE, FAILURE_RESERVE


def frame(value):
    return json.dumps(value, separators=(",", ":")).encode() + b"\r\n"


GREETING = frame({"QMP": {"capabilities": [], "version": {
    "qemu": {"major": 8, "minor": 2, "micro": 2}, "package": ""}}})
COMMANDS = ["qmp_capabilities", "query-commands", "query-status", "query-cpus-fast",
            "qom-get", "human-monitor-command", "quit"]
REQUESTS = [frame({"execute": name, "id": index})
            for index, name in enumerate(COMMANDS[:3], 1)]
RESULTS = [{}, [{"name": name} for name in COMMANDS],
           {"status": "prelaunch", "running": False, "singlestep": False}]
REPLIES = [frame({"return": result, "id": index})
           for index, result in enumerate(RESULTS, 1)]
RESUME = frame({"event": "RESUME", "timestamp": {"seconds": 1, "microseconds": 2}})


class WireTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)

    def endpoints(self):
        owner, peer = socket.socketpair()
        self.stack.enter_context(owner)
        self.stack.enter_context(peer)
        owner.setblocking(False)
        peer.settimeout(0.5)
        return owner, peer

    def pipe(self):
        read, write = os.pipe()
        reader = self.stack.enter_context(os.fdopen(read, "rb", buffering=0))
        writer = self.stack.enter_context(os.fdopen(write, "wb", buffering=0))
        os.set_blocking(reader.fileno(), False)
        return reader, writer

    def peer_task(self, callback):
        errors = []

        def run():
            try:
                callback()
            except (OSError, AssertionError) as error:
                errors.append(error)

        thread = threading.Thread(target=run, daemon=True)
        thread.start()

        def check():
            thread.join(1)
            self.assertFalse(thread.is_alive(), "peer fixture did not finish")
            if errors:
                raise errors[0]

        self.addCleanup(check)
        return check

    def recv_exact(self, peer, expected):
        data = bytearray()
        while len(data) < len(expected):
            chunk = peer.recv(len(expected) - len(data))
            self.assertTrue(chunk, f"peer EOF after {bytes(data)!r}")
            data.extend(chunk)
        self.assertEqual(bytes(data), expected)

    def wire(self, qmp, streams=None, started_ns=None):
        return self.stack.enter_context(C0Wire(
            qmp, {} if streams is None else streams,
            started_ns=time.monotonic_ns() if started_ns is None else started_ns,
        ))

    def fixture(self, wire, peer, replies=REPLIES):
        def exchange():
            peer.sendall(GREETING)
            for request, response in zip(REQUESTS, replies):
                self.recv_exact(peer, request)
                peer.sendall(response)

        self.peer_task(exchange)
        return wire.prelaunch()

    def no_next_request(self, peer):
        peer.setblocking(False)
        with self.assertRaises(BlockingIOError):
            peer.recv(1)

    def assert_failure(self, wire, reason):
        with self.assertRaises(ProbeError) as context:
            wire.prelaunch()
        self.assertEqual(context.exception.reason, reason)
        self.assertEqual(wire.failure.reason, reason)
        return context.exception

    def test_success_fragmented_reply_passive_rsp_pipe_tail_and_owner_lifetime(self):
        qmp, peer = self.endpoints()
        rsp, rsp_peer = self.endpoints()
        reader, writer = self.pipe()
        wire = self.wire(qmp, {"rsp": rsp, "serial": reader})

        def exchange():
            peer.sendall(GREETING[:9])
            time.sleep(0.01)
            peer.sendall(GREETING[9:])
            for index, (request, response) in enumerate(zip(REQUESTS, REPLIES)):
                self.recv_exact(peer, request)
                if index == 1:
                    rsp_peer.sendall(b"+$passive#00")
                    writer.write(b"last serial bytes")
                    writer.close()
                peer.sendall(response[:-1])
                time.sleep(0.005)
                peer.sendall(response[-1:])

        self.peer_task(exchange)
        result = wire.prelaunch()
        self.assertEqual(result.commands, tuple(COMMANDS))
        self.assertEqual(wire.raw("rsp"), b"+$passive#00")
        self.assertEqual(wire.raw("serial"), b"last serial bytes")
        self.assertEqual(tuple(row.stream for row in wire.eofs), ("serial",))
        self.assertEqual(wire.raw("qmp-in"), GREETING + b"".join(REPLIES))
        self.assertEqual(wire.raw("qmp-out"), b"".join(REQUESTS))
        self.assertEqual(tuple(row.operation for row in wire.operations),
                         ("qmp_capabilities", "query_commands", "query_status"))
        for index, row in enumerate(wire.operations):
            self.assertEqual((row.seq, row.protocol, row.result), (index + 1, "qmp", "ok"))
            self.assertEqual(row.request.stream, "qmp-out")
            self.assertEqual(row.response.stream, "qmp-in")
            self.assertEqual(wire.raw(row.request.stream)[
                row.request.offset:row.request.offset + row.request.length], REQUESTS[index])
            self.assertEqual(wire.raw(row.response.stream)[
                row.response.offset:row.response.offset + row.response.length], REPLIES[index][:-2])
            self.assertLessEqual(row.started_ns, row.finished_ns)
        self.assertEqual(result.observed_ns, wire.operations[-1].finished_ns)
        wire.close()
        self.assertGreaterEqual(qmp.fileno(), 0)
        self.assertGreaterEqual(rsp.fileno(), 0)
        self.assertFalse(reader.closed)

    def test_coalesced_event_receipt_equal_to_reply_and_denies_next_effect(self):
        qmp, peer = self.endpoints()
        wire = self.wire(qmp)

        def exchange():
            peer.sendall(GREETING)
            self.recv_exact(peer, REQUESTS[0])
            peer.sendall(REPLIES[0] + RESUME)

        self.peer_task(exchange)
        self.assert_failure(wire, "qmp_prelaunch_event")
        self.no_next_request(peer)
        self.assertEqual(wire.raw("qmp-in"), GREETING + REPLIES[0] + RESUME)
        self.assertEqual(len(wire.operations), 1)
        self.assertEqual(wire.operations[0].result, "ok")
        self.assertEqual(len(wire.events), 1)
        event = wire.events[0]
        self.assertEqual((event.seq, event.name, event.protocol), (1, "RESUME", "qmp"))
        self.assertEqual(event.received_ns, wire.operations[0].finished_ns)
        self.assertEqual((event.wire.offset, event.wire.length),
                         (len(GREETING) + len(REPLIES[0]), len(RESUME) - 2))
        with self.assertRaises(ProbeError):
            wire.prelaunch()
        self.assertEqual(wire.failure.reason, "qmp_prelaunch_event")
        self.no_next_request(peer)

    def test_coalesced_extra_reply_or_partial_frame_never_dispatches_next_request(self):
        for extra in (REPLIES[1], b'{"event":'):
            with self.subTest(extra=extra):
                qmp, peer = self.endpoints()
                wire = self.wire(qmp)

                def exchange():
                    peer.sendall(GREETING)
                    self.recv_exact(peer, REQUESTS[0])
                    peer.sendall(REPLIES[0] + extra)

                self.peer_task(exchange)
                self.assert_failure(wire, "qmp_unsolicited")
                self.assertEqual(wire.raw("qmp-in"), GREETING + REPLIES[0] + extra)
                self.assertEqual(len(wire.operations), 1)
                self.no_next_request(peer)

    def test_wrong_reply_id_is_retained_raw_without_accepted_response(self):
        qmp, peer = self.endpoints()
        wire = self.wire(qmp)
        wrong = frame({"return": {}, "id": True})

        def exchange():
            peer.sendall(GREETING)
            self.recv_exact(peer, REQUESTS[0])
            peer.sendall(wrong)

        self.peer_task(exchange)
        self.assert_failure(wire, "qmp_response_identity")
        self.assertEqual(wire.raw("qmp-in"), GREETING + wrong)
        self.assertEqual(wire.operations[0].result, "error")
        self.assertIsNone(wire.operations[0].response)
        self.no_next_request(peer)

    def test_partial_send_retains_actual_prefix_and_preserves_first_failure(self):
        qmp, peer = self.endpoints()
        wire = self.wire(qmp)
        peer.sendall(GREETING)
        actual_send = socket.socket.send
        calls = 0

        def send_prefix(sock, data):
            nonlocal calls
            self.assertIs(sock, qmp)
            calls += 1
            if calls == 1:
                sent = actual_send(sock, data[:7])
                sock.shutdown(socket.SHUT_WR)
                return sent
            return actual_send(sock, data)

        with patch.object(socket.socket, "send", send_prefix):
            self.assert_failure(wire, "qmp_write_error")
        self.assertEqual(peer.recv(128), REQUESTS[0][:7])
        self.assertEqual(peer.recv(1), b"")
        self.assertEqual(wire.raw("qmp-out"), REQUESTS[0][:7])
        row = wire.operations[0]
        self.assertEqual((row.request.offset, row.request.length), (0, 7))
        self.assertEqual(row.result, "error")
        self.assertIsNone(row.response)
        with self.assertRaises(ProbeError):
            wire.prelaunch()
        self.assertEqual(wire.failure.reason, "qmp_write_error")

    def test_eof_records_actual_zero_read_and_fresh_independent_fixture_succeeds(self):
        qmp, peer = self.endpoints()
        wire = self.wire(qmp)

        def exchange():
            peer.sendall(GREETING)
            self.recv_exact(peer, REQUESTS[0])
            peer.sendall(b'{"return":')
            peer.shutdown(socket.SHUT_WR)

        self.peer_task(exchange)
        self.assert_failure(wire, "qmp_eof")
        self.assertEqual(wire.raw("qmp-in"), GREETING + b'{"return":')
        self.assertEqual(tuple(row.stream for row in wire.eofs), ("qmp-in",))
        self.assertIsNone(wire.operations[0].response)
        self.no_next_request(peer)
        fresh_qmp, fresh_peer = self.endpoints()
        self.assertEqual(self.fixture(self.wire(fresh_qmp), fresh_peer).commands, tuple(COMMANDS))

    def test_original_owner_deadline_clips_wait_without_claiming_eof(self):
        qmp, peer = self.endpoints()
        started_ns = time.monotonic_ns() - 85_000_000_000 + 200_000_000
        wire = self.wire(qmp, started_ns=started_ns)
        peer.sendall(GREETING)
        before = time.monotonic()
        self.assert_failure(wire, "qmp_response_timeout")
        self.assertLess(time.monotonic() - before, 0.8)
        self.recv_exact(peer, REQUESTS[0])
        self.assertEqual(wire.eofs, ())
        self.assertEqual(wire.operations[0].result, "timeout")
        self.no_next_request(peer)

    def test_shared_output_reserve_denies_request_before_first_send(self):
        qmp, peer = self.endpoints()
        wire = self.wire(qmp)
        wire.reserve_output(MAX_RETAINED_BYTES - REPORT_RESERVE - FAILURE_RESERVE
                            - len(GREETING) - len(REQUESTS[0]) + 1)
        peer.sendall(GREETING)
        self.assert_failure(wire, "storage_limit")
        self.assertEqual(wire.raw("qmp-in"), GREETING)
        self.assertEqual(wire.raw("qmp-out"), b"")
        self.assertEqual(wire.operations, ())
        self.no_next_request(peer)

    def test_duplicate_socket_description_is_refused_even_with_distinct_fds(self):
        qmp, peer = self.endpoints()
        alias = self.stack.enter_context(socket.socket(fileno=os.dup(qmp.fileno())))
        self.assertNotEqual(alias.fileno(), qmp.fileno())
        with self.assertRaisesRegex(ProbeError, "c0_stream_descriptor"):
            self.wire(qmp, {"rsp": alias})
        self.no_next_request(peer)

    def test_buffered_pipe_is_refused_before_bypassing_its_prefetched_bytes(self):
        qmp, peer = self.endpoints()
        read, write = os.pipe()
        reader = self.stack.enter_context(os.fdopen(read, "rb"))
        writer = self.stack.enter_context(os.fdopen(write, "wb", buffering=0))
        writer.write(b"prefetched")
        os.set_blocking(reader.fileno(), False)
        self.assertEqual(reader.peek(), b"prefetched")
        with self.assertRaisesRegex(ProbeError, "c0_stream_type"):
            self.wire(qmp, {"serial": reader})
        self.assertEqual(reader.read(10), b"prefetched")
        self.no_next_request(peer)

    def test_short_write_followed_by_early_reply_denies_remainder(self):
        qmp, peer = self.endpoints()
        wire = self.wire(qmp)
        peer.sendall(GREETING)
        actual_send = socket.socket.send
        calls = 0

        def inject_early_reply(sock, data):
            nonlocal calls
            calls += 1
            if calls == 1:
                sent = actual_send(sock, data[:7])
                peer.sendall(REPLIES[0])
                return sent
            return actual_send(sock, data)

        with patch.object(socket.socket, "send", inject_early_reply):
            self.assert_failure(wire, "qmp_unsolicited")
        self.recv_exact(peer, REQUESTS[0][:7])
        self.assertEqual(calls, 1)
        self.assertEqual(wire.raw("qmp-out"), REQUESTS[0][:7])
        self.assertEqual(wire.raw("qmp-in"), GREETING + REPLIES[0])
        self.assertIsNone(wire.operations[0].response)
        self.no_next_request(peer)

    def test_socket_with_python_timeout_is_refused_before_any_io(self):
        qmp, peer = self.endpoints()
        qmp.settimeout(0.5)
        with self.assertRaisesRegex(ProbeError, "c0_stream_descriptor"):
            self.wire(qmp)
        self.no_next_request(peer)
        self.assertGreaterEqual(qmp.fileno(), 0)

    def test_exact_frame_count_limit_refuses_a_coalesced_flood_before_send(self):
        qmp, peer = self.endpoints()
        wire = self.wire(qmp)
        flood = GREETING + b"{}\r\n" * 128
        peer.sendall(flood)
        self.assert_failure(wire, "qmp_frame_limit")
        self.assertEqual(wire.raw("qmp-in"), flood)
        self.assertEqual(wire.operations, ())
        self.no_next_request(peer)

    def test_valid_reply_clock_precedes_semantic_processing(self):
        qmp, peer = self.endpoints()
        wire = self.wire(qmp)
        from run0_c0_wire import decode_frame

        observed_by_parser = []

        def parse(data):
            observed_by_parser.append(time.monotonic_ns())
            return decode_frame(data)

        with patch("run0_c0_wire.decode_frame", side_effect=parse):
            self.fixture(wire, peer)
        self.assertEqual(len(observed_by_parser), 4)
        for row, parsed in zip(wire.operations, observed_by_parser[1:], strict=True):
            self.assertLessEqual(row.finished_ns, parsed)

    def test_inventory_requires_unique_names_and_every_closed_operation(self):
        for names in (COMMANDS + [COMMANDS[0]], *(COMMANDS[:i] + COMMANDS[i+1:]
                                                 for i in range(len(COMMANDS)))):
            with self.subTest(names=names):
                qmp, peer = self.endpoints()
                wire = self.wire(qmp)

                def exchange():
                    peer.sendall(GREETING)
                    self.recv_exact(peer, REQUESTS[0])
                    peer.sendall(REPLIES[0])
                    self.recv_exact(peer, REQUESTS[1])
                    peer.sendall(frame({"return": [{"name": name} for name in names], "id": 2}))

                self.peer_task(exchange)
                self.assert_failure(wire, "qmp_command_inventory")
                self.assertEqual(wire.raw("qmp-out"), b"".join(REQUESTS[:2]))
                self.assertIsNone(wire.operations[-1].response)
                self.no_next_request(peer)

    def test_lf_only_and_not_prelaunch_refuse_without_success(self):
        for response, expected in (
            (REPLIES[0][:-2] + b"\n", "qmp_wire_framing"),
            (frame({"return": {"running": False, "status": "paused", "singlestep": False},
                    "id": 3}), "qmp_not_prelaunch"),
        ):
            with self.subTest(expected=expected):
                qmp, peer = self.endpoints()
                wire = self.wire(qmp)

                def exchange():
                    peer.sendall(GREETING)
                    count = 1 if expected == "qmp_wire_framing" else 3
                    for request, reply in zip(REQUESTS[:count], [*REPLIES[:count - 1], response]):
                        self.recv_exact(peer, request)
                        peer.sendall(reply)

                self.peer_task(exchange)
                self.assert_failure(wire, expected)
                self.assertIsNone(wire.operations[-1].response)
                self.no_next_request(peer)


if __name__ == "__main__":
    unittest.main()
