"""Real socket controls for the C0-only reset RSP bootstrap."""

from dataclasses import FrozenInstanceError
import socket
import time
import unittest
from contextlib import ExitStack
from unittest.mock import patch

import run0_rsp as rsp
from boot_profile_capture import ProbeError
from run0_c0_wire import C0Wire, MAX_RETAINED_BYTES, REPORT_RESERVE, FAILURE_RESERVE
import test_run0_c0_wire as qmp_fixture
from test_run0_rsp import description_script, initial_script, packet


def reset_script(rip=0xfff0):
    raw = bytearray(608)
    raw[128:136] = rip.to_bytes(8, "little")
    return initial_script() + description_script() + [
        (b"g", raw.hex().encode()),
        (b"qqemu.Supported", b"sstepbits;sstep;PhyMemMode"),
        (b"qqemu.PhyMemMode", b"0"),
        (b"Qqemu.PhyMemMode:1", b"OK"),
        (b"qqemu.PhyMemMode", b"1"),
    ]


class ResetBootstrapTests(unittest.TestCase):
    setUp = qmp_fixture.WireTests.setUp
    endpoints = qmp_fixture.WireTests.endpoints
    pipe = qmp_fixture.WireTests.pipe
    peer_task = qmp_fixture.WireTests.peer_task
    recv_exact = qmp_fixture.WireTests.recv_exact
    wire = qmp_fixture.WireTests.wire
    fixture = qmp_fixture.WireTests.fixture
    no_next_request = qmp_fixture.WireTests.no_next_request

    def session(self, *, started_ns=None, prelaunch=True, streams=None):
        qmp, qmp_peer = self.endpoints()
        rsp_socket, rsp_peer = self.endpoints()
        wire = self.wire(qmp, {"rsp": rsp_socket, **(streams or {})}, started_ns)
        if prelaunch:
            self.fixture(wire, qmp_peer)
        return wire, qmp_peer, rsp_socket, rsp_peer

    def script(self, peer, rows, *, serial=None):
        def exchange():
            for index, (request, reply) in enumerate(rows):
                self.recv_exact(peer, packet(request))
                framed = b"+" + packet(reply)
                if index % 2 == 0:
                    peer.sendall(framed)
                else:
                    peer.sendall(framed[:3])
                    peer.sendall(framed[3:])
                if index == 0 and serial is not None:
                    serial.write(b"serial tail")
                    serial.close()
                self.recv_exact(peer, b"+")

        return self.peer_task(exchange)

    def failure(self, wire, reason):
        with self.assertRaises(ProbeError) as caught:
            wire.prepare_rsp_reset()
        self.assertEqual(caught.exception.reason, reason)
        self.assertEqual(wire.failure.reason, reason)

    def test_reset_sequence_shares_ledger_and_preserves_exact_wire(self):
        reader, writer = self.pipe()
        wire, qmp_peer, _, peer = self.session(streams={"serial": reader})
        script = reset_script()
        finished = self.script(peer, script, serial=writer)
        result = wire.prepare_rsp_reset()
        finished()
        self.assertEqual((result.target.packet_bytes, result.registers.values[16],
                          result.physical_mode), (608, 0xfff0, 1))
        with self.assertRaises(FrozenInstanceError):
            result.physical_mode = 0
        incoming = b"".join(b"+" + packet(reply) for _, reply in script)
        outgoing = b"".join(packet(request) + b"+" for request, _ in script)
        self.assertEqual(wire.raw("rsp"), incoming)
        self.assertEqual(wire.raw("rsp-out"), outgoing)
        self.assertEqual(wire.raw("serial"), b"serial tail")
        rows = wire.operations
        self.assertEqual([row.seq for row in rows], list(range(1, len(script) + 4)))
        self.assertEqual([row.protocol for row in rows[:3]], ["qmp"] * 3)
        self.assertEqual([row.protocol for row in rows[3:]], ["rsp"] * len(script))
        for row, (request, reply) in zip(rows[3:], script, strict=True):
            for raw, part, expected in ((outgoing, row.request, packet(request)),
                                        (incoming, row.response, packet(reply))):
                self.assertEqual(raw[part.offset:part.offset + part.length], expected)
            self.assertEqual(row.result, "ok")
            self.assertLessEqual(row.started_ns, row.finished_ns)
        for first, second in zip(rows, rows[1:]):
            self.assertLessEqual(first.finished_ns, second.started_ns)
        with self.assertRaises(ProbeError):
            wire.prepare_rsp_reset()
        self.assertIsNone(wire.failure)
        self.no_next_request(qmp_peer)
        self.no_next_request(peer)

    def test_early_denial_then_success_on_the_same_clean_wire(self):
        wire, qmp_peer, _, peer = self.session(prelaunch=False)
        with self.assertRaises(ProbeError):
            wire.prepare_rsp_reset()
        self.assertIsNone(wire.failure)
        self.no_next_request(peer)
        peer.settimeout(0.5)
        self.fixture(wire, qmp_peer)
        finished = self.script(peer, reset_script())
        self.assertEqual(wire.prepare_rsp_reset().physical_mode, 1)
        finished()

    def test_previously_retained_or_unsolicited_rsp_prevents_first_write(self):
        for payload in (b"+", packet(b"unsolicited"), b"$"):
            with self.subTest(payload=payload):
                wire, _, _, peer = self.session()
                peer.sendall(payload)
                self.failure(wire, "rsp_unsolicited")
                self.assertEqual(wire.raw("rsp"), payload)
                self.assertEqual(wire.raw("rsp-out"), b"")
                self.assertEqual(len(wire.operations), 3)
                self.no_next_request(peer)

    def test_extra_frame_or_partial_after_response_prevents_response_ack(self):
        for tail in (packet(b"unsolicited"), b"$"):
            with self.subTest(tail=tail):
                wire, _, _, peer = self.session()
                request, reply = initial_script()[0]

                def exchange():
                    self.recv_exact(peer, packet(request))
                    peer.sendall(b"+" + packet(reply) + tail)

                self.peer_task(exchange)
                self.failure(wire, "rsp_unsolicited")
                self.assertEqual(wire.raw("rsp"), b"+" + packet(reply) + tail)
                self.assertEqual(wire.raw("rsp-out"), packet(request))
                self.assertEqual(wire.operations[-1].result, "error")
                self.no_next_request(peer)

    def test_unexpected_qmp_event_during_rsp_response_is_retained_and_denied(self):
        wire, qmp_peer, _, peer = self.session()
        request, _ = initial_script()[0]

        def exchange():
            self.recv_exact(peer, packet(request))
            qmp_peer.sendall(qmp_fixture.RESUME)

        self.peer_task(exchange)
        self.failure(wire, "qmp_prelaunch_event")
        self.assertEqual(len(wire.events), 1)
        event = wire.events[0]
        raw = wire.raw("qmp-in")
        self.assertEqual(raw[event.wire.offset:event.wire.offset + event.wire.length],
                         qmp_fixture.RESUME[:-2])
        self.assertEqual(wire.raw("rsp-out"), packet(request))
        self.no_next_request(peer)

    def test_wrong_reset_rip_denies_physical_mode_and_fresh_wire_succeeds(self):
        wire, _, _, peer = self.session()
        script = reset_script(rip=0x1234)[:-4]
        finished = self.script(peer, script)
        self.failure(wire, "rsp_reset_rip")
        finished()
        self.assertEqual(wire.operations[-1].operation, "reset_registers")
        self.assertEqual(wire.operations[-1].result, "error")
        self.no_next_request(peer)
        fresh, _, _, fresh_peer = self.session()
        finished = self.script(fresh_peer, reset_script())
        self.assertEqual(fresh.prepare_rsp_reset().physical_mode, 1)
        finished()

    def test_eof_retains_partial_reply_without_ack_or_more_requests(self):
        wire, _, _, peer = self.session()
        request, _ = initial_script()[0]

        def exchange():
            self.recv_exact(peer, packet(request))
            peer.sendall(b"+$Packet")
            peer.shutdown(socket.SHUT_WR)

        self.peer_task(exchange)
        self.failure(wire, "rsp_eof")
        self.assertEqual(wire.raw("rsp"), b"+$Packet")
        self.assertEqual(wire.raw("rsp-out"), packet(request))
        self.assertEqual(tuple(row.stream for row in wire.eofs), ("rsp",))
        self.assertIsNone(wire.operations[-1].response)
        self.no_next_request(peer)

    def test_partial_send_retains_prefix_and_preserves_first_failure(self):
        wire, _, endpoint, peer = self.session()
        request, _ = initial_script()[0]
        original_send = socket.socket.send
        calls = 0

        def send_prefix(sock, data):
            nonlocal calls
            self.assertIs(sock, endpoint)
            calls += 1
            if calls == 1:
                sent = original_send(sock, data[:7])
                sock.shutdown(socket.SHUT_WR)
                return sent
            return original_send(sock, data)

        with patch.object(socket.socket, "send", send_prefix):
            self.failure(wire, "rsp_write_error")
        self.assertEqual(peer.recv(128), packet(request)[:7])
        self.assertEqual(peer.recv(1), b"")
        self.assertEqual(wire.raw("rsp-out"), packet(request)[:7])
        row = wire.operations[-1]
        self.assertEqual((row.request.offset, row.request.length, row.result), (0, 7, "error"))
        with self.assertRaises(ProbeError):
            wire.prepare_rsp_reset()
        self.assertEqual(wire.failure.reason, "rsp_write_error")

    def test_shared_storage_limit_prevents_first_rsp_write(self):
        wire, _, _, peer = self.session()
        budget = MAX_RETAINED_BYTES - REPORT_RESERVE - FAILURE_RESERVE
        already_used = len(wire.raw("qmp-in")) + len(wire.raw("qmp-out"))
        wire.reserve_output(budget - already_used - len(packet(initial_script()[0][0])) + 1)
        self.failure(wire, "storage_limit")
        self.assertEqual(len(wire.operations), 3)
        self.assertEqual(wire.raw("rsp-out"), b"")
        self.no_next_request(peer)

    def test_original_owner_deadline_clips_rsp_wait(self):
        start = time.monotonic_ns() - 85_000_000_000 + 300_000_000
        wire, _, _, peer = self.session(started_ns=start)
        self.failure(wire, "rsp_response_timeout")
        self.recv_exact(peer, packet(initial_script()[0][0]))
        self.assertEqual(wire.operations[-1].result, "timeout")
        self.assertEqual(wire.eofs, ())
        self.no_next_request(peer)

    def test_operation_and_ack_caps_refuse_before_first_rsp_dispatch(self):
        for cap, expected in (("operations", "c0_operation_limit"), ("acks", "rsp_ack_limit")):
            with self.subTest(cap=cap):
                wire, _, _, peer = self.session()
                if cap == "operations":
                    wire._operations.extend([wire.operations[-1]] * (512 - len(wire.operations)))
                else:
                    wire._rsp_acks = 1023
                self.failure(wire, expected)
                self.assertEqual(wire.raw("rsp-out"), b"")
                self.no_next_request(peer)
        wire, _, _, peer = self.session()
        wire._rsp_acks = 984  # Exactly 40 further ACKs for 20 bootstrap operations.
        finished = self.script(peer, reset_script())
        self.assertEqual(wire.prepare_rsp_reset().physical_mode, 1)
        finished()
        self.assertEqual(wire._rsp_acks, 1024)

    def test_malformed_early_duplicate_and_short_responses_stop_next_dispatch(self):
        first_request, reply = initial_script()[0]
        for raw, reason, acknowledged in (
            (packet(reply), "rsp_request_ack", False),
            (b"-", "rsp_request_ack", False),
            (b"++" + packet(reply), "rsp_response_packet", False),
            (b"+" + packet(reply)[:-2] + b"00", "rsp_checksum", False),
            (b"+" + packet(b""), "rsp_unsupported", True),
            (b"+" + packet(b"E01"), "rsp_remote_error", True),
            (b"+" + packet(b"PacketSize=ff;qXfer:features:read+"), "rsp_packet_size_unsupported", True),
        ):
            with self.subTest(raw=raw):
                wire, _, _, peer = self.session()

                def exchange():
                    self.recv_exact(peer, packet(first_request))
                    peer.sendall(raw)
                    if acknowledged:
                        self.recv_exact(peer, b"+")

                finished = self.peer_task(exchange)
                self.failure(wire, reason)
                finished()
                self.assertEqual(wire.raw("rsp"), raw)
                self.assertEqual(wire.raw("rsp-out"), packet(first_request) + (b"+" if acknowledged else b""))
                self.assertEqual(wire.operations[-1].result, "error")
                self.no_next_request(peer)

    def test_short_reset_payload_and_false_mode_replies_are_terminal(self):
        for index, reply, reason in (
            (-5, b"00", "rsp_register_bytes"),
            (-4, b"sstep", "rsp_physical_unsupported"),
            (-3, b"1", "rsp_physical_mode"),
            (-2, b"NO", "rsp_physical_set"),
            (-1, b"0", "rsp_physical_mode"),
        ):
            with self.subTest(index=index):
                wire, _, _, peer = self.session()
                script = reset_script()
                target = len(script) + index
                script[target] = (script[target][0], reply)
                finished = self.script(peer, script[:target + 1])
                self.failure(wire, reason)
                finished()
                self.assertEqual(wire.operations[-1].result, "error")
                self.no_next_request(peer)

    def test_real_partial_request_cannot_accept_early_reply(self):
        wire, _, endpoint, peer = self.session()
        request, reply = initial_script()[0]
        original_send = socket.socket.send
        calls = 0

        def short_send(sock, data):
            nonlocal calls
            self.assertIs(sock, endpoint)
            calls += 1
            if calls == 1:
                sent = original_send(sock, data[:7])
                peer.sendall(b"+" + packet(reply))
                return sent
            return original_send(sock, data)

        with patch.object(socket.socket, "send", short_send):
            self.failure(wire, "rsp_unsolicited")
        self.assertEqual(wire.raw("rsp-out"), packet(request)[:7])
        self.assertEqual(peer.recv(7), packet(request)[:7])
        self.no_next_request(peer)

    def test_cancelled_session_keeps_first_failure_and_fresh_session_succeeds(self):
        wire, _, _, peer = self.session()
        with patch.object(wire, "_poll", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                wire.prepare_rsp_reset()
        self.assertEqual(wire.failure.reason, "c0_cancelled")
        with self.assertRaises(ProbeError):
            wire.prepare_rsp_reset()
        self.assertEqual(wire.failure.reason, "c0_cancelled")
        self.no_next_request(peer)
        fresh, _, _, fresh_peer = self.session()
        finished = self.script(fresh_peer, reset_script())
        self.assertEqual(fresh.prepare_rsp_reset().physical_mode, 1)
        finished()

    def test_c0_codec_crosses_legacy_wire_and_ack_limits_without_reset(self):
        from run0_rsp import _C0AckDecoder

        frame = packet(b"x" * 4096)
        legacy = rsp.AckDecoder()
        c0 = _C0AckDecoder()
        for _ in range(64):
            frames = c0.feed(frame)
            self.assertEqual(frames[0].payload, b"x" * 4096)
        with self.assertRaisesRegex(rsp.RSPError, "rsp_wire_limit"):
            legacy.feed(frame * 64)
        for _ in range(512):
            self.assertEqual(c0.feed(b"+")[0].kind, "ACK")
        with self.assertRaisesRegex(rsp.RSPError, "rsp_ack_limit"):
            c0.feed(b"+")
        legacy = rsp.AckDecoder()
        self.assertEqual(len(legacy.feed(b"+" * 256)), 256)
        with self.assertRaisesRegex(rsp.RSPError, "rsp_ack_limit"):
            legacy.feed(b"+")


if __name__ == "__main__":
    unittest.main()
