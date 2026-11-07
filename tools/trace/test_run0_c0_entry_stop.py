"""Real socket controls for the admitted entry prefix; no VM or guest reads."""

from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import socket
import tempfile
import time
import unittest
from unittest.mock import patch

import boot_profile_capture as capture
from boot_profile_capture import ProbeError
import run0_c0_wire as transport
import run0_host_cpu_witness as witness
from run0_c0_entry import validate_prior_entry, export_validated_prior_entry
from test_run0_c0_decode import full_fixture
import test_run0_c0_rsp as reset_fixture
from test_run0_c0_rsp import reset_script
from test_run0_c0_wire import frame, RESUME
from test_run0_rsp import packet


STOP = frame({"event": "STOP", "timestamp": {"seconds": 1, "microseconds": 3}})
RSP_STOP = packet(b"T05thread:01;")
DEBUG_REQUEST = frame({"execute": "query-status", "id": 4})
DEBUG_REPLY = frame({"return": {"running": False, "singlestep": False, "status": "debug"}, "id": 4})


def rtc(profile, offset=0):
    number = 1 if profile == capture.VAPIC_OFF_INVOCATION_PROFILE else 2
    return frame({"event": "RTC_CHANGE", "timestamp": {"seconds": 1, "microseconds": 4},
                  "data": {"offset": offset, "qom-path": f"/machine/unattached/device[{number}]/rtc"}})


class EntryStopTests(unittest.TestCase):
    endpoints = reset_fixture.ResetBootstrapTests.endpoints
    pipe = reset_fixture.ResetBootstrapTests.pipe
    peer_task = reset_fixture.ResetBootstrapTests.peer_task
    recv_exact = reset_fixture.ResetBootstrapTests.recv_exact
    wire = reset_fixture.ResetBootstrapTests.wire
    fixture = reset_fixture.ResetBootstrapTests.fixture
    no_next_request = reset_fixture.ResetBootstrapTests.no_next_request
    session = reset_fixture.ResetBootstrapTests.session
    script = reset_fixture.ResetBootstrapTests.script

    @classmethod
    def setUpClass(cls):
        cls.tokens = {}
        for profile in (capture.INVOCATION_PROFILE, capture.SATA_OFF_INVOCATION_PROFILE,
                        capture.VAPIC_OFF_INVOCATION_PROFILE):
            with tempfile.TemporaryDirectory() as tmp:
                report, _, blobs, _, _ = full_fixture(Path(tmp), profile)
                cls.tokens[profile] = validate_prior_entry(report["profile_ref"],
                    report["prior_admission_ref"], report["profile_mapping_ref"], blobs)

    def setUp(self):
        reset_fixture.ResetBootstrapTests.setUp(self)
        for name in ("install_entry_breakpoint", "resume_to_entry", "confirm_entry_stop"):
            self.assertTrue(callable(getattr(transport.C0Wire, name, None)),
                            "entry prefix absent: expected gate-first RED: " + name)

    def ready(self, profile=capture.VAPIC_OFF_INVOCATION_PROFILE):
        wire, qmp, endpoint, peer = self.session()
        done = self.script(peer, reset_script())
        wire.prepare_rsp_reset()
        done()
        return wire, qmp, endpoint, peer, self.tokens[profile]

    def install(self, wire, peer, token, reply=b"OK"):
        address = export_validated_prior_entry(token)["entry_address"]
        done = self.script(peer, [(f"Z1,{address:x},1".encode(), reply)])
        try:
            return wire.install_entry_breakpoint(token)
        finally:
            done()

    def check_failure(self, wire, call, reason):
        with self.assertRaises(ProbeError) as caught:
            call()
        self.assertEqual(caught.exception.reason, reason)
        self.assertEqual(wire.failure.reason, reason)
        before = wire.raw("rsp-out"), wire.raw("qmp-out")
        for later in (wire.resume_to_entry, wire.confirm_entry_stop,
                      lambda: wire.install_entry_breakpoint(self.tokens[capture.VAPIC_OFF_INVOCATION_PROFILE])):
            with self.assertRaises(ProbeError):
                later()
        self.assertEqual(before, (wire.raw("rsp-out"), wire.raw("qmp-out")))
        self.assertEqual(wire.failure.reason, reason)

    def successful_stop(self, wire, qmp, peer, profile, *, fragments=False, qmp_late=False):
        def exchange():
            self.recv_exact(peer, packet(b"c"))
            if not qmp_late:
                qmp.sendall(RESUME + rtc(profile, -1) + STOP)
            if fragments:
                peer.sendall(b"+" + RSP_STOP[:5])
                peer.settimeout(0.03)
                with self.assertRaises(socket.timeout):
                    peer.recv(1)  # No outgoing byte while the stop is incomplete.
                peer.settimeout(0.5)
                peer.sendall(RSP_STOP[5:])
            else:
                peer.sendall(b"+" + RSP_STOP)
            self.recv_exact(peer, b"+")
            self.recv_exact(qmp, DEBUG_REQUEST)
            qmp.sendall((RESUME + STOP if qmp_late else b"") + DEBUG_REPLY + rtc(profile))
        done = self.peer_task(exchange)
        stopped = wire.resume_to_entry()
        confirmed = wire.confirm_entry_stop()
        done()
        return stopped, confirmed

    def test_exact_bootstrap_breakpoint_coalesced_stop_and_separate_debug_confirmation(self):
        for profile in self.tokens:
            with self.subTest(profile=profile):
                wire, qmp, _, peer, token = self.ready(profile)
                installed = self.install(wire, peer, token)
                stopped, confirmed = self.successful_stop(wire, qmp, peer, profile)
                self.assertEqual(installed.operation, "hardware_breakpoint_set")
                rows = wire.operations[-4:]
                self.assertEqual([r.operation for r in rows],
                                 ["hardware_breakpoint_set", "resume", "acknowledge_stop", "query_status"])
                self.assertEqual([r.seq for r in wire.operations], list(range(1, len(wire.operations)+1)))
                self.assertEqual(stopped.breakpoint_seq, installed.seq)
                self.assertEqual(stopped.resume_seq, rows[1].seq)
                self.assertEqual(stopped.acknowledge_stop_seq, rows[2].seq)
                self.assertEqual(confirmed.stop, stopped)
                self.assertEqual(confirmed.query_status_seq, rows[3].seq)
                for row, request, response in ((rows[1], packet(b"c"), b"+"),
                                                (rows[2], b"+", None),
                                                (rows[3], DEBUG_REQUEST, DEBUG_REPLY[:-2])):
                    part = row.request
                    self.assertEqual(wire.raw(part.stream)[part.offset:part.offset+part.length], request)
                    if response is None:
                        self.assertIsNone(row.response)
                    else:
                        part = row.response
                        self.assertEqual(wire.raw(part.stream)[part.offset:part.offset+part.length], response)
                    self.assertEqual(row.result, "ok")
                stop_event = next(e for e in wire.events if e.protocol == "rsp")
                self.assertEqual(stop_event.name, "T05thread:01;")
                self.assertLess(stop_event.received_ns, rows[2].started_ns)
                self.assertEqual(stopped.stop_event_seq, stop_event.seq)
                self.assertEqual([e.seq for e in wire.events], list(range(1, len(wire.events)+1)))
                self.assertEqual([e.received_ns for e in wire.events], sorted(e.received_ns for e in wire.events))
                with self.assertRaises(FrozenInstanceError):
                    stopped.resume_seq = 0
                self.no_next_request(peer)
                self.no_next_request(qmp)

    def test_fragmented_stop_is_silent_and_qmp_bracket_may_arrive_later(self):
        wire, qmp, _, peer, token = self.ready()
        self.install(wire, peer, token)
        self.successful_stop(wire, qmp, peer, capture.VAPIC_OFF_INVOCATION_PROFILE,
                             fragments=True, qmp_late=True)
        self.assertEqual(wire.events[0].protocol, "rsp")

    def test_local_state_and_token_denials_preserve_valid_session(self):
        wire, qmp, _, peer, token = self.ready()
        before = wire.raw("rsp-out")
        for call in (wire.resume_to_entry, wire.confirm_entry_stop,
                     lambda: wire.install_entry_breakpoint(42),
                     lambda: wire.install_entry_breakpoint({"status": "ADMIT"})):
            with self.assertRaises(ProbeError):
                call()
        self.assertIsNone(wire.failure)
        self.assertEqual(before, wire.raw("rsp-out"))
        self.install(wire, peer, token)
        before = wire.raw("rsp-out")
        for other in self.tokens.values():
            with self.assertRaises(ProbeError):
                wire.install_entry_breakpoint(other)
        self.assertIsNone(wire.failure)
        self.assertEqual(before, wire.raw("rsp-out"))
        self.successful_stop(wire, qmp, peer, capture.VAPIC_OFF_INVOCATION_PROFILE)
        for call in (wire.resume_to_entry, wire.confirm_entry_stop):
            with self.assertRaises(ProbeError):
                call()
        self.assertIsNone(wire.failure)

    def test_wrong_duplicate_early_stop_and_tails_prevent_stop_ack(self):
        for raw, reason in (
            (RSP_STOP, "rsp_request_ack"),
            (b"-", "rsp_request_ack"),
            (b"++" + RSP_STOP, "rsp_stop_packet"),
            (b"+" + packet(b"T05thread:02;"), "rsp_stop_identity"),
            (b"+" + RSP_STOP + RSP_STOP, "rsp_unsolicited"),
            (b"+" + RSP_STOP + b"$", "rsp_unsolicited"),
            (b"+" + RSP_STOP + b"+", "rsp_unsolicited"),
            (b"+" + RSP_STOP[:-2] + b"00", "rsp_checksum"),
        ):
            with self.subTest(raw=raw):
                wire, _, _, peer, token = self.ready()
                self.install(wire, peer, token)
                prefix = wire.raw("rsp-out")
                def exchange():
                    self.recv_exact(peer, packet(b"c"))
                    peer.sendall(raw)
                self.peer_task(exchange)
                self.check_failure(wire, wire.resume_to_entry, reason)
                self.assertEqual(wire.raw("rsp-out"), prefix + packet(b"c"))
                self.no_next_request(peer)

    def test_ack_only_eof_and_owner_timeout_are_incomplete_without_a_stop_ack(self):
        for eof in (False, True):
            with self.subTest(eof=eof):
                wire, _, _, peer, token = self.ready()
                self.install(wire, peer, token)
                wire._deadline = time.monotonic_ns() + 60_000_000
                def exchange():
                    self.recv_exact(peer, packet(b"c"))
                    peer.sendall(b"+")
                    if eof:
                        peer.shutdown(socket.SHUT_WR)
                self.peer_task(exchange)
                self.check_failure(wire, wire.resume_to_entry,
                                   "rsp_eof" if eof else "rsp_stop_timeout")
                self.assertEqual(wire.operations[-1].operation, "resume")
                self.assertEqual(wire.operations[-1].result, "ok")
                self.no_next_request(peer)

    def test_early_install_is_local_and_then_same_session_succeeds(self):
        wire, qmp, _, peer = self.session()
        token = self.tokens[capture.VAPIC_OFF_INVOCATION_PROFILE]
        with self.assertRaisesRegex(ProbeError, "c0_entry_state"):
            wire.install_entry_breakpoint(token)
        self.no_next_request(peer)
        self.assertIsNone(wire.failure)
        peer.settimeout(0.5)
        done = self.script(peer, reset_script())
        wire.prepare_rsp_reset()
        done()
        self.install(wire, peer, token)
        self.successful_stop(wire, qmp, peer, capture.VAPIC_OFF_INVOCATION_PROFILE)

    def test_breakpoint_error_is_terminal_and_fresh_session_succeeds(self):
        for reply in (b"E01", b"NO", b""):
            wire, _, _, peer, token = self.ready()
            reason = "rsp_remote_error" if reply == b"E01" else (
                "rsp_unsupported" if reply == b"" else "rsp_breakpoint_reply")
            self.check_failure(wire, lambda: self.install(wire, peer, token, reply), reason)
            self.assertEqual(wire.operations[-1].result, "error")
            self.no_next_request(peer)
        fresh, qmp, _, peer, token = self.ready()
        self.install(fresh, peer, token)
        self.successful_stop(fresh, qmp, peer, capture.VAPIC_OFF_INVOCATION_PROFILE)

    def test_continue_cap_checks_precede_every_effect(self):
        for cap, reason in (("operations", "c0_operation_limit"), ("acks", "rsp_ack_limit"),
                            ("events", "c0_event_limit"), ("bytes", "storage_limit")):
            with self.subTest(cap=cap):
                wire, _, _, peer, token = self.ready()
                self.install(wire, peer, token)
                before = wire.raw("rsp-out")
                if cap == "operations":
                    wire._operations.extend([wire.operations[-1]] * (511-len(wire.operations)))
                elif cap == "acks":
                    wire._rsp_acks = 1023
                elif cap == "events":
                    wire._events.extend([None] * 126)
                else:
                    wire.reserve_output(wire._remaining_bytes - len(packet(b"c")) + 1)
                self.check_failure(wire, wire.resume_to_entry, reason)
                self.assertEqual(before, wire.raw("rsp-out"))
                self.no_next_request(peer)

    def test_actual_partial_continue_and_early_reply_never_send_remainder(self):
        for early in (False, True):
            with self.subTest(early=early):
                wire, _, endpoint, peer, token = self.ready()
                self.install(wire, peer, token)
                before = wire.raw("rsp-out")
                send = socket.socket.send
                calls = 0
                def partial(sock, data):
                    nonlocal calls
                    if sock is not endpoint:
                        return send(sock, data)
                    calls += 1
                    if calls == 1:
                        sent = send(sock, data[:2])
                        if early:
                            peer.sendall(b"+")
                        else:
                            sock.shutdown(socket.SHUT_WR)
                        return sent
                    return send(sock, data)
                with patch.object(socket.socket, "send", partial):
                    self.check_failure(wire, wire.resume_to_entry,
                                       "rsp_unsolicited" if early else "rsp_write_error")
                self.assertEqual(wire.raw("rsp-out"), before + packet(b"c")[:2])
                self.assertEqual(wire.operations[-1].request.length, 2)
                self.recv_exact(peer, packet(b"c")[:2])

    def test_breakpoint_partial_send_retains_only_actual_candidate_prefix(self):
        wire, _, endpoint, peer, token = self.ready()
        before = wire.raw("rsp-out")
        request = packet(f"Z1,{export_validated_prior_entry(token)['entry_address']:x},1".encode())
        send = socket.socket.send
        first = True
        def partial(sock, data):
            nonlocal first
            if sock is endpoint and first:
                first = False
                result = send(sock, data[:7])
                sock.shutdown(socket.SHUT_WR)
                return result
            return send(sock, data)
        with patch.object(socket.socket, "send", partial):
            self.check_failure(wire, lambda: wire.install_entry_breakpoint(token), "rsp_write_error")
        self.assertEqual(wire.raw("rsp-out"), before + request[:7])
        self.assertEqual(wire.operations[-1].operation, "hardware_breakpoint_set")
        self.assertEqual(wire.operations[-1].request.length, 7)
        self.recv_exact(peer, request[:7])

    def test_continue_eagain_and_eintr_keep_prefix_and_original_deadline(self):
        for error in (BlockingIOError, InterruptedError):
            wire, _, endpoint, peer, token = self.ready()
            self.install(wire, peer, token)
            wire._deadline = time.monotonic_ns() + 35_000_000
            send = socket.socket.send
            first = True
            before = wire.raw("rsp-out")
            def blocked(sock, data):
                nonlocal first
                if sock is not endpoint:
                    return send(sock, data)
                if first:
                    first = False
                    return send(sock, data[:1])
                raise error()
            with patch.object(socket.socket, "send", blocked):
                self.check_failure(wire, wire.resume_to_entry, "rsp_request_timeout")
            self.assertEqual(wire.raw("rsp-out"), before + b"$")
            self.assertEqual(wire.operations[-1].result, "timeout")
            self.assertLessEqual(wire.operations[-1].finished_ns-wire._deadline, 100_000_000)
            self.recv_exact(peer, b"$")
            self.no_next_request(peer)

    def test_stop_wait_does_not_restart_at_late_continue_ack(self):
        wire, _, _, peer, token = self.ready()
        self.install(wire, peer, token)
        def exchange():
            self.recv_exact(peer, packet(b"c"))
            time.sleep(0.03)
            peer.sendall(b"+")
        self.peer_task(exchange)
        with patch.object(transport, "CONTINUE_NS", 60_000_000):
            self.check_failure(wire, wire.resume_to_entry, "rsp_stop_timeout")
        resume = wire.operations[-1]
        self.assertEqual(wire._stop_deadline, resume.started_ns + 60_000_000)
        self.assertGreater(resume.finished_ns, resume.started_ns + 20_000_000)
        self.no_next_request(peer)

    def test_stop_ack_blocked_or_zero_send_retains_row_without_success(self):
        for zero in (False, True):
            with self.subTest(zero=zero):
                wire, _, endpoint, peer, token = self.ready()
                self.install(wire, peer, token)
                wire._deadline = time.monotonic_ns() + 60_000_000
                before = wire.raw("rsp-out")
                def exchange():
                    self.recv_exact(peer, packet(b"c"))
                    peer.sendall(b"+" + RSP_STOP)
                self.peer_task(exchange)
                send = socket.socket.send
                def blocked(sock, data):
                    if sock is endpoint and bytes(data) == b"+":
                        if zero:
                            return 0
                        raise BlockingIOError()
                    return send(sock, data)
                with patch.object(socket.socket, "send", blocked):
                    self.check_failure(wire, wire.resume_to_entry,
                                       "rsp_send_eof" if zero else "rsp_request_timeout")
                row = wire.operations[-1]
                self.assertEqual(row.operation, "acknowledge_stop")
                self.assertIsNone(row.request)
                self.assertIsNone(row.response)
                self.assertEqual(row.result, "error" if zero else "timeout")
                self.assertEqual(wire.raw("rsp-out"), before + packet(b"c"))
                self.no_next_request(peer)

    def test_equal_stop_ack_clock_is_refused_without_normalizing(self):
        wire, _, _, peer, token = self.ready()
        self.install(wire, peer, token)
        before = wire.raw("rsp-out")
        def exchange():
            self.recv_exact(peer, packet(b"c"))
            peer.sendall(b"+" + RSP_STOP)
        self.peer_task(exchange)
        acknowledge = wire._acknowledge_stop
        def equal_clock(event):
            with patch.object(transport.time, "monotonic_ns", return_value=event.received_ns):
                return acknowledge(event)
        with patch.object(wire, "_acknowledge_stop", equal_clock):
            self.check_failure(wire, wire.resume_to_entry, "rsp_stop_ack_clock")
        self.assertEqual(wire.raw("rsp-out"), before + packet(b"c"))
        self.no_next_request(peer)

    def test_cross_socket_equal_clock_event_order_is_receive_order(self):
        for rsp_first in (False, True):
            with self.subTest(rsp_first=rsp_first):
                wire, qmp, endpoint, peer, token = self.ready()
                self.install(wire, peer, token)
                send = socket.socket.send
                select = wire._selector.select
                read = wire._read
                observed = None
                def inject(sock, data):
                    nonlocal observed
                    sent = send(sock, data)
                    if sock is endpoint and bytes(data) == packet(b"c"):
                        self.recv_exact(peer, packet(b"c"))
                        qmp.sendall(RESUME + STOP)
                        peer.sendall(b"+" + RSP_STOP)
                        observed = time.monotonic_ns()
                    return sent
                def ordered(timeout):
                    return sorted(select(timeout), key=lambda row: row[0].data == "rsp",
                                  reverse=rsp_first)
                def receive(key, deadline, reason):
                    if observed is None:
                        return read(key, deadline, reason)
                    with patch.object(transport.time, "monotonic_ns", return_value=observed):
                        return read(key, deadline, reason)
                with patch.object(socket.socket, "send", inject), \
                     patch.object(wire._selector, "select", ordered), \
                     patch.object(wire, "_read", receive):
                    wire.resume_to_entry()
                self.recv_exact(peer, b"+")
                expected = ["T05thread:01;", "RESUME", "STOP"] if rsp_first else ["RESUME", "STOP", "T05thread:01;"]
                self.assertEqual([e.name for e in wire.events], expected)
                self.assertTrue(all(e.received_ns == observed for e in wire.events))
                self.assertEqual(wire._event_ordinals, sorted(set(wire._event_ordinals)))

    def test_forbidden_qmp_events_and_wrong_profile_path_prevent_stop_ack(self):
        malformed = json.loads(rtc(capture.VAPIC_OFF_INVOCATION_PROFILE))
        malformed["data"]["offset"] = True
        for raw, reason in (
            (STOP, "c0_boot_event_order"), (RESUME + RESUME, "c0_boot_event_order"),
            (RESUME + STOP + STOP, "c0_boot_event_order"),
            (rtc(capture.VAPIC_OFF_INVOCATION_PROFILE), "c0_boot_event_order"),
            (RESUME + rtc(capture.INVOCATION_PROFILE), "c0_boot_event"),
            (RESUME + frame(malformed), "c0_boot_event"),
            (RESUME.replace(b"RESUME", b"RESET"), "c0_boot_event"),
            (frame({"return": {}, "id": 4}), "qmp_unsolicited"),
        ):
            with self.subTest(raw=raw):
                wire, qmp, _, peer, token = self.ready()
                self.install(wire, peer, token)
                before = wire.raw("rsp-out")
                def exchange():
                    self.recv_exact(peer, packet(b"c"))
                    qmp.sendall(raw)
                self.peer_task(exchange)
                self.check_failure(wire, wire.resume_to_entry, reason)
                self.assertEqual(wire.raw("rsp-out"), before + packet(b"c"))
                self.no_next_request(peer)

    def test_debug_confirmation_requires_bracket_status_and_next_qmp_id(self):
        for response, reason in (
            (DEBUG_REPLY, "c0_boot_events_missing"),
            (RESUME + DEBUG_REPLY + STOP, "c0_boot_events_missing"),
            (RESUME + STOP + DEBUG_REPLY.replace(b'"id":4', b'"id":25'), "qmp_response_identity"),
            (RESUME + STOP + DEBUG_REPLY.replace(b'"debug"', b'"prelaunch"'), "qmp_not_debug"),
        ):
            with self.subTest(response=response):
                wire, qmp, _, peer, token = self.ready()
                self.install(wire, peer, token)
                def exchange():
                    self.recv_exact(peer, packet(b"c"))
                    peer.sendall(b"+" + RSP_STOP)
                    self.recv_exact(peer, b"+")
                    self.recv_exact(qmp, DEBUG_REQUEST)
                    qmp.sendall(response)
                self.peer_task(exchange)
                wire.resume_to_entry()
                self.check_failure(wire, wire.confirm_entry_stop, reason)
                self.no_next_request(peer)
                self.no_next_request(qmp)

    def test_fragmented_qmp_events_can_interleave_with_complete_rsp_stop(self):
        wire, qmp, _, peer, token = self.ready()
        self.install(wire, peer, token)
        def exchange():
            self.recv_exact(peer, packet(b"c"))
            qmp.sendall(RESUME[:8])
            peer.sendall(b"+" + RSP_STOP)
            self.recv_exact(peer, b"+")
            self.recv_exact(qmp, DEBUG_REQUEST)
            qmp.sendall(RESUME[8:] + STOP + DEBUG_REPLY)
        done = self.peer_task(exchange)
        wire.resume_to_entry()
        wire.confirm_entry_stop()
        done()

    def test_shared_event_capacity_fails_at_recognition_before_stop_ack(self):
        wire, qmp, _, peer, token = self.ready()
        self.install(wire, peer, token)
        before = wire.raw("rsp-out")
        def exchange():
            self.recv_exact(peer, packet(b"c"))
            qmp.sendall(RESUME + rtc(capture.VAPIC_OFF_INVOCATION_PROFILE) + STOP)
            peer.sendall(b"+" + RSP_STOP)
        self.peer_task(exchange)
        with patch.object(transport, "MAX_EVENTS", 3):
            self.check_failure(wire, wire.resume_to_entry, "c0_event_limit")
        self.assertEqual(len(wire.events), 3)
        self.assertEqual(wire.raw("rsp-out"), before + packet(b"c"))
        self.no_next_request(peer)

    def test_late_rsp_tail_denies_debug_query_and_qmp_eof_denies_stop_ack(self):
        wire, qmp, _, peer, token = self.ready()
        self.install(wire, peer, token)
        def tail():
            self.recv_exact(peer, packet(b"c"))
            peer.sendall(b"+" + RSP_STOP)
            self.recv_exact(peer, b"+")
            peer.sendall(b"$")
        done = self.peer_task(tail)
        wire.resume_to_entry()
        done()
        before = wire.raw("qmp-out")
        self.check_failure(wire, wire.confirm_entry_stop, "rsp_unsolicited")
        self.assertEqual(wire.raw("qmp-out"), before)
        self.no_next_request(qmp)
        wire, qmp, _, peer, token = self.ready()
        self.install(wire, peer, token)
        def close_qmp():
            self.recv_exact(peer, packet(b"c"))
            qmp.shutdown(socket.SHUT_WR)
        self.peer_task(close_qmp)
        self.check_failure(wire, wire.resume_to_entry, "qmp_eof")
        self.no_next_request(peer)

    def test_cancelled_prefix_preserves_first_failure(self):
        wire, _, _, peer, token = self.ready()
        self.install(wire, peer, token)
        with patch.object(wire, "_poll", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                wire.resume_to_entry()
        self.assertEqual(wire.failure.reason, "c0_cancelled")
        with self.assertRaises(ProbeError):
            wire.resume_to_entry()
        self.assertEqual(wire.failure.reason, "c0_cancelled")
        self.no_next_request(peer)


class RTCProfileTests(unittest.TestCase):
    def test_closed_rtc_path_per_exact_profile_and_no_union(self):
        profiles = (capture.INVOCATION_PROFILE, capture.SATA_OFF_INVOCATION_PROFILE,
                    capture.VAPIC_OFF_INVOCATION_PROFILE)
        for profile in profiles:
            value = json.loads(rtc(profile))
            self.assertTrue(witness.shared_qmp_boot_event(value, profile))
            value["data"]["qom-path"] = ("/machine/unattached/device[2]/rtc"
                if profile == capture.VAPIC_OFF_INVOCATION_PROFILE else "/machine/unattached/device[1]/rtc")
            self.assertFalse(witness.shared_qmp_boot_event(value, profile))
        self.assertFalse(witness.shared_qmp_boot_event(json.loads(RESUME), "unknown"))


if __name__ == "__main__":
    unittest.main()
