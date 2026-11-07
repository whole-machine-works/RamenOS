"""Synthetic sockets/helpers only; these controls never authorize a VM launch."""

from dataclasses import replace
import copy
import json
import importlib
import os
import sys
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import socket
import struct
import time
import unittest
from unittest.mock import patch

from boot_profile_capture import ProbeError
import run0_c0_decode as decoder
import run0_c0_wire as wire_module
import test_run0_c0_entry_stop as entry_fixture
from test_run0_c0_decode import synthetic_c0_hmp
from test_run0_c0_wire import frame


class HostJoinControls(unittest.TestCase):
    endpoints = entry_fixture.EntryStopTests.endpoints
    pipe = entry_fixture.EntryStopTests.pipe
    peer_task = entry_fixture.EntryStopTests.peer_task
    recv_exact = entry_fixture.EntryStopTests.recv_exact
    wire = entry_fixture.EntryStopTests.wire
    fixture = entry_fixture.EntryStopTests.fixture
    no_next_request = entry_fixture.EntryStopTests.no_next_request
    session = entry_fixture.EntryStopTests.session
    script = entry_fixture.EntryStopTests.script
    ready = entry_fixture.EntryStopTests.ready
    install = entry_fixture.EntryStopTests.install
    successful_stop = entry_fixture.EntryStopTests.successful_stop
    setUpClass = classmethod(entry_fixture.EntryStopTests.setUpClass.__func__)

    def setUp(self):
        entry_fixture.reset_fixture.ResetBootstrapTests.setUp(self)
        for name in ("confirm_stopped_physical_mode", "read_selected_registers",
                     "begin_host_observation", "host_peer_credentials", "host_bracket",
                     "pump_host_observation", "finish_host_observation", "read_current_layout",
                     "read_final_register_view"):
            self.assertTrue(callable(getattr(wire_module.C0Wire, name, None)),
                            "host join absent: expected gate-first RED: " + name)

    def stopped(self):
        wire, qmp, _, peer, token = self.ready()
        self.install(wire, peer, token)
        stopped, confirmed = self.successful_stop(wire, qmp, peer,
                                                  entry_fixture.capture.VAPIC_OFF_INVOCATION_PROFILE)
        values = {number: 0 for number in decoder.SELECTED_REGISTERS}
        values.update({16: stopped.entry_address, 17: 2, 18: 0x38,
                       27: 0x80000011, 29: 0x1000, 30: 0x20, 32: 0x500})
        return wire, qmp, peer, confirmed, values

    def mode(self, wire, peer, confirmed, reply=b"1"):
        done = self.script(peer, [(b"qqemu.PhyMemMode", reply)])
        try:
            return wire.confirm_stopped_physical_mode(confirmed)
        finally:
            done()

    def registers(self, wire, peer, confirmed, values, phase="before"):
        rows = [(f"p{number:x}".encode(), value.to_bytes(4 if 17 <= number <= 23 else 8,
                  "little").hex().encode()) for number, value in values.items()]
        done = self.script(peer, rows)
        try:
            return wire.read_selected_registers(confirmed, phase)
        finally:
            done()

    def lease(self):
        wire, qmp, peer, confirmed, values = self.stopped()
        self.mode(wire, peer, confirmed)
        registers = self.registers(wire, peer, confirmed, values)
        lease = wire.begin_host_observation(confirmed, registers)
        return wire, qmp, peer, confirmed, values, registers, lease

    def peer(self, wire, lease):
        # Explicit synthetic Linux credential bytes; no process/live-origin claim.
        with patch.object(socket.socket, "getsockopt", return_value=struct.pack("=iii", 123, 456, 789)):
            return wire.host_peer_credentials(lease)

    def bracket(self, wire, qmp, lease, values, phase="before", *, tid=123, width=40, hmp=None):
        path = "/machine/unattached/device[0]"
        commands = [("query-status", None, {"running": False, "singlestep": False, "status": "debug"}),
                    ("query-cpus-fast", None, [{"cpu-index": 0, "qom-path": path,
                      "target": "x86_64", "thread-id": tid, "props": {}}]),
                    ("qom-get", {"path": path, "property": "realized"}, True),
                    ("qom-get", {"path": path, "property": "phys-bits"}, width),
                    ("human-monitor-command", {"command-line": "info registers"},
                     synthetic_c0_hmp(values) if hmp is None else hmp)]
        first = wire._qmp_identifier + 1

        def exchange():
            for identifier, (command, args, result) in enumerate(commands, first):
                request = {"execute": command, "id": identifier}
                if args is not None:
                    request["arguments"] = args
                self.recv_exact(qmp, frame(request))
                qmp.sendall(frame({"return": result, "id": identifier}))
                if command == "qom-get" and width < 32 and args["property"] == "phys-bits":
                    break
        done = self.peer_task(exchange)
        try:
            return wire.host_bracket(lease, phase)
        finally:
            done()

    def test_mode_and_selected_registers_use_exact_order_width_and_same_ledger(self):
        wire, qmp, peer, confirmed, values = self.stopped()
        before = len(wire.operations)
        mode = self.mode(wire, peer, confirmed)
        registers = self.registers(wire, peer, confirmed, values)
        self.assertEqual(mode.value, 1)
        self.assertEqual(tuple(row[0] for row in registers.values), decoder.SELECTED_REGISTERS)
        self.assertEqual(dict((number, value) for number, value, _ in registers.values), values)
        self.assertEqual([r.seq for r in wire.operations], list(range(1, len(wire.operations)+1)))
        self.assertEqual(len(wire.operations)-before, 30)
        self.assertTrue(all(r.result == "ok" for r in wire.operations))
        self.assertEqual([seq for _, _, seq in registers.values], list(range(before+2, before+31)))
        self.no_next_request(qmp)
        self.no_next_request(peer)

    def test_forged_confirmed_or_register_receipts_deny_without_poisoning_valid_session(self):
        wire, qmp, peer, confirmed, values = self.stopped()
        initial = wire.raw("rsp-out")
        for fake in (None, {}, replace(confirmed)):
            with self.assertRaises(ProbeError):
                wire.confirm_stopped_physical_mode(fake)
        self.assertEqual(initial, wire.raw("rsp-out"))
        self.assertIsNone(wire.failure)
        self.mode(wire, peer, confirmed)
        registers = self.registers(wire, peer, confirmed, values)
        with self.assertRaises(ProbeError):
            wire.begin_host_observation(confirmed, replace(registers))
        wire.begin_host_observation(confirmed, registers)

    def test_mode_zero_stops_before_any_selected_register(self):
        wire, qmp, peer, confirmed, _ = self.stopped()
        with self.assertRaisesRegex(ProbeError, "c0_physical_mode"):
            self.mode(wire, peer, confirmed, b"0")
        self.assertEqual(wire.failure.reason, "c0_physical_mode")
        self.assertEqual(wire.operations[-1].result, "error")
        self.no_next_request(peer)

    def test_wrong_register_width_retains_actual_reply_and_stops_at_that_register(self):
        wire, _, peer, confirmed, _ = self.stopped()
        self.mode(wire, peer, confirmed)
        done = self.script(peer, [(b"p0", b"00" * 4)])
        with self.assertRaisesRegex(ProbeError, "c0_selected_register_width"):
            wire.read_selected_registers(confirmed, "before")
        done()
        self.assertEqual(wire.operations[-1].operation, "register_read")
        self.assertEqual(wire.operations[-1].result, "error")
        part = wire.operations[-1].response
        self.assertEqual(wire.raw(part.stream)[part.offset:part.offset+part.length],
                         entry_fixture.packet(b"00" * 4))
        self.no_next_request(peer)

    def test_wrong_rip_stops_before_host_lease(self):
        wire, _, peer, confirmed, values = self.stopped()
        self.mode(wire, peer, confirmed)
        values[16] += 1
        with self.assertRaisesRegex(ProbeError, "c0_entry_rip"):
            self.registers(wire, peer, confirmed, values)
        self.assertEqual(wire.failure.reason, "c0_entry_rip")

    def test_lease_original_deadline_and_exact_identity(self):
        wire, qmp, peer, confirmed, _, registers, lease = self.lease()
        now = time.monotonic_ns()
        self.assertLessEqual(lease.deadline_ns, now + 5_000_000_000)
        self.assertLessEqual(lease.deadline_ns, wire._deadline)
        self.assertLessEqual(lease.deadline_ns, confirmed.stop.received_ns + 60_000_000_000)
        for fake in (None, {}, replace(lease)):
            with self.assertRaises(ProbeError):
                wire.host_peer_credentials(fake)
        with self.assertRaises(ProbeError):
            wire.begin_host_observation(confirmed, registers)
        self.assertIsNone(wire.failure)
        self.no_next_request(qmp)
        self.no_next_request(peer)

    def test_peer_precedes_fresh_five_command_brackets_and_actual_global_sequences(self):
        wire, qmp, _, _, values, _, lease = self.lease()
        with self.assertRaises(ProbeError):
            wire.host_bracket(lease, "before")
        peer = self.peer(wire, lease)
        before = self.bracket(wire, qmp, lease, values)
        after = self.bracket(wire, qmp, lease, values, "after")
        self.assertLess(peer.observed_ns, wire.operations[dict(before.operations)["status_seq"]-1].started_ns)
        self.assertEqual(before.cpu_identity, after.cpu_identity)
        self.assertEqual(before.hmp_bytes, after.hmp_bytes)
        self.assertEqual([name for name, _ in before.operations],
                         ["status_seq", "cpu_seq", "realized_seq", "phys_bits_seq", "hmp_seq"])
        self.assertEqual([wire.operations[seq-1].operation for _, seq in after.operations],
                         ["query_status", "query_cpus_fast", "qom_realized", "qom_phys_bits", "hmp_registers"])
        requests = [json.loads(line) for line in wire.raw("qmp-out").splitlines()]
        self.assertEqual([row["id"] for row in requests], list(range(1, 15)))

    def test_host_width_and_hmp_contradictions_terminalize_before_field_authority(self):
        for mode in ("width", "hmp"):
            wire, qmp, _, _, values, _, lease = self.lease()
            self.peer(wire, lease)
            with self.assertRaises(ProbeError):
                self.bracket(wire, qmp, lease, values, width=31 if mode == "width" else 40,
                             hmp="CPU#0\r\n" if mode == "hmp" else None)
            self.assertIsNotNone(wire.failure)
            self.assertIsNone(wire._host_receipt)

    def test_after_bracket_changes_and_forged_completion_do_not_admit(self):
        for change in ("tid", "hmp", "receipt"):
            wire, qmp, _, _, values, _, lease = self.lease()
            self.peer(wire, lease)
            self.bracket(wire, qmp, lease, values)
            if change == "receipt":
                import run0_c0_host as host
                self.bracket(wire, qmp, lease, values, "after")
                for forged in ({"admitted": True}, object.__new__(host.HostObservationReceipt)):
                    with self.assertRaises(ProbeError):
                        wire.finish_host_observation(lease, forged)
                self.assertIsNone(wire.failure)
            else:
                with self.assertRaisesRegex(ProbeError, "c0_host_bracket_changed"):
                    self.bracket(wire, qmp, lease, values, "after",
                                 tid=124 if change == "tid" else 123,
                                 hmp=synthetic_c0_hmp(values)+"\r\n" if change == "hmp" else None)
                self.assertIsNotNone(wire.failure)
            self.assertIsNone(wire._host_receipt)

    def test_host_pump_accepts_only_profile_rtc_and_sends_nothing(self):
        wire, qmp, peer, _, _, _, lease = self.lease()
        before = wire.raw("qmp-out"), wire.raw("rsp-out")
        qmp.sendall(entry_fixture.rtc(entry_fixture.capture.VAPIC_OFF_INVOCATION_PROFILE, 4))
        wire.pump_host_observation(lease)
        self.assertEqual((wire.raw("qmp-out"), wire.raw("rsp-out")), before)
        self.assertEqual(wire.events[-1].name, "RTC_CHANGE")
        peer.sendall(b"$")
        with self.assertRaisesRegex(ProbeError, "rsp_unsolicited"):
            wire.pump_host_observation(lease)
        self.assertEqual(wire.failure.reason, "rsp_unsolicited")

    def test_foreign_or_partial_qmp_during_host_observation_stops_before_more_effects(self):
        for raw, reason in ((entry_fixture.rtc(entry_fixture.capture.INVOCATION_PROFILE),
                             "c0_boot_event"), (b'{"event":', "qmp_observation_partial")):
            wire, qmp, peer, _, _, _, lease = self.lease()
            qmp.sendall(raw)
            with self.assertRaises(ProbeError):
                wire.pump_host_observation(lease)
            self.assertEqual(wire.failure.reason, reason)
            before = wire.raw("qmp-out"), wire.raw("rsp-out")
            with self.assertRaises(ProbeError):
                wire.host_peer_credentials(lease)
            self.assertEqual((wire.raw("qmp-out"), wire.raw("rsp-out")), before)
            self.no_next_request(peer)

    def test_expired_lease_or_cancel_preserves_first_failure_without_renewal(self):
        for cancellation in (False, True):
            wire, _, _, _, _, _, lease = self.lease()
            if cancellation:
                with patch.object(wire, "_poll", side_effect=KeyboardInterrupt):
                    with self.assertRaises(KeyboardInterrupt):
                        wire.pump_host_observation(lease)
                reason = "c0_cancelled"
            else:
                with patch.object(wire_module.time, "monotonic_ns", return_value=lease.deadline_ns):
                    with self.assertRaisesRegex(ProbeError, "witness_deadline"):
                        wire.pump_host_observation(lease)
                reason = "witness_deadline"
            self.assertEqual(wire.failure.reason, reason)
            with self.assertRaises(ProbeError):
                wire.host_peer_credentials(lease)
            self.assertEqual(wire.failure.reason, reason)

    def test_host_timeout_keeps_pending_row_and_partial_raw_without_another_request(self):
        wire, qmp, _, _, values, _, lease = self.lease()
        self.peer(wire, lease)
        # Shortened fixture clock only; the production lease is never renewed.
        object.__setattr__(lease, "deadline_ns", time.monotonic_ns()+30_000_000)
        request = frame({"execute": "query-status", "id": 5})
        done = self.peer_task(lambda: (self.recv_exact(qmp, request), qmp.sendall(b'{"return":')))
        with self.assertRaises(ProbeError):
            wire.host_bracket(lease, "before")
        done()
        self.assertEqual(wire.operations[-1].operation, "query_status")
        self.assertEqual(wire.operations[-1].result, "timeout")
        self.assertIsNone(wire.operations[-1].response)
        self.assertTrue(wire.raw("qmp-in").endswith(b'{"return":'))
        self.assertIsNone(wire._host_before)
        self.no_next_request(qmp)

    def test_after_phase_and_layout_remain_closed_before_actual_host_receipt(self):
        wire, _, _, confirmed, _, _, lease = self.lease()
        for call in (lambda: wire.read_selected_registers(confirmed, "after"),
                     lambda: wire.read_current_layout(confirmed, "before"),
                     lambda: wire.finish_host_observation(lease, {"admitted": True})):
            with self.assertRaises(ProbeError):
                call()
        self.assertIsNone(wire._host_receipt)
        self.assertIsNone(wire.failure)

    def test_closed_host_adapter_exists_and_preserves_reset_entrypoint(self):
        host = importlib.import_module("run0_c0_host")
        import run0_host_cpu_witness as witness
        self.assertTrue(issubclass(host._OwnedC0Observation, witness.OwnedCPUObservation))
        self.assertTrue(callable(getattr(witness.OwnedCPUObservation, "_observe_body", None)))
        observation = witness.OwnedCPUObservation(None, None, None, None, None, None, None)
        with self.assertRaisesRegex(ProbeError, "owned_observation_state"):
            observation.observe()

    def observed(self, *, change=None):
        """Actual helpers over private synthetic files; mocked proc/peer only."""
        import run0_c0_host as host
        import run0_host_cpu_witness as witness
        import test_run0_host_cpu_reader as reader_fixture
        wire, qmp, peer, confirmed, values = self.stopped()
        self.mode(wire, peer, confirmed)
        registers = self.registers(wire, peer, confirmed, values)
        folder = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"],
                                 start_new_session=True)

        def reap():
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=2)
        self.addCleanup(reap)
        proc = folder / "proc"
        directory = proc / str(child.pid)
        directory.mkdir(parents=True)
        rest = [b"S", str(os.getpid()).encode(), *([b"0"] * 17), b"721231", *([b"0"] * 30)]
        stat_bytes = str(child.pid).encode() + b" (synthetic child) " + b" ".join(rest) + b"\n"
        mount = b"10 1 8:1 / / rw - ext4 /dev/sda1 rw\n"
        executable = reader_fixture.elf_fixture()
        exe = reader_fixture.exe_identity(executable)
        for name, data in (("stat", stat_bytes), ("maps", reader_fixture.MAPS),
                           ("smaps", reader_fixture.smaps()), ("exe", executable)):
            (directory / name).write_bytes(data)
        (folder / "mountinfo").write_bytes(mount)
        field_file = directory / "mem"
        fd = os.open(field_file, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        reader, cpu = reader_fixture.reader, reader_fixture.CPU
        try:
            os.ftruncate(fd, 0x1a00000)
            for offset, data in ((0x17ddad0, struct.pack("<QQ", cpu, cpu+0x238)),
                (0x1930b64, struct.pack("<I", 1)), (cpu+0x238, struct.pack("<QQ", 0, 0x17ddad0)),
                (cpu+0x2c8, struct.pack("<i", 0)),
                (cpu+0xb8, struct.pack("<i", 124 if change == "tid" else 123)),
                (cpu+0x2870, struct.pack("<II", (1 << 14) | (1 << 15), 0))):
                os.pwrite(fd, data, offset)
        finally:
            os.close(fd)
        metadata = b"".join(struct.pack(">I", len(data)) + data for data in (
            stat_bytes, reader_fixture.MAPS, reader_fixture.smaps(), mount, witness.canonical(exe)))
        before_file, after_file = folder / "metadata-before", folder / "metadata-after"
        before_file.write_bytes(metadata)
        if change == "start":
            metadata = metadata.replace(b"721231", b"721232")
        after_file.write_bytes(metadata)
        abi, _ = reader_fixture.fixture()
        if change == "abi":
            abi = replace(abi, elf=replace(abi.elf, sha256="0"*64))
        native = SimpleNamespace(sigchld=lambda: bytes(152),
                                 filesystem_magic=lambda _: witness.NATIVE_LAYOUT["proc_super_magic"])
        observation = host._OwnedC0Observation(child, wire, confirmed, registers, native, abi,
                                               "/qemu", (0x801, 7, len(executable)))
        original_open, original_start = os.open, witness.OwnedHelper.start

        def fixture_open(path, flags, *args, **kwargs):
            if path == "/proc":
                path = proc
            elif path == "/proc/self/mountinfo":
                path = folder / "mountinfo"
            return original_open(path, flags, *args, **kwargs)

        def start(helper, argv, pass_fds, output_limit, stderr_limit):
            if "--metadata-reader" in argv:
                output = argv[argv.index("--result-fd")+1]
                source = before_file if helper.role == "metadata_before" else after_file
                argv = [sys.executable, "-c", "import os,sys; "
                        "os.write(int(sys.argv[1]),open(sys.argv[2],'rb').read())", output, str(source)]
            return original_start(helper, argv, pass_fds, output_limit, stderr_limit)

        path = "/machine/unattached/device[0]"
        replies = [("query-status", None, {"running": False, "singlestep": False, "status": "debug"}),
            ("query-cpus-fast", None, [{"cpu-index": 0, "qom-path": path, "target": "x86_64",
                                      "thread-id": 123, "props": {}}]),
            ("qom-get", {"path": path, "property": "realized"}, True),
            ("qom-get", {"path": path, "property": "phys-bits"}, 40),
            ("human-monitor-command", {"command-line": "info registers"}, synthetic_c0_hmp(values))]
        first = wire._qmp_identifier + 1
        count = 0 if change == "peer" else 5 if change in ("start", "abi", "tid") else 10

        def exchange():
            for index in range(count):
                command, args, value = replies[index % 5]
                request = {"execute": command, "id": first+index}
                if args is not None:
                    request["arguments"] = args
                self.recv_exact(qmp, frame(request))
                qmp.sendall(frame({"return": value, "id": first+index}))
        done = self.peer_task(exchange)
        pidfd_checks = []

        def live(fd):
            pidfd_checks.append(fd)
            if change == "pidfd" and len(pidfd_checks) == 2:
                raise ProbeError("INCOMPLETE", "pidfd_not_live")
            return {"observed_ns": time.monotonic_ns(), "readable": False,
                    "hangup": False, "error": None}

        peer_bytes = struct.pack("=iII", child.pid + (1 if change == "peer" else 0), os.getuid(), os.getgid())
        try:
            with patch.object(witness.os, "open", side_effect=fixture_open), \
                 patch.object(witness.os, "pidfd_open", create=True,
                              side_effect=lambda _: original_open(directory / "stat", os.O_RDONLY)), \
                 patch.object(witness, "pidfd_check", side_effect=live), \
                 patch.object(witness.OwnedHelper, "start", start), \
                 patch.object(socket.socket, "getsockopt", return_value=peer_bytes), \
                 patch.object(host.threading, "active_count", return_value=1):
                if change is None:
                    receipt = observation.observe()
                else:
                    with self.assertRaises(ProbeError):
                        observation.observe()
                    receipt = None
        finally:
            done()
        return wire, qmp, peer, confirmed, values, observation, receipt

    def test_shared_body_actual_three_helpers_fourteen_reads_and_descriptor_closure(self):
        wire, _, _, _, _, observation, receipt = self.observed()
        self.assertIs(wire._host_receipt, receipt)
        self.assertEqual(len(observation.reads), 14)
        self.assertEqual(sum(row["length"] for row in observation.reads), 104)
        self.assertEqual(tuple(observation.helpers), ("metadata_before", "fields", "metadata_after"))
        for helper in observation.helpers.values():
            self.assertTrue(helper.closed and helper.reaped)
            self.assertEqual(helper.returncode, 0)
            self.assertEqual(helper.eofs, {"stdout", "stderr"})
            self.assertEqual([row["operation"] for row in helper.lifecycle], ["spawn", "wait", "close"])
        self.assertEqual(observation.deadline_ns, wire._host_lease.deadline_ns)
        self.assertLess(observation.process["mem_closed_ns"],
                        observation.helpers["metadata_after"].lifecycle[0]["started_ns"])
        self.assertEqual(receipt.field_state,
                         tuple(sorted({"cpl": 0, "cs64": True, "lma": True,
                                       "no_npt": True, "no_svm_guest": True, "no_smm": True,
                                       "hflags": 49152, "hflags2": 0,
                                       "observed_consistent": True}.items())))
        with self.assertRaises(ProbeError):
            wire.finish_host_observation(wire._host_lease, receipt)

    def test_peer_start_abi_tid_and_pidfd_changes_never_issue_host_receipt(self):
        for change in ("peer", "start", "abi", "tid", "pidfd"):
            with self.subTest(change=change):
                wire, _, _, _, _, observation, receipt = self.observed(change=change)
                self.assertIsNone(receipt)
                self.assertIsNone(wire._host_receipt)
                self.assertFalse(observation._finished)
                self.assertIsNotNone(wire.failure)
                if change == "peer":
                    self.assertEqual(observation.helpers, {})
                else:
                    self.assertTrue(all(helper.reaped and helper.closed for helper in observation.helpers.values()))
                if change == "abi":
                    self.assertEqual(tuple(observation.helpers), ("metadata_before",))
                    self.assertNotIn("mem_open", observation.process)

    def test_missing_owned_child_and_wrong_owner_thread_refuse_before_host_effect(self):
        import run0_c0_host as host
        wire, _, peer, confirmed, values = self.stopped()
        self.mode(wire, peer, confirmed)
        registers = self.registers(wire, peer, confirmed, values)
        observation = host._OwnedC0Observation(None, wire, confirmed, registers,
                                              None, None, None, None)
        for count, reason in ((1, "owned_observation_state"), (2, "main_thread_owner_required")):
            with patch.object(host.threading, "active_count", return_value=count):
                with self.assertRaisesRegex(ProbeError, reason):
                    observation.observe()
            self.assertIsNone(wire._host_lease)
            self.assertIsNone(wire.failure)
            self.assertEqual(observation.helpers, {})

    def test_current_layout_requires_actual_host_completion_and_exact_profile(self):
        from test_run0_rsp_capability import LAYOUT
        wire, qmp, _, confirmed, _, _, receipt = self.observed()
        self.assertIsNotNone(receipt)
        request = frame({"execute": "human-monitor-command", "id": 15,
                         "arguments": {"command-line": "info mtree -f"}})
        done = self.peer_task(lambda: (self.recv_exact(qmp, request),
            qmp.sendall(frame({"return": LAYOUT, "id": 15}))))
        layout = wire.read_current_layout(confirmed, "before")
        done()
        self.assertEqual(layout.ranges, ((0, 0xa0000), (0x100000, 0x20000000)))
        self.assertEqual(layout.raw_bytes, LAYOUT.encode())
        with self.assertRaisesRegex(ProbeError, "c0_current_acquisition_pending"):
            wire.read_selected_registers(confirmed, "after")
        self.no_next_request(qmp)

    def test_after_registers_final_hmp_and_final_layout_are_separate_closed_steps(self):
        from test_run0_rsp_capability import LAYOUT
        wire, qmp, peer, confirmed, values, _, _ = self.observed()

        def qmp_result(identifier, command, value, call):
            request = frame({"execute": "human-monitor-command", "id": identifier,
                             "arguments": {"command-line": command}})
            done = self.peer_task(lambda: (self.recv_exact(qmp, request),
                qmp.sendall(frame({"return": value, "id": identifier}))))
            try:
                return call()
            finally:
                done()

        qmp_result(15, "info mtree -f", LAYOUT, lambda: wire.read_current_layout(confirmed, "before"))
        with self.assertRaises(ProbeError):
            wire.read_final_register_view(confirmed, wire._before_registers)
        # Explicit protocol fixture seam only. No live-origin binding or production
        # registration is minted; the real public completion guard stays closed.
        with patch.object(wire, "_require_acquisition_complete", return_value=None):
            after = self.registers(wire, peer, confirmed, values, "after")
            self.no_next_request(qmp)  # selected p never silently emits final HMP.
            qmp.settimeout(0.5)
            with self.assertRaises(ProbeError):
                wire.read_current_layout(confirmed, "after")
            view = qmp_result(16, "info registers", synthetic_c0_hmp(values),
                              lambda: wire.read_final_register_view(confirmed, after))
            layout = qmp_result(17, "info mtree -f", LAYOUT,
                                lambda: wire.read_current_layout(confirmed, "after"))
        self.assertEqual(view.raw_bytes, wire._host_before.hmp_bytes)
        self.assertGreater(view.operation_seq, after.values[-1][2])
        self.assertGreater(layout.operation_seq, view.operation_seq)
        with self.assertRaises(ProbeError):
            wire.read_selected_registers(confirmed, "after")

    def test_registered_synthetic_binding_is_rejected_before_any_after_query(self):
        import run0_c0_acquire as acquire
        wire, _, _, _, _, _, _ = self.lease()
        binding = object.__new__(acquire.CurrentC0RamBinding)
        object.__setattr__(binding, "origin", "synthetic_fixture")
        wire._current_binding = binding
        wire._current_acquisition = wire._reads_complete = object()
        wire._ram_transport_identity, wire._admission_epoch = ("fixture", 1, 2), 1
        before = wire.raw("rsp-out"), wire.raw("qmp-out")
        with self.assertRaisesRegex(ProbeError, "acquire_runtime_binding_required"):
            wire._require_acquisition_complete()
        self.assertEqual((wire.raw("rsp-out"), wire.raw("qmp-out")), before)

    def test_new_profile_current_layout_rejects_each_excluded_device(self):
        from test_run0_rsp_capability import LAYOUT
        for forbidden in ("ahci", "kvmvapic"):
            wire, qmp, _, confirmed, _, _, _ = self.observed()
            layout = LAYOUT.replace("vga", forbidden)
            request = frame({"execute": "human-monitor-command", "id": 15,
                             "arguments": {"command-line": "info mtree -f"}})
            done = self.peer_task(lambda: (self.recv_exact(qmp, request),
                qmp.sendall(frame({"return": layout, "id": 15}))))
            with self.assertRaises(ProbeError):
                wire.read_current_layout(confirmed, "before")
            done()
            self.assertIsNone(wire._layout_before)
            self.assertIsNotNone(wire.failure)


class HostHelperControls(unittest.TestCase):
    def test_complete_synthetic_replay_and_missing_evidence_remain_strict(self):
        import run0_host_cpu_witness as witness
        from test_run0_c0_decode import full_fixture
        with tempfile.TemporaryDirectory() as folder:
            report, ref, blobs, host, put = full_fixture(Path(folder),
                entry_fixture.capture.VAPIC_OFF_INVOCATION_PROFILE)
            self.assertEqual(decoder.decode_c0("synthetic_fixture", ref, blobs, host)["status"], "PASS")
            original = json.loads(blobs["host-report.json"])
            for mutation in ("host_window", "bracket_seq", "missing_raw", "missing_wait",
                             "cross_stop", "runtime_promotion"):
                changed, retained = copy.deepcopy(original), dict(blobs)

                def retain(name, value):
                    raw = witness.canonical(value)
                    retained[name] = raw
                    return witness.CaptureEvidence.ref(name, raw)

                if mutation in ("host_window", "bracket_seq"):
                    control = json.loads(blobs[original["control_ref"]["path"]])
                    if mutation == "host_window":
                        memory = next(row["seq"] for row in control["operations"]
                                      if row["operation"] == "physical_read")
                        control["after"]["status_seq"] = memory
                    else:
                        control["before"]["hmp_seq"] = control["before"]["status_seq"]
                    changed["control_ref"] = retain("bad-control.json", control)
                elif mutation == "missing_raw":
                    control = json.loads(blobs[original["control_ref"]["path"]])
                    del retained[control["raw_qmp_in_ref"]["path"]]
                elif mutation == "missing_wait":
                    changed["termination"]["waits"].pop()
                elif mutation == "cross_stop":
                    changed["binding"]["stop_id"] = "other-stop"
                else:
                    changed["origin"] = "retained_runtime"
                bad_ref = retain("bad-host.json", changed)
                with self.subTest(mutation=mutation), self.assertRaises(ProbeError):
                    witness.validate_report(bad_ref, retained)

    def test_wire_budget_overflow_retains_only_the_charged_helper_prefix(self):
        import run0_c0_host as host
        import run0_host_cpu_witness as witness
        qmp, peer = socket.socketpair()
        qmp.setblocking(False)
        wire = wire_module.C0Wire(qmp, {}, started_ns=time.monotonic_ns())
        result, output = os.pipe()
        budget = host._WireBudget(wire)
        wire.reserve_output(budget.byte_limit-1)
        helper = witness.OwnedHelper("fields", result, time.monotonic()+2, budget=budget)
        try:
            helper.start([sys.executable, "-c", "import os,sys; "
                          "os.write(int(sys.argv[1]),b'abc')", str(output)], (output,), 32, 32)
        finally:
            os.close(output)
        try:
            with self.assertRaisesRegex(ProbeError, "helper_output_limit"):
                helper.drain()
            self.assertEqual(bytes(helper.output), b"a")
            self.assertEqual(budget.retained_bytes, budget.byte_limit)
            self.assertEqual(helper.io_errors[-1]["observed_overflow_bytes"], 1)
            self.assertNotIn("stdout", helper.eofs)
        finally:
            helper.close()
            wire.close()
            qmp.close()
            peer.close()
        self.assertTrue(helper.closed and helper.reaped)

    def test_close_pipes_then_stall_keeps_pumping_and_still_reaps_actual_child(self):
        import run0_host_cpu_witness as witness
        result, output = os.pipe()
        deadline = time.monotonic() + 2
        helper = witness.OwnedHelper("fields", result, deadline)
        observation = witness.OwnedCPUObservation(None, None, None, None, None, None, None)
        observation.deadline_ns = int(deadline * 1e9)
        observation.helpers["fields"] = helper
        calls = []

        def pump():
            calls.append(time.monotonic_ns())
            if helper.eofs == {"stdout", "stderr"}:
                raise ProbeError("INCOMPLETE", "fixture_wait_cancel")

        observation._pump = pump
        helper.pump = pump
        try:
            helper.start([sys.executable, "-c", "import os,sys,time; "
                          "os.close(int(sys.argv[1])); os.close(2); time.sleep(30)", str(output)],
                         (output,), 32, 32)
        finally:
            os.close(output)
        try:
            with self.assertRaisesRegex(ProbeError, "fixture_wait_cancel"):
                observation._completed(helper)
            self.assertFalse(helper.reaped)
        finally:
            observation._close_helper(helper)
        self.assertGreater(len(calls), 0)
        self.assertTrue(helper.reaped and helper.closed)
        self.assertIn(helper.returncode, (-15, -9))
        self.assertEqual(helper.lifecycle[-2]["operation"], "wait")
        self.assertEqual(helper.lifecycle[-2]["result"], "ok")
        self.assertEqual(helper.lifecycle[-1]["operation"], "close")


if __name__ == "__main__":
    unittest.main()
