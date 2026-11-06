"""Gate-first controls for the host witness parent and retained evidence."""

import hashlib
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from types import MappingProxyType, SimpleNamespace
from pathlib import Path
from textwrap import dedent

import boot_profile_capture as base
import run0_host_cpu_witness as witness
import test_run0_host_cpu_reader as reader_controls


class ParentAdmissionControls(unittest.TestCase):
    def test_sata_off_checks_bundle_at_the_actual_input_root(self):
        old = Path("/tmp/wmw-debug-d21-YFXXNEg5/run0/inputs")
        fresh = Path("/tmp/sata-off/inputs")
        fixed = ["/etc/ld.so.preload", "/etc/qemu/qemu.conf",
                 "/var/run/qemu/Debian_1_8.2.2+ds-0ubuntu1.18"]
        modules = {"checked_absences": [*fixed, str(old / "qemu-bundle")]}
        self.assertEqual(witness.runtime_module_absences(modules, old, base.INVOCATION_PROFILE),
                         modules["checked_absences"])
        self.assertEqual(witness.runtime_module_absences(modules, fresh,
                         base.SATA_OFF_INVOCATION_PROFILE), [*fixed, str(fresh / "qemu-bundle")])
        with self.assertRaises(base.ProbeError):
            witness.runtime_module_absences(modules, fresh, base.INVOCATION_PROFILE)

    def test_hc01_native_layout_refuses_changes(self):
        actual = {
            "pointer_size": 8, "long_size": 8, "int_size": 4, "sigchld": 17,
            "sig_dfl": 0, "sa_no_cld_wait": 2, "sigaction_size": 152,
            "sigaction_align": 8, "handler_offset": 0, "handler_size": 8,
            "mask_offset": 8, "mask_size": 128, "flags_offset": 136, "flags_size": 4,
            "restorer_offset": 144, "restorer_size": 8, "ucred_size": 12,
            "ucred_align": 4, "peer_pid_offset": 0, "peer_uid_offset": 4,
            "peer_gid_offset": 8, "statfs_size": 120, "statfs_align": 8,
            "fs_type_offset": 0, "fs_type_size": 8, "fs_type_signed": 1,
            "proc_super_magic": 40864, "ext4_super_magic": 61267, "so_peercred": 17,
        }
        witness.validate_native_layout(actual)
        for changes in ({"statfs_size": 112}, {"sig_dfl": False}, {"extra": 1},
                        {"sa_no_cld_wait": 0}, {"peer_pid_offset": 4}):
            with self.subTest(changes=changes), self.assertRaises(base.ProbeError):
                witness.validate_native_layout(actual | changes)

    def test_hc02_sigchld_flags_are_checked_in_native_bytes(self):
        default = bytearray(152)
        self.assertEqual(witness.decode_sigchld(bytes(default)), (0, 0))
        for offset, value in ((0, 1), (136, 2)):
            record = default.copy()
            record[offset] = value
            with self.subTest(offset=offset), self.assertRaises(base.ProbeError):
                witness.decode_sigchld(bytes(record))
        default[137] = 1
        with self.assertRaisesRegex(base.ProbeError, "sigchld_unknown_flags"):
            witness.decode_sigchld(bytes(default))
        with self.assertRaises(base.ProbeError):
            witness.decode_sigchld(bytes(default[:-1]))

    def test_hc03_peer_credentials_must_bind_exact_child(self):
        record = struct.pack("<iII", 123, 501, 20)
        self.assertEqual(witness.decode_peer(record, 123, 501, 20), (123, 501, 20))
        for identity in ((124, 501, 20), (123, 502, 20), (123, 501, 21), (True, 501, 20)):
            with self.subTest(identity=identity), self.assertRaises(base.ProbeError):
                witness.decode_peer(record, *identity)

    def test_hc03_proc_identity_keeps_starttime_and_parent(self):
        # Real Linux field order: state is field 3, ppid field 4, starttime field 22.
        rest = [b"S", b"41", *([b"0"] * 17), b"721231", *([b"0"] * 30)]
        line = b"123 (qemu worker) " + b" ".join(rest) + b"\n"
        self.assertEqual(witness.parse_proc_stat(line), (123, 41, 721231))
        for bad in (line[:-1], line.replace(b") S ", b") Z "), line + line,
                    line.replace(b"721231", b"-1")):
            with self.subTest(bad=bad[:40]), self.assertRaises(base.ProbeError):
                witness.parse_proc_stat(bad)

    def test_hc14_evidence_only_resolves_exact_immutable_bytes(self):
        data = b"actual retained response"
        reference = {"path": "control/status.bin", "length": len(data),
                     "sha256": hashlib.sha256(data).hexdigest()}
        blobs = {reference["path"]: data}
        self.assertEqual(witness.retained_blob(reference, blobs, 1024), data)
        for ref, entries in ((reference | {"path": "../status.bin"}, blobs),
                             (reference | {"length": True}, blobs),
                             (reference, MappingProxyType(blobs)),
                             (reference, {reference["path"]: bytearray(data)}),
                             (reference, {reference["path"]: b"x" * len(data)}),
                             (reference, {})):
            with self.subTest(ref=ref), self.assertRaises(base.ProbeError):
                witness.retained_blob(ref, entries, 1024)

        class AcquiringMapping:
            def __getitem__(self, key):
                raise AssertionError("retained bytes must never be acquired")

        proxy = MappingProxyType(AcquiringMapping())
        with self.assertRaisesRegex(base.ProbeError, "retained_bytes_mapping"):
            witness.validate_report(reference, proxy)

    def test_hc15_witness_is_not_constructible_from_caller_flags(self):
        with self.assertRaises(TypeError):
            witness.ValidatedHostState("retained_runtime", {}, {}, {"no_npt": True}, "PASS")
        with self.assertRaises(base.ProbeError):
            witness.validate_report({"path": "not-present.json", "length": 0,
                                     "sha256": "0" * 64}, {})

        class AcquiringMapping:
            def __getitem__(self, key):
                raise AssertionError("opaque export must never use an acquiring mapping")

        forged = object.__new__(witness.ValidatedHostState)
        object.__setattr__(forged, "origin", "synthetic_fixture")
        object.__setattr__(forged, "report_ref", MappingProxyType(AcquiringMapping()))
        with self.assertRaisesRegex(base.ProbeError, "host_witness_value"):
            witness.export_validated_host_state(forged)

    def test_hc11_owned_helper_retains_actual_tail_eof_and_wait(self):
        read_fd, write_fd = os.pipe()
        deadline = time.monotonic() + 5
        helper = None
        try:
            helper = witness.OwnedHelper("fields", read_fd, deadline)
            helper.start(
                [sys.executable, "-c",
                           "import os,sys; os.write(int(sys.argv[1]), b'tail'); "
                           "sys.stderr.write('actual stderr')", str(write_fd)],
                (write_fd,), 32, 32,
            )
        finally:
            os.close(write_fd)
            if helper is None:
                os.close(read_fd)
        try:
            helper.drain()
            self.assertEqual(bytes(helper.output), b"tail")
            self.assertEqual(bytes(helper.stderr), b"actual stderr")
            self.assertEqual(helper.eofs, {"stdout", "stderr"})
            self.assertEqual(helper.wait(), 0)
            self.assertTrue(helper.reaped)
            self.assertEqual(helper.actions, [])
        finally:
            helper.close()

    def test_hc11_stalled_helper_keeps_the_original_deadline(self):
        read_fd, write_fd = os.pipe()
        deadline = time.monotonic() + 3
        helper = None
        try:
            helper = witness.OwnedHelper("fields", read_fd, deadline)
            helper.start(
                [sys.executable, "-c",
                           "import os,signal,sys,time; "
                           "signal.signal(signal.SIGTERM,signal.SIG_IGN); "
                           "os.write(int(sys.argv[1]),b'ready'); time.sleep(30)",
                           str(write_fd)],
                (write_fd,), 32, 32,
            )
        finally:
            os.close(write_fd)
            if helper is None:
                os.close(read_fd)
        try:
            helper.until(lambda: bytes(helper.output) == b"ready")
            with self.assertRaises(base.ProbeError):
                helper.drain()
            helper.terminate()
            self.assertEqual(helper.deadline, deadline)
            self.assertTrue(helper.reaped)
            self.assertEqual(helper.returncode, -9)
            self.assertEqual(helper.actions, ["SIGTERM", "SIGKILL"])
        finally:
            helper.close()


class ParentIntegrationControls(unittest.TestCase):
    def helper(self):
        result, output = os.pipe()
        helper = witness.OwnedHelper("fields", result, time.monotonic() + 3)
        self.addCleanup(helper.close)
        return helper, output

    def test_hc11_static_loader_selector_failure_precedes_spawn(self):
        with patch.object(witness.selectors, "DefaultSelector", side_effect=OSError("fixture")), \
             patch.object(witness.subprocess, "Popen") as spawn:
            with self.assertRaisesRegex(OSError, "fixture"):
                witness._static_tool([sys.executable, "-c", "pass"], {}, time.monotonic() + 3)
            spawn.assert_not_called()

    def test_hc12_partial_write_prefix_is_charged_before_retaining_duplicate(self):
        with tempfile.TemporaryDirectory() as folder:
            run = Path(folder)
            budget = base.Budget(time.monotonic() + 60, byte_limit=8)
            budget.retain(6)
            evidence = witness.CaptureEvidence(run, budget, {})
            witness.write_private(run / "fields-output.bin", b"ab")
            observation = witness.OwnedCPUObservation(None, None, budget, None, None, None, None)
            observation.helpers["fields"] = SimpleNamespace(
                output=bytearray(b"abcdef"), stderr=bytearray(), child=None,
                eofs=set(), io_errors=[],
            )
            wire = SimpleNamespace(eofs=[], io_errors=[])
            witness.retain_partial(evidence, observation, [], [], None, wire, None)
            self.assertEqual(budget.retained_bytes, 8)
            self.assertEqual((run / "fields-output.bin").read_bytes(), b"ab")
            self.assertEqual((run / "partial-fields-output.bin").read_bytes(), b"abcdef")

    def test_hc12_partial_request_files_reuse_the_exact_prefix(self):
        frames = {"fields-begin.json": b"begin\n", "fields-admit.json": b"admit\n"}
        transcript = b"".join(frames.values())
        for failed in frames:
            with self.subTest(failed=failed), tempfile.TemporaryDirectory() as folder:
                run = Path(folder)
                budget = base.Budget(time.monotonic() + 60, byte_limit=len(transcript))
                budget.retain(len(transcript))
                evidence = witness.CaptureEvidence(run, budget, {})
                for name, data in frames.items():
                    if name == failed:
                        witness.write_private(run / name, data[:2])
                        break
                    evidence.put(name, data, charged=True)
                observation = witness.OwnedCPUObservation(None, None, budget, None, None, None, None)
                observation.request_sent.extend(transcript)
                wire = SimpleNamespace(eofs=[], io_errors=[])
                witness.retain_partial(evidence, observation, [], [], None, wire, None)
                details = json.loads((run / "failure-details.json").read_bytes())
                retained = b"".join((run / ref["path"]).read_bytes()
                                    for ref in details["fields_request_refs"])
                self.assertEqual(retained, transcript)
                self.assertEqual(budget.retained_bytes, len(transcript))

    def test_hc14_report_and_stderr_refusal_preserve_first_failure(self):
        report = {"termination": {"status": "DENY", "first_failure": "exact_primary",
                                  "secondary_failures": ["secondary_fixture"]}}
        with patch.object(witness, "write_private", side_effect=OSError("report failure")), \
             patch.object(witness.sys, "stderr") as stderr:
            for failure in (OSError("stderr failure"), ValueError("stderr closed")):
                with self.subTest(failure=failure):
                    stderr.write.side_effect = failure
                    with self.assertRaisesRegex(base.ProbeError, "exact_primary") as refused:
                        witness.persist_capture_report(Path("/fixture"), report)
                    self.assertEqual(refused.exception.status, "DENY")
                    self.assertIn("report_write_failed", stderr.write.call_args.args[0])

    def test_hc04_observation_refuses_buffered_event_before_field_dispatch(self):
        with tempfile.TemporaryDirectory() as folder:
            deadline = time.monotonic() + 3
            budget = base.Budget(time.monotonic() + 60)
            wire = witness.ResetWire(Path(folder), budget)
            reader, sender = socket.socketpair()
            try:
                wire.add("qmp", reader)
                qmp = witness.ResetQMP(wire, budget)
                observation = witness.OwnedCPUObservation(None, qmp, budget, None, None,
                                                         None, None)
                observation.deadline = deadline
                event = b'{"event":"DEVICE_DELETED","timestamp":{}}\r\n'
                sender.sendall(event)
                with self.assertRaisesRegex(base.ProbeError, "unexpected_guest_event"):
                    observation._pump()
                self.assertEqual((Path(folder) / "qmp.bin").read_bytes(), event)
                self.assertEqual(qmp.received_events[0][2], "DEVICE_DELETED")
                self.assertEqual(observation.helpers, {})
            finally:
                sender.close()
                wire.close()

    def test_hc11_spawn_owner_survives_pipe_setup_failure(self):
        helper, output = self.helper()
        try:
            with patch.object(witness.os, "set_blocking", side_effect=OSError("fixture")):
                with self.assertRaisesRegex(OSError, "fixture"):
                    helper.start([sys.executable, "-c", "import time; time.sleep(20)"],
                                 (output,), 32, 32)
            self.assertEqual([row["operation"] for row in helper.lifecycle], ["spawn"])
        finally:
            os.close(output)
        helper.close()
        self.assertTrue(helper.reaped)
        self.assertEqual(helper.lifecycle[-2]["operation"], "wait")
        self.assertEqual(helper.lifecycle[-1]["operation"], "close")

    def test_hc12_helper_retains_capped_prefix_without_eof(self):
        helper, output = self.helper()
        try:
            helper.start([sys.executable, "-c", "import os,sys; "
                          "os.write(int(sys.argv[1]),b'0123456789')", str(output)],
                         (output,), 4, 32)
        finally:
            os.close(output)
        with self.assertRaisesRegex(base.ProbeError, "helper_output_limit"):
            helper.drain()
        self.assertEqual(bytes(helper.output), b"0123")
        self.assertNotIn("stdout", helper.eofs)
        self.assertEqual(helper.io_errors[-1]["observed_overflow_bytes"], 1)

    def test_hc12_helper_shares_the_capture_budget(self):
        result, output = os.pipe()
        deadline = time.monotonic() + 3
        budget = base.Budget(deadline, byte_limit=6)
        budget.retain(4)
        helper = witness.OwnedHelper("fields", result, deadline, budget=budget)
        self.addCleanup(helper.close)
        try:
            helper.start([sys.executable, "-c", "import os,sys; "
                          "os.write(int(sys.argv[1]),b'abcdef')", str(output)],
                         (output,), 32, 32)
        finally:
            os.close(output)
        with self.assertRaisesRegex(base.ProbeError, "helper_output_limit"):
            helper.drain()
        self.assertEqual(bytes(helper.output), b"ab")
        self.assertEqual(budget.retained_bytes, 6)
        self.assertNotIn("stdout", helper.eofs)

    def test_hc11_cleanup_refusal_prevents_observation_continuation(self):
        helper, output = self.helper()
        os.close(output)
        helper.start([sys.executable, "-c", "pass"], (), 32, 32)
        helper.drain()
        self.assertEqual(helper.wait(), 0)
        observation = witness.OwnedCPUObservation(None, None, None, None, None, None, None)
        close = os.close

        def refuse(fd):
            if fd == helper.result_fd:
                raise OSError(5, "fixture close refusal")
            close(fd)

        try:
            with patch.object(witness.os, "close", side_effect=refuse):
                observation._close_helper(helper)
            with self.assertRaisesRegex(base.ProbeError, "helper_cleanup_incomplete"):
                observation._require_helper_closed(helper)
            self.assertEqual(observation.secondary_failures, ["fields_close_error"])
        finally:
            close(helper.result_fd)

    def test_hc11_echild_is_never_a_successful_owned_wait(self):
        owner = witness.OwnedWait("fields", time.monotonic() + 3)
        owner.child = subprocess.Popen([sys.executable, "-c", "pass"])
        pid, status = os.waitpid(owner.child.pid, 0)
        self.assertEqual(pid, owner.child.pid)
        try:
            with self.assertRaises(ChildProcessError):
                owner.wait()
            self.assertFalse(owner.reaped)
            self.assertEqual(owner.lifecycle[-1]["result"], "error")
            self.assertIsNone(owner.lifecycle[-1]["returncode"])
            with patch.object(witness.os, "killpg") as killpg:
                owner.terminate()
                killpg.assert_not_called()
        finally:
            owner.child.returncode = os.waitstatus_to_exitcode(status)

    def test_hc11_pump_cannot_spend_the_remaining_read_allowance(self):
        helper, output = self.helper()
        try:
            helper.start([sys.executable, "-c", "import os,sys; "
                          "os.write(int(sys.argv[1]),b'ready')", str(output)],
                         (output,), 32, 32)
        finally:
            os.close(output)
        helper.pump = lambda: time.sleep(0.04)
        with self.assertRaisesRegex(base.ProbeError, "helper_io_deadline"):
            helper._step(time.monotonic() + 0.02)
        self.assertEqual(bytes(helper.output), b"")

    def test_hc08_parent_rederives_actual_worker_reads_and_rejects_tampering(self):
        with tempfile.TemporaryDirectory() as folder:
            session = reader_controls.Session(folder)
            try:
                session.send(session.begin)
                session.until("head_ready")
                prefix = b"".join(witness.canonical(row) for row in session.rows)
                grant = witness.field_receipts(prefix, session.begin, session.maps,
                                               session.abi, head_only=True)
                self.assertEqual(grant["cpu"], reader_controls.CPU)
                session.send(grant)
                session.until("finished")
                self.assertEqual(session.child.wait(timeout=2), 0)
                frames = [witness.canonical(row) for row in session.rows]
                derived, reads, state = witness.field_receipts(
                    b"".join(frames), session.begin, session.maps, session.abi,
                )
                self.assertEqual(derived, grant)
                self.assertEqual([row["seq"] for row in reads], list(range(1, 15)))
                self.assertEqual(sum(row["length"] for row in reads), 104)
                self.assertTrue(state["no_npt"])
                for mutation in (frames[:-1], frames + [frames[-1]],
                                 frames[:5] + [frames[6], frames[5]] + frames[7:]):
                    with self.subTest(frame_count=len(mutation)), self.assertRaises(base.ProbeError):
                        witness.field_receipts(b"".join(mutation), session.begin,
                                               session.maps, session.abi)
            finally:
                session.close()


def synthetic_qmp(tid, first, last):
    regs = ("\r\nCPU#0\r\nEIP=0000fff0 CPL=0 A20=1 SMM=0\r\n"
            "CS =f000 ffff0000 0000ffff 00009b00\r\n"
            "CR0=60000010\r\nEFER=0000000000000000\r\n")
    path = "/machine/unattached/device[0]"
    bracket = (
        ("query-status", None, {"running": False, "status": "prelaunch"}),
        ("query-cpus-fast", None, [{"cpu-index": 0, "thread-id": tid, "target": "x86_64",
                                    "qom-path": path, "props": {}}]),
        ("qom-get", {"path": path, "property": "realized"}, True),
        ("qom-get", {"path": path, "property": "phys-bits"}, 40),
        ("human-monitor-command", {"command-line": "info registers"}, regs),
    )
    commands = [{"name": name} for name in ("qmp_capabilities", "query-commands", "query-status",
                                           "query-cpus-fast", "qom-get",
                                           "human-monitor-command", "quit")]
    transcript = (("qmp_capabilities", None, {}), ("query-commands", None, commands),
                  *bracket, *bracket, ("quit", None, {}))
    requests, replies, times, events = [], [b'{"QMP":{}}\r\n'], [], []

    def frame(obj, delim=b"\r\n"):
        return json.dumps(obj, separators=(",", ":")).encode() + delim

    for seq, (cmd, args, result) in enumerate(transcript, 1):
        request = {"execute": cmd, "id": seq}
        if args is not None:
            request["arguments"] = args
        requests.append(frame(request, b"" if cmd == "quit" else b"\r\n"))
        start = (first - 10000 if seq <= 7 else last + 10000) + seq * 100
        times.append((start, start + 90))
        if cmd == "quit":
            events.append(start + 45)
            replies.append(frame({"event": "SHUTDOWN", "timestamp": {"seconds": 1},
                                  "data": {"guest": False, "reason": "host-qmp-quit"}}))
        replies.append(frame({"return": result, "id": seq}))
    return b"".join(replies), b"".join(requests), times, events


def synthetic_shared_control(put, rsp_index, blobs, profile_sha, first, last, sequence_map):
    from run0_c0_decode import validate_c0_rsp
    from test_run0_c0_decode import synthetic_c0_hmp

    rsp = validate_c0_rsp(rsp_index, blobs)
    text = synthetic_c0_hmp(rsp["before_registers"])
    layout = ('FlatView #0\n AS "memory", root: system\n'
              ' AS "cpu-memory-0", root: system\n Root memory region: system\n'
              '  0000000000000000-000000001fffffff (prio 0, ram): pc.ram\n')
    path = "/machine/unattached/device[0]"
    cpu = [{"cpu-index": 0, "thread-id": 123, "target": "x86_64", "qom-path": path, "props": {}}]
    paused = {"running": False, "status": "debug"}
    commands = ("qmp_capabilities", "query-commands", "query-status", "query-cpus-fast",
                "qom-get", "human-monitor-command", "quit")
    outgoing = bytearray()
    incoming = bytearray(b'{"QMP":{}}\r\n')
    qmp, all_ops = [], []
    refs = []

    def qop(at, label, execute, result, args=None):
        request = {"execute": execute, "id": len(qmp) + 1}
        if args is not None:
            request["arguments"] = args
        delimit = b"" if label == "quit" else b"\r\n"
        data = json.dumps(request, separators=(",", ":")).encode() + delimit
        tx = {"blob": None, "offset": len(outgoing), "length": len(data)}
        outgoing.extend(data)
        data = json.dumps({"return": result, "id": request["id"]},
                          separators=(",", ":")).encode()
        rx = {"blob": None, "offset": len(incoming), "length": len(data)}
        incoming.extend(data + b"\r\n")
        row = {"protocol": "qmp", "operation": label, "started_ns": at,
               "finished_ns": at + 10, "request": tx, "response": rx, "result": "ok"}
        qmp.append(row)
        refs.append((tx, rx))
        all_ops.append(row)
        return row

    qop(first - 90000, "qmp_capabilities", "qmp_capabilities", {})
    qop(first - 89900, "query_commands", "query-commands", [{"name": cmd} for cmd in commands])
    qop(first - 89800, "query_status", "query-status", {"running": False, "status": "prelaunch"})

    def bracket(at, include_width):
        indexed = {
            "status_seq": qop(at, "query_status", "query-status", paused),
            "cpu_seq": qop(at+20, "query_cpus_fast", "query-cpus-fast", cpu),
            "realized_seq": None, "phys_bits_seq": None,
        }
        if include_width:
            indexed["realized_seq"] = qop(
                at+40, "qom_realized", "qom-get", True, {"path": path, "property": "realized"},
            )
            indexed["phys_bits_seq"] = qop(
                at+60, "qom_phys_bits", "qom-get", 40, {"path": path, "property": "phys-bits"},
            )
        indexed["hmp_seq"] = qop(
            at+80, "hmp_registers", "human-monitor-command", text,
            {"command-line": "info registers"},
        )
        return indexed

    before = bracket(first - 9500, True)
    after = bracket(last + 1000, False)
    qop(last + 1100, "hmp_flatview", "human-monitor-command", layout,
        {"command-line": "info mtree -f"})
    first_mem = min(row["seq"] for row in rsp_index["operations"]
                    if row["operation"] == "physical_read")
    rsp_ops = {}
    for original in rsp_index["operations"]:
        seq = original["seq"]
        at = first - 80000 + 100 * seq if seq < first_mem else last + 3000 + 100 * seq
        row = dict(original, started_ns=at, finished_ns=at + 10)
        all_ops.append(row)
        rsp_ops[seq] = row

    final_at = max(row["finished_ns"] for row in rsp_ops.values()) + 100
    qop(final_at, "hmp_registers", "human-monitor-command", text,
        {"command-line": "info registers"})
    qop(final_at+20, "hmp_flatview", "human-monitor-command", layout,
        {"command-line": "info mtree -f"})
    qop(final_at+40, "quit", "quit", {})
    in_ref = put("qmp.bin", bytes(incoming))
    out_ref = put("qmp-requests.bin", bytes(outgoing))
    for tx, rx in refs:
        tx["blob"], rx["blob"] = out_ref, in_ref
    all_ops.sort(key=lambda row: row["started_ns"])
    for seq, row in enumerate(all_ops, 1):
        row["seq"] = seq
    if sequence_map is not None:
        sequence_map.update({seq: row["seq"] for seq, row in rsp_ops.items()})
    event = dict(rsp_index["events"][0], received_ns=rsp_ops[rsp["resume_seq"]]["finished_ns"]+10)
    event_wire = event["wire"]
    raw = blobs[event_wire["blob"]["path"]]
    offset, length = event_wire["offset"], event_wire["length"]
    stop_ref = put("c0-stop.bin", raw[offset:offset+length])
    before = {key: None if row is None else row["seq"] for key, row in before.items()}
    after = {key: None if row is None else row["seq"] for key, row in after.items()}
    index = {"schema_version": 1, "scope": "shared_c0", "run_id": "witness",
             "profile_sha256": profile_sha, "clock": "host_monotonic_ns",
             "raw_qmp_in_ref": in_ref, "raw_qmp_out_ref": out_ref,
             "raw_rsp_in_ref": rsp_index["raw_rsp_in_ref"],
             "raw_rsp_out_ref": rsp_index["raw_rsp_out_ref"],
             "operations": all_ops, "events": [event], "before": before, "after": after}
    binding = {"context": "c0", "run_id": "witness", "profile_sha256": profile_sha,
               "cpu_index": 0, "qmp_thread_id": 123, "rsp_thread": "01", "stop_id": "C0",
               "stop_ref": stop_ref, "resume_seq": rsp_ops[rsp["resume_seq"]]["seq"],
               "breakpoint_seq": rsp_ops[rsp["breakpoint_seq"]]["seq"],
               "control_before_seq": before["status_seq"], "control_after_seq": after["status_seq"]}
    return index, binding, last + 1095, final_at + 100


def synthetic_host_report(folder, *, rsp_index=None, rsp_blobs=None, profile=None,
                          sequence_map=None):
    """Test-only evidence producer. The production validator constructs the witness."""
    reader = reader_controls.reader
    mutate = None
    if rsp_index is not None:
        def mutate(fd):
            os.pwrite(fd, struct.pack("<I", (1 << 14) | (1 << 15)),
                      reader_controls.CPU + reader.HFLAGS)
    session = reader_controls.Session(folder, mutate)
    try:
        session.send(session.begin)
        session.until("head_ready")
        session.admit()
        session.until("finished")
        assert session.child.wait(timeout=2) == 0
        wire = b"".join(witness.canonical(row) for row in session.rows)
        grant, reads, state = witness.field_receipts(
            wire, session.begin, session.maps, session.abi,
        )
    finally:
        session.close()

    blobs = dict(rsp_blobs or {})

    def put(name, value):
        data = value if type(value) is bytes else witness.canonical(value)
        blobs[name] = data
        return {"path": name, "length": len(data), "sha256": hashlib.sha256(data).hexdigest()}

    executable = reader_controls.elf_fixture()
    exe = reader_controls.exe_identity(executable)
    marker = put("fixture-source.txt", b"synthetic source for parser fixture\n")
    native_ref = put("native.json", {
        "schema_version": 1, "kind": "run0_host_cpu_native_abi_v0",
        "layout_ref": put("layout.json", dict(witness.NATIVE_LAYOUT)),
        "layout_source_ref": marker, "layout_binary_ref": marker,
        "package_observation_ref": marker,
        "headers": [{"role": role, "ref": marker} for role in witness.NATIVE_HEADER_PINS],
        "parser_source_refs": [{"role": "linux_dev_t", "ref": marker}],
    })
    abi = {"schema_version": 1, "kind": "run0_host_cpu_abi_v0",
           "contract_abi_sha256": reader.ABI_SHA256,
           "kernel_source_refs": [{"role": role, "ref": marker}
                                  for role in witness.KERNEL_SOURCE_PINS]}
    abi.update(dict.fromkeys(witness.ABI_BLOB_LIMITS, marker))
    abi.update(qemu_ref=put("fixture-qemu.bin", executable), native_abi_ref=native_ref)
    abi_ref = put("abi.json", abi)
    profile = {} if profile is None else profile
    profile_ref = put("profile.json", profile)
    profile_digest = witness.entry.profile_digest(profile)
    observer = put("observer.json", {"scope": "synthetic_fixture"})
    plan = {
        "schema_version": 1, "kind": "run0_host_cpu_witness_plan_v0",
        "inputs": "/fixture", "run": "/fixture/witness", "uid": 41, "gid": 42,
        "argv": base.build_argv(Path("/fixture"), Path("/fixture/witness"),
                                profile.get("invocation_profile", base.INVOCATION_PROFILE)),
        "launch_identity": {name: exe[name] for name in ("device", "inode", "size")},
        "profile_sha256": profile_ref["sha256"], "abi_sha256": abi_ref["sha256"],
        "source_dossier_sha256": marker["sha256"], "observer_ref": observer,
        "esp_validation": {},
    }
    first, last = reads[0]["started_ns"], reads[-1]["finished_ns"]
    if rsp_index is None:
        raw_in, raw_out, times, events = synthetic_qmp(123, first, last)
        in_ref, out_ref = put("qmp.bin", raw_in), put("qmp-requests.bin", raw_out)
        control, tid = witness.reset_control_index(
            "witness", profile_digest, raw_in, raw_out, in_ref, out_ref, times, events,
        )
        binding = {"context": "reset", "run_id": "witness", "profile_sha256": profile_digest,
                   "cpu_index": 0, "qmp_thread_id": tid, "rsp_thread": None, "stop_id": "reset",
                   "stop_ref": None, "resume_seq": None, "breakpoint_seq": None,
                   "control_before_seq": 3, "control_after_seq": 8}
        after_pidfd, qemu_wait = last + 11295, last + 20000
    else:
        control, binding, after_pidfd, qemu_wait = synthetic_shared_control(
            put, rsp_index, blobs, profile_digest, first, last, sequence_map,
        )
        in_ref = control["raw_qmp_in_ref"]
    rows = []

    def add_lifecycle(role, pid, op, started, finished):
        rows.append({"role": role, "pid": pid, "operation": op, "started_ns": started,
                     "finished_ns": finished, "result": "ok",
                     "returncode": 0 if op == "wait" else None, "errno": None})

    pids = dict(zip(witness.WAIT_ROLES, (51, 52, 53, 54), strict=True))
    clocks = {"qemu": (first - 100000, qemu_wait),
              "metadata_before": (first - 400, first - 360),
              "fields": (first - 200, last + 100),
              "metadata_after": (last + 200, last + 250)}
    for role, pid in pids.items():
        spawn, wait = clocks[role]
        add_lifecycle(role, pid, "spawn", spawn, spawn + 10)
        add_lifecycle(role, pid, "wait", wait, wait + 10)
        add_lifecycle(role, pid, "close", wait + 11, wait + 12)
    rows.sort(key=lambda row: row["started_ns"])
    for seq, row in enumerate(rows, 1):
        row["seq"] = seq
    lifecycle = put("lifecycle.json", {"schema_version": 1, "rows": rows})

    rest = [b"S", b"41", *([b"0"] * 17), b"721231", *([b"0"] * 30)]
    proc_stat = b"51 (synthetic qemu) " + b" ".join(rest) + b"\n"
    mount = b"10 1 8:1 / / rw - ext4 /dev/sda1 rw\n"
    metadata_bytes = b"".join(struct.pack(">I", len(data)) + data for data in (
        proc_stat, reader_controls.MAPS, reader_controls.smaps(), mount, witness.canonical(exe),
    ))
    before_ref, before = witness.retain_metadata(
        put, "before", 52, clocks["metadata_before"][0], clocks["metadata_before"][1] + 10,
        metadata_bytes, b"",
    )
    after_ref, after = witness.retain_metadata(
        put, "after", 54, clocks["metadata_after"][0], clocks["metadata_after"][1] + 10,
        metadata_bytes, b"",
    )
    fields_ref, fields = witness.retain_fields(
        put, 53, witness.canonical(session.begin), witness.canonical(grant), wire, b"", reads,
    )
    stream_refs = {
        "qmp": in_ref, "serial": put("serial.bin", b""), "debug": put("debug.bin", b""),
        "qemu_stdout": put("stdout.bin", b""), "qemu_stderr": put("stderr.bin", b""),
        "metadata_before_stdout": before["wire_ref"], "metadata_before_stderr": before["stderr_ref"],
        "fields_stdout": fields["output_ref"], "fields_stderr": fields["stderr_ref"],
        "metadata_after_stdout": after["wire_ref"], "metadata_after_stderr": after["stderr_ref"],
    }
    if rsp_index is not None:
        stream_refs["rsp"] = control["raw_rsp_in_ref"]
    streams = put("streams.json", {"schema_version": 1, "rows": [
        {"name": name, "raw_ref": ref, "eof": True, "error": None}
        for name, ref in stream_refs.items()
    ]})
    policy = put("sigchld.bin", bytes(152))

    def signal_receipt(at):
        return {"observed_ns": at, "raw_ref": policy, "abi_ref": native_ref, "handler": 0,
                "flags": 0, "no_cld_wait_mask": 2, "observer_pid": 41}

    def pidfd_receipt(at):
        return {"observed_ns": at, "readable": False, "hangup": False, "error": None}

    process = {
        "schema_version": 1, "observer_pid": 41, "qemu_pid": 51, "ppid": 41,
        "starttime_ticks": 721231, "pidfd_opened_ns": first - 490,
        "pidfd_before": pidfd_receipt(first - 480),
        "pidfd_after": pidfd_receipt(after_pidfd),
        "procdir_identity": {"dev": 2, "inode": 3, "mode": 0o40500, "statfs_magic": 40864},
        "mem_open": {"at_ns": first - 250, "fd": 3, "flags": 0,
                     "access_mode": "O_RDONLY", "cloexec": True},
        "mem_closed_ns": last + 130, "exe_before_ref": before["exe_identity_ref"],
        "exe_after_ref": after["exe_identity_ref"], "lifecycle_ref": lifecycle,
    }
    waits = [{"role": role, "pid": pid, "started": True, "reaped": True, "returncode": 0,
              "actions": [], "grace": "exited" if role == "qemu" else "not_attempted"}
             for role, pid in pids.items()]
    report = {
        "schema_version": 1, "kind": "run0_host_cpu_witness_v0", "run_id": "witness",
        "origin": "synthetic_fixture", "claims": witness.FALSE_CLAIMS,
        "fresh_c0_verified": False, "profile_ref": profile_ref, "observer_ref": observer,
        "source_ref": marker, "abi_ref": abi_ref, "plan_ref": put("plan.json", plan),
        "binding": binding,
        "metadata_before_ref": before_ref, "metadata_after_ref": after_ref,
        "peer_ref": put("peer.json", {
            "schema_version": 1, "socket_role": "qmp", "socket_path": "qmp.sock",
            "observed_ns": first - 9705, "raw_ref": put("peer.bin", struct.pack("<iII", 51, 41, 42)),
            "pid": 51, "uid": 41, "gid": 42, "abi_ref": native_ref,
        }),
        "sigchld_ref": put("sigchld.json", {
            "schema_version": 1, "before_spawn": signal_receipt(first - 110000),
            "before_open": signal_receipt(first - 500), "sole_reaper_pid": 41,
            "no_concurrent_reaper": True, "policy_ref": observer,
        }),
        "process_ref": put("process.json", process), "reads_ref": fields_ref,
        "state": state, "admission": {"status": "ADMIT", "reason": "reset_field_subset"},
        "termination": {"status": "PASS", "first_failure": None, "secondary_failures": [],
                        "waits": waits, "streams_ref": streams},
        "control_ref": put("control.json", control),
    }
    return report, blobs, put


class RetainedReportControls(unittest.TestCase):
    def test_hc14_hc15_pass_requires_derived_state_actual_wait_and_complete_wire(self):
        with tempfile.TemporaryDirectory() as folder:
            report, blobs, put = synthetic_host_report(folder)
        ref = put("report.json", report)
        value = witness.validate_report(ref, blobs)
        self.assertEqual(value.origin, "synthetic_fixture")
        self.assertEqual(value.final_status, "PASS")
        self.assertTrue(value.state["no_npt"])
        self.assertEqual(value.binding["qmp_thread_id"], 123)
        self.assertEqual(witness.export_validated_host_state(value)["report_ref"], ref)
        with self.assertRaises(TypeError):
            value.state["no_npt"] = False
        state = report["state"] | {"hflags": 1}
        for update in ({"state": state}, {"origin": "retained_runtime"},
                       {"termination": report["termination"] | {"waits": []}}):
            with self.subTest(update=update), self.assertRaises(base.ProbeError):
                witness.validate_report(put("changed-report.json", report | update), blobs)
        controls = json.loads(blobs[report["control_ref"]["path"]])
        incoming = blobs[controls["raw_qmp_in_ref"]["path"]] + b'{"event":"RESUME"}\r\n'
        controls["raw_qmp_in_ref"] = put("changed-qmp.bin", incoming)
        changed = report | {"control_ref": put("changed-control.json", controls)}
        with self.assertRaises(base.ProbeError):
            witness.validate_report(put("changed-report.json", changed), blobs)

    def test_hc11_collector_reaps_rejected_control_and_retains_empty_stream_eof(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            run = root / "control"
            image = b"fixture vars"
            witness.write_private(root / "initial_vars", image)
            abi_index = b'{"source_dossier_ref":null,"native_abi_ref":null}'
            ref = witness.CaptureEvidence.ref("host-abi.json", abi_index)
            profile = {"inputs": {
                "initial_vars": {"length": len(image), "sha256": hashlib.sha256(image).hexdigest()},
            }}
            script = dedent("""
                import json, socket, sys
                from pathlib import Path
                run = Path(sys.argv[1])
                sockets, accepted = [], []
                for name in ("qmp", "serial", "debug"):
                    server = socket.socket(socket.AF_UNIX)
                    server.bind(str(run / (name + ".sock")))
                    server.listen(1)
                    sockets.append(server)
                for server in sockets:
                    connection, _ = server.accept()
                    accepted.append(connection)
                qmp = accepted[0]
                qmp.sendall(b'{"QMP":{}}\\r\\n')
                wire = qmp.makefile("rb")
                for reply in ({}, []):
                    req = json.loads(wire.readline())
                    qmp.sendall(json.dumps({"id":req["id"],"return":reply}).encode()+b"\\r\\n")
                tail = bytearray()
                while not tail.endswith(b"}"):
                    chunk = wire.read(1)
                    if not chunk:
                        raise RuntimeError("missing quit")
                    tail.extend(chunk)
                quit = json.loads(tail)
                assert quit["execute"] == "quit"
                qmp.sendall(json.dumps({"id":quit["id"],"return":{}}).encode()+b"\\r\\n")
                wire.close()
                for connection in accepted + sockets:
                    connection.close()
            """)
            plan = {"inputs": str(root), "argv": [sys.executable, "-c", script, str(run)]}
            prepared = (plan, profile, witness.canonical(profile), b"{}\n", ref,
                        {ref["path"]: abi_index}, None, None)
            with patch.object(witness, "REVIEWED_LAUNCH_ABI_SHA256", ref["sha256"]), \
                 patch.object(witness, "NativeQueries") as native, \
                 patch.object(witness, "clean_launch_env", lambda _: {"PATH": "/usr/bin:/bin"},
                              create=True):
                native.return_value.sigchld.return_value = bytes(152)
                report, _ = witness.run_reset_capture(prepared, run)
            termination = report["termination"]
            self.assertEqual(termination["first_failure"], "qmp_command_inventory")
            self.assertEqual([(row["reaped"], row["returncode"]) for row in termination["waits"]],
                             [(True, 0)])
            details = json.loads((run / "failure-details.json").read_bytes())
            self.assertEqual({row["stream"] for row in details["vm_stream_eofs"]},
                             {"qmp", "serial", "debug", "stdout", "stderr"})
            self.assertEqual((run / "serial.bin").read_bytes(), b"")
            self.assertEqual((run / "debug.bin").read_bytes(), b"")


if __name__ == "__main__":
    unittest.main()
