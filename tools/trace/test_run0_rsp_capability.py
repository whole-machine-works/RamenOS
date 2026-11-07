"""Gate-first controls for the reset-only RUN0 launcher."""

from contextlib import contextmanager, ExitStack
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import boot_profile_capture as previous
import run0_rsp_capability as cap


CPU = {
    "cpu-index": 0, "qom-path": "/machine/unattached/device[0]",
    "target": "x86_64", "thread-id": 123, "props": {},
}
LAYOUT = """FlatView #0
 AS "memory", root: system
 AS "cpu-memory-0", root: system
 Root memory region: system
  0000000000000000-000000000009ffff (prio 0, ram): pc.ram
  00000000000a0000-00000000000bffff (prio 1, i/o): vga
  0000000000100000-000000001fffffff (prio 0, ram): pc.ram @0000000000100000
FlatView #1
 AS "unconfigured-device", root: bus master container
 Root memory region: (none)
  No rendered FlatView
"""


class Wire:
    def __init__(self, replies):
        self.replies = list(replies)
        self.writes = []

    def send(self, data, deadline):
        self.writes.append(data)

    def next(self, deadline):
        return json.dumps(self.replies.pop(0)).encode()


_OWNED_CHILD = r"""
import json, os, socket, sys, time
mode, descriptors = sys.argv[1], json.loads(sys.argv[2])
channels = {name: socket.socket(fileno=fd) for name, fd in descriptors.items()}
for channel in channels.values():
    channel.settimeout(10)
qmp = channels['qmp']
qmp.sendall(b'{"QMP":{}}\r\n')
pending = ''
decoder = json.JSONDecoder()
while True:
    pending += qmp.recv(4096).decode('ascii')
    try:
        command, end = decoder.raw_decode(pending.lstrip())
    except json.JSONDecodeError:
        continue
    pending = pending.lstrip()[end:].lstrip()
    assert command['execute'] in ('qmp_capabilities', 'quit')
    qmp.sendall((json.dumps({'return': {}, 'id': command['id']}) + '\r\n').encode())
    if command['execute'] == 'quit':
        if mode == 'late-rsp':
            channels['rsp'].sendall(b'$OK#9a')
        if mode == 'cancel-wait':
            assert channels['release'].recv(1) == b'x'
        break
os.write(1, b'owned-stdout-tail')
os.write(2, b'owned-stderr-tail')
for channel in channels.values():
    channel.close()
"""


@contextmanager
def control_root(name):
    """Opt-in retention is test-only; CI defaults remain disposable fixtures."""
    retained = os.environ.get("RAMEN_CAPABILITY_CONTROL_ROOT")
    if retained:
        root = Path(retained).resolve()
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        yield Path(tempfile.mkdtemp(prefix=name + "-", dir=root)).resolve()
    else:
        with tempfile.TemporaryDirectory(prefix=name + "-") as tmp:
            yield Path(tmp).resolve()


class LauncherFixture:
    """Real child, QMP bytes, streams and files; synthetic pinned input admission.

    This exercises lifecycle orchestration only, never QEMU capability acceptance.
    The observer seam returns without manufacturing guest observations. Every
    caller must obtain an INCOMPLETE result from its specific exercised fault.
    """

    def __init__(self, root, mode):
        self.root, self.mode = root, mode
        self.inputs, self.run = root / "inputs", root / "run"
        self.inputs.mkdir(mode=0o700)
        variables = b"private-lifecycle-control-vars"
        cap.write_private(self.inputs / "initial_vars", variables)
        self.profile = {"inputs": {"initial_vars": {
            "length": len(variables), "sha256": hashlib.sha256(variables).hexdigest(),
        }}}
        self.profile_bytes = cap.canonical(self.profile)
        cap.write_private(self.inputs / "profile.json", self.profile_bytes)
        self.parents, self.child_ends = {}, {}
        for name in (*cap.STREAMS[:4], "release"):
            self.parents[name], self.child_ends[name] = socket.socketpair()
        self.plan = {"observer": {"kind": "owned_python_lifecycle_fixture"},
                     "profile_sha256": hashlib.sha256(self.profile_bytes).hexdigest(),
                     "argv": [sys.executable, "-B", "-c", _OWNED_CHILD, mode,
                              json.dumps({n: s.fileno() for n, s in self.child_ends.items()})]}
        self.children, self.waits, self.signals, self.reap_deadlines = [], [], [], []
        self.wait_phase = "collector"
        self._popen, self._reap = subprocess.Popen, previous.reap_owned

    def spawn(self, *args, **kwargs):
        child = self._popen(*args, **kwargs,
                            pass_fds=tuple(s.fileno() for s in self.child_ends.values()))
        self.children.append(child)
        for stream in self.child_ends.values():
            stream.close()
        actual_wait = child.wait

        def wait(timeout=None):
            row = {"phase": self.wait_phase, "started_ns": time.monotonic_ns(), "timeout": timeout}
            self.waits.append(row)
            try:
                if self.mode == "cancel-wait" and not self.signals:
                    self.signals.append({"signal": "SIGINT", "sent_ns": time.monotonic_ns()})
                    try:
                        os.kill(os.getpid(), signal.SIGINT)
                    finally:
                        self.parents["release"].sendall(b"x")
                row["returncode"] = actual_wait(timeout=timeout)
                return row["returncode"]
            except BaseException as error:
                row["exception"] = type(error).__name__
                raise
            finally:
                row["finished_ns"] = time.monotonic_ns()
        child.wait = wait
        return child

    def connect(self, path, child, deadline):
        assert child is self.children[0] and time.monotonic() < deadline
        return self.parents[{"gdb": "rsp"}.get(path.stem, path.stem)]

    def reap(self, child, deadline, **kwargs):
        self.reap_deadlines.append(deadline)
        return self._reap(child, deadline, **kwargs)

    def collect(self, fail_name=None):
        actual_put = cap.Evidence.put

        def put(evidence, name, data):
            if name == fail_name:
                # A real exclusive-create refusal, isolated to this identity
                # copy, leaves the terminal receipt's directory writable.
                (evidence.run / name).mkdir(mode=0o700)
            return actual_put(evidence, name, data)

        with ExitStack() as stack:
            for owner, name, replacement in (
                (cap.base, "validate_profile", lambda *_: None),
                (cap, "read_exact", lambda *_: self.profile_bytes),
                (cap, "observer_manifest", lambda: self.plan["observer"]),
                (cap, "observe", lambda *_: None),
                (cap.base, "connect", self.connect),
                (cap.base, "reap_owned", self.reap),
                (subprocess, "Popen", self.spawn),
                (cap.Evidence, "put", put),
            ):
                stack.enter_context(patch.object(owner, name, replacement))
            return cap.run_capability(self.plan, self.profile, self.profile_bytes,
                                      b"lifecycle control dossier", self.inputs, self.run)

    def close(self):
        # A failing collector must not strand the control's real child. Retain
        # this fallback separately; it can never repair the collector's proof.
        before = [{"pid": c.pid, "returncode": c.returncode,
                   "stdout_closed": c.stdout.closed, "stderr_closed": c.stderr.closed}
                  for c in self.children]
        self.wait_phase = "test_finally_cleanup"
        fallback = []
        for child in self.children:
            fallback.append(self._reap(child, time.monotonic() + 3))
            child.stdout.close()
            child.stderr.close()
        for stream in (*self.parents.values(), *self.child_ends.values()):
            stream.close()
        cap.write_private(self.root / "fixture-evidence.json", cap.canonical({
            "kind": "owned_python_lifecycle_control", "mode": self.mode,
            "collector_children_before_fallback": before, "actual_waits": self.waits,
            "signals": self.signals, "collector_reap_deadlines": self.reap_deadlines,
            "test_finally_cleanup": fallback,
        }))


class CapabilityControls(unittest.TestCase):
    def test_cap02_sata_off_profile_has_a_distinct_pin_and_exact_machine(self):
        old = {"invocation_profile": previous.INVOCATION_PROFILE}
        new = {"invocation_profile": previous.SATA_OFF_INVOCATION_PROFILE}
        self.assertEqual(cap.profile_pin(old), cap.PROFILE_SHA256)
        self.assertNotEqual(cap.profile_pin(old), cap.profile_pin(new))
        with self.assertRaises(previous.ProbeError):
            cap.decode_pinned_profile(cap.canonical(new))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            old_argv = cap.capability_argv(root, root / "fresh")
            new_argv = cap.capability_argv(root, root / "fresh", new["invocation_profile"])
            machine = old_argv.index("-machine") + 1
            old_argv[machine] = "pc-q35-8.2,accel=tcg,sata=off"
            self.assertEqual(old_argv, new_argv)

    def test_vapic_off_has_exact_distinct_pin_and_closed_argv(self):
        invocation = previous.VAPIC_OFF_INVOCATION_PROFILE
        self.assertEqual(cap.profile_pin({"invocation_profile": invocation}),
                         "ab82f30ae31a03761b39088a4dd96c138203ed7d631909a953bc5224f7403da3")
        for other in (previous.INVOCATION_PROFILE, previous.SATA_OFF_INVOCATION_PROFILE):
            self.assertNotEqual(cap.profile_pin({"invocation_profile": other}),
                                cap.profile_pin({"invocation_profile": invocation}))
        argv = cap.capability_argv(Path("/inputs"), Path("/private/run"), invocation)
        cap.validate_invocation_argv(argv, invocation)
        for changed in (argv[:3] + argv[5:], argv[:4] + ["apic.vapic=on"] + argv[5:]):
            with self.subTest(argv=changed), self.assertRaises(previous.ProbeError):
                cap.validate_invocation_argv(changed, invocation)
        for other in (previous.INVOCATION_PROFILE, previous.SATA_OFF_INVOCATION_PROFILE):
            with self.subTest(profile=other), self.assertRaises(previous.ProbeError):
                cap.validate_invocation_argv(argv, other)

    def test_vapic_off_layout_rejects_both_removed_devices(self):
        invocation = previous.VAPIC_OFF_INVOCATION_PROFILE
        self.assertEqual(cap.validate_profile_layout(LAYOUT, invocation),
                         cap.parse_flatview(LAYOUT))
        for name, reason in (("ich9-ahci", "sata_off_ahci_visible"),
                             ("kvmvapic", "vapic_off_device_visible")):
            layout = LAYOUT.replace("vga", name)
            with self.subTest(name=name), self.assertRaisesRegex(previous.ProbeError, reason):
                cap.validate_profile_layout(layout, invocation)
        # A clean new check must still succeed after a refusal.
        self.assertEqual(cap.validate_profile_layout(LAYOUT, invocation),
                         cap.parse_flatview(LAYOUT))

    def test_vapic_off_observation_denies_before_any_rsp_dispatch(self):
        invocation = previous.VAPIC_OFF_INVOCATION_PROFILE
        for device, reason in (("ich9-ahci", "sata_off_ahci_visible"),
                               ("kvmvapic", "vapic_off_device_visible")):
            qmp = SimpleNamespace(
                cpu=CPU["qom-path"],
                require_prelaunch=Mock(return_value={"status": "prelaunch"}),
                request=Mock(side_effect=[
                    [{"name": name} for name in cap.QMP_COMMANDS], [CPU], True, 40,
                    "CPU#0", LAYOUT.replace("vga", device),
                ]),
            )
            rsp, evidence = Mock(), Mock()
            with self.subTest(device=device), self.assertRaisesRegex(previous.ProbeError, reason):
                cap.observe(qmp, rsp, evidence, cap.empty_observations(), invocation)
            self.assertEqual(rsp.mock_calls, [])

    def test_cap01_unreviewed_plan_denies_before_child(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(subprocess, "Popen") as spawn:
            root = Path(tmp).resolve()
            plan = root / "plan.json"
            plan.write_text("{}")
            plan.chmod(0o600)
            with self.assertRaises(previous.ProbeError):
                cap.collect(plan, "0" * 64, root, root / "fresh")
            spawn.assert_not_called()
            self.assertFalse((root / "fresh").exists())

    def test_cap02_exact_previous_invocation_uses_private_sockets_and_pause(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            argv = cap.capability_argv(root, root / "fresh")
            self.assertEqual(argv, previous.build_argv(root, root / "fresh"))
            self.assertIn("-S", argv)
            self.assertEqual(argv[argv.index("-smp") + 1], "1")
            self.assertEqual(argv[argv.index("-gdb") + 1], "chardev:gdb0")
            self.assertIn("server=on,wait=off,id=gdb0", " ".join(argv))

    def test_cap03_exact_cpu_and_effective_width(self):
        self.assertEqual(cap.cpu_path([CPU]), CPU["qom-path"])
        self.assertEqual(cap.realized_width(True, 40), 40)
        for pair in ((False, 40), (True, 0), (True, True), (True, 53)):
            with self.subTest(pair=pair), self.assertRaises(previous.ProbeError):
                cap.realized_width(*pair)
        for cpus in ([CPU, CPU], [{**CPU, "cpu-index": False}], [{**CPU, "qom-path": "/objects/other"}]):
            with self.subTest(cpus=cpus), self.assertRaises(previous.ProbeError):
                cap.cpu_path(cpus)

    def test_cap04_qmp_denial_precedes_dispatch_and_success_uses_exact_id(self):
        wire = Wire([{"QMP": {}}, {"return": {}, "id": 1},
                     {"return": {"running": False, "status": "prelaunch"}, "id": 2}])
        qmp = cap.CapabilityQMP(wire, previous.Budget(time.monotonic() + 10))
        qmp.negotiate()
        for command, arguments in (
            ("cont", None), ("qom-get", {"path": CPU["qom-path"], "property": "phys-bits"}),
            ("human-monitor-command", {"command-line": "info mem"}),
        ):
            with self.assertRaises(previous.ProbeError):
                qmp.request(command, arguments)
        self.assertEqual(len(wire.writes), 1)
        qmp.require_prelaunch()
        self.assertEqual(json.loads(wire.writes[1]), {"execute": "query-status", "id": 2})
        self.assertEqual(qmp.operations[1]["result"], "ok")

    def test_cap04_register_binding_and_mode_witness(self):
        snapshot = """CPU#0
EAX=00000000 EBX=00000000 ECX=00000000 EDX=00060fb1
ESI=00000000 EDI=00000000 EBP=00000000 ESP=00000000
EIP=0000fff0 EFL=00000002 [-------] CPL=0 II=0 A20=1 SMM=0 HLT=0
ES =0000 00000000 0000ffff 00009300
CS =f000 ffff0000 0000ffff 00009b00
SS =0000 00000000 0000ffff 00009300
DS =0000 00000000 0000ffff 00009300
FS =0000 00000000 0000ffff 00009300
GS =0000 00000000 0000ffff 00009300
GDT=     00000000 0000ffff
IDT=     00000000 0000ffff
CR0=60000010 CR2=00000000 CR3=00000000 CR4=00000000
EFER=0000000000000000
"""
        names = ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip",
                 "eflags", "es", "cs", "ss", "ds", "fs", "gs", "fs_base", "gs_base",
                 "cr0", "cr2", "cr3", "cr4", "efer")
        values = (0, 0, 0, 0x60FB1, 0, 0, 0, 0, 0xFFF0, 2, 0, 0xF000, 0, 0, 0,
                  0, 0, 0, 0x60000010, 0, 0, 0, 0)
        description = SimpleNamespace(registers=tuple(SimpleNamespace(name=n) for n in names))
        regs = SimpleNamespace(values=values)
        cap.bind_registers(snapshot.replace("\n", "\r\n"), description, regs)
        for variant in (snapshot.replace("SMM=0", "SMM=1"),
                        snapshot.replace("0000fff0", "0000fff1"),
                        snapshot.replace("GDT=", "BAD=")):
            with self.assertRaises(previous.ProbeError):
                cap.bind_registers(variant, description, regs)

    def test_cap05_exact_flatview_rejects_alias_overlay_and_wrap(self):
        self.assertEqual(cap.parse_flatview(LAYOUT), ((0, 0xA0000), (0x100000, 0x20000000)))
        bad = (
            LAYOUT.replace(' AS "cpu-memory-0", root: system\n', ""),
            LAYOUT.replace("@0000000000100000", "@0000000000000000"),
            LAYOUT.replace("00000000000a0000-", "0000000000090000-"),
            LAYOUT.replace("000000001fffffff", "ffffffffffffffff"),
            LAYOUT.replace("(prio 0, ram)", "(prio 0, ramd)"),
            LAYOUT.replace(" Root memory region: system", " Root memory region: (none)"),
            LAYOUT + LAYOUT.replace("FlatView #0", "FlatView #2").replace(
                "FlatView #1", "FlatView #3"),
        )
        for layout in bad:
            with self.subTest(layout=layout), self.assertRaises(previous.ProbeError):
                cap.parse_flatview(layout)

    def test_cap06_real_child_late_tail_reap_and_eof(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            deadline = time.monotonic() + 10
            mux = cap.CapabilityWire(root, previous.Budget(deadline))
            child = subprocess.Popen(
                [sys.executable, "-c", "import os; os.write(1, b'late-tail')"],
                stdout=subprocess.PIPE, start_new_session=True,
            )
            try:
                mux.add("stdout", child.stdout)
                proof = previous.reap_owned(child, deadline, acknowledged_quit=True)
                mux.drain(deadline)
                self.assertTrue(proof["reaped"])
                self.assertEqual(proof["returncode"], 0)
                self.assertEqual(mux.eofs[0]["stream"], "stdout")
                self.assertEqual((root / "stdout.bin").read_bytes(), b"late-tail")
            finally:
                previous.reap_owned(child, deadline)
                mux.close()

    def test_cap06_stalled_child_reaped_after_term_and_kill(self):
        child = subprocess.Popen(
            [sys.executable, "-c",
             "import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); "
             "print('ready',flush=True); time.sleep(30)"],
            stdout=subprocess.PIPE, start_new_session=True,
        )
        try:
            self.assertTrue(select.select([child.stdout], [], [], 5)[0])
            self.assertEqual(child.stdout.readline(), b"ready\n")
            proof = previous.reap_owned(child, time.monotonic() + 3)
            self.assertTrue(proof["reaped"])
            self.assertEqual(proof["returncode"], -9)
            self.assertEqual(proof["actions"],
                             ["SIGTERM_owned_process_group", "SIGKILL_owned_process_group"])
        finally:
            previous.reap_owned(child, time.monotonic() + 3)
            child.stdout.close()

    def test_cap07_wire_cap_and_deadline_refuse_before_socket_write(self):
        sender, peer = socket.socketpair()
        with tempfile.TemporaryDirectory() as tmp, sender, peer:
            root = Path(tmp).resolve()
            deadline = time.monotonic() + 10
            mux = cap.CapabilityWire(root, previous.Budget(deadline, byte_limit=0))
            try:
                mux.add("rsp", sender)
                with self.assertRaises(previous.ProbeError):
                    mux.write_all(b"+", deadline)
                peer.setblocking(False)
                with self.assertRaises(BlockingIOError):
                    peer.recv(1)
                with self.assertRaisesRegex(previous.ProbeError, "rsp_request_timeout"):
                    mux.write_all(b"+", time.monotonic() - 1)
            finally:
                mux.close()

    def test_cap08_exact_false_claims_and_integer_type(self):
        observations = cap.empty_observations()
        cap.validate_observations(observations)
        for patch_value in (
            {"resumed": True}, {"guest_memory_read_bytes": False}, {"phys_bits": True},
            {"hardware_breakpoint_tested": True}, {"unknown": None},
        ):
            with self.assertRaises(previous.ProbeError):
                cap.validate_observations({**observations, **patch_value})

    def test_cap09_new_transport_after_bad_response_has_fresh_identity(self):
        bad = cap.CapabilityQMP(Wire([{"QMP": {}}, {"return": {}, "id": 4}]),
                                previous.Budget(time.monotonic() + 10))
        with self.assertRaises(previous.ProbeError):
            bad.negotiate()
        good = cap.CapabilityQMP(Wire([{"QMP": {}}, {"return": {}, "id": 1}]),
                                 previous.Budget(time.monotonic() + 10))
        good.negotiate()
        self.assertEqual(good.operations[0]["result"], "ok")

    def assert_owned_failure_report(self, fixture, report, reason):
        cap.validate_report(report)
        self.assertEqual(report, json.loads((fixture.run / "report.json").read_bytes()))
        end = report["termination"]
        self.assertEqual((end["status"], end["reason"]), ("INCOMPLETE", reason))
        self.assertTrue(end["reaped"])
        self.assertEqual(len(fixture.children), 1)
        child = fixture.children[0]
        self.assertEqual(end["returncode"], child.returncode)
        self.assertTrue(child.stdout.closed and child.stderr.closed)
        self.assertTrue(any(row.get("returncode") == child.returncode for row in fixture.waits))
        self.assertEqual(len(fixture.reap_deadlines), 1)
        self.assertTrue(all(value is False for value in report["claims"].values()))
        self.assertFalse(report["fresh_c0_verified"])

    def test_cap06_launcher_post_spawn_write_failure_reaps_unregistered_pipes(self):
        with control_root("post-spawn-write") as root:
            fixture = LauncherFixture(root, "ordinary")
            try:
                report = fixture.collect("owned-child.json")
                self.assert_owned_failure_report(fixture, report, "host_io_error")
                self.assertTrue((fixture.run / "owned-child.json").is_dir())
                self.assertFalse((fixture.run / "stdout.bin").exists())
                self.assertFalse((fixture.run / "stderr.bin").exists())
                self.assertTrue(all(not row["eof"] for row in report["termination"]["streams"]))
                self.assertIn("SIGTERM_owned_process_group", report["termination"]["actions"])
                failures = json.loads((fixture.run / "failures.json").read_bytes())
                self.assertEqual(failures[0], {"status": "INCOMPLETE", "reason": "host_io_error"})
            finally:
                fixture.close()

    def test_cap06_launcher_late_rsp_bytes_remain_incomplete_after_real_eof(self):
        with control_root("late-rsp") as root:
            fixture = LauncherFixture(root, "late-rsp")
            try:
                report = fixture.collect()
                self.assert_owned_failure_report(fixture, report, "rsp_trailing_unconsumed")
                self.assertEqual(report["termination"]["returncode"], 0)
                self.assertEqual(report["termination"]["actions"], [])
                self.assertTrue(all(row["eof"] and row["error"] is None
                                    for row in report["termination"]["streams"]))
                self.assertEqual((fixture.run / "rsp.bin").read_bytes(), b"$OK#9a")
                self.assertEqual((fixture.run / "stdout.bin").read_bytes(), b"owned-stdout-tail")
                self.assertEqual((fixture.run / "stderr.bin").read_bytes(), b"owned-stderr-tail")
                retained = next(row for row in report["raw_refs"] if row["path"] == "rsp.bin")
                self.assertEqual(retained["length"], 6)
                self.assertEqual(retained["sha256"], hashlib.sha256(b"$OK#9a").hexdigest())
            finally:
                fixture.close()

    def test_cap06_launcher_sigint_at_actual_wait_retains_owned_proof(self):
        with control_root("cancel-wait") as root:
            fixture = LauncherFixture(root, "cancel-wait")
            previous_handler = signal.getsignal(signal.SIGINT)
            try:
                report = fixture.collect()
                self.assert_owned_failure_report(fixture, report, "observer_cancelled")
                self.assertEqual(signal.getsignal(signal.SIGINT), previous_handler)
                self.assertEqual(len(fixture.signals), 1)
                self.assertEqual(report["termination"]["returncode"], 0)
                self.assertEqual(report["termination"]["actions"], [])
                self.assertTrue(all(row["eof"] for row in report["termination"]["streams"]))
                self.assertTrue(all("exception" not in row for row in fixture.waits))
                self.assertEqual(json.loads((fixture.run / "failures.json").read_bytes())[0],
                                 {"status": "INCOMPLETE", "reason": "observer_cancelled"})
            finally:
                fixture.close()

    def test_cap07_identity_copy_failure_has_distinct_prelaunch_receipt(self):
        with control_root("prelaunch-write") as root:
            fixture = LauncherFixture(root, "ordinary")
            try:
                with self.assertRaisesRegex(previous.ProbeError, "identity_retention_failed"):
                    fixture.collect("observer.json")
                self.assertEqual(fixture.children, [])
                self.assertFalse((fixture.run / "report.json").exists())
                self.assertTrue((fixture.run / "observer.json").is_dir())
                self.assertEqual(json.loads((fixture.run / "prelaunch-failure.json").read_bytes()), {
                    "schema_version": 1, "kind": "run0_reset_prelaunch_failure_v0",
                    "status": "INCOMPLETE", "reason": "identity_retention_failed",
                    "child_spawned": False,
                })
            finally:
                fixture.close()


if __name__ == "__main__":
    unittest.main()
