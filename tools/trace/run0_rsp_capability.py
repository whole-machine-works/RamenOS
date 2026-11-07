"""Observe the pinned QEMU debugger at reset with an owned paused VM."""

import argparse
from contextlib import ExitStack, contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import threading
import time

import boot_profile_capture as base
import boot_profile_inputs as entry


PROFILE_SHA256 = "3e5916da4e1ec79eda8d967f4bd2fc26909fb509479c086db4576baa506a910e"
SATA_OFF_PROFILE_SHA256 = "b3c4bd6caa30641a0f1859f4fbc88cad64254f602c7190108cb223ff0c32feef"
VAPIC_OFF_PROFILE_SHA256 = "ab82f30ae31a03761b39088a4dd96c138203ed7d631909a953bc5224f7403da3"
QEMU_SHA256 = "8a35ccba41582fc6c38b9df85fc9e35fa1d42f414d2d7d8090ee9b2f5e7c0854"
SOURCE_DOSSIER_SHA256 = "f2dbb099816cc1dfad09f2ea2a938c4127a63e7985f8c363070ecab590973db9"
CAPTURE_LIMIT = 32 * 1024 * 1024
REPORT_LIMIT = 1024 * 1024
FAILURE_LIMIT = 8192
MAX_RSP_WIRE = 256 * 1024
MAX_OPERATION_BYTES = 65536
STREAMS = ("qmp", "rsp", "serial", "debug", "stdout", "stderr")
HMP = ("info registers", "info mtree -f")
QMP_PLAIN = ("qmp_capabilities", "query-commands", "query-status",
             "query-cpus-fast", "quit")
QMP_COMMANDS = (*QMP_PLAIN, "qom-get", "human-monitor-command")
OPERATION_NAMES = {
    "qmp": frozenset((*[name.replace("-", "_") for name in QMP_PLAIN],
                      "hmp_registers", "hmp_flatview", "qom_realized", "qom_phys_bits")),
    "rsp": frozenset(("supported", "thread_first", "thread_next", "thread_current",
                      "thread_general", "thread_continue", "feature_target", "feature_core",
                      "reset_registers", "qemu_supported", "physical_mode_query",
                      "physical_mode_enable")),
}
FALSE_CLAIMS = {name: False for name in (*entry.CLAIM_NAMES,
                                        "capture_complete", "profile_preconditions_met")}
OBS_REFS = ("qmp_cpu_ref", "target_xml_ref", "core_xml_ref",
            "reset_registers_ref", "hmp_registers_ref", "layout_ref",
            "initial_status_ref", "final_status_ref")
MAX_ADDRESS = (1 << 64) - 1

deny = base.deny
incomplete = base.incomplete


def exact_int(value, low, high):
    return type(value) is int and low <= value <= high


def capability_argv(inputs, run, invocation_profile=base.INVOCATION_PROFILE):
    return base.build_argv(inputs, run, invocation_profile)


def profile_pin(profile):
    deny(type(profile) is dict, "profile_identity")
    invocation = profile.get("invocation_profile")
    if invocation == base.INVOCATION_PROFILE:
        return PROFILE_SHA256
    if invocation == base.SATA_OFF_INVOCATION_PROFILE:
        return SATA_OFF_PROFILE_SHA256
    deny(invocation == base.VAPIC_OFF_INVOCATION_PROFILE, "invocation_profile")
    return VAPIC_OFF_PROFILE_SHA256


def decode_pinned_profile(raw):
    digest = hashlib.sha256(raw).hexdigest()
    deny(digest in (PROFILE_SHA256, SATA_OFF_PROFILE_SHA256, VAPIC_OFF_PROFILE_SHA256),
         "pinned_file_digest")
    profile = entry.decode_packet(raw)
    deny(digest == profile_pin(profile), "profile_identity")
    return profile


def validate_invocation_argv(argv, invocation_profile):
    """Bind a retained argv to the exact builder and profile without filesystem reads."""
    deny(type(argv) is list and all(type(arg) is str for arg in argv)
         and argv and "-qmp" in argv[:-1], "retained_argv")
    qmp = argv[argv.index("-qmp") + 1]
    suffix = "/qmp.sock,server=on,wait=off"
    deny(qmp.startswith("unix:") and qmp.endswith(suffix), "retained_argv")
    run = Path(qmp[len("unix:"):-len(suffix)])
    deny(argv == capability_argv(Path(argv[0]).parent, run, invocation_profile),
         "retained_argv")


def cpu_path(cpus):
    incomplete(type(cpus) is list and len(cpus) == 1, "sole_cpu_unavailable")
    row = cpus[0]
    deny(type(row) is dict and set(row) ==
         {"cpu-index", "qom-path", "target", "thread-id", "props"}, "cpu_reply_shape")
    deny(exact_int(row["cpu-index"], 0, 0) and row["target"] == "x86_64" and
         exact_int(row["thread-id"], 1, (1 << 63) - 1) and
         type(row["props"]) is dict, "cpu_reply_identity")
    path = row["qom-path"]
    deny(type(path) is str and len(path) <= 256 and re.fullmatch(
        r"/machine(?:/[A-Za-z0-9_.\[\]-]+)+", path) is not None and
        all(part not in (".", "..") for part in path.split("/")), "cpu_path")
    return path


def realized_width(realized, width):
    deny(type(realized) is bool and type(width) is int, "cpu_property_type")
    incomplete(realized and 32 <= width <= 52, "realized_width_unavailable")
    return width


class CapabilityQMP:
    """The only QMP command dispatcher in the reset probe."""

    def __init__(self, wire, budget):
        self.wire = wire
        self.budget = budget
        self.negotiated = False
        self.greeted = False
        self.terminal = False
        self.cpu = None
        self.operations = []
        self.events = []

    def receive(self, deadline, *, teardown=False):
        self.budget.message(teardown=teardown)
        frame = self.wire.next(deadline)
        return frame, base.decode_frame(frame)

    def negotiate(self):
        deny(not self.greeted and not self.terminal, "qmp_duplicate_greeting")
        deadline = time.monotonic() + min(base.RESPONSE_SECONDS,
                                         self.budget.remaining(base.TEARDOWN_SECONDS))
        _, greeting = self.receive(deadline)
        deny(set(greeting) == {"QMP"} and type(greeting["QMP"]) is dict, "qmp_greeting")
        self.greeted = True
        self.request("qmp_capabilities")
        self.negotiated = True

    def event(self, value):
        deny(set(value) <= {"event", "timestamp", "data"} and
             type(value.get("event")) is str and type(value.get("timestamp")) is dict,
             "qmp_event_shape")
        self.events.append(value)
        incomplete(value["event"] not in ("RESET", "RESUME", "STOP"), "unexpected_guest_event")

    def request(self, command, arguments=None):
        arguments = {} if arguments is None else arguments
        allowed = command in QMP_PLAIN and arguments == {}
        if command == "qom-get":
            allowed = self.cpu is not None and arguments in (
                {"path": self.cpu, "property": "realized"},
                {"path": self.cpu, "property": "phys-bits"},
            )
        if command == "human-monitor-command":
            allowed = arguments in tuple({"command-line": text} for text in HMP)
        deny(allowed, "qmp_command_denied")
        deny(not self.terminal and self.greeted and
             (self.negotiated != (command == "qmp_capabilities")), "qmp_session_state")
        teardown = command == "quit"
        self.budget.message(teardown=teardown)
        deadline = time.monotonic() + min(base.RESPONSE_SECONDS,
                                         self.budget.remaining(
                                             1.5 if teardown else base.TEARDOWN_SECONDS))
        identifier = len(self.operations) + 1
        request = {"execute": command, "id": identifier}
        if arguments:
            request["arguments"] = arguments
        wire_bytes = json.dumps(request, separators=(",", ":")).encode()
        wire_bytes += b"" if command == "quit" else b"\r\n"
        name = command.replace("-", "_")
        if command == "human-monitor-command":
            name = "hmp_registers" if arguments["command-line"] == HMP[0] else "hmp_flatview"
        if command == "qom-get":
            name = "qom_realized" if arguments["property"] == "realized" else "qom_phys_bits"
        row = {"operation": name, "request": wire_bytes, "response": None,
               "started_ns": time.monotonic_ns(), "finished_ns": None, "result": "pending"}
        self.operations.append(row)
        try:
            self.wire.send(wire_bytes, deadline)
            while True:
                raw, response = self.receive(deadline, teardown=teardown)
                if "event" in response:
                    self.event(response)
                    continue
                row["response"] = raw
                deny(set(response) in ({"return", "id"}, {"error", "id"}) and
                     exact_int(response.get("id"), identifier, identifier), "qmp_response_identity")
                incomplete("error" not in response, "qmp_command_error")
                value = response["return"]
                if command == "query-cpus-fast":
                    self.cpu = cpu_path(value)
                row["result"] = "ok"
                return value
        except (base.ProbeError, OSError) as exc:
            self.terminal = True
            row["result"] = "timeout" if "timeout" in getattr(exc, "reason", "") else "error"
            raise
        finally:
            row["finished_ns"] = time.monotonic_ns()

    def require_prelaunch(self):
        state = self.request("query-status")
        incomplete(type(state) is dict and state.get("running") is False and
                   state.get("status") == "prelaunch", "prelaunch_unavailable")
        return state


class CapabilityWire(base.Pump):
    """One multiplexed owner for the QMP, RSP and output streams."""

    def __init__(self, run, budget):
        super().__init__(run, budget)
        self.rsp_pending = bytearray()
        self.rsp_bytes = 0

    def log(self, name, data):
        if name in ("rsp", "rsp-requests"):
            incomplete(len(data) <= MAX_RSP_WIRE - self.rsp_bytes, "rsp_wire_limit")
            self.rsp_bytes += len(data)
        super().log(name, data)
        if name == "rsp":
            self.rsp_pending.extend(data)

    def read_chunk(self, deadline, max_bytes):
        deny(exact_int(max_bytes, 1, 8192), "rsp_chunk_limit")
        while True:
            incomplete(time.monotonic() < deadline, "rsp_response_timeout")
            if self.rsp_pending:
                data = bytes(self.rsp_pending[:max_bytes])
                del self.rsp_pending[:max_bytes]
                return data
            incomplete(all(row["stream"] != "rsp" for row in self.io_errors), "rsp_io_error")
            incomplete(all(row["stream"] != "rsp" for row in self.eofs), "rsp_eof")
            self.step(deadline)

    def write_all(self, data, deadline):
        self._write("rsp", data, deadline)

    def send(self, data, deadline):
        self._write("qmp", data, deadline)

    def _write(self, name, data, deadline):
        remaining = memoryview(data)
        while remaining:
            incomplete(time.monotonic() < deadline, name + "_request_timeout")
            incomplete(len(remaining) <= self.budget.byte_limit - self.budget.retained_bytes,
                       "storage_limit")
            if name == "rsp":
                incomplete(len(remaining) <= MAX_RSP_WIRE - self.rsp_bytes, "rsp_wire_limit")
            try:
                count = self.sources[name].send(remaining)
            except (BlockingIOError, InterruptedError):
                self.step(deadline)
                continue
            except OSError as exc:
                self.io_errors.append({"stream": name, "operation": "write", "errno": exc.errno})
                raise
            incomplete(count > 0, name + "_send_eof")
            self.log(name + "-requests", bytes(remaining[:count]))
            remaining = remaining[count:]

    def close(self):
        errors = []
        entries = [(None, self.selector), *self.sources.items(), *self.logs.items()]
        for name, stream in entries:
            try:
                stream.close()
            except OSError as exc:
                row = {"stream": name.removesuffix("-requests") if name else None,
                       "operation": "close", "errno": exc.errno}
                errors.append(row)
                self.io_errors.append(row)
        return errors

    def finish(self, deadline, qmp):
        late = self.drain(deadline)
        if qmp is not None:
            for row in late:
                qmp.event(row["raw_qmp"])
        incomplete(not self.rsp_pending, "rsp_trailing_unconsumed")


_VIEW = re.compile(r"FlatView #(\d+)")
_AS = re.compile(r' AS "([^"]+)", root: (.+)')
_ROOT = re.compile(r" Root memory region: (.+)")
_RANGE = re.compile(
    r"  ([0-9a-f]{16})-([0-9a-f]{16}) \(prio (-?\d+), (ram|ramd|nv-ram|rom|romd|i/o)\): "
    r"([^@\r\n]+?)(?: @([0-9a-f]{16}))?"
)


def parse_flatview(text):
    deny(type(text) is str and len(text) <= MAX_OPERATION_BYTES and text.isascii(),
         "flatview_reply_shape")
    views = []
    address_spaces = {}
    view = None
    for line in text.splitlines():
        if not line:
            continue
        match = _VIEW.fullmatch(line)
        if match:
            deny(match[1] == str(len(views)), "flatview_number")
            view = {"root": None, "rows": [], "empty": False}
            views.append(view)
            continue
        deny(view is not None, "flatview_missing_header")
        match = _AS.fullmatch(line)
        if match:
            deny(view["root"] is None and match[1] not in address_spaces, "flatview_duplicate_as")
            address_spaces[match[1]] = (view, match[2])
            continue
        match = _ROOT.fullmatch(line)
        if match:
            deny(view["root"] is None, "flatview_duplicate_root")
            view["root"] = match[1]
            continue
        if line == "  No rendered FlatView":
            deny(view["root"] == "(none)" and not view["rows"] and not view["empty"],
                 "flatview_unexpected_empty")
            view["empty"] = True
            continue
        match = _RANGE.fullmatch(line)
        deny(match is not None and view["root"] not in (None, "(none)") and
             not view["empty"], "flatview_unknown_row")
        lo, hi = int(match[1], 16), int(match[2], 16)
        deny(lo <= hi < MAX_ADDRESS, "flatview_extent")
        deny(not view["rows"] or view["rows"][-1][1] <= lo, "flatview_overlap")
        view["rows"].append((lo, hi + 1, match[4], match[5], int(match[6] or "0", 16),
                             match[3]))
    deny(all(v["root"] is not None and (v["root"] == "(none)") == v["empty"]
             for v in views), "flatview_missing_root")
    incomplete("memory" in address_spaces and "cpu-memory-0" in address_spaces,
               "flatview_memory_unavailable")
    memory, root = address_spaces["memory"]
    cpu, cpu_root = address_spaces["cpu-memory-0"]
    deny(memory is cpu and root == cpu_root == memory["root"] == "system",
         "flatview_memory_identity")
    ordinary = []
    for lo, hi, kind, name, offset, priority in memory["rows"]:
        if name == "pc.ram":
            # Q35's observed first PAM ROM shadow resolves to the pc.ram leaf.
            # Recognize only this exact readonly tuple, never as grantable RAM.
            if (lo, hi, kind, offset, priority) == (0xC0000, 0xC4000, "rom", 0xC0000, "0"):
                continue
            deny(kind == "ram" and lo == offset, "flatview_ram_alias")
            ordinary.append((lo, hi))
    incomplete(bool(ordinary), "flatview_ram_unavailable")
    return tuple(ordinary)


def empty_observations():
    return {**dict.fromkeys(OBS_REFS), "realized": None, "phys_bits": None,
            "rsp_thread": None, "physical_mode": None, "resumed": False,
            "guest_memory_read_bytes": 0, "hardware_breakpoint_tested": False}


def validate_observations(value):
    deny(type(value) is dict and set(value) == set(empty_observations()), "observation_shape")
    deny(value["resumed"] is False and value["hardware_breakpoint_tested"] is False and
         exact_int(value["guest_memory_read_bytes"], 0, 0), "observation_scope")
    deny(value["realized"] is None or type(value["realized"]) is bool, "observation_realized")
    deny(value["phys_bits"] is None or exact_int(value["phys_bits"], 32, 52), "observation_width")
    deny(value["rsp_thread"] is None or value["rsp_thread"] == "01", "observation_thread")
    deny(value["physical_mode"] is None or exact_int(value["physical_mode"], 0, 1),
         "observation_physical_mode")
    for key in OBS_REFS:
        if value[key] is not None:
            validate_ref(value[key])


def validate_ref(ref):
    deny(type(ref) is dict and set(ref) == {"path", "sha256", "length"}, "blob_ref_shape")
    deny(type(ref["path"]) is str and re.fullmatch(r"[A-Za-z0-9_.-]{1,240}", ref["path"]) and
         ref["path"] not in (".", "..") and type(ref["sha256"]) is str and
         re.fullmatch(r"[0-9a-f]{64}", ref["sha256"]) and
         exact_int(ref["length"], 0, CAPTURE_LIMIT), "blob_ref_value")


def bind_registers(text, description, registers):
    deny(type(text) is str and text.isascii() and len(text) <= MAX_OPERATION_BYTES,
         "hmp_register_shape")
    lines = text.splitlines()
    deny([line for line in lines if line.startswith("CPU#")] == ["CPU#0"], "hmp_cpu_identity")
    values = {reg.name: value for reg, value in zip(
        description.registers, registers.values, strict=True)}
    # The pinned reset profile uses the monitor's 32-bit display for these
    # registers. GDB still emits its fixed x86-64 register widths.
    fields = {f"E{name}": f"r{name.lower()}" for name in
              ("AX", "BX", "CX", "DX", "SI", "DI", "BP", "SP")}
    fields.update({"EIP": "rip", "EFL": "eflags", "CR0": "cr0", "CR2": "cr2",
                   "CR3": "cr3", "CR4": "cr4", "EFER": "efer"})
    for hmp_name, rsp_name in fields.items():
        samples = re.findall(rf"(?<![A-Za-z0-9_]){hmp_name}=([0-9a-f]{{8,16}})(?=\s|$)",
                             text)
        deny(len(samples) == 1 and int(samples[0], 16) == values[rsp_name],
             "hmp_rsp_register_mismatch")
    for name in ("CS", "SS", "DS", "ES", "FS", "GS"):
        samples = [match.groups() for line in lines if (match := re.fullmatch(
            rf"{name} =([0-9a-f]{{4}}) ([0-9a-f]{{8,16}}) "
            r"[0-9a-f]{8} ([0-9a-f]{8})(?: .*|)", line))]
        deny(len(samples) == 1 and int(samples[0][0], 16) == values[name.lower()],
             "hmp_rsp_segment_mismatch")
        if name in ("FS", "GS"):
            deny(int(samples[0][1], 16) == values[name.lower() + "_base"],
                 "hmp_rsp_segment_base_mismatch")
        if name == "CS":
            incomplete(int(samples[0][2], 16) & (1 << 21) == 0, "reset_cs64")
    for flag, expected in (("CPL", "0"), ("SMM", "0"), ("A20", "1")):
        incomplete(re.findall(rf"\b{flag}=([0-9]+)(?=\s|$)", text) == [expected],
                   "reset_cpu_flags")
    for table in ("GDT", "IDT"):
        deny(sum(re.fullmatch(rf"{table}= +[0-9a-f]{{8,16}} [0-9a-f]{{8}}", line)
                 is not None for line in lines) == 1, "hmp_descriptor_table")


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
            + "\n").encode()


def read_exact(path, digest, limit):
    base.private_regular(path)
    incomplete(path.stat().st_size <= limit, "pinned_file_size")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    incomplete(len(data) <= limit, "pinned_file_size")
    deny(hashlib.sha256(data).hexdigest() == digest, "pinned_file_digest")
    return data


def observer_manifest():
    directory = Path(__file__).resolve().parent
    files = ("run0_rsp_capability.py", "run0_rsp.py", "boot_profile_capture.py",
             "boot_profile_inputs.py")
    return {"python": base.file_ref(Path(sys.executable).resolve()),
            "sources": [base.file_ref(directory / name) for name in files]}


def prepare_plan(inputs, run, dossier):
    base.safe_path(inputs)
    base.safe_path(run)
    deny(re.fullmatch(r"[a-z0-9-]{1,64}", run.name) is not None, "run_id")
    deny(run.parent.resolve() == run.parent and not os.path.lexists(run),
         "run_parent_or_freshness")
    path = inputs / "profile.json"
    base.private_regular(path)
    with path.open("rb") as stream:
        profile_bytes = stream.read(MAX_OPERATION_BYTES + 1)
    incomplete(len(profile_bytes) <= MAX_OPERATION_BYTES, "pinned_file_size")
    profile = decode_pinned_profile(profile_bytes)
    base.validate_profile(profile, inputs)
    deny(profile["inputs"]["qemu"]["sha256"] == QEMU_SHA256, "qemu_package_pin")
    dossier_bytes = read_exact(dossier, SOURCE_DOSSIER_SHA256, MAX_OPERATION_BYTES)
    esp = base.check_esp(inputs, profile)
    argv = capability_argv(inputs, run, profile["invocation_profile"])
    plan = {"schema_version": 1, "kind": "run0_reset_capability_plan_v0",
            "inputs": str(inputs), "run": str(run), "argv": argv, "esp_validation": esp,
            "profile_sha256": profile_pin(profile), "source_dossier_sha256": SOURCE_DOSSIER_SHA256,
            "observer": observer_manifest()}
    return plan, profile, profile_bytes, dossier_bytes


def write_private(path, data):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
        stream.write(data)


class Evidence:
    def __init__(self, run, budget):
        self.run = run
        self.budget = budget

    def put(self, name, data):
        self.budget.retain(len(data))
        write_private(self.run / name, data)
        return {"path": name, "sha256": hashlib.sha256(data).hexdigest(), "length": len(data)}


def collect(plan_path, digest, inputs, run, dossier=None):
    plan_bytes = read_exact(plan_path, digest, MAX_OPERATION_BYTES)
    incomplete(dossier is not None, "source_dossier_missing")
    plan, profile, profile_bytes, dossier_bytes = prepare_plan(inputs, run, dossier)
    deny(plan_bytes == canonical(plan), "plan_changed")
    return run_capability(plan, profile, profile_bytes, dossier_bytes, inputs, run)


def validate_profile_layout(layout, invocation_profile):
    """Validate the current FlatView and the selected profile's device exclusions."""
    base.admission_machine(invocation_profile)
    deny(type(layout) is str, "flatview_reply_shape")
    ranges = parse_flatview(layout)
    if invocation_profile in (base.SATA_OFF_INVOCATION_PROFILE, base.VAPIC_OFF_INVOCATION_PROFILE):
        deny("ahci" not in layout.casefold(), "sata_off_ahci_visible")
    if invocation_profile == base.VAPIC_OFF_INVOCATION_PROFILE:
        deny("kvmvapic" not in layout.casefold(), "vapic_off_device_visible")
    return ranges


def observe(qmp, rsp, evidence, observation, invocation_profile=base.INVOCATION_PROFILE):
    commands = qmp.request("query-commands")
    incomplete(type(commands) is list and all(type(row) is dict and
               set(row) == {"name"} and type(row["name"]) is str for row in commands),
               "qmp_commands_shape")
    incomplete(set(QMP_COMMANDS) <= {row["name"] for row in commands}, "qmp_capability_missing")
    observation["initial_status_ref"] = evidence.put("initial-status.json",
                                                     canonical(qmp.require_prelaunch()))
    cpus = qmp.request("query-cpus-fast")
    observation["qmp_cpu_ref"] = evidence.put("cpu.json", canonical(cpus))
    realized = qmp.request("qom-get", {"path": qmp.cpu, "property": "realized"})
    if type(realized) is bool:
        observation["realized"] = realized
    width = qmp.request("qom-get", {"path": qmp.cpu, "property": "phys-bits"})
    observation["phys_bits"] = realized_width(realized, width)
    hmp_regs = qmp.request("human-monitor-command", {"command-line": HMP[0]})
    deny(type(hmp_regs) is str, "hmp_register_shape")
    observation["hmp_registers_ref"] = evidence.put("hmp-registers.txt", hmp_regs.encode())
    layout = qmp.request("human-monitor-command", {"command-line": HMP[1]})
    deny(type(layout) is str, "flatview_reply_shape")
    observation["layout_ref"] = evidence.put("flatview.txt", layout.encode())
    validate_profile_layout(layout, invocation_profile)
    rsp.query_supported()
    rsp.query_threads()
    rsp.select_thread()
    observation["rsp_thread"] = "01"
    description = rsp.read_target_description()
    observation["target_xml_ref"] = evidence.put("target.xml", description.target_xml)
    observation["core_xml_ref"] = evidence.put("i386-64bit.xml", description.core_xml)
    registers = rsp.read_reset_registers()
    observation["reset_registers_ref"] = evidence.put("reset-registers.bin", registers.raw_bytes)
    bind_registers(hmp_regs, description, registers)
    rsp.query_qemu_supported()
    observation["physical_mode"] = rsp.query_physical_mode()
    deny(observation["physical_mode"] == 0, "unexpected_initial_physical_mode")
    rsp.enable_physical_mode()
    observation["physical_mode"] = rsp.query_physical_mode()
    incomplete(observation["physical_mode"] == 1, "physical_mode_readback")
    observation["final_status_ref"] = evidence.put("final-status.json",
                                                   canonical(qmp.require_prelaunch()))


def operation_rows(qmp, rsp):
    rows = []
    if qmp is not None:
        rows.extend({**row, "protocol": "qmp"} for row in qmp.operations)
    if rsp is not None:
        rows.extend({"protocol": "rsp", "operation": row.name, "request": row.request_packet,
                     "response": row.response_packet, "started_ns": row.started_ns,
                     "finished_ns": row.finished_ns, "result": row.result}
                    for row in rsp.operations)
    return sorted(rows, key=lambda row: row["started_ns"])


def retained_operation(row, index, evidence):
    request = evidence.put(f"op-{index}-request.bin", row["request"])
    response = row["response"]
    if response is not None:
        response = evidence.put(f"op-{index}-response.bin", response)
    return {key: row[key] for key in
            ("protocol", "operation", "started_ns", "finished_ns", "result")} | {
                "seq": index, "request_ref": request, "response_ref": response}


def stream_results(wire):
    rows = []
    for name in STREAMS:
        errors = [row for row in wire.io_errors if row["stream"] == name]
        rows.append({"name": name, "eof": any(row["stream"] == name for row in wire.eofs),
                     "error": {k: errors[0][k] for k in ("operation", "errno")} if errors else None})
    return rows


@contextmanager
def defer_cleanup_interrupt():
    requested = [False]

    def note_interrupt(_signum, _frame):
        requested[0] = True

    previous = signal.signal(signal.SIGINT, note_interrupt)
    try:
        yield requested
    finally:
        signal.signal(signal.SIGINT, previous)


def run_capability(plan, profile, profile_bytes, dossier_bytes, inputs, run):
    deny(threading.current_thread() is threading.main_thread(), "main_thread_owner_required")
    with ExitStack() as cleanup:
        return _run_capability(plan, profile, profile_bytes, dossier_bytes, inputs, run, cleanup)


def _run_capability(plan, profile, profile_bytes, dossier_bytes, inputs, run, cleanup):
    from run0_rsp import RSPClient

    base.create_run(run)
    deadline = time.monotonic() + base.VM_SECONDS
    budget = base.Budget(deadline, byte_limit=CAPTURE_LIMIT - REPORT_LIMIT - FAILURE_LIMIT)
    evidence = Evidence(run, budget)
    try:
        report = {
            "schema_version": 1, "kind": "run0_reset_capability_v0", "run_id": run.name,
            "profile_ref": evidence.put("profile.json", profile_bytes),
            "observer_ref": evidence.put("observer.json", canonical(plan["observer"])),
            "source_dossier_ref": evidence.put("source-dossier.json", dossier_bytes),
            "argv_ref": evidence.put("argv.json", canonical(plan["argv"])),
            "raw_refs": [], "observations": empty_observations(), "operations": [],
            "claims": dict(FALSE_CLAIMS), "fresh_c0_verified": False,
        }
        wire = CapabilityWire(run, budget)
    except (base.ProbeError, OSError, KeyboardInterrupt):
        # No capture report can bind identity files that failed to materialize.
        # This receipt records the earlier failure without inventing those refs.
        try:
            write_private(run / "prelaunch-failure.json", canonical({
                "schema_version": 1, "kind": "run0_reset_prelaunch_failure_v0",
                "status": "INCOMPLETE", "reason": "identity_retention_failed",
                "child_spawned": False,
            }))
        except OSError:
            pass
        raise base.ProbeError("INCOMPLETE", "identity_retention_failed")
    termination = {"status": "INCOMPLETE", "reason": "observation_not_finished",
                   "reaped": False, "returncode": None, "actions": [],
                   "grace": "not_attempted", "streams": []}
    report["termination"] = termination
    child = qmp = rsp = None
    quit_ack = False
    failures = []

    def failure(exc):
        if isinstance(exc, base.ProbeError):
            reason = exc.reason
            if type(reason) is not str or not re.fullmatch(r"[a-z0-9_]{1,96}", reason):
                reason = "observer_failure"
            issue = {"status": exc.status, "reason": reason}
        elif isinstance(exc, KeyboardInterrupt):
            issue = {"status": "INCOMPLETE", "reason": "observer_cancelled"}
        else:
            issue = {"status": "INCOMPLETE", "reason": "host_io_error"}
        if not failures or issue["status"] == "DENY" and termination["status"] != "DENY":
            termination.update(issue)
        failures.append(issue)

    try:
        budget.retain(profile["inputs"]["initial_vars"]["length"])
        shutil.copyfile(inputs / "initial_vars", run / "vars.fd")
        os.chmod(run / "vars.fd", 0o600)
        initial = base.file_ref(run / "vars.fd", profile["inputs"]["initial_vars"]["length"])
        deny(initial["sha256"] == profile["inputs"]["initial_vars"]["sha256"],
             "vars_clone_mismatch")
        report["raw_refs"].append(evidence.put("vars-initial.json", canonical(initial)))
        with defer_cleanup_interrupt() as spawn_interrupted:
            child = subprocess.Popen(
                plan["argv"], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
                umask=0o077, env={"PATH": "/usr/bin:/bin", "LANG": "C", "HOME": str(run)},
            )
        report["raw_refs"].append(evidence.put("owned-child.json", canonical({"pid": child.pid})))
        if spawn_interrupted[0]:
            raise KeyboardInterrupt
        wire.add("stdout", child.stdout)
        wire.add("stderr", child.stderr)
        for name, socket_name in (("qmp", "qmp"), ("rsp", "gdb"),
                                  ("serial", "serial"), ("debug", "debug")):
            connect_deadline = min(time.monotonic() + base.RESPONSE_SECONDS,
                                   deadline - base.TEARDOWN_SECONDS)
            wire.add(name, base.connect(run / (socket_name + ".sock"), child, connect_deadline))
        qmp = CapabilityQMP(wire, budget)
        qmp.negotiate()
        rsp = RSPClient(wire, budget)
        observe(qmp, rsp, evidence, report["observations"],
                profile.get("invocation_profile", base.INVOCATION_PROFILE))
        termination.update(status="PASS", reason="reset_capability_observed")
    except (base.ProbeError, OSError, KeyboardInterrupt) as exc:
        failure(exc)
    finally:
        interrupted = cleanup.enter_context(defer_cleanup_interrupt())
        if child is not None:
            try:
                if qmp is not None and qmp.negotiated and not qmp.terminal and child.poll() is None:
                    quit_ack = qmp.request("quit") == {}
                incomplete(quit_ack, "quit_unacknowledged")
            except (base.ProbeError, OSError, KeyboardInterrupt) as exc:
                failure(exc)
            finally:
                try:
                    proof = base.reap_owned(child, deadline, acknowledged_quit=quit_ack)
                    termination.update(reaped=proof["reaped"], returncode=proof["returncode"],
                                       actions=proof["actions"])
                    grace = proof.get("quit_grace", {}).get("outcome")
                    if grace:
                        termination["grace"] = {
                            "already_exited": "exited", "deadline_exhausted": "timeout",
                            "exited": "exited", "timeout": "timeout",
                        }[grace]
                except OSError as exc:
                    termination["grace"] = "error"
                    failure(exc)
        if interrupted[0]:
            failure(KeyboardInterrupt())
            interrupted[0] = False
        try:
            wire.finish(deadline, qmp)
        except (base.ProbeError, OSError) as exc:
            failure(exc)
        if wire.close():
            failure(base.ProbeError("INCOMPLETE", "stream_close_error"))
        if child is not None:
            for name, pipe in (("stdout", child.stdout), ("stderr", child.stderr)):
                if pipe is not None and not pipe.closed:
                    try:
                        pipe.close()
                    except OSError as exc:
                        wire.io_errors.append({"stream": name, "operation": "close",
                                               "errno": exc.errno})
                        failure(exc)
        termination["streams"] = stream_results(wire)
    try:
        base.validate_profile(profile, inputs)
        deny(read_exact(inputs / "profile.json", plan["profile_sha256"], MAX_OPERATION_BYTES)
             == profile_bytes and observer_manifest() == plan["observer"], "pins_changed")
    except (base.ProbeError, OSError) as exc:
        failure(exc)
    try:
        report["raw_refs"].extend(base.file_ref(path, CAPTURE_LIMIT)
                                  for path in sorted(run.glob("*.bin"))
                                  if not path.name.startswith("op-"))
        if (run / "vars.fd").is_file():
            report["raw_refs"].append(base.file_ref(
                run / "vars.fd", profile["inputs"]["initial_vars"]["length"]))
        for index, row in enumerate(operation_rows(qmp, rsp), 1):
            report["operations"].append(retained_operation(row, index, evidence))
        if qmp is not None:
            report["raw_refs"].append(evidence.put("qmp-events.json", canonical(qmp.events)))
        if termination["status"] == "PASS":
            incomplete(termination["reaped"] and termination["returncode"] == 0 and
                       not termination["actions"] and time.monotonic() <= deadline and
                       all(row["eof"] and row["error"] is None for row in termination["streams"]),
                       "owned_teardown_incomplete")
    except (base.ProbeError, OSError) as exc:
        failure(exc)
    if interrupted[0]:
        failure(KeyboardInterrupt())
    if failures:
        try:
            data = canonical(failures)
            incomplete(len(data) <= FAILURE_LIMIT, "failure_record_limit")
            write_private(run / "failures.json", data)
            report["raw_refs"].append(base.file_ref(run / "failures.json", FAILURE_LIMIT))
        except (base.ProbeError, OSError):
            # The reserved report still preserves the primary failure and wait.
            pass
    return persist_report(report, run)


def validate_report(report):
    fields = {"schema_version", "kind", "run_id", "profile_ref", "observer_ref",
              "source_dossier_ref", "argv_ref", "raw_refs", "observations", "operations",
              "termination", "claims", "fresh_c0_verified"}
    deny(type(report) is dict and set(report) == fields and
         exact_int(report["schema_version"], 1, 1) and
         report["kind"] == "run0_reset_capability_v0" and
         type(report["run_id"]) is str and re.fullmatch(r"[a-z0-9-]{1,64}", report["run_id"]),
         "capability_report_shape")
    deny(type(report["claims"]) is dict and set(report["claims"]) == set(FALSE_CLAIMS) and
         all(value is False for value in report["claims"].values()) and
         report["fresh_c0_verified"] is False, "capability_report_claims")
    for key in ("profile_ref", "observer_ref", "source_dossier_ref", "argv_ref"):
        validate_ref(report[key])
    deny(type(report["raw_refs"]) is list and len(report["raw_refs"]) <= 16, "raw_ref_count")
    for ref in report["raw_refs"]:
        validate_ref(ref)
    validate_observations(report["observations"])
    deny(type(report["operations"]) is list and len(report["operations"]) <= base.MAX_MESSAGES,
         "operation_count")
    for index, row in enumerate(report["operations"], 1):
        deny(type(row) is dict and set(row) ==
             {"seq", "protocol", "operation", "request_ref", "response_ref", "started_ns",
              "finished_ns", "result"}, "operation_shape")
        deny(exact_int(row["seq"], index, index) and type(row["protocol"]) is str and
             row["protocol"] in OPERATION_NAMES and type(row["operation"]) is str and
             row["operation"] in OPERATION_NAMES[row["protocol"]] and
             exact_int(row["started_ns"], 0, (1 << 63) - 1) and
             row["result"] in ("ok", "error", "timeout", "pending"), "operation_values")
        deny(row["finished_ns"] is None and row["result"] == "pending" or
             exact_int(row["finished_ns"], row["started_ns"], (1 << 63) - 1), "operation_time")
        validate_ref(row["request_ref"])
        if row["response_ref"] is not None:
            validate_ref(row["response_ref"])
        else:
            deny(row["result"] != "ok", "operation_response_missing")
    end = report["termination"]
    deny(type(end) is dict and set(end) ==
         {"status", "reason", "reaped", "returncode", "actions", "grace", "streams"},
         "termination_shape")
    deny(end["status"] in ("PASS", "DENY", "INCOMPLETE") and type(end["reason"]) is str and
         re.fullmatch(r"[a-z0-9_]{1,96}", end["reason"]) and type(end["reaped"]) is bool and
         (end["returncode"] is None or exact_int(end["returncode"], -(1 << 31), (1 << 31) - 1)) and
         end["grace"] in ("not_attempted", "exited", "timeout", "error") and
         type(end["actions"]) is list and len(end["actions"]) <= 8 and
         all(type(x) is str and 0 < len(x) <= 96 for x in end["actions"]), "termination_values")
    deny(end["reaped"] == (end["returncode"] is not None), "termination_wait_identity")
    deny(type(end["streams"]) is list and len(end["streams"]) == len(STREAMS),
         "termination_streams")
    for name, row in zip(STREAMS, end["streams"], strict=True):
        deny(type(row) is dict and set(row) == {"name", "eof", "error"} and
             row["name"] == name and type(row["eof"]) is bool, "stream_shape")
        error = row["error"]
        deny(error is None or type(error) is dict and set(error) == {"operation", "errno"} and
             error["operation"] in ("read", "write", "close") and
             exact_int(error["errno"], 1, 4095), "stream_error_shape")
    if end["status"] == "PASS":
        observed = report["observations"]
        deny(end["reaped"] and end["returncode"] == 0 and not end["actions"] and
             all(row["eof"] and row["error"] is None for row in end["streams"]) and
             all(observed[key] is not None for key in OBS_REFS) and
             observed["realized"] is True and observed["rsp_thread"] == "01" and
             observed["physical_mode"] == 1 and observed["phys_bits"] is not None,
             "pass_evidence_missing")


def persist_report(report, run):
    validate_report(report)
    data = canonical(report)
    if len(data) > REPORT_LIMIT:
        report["termination"].update(status="INCOMPLETE", reason="report_limit")
        report["operations"] = []
        data = canonical(report)
    try:
        write_private(run / "report.json", data)
    except OSError:
        report["termination"].update(status="INCOMPLETE", reason="report_persistence_failed")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "collect"))
    parser.add_argument("--inputs-root", type=Path, required=True)
    parser.add_argument("--source-dossier", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--plan-file", type=Path, required=True)
    parser.add_argument("--plan-sha256")
    args = parser.parse_args(argv)
    try:
        if args.command == "plan":
            deny(args.plan_sha256 is None, "unexpected_plan_digest")
            plan, *_ = prepare_plan(args.inputs_root, args.run_dir, args.source_dossier)
            data = canonical(plan)
            write_private(args.plan_file, data)
            print(hashlib.sha256(data).hexdigest())
            return 0
        deny(type(args.plan_sha256) is str and re.fullmatch(r"[0-9a-f]{64}", args.plan_sha256),
             "reviewed_plan_digest_required")
        result = collect(args.plan_file, args.plan_sha256, args.inputs_root,
                         args.run_dir, args.source_dossier)
        end = result["termination"]
        print(json.dumps({"status": end["status"], "reason": end["reason"],
                          "reaped": end["reaped"]}, sort_keys=True))
        return {"PASS": 0, "INCOMPLETE": 2, "DENY": 1}[end["status"]]
    except (base.ProbeError, entry.AdmissionError, OSError) as exc:
        status = getattr(exc, "status", "INCOMPLETE" if isinstance(exc, OSError) else "DENY")
        print(json.dumps({"status": status, "reason": getattr(exc, "reason", str(exc))}))
        return 1 if status == "DENY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
