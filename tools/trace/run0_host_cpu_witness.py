"""True-parent supervision and retained evidence for the RUN0 CPU witness."""

import argparse
from collections.abc import Mapping
import ctypes
from contextlib import ExitStack
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import select
import selectors
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
from types import MappingProxyType

import boot_profile_capture as base
import boot_profile_inputs as entry
from run0_rsp_capability import (
    FALSE_CLAIMS, QEMU_SHA256, SOURCE_DOSSIER_SHA256,
    CapabilityQMP, CapabilityWire, canonical, cpu_path, defer_cleanup_interrupt, realized_width,
    decode_pinned_profile, profile_pin, read_exact, write_private,
)


NATIVE_LAYOUT = MappingProxyType({
    "pointer_size": 8, "long_size": 8, "int_size": 4, "sigchld": 17,
    "sig_dfl": 0, "sa_no_cld_wait": 2, "sigaction_size": 152,
    "sigaction_align": 8, "handler_offset": 0, "handler_size": 8,
    "mask_offset": 8, "mask_size": 128, "flags_offset": 136, "flags_size": 4,
    "restorer_offset": 144, "restorer_size": 8, "ucred_size": 12,
    "ucred_align": 4, "peer_pid_offset": 0, "peer_uid_offset": 4,
    "peer_gid_offset": 8, "statfs_size": 120, "statfs_align": 8,
    "fs_type_offset": 0, "fs_type_size": 8, "fs_type_signed": 1,
    "proc_super_magic": 40864, "ext4_super_magic": 61267, "so_peercred": 17,
})
NATIVE_LAYOUT_SHA256 = "77acf8cadc459a762652eb261202a39143f80e314ecec3b86693838215324bfe"
REPORT_LIMIT = 1024 * 1024
MAX_U64 = (1 << 64) - 1
MAX_PID = (1 << 31) - 1
SAFE_BLOB = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*")
HASH = re.compile(r"[0-9a-f]{64}")
deny = base.deny
incomplete = base.incomplete


def exact_int(value, low, high):
    return type(value) is int and low <= value <= high


def object_fields(value, keys, reason):
    deny(type(value) is dict and all(type(key) is str for key in value)
         and set(value) == set(keys), reason)
    return value


def validate_native_layout(layout):
    object_fields(layout, NATIVE_LAYOUT, "native_layout_fields")
    deny(all(type(layout[name]) is int and layout[name] == expected
             for name, expected in NATIVE_LAYOUT.items()), "native_layout_mismatch")


def decode_sigchld(raw):
    deny(type(raw) is bytes and len(raw) == NATIVE_LAYOUT["sigaction_size"],
         "sigaction_layout")
    handler = struct.unpack_from("<Q", raw, NATIVE_LAYOUT["handler_offset"])[0]
    flags = struct.unpack_from("<I", raw, NATIVE_LAYOUT["flags_offset"])[0]
    deny(handler == NATIVE_LAYOUT["sig_dfl"] and
         not flags & NATIVE_LAYOUT["sa_no_cld_wait"], "sigchld_reaping_policy")
    incomplete(flags == 0, "sigchld_unknown_flags")
    return handler, flags


def decode_peer(raw, expected_pid, expected_uid, expected_gid):
    deny(type(raw) is bytes and len(raw) == NATIVE_LAYOUT["ucred_size"], "peer_layout")
    deny(exact_int(expected_pid, 1, MAX_PID) and exact_int(expected_uid, 0, 0xffffffff)
         and exact_int(expected_gid, 0, 0xffffffff), "peer_expected_identity")
    peer = struct.unpack("<iII", raw)
    deny(peer == (expected_pid, expected_uid, expected_gid), "peer_identity")
    return peer


class NativeQueries:
    """Only native structures confirmed by the installed-header fixture."""

    def __init__(self, layout):
        validate_native_layout(layout)
        incomplete(sys.platform == "linux", "native_linux_required")
        incomplete(os.uname().machine == "x86_64" and sys.byteorder == "little"
                   and ctypes.sizeof(ctypes.c_void_p) == 8
                   and ctypes.sizeof(ctypes.c_long) == 8
                   and ctypes.sizeof(ctypes.c_int) == 4
                   and ctypes.alignment(ctypes.c_long) == 8
                   and os.confstr("CS_GNU_LIBC_VERSION") == "glibc 2.39",
                   "native_abi_unavailable")
        libc = ctypes.CDLL(None, use_errno=True)
        self._sigaction = libc.sigaction
        self._sigaction.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)
        self._sigaction.restype = ctypes.c_int
        self._fstatfs = libc.fstatfs
        self._fstatfs.argtypes = (ctypes.c_int, ctypes.c_void_p)
        self._fstatfs.restype = ctypes.c_int

    def sigchld(self):
        buffer = ctypes.create_string_buffer(NATIVE_LAYOUT["sigaction_size"])
        deny(ctypes.addressof(buffer) % NATIVE_LAYOUT["sigaction_align"] == 0,
             "sigaction_buffer_alignment")
        if self._sigaction(NATIVE_LAYOUT["sigchld"], None, buffer) != 0:
            raise OSError(ctypes.get_errno(), "sigaction query failed")
        return buffer.raw

    def filesystem_magic(self, fd):
        buffer = ctypes.create_string_buffer(NATIVE_LAYOUT["statfs_size"])
        deny(ctypes.addressof(buffer) % NATIVE_LAYOUT["statfs_align"] == 0,
             "statfs_buffer_alignment")
        if self._fstatfs(fd, buffer) != 0:
            raise OSError(ctypes.get_errno(), "fstatfs query failed")
        return struct.unpack_from("<q", buffer, NATIVE_LAYOUT["fs_type_offset"])[0]


def parse_proc_stat(raw):
    deny(type(raw) is bytes and 0 < len(raw) <= 4096 and raw.isascii() and
         raw.endswith(b"\n") and raw.count(b"\n") == 1, "proc_stat_shape")
    match = re.fullmatch(rb"([1-9][0-9]{0,9}) \(([^\x00\r\n]*)\) ([^\r\n]+)\n", raw)
    deny(match is not None, "proc_stat_grammar")
    fields = match[3].split(b" ")
    deny(len(fields) == 50 and fields[0] in (b"R", b"S", b"D", b"T", b"t", b"I"),
         "proc_stat_state")
    deny(all(re.fullmatch(rb"-?[0-9]{1,20}", field) for field in fields[1:]),
         "proc_stat_numbers")
    pid, ppid, starttime = int(match[1]), int(fields[1]), int(fields[19])
    deny(exact_int(pid, 1, MAX_PID) and exact_int(ppid, 1, MAX_PID)
         and exact_int(starttime, 1, MAX_U64), "proc_stat_identity")
    return pid, ppid, starttime


def retained_blob(ref, blobs, limit):
    object_fields(ref, ("path", "length", "sha256"), "blob_reference_fields")
    path, length, digest = ref["path"], ref["length"], ref["sha256"]
    deny(type(path) is str and len(path) <= 240 and SAFE_BLOB.fullmatch(path) and
         all(part not in (".", "..") for part in path.split("/")) and
         exact_int(length, 0, limit) and type(digest) is str and HASH.fullmatch(digest),
         "blob_reference_value")
    deny(type(blobs) is dict and all(type(key) is str for key in blobs),
         "retained_bytes_mapping")
    incomplete(path in blobs, "referenced_blob_unavailable")
    data = blobs[path]
    deny(type(data) is bytes and len(data) == length, "retained_blob_length")
    deny(hashlib.sha256(data).hexdigest() == digest, "retained_blob_digest")
    return data


def strict_json(raw, limit):
    deny(type(raw) is bytes and 0 < len(raw) <= limit, "json_size")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=entry.reject_pairs,
                          parse_float=entry.reject_constant, parse_constant=entry.reject_constant)
    except (entry.AdmissionError, ValueError, UnicodeError, RecursionError) as error:
        raise base.ProbeError("DENY", "invalid_json") from error


@dataclass(frozen=True, slots=True)
class WitnessFields(Mapping):
    pairs: tuple

    def __iter__(self):
        return (key for key, _ in self.pairs)

    def __len__(self):
        return len(self.pairs)

    def __getitem__(self, key):
        for name, value in self.pairs:
            if name == key:
                return value
        raise KeyError(key)


def immutable(value):
    if type(value) is dict:
        return WitnessFields(tuple((name, immutable(item)) for name, item in value.items()))
    if type(value) is list:
        return tuple(immutable(item) for item in value)
    return value


@dataclass(frozen=True, slots=True, init=False)
class ValidatedHostState:
    origin: str
    report_ref: WitnessFields
    binding: WitnessFields
    state: WitnessFields
    final_status: str

    def __init__(self, *args, **kwargs):
        raise TypeError("use validate_report on exact retained evidence")


def export_validated_host_state(value):
    """Unwrap only data produced by the tuple-backed immutable witness."""
    deny(type(value) is ValidatedHostState, "host_witness_type")

    def plain(item, depth=0):
        deny(depth <= 8, "host_witness_depth")
        if type(item) is WitnessFields:
            pairs = item.pairs
            deny(type(pairs) is tuple and len(pairs) <= 32, "host_witness_pairs")
            result = {}
            for pair in pairs:
                deny(type(pair) is tuple and len(pair) == 2 and type(pair[0]) is str
                     and pair[0] not in result, "host_witness_pair")
                result[pair[0]] = plain(pair[1], depth + 1)
            return result
        if type(item) is tuple:
            deny(len(item) <= 32, "host_witness_items")
            return [plain(child, depth + 1) for child in item]
        deny(type(item) in (str, int, bool, type(None)), "host_witness_value")
        return item

    try:
        return {name: plain(getattr(value, name)) for name in (
            "origin", "report_ref", "binding", "state", "final_status",
        )}
    except AttributeError as error:
        raise base.ProbeError("DENY", "host_witness_fields") from error


def validate_report(report_ref, blobs):
    """Produce an opaque witness only from complete retained evidence."""
    deny(type(report_ref) is dict, "blob_reference_fields")
    report_ref = report_ref.copy()
    deny(type(blobs) is dict, "retained_bytes_mapping")
    blobs = blobs.copy()
    deny(all(type(key) is str and type(value) is bytes for key, value in blobs.items()),
         "retained_bytes_mapping")
    report = json_index(report_ref, blobs, (
        "schema_version", "kind", "run_id", "binding", "profile_ref", "observer_ref",
        "source_ref", "abi_ref", "plan_ref", "metadata_before_ref", "metadata_after_ref",
        "peer_ref", "sigchld_ref", "process_ref", "reads_ref", "state", "admission",
        "termination", "claims", "fresh_c0_verified", "origin", "control_ref",
    ), "witness_report")
    deny(report["kind"] == "run0_host_cpu_witness_v0"
         and report["origin"] in ("synthetic_fixture", "retained_runtime")
         and type(report["run_id"]) is str and re.fullmatch(r"[a-z0-9-]{1,64}", report["run_id"])
         and canonical(report["claims"]) == canonical(FALSE_CLAIMS)
         and report["fresh_c0_verified"] is False, "witness_identity")
    admission = object_fields(report["admission"], ("status", "reason"), "admission")
    termination = object_fields(report["termination"], (
        "status", "first_failure", "secondary_failures", "waits", "streams_ref",
    ), "termination")
    if "DENY" in (admission["status"], termination["status"]):
        deny(False, "witness_denied")
    incomplete(admission["status"] == "ADMIT" and termination["status"] == "PASS"
               and termination["first_failure"] is None and termination["secondary_failures"] == [],
               "witness_incomplete")
    return validate_complete_report(report_ref, report, blobs)


class OwnedWait:
    """Record the actual wait and signals for one unreaped process group."""

    def __init__(self, role, deadline):
        self.role, self.deadline = role, deadline
        self.io_deadline = deadline - 0.75
        self.child = None
        self.reaped, self.returncode = False, None
        self.ownership_lost = False
        self.actions, self.lifecycle = [], []
        self.cancelled = False

    def _receipt(self, operation, started, result, *, returncode=None, errno=None):
        self.lifecycle.append({
            "role": self.role, "pid": self.child.pid, "operation": operation,
            "started_ns": started, "finished_ns": time.monotonic_ns(),
            "result": result, "returncode": returncode, "errno": errno,
        })

    def wait(self, deadline=None, *, pump=None):
        if self.reaped:
            return self.returncode
        incomplete(not self.ownership_lost and self.child is not None, "owned_wait_unavailable")
        deadline = self.io_deadline if deadline is None else min(deadline, self.deadline)
        started = time.monotonic_ns()
        try:
            while True:
                if pump is not None:
                    pump()
                pid, status = os.waitpid(self.child.pid, os.WNOHANG)
                if pid == self.child.pid:
                    code = os.waitstatus_to_exitcode(status)
                    break
                deny(pid == 0, "owned_wait_pid")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._receipt("wait", started, "timeout")
                    return None
                time.sleep(min(0.025, remaining))
        except OSError as error:
            if isinstance(error, ChildProcessError):
                self.ownership_lost = True
            self._receipt("wait", started, "error", errno=error.errno)
            raise
        self.child.returncode = code
        self.reaped, self.returncode = True, code
        self._receipt("wait", started, "ok", returncode=code)
        return code

    def _signal(self, sig, action):
        started = time.monotonic_ns()
        operation = "signal_term" if sig == signal.SIGTERM else "signal_kill"
        try:
            os.killpg(self.child.pid, sig)
        except OSError as error:
            self._receipt(operation, started, "error", errno=error.errno)
        else:
            self.actions.append(action)
            self._receipt(operation, started, "ok")

    def terminate(self):
        if self.reaped or self.ownership_lost or self.child is None:
            return
        with defer_cleanup_interrupt() as interrupted:
            if self.wait(time.monotonic()) is None:
                self._signal(signal.SIGTERM, "SIGTERM")
                if self.wait(time.monotonic() + 0.25) is None:
                    self._signal(signal.SIGKILL, "SIGKILL")
                    self.wait(self.deadline)
        self.cancelled = self.cancelled or interrupted[0]


class OwnedHelper(OwnedWait):
    """One private subprocess with bounded result/stderr pipes and an actual wait."""

    def __init__(self, role, result_fd, deadline, *, pump=None, budget=None):
        super().__init__(role, deadline)
        self.result_fd = result_fd
        self.pump = pump
        self.budget = budget
        self.output, self.stderr = bytearray(), bytearray()
        self.eofs, self.io_errors = set(), []
        self.closed = False
        self.selector = selectors.DefaultSelector()

    def start(self, argv, pass_fds, output_limit, stderr_limit):
        """The caller already holds this owner, even if pipe registration fails."""
        deny(self.child is None and not self.closed, "helper_already_started")
        started = time.monotonic_ns()
        incomplete(time.monotonic() < self.io_deadline, "helper_start_deadline")
        with defer_cleanup_interrupt() as interrupted:
            self.child = subprocess.Popen(
                argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE, pass_fds=pass_fds, close_fds=True,
                start_new_session=True, umask=0o077,
                env={"PATH": "/usr/bin:/bin", "LANG": "C"},
            )
        self.cancelled = interrupted[0]
        self._receipt("spawn", started, "ok")
        incomplete(not self.cancelled, "helper_cancelled")
        for name, stream, buffer, limit in (
            ("stdout", self.result_fd, self.output, output_limit),
            ("stderr", self.child.stderr, self.stderr, stderr_limit),
        ):
            fd = stream if type(stream) is int else stream.fileno()
            os.set_blocking(fd, False)
            self.selector.register(stream, selectors.EVENT_READ, (name, buffer, limit))

    def _step(self, deadline):
        incomplete(time.monotonic() < deadline, "helper_io_deadline")
        if self.pump is not None:
            self.pump()
        remaining = deadline - time.monotonic()
        incomplete(remaining > 0, "helper_io_deadline")
        for key, _ in self.selector.select(min(remaining, 0.025)):
            incomplete(time.monotonic() < deadline, "helper_io_deadline")
            name, data, limit = key.data
            available = limit - len(data)
            if self.budget is not None:
                available = min(available, self.budget.byte_limit - self.budget.retained_bytes)
            try:
                chunk = os.read(key.fd, min(65536, available + 1))
            except (BlockingIOError, InterruptedError):
                continue
            except OSError as error:
                self.io_errors.append({"name": name, "operation": "read", "errno": error.errno})
                self.selector.unregister(key.fileobj)
                raise
            if not chunk:
                self.selector.unregister(key.fileobj)
                self.eofs.add(name)
                continue
            prefix = chunk[:available]
            if self.budget is not None:
                self.budget.retain(len(prefix))
            data.extend(prefix)
            if len(chunk) > available:
                self.io_errors.append({"name": name, "operation": "read", "errno": None,
                                       "observed_overflow_bytes": len(chunk) - available})
                self.selector.unregister(key.fileobj)
                incomplete(False, "helper_output_limit")

    def until(self, ready):
        incomplete(not self.cancelled, "helper_cancelled")
        while not ready():
            incomplete(bool(self.selector.get_map()), "helper_output_eof")
            self._step(self.io_deadline)

    def drain(self):
        self.until(lambda: not self.selector.get_map())
        incomplete(self.eofs == {"stdout", "stderr"}, "helper_stream_eof")

    def close(self):
        if self.closed:
            return
        try:
            self.terminate()
        finally:
            # The worker has been stopped or reaped. Retain any bounded tail
            # still available through its original result pipes.
            self.pump = None
            while self.selector.get_map() and time.monotonic() < self.deadline:
                try:
                    self._step(self.deadline)
                except (base.ProbeError, OSError):
                    break
            started = time.monotonic_ns()
            close_error = None
            self.selector.close()
            stderr = self.child.stderr if self.child is not None else None
            for name, stream in (("stdout", self.result_fd), ("stderr", stderr)):
                if stream is None:
                    continue
                try:
                    if type(stream) is int:
                        os.close(stream)
                    else:
                        stream.close()
                except OSError as error:
                    close_error = error.errno
                    self.io_errors.append({"name": name, "operation": "close", "errno": error.errno})
            if self.child is not None:
                self._receipt("close", started, "ok" if close_error is None else "error",
                              errno=close_error)
            self.closed = True


def ndjson(raw, limit):
    """Return exact line spans, leaving an unfinished tail distinguishable."""
    deny(type(raw) is bytes and len(raw) <= limit, "field_wire_size")
    rows = []
    offset = 0
    for line in raw.splitlines(keepends=True):
        if not line.endswith(b"\n"):
            break
        deny(len(rows) < 30 and line.count(b"\r") == 0, "field_wire_framing")
        rows.append((strict_json(line, limit), offset, len(line)))
        offset += len(line)
    return rows, offset


def field_receipts(raw, begin, maps, abi, *, head_only=False):
    """Recompute the field inventory and state from the helper's exact output."""
    import run0_host_cpu_reader as reader

    frames, used = ndjson(raw, reader.FIELD_OUTPUT)
    if head_only and len(frames) < 5:
        return None
    incomplete(head_only or used == len(raw), "field_wire_partial")
    cursor, reads = 0, []
    deadline = begin["deadline_ns"]
    last = 0

    def next_frame():
        nonlocal cursor
        incomplete(cursor < len(frames), "field_frame_missing")
        frame = frames[cursor]
        cursor += 1
        return frame

    def read(phase, role, address, length):
        nonlocal last
        seq = len(reads) + 1
        start, offset, size = next_frame()
        object_fields(start, ("kind", "seq", "phase", "address", "length", "started_ns"),
                      "field_read_started_shape")
        started = start["started_ns"]
        deny(start == {"kind": "read_started", "seq": seq, "phase": phase,
                       "address": address, "length": length, "started_ns": started}
             and all(type(start[key]) is int for key in ("seq", "phase", "address", "length"))
             and exact_int(started, max(1, last), deadline), "field_read_started_value")
        finish, finish_offset, finish_size = next_frame()
        object_fields(finish, ("kind", "seq", "finished_ns", "returned", "errno", "hex"),
                      "field_read_finished_shape")
        finished, returned, raw_hex = finish["finished_ns"], finish["returned"], finish["hex"]
        deny(finish["kind"] == "read_finished" and exact_int(finish["seq"], seq, seq)
             and exact_int(finished, started, (1 << 63) - 1)
             and exact_int(returned, -1, length)
             and type(raw_hex) is str
             and re.fullmatch(r"[0-9a-f]*", raw_hex) is not None
             and len(raw_hex) == 2 * max(returned, 0), "field_read_finished_value")
        error = finish["errno"]
        deny((returned == -1 and exact_int(error, 1, 4095))
             or (returned >= 0 and error is None), "field_read_errno")
        incomplete(finished <= deadline, "field_read_deadline")
        incomplete(returned == length, "field_read_incomplete")
        reads.append({
            "seq": seq, "phase": phase, "role": role, "address": address,
            "length": length, "started_ns": started, "finished_ns": finished,
            "result": "ok", "returned": returned, "errno": error, "raw_hex": raw_hex,
            "started_wire": (offset, size), "finished_wire": (finish_offset, finish_size),
        })
        last = finished
        return bytes.fromhex(raw_hex)

    bias = maps.load_bias
    queue = reader.end(bias, reader.QUEUE)
    generation_address = reader.end(bias, reader.GENERATION)
    head = read(1, "head", queue, 16)
    generation = read(1, "generation", generation_address, 4)
    ready, _, _ = next_frame()
    deny(type(ready) is dict and ready == {
        "kind": "head_ready", "nonce": begin["nonce"], "completed_phase": 1,
    } and type(ready["completed_phase"]) is int, "field_head_ready")
    grant = reader.admit_cpu(head, maps, abi)
    cpu = int.from_bytes(head[:8], "little")
    admit = {"kind": "admit_cpu", "version": 1, "nonce": begin["nonce"],
             "cpu": cpu, "map": grant}
    if head_only:
        deny(cursor == len(frames) and used == len(raw), "field_before_admission")
        return admit

    def cpu_read(phase, role, offset, length):
        return read(phase, role, reader.end(cpu, offset), length)

    node = cpu_read(2, "node", reader.NODE, 16)
    index = cpu_read(2, "cpu_index", reader.INDEX, 4)
    tid = cpu_read(2, "thread_id", reader.TID, 4)
    deny(struct.unpack("<QQ", node) == (0, queue)
         and struct.unpack("<i", index)[0] == 0
         and struct.unpack("<i", tid)[0] == begin["expected_thread_id"], "field_cpu_identity")
    flags = cpu_read(3, "hflags", reader.HFLAGS, 4)
    flags2 = cpu_read(3, "hflags2", reader.HFLAGS2, 4)
    for phase, role, offset, expected in (
        (4, "hflags", reader.HFLAGS, flags), (4, "hflags2", reader.HFLAGS2, flags2),
        (5, "node", reader.NODE, node), (5, "cpu_index", reader.INDEX, index),
        (5, "thread_id", reader.TID, tid),
    ):
        incomplete(cpu_read(phase, role, offset, len(expected)) == expected, "field_cpu_changed")
    incomplete(read(6, "head", queue, 16) == head
               and read(6, "generation", generation_address, 4) == generation,
               "field_globals_changed")
    finished, _, _ = next_frame()
    deny(cursor == len(frames) and finished == {
        "kind": "finished", "status": "ADMIT", "reason": "field_subset_complete",
    }, "field_terminal_frame")
    hflags, hflags2 = struct.unpack("<II", flags + flags2)
    state = {
        "hflags": hflags, "hflags2": hflags2, "cpl": hflags & 3,
        "cs64": bool(hflags & (1 << 15)), "lma": bool(hflags & (1 << 14)),
        "no_npt": not hflags2 & (1 << 6), "no_svm_guest": not hflags & (1 << 21),
        "no_smm": not hflags & (1 << 19), "observed_consistent": True,
    }
    incomplete(all(state[key] for key in ("no_npt", "no_svm_guest", "no_smm")),
               "field_cpu_state")
    return admit, reads, state


class ResetWire(CapabilityWire):
    witness_deadline = None

    def send(self, data, deadline):
        if self.witness_deadline is not None:
            deadline = min(deadline, self.witness_deadline)
        super().send(data, deadline)


class ResetQMP(CapabilityQMP):
    """Reuse the typed protocol with only reset witness commands."""

    def __init__(self, wire, budget):
        super().__init__(wire, budget)
        self.witness_deadline = None
        self.received_events = []
        self.quitting = False

    def receive(self, deadline, *, teardown=False):
        if self.witness_deadline is not None and not teardown:
            deadline = min(deadline, self.witness_deadline)
            incomplete(time.monotonic() < deadline, "witness_deadline")
        frame, value = super().receive(deadline, teardown=teardown)
        if "event" in value:
            self.received_events.append((time.monotonic_ns(), frame, value.get("event")))
        return frame, value

    def request(self, command, arguments=None):
        deny(command != "human-monitor-command" or arguments == {
            "command-line": "info registers",
        }, "reset_hmp_allowlist")
        if self.witness_deadline is not None and command != "quit":
            incomplete(time.monotonic() < self.witness_deadline, "witness_deadline")
        if command == "quit":
            self.quitting = True
        self.wire.witness_deadline = self.witness_deadline if command != "quit" else None
        try:
            return super().request(command, arguments)
        finally:
            self.wire.witness_deadline = None

    def event(self, value):
        super().event(value)
        incomplete(self.quitting and is_qmp_shutdown(value), "unexpected_guest_event")

    def require_quiet(self):
        if self.wire.frames:
            raw = self.wire.frames.popleft()
            self.budget.message()
            value = base.decode_frame(raw)
            deny("event" in value, "qmp_unsolicited_reply")
            self.received_events.append((time.monotonic_ns(), raw, value.get("event")))
            self.event(value)
        incomplete(not self.wire.partial and not self.wire.qmp_eof
                   and not any(row["stream"] == "qmp" for row in self.wire.io_errors),
                   "qmp_observation_interrupted")

    def bracket(self):
        self.require_prelaunch()
        status = len(self.operations)
        cpus = self.request("query-cpus-fast")
        path = cpu_path(cpus)
        tid = cpus[0]["thread-id"]
        deny(exact_int(tid, 1, MAX_PID), "qmp_host_tid")
        realized = self.request("qom-get", {"path": path, "property": "realized"})
        width = self.request("qom-get", {"path": path, "property": "phys-bits"})
        width = realized_width(realized, width)
        registers = self.request("human-monitor-command", {"command-line": "info registers"})
        reset_registers(registers)
        index = {"status_seq": status, "cpu_seq": status + 1, "realized_seq": status + 2,
                 "phys_bits_seq": status + 3, "hmp_seq": status + 4}
        return index, (path, tid, width), registers


def reset_registers(raw):
    deny(type(raw) is str and raw.isascii() and 0 < len(raw) <= 65536, "hmp_shape")
    lines = raw.splitlines()
    deny([line for line in lines if line.startswith("CPU#")] == ["CPU#0"], "hmp_cpu")
    cs = [match for line in lines if (match := re.fullmatch(
        r"CS =[0-9a-f]{4} [0-9a-f]{8} [0-9a-f]{8} ([0-9a-f]{8})(?: .*|)", line
    ))]
    deny(len(cs) == 1, "hmp_cs")
    for name, expected in (("CPL", "0"), ("SMM", "0"), ("A20", "1")):
        incomplete(re.findall(rf"\b{name}=([0-9]+)(?=\s|$)", raw) == [expected], "hmp_reset_mode")
    for name, bit in (("CR0", 31), ("EFER", 10)):
        values = re.findall(rf"\b{name}=([0-9a-f]{{8,16}})(?=\s|$)", raw)
        deny(len(values) == 1, "hmp_mode_register")
        incomplete(not int(values[0], 16) & (1 << bit), "hmp_reset_mode")
    incomplete(not int(cs[0][1], 16) & (1 << 21), "hmp_reset_mode")


def pidfd_check(fd):
    poller = select.poll()
    poller.register(fd, select.POLLIN)
    events = poller.poll(0)
    bits = events[0][1] if events else 0
    deny(len(events) <= 1 and not bits & ~(select.POLLIN | select.POLLHUP | select.POLLERR),
         "pidfd_event")
    receipt = {"observed_ns": time.monotonic_ns(), "readable": bool(bits & select.POLLIN),
               "hangup": bool(bits & select.POLLHUP), "error": None}
    incomplete(bits == 0, "pidfd_not_live")
    return receipt


class _ResetObservationPort:
    """Closed reset semantics over the existing exact ResetQMP owner."""

    def __init__(self, qmp, budget):
        self.qmp = qmp
        self.deadline = min(time.monotonic() + 5, budget.deadline - 5)
        self.deadline_ns = int(self.deadline * 1_000_000_000)
        qmp.witness_deadline = self.deadline

    def peer(self):
        raw = self.qmp.wire.sources["qmp"].getsockopt(socket.SOL_SOCKET,
                                                  NATIVE_LAYOUT["so_peercred"], 12)
        return raw, time.monotonic_ns()

    def bracket(self, phase):
        return self.qmp.bracket()

    def pump(self):
        self.qmp.wire.step(min(self.deadline, time.monotonic() + 0.005))
        self.qmp.require_quiet()

    @staticmethod
    def field_mode(state):
        incomplete(state["cpl"] == 0 and not state["cs64"] and not state["lma"],
                   "reset_field_mode")

    @staticmethod
    def changed():
        return "reset_bracket_changed"


C0_SOURCE_PERSISTENCE_SHA256 = "d2b1bcd4e5f7318b587a02c15576fb54097fe379a00fed6be53cff61c3962ad9"
WITNESS_PLAN_FIELDS = ("schema_version", "kind", "inputs", "run", "argv", "uid", "gid",
                       "launch_identity", "profile_sha256", "abi_sha256",
                       "source_dossier_sha256", "observer_ref", "esp_validation")
C0_PLAN_INPUT_FIELDS = ("prior_admission_ref", "profile_mapping_ref", "capability_ref",
                        "source_persistence_ref")


def validate_c0_plan_inputs(plan, profile_ref, abi_index, blobs, *, abi_ref):
    """Recompute a closed input manifest; input arrays never grant output authority."""
    import run0_c0_decode as decoder
    import run0_c0_capture as capture

    deny(plan.get("context") == "c0", "c0_plan_context")
    references = {}
    for name in C0_PLAN_INPUT_FIELDS:
        value = plan.get(name)
        deny(type(value) is list and len(value) == 3, "c0_plan_input_array")
        reference = decoder._ref(dict(zip(("path", "sha256", "length"), value)), REPORT_LIMIT)
        deny(not capture._output_name(reference["path"]), "c0_plan_input_output_collision")
        references[name] = reference
    persistence = references["source_persistence_ref"]
    deny(persistence["sha256"] == C0_SOURCE_PERSISTENCE_SHA256, "c0_source_persistence_pin")
    store = decoder._Blobs(blobs)
    # Preparation verifies this exact ABI root through the same store. Include
    # it explicitly in the reconstructed manifest; do not infer its path or
    # drop a verified producer input to make a digest match.
    abi_ref = decoder._ref(abi_ref, REPORT_LIMIT)
    abi_raw = store.get(abi_ref, REPORT_LIMIT)
    deny(type(abi_index) is dict and strict_json(abi_raw, REPORT_LIMIT) == abi_index
         and plan.get("abi_sha256") == abi_ref["sha256"], "c0_plan_abi_root_identity")
    profile, _, _ = decoder._profile_binding({"profile_ref": profile_ref, **references}, store)
    deny(profile["invocation_profile"] == base.VAPIC_OFF_INVOCATION_PROFILE,
         "c0_runtime_profile")
    decoder._capability_binding({**references,
        "source_dossier_ref": abi_index["source_dossier_ref"]}, store, profile)
    store.get(persistence, REPORT_LIMIT)
    deny(all(not capture._output_name(name) for name in store.verified),
         "c0_plan_input_output_collision")
    manifest = [CaptureEvidence.ref(name, raw) for name, raw in sorted(store.verified.items())]
    deny(type(plan.get("prior_inputs_sha256")) is str and
         plan["prior_inputs_sha256"] == hashlib.sha256(canonical(manifest)).hexdigest(),
         "c0_prior_inputs_digest")
    return profile


def require_c0_runtime_registration(prepared, plan):
    """Release only the exact immutable prepared C0 source, profile and input join.

    The owned collector calls this before Popen and current-binding issuance.
    Python observer internals are trusted; neither a dictionary nor a fixture
    origin string is a registration. The later owned-wire issuer remains required.
    """
    import run0_c0_capture as capture
    import run0_c0_entry as prior_entry
    import run0_host_cpu_reader as reader

    deny(type(prepared) is capture.PreparedC0Inputs, "c0_runtime_prepared_type")
    try:
        for name in capture.PreparedC0Inputs.__dataclass_fields__:
            getattr(prepared, name)
    except AttributeError as error:
        raise base.ProbeError("DENY", "c0_runtime_prepared_fields") from error
    for name in ("inputs", "run", "source_dossier", "host_abi"):
        value = getattr(prepared, name)
        deny(type(value) is str and 1 <= len(value) <= 4096, "c0_runtime_path_type")
        base.safe_path(Path(value))
        deny(Path(value).is_absolute(), "c0_runtime_path_absolute")
    for name, limit in (("plan_bytes", REPORT_LIMIT), ("profile_bytes", 65536),
                        ("observer_source_bytes", 65536), ("pinned_efi", base.INPUT_LIMITS["efi"])):
        value = getattr(prepared, name)
        deny(type(value) is bytes and 1 <= len(value) <= limit, "c0_runtime_bytes_type")
    for name in ("abi_blobs", "prior_blobs"):
        inventory = getattr(prepared, name)
        deny(type(inventory) is tuple and len(inventory) <= 4096 and all(
            type(row) is tuple and len(row) == 2 and type(row[0]) is str
            and type(row[1]) is bytes for row in inventory), "c0_runtime_blob_inventory")
        deny(len({row[0] for row in inventory}) == len(inventory)
             and sum(len(row[1]) for row in inventory) <= 256 << 20,
             "c0_runtime_blob_bound")
    layout = prepared.native_layout
    deny(type(layout) is tuple and len(layout) == len(NATIVE_LAYOUT) and all(
        type(row) is tuple and len(row) == 2 and type(row[0]) is str and type(row[1]) is int
        for row in layout) and len({row[0] for row in layout}) == len(layout),
        "c0_runtime_layout_inventory")
    object_fields(plan, (*WITNESS_PLAN_FIELDS, "context", *C0_PLAN_INPUT_FIELDS,
                         "prior_inputs_sha256"), "c0_runtime_plan_fields")
    try:
        plan_bytes = canonical(plan)
    except (TypeError, ValueError, RecursionError) as error:
        raise base.ProbeError("DENY", "c0_runtime_plan_native") from error
    deny(plan_bytes == prepared.plan_bytes and exact_int(plan["schema_version"], 1, 1),
         "c0_runtime_plan_identity")
    deny(exact_int(plan["uid"], 0, 0xffffffff) and plan["uid"] == os.getuid()
         and exact_int(plan["gid"], 0, 0xffffffff) and plan["gid"] == os.getgid()
         and plan["argv"] == base.build_argv(Path(prepared.inputs), Path(prepared.run),
                                           base.VAPIC_OFF_INVOCATION_PROFILE),
         "c0_runtime_launch_identity")
    deny(plan.get("kind") == "run0_c0_owned_capture_plan_v0" and plan.get("context") == "c0"
         and plan.get("inputs") == prepared.inputs and plan.get("run") == prepared.run,
         "c0_runtime_prepared_plan")
    deny(type(prepared.field_abi) is reader.HostABI
         and type(prepared.prior) is prior_entry.ValidatedPriorEntry,
         "c0_runtime_prepared_proofs")
    profile = decode_pinned_profile(prepared.profile_bytes)
    deny(profile["invocation_profile"] == base.VAPIC_OFF_INVOCATION_PROFILE
         and plan["profile_sha256"] == profile_pin(profile)
         and read_exact(Path(prepared.inputs)/"profile.json", plan["profile_sha256"], 65536)
             == prepared.profile_bytes, "c0_runtime_profile_identity")
    deny(c0_observer_source_bytes() == prepared.observer_source_bytes
         and plan["observer_ref"] == CaptureEvidence.ref("observer.json", prepared.observer_source_bytes),
         "c0_runtime_source_changed")
    deny(type(prepared.abi_ref) is tuple and len(prepared.abi_ref) == 3
         and prepared.abi_ref[1] == REVIEWED_LAUNCH_ABI_SHA256
         and plan["abi_sha256"] == REVIEWED_LAUNCH_ABI_SHA256
         and plan["source_dossier_sha256"] == SOURCE_DOSSIER_SHA256,
         "c0_runtime_abi_identity")
    for key in C0_PLAN_INPUT_FIELDS:
        deny(type(getattr(prepared, key)) is tuple and plan[key] == list(getattr(prepared, key)),
             "c0_runtime_input_identity")
    abi_blobs, prior_blobs = dict(prepared.abi_blobs), dict(prepared.prior_blobs)
    deny(all(name not in abi_blobs or abi_blobs[name] == raw for name, raw in prior_blobs.items()),
         "c0_runtime_input_collision")
    manifest = [CaptureEvidence.ref(name, raw) for name, raw in sorted(prepared.prior_blobs)]
    deny(len(prior_blobs) == len(prepared.prior_blobs)
         and plan["prior_inputs_sha256"] == hashlib.sha256(canonical(manifest)).hexdigest(),
         "c0_runtime_prior_snapshot")
    blobs = {**abi_blobs, **prior_blobs}
    reference = dict(zip(("path", "sha256", "length"), prepared.abi_ref))
    index, pinned_abi = resolve_abi(reference, blobs, True)
    deny(prepared.field_abi == pinned_abi, "c0_runtime_host_abi_identity")
    deny(read_exact(Path(prepared.host_abi), reference["sha256"], REPORT_LIMIT)
         == blobs[reference["path"]]
         and read_exact(Path(prepared.source_dossier), SOURCE_DOSSIER_SHA256, 65536)
         == retained_blob(index["source_dossier_ref"], blobs, 65536), "c0_runtime_input_changed")
    validate_native_layout(dict(prepared.native_layout))
    profile_ref = CaptureEvidence.ref("profile.json", prepared.profile_bytes)
    validate_c0_plan_inputs(plan, profile_ref, index, blobs, abi_ref=reference)
    prior = prior_entry.validate_prior_entry(profile_ref,
        dict(zip(("path", "sha256", "length"), prepared.prior_admission_ref)),
        dict(zip(("path", "sha256", "length"), prepared.profile_mapping_ref)), blobs)
    deny(prior == prepared.prior and prepared.pinned_efi == retained_blob(
        profile["inputs"]["efi"], blobs, base.INPUT_LIMITS["efi"]), "c0_runtime_prior_identity")
    return None


class OwnedCPUObservation:
    """Shared owned helper flow; the public observe entry remains reset-only."""

    def __init__(self, child, qmp, budget, native, abi, launch_path, launch_identity):
        self.child, self.qmp, self.budget = child, qmp, budget
        self.native, self.abi = native, abi
        self.launch_path, self.launch_identity = launch_path, launch_identity
        self.helpers = {}
        self.secondary_failures = []
        self.before = self.after = self.peer_raw = self.sigchld_raw = None
        self.begin_raw = self.admit_raw = self.reads = self.state = None
        self.request_sent = bytearray()
        self.before_bracket = self.after_bracket = None
        self.peer_at_ns = self.sigchld_at_ns = None
        self.process = {}
        self._observation_port = None

    def _time(self):
        incomplete(time.monotonic_ns() < self.deadline_ns, "witness_deadline")

    def _pump(self):
        if self._observation_port is not None:
            self._observation_port.pump()
            return
        self.qmp.wire.step(min(self.deadline, time.monotonic() + 0.005))
        self.qmp.require_quiet()

    def _open(self, path, cleanup, flags, *, dir_fd=None):
        self._time()
        fd = os.open(path, flags | os.O_CLOEXEC | os.O_RDONLY, dir_fd=dir_fd)
        cleanup.callback(self._close_fd, fd, Path(path).name)
        return fd

    def _close_fd(self, fd, role):
        try:
            os.close(fd)
        except OSError:
            self.secondary_failures.append(f"{role}_descriptor_close")
        else:
            if role == "mem":
                self.process["mem_closed_ns"] = time.monotonic_ns()

    def _helper(self, role, result, output, descriptors, extra, limit):
        import run0_host_cpu_reader as reader

        deny(role not in self.helpers and all(item.reaped for item in self.helpers.values()),
             "helper_ownership")
        self._time()
        helper = self.helpers[role] = OwnedHelper(role, result, self.deadline, pump=self._pump,
                                                 budget=self.budget)
        mode = "--field-reader" if role == "fields" else "--metadata-reader"
        argv = [sys.executable, "-E", "-s", "-B", str(Path(reader.__file__).resolve()), mode]
        inherited = dict(descriptors, result=output)
        for name, fd in inherited.items():
            argv.extend((f"--{name}-fd", str(fd)))
        helper.start(argv + extra, tuple(inherited.values()), limit, 16384)
        return helper

    def _close_helper(self, helper):
        try:
            helper.close()
        except OSError:
            self.secondary_failures.append(f"{helper.role}_close_error")
        else:
            if any(row["operation"] == "close" for row in helper.io_errors):
                self.secondary_failures.append(f"{helper.role}_close_error")
        if helper.child is not None and not helper.reaped:
            self.secondary_failures.append(f"{helper.role}_wait_uncertain")

    def _require_helper_closed(self, helper):
        incomplete(helper.closed and helper.reaped and not helper.io_errors
                   and not self.secondary_failures, "helper_cleanup_incomplete")

    def _completed(self, helper):
        helper.drain()
        code = helper.wait(pump=self._pump)
        deny(code != 2, "reader_denied")
        incomplete(code == 0 and not helper.io_errors, "reader_incomplete")
        self._time()
        return bytes(helper.output)

    def _metadata(self, procdir, phase):
        import run0_host_cpu_reader as reader

        role = f"metadata_{phase}"
        with ExitStack() as cleanup:
            fds = {name: self._open(name, cleanup, os.O_NOFOLLOW, dir_fd=procdir)
                   for name in ("stat", "maps", "smaps")}
            fds["exe"] = self._open("exe", cleanup, 0, dir_fd=procdir)
            fds["mountinfo"] = self._open("/proc/self/mountinfo", cleanup, os.O_NOFOLLOW)
            self._time()
            result, output = os.pipe()
            try:
                self._helper(role, result, output, fds,
                             ["--deadline-ns", str(self.deadline_ns)], reader.META_LIMIT)
            finally:
                os.close(output)
                if role not in self.helpers:
                    os.close(result)
            helper = self.helpers[role]
            try:
                raw = self._completed(helper)
            finally:
                self._close_helper(helper)
            self._require_helper_closed(helper)
        value = reader.parse_metadata_output(raw)
        reader.bind_mount_path(value["mountinfo"], self.launch_path, value["exe"])
        exe = value["exe"]
        deny((exe["device"], exe["inode"], exe["size"]) == self.launch_identity
             and exe["sha256"] == self.abi.elf.sha256
             and exe["build_id"] == self.abi.elf.build_id, "owned_exe_identity")
        return value

    def _send_frame(self, fd, frame, helper):
        remaining = memoryview(frame)
        while remaining:
            incomplete(time.monotonic() < helper.io_deadline, "field_request_deadline")
            incomplete(len(remaining) <= self.budget.byte_limit - self.budget.retained_bytes,
                       "storage_limit")
            try:
                count = os.write(fd, remaining)
            except (BlockingIOError, InterruptedError):
                helper._step(helper.io_deadline)
                continue
            incomplete(count > 0, "field_request_eof")
            self.budget.retain(count)
            self.request_sent.extend(remaining[:count])
            remaining = remaining[count:]

    def _fields(self, mem_fd, maps, tid):
        import run0_host_cpu_reader as reader

        begin = {"kind": "begin", "version": 1, "nonce": secrets.token_hex(32),
                 "source_sha256": reader.ABI_SHA256, "deadline_ns": self.deadline_ns,
                 "load_bias": maps.load_bias, "expected_cpu_index": 0,
                 "expected_thread_id": tid, "global_maps": list(maps.global_maps)}
        self._time()
        with ExitStack() as cleanup:
            request, writer = os.pipe()
            cleanup.callback(os.close, writer)
            try:
                result, output = os.pipe()
                try:
                    helper = self._helper("fields", result, output,
                                          {"mem": mem_fd, "request": request}, [],
                                          reader.FIELD_OUTPUT)
                finally:
                    os.close(output)
                    if "fields" not in self.helpers:
                        os.close(result)
            finally:
                os.close(request)
            os.set_blocking(writer, False)
            self.begin_raw = canonical(begin)
            deny(len(self.begin_raw) <= reader.FIELD_INPUT, "field_request_limit")
            self._send_frame(writer, self.begin_raw, helper)
            admit = None

            def has_head():
                nonlocal admit
                admit = field_receipts(bytes(helper.output), begin, maps, self.abi, head_only=True)
                return admit is not None

            helper.until(has_head)
            self.admit_raw = canonical(admit)
            deny(len(self.begin_raw) + len(self.admit_raw) <= reader.FIELD_INPUT,
                 "field_request_limit")
            self._send_frame(writer, self.admit_raw, helper)
            raw = self._completed(helper)
            derived, self.reads, state = field_receipts(raw, begin, maps, self.abi)
            deny(derived == admit, "field_admission_changed")
        self._close_helper(helper)
        self._require_helper_closed(helper)
        return state, [*maps.global_maps, admit["map"]]

    def observe(self):
        deny(threading.current_thread() is threading.main_thread()
             and threading.active_count() == 1, "main_thread_owner_required")
        deny(type(self.child) is subprocess.Popen and self.child.returncode is None
             and type(self.qmp) is ResetQMP and type(self.qmp.wire) is ResetWire,
             "owned_observation_state")
        return self._observe_body(_ResetObservationPort(self.qmp, self.budget))

    def _observe_body(self, port):
        """One descriptor/helper implementation; only the two closed ports enter."""
        import run0_host_cpu_reader as reader
        if type(port) is _ResetObservationPort:
            deny(type(self) is OwnedCPUObservation, "owned_observation_port")
        else:
            from run0_c0_host import _C0ObservationPort, _OwnedC0Observation
            deny(type(port) is _C0ObservationPort and type(self) is _OwnedC0Observation,
                 "owned_observation_port")
        deny(self._observation_port is None, "owned_observation_reuse")
        self._observation_port = port
        self.deadline, self.deadline_ns = port.deadline, port.deadline_ns
        self._time()
        self.peer_raw, self.peer_at_ns = port.peer()
        decode_peer(self.peer_raw, self.child.pid, os.getuid(), os.getgid())
        self.before_bracket, cpu_before, registers_before = port.bracket("before")
        tid = cpu_before[1]
        self.process.update(observer_pid=os.getpid(), qemu_pid=self.child.pid)
        self._time()
        self.sigchld_raw = self.native.sigchld()
        self.sigchld_at_ns = time.monotonic_ns()
        decode_sigchld(self.sigchld_raw)
        try:
            with ExitStack() as cleanup:
                self._time()
                pidfd = os.pidfd_open(self.child.pid)
                cleanup.callback(self._close_fd, pidfd, "pidfd")
                self.process["pidfd_opened_ns"] = time.monotonic_ns()
                self._time()
                self.process["pidfd_before"] = pidfd_check(pidfd)
                flags = os.O_DIRECTORY | os.O_NOFOLLOW
                proc = self._open("/proc", cleanup, flags)
                procdir = self._open(str(self.child.pid), cleanup, flags, dir_fd=proc)
                self._time()
                info = os.fstat(procdir)
                self._time()
                magic = self.native.filesystem_magic(procdir)
                deny(stat.S_ISDIR(info.st_mode) and magic == NATIVE_LAYOUT["proc_super_magic"],
                     "owned_proc_directory")
                self.process["procdir_identity"] = {
                    "dev": info.st_dev, "inode": info.st_ino, "mode": info.st_mode,
                    "statfs_magic": magic,
                }
                self.before = self._metadata(procdir, "before")
                incomplete(not self.secondary_failures, "metadata_descriptor_cleanup")
                pid, ppid, starttime = parse_proc_stat(self.before["stat"])
                deny((pid, ppid) == (self.child.pid, os.getpid()), "owned_proc_parent")
                self.process.update(ppid=ppid, starttime_ticks=starttime)
                maps = reader.admit_host_maps(self.before["maps"], self.before["smaps"],
                                              self.before["exe"], self.abi)
                self._pump()
                with ExitStack() as mem_cleanup:
                    mem = self._open("mem", mem_cleanup, os.O_NOFOLLOW, dir_fd=procdir)
                    self._time()
                    flags = fcntl.fcntl(mem, fcntl.F_GETFL)
                    self._time()
                    descriptor_flags = fcntl.fcntl(mem, fcntl.F_GETFD)
                    deny(flags & os.O_ACCMODE == os.O_RDONLY
                         and descriptor_flags & fcntl.FD_CLOEXEC, "owned_mem_flags")
                    self.process["mem_open"] = {
                        "at_ns": time.monotonic_ns(), "fd": mem, "flags": flags,
                        "access_mode": "O_RDONLY", "cloexec": True,
                    }
                    state, grants = self._fields(mem, maps, tid)
                incomplete(not self.secondary_failures, "mem_descriptor_cleanup")
                self.after = self._metadata(procdir, "after")
                incomplete(not self.secondary_failures, "metadata_descriptor_cleanup")
                deny(parse_proc_stat(self.after["stat"]) == (pid, ppid, starttime),
                     "owned_proc_changed")
                reader.metadata_consistent(self.before, self.after, grants)
                self.after_bracket, cpu_after, registers_after = port.bracket("after")
                incomplete(cpu_after == cpu_before and registers_after == registers_before,
                           port.changed())
                self._time()
                self.process["pidfd_after"] = pidfd_check(pidfd)
                port.field_mode(state)
                self._time()
            incomplete(not self.secondary_failures, "observation_descriptor_cleanup")
            self.state = state
            return state
        finally:
            for helper in self.helpers.values():
                if not helper.closed:
                    self._close_helper(helper)


RESET_OPERATIONS = (
    "qmp_capabilities", "query_commands",
    *("query_status", "query_cpus_fast", "qom_realized", "qom_phys_bits", "hmp_registers") * 2,
    "quit",
)


def qmp_frames(raw, *, outgoing=False):
    """Decode complete exact reset wire frames with directional offsets."""
    deny(type(raw) is bytes and 0 < len(raw) <= 1024 * 1024, "qmp_wire_limit")
    offset, frames = 0, []
    while offset < len(raw):
        boundary = raw.find(b"\r\n", offset)
        if boundary == -1:
            deny(outgoing, "qmp_wire_partial")
            boundary = next_offset = len(raw)
        else:
            next_offset = boundary + 2
        frame = raw[offset:boundary]
        deny(frame and b"\r" not in frame and b"\n" not in frame and len(frames) < 128,
             "qmp_wire_framing")
        frames.append((base.decode_frame(frame), offset,
                       (next_offset if outgoing else boundary) - offset))
        offset = next_offset
    return frames


def slice_ref(ref, offset, length):
    return {"blob": ref, "offset": offset, "length": length}


def is_qmp_shutdown(value):
    return (
        set(value) == {"event", "timestamp", "data"} and value["event"] == "SHUTDOWN"
        and type(value["timestamp"]) is dict
        and canonical(value["data"]) == canonical({"guest": False, "reason": "host-qmp-quit"})
    )


def reset_control_index(run_id, profile_sha, raw_in, raw_out, in_ref, out_ref,
                        operation_times, event_times):
    """Reconstruct reset operations from wire bytes, then bind the reported clocks."""
    requests = qmp_frames(raw_out, outgoing=True)
    incoming = qmp_frames(raw_in)
    deny(len(requests) == len(operation_times) == len(RESET_OPERATIONS), "qmp_inventory")
    greeting, _, _ = incoming[0]
    deny(set(greeting) == {"QMP"} and type(greeting["QMP"]) is dict, "qmp_greeting")
    next_reply = 1
    operations, events, cpus, registers = [], [], [], []
    last = 0
    path = None
    for seq, (name, (request, offset, size), (started, finished)) in enumerate(
        zip(RESET_OPERATIONS, requests, operation_times, strict=True), 1,
    ):
        deny(exact_int(started, max(1, last), (1 << 63) - 1)
             and exact_int(finished, started, min((1 << 63) - 1, started + 5_000_000_000)),
             "qmp_clock_order")
        last = finished
        execute = name.replace("_", "-")
        args = None
        if name == "qmp_capabilities":
            execute = name
        elif name in ("qom_realized", "qom_phys_bits"):
            execute = "qom-get"
            args = {"path": path, "property": name.removeprefix("qom_").replace("_", "-")}
        elif name == "hmp_registers":
            execute = "human-monitor-command"
            args = {"command-line": "info registers"}
        expected = {"execute": execute, "id": seq}
        if args is not None:
            expected["arguments"] = args
        deny(request == expected and exact_int(request.get("id"), seq, seq)
             and raw_out[offset:offset + size].endswith(b"\r\n") == (name != "quit"),
             "qmp_request_identity")
        incomplete(next_reply < len(incoming), "qmp_reply_missing")
        response, pos, count = incoming[next_reply]
        next_reply += 1
        if "event" in response:
            deny(name == "quit" and not events and len(event_times) == 1
                 and is_qmp_shutdown(response)
                 and exact_int(event_times[0], started, finished), "qmp_unexpected_event")
            events.append({"seq": 1, "protocol": "qmp", "received_ns": event_times[0],
                           "wire": slice_ref(in_ref, pos, count), "name": "SHUTDOWN"})
            incomplete(next_reply < len(incoming), "qmp_reply_missing")
            response, pos, count = incoming[next_reply]
            next_reply += 1
        deny(set(response) == {"return", "id"}
             and exact_int(response["id"], seq, seq), "qmp_response_identity")
        value = response["return"]
        if name in ("qmp_capabilities", "quit"):
            deny(value == {}, "qmp_empty_response")
        elif name == "query_commands":
            required = {"qmp_capabilities", "query-commands", "query-status", "query-cpus-fast",
                        "quit", "qom-get", "human-monitor-command"}
            deny(type(value) is list and all(
                type(row) is dict and set(row) == {"name"} and type(row["name"]) is str
                for row in value
            ) and required <= {row["name"] for row in value}, "qmp_command_inventory")
        elif name == "query_status":
            incomplete(type(value) is dict and value.get("running") is False
                       and value.get("status") == "prelaunch", "prelaunch_unavailable")
        elif name == "query_cpus_fast":
            path = cpu_path(value)
            tid = value[0]["thread-id"]
            deny(exact_int(tid, 1, MAX_PID), "qmp_host_tid")
        elif name == "qom_realized":
            deny(value is True, "qmp_cpu_realized")
        elif name == "qom_phys_bits":
            cpus.append((path, tid, realized_width(True, value)))
        elif name == "hmp_registers":
            reset_registers(value)
            registers.append(value)
        operations.append({
            "seq": seq, "protocol": "qmp", "operation": name,
            "request": slice_ref(out_ref, offset, size),
            "response": slice_ref(in_ref, pos, count),
            "started_ns": started, "finished_ns": finished, "result": "ok",
        })
    if next_reply + 1 == len(incoming) and not events and len(event_times) == 1:
        response, pos, count = incoming[next_reply]
        deny(is_qmp_shutdown(response) and exact_int(event_times[0], last, (1 << 63) - 1),
             "qmp_unexpected_late_event")
        events.append({"seq": 1, "protocol": "qmp", "received_ns": event_times[0],
                       "wire": slice_ref(in_ref, pos, count), "name": "SHUTDOWN"})
        next_reply += 1
    deny(next_reply == len(incoming) and len(event_times) == len(events), "qmp_wire_unconsumed")
    incomplete(cpus[0] == cpus[1] and registers[0] == registers[1], "reset_bracket_changed")

    def bracket(status):
        return {"status_seq": status, "cpu_seq": status + 1, "realized_seq": status + 2,
                "phys_bits_seq": status + 3, "hmp_seq": status + 4}

    return {
        "schema_version": 1, "scope": "reset_witness", "run_id": run_id,
        "profile_sha256": profile_sha, "clock": "host_monotonic_ns",
        "raw_qmp_in_ref": in_ref, "raw_qmp_out_ref": out_ref,
        "raw_rsp_in_ref": None, "raw_rsp_out_ref": None,
        "operations": operations, "events": events, "before": bracket(3), "after": bracket(8),
    }, cpus[0][1]


def json_index(ref, blobs, fields, reason, limit=REPORT_LIMIT):
    index = strict_json(retained_blob(ref, blobs, limit), limit)
    object_fields(index, fields, reason)
    deny(exact_int(index["schema_version"], 1, 1), reason)
    return index


def metadata_index(ref, blobs, phase):
    import run0_host_cpu_reader as reader

    limits = {"stat": 4096, "maps": reader.MAP_LIMIT, "smaps": reader.SMAP_LIMIT,
              "mountinfo": reader.MOUNT_LIMIT, "exe_identity": 4096}
    index = json_index(ref, blobs, (
        "schema_version", "phase", "reader_pid", "started_ns", "finished_ns",
        *(f"{role}_ref" for role in limits), "wire_ref", "stderr_ref", "wait_role",
    ), "metadata_index")
    started, finished = index["started_ns"], index["finished_ns"]
    deny(index["phase"] == phase and index["wait_role"] == f"metadata_{phase}"
         and exact_int(index["reader_pid"], 1, MAX_PID)
         and exact_int(started, 1, (1 << 63) - 1)
         and exact_int(finished, started, (1 << 63) - 1), "metadata_index_values")
    wire = retained_blob(index["wire_ref"], blobs, reader.META_LIMIT)
    retained_blob(index["stderr_ref"], blobs, 16384)
    value = reader.parse_metadata_output(wire)
    offset = 0
    for role, limit in limits.items():
        length, = struct.unpack_from(">I", wire, offset)
        offset += 4
        exact = retained_blob(index[f"{role}_ref"], blobs, limit)
        deny(exact == wire[offset:offset + length], "metadata_frame_binding")
        offset += length
    return index, value


def field_index(ref, blobs, maps, abi, tid):
    import run0_host_cpu_reader as reader

    index = json_index(ref, blobs, (
        "schema_version", "nonce", "begin_ref", "admit_cpu_ref", "output_ref",
        "stderr_ref", "helper_pid", "deadline_ns", "reads", "wait_role",
    ), "field_index")
    deny(index["wait_role"] == "fields" and exact_int(index["helper_pid"], 1, MAX_PID)
         and exact_int(index["deadline_ns"], 1, (1 << 63) - 1)
         and type(index["nonce"]) is str and HASH.fullmatch(index["nonce"]), "field_index_values")
    begin_raw = retained_blob(index["begin_ref"], blobs, reader.FIELD_INPUT)
    admit_raw = retained_blob(index["admit_cpu_ref"], blobs, reader.FIELD_INPUT)
    deny(len(begin_raw) + len(admit_raw) <= reader.FIELD_INPUT, "field_request_limit")
    begin = {"kind": "begin", "version": 1, "nonce": index["nonce"],
             "source_sha256": reader.ABI_SHA256, "deadline_ns": index["deadline_ns"],
             "load_bias": maps.load_bias, "expected_cpu_index": 0,
             "expected_thread_id": tid, "global_maps": list(maps.global_maps)}
    deny(begin_raw == canonical(begin), "field_begin_binding")
    raw = retained_blob(index["output_ref"], blobs, reader.FIELD_OUTPUT)
    retained_blob(index["stderr_ref"], blobs, 16384)
    admit, rows, state = field_receipts(raw, begin, maps, abi)
    deny(admit_raw == canonical(admit), "field_grant_binding")
    for row in rows:
        for name in ("started_wire", "finished_wire"):
            row[name] = slice_ref(index["output_ref"], *row[name])
    deny(canonical(index["reads"]) == canonical(rows), "field_read_index_binding")
    return index, rows, state, [*maps.global_maps, admit["map"]]


WAIT_ROLES = ("qemu", "metadata_before", "fields", "metadata_after")


def lifecycle_index(ref, blobs, waits):
    index = json_index(ref, blobs, ("schema_version", "rows"), "lifecycle_index")
    rows = index["rows"]
    deny(type(rows) is list and 0 < len(rows) <= 64, "lifecycle_rows")
    deny(type(waits) is list and len(waits) == len(WAIT_ROLES), "wait_inventory")
    pids = {}
    for wait, role in zip(waits, WAIT_ROLES, strict=True):
        object_fields(wait, ("role", "pid", "started", "reaped", "returncode", "actions",
                             "grace"), "wait_fields")
        deny(wait["role"] == role and exact_int(wait["pid"], 1, MAX_PID), "wait_role")
        incomplete(wait["started"] is True and wait["reaped"] is True
                   and exact_int(wait["returncode"], 0, 0) and wait["actions"] == []
                   and wait["grace"] == ("exited" if role == "qemu" else "not_attempted"),
                   "owned_wait_incomplete")
        pids[role] = wait["pid"]
    deny(len(set(pids.values())) == len(WAIT_ROLES), "wait_pid_overlap")
    lifecycle = {role: {} for role in WAIT_ROLES}
    last = 0
    for seq, row in enumerate(rows, 1):
        object_fields(row, ("seq", "role", "pid", "operation", "started_ns", "finished_ns",
                            "result", "returncode", "errno"), "lifecycle_fields")
        role, op = row["role"], row["operation"]
        deny(type(role) is str and role in lifecycle and type(op) is str
             and op in ("spawn", "wait", "close") and op not in lifecycle[role]
             and exact_int(row["seq"], seq, seq) and exact_int(row["pid"], pids[role], pids[role])
             and exact_int(row["started_ns"], max(1, last), (1 << 63) - 1)
             and exact_int(row["finished_ns"], row["started_ns"], (1 << 63) - 1)
             and row["result"] == "ok" and row["errno"] is None
             and (exact_int(row["returncode"], 0, 0) if op == "wait"
                  else row["returncode"] is None), "lifecycle_row_binding")
        last = row["finished_ns"]
        lifecycle[role][op] = row
    for role in WAIT_ROLES:
        incomplete(tuple(lifecycle[role]) == ("spawn", "wait", "close"),
                   "lifecycle_missing_receipt")
    return lifecycle


def streams_index(ref, blobs, control, before, reads, after):
    index = json_index(ref, blobs, ("schema_version", "rows"), "streams_index")
    names = {
        "qmp": control["raw_qmp_in_ref"], "serial": None, "debug": None,
        "qemu_stdout": None, "qemu_stderr": None,
        "metadata_before_stdout": before["wire_ref"], "metadata_before_stderr": before["stderr_ref"],
        "fields_stdout": reads["output_ref"], "fields_stderr": reads["stderr_ref"],
        "metadata_after_stdout": after["wire_ref"], "metadata_after_stderr": after["stderr_ref"],
    }
    if control["scope"] == "shared_c0":
        names["rsp"] = control["raw_rsp_in_ref"]
    rows = index["rows"]
    deny(type(rows) is list and len(rows) == len(names), "streams_inventory")
    seen = set()
    for row in rows:
        object_fields(row, ("name", "raw_ref", "eof", "error"), "stream_fields")
        name = row["name"]
        deny(type(name) is str and name in names and name not in seen, "stream_name")
        seen.add(name)
        deny(names[name] is None or row["raw_ref"] == names[name], "stream_reference")
        retained_blob(row["raw_ref"], blobs, OUTPUT_LIMIT if name == "rsp" else 2 * 1024 * 1024)
        incomplete(row["eof"] is True and row["error"] is None, "stream_incomplete")


def checked_process(report, blobs, abi_index, plan, before, after, field):
    pid_max = (1 << 63) - 1
    native_ref = abi_index["native_abi_ref"]
    process = json_index(report["process_ref"], blobs, (
        "schema_version", "observer_pid", "qemu_pid", "ppid", "starttime_ticks",
        "pidfd_opened_ns", "pidfd_before", "pidfd_after", "procdir_identity",
        "mem_open", "mem_closed_ns", "exe_before_ref", "exe_after_ref", "lifecycle_ref",
    ), "process_index")
    observer_pid, qemu_pid = process["observer_pid"], process["qemu_pid"]
    deny(exact_int(observer_pid, 1, MAX_PID) and exact_int(qemu_pid, 1, MAX_PID)
         and qemu_pid != observer_pid and exact_int(process["ppid"], observer_pid, observer_pid)
         and exact_int(process["starttime_ticks"], 1, MAX_U64), "process_identity")
    for name, metadata in (("before", before), ("after", after)):
        deny(process[f"exe_{name}_ref"] == metadata["exe_identity_ref"], "process_exe_ref")
        raw = retained_blob(metadata["stat_ref"], blobs, 4096)
        deny(parse_proc_stat(raw) == (qemu_pid, observer_pid, process["starttime_ticks"]),
             "process_stat_identity")

    peer = json_index(report["peer_ref"], blobs, (
        "schema_version", "socket_role", "socket_path", "observed_ns", "raw_ref",
        "pid", "uid", "gid", "abi_ref",
    ), "peer_index")
    deny(peer["socket_role"] == "qmp" and peer["socket_path"] == "qmp.sock"
         and peer["abi_ref"] == native_ref and exact_int(peer["observed_ns"], 1, pid_max)
         and exact_int(peer["pid"], qemu_pid, qemu_pid) and exact_int(peer["uid"], 0, 0xffffffff)
         and exact_int(peer["gid"], 0, 0xffffffff), "peer_binding")
    raw_peer = retained_blob(peer["raw_ref"], blobs, 12)
    actual_peer = decode_peer(raw_peer, qemu_pid, plan["uid"], plan["gid"])
    deny(actual_peer == (peer["pid"], peer["uid"], peer["gid"]), "peer_index_identity")

    sigchld = json_index(report["sigchld_ref"], blobs, (
        "schema_version", "before_spawn", "before_open", "sole_reaper_pid",
        "no_concurrent_reaper", "policy_ref",
    ), "sigchld_index")
    deny(exact_int(sigchld["sole_reaper_pid"], observer_pid, observer_pid)
         and sigchld["no_concurrent_reaper"] is True
         and sigchld["policy_ref"] == report["observer_ref"], "sigchld_owner")
    signal_times = []
    for role in ("before_spawn", "before_open"):
        row = object_fields(sigchld[role], (
            "observed_ns", "raw_ref", "abi_ref", "handler", "flags",
            "no_cld_wait_mask", "observer_pid",
        ), "sigchld_fields")
        deny(row["abi_ref"] == native_ref and exact_int(row["observed_ns"], 1, pid_max)
             and exact_int(row["observer_pid"], observer_pid, observer_pid)
             and exact_int(row["no_cld_wait_mask"], 2, 2), "sigchld_binding")
        handler, flags = decode_sigchld(retained_blob(row["raw_ref"], blobs, 152))
        deny(exact_int(row["handler"], handler, handler) and exact_int(row["flags"], flags, flags),
             "sigchld_identity")
        signal_times.append(row["observed_ns"])

    procdir = object_fields(process["procdir_identity"],
                            ("dev", "inode", "mode", "statfs_magic"), "procdir_fields")
    deny(exact_int(procdir["dev"], 0, MAX_U64) and exact_int(procdir["inode"], 1, MAX_U64)
         and exact_int(procdir["mode"], 1, 0xffffffff) and stat.S_ISDIR(procdir["mode"])
         and exact_int(procdir["statfs_magic"], 40864, 40864), "procdir_binding")
    mem = object_fields(process["mem_open"],
                         ("at_ns", "fd", "flags", "access_mode", "cloexec"), "mem_fields")
    deny(exact_int(mem["at_ns"], 1, pid_max) and exact_int(mem["fd"], 0, MAX_PID)
         and exact_int(mem["flags"], 0, 0xffffffff)
         and mem["flags"] & os.O_ACCMODE == os.O_RDONLY
         and mem["access_mode"] == "O_RDONLY" and mem["cloexec"] is True
         and exact_int(process["mem_closed_ns"], mem["at_ns"], pid_max), "mem_binding")
    deny(exact_int(process["pidfd_opened_ns"], signal_times[1], pid_max), "pidfd_open_clock")
    for name in ("before", "after"):
        check = object_fields(process[f"pidfd_{name}"], ("observed_ns", "readable", "hangup",
                                                       "error"), "pidfd_fields")
        incomplete(check["readable"] is False and check["hangup"] is False
                   and check["error"] is None, "pidfd_not_live")
        deny(exact_int(check["observed_ns"], process["pidfd_opened_ns"], field["deadline_ns"]),
             "pidfd_clock")
    return process, peer, signal_times


def validate_control_index(ref, blobs, binding, *, retained_runtime=False,
                           invocation_profile=base.INVOCATION_PROFILE):
    index = json_index(ref, blobs, (
        "schema_version", "scope", "run_id", "profile_sha256", "clock",
        "raw_qmp_in_ref", "raw_qmp_out_ref", "raw_rsp_in_ref", "raw_rsp_out_ref",
        "operations", "events", "before", "after",
    ), "control_index")
    if binding["context"] == "c0":
        return shared_control_index(index, blobs, binding, retained_runtime=retained_runtime,
                                    invocation_profile=invocation_profile)
    deny(index["scope"] == "reset_witness" and index["raw_rsp_in_ref"] is None
         and index["raw_rsp_out_ref"] is None, "reset_control_scope")
    ops, events = index["operations"], index["events"]
    deny(type(ops) is list and len(ops) == len(RESET_OPERATIONS)
         and type(events) is list and len(events) <= 1, "control_inventory")
    for row in ops:
        object_fields(row, ("seq", "protocol", "operation", "request", "response",
                            "started_ns", "finished_ns", "result"), "control_operation")
    for row in events:
        object_fields(row, ("seq", "protocol", "received_ns", "wire", "name"), "control_event")
    in_ref, out_ref = index["raw_qmp_in_ref"], index["raw_qmp_out_ref"]
    raw_in = retained_blob(in_ref, blobs, 1024 * 1024)
    raw_out = retained_blob(out_ref, blobs, 1024 * 1024)
    derived, tid = reset_control_index(
        binding["run_id"], binding["profile_sha256"], raw_in, raw_out, in_ref, out_ref,
        [(op["started_ns"], op["finished_ns"]) for op in ops],
        [event["received_ns"] for event in events],
    )
    deny(canonical(index) == canonical(derived)
         and exact_int(binding["qmp_thread_id"], tid, tid)
         and exact_int(binding["control_before_seq"], derived["before"]["status_seq"],
                       derived["before"]["status_seq"])
         and exact_int(binding["control_after_seq"], derived["after"]["status_seq"],
                       derived["after"]["status_seq"]), "control_binding")
    return index, tid


def checked_chronology(control, lifecycle, process, peer, sig_times, before, after, field, rows):
    bspawn, bwait, bclose = lifecycle["metadata_before"].values()
    fspawn, fwait, fclose = lifecycle["fields"].values()
    aspawn, await_, aclose = lifecycle["metadata_after"].values()
    vspawn, vwait, vclose = lifecycle["qemu"].values()
    for metadata, spawn, wait in ((before, bspawn, bwait), (after, aspawn, await_)):
        deny(metadata["reader_pid"] == spawn["pid"]
             and metadata["started_ns"] == spawn["started_ns"]
             and metadata["finished_ns"] == wait["finished_ns"], "metadata_lifecycle")
    deny(field["helper_pid"] == fspawn["pid"] and process["qemu_pid"] == vspawn["pid"],
         "process_lifecycle")
    ops = control["operations"]
    before_status = ops[control["before"]["status_seq"] - 1]
    before_hmp = ops[control["before"]["hmp_seq"] - 1]
    after_status = ops[control["after"]["status_seq"] - 1]
    after_hmp = ops[control["after"]["hmp_seq"] - 1]
    clock = [
        sig_times[0], vspawn["started_ns"], vspawn["finished_ns"], ops[0]["started_ns"],
        ops[1]["finished_ns"], peer["observed_ns"], before_status["started_ns"],
        before_hmp["finished_ns"], sig_times[1], process["pidfd_opened_ns"],
        process["pidfd_before"]["observed_ns"], bspawn["started_ns"],
        bclose["finished_ns"], process["mem_open"]["at_ns"], fspawn["started_ns"],
        fspawn["finished_ns"], rows[0]["started_ns"], rows[-1]["finished_ns"],
        fwait["started_ns"], fclose["finished_ns"], process["mem_closed_ns"],
        aspawn["started_ns"], aclose["finished_ns"], after_status["started_ns"],
        after_hmp["finished_ns"], process["pidfd_after"]["observed_ns"],
        field["deadline_ns"],
    ]
    vm_seconds = 60 if control["scope"] == "reset_witness" else 90
    deny(clock == sorted(clock)
         and field["deadline_ns"] <= peer["observed_ns"] + 5_000_000_000
         and field["deadline_ns"] <= vspawn["started_ns"] + (vm_seconds - 5) * 1_000_000_000
         and process["pidfd_after"]["observed_ns"] <= ops[-1]["started_ns"]
         <= ops[-1]["finished_ns"] <= vwait["started_ns"]
         and vclose["finished_ns"] <= vspawn["started_ns"] + vm_seconds * 1_000_000_000,
         "witness_clock_binding")
    deny(all(event["received_ns"] <= vclose["started_ns"] for event in control["events"]),
         "control_event_after_close")
    if control["scope"] == "shared_c0":
        first_read = next(op for op in ops if op["operation"] == "physical_read")
        stop = next(event for event in control["events"] if event["protocol"] == "rsp")
        deny(process["pidfd_after"]["observed_ns"] <= first_read["started_ns"]
             and stop["received_ns"] <= ops[-2]["finished_ns"]
             <= stop["received_ns"] + 60_000_000_000
             and ops[-2]["finished_ns"] <= vspawn["started_ns"] + 85_000_000_000,
             "shared_witness_clock")


ABI_BLOB_LIMITS = {
    "qemu_ref": 64 * 1024 * 1024, "debug_ref": 512 * 1024 * 1024,
    "dwz_ref": 64 * 1024 * 1024, "debug_package_ref": 512 * 1024 * 1024,
    "query_script_ref": 65536, "query_result_ref": 1024 * 1024,
    "static_getter_ref": 1024 * 1024, "kernel_observation_ref": 1024 * 1024,
    "qemu_allocation_source_ref": 1024 * 1024, "runtime_dependencies_ref": 1024 * 1024,
    "source_dossier_ref": 65536, "native_abi_ref": 1024 * 1024,
}
RUNTIME_ABI_PINS = {
    "qemu_ref": QEMU_SHA256,
    "debug_ref": "566adc4ebfafd96489ff54c26eb4e163622fbcc1503c1a5dd0f8e8ebbaa465d9",
    "dwz_ref": "03b0774ebe48584e4c825ce63b440975080be2ba4da27efd2165f7775b6c8d8c",
    "debug_package_ref": "388ab63ff3c36d50bea1a52fd18595be0abc2d7794f6d5b41d51be008e63e0b4",
    "qemu_allocation_source_ref": "bef71f240e63dc050e39264d2a3ed8e8499012283d95c5077a29b4c45e177d7f",
    "source_dossier_ref": SOURCE_DOSSIER_SHA256,
}
KERNEL_SOURCE_PINS = {
    "fs/proc/base.c": "9481f79cada6bbfde39b396e4068b068dd5fb6e5fa6b867fec357f3635599525",
    "mm/memory.c": "86f884d12f88390d71a8b92818bb1455a88da991f23cb9c9f86a40e5a6e0bcb1",
    "mm/mmap.c": "9fa0f5ec5ef72f9e8976f488dca302283db04e06d7130d60682baa1690fa2207",
    "include/linux/mm.h": "68742bab5ce2ff98ade08e1e80241c3595369eb11eb88ceec6e8b239c916dcc6",
    "fs/ext4/file.c": "fe410d6d2fe594f1c0eba95eae3cbe2ab76879cd9147b1d910eb58a338e23040",
    "fs/proc/task_mmu.c": "2cbb688cedfd6af2f3c16ad778f8a29129417cb613687948d587049b9d3d7f88",
}


def resolve_abi(ref, blobs, runtime):
    import run0_host_cpu_reader as reader

    index = json_index(ref, blobs, ("schema_version", "kind", "contract_abi_sha256",
                                   "kernel_source_refs", *ABI_BLOB_LIMITS), "abi_index")
    deny(index["kind"] == "run0_host_cpu_abi_v0"
         and index["contract_abi_sha256"] == reader.ABI_SHA256, "abi_contract_pin")
    values = {name: retained_blob(index[name], blobs, limit)
              for name, limit in ABI_BLOB_LIMITS.items()}
    if runtime:
        for name, digest in RUNTIME_ABI_PINS.items():
            deny(index[name]["sha256"] == digest, "abi_source_pin")
    sources = index["kernel_source_refs"]
    deny(type(sources) is list and len(sources) == len(KERNEL_SOURCE_PINS), "kernel_source_inventory")
    seen = set()
    for row in sources:
        object_fields(row, ("role", "ref"), "kernel_source_fields")
        role = row["role"]
        deny(type(role) is str and role in KERNEL_SOURCE_PINS and role not in seen,
             "kernel_source_role")
        seen.add(role)
        retained_blob(row["ref"], blobs, 2 * 1024 * 1024)
        deny(not runtime or row["ref"]["sha256"] == KERNEL_SOURCE_PINS[role], "kernel_source_pin")
    native_layout_from_index(index["native_abi_ref"], blobs, runtime)
    elf = reader.parse_elf(values["qemu_ref"])
    deny(not runtime or elf.build_id == "0bbe3fc40f3335f9ccdcd61cd96e02bf871f2449", "abi_build_id")
    return index, reader.HostABI(elf, reader.ABI_SHA256)


def validate_complete_report(report_ref, report, blobs):
    import run0_host_cpu_reader as reader

    binding = object_fields(report["binding"], (
        "context", "run_id", "profile_sha256", "cpu_index", "qmp_thread_id", "rsp_thread",
        "stop_id", "stop_ref", "resume_seq", "breakpoint_seq", "control_before_seq",
        "control_after_seq",
    ), "stop_binding")
    deny(binding["context"] in ("reset", "c0") and binding["run_id"] == report["run_id"]
         and exact_int(binding["cpu_index"], 0, 0)
         and type(binding["profile_sha256"]) is str and HASH.fullmatch(binding["profile_sha256"]),
         "binding_identity")
    reset = binding["context"] == "reset"
    if reset:
        deny(binding["stop_id"] == "reset"
             and all(binding[key] is None for key in ("rsp_thread", "stop_ref", "resume_seq",
                                                    "breakpoint_seq")), "reset_stop_binding")
    else:
        deny(binding["stop_id"] == "C0" and binding["rsp_thread"] == "01", "c0_stop_binding")
    runtime = report["origin"] == "retained_runtime"
    profile_bytes = retained_blob(report["profile_ref"], blobs, 65536)
    profile = decode_pinned_profile(profile_bytes) if runtime else strict_json(profile_bytes, 65536)
    deny(type(profile) is dict and entry.profile_digest(profile) == binding["profile_sha256"],
         "profile_binding")
    invocation = profile.get("invocation_profile", base.INVOCATION_PROFILE)
    if runtime:
        incomplete(REVIEWED_LAUNCH_ABI_SHA256 is not None, "runtime_provenance_pending")
        deny(reset or invocation == base.VAPIC_OFF_INVOCATION_PROFILE, "c0_runtime_profile")
        deny(report["abi_ref"]["sha256"] == REVIEWED_LAUNCH_ABI_SHA256, "runtime_abi_pin")
    index, abi = resolve_abi(report["abi_ref"], blobs, runtime)
    deny(report["source_ref"] == index["source_dossier_ref"], "source_binding")
    c0_runtime = runtime and not reset
    plan_fields = WITNESS_PLAN_FIELDS
    if c0_runtime:
        plan_fields += ("context", *C0_PLAN_INPUT_FIELDS, "prior_inputs_sha256")
    plan = json_index(report["plan_ref"], blobs, plan_fields, "plan_index")
    for name in ("inputs", "run"):
        deny(type(plan[name]) is str, "plan_path")
        base.safe_path(Path(plan[name]))
    deny(plan["kind"] == ("run0_c0_owned_capture_plan_v0" if c0_runtime
                               else "run0_host_cpu_witness_plan_v0")
         and Path(plan["run"]).name == report["run_id"]
         and plan["argv"] == base.build_argv(Path(plan["inputs"]), Path(plan["run"]), invocation)
         and plan["profile_sha256"] == report["profile_ref"]["sha256"]
         and plan["abi_sha256"] == report["abi_ref"]["sha256"]
         and plan["source_dossier_sha256"] == report["source_ref"]["sha256"], "plan_binding")
    if c0_runtime:
        validate_c0_plan_inputs(plan, report["profile_ref"], index, blobs, abi_ref=report["abi_ref"])
    if runtime:
        verify_runtime_observer(report, blobs, profile, plan, index)
    else:
        deny(plan["observer_ref"] == report["observer_ref"], "observer_plan_binding")
        retained_blob(report["observer_ref"], blobs, 65536)
    control, tid = validate_control_index(report["control_ref"], blobs, binding,
                                          retained_runtime=runtime, invocation_profile=invocation)
    before, bvalue = metadata_index(report["metadata_before_ref"], blobs, "before")
    after, avalue = metadata_index(report["metadata_after_ref"], blobs, "after")
    for metadata in (bvalue, avalue):
        reader.bind_mount_path(metadata["mountinfo"], plan["argv"][0], metadata["exe"])
        actual = {name: metadata["exe"][name] for name in ("device", "inode", "size")}
        deny(canonical(actual) == canonical(plan["launch_identity"]), "launch_exe_identity")
    maps = reader.admit_host_maps(bvalue["maps"], bvalue["smaps"], bvalue["exe"], abi)
    field, rows, state, grants = field_index(report["reads_ref"], blobs, maps, abi, tid)
    reader.metadata_consistent(bvalue, avalue, grants)
    incomplete(state["cpl"] == 0 and state["cs64"] is not reset
               and state["lma"] is not reset, "witness_field_mode")
    deny(canonical(report["state"]) == canonical(state), "state_binding")
    process, peer, signal_times = checked_process(report, blobs, index, plan, before, after, field)
    termination = report["termination"]
    lifecycle = lifecycle_index(process["lifecycle_ref"], blobs, termination["waits"])
    checked_chronology(control, lifecycle, process, peer, signal_times, before, after, field, rows)
    streams_index(termination["streams_ref"], blobs, control, before, field, after)
    witness_output_size(report_ref, report, blobs, process, plan, index, runtime)
    witness = object.__new__(ValidatedHostState)
    for name, value in (
        ("origin", report["origin"]), ("report_ref", dict(report_ref)),
        ("binding", binding), ("state", state), ("final_status", "PASS"),
    ):
        object.__setattr__(witness, name, immutable(value))
    return witness


def witness_output_size(report_ref, report, blobs, process, plan, abi, runtime):
    """Charge exact linked output paths once, with source inputs counted separately."""
    index_refs = [report[key] for key in (
        "metadata_before_ref", "metadata_after_ref", "peer_ref", "sigchld_ref", "process_ref",
        "reads_ref", "control_ref",
    )] + [process["lifecycle_ref"], report["termination"]["streams_ref"]]
    inputs = (report["abi_ref"], report["source_ref"], abi["native_abi_ref"])
    queue = [report_ref, report, plan["observer_ref"], *(
        strict_json(retained_blob(ref, blobs, REPORT_LIMIT), REPORT_LIMIT) for ref in index_refs
    )]
    if runtime:
        observer = strict_json(retained_blob(report["observer_ref"], blobs, 65536), 65536)
        queue.append(observer)
        inputs += (observer["postcheck"]["runtime_ref"], observer["postcheck"]["module_closure_ref"])
    total, found = 0, set()
    while queue:
        value = queue.pop()
        if type(value) in (dict, MappingProxyType):
            if set(value) == {"path", "length", "sha256"}:
                if value not in inputs and value["path"] not in found:
                    found.add(value["path"])
                    total += value["length"]
                    incomplete(total <= OUTPUT_LIMIT, "witness_storage_limit")
            else:
                queue.extend(value.values())
        elif type(value) is list:
            queue.extend(value)


NATIVE_HEADER_PINS = {
    "/usr/include/x86_64-linux-gnu/bits/sigaction.h": "b2f76a26bbfa3668859e8e8a93af9321e14083914df0aa0367cdffaabf4ece81",
    "/usr/include/x86_64-linux-gnu/bits/types/__sigset_t.h": "05291a7d38bb1d0da1ed01c09fe85fa2b1f4d5bc708e06bb930efec672db08d5",
    "/usr/include/x86_64-linux-gnu/bits/socket.h": "0d54fcf79ed8111df5d3580eb4bb662b744f8ffae03206c624ebec84d43f0ea0",
    "/usr/include/x86_64-linux-gnu/bits/signum-generic.h": "0a27898a4f720aeabcafb45eba42b0cd6b9593a6e77bd87019969eda94cf435b",
    "/usr/include/x86_64-linux-gnu/bits/signum-arch.h": "ef1475e1546024be5b12edea07ed215ce3a9b004b1266ba7a3b5e40fb7bbe986",
    "/usr/include/x86_64-linux-gnu/bits/statfs.h": "063abffe73524326242b3e46d1d13912d35462e758c41f7658959fd76f7ab70b",
    "/usr/include/x86_64-linux-gnu/sys/statfs.h": "3e01283fc2e908ee350239e290a1c6d002c6199d854a6f23b94cc5ff98a9ac40",
    "/usr/include/x86_64-linux-gnu/bits/types.h": "371847ed3adab1c19db392034f6a22407d321b1dc5f2440563f4b0b8b6c5386b",
    "/usr/include/x86_64-linux-gnu/bits/wordsize.h": "716d8459074e2a082d65a28192b32eddbfd7587348372395b1c283a723ae4c18",
    "/usr/include/x86_64-linux-gnu/bits/typesizes.h": "047ee5ab17a95364c4b0f14c3eb0750e84e457c408f9a65a6c225ece585e0c14",
    "/usr/include/linux/magic.h": "223b3af6647ffa78cdd83678b8e5b53f92dc7105837556f10629cacbd6e6918e",
}


def native_layout_from_index(ref, blobs, runtime):
    index = json_index(ref, blobs, (
        "schema_version", "kind", "layout_ref", "layout_source_ref", "layout_binary_ref",
        "headers", "package_observation_ref", "parser_source_refs",
    ), "native_abi_index")
    deny(index["kind"] == "run0_host_cpu_native_abi_v0", "native_abi_kind")
    layout_raw = retained_blob(index["layout_ref"], blobs, 4096)
    deny(not runtime or index["layout_ref"]["sha256"] == NATIVE_LAYOUT_SHA256,
         "native_layout_source_pin")
    layout = strict_json(layout_raw, 4096)
    validate_native_layout(layout)
    retained_blob(index["layout_source_ref"], blobs, 65536)
    retained_blob(index["layout_binary_ref"], blobs, 1024 * 1024)
    retained_blob(index["package_observation_ref"], blobs, 1024 * 1024)
    rows = index["headers"]
    deny(type(rows) is list and len(rows) == len(NATIVE_HEADER_PINS), "native_header_count")
    seen = set()
    for row in rows:
        object_fields(row, ("role", "ref"), "native_header_fields")
        role = row["role"]
        deny(type(role) is str and role in NATIVE_HEADER_PINS and role not in seen,
             "native_header_role")
        seen.add(role)
        retained_blob(row["ref"], blobs, 1024 * 1024)
        deny(not runtime or row["ref"]["sha256"] == NATIVE_HEADER_PINS[role], "native_header_pin")
    parser = index["parser_source_refs"]
    deny(type(parser) is list and len(parser) == 1, "native_parser_source_count")
    object_fields(parser[0], ("role", "ref"), "native_parser_source_fields")
    deny(parser[0]["role"] == "linux_dev_t", "native_parser_source_role")
    retained_blob(parser[0]["ref"], blobs, 1024 * 1024)
    return layout


def retain_metadata(put, phase, pid, started, finished, wire, stderr):
    import run0_host_cpu_reader as reader

    reader.parse_metadata_output(wire)
    index = {"schema_version": 1, "phase": phase, "reader_pid": pid,
             "started_ns": started, "finished_ns": finished, "wait_role": f"metadata_{phase}",
             "wire_ref": put(f"metadata-{phase}.bin", wire),
             "stderr_ref": put(f"metadata-{phase}-stderr.bin", stderr)}
    offset = 0
    for name in ("stat", "maps", "smaps", "mountinfo", "exe_identity"):
        length, = struct.unpack_from(">I", wire, offset)
        offset += 4
        index[f"{name}_ref"] = put(f"metadata-{phase}-{name}.bin", wire[offset:offset + length])
        offset += length
    return put(f"metadata-{phase}.json", canonical(index)), index


def retain_fields(put, pid, begin_raw, admit_raw, output, stderr, reads):
    begin = strict_json(begin_raw, 8192)
    output_ref = put("fields-output.bin", output)
    rows = []
    for original in reads:
        row = dict(original)
        for name in ("started_wire", "finished_wire"):
            row[name] = slice_ref(output_ref, *row[name])
        rows.append(row)
    index = {"schema_version": 1, "nonce": begin["nonce"], "helper_pid": pid,
             "deadline_ns": begin["deadline_ns"], "wait_role": "fields", "reads": rows,
             "begin_ref": put("fields-begin.json", begin_raw),
             "admit_cpu_ref": put("fields-admit.json", admit_raw),
             "output_ref": output_ref, "stderr_ref": put("fields-stderr.bin", stderr)}
    return put("fields.json", canonical(index)), index


def shared_qmp_event_timestamp(value):
    timestamp = value.get("timestamp")
    return (type(timestamp) is dict and set(timestamp) == {"seconds", "microseconds"}
            and exact_int(timestamp["seconds"], 0, (1 << 63) - 1)
            and exact_int(timestamp["microseconds"], 0, 999999))


def shared_qmp_boot_event(value, invocation_profile=base.INVOCATION_PROFILE):
    # The exact profile selects one source/observed canonical RTC path. VAPIC
    # consumes an earlier unattached device number when enabled; never admit a
    # union of both paths or derive the selected identity from an event itself.
    paths = {base.INVOCATION_PROFILE: "/machine/unattached/device[2]/rtc",
             base.SATA_OFF_INVOCATION_PROFILE: "/machine/unattached/device[2]/rtc",
             base.VAPIC_OFF_INVOCATION_PROFILE: "/machine/unattached/device[1]/rtc"}
    if (type(value) is not dict or type(invocation_profile) is not str
            or invocation_profile not in paths or not shared_qmp_event_timestamp(value)):
        return False
    if value.get("event") in ("RESUME", "STOP"):
        return set(value) == {"event", "timestamp"}
    if value.get("event") != "RTC_CHANGE" or set(value) != {"event", "timestamp", "data"}:
        return False
    data = value["data"]
    return (type(data) is dict and set(data) == {"offset", "qom-path"}
            and exact_int(data["offset"], -(1 << 63), (1 << 63) - 1)
            and data["qom-path"] == paths[invocation_profile])


def verify_shared_qmp(index, blobs, binding, rsp, *, retained_runtime,
                      invocation_profile=base.INVOCATION_PROFILE):
    """Validate all QMP bytes without letting the RSP evidence stand in for QMP."""
    from run0_rsp_capability import parse_flatview

    in_ref, out_ref = index["raw_qmp_in_ref"], index["raw_qmp_out_ref"]
    raw_in = retained_blob(in_ref, blobs, 1024 * 1024)
    raw_out = retained_blob(out_ref, blobs, 1024 * 1024)
    incoming, requests = qmp_frames(raw_in), qmp_frames(raw_out, outgoing=True)
    greeting = incoming[0][0]
    deny(set(greeting) == {"QMP"} and type(greeting["QMP"]) is dict, "qmp_greeting")
    qmp_ops = [op for op in index["operations"] if op["protocol"] == "qmp"]
    qmp_events = [event for event in index["events"] if event["protocol"] == "qmp"]
    deny(len(qmp_ops) == len(requests) and 5 <= len(qmp_ops) <= 32
         and qmp_ops[0]["operation"] == "qmp_capabilities"
         and qmp_ops[1]["operation"] == "query_commands"
         and qmp_ops[-1]["operation"] == "quit", "shared_qmp_inventory")
    path = None
    replies, response_pos, event_count = {}, 1, 0
    shutdown_seq = None
    resume = rsp["operations"][rsp["resume_seq"]]
    boot_events = retained_runtime or any(
        value.get("event") in ("RESUME", "STOP", "RTC_CHANGE") for value, _, _ in incoming[1:]
    )
    initial_status = debug_status = resumed = stopped = False
    previous_reply_ns = 0

    def consume_event(value, offset, length, op, *, tail=False):
        nonlocal event_count, resumed, stopped, shutdown_seq

        name = value.get("event")
        deny(event_count < len(qmp_events), "shared_qmp_event_binding")
        event = qmp_events[event_count]
        deny(event["name"] == name
             and canonical(event["wire"]) == canonical(slice_ref(in_ref, offset, length)),
             "shared_qmp_event_binding")
        event_count += 1
        upper = (1 << 63) - 1 if tail else op["finished_ns"]
        if name == "SHUTDOWN":
            deny(op["operation"] == "quit" and shutdown_seq is None and is_qmp_shutdown(value)
                 and (not boot_events or shared_qmp_event_timestamp(value)),
                 "shared_qmp_event_forbidden")
            deny(exact_int(event["received_ns"], max(previous_reply_ns, op["started_ns"]), upper),
                 "shared_qmp_event_clock")
            shutdown_seq = op["seq"]
            return

        deny(initial_status and resume["seq"] < op["seq"]
             and shared_qmp_boot_event(value, invocation_profile),
             "shared_qmp_event_forbidden")
        lower = max(previous_reply_ns, resume["started_ns"])
        deny(exact_int(event["received_ns"], lower, upper), "shared_qmp_event_clock")
        if name == "RESUME":
            deny(not resumed and not debug_status and not tail, "shared_qmp_event_forbidden")
            resumed = True
        elif name == "STOP":
            deny(resumed and not stopped and not debug_status and not tail,
                 "shared_qmp_event_forbidden")
            stopped = True
        else:
            # The RTC monitor timer can deliver a queued notification after STOP
            # or during quit. Its wall-clock timestamp is not a stop receipt.
            deny(resumed, "shared_qmp_event_forbidden")

    for qid, (op, (request, offset, length)) in enumerate(zip(qmp_ops, requests, strict=True), 1):
        name = op["operation"]
        execute = {"qmp_capabilities": "qmp_capabilities", "query_commands": "query-commands",
                   "query_status": "query-status", "query_cpus_fast": "query-cpus-fast",
                   "qom_realized": "qom-get", "qom_phys_bits": "qom-get",
                   "hmp_registers": "human-monitor-command",
                   "hmp_flatview": "human-monitor-command", "quit": "quit"}.get(name)
        deny(execute is not None and (name != "qmp_capabilities" or qid == 1)
             and (name != "quit" or qid == len(qmp_ops)), "shared_qmp_operation")
        expected = {"execute": execute, "id": qid}
        if execute == "qom-get":
            deny(path is not None, "shared_qom_cpu_unavailable")
            expected["arguments"] = {"path": path, "property": name[4:].replace("_", "-")}
        elif execute == "human-monitor-command":
            expected["arguments"] = {
                "command-line": "info registers" if name == "hmp_registers" else "info mtree -f",
            }
        deny(request == expected and exact_int(request["id"], qid, qid)
             and raw_out[offset:offset + length].endswith(b"\r\n") == (name != "quit")
             and canonical(op["request"]) == canonical(slice_ref(out_ref, offset, length)),
             "shared_qmp_request_binding")
        incomplete(response_pos < len(incoming), "shared_qmp_reply_missing")
        result, offset, length = incoming[response_pos]
        response_pos += 1
        while "event" in result:
            consume_event(result, offset, length, op)
            incomplete(response_pos < len(incoming), "shared_qmp_reply_missing")
            result, offset, length = incoming[response_pos]
            response_pos += 1
        deny(set(result) == {"id", "return"} and exact_int(result["id"], qid, qid)
             and canonical(op["response"]) == canonical(slice_ref(in_ref, offset, length)),
             "shared_qmp_response_binding")
        previous_reply_ns = op["finished_ns"]
        value = result["return"]
        if name in ("qmp_capabilities", "quit"):
            deny(value == {}, "shared_qmp_empty_reply")
        elif name == "query_commands":
            deny(type(value) is list and all(type(row) is dict and set(row) == {"name"}
                                            and type(row["name"]) is str for row in value),
                 "shared_qmp_command_inventory")
        elif name == "query_status":
            incomplete(type(value) is dict and value.get("running") is False
                       and value.get("status") in ("prelaunch", "debug"), "shared_qmp_running")
            if value["status"] == "debug":
                deny(not boot_events or resume["seq"] < op["seq"], "shared_qmp_debug_order")
                incomplete(not boot_events or stopped, "shared_qmp_boot_events_missing")
                debug_status = True
            elif op["seq"] < resume["seq"]:
                initial_status = True
            else:
                deny(not boot_events, "shared_qmp_debug_order")
        elif name == "query_cpus_fast":
            path = cpu_path(value)
        elif name == "qom_realized":
            deny(value is True, "shared_qmp_realized")
        elif name == "qom_phys_bits":
            realized_width(True, value)
        elif name == "hmp_flatview":
            deny(type(value) is str and value.isascii() and len(value) <= 65536, "shared_qmp_layout")
            parse_flatview(value)
        elif name == "hmp_registers":
            deny(type(value) is str and value.isascii() and len(value) <= 65536,
                 "shared_qmp_registers")
        replies[op["seq"]] = name, value

    for value, offset, length in incoming[response_pos:]:
        deny("event" in value, "shared_qmp_unindexed")
        consume_event(value, offset, length, qmp_ops[-1], tail=True)
    deny(event_count == len(qmp_events), "shared_qmp_unindexed")
    ack_seq = rsp["acknowledge_stop_seq"]
    memory_sequences = [seq for seq, op in rsp["operations"].items()
                        if op["operation"] == "physical_read"]
    first_memory, last_memory = min(memory_sequences), max(memory_sequences)
    deny(any(op["operation"] == "query_status" and op["seq"] < rsp["resume_seq"]
             and replies[op["seq"]][1]["status"] == "prelaunch" for op in qmp_ops),
         "shared_qmp_initial_status")
    brackets = []
    for phase in ("before", "after"):
        bracket = object_fields(index[phase], ("status_seq", "cpu_seq", "realized_seq",
                                               "phys_bits_seq", "hmp_seq"), "shared_qmp_bracket")
        width = None
        identity = []
        for key, label in (("status_seq", "query_status"), ("cpu_seq", "query_cpus_fast"),
                           ("realized_seq", "qom_realized"), ("phys_bits_seq", "qom_phys_bits"),
                           ("hmp_seq", "hmp_registers")):
            seq = bracket[key]
            if phase == "after" and label in ("qom_realized", "qom_phys_bits") and seq is None:
                continue
            deny(exact_int(seq, ack_seq + 1, first_memory - 1)
                 and seq in replies and replies[seq][0] == label, "shared_qmp_bracket_member")
            identity.append(seq)
        deny(identity == sorted(set(identity))
             and (bracket["realized_seq"] is None) == (bracket["phys_bits_seq"] is None),
             "shared_qmp_bracket_order")
        deny(exact_int(binding[f"control_{phase}_seq"], identity[0], identity[0])
             and replies[identity[0]][1]["status"] == "debug", "shared_qmp_debug_binding")
        cpu = replies[bracket["cpu_seq"]][1][0]
        if bracket["phys_bits_seq"] is not None:
            width = replies[bracket["phys_bits_seq"]][1]
        text = replies[bracket["hmp_seq"]][1]
        c0_registers(text, rsp["before_registers"])
        brackets.append((identity, cpu["qom-path"], cpu["thread-id"], width, text))
    before, after = brackets
    deny(before[0][-1] < after[0][0] and before[1:3] == after[1:3]
         and (after[3] is None or before[3] == after[3]) and before[4] == after[4]
         and exact_int(binding["qmp_thread_id"], before[2], before[2]), "shared_qmp_identity")
    layouts = [op["seq"] for op in qmp_ops if op["operation"] == "hmp_flatview"]
    final_hmp = [op["seq"] for op in qmp_ops if op["operation"] == "hmp_registers"
                 and last_memory < op["seq"] < qmp_ops[-1]["seq"]]
    deny(len(layouts) == 2 and ack_seq < layouts[0] < first_memory <= last_memory
         < layouts[1] < qmp_ops[-1]["seq"] and len(final_hmp) == 1
         and (shutdown_seq is None or shutdown_seq == qmp_ops[-1]["seq"]), "shared_qmp_layout_order")
    c0_registers(replies[final_hmp[0]][1], rsp["after_registers"])
    return before[2]


def c0_registers(raw, values):
    lines = raw.splitlines()
    deny([line for line in lines if line.startswith("CPU#")] == ["CPU#0"], "c0_hmp_cpu")
    for key, expected in (("CPL", "0"), ("SMM", "0"), ("A20", "1")):
        incomplete(re.findall(rf"\b{key}=([0-9]+)(?=\s|$)", raw) == [expected], "c0_hmp_mode")
    cs = [match for line in lines if (match := re.fullmatch(
        r"CS =([0-9a-f]{4}) [0-9a-f]{8,16} [0-9a-f]{8} ([0-9a-f]{8})(?: .*|)", line,
    ))]
    deny(len(cs) == 1 and int(cs[0][1], 16) == values[18], "c0_hmp_cs")
    incomplete(bool(int(cs[0][2], 16) & (1 << 21)) and bool(values[32] & (1 << 10)),
               "c0_hmp_long_mode")
    for key, register in (("RIP", 16), ("CR0", 27), ("CR3", 29), ("CR4", 30), ("EFER", 32)):
        found = re.findall(rf"\b{key}=([0-9a-f]{{8,16}})(?=\s|$)", raw)
        deny(len(found) == 1 and int(found[0], 16) == values[register], "c0_hmp_rsp_mismatch")


def shared_control_index(index, blobs, binding, *, retained_runtime=False,
                         invocation_profile=base.INVOCATION_PROFILE):
    from run0_c0_decode import validate_c0_rsp

    deny(index["scope"] == "shared_c0" and index["clock"] == "host_monotonic_ns"
         and index["run_id"] == binding["run_id"]
         and index["profile_sha256"] == binding["profile_sha256"], "shared_control_identity")
    operations, events = index["operations"], index["events"]
    deny(type(operations) is list and 1 <= len(operations) <= 512
         and type(events) is list and 1 <= len(events) <= 128, "shared_control_inventory")
    last = 0
    for seq, op in enumerate(operations, 1):
        object_fields(op, ("seq", "protocol", "operation", "request", "response",
                           "started_ns", "finished_ns", "result"), "shared_operation_fields")
        deny(exact_int(op["seq"], seq, seq) and op["protocol"] in ("qmp", "rsp")
             and type(op["operation"]) is str and op["result"] == "ok"
             and exact_int(op["started_ns"], max(1, last), (1 << 63) - 1)
             and exact_int(op["finished_ns"], op["started_ns"],
                           op["started_ns"] + (60 if op["operation"] == "resume" else 5)
                           * 1_000_000_000), "shared_operation_clock")
        last = op["finished_ns"]
    last = 0
    for seq, event in enumerate(events, 1):
        object_fields(event, ("seq", "protocol", "received_ns", "wire", "name"),
                      "shared_event_fields")
        deny(exact_int(event["seq"], seq, seq) and event["protocol"] in ("qmp", "rsp")
             and exact_int(event["received_ns"], max(1, last), (1 << 63) - 1),
             "shared_event_clock")
        last = event["received_ns"]
    rsp = validate_c0_rsp(index, blobs)
    deny(exact_int(binding["resume_seq"], rsp["resume_seq"], rsp["resume_seq"])
         and exact_int(binding["breakpoint_seq"], rsp["breakpoint_seq"], rsp["breakpoint_seq"]),
         "shared_rsp_binding")
    event = rsp["stop_event"]["wire"]
    raw_rsp = retained_blob(dict(event["blob"]), blobs, 32 * 1024 * 1024)
    offset, size = event["offset"], event["length"]
    deny(retained_blob(binding["stop_ref"], blobs, 8192) == raw_rsp[offset:offset + size],
         "shared_stop_binding")
    tid = verify_shared_qmp(index, blobs, binding, rsp, retained_runtime=retained_runtime,
                            invocation_profile=invocation_profile)
    return index, tid


OUTPUT_LIMIT = 32 * 1024 * 1024
FAILURE_RESERVE = 128 * 1024
OBSERVED_STREAMS = {"qmp": "qmp", "serial": "serial", "debug": "debug",
                    "stdout": "qemu_stdout", "stderr": "qemu_stderr"}


class CaptureEvidence:
    """Private files and exact byte references for independently replayable evidence."""

    def __init__(self, run, budget, abi_blobs):
        self.run, self.budget = run, budget
        self.blobs = dict(abi_blobs)

    def put(self, name, data, *, charged=False):
        deny(name not in self.blobs, "duplicate_evidence_path")
        if not charged:
            self.budget.retain(len(data))
        write_private(self.run / name, data)
        self.blobs[name] = data
        return self.ref(name, data)

    def existing(self, name, limit):
        path = self.run / name
        base.private_regular(path)
        incomplete(path.stat().st_size <= limit, "capture_file_limit")
        with path.open("rb") as stream:
            data = stream.read(limit + 1)
        incomplete(len(data) <= limit, "capture_file_limit")
        self.blobs[name] = data
        return self.ref(name, data)

    @staticmethod
    def ref(name, data):
        return {"path": name, "length": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def connect_owned(path, deadline):
    """Connect to an owned socket without a poll or any possible child wait."""
    while time.monotonic() < deadline:
        connection = socket.socket(socket.AF_UNIX)
        try:
            connection.settimeout(max(0.001, deadline - time.monotonic()))
            connection.connect(str(path))
            info = path.lstat()
            deny(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.getuid(), "socket_identity")
            os.chmod(path, 0o600)
            connection.setblocking(False)
            return connection
        except (FileNotFoundError, ConnectionRefusedError, BlockingIOError, TimeoutError):
            connection.close()
            time.sleep(min(0.01, max(0, deadline - time.monotonic())))
        except BaseException:
            connection.close()
            raise
    raise base.ProbeError("INCOMPLETE", "socket_connect_timeout")


def drain_reset_wire(wire, qmp, deadline):
    while wire.selector.get_map() or wire.frames:
        incomplete(time.monotonic() < deadline, "stream_eof_deadline")
        if wire.selector.get_map():
            wire.step(deadline)
        while wire.frames:
            raw = wire.frames.popleft()
            wire.budget.message(teardown=True)
            value = base.decode_frame(raw)
            deny(qmp is not None and "event" in value, "qmp_unsolicited_reply")
            qmp.received_events.append((time.monotonic_ns(), raw, value.get("event")))
            qmp.event(value)
    incomplete(not wire.partial, "qmp_trailing_partial_frame")


def failure_reason(error):
    if isinstance(error, base.ProbeError):
        reason = error.reason
        return error.status, reason if type(reason) is str and re.fullmatch(
            r"[a-z0-9_]{1,96}", reason,
        ) else "observer_failure"
    if isinstance(error, KeyboardInterrupt):
        return "INCOMPLETE", "observer_cancelled"
    return "INCOMPLETE", "host_io_error"


def wait_result(owner, grace):
    return {"role": owner.role, "pid": owner.child.pid, "started": True, "reaped": owner.reaped,
            "returncode": owner.returncode, "actions": owner.actions, "grace": grace}


def retain_partial(evidence, observation, owners, failures, qmp, wire, before_spawn):
    """Use reserved storage for raw failure coordinates after observation ends."""
    details = {
        "schema_version": 1, "failures": failures,
        "lifecycle": [row for owner in owners for row in owner.lifecycle],
        "helpers": [], "process": observation.process if observation else {},
        "qmp_operations": [] if qmp is None else [{
            key: row[key] for key in ("operation", "started_ns", "finished_ns", "result")
        } for row in qmp.operations],
        "vm_stream_eofs": wire.eofs, "vm_stream_errors": wire.io_errors,
        "qmp_events": [] if qmp is None else [{"received_ns": at, "name": name}
                                              for at, _, name in qmp.received_events],
    }

    def retain_existing_or_partial(name, data, *, charged=False):
        partial = "partial-" + name
        if name in evidence.blobs and evidence.blobs[name] == data:
            return evidence.ref(name, data)
        if charged and os.path.lexists(evidence.run / name):
            # A failed O_EXCL write can leave a visible prefix before put()
            # records its reference. Charge any resulting physical duplicate.
            prior = evidence.existing(name, len(data))
            if evidence.blobs[name] == data:
                return prior
            evidence.budget.retain(prior["length"])
        return evidence.put(partial, data, charged=charged)

    if before_spawn is not None:
        details["sigchld_spawn_ref"] = retain_existing_or_partial(
            "sigchld-spawn.bin", before_spawn,
        )
    if observation is not None:
        for role, helper in observation.helpers.items():
            stem = role.replace("_", "-")
            output_name = f"{stem}.bin" if role != "fields" else "fields-output.bin"
            details["helpers"].append({
                "role": role, "pid": helper.child.pid if helper.child else None,
                "eofs": sorted(helper.eofs), "errors": helper.io_errors,
                "output_ref": retain_existing_or_partial(output_name, bytes(helper.output),
                                                        charged=True),
                "stderr_ref": retain_existing_or_partial(f"{stem}-stderr.bin",
                                                        bytes(helper.stderr), charged=True),
            })
        request = bytes(observation.request_sent)
        for name in ("fields-begin.json", "fields-admit.json"):
            if name in evidence.blobs or os.path.lexists(evidence.run / name):
                prior = evidence.existing(name, len(request))
                prefix = evidence.blobs[name]
                deny(request.startswith(prefix), "retained_request_prefix")
                details.setdefault("fields_request_refs", []).append(prior)
                request = request[len(prefix):]
        if request:
            details.setdefault("fields_request_refs", []).append(
                retain_existing_or_partial("fields-request.bin", request, charged=True),
            )
        for name, data in (("peer.bin", observation.peer_raw),
                           ("sigchld-open.bin", observation.sigchld_raw)):
            if data is not None:
                details[name + "_ref"] = retain_existing_or_partial(name, data)
    encoded = canonical(details)
    incomplete(len(encoded) <= FAILURE_RESERVE, "failure_record_limit")
    write_private(evidence.run / "failure-details.json", encoded)


def retain_complete(evidence, report, qmp, observation, owner, before_spawn,
                    before_spawn_ns, native_ref, grace):
    put = evidence.put
    wire = qmp.wire
    stream_refs = {
        target: evidence.existing(f"{source}.bin", 2 * 1024 * 1024)
        for source, target in OBSERVED_STREAMS.items()
    }
    out_ref = evidence.existing("qmp-requests.bin", 1024 * 1024)
    in_ref = stream_refs["qmp"]
    control, tid = reset_control_index(
        report["run_id"], report["binding"]["profile_sha256"],
        evidence.blobs[in_ref["path"]], evidence.blobs[out_ref["path"]], in_ref, out_ref,
        [(op["started_ns"], op["finished_ns"]) for op in qmp.operations],
        [when for when, _, _ in qmp.received_events],
    )
    report["control_ref"] = put("control.json", canonical(control))
    report["binding"].update(qmp_thread_id=tid, control_before_seq=control["before"]["status_seq"],
                             control_after_seq=control["after"]["status_seq"])

    def put_helper(name, data):
        # Exact raw streams and requests were already charged while reading/writing.
        return put(name, data, charged=name in prepaid)

    helpers = observation.helpers
    owners = [owner, *(helpers[role] for role in WAIT_ROLES[1:])]
    prepaid = {"metadata-before.bin", "metadata-before-stderr.bin",
               "metadata-after.bin", "metadata-after-stderr.bin",
               "fields-output.bin", "fields-stderr.bin", "fields-begin.json",
               "fields-admit.json"}
    metadata = {}
    for phase in ("before", "after"):
        helper = helpers[f"metadata_{phase}"]
        report[f"metadata_{phase}_ref"], metadata[phase] = retain_metadata(
            put_helper, phase, helper.child.pid, helper.lifecycle[0]["started_ns"],
            next(row["finished_ns"] for row in helper.lifecycle if row["operation"] == "wait"),
            bytes(helper.output), bytes(helper.stderr),
        )
        stream_refs[f"metadata_{phase}_stdout"] = metadata[phase]["wire_ref"]
        stream_refs[f"metadata_{phase}_stderr"] = metadata[phase]["stderr_ref"]
    helper = helpers["fields"]
    deny(bytes(observation.request_sent) == observation.begin_raw + observation.admit_raw,
         "field_request_transcript")
    report["reads_ref"], fields = retain_fields(
        put_helper, helper.child.pid, observation.begin_raw, observation.admit_raw,
        bytes(helper.output), bytes(helper.stderr), observation.reads,
    )
    stream_refs["fields_stdout"] = fields["output_ref"]
    stream_refs["fields_stderr"] = fields["stderr_ref"]
    lifecycle = sorted((row for item in owners for row in item.lifecycle),
                       key=lambda row: row["started_ns"])
    lifecycle_ref = put("lifecycle.json", canonical({
        "schema_version": 1, "rows": [row | {"seq": seq}
                                     for seq, row in enumerate(lifecycle, 1)],
    }))
    process = observation.process | {
        "schema_version": 1, "lifecycle_ref": lifecycle_ref,
        "exe_before_ref": metadata["before"]["exe_identity_ref"],
        "exe_after_ref": metadata["after"]["exe_identity_ref"],
    }
    report["process_ref"] = put("process.json", canonical(process))
    peer = observation.peer_raw
    pid, uid, gid = struct.unpack("<iII", peer)
    report["peer_ref"] = put("peer.json", canonical({
        "schema_version": 1, "socket_role": "qmp", "socket_path": "qmp.sock",
        "observed_ns": observation.peer_at_ns, "raw_ref": put("peer.bin", peer),
        "pid": pid, "uid": uid, "gid": gid, "abi_ref": native_ref,
    }))

    def signal_receipt(role, raw, at):
        handler, flags = decode_sigchld(raw)
        return {"observed_ns": at, "raw_ref": put(f"sigchld-{role}.bin", raw),
                "abi_ref": native_ref, "handler": handler, "flags": flags,
                "no_cld_wait_mask": 2, "observer_pid": os.getpid()}

    report["sigchld_ref"] = put("sigchld.json", canonical({
        "schema_version": 1, "sole_reaper_pid": os.getpid(), "no_concurrent_reaper": True,
        "policy_ref": report["observer_ref"],
        "before_spawn": signal_receipt("spawn", before_spawn, before_spawn_ns),
        "before_open": signal_receipt("open", observation.sigchld_raw, observation.sigchld_at_ns),
    }))
    eof = {OBSERVED_STREAMS[row["stream"]] for row in wire.eofs}
    incomplete(not wire.io_errors, "qemu_stream_error")
    for role, helper in helpers.items():
        incomplete(not helper.io_errors, "helper_stream_error")
        eof.update(f"{role}_{stream}" for stream in helper.eofs)
    incomplete(eof == set(stream_refs), "required_stream_eof")
    streams = put("streams.json", canonical({
        "schema_version": 1, "rows": [{"name": name, "raw_ref": ref, "eof": True, "error": None}
                                      for name, ref in stream_refs.items()],
    }))
    report["state"] = observation.state
    report["admission"] = {"status": "ADMIT", "reason": "reset_field_subset"}
    report["termination"] = {
        "status": "PASS", "first_failure": None, "secondary_failures": [],
        "waits": [wait_result(item, grace if item is owner else "not_attempted")
                  for item in owners], "streams_ref": streams,
    }


# Scope the reset collector to the independently reviewed host ABI assembly.
REVIEWED_LAUNCH_ABI_SHA256 = "db5be432574e2d8631059a8a69d421c1163eee60c51fb61d7c358e2bb271aa73"


def run_reset_capture(prepared, run):
    plan, profile, profile_bytes, observer_bytes, abi_ref, abi_blobs, layout, abi = prepared
    incomplete(REVIEWED_LAUNCH_ABI_SHA256 is not None
               and abi_ref["sha256"] == REVIEWED_LAUNCH_ABI_SHA256,
               "runtime_provenance_pending")
    deny(threading.current_thread() is threading.main_thread()
         and threading.active_count() == 1, "main_thread_owner_required")
    native = NativeQueries(layout)
    base.create_run(run)
    deadline = time.monotonic() + base.VM_SECONDS
    budget = base.Budget(deadline, byte_limit=OUTPUT_LIMIT - REPORT_LIMIT - FAILURE_RESERVE)
    evidence = CaptureEvidence(run, budget, abi_blobs)
    abi_index = strict_json(abi_blobs[abi_ref["path"]], REPORT_LIMIT)
    before_spawn = before_spawn_ns = None
    try:
        report = {
            "schema_version": 1, "kind": "run0_host_cpu_witness_v0", "run_id": run.name,
            "origin": "retained_runtime", "claims": dict(FALSE_CLAIMS), "fresh_c0_verified": False,
            "profile_ref": evidence.put("profile.json", profile_bytes),
            "observer_ref": evidence.put("observer.json", observer_bytes),
            "source_ref": abi_index["source_dossier_ref"], "abi_ref": abi_ref,
            "plan_ref": evidence.put("plan.json", canonical(plan)),
            "binding": {"context": "reset", "run_id": run.name,
                        "profile_sha256": entry.profile_digest(profile),
                        "cpu_index": 0, "qmp_thread_id": None, "rsp_thread": None,
                        "stop_id": "reset", "stop_ref": None, "resume_seq": None,
                        "breakpoint_seq": None, "control_before_seq": None,
                        "control_after_seq": None},
            **dict.fromkeys(("metadata_before_ref", "metadata_after_ref", "peer_ref",
                             "sigchld_ref", "process_ref", "reads_ref", "state", "control_ref")),
        }
        vars_ref = profile["inputs"]["initial_vars"]
        budget.retain(vars_ref["length"])
        vars_path = run / "vars.fd"
        write_private(vars_path, read_exact(
            Path(plan["inputs"]) / "initial_vars", vars_ref["sha256"], vars_ref["length"],
        ))
        wire = ResetWire(run, budget)
    except (base.ProbeError, OSError, KeyboardInterrupt) as error:
        status, reason = failure_reason(error)
        write_private(run / "prelaunch-failure.json", canonical({
            "schema_version": 1, "kind": "run0_host_cpu_prelaunch_failure_v0",
            "status": status, "reason": reason, "child_spawned": False,
        }))
        raise

    owner = OwnedWait("qemu", deadline)
    qmp = observation = None
    failures = []
    grace = "not_attempted"

    def fail(error):
        status, reason = failure_reason(error)
        failures.append({"status": status, "reason": reason})

    try:
        budget.remaining(base.TEARDOWN_SECONDS)
        before_spawn = native.sigchld()
        before_spawn_ns = time.monotonic_ns()
        decode_sigchld(before_spawn)
        with defer_cleanup_interrupt() as interrupted:
            started = time.monotonic_ns()
            owner.child = subprocess.Popen(
                plan["argv"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, start_new_session=True, close_fds=True,
                umask=0o077, env=clean_launch_env(run),
            )
            owner._receipt("spawn", started, "ok")
        if interrupted[0]:
            raise KeyboardInterrupt
        wire.add("stdout", owner.child.stdout)
        wire.add("stderr", owner.child.stderr)
        for name in ("qmp", "serial", "debug"):
            connect_deadline = min(time.monotonic() + base.RESPONSE_SECONDS,
                                   deadline - base.TEARDOWN_SECONDS)
            wire.add(name, connect_owned(run / f"{name}.sock", connect_deadline))
        qmp = ResetQMP(wire, budget)
        qmp.negotiate()
        commands = qmp.request("query-commands")
        required = {"qmp_capabilities", "query-commands", "query-status", "query-cpus-fast",
                    "quit", "qom-get", "human-monitor-command"}
        incomplete(type(commands) is list and all(
            type(row) is dict and set(row) == {"name"} and type(row["name"]) is str
            for row in commands
        ) and required <= {row["name"] for row in commands}, "qmp_command_inventory")
        fingerprint = tuple(plan["launch_identity"][key] for key in ("device", "inode", "size"))
        observation = OwnedCPUObservation(owner.child, qmp, budget, native, abi,
                                          plan["argv"][0], fingerprint)
        observation.observe()
    except (base.ProbeError, OSError, KeyboardInterrupt) as error:
        fail(error)
    finally:
        with defer_cleanup_interrupt() as interrupted:
            if owner.child is not None:
                try:
                    if qmp is not None and qmp.negotiated and not qmp.terminal:
                        incomplete(qmp.request("quit") == {}, "quit_unacknowledged")
                        result = owner.wait(time.monotonic() + 0.5)
                        grace = "exited" if result is not None else "timeout"
                    incomplete(grace == "exited" and owner.returncode == 0,
                               "owned_quit_incomplete")
                except (base.ProbeError, OSError) as error:
                    fail(error)
                finally:
                    try:
                        owner.terminate()
                    except OSError as error:
                        fail(error)
                    if not owner.reaped:
                        fail(base.ProbeError("INCOMPLETE", "owned_wait_uncertain"))
            try:
                drain_reset_wire(wire, qmp, deadline)
            except (base.ProbeError, OSError) as error:
                fail(error)
            close_start = time.monotonic_ns()
            errors = wire.close()
            if owner.child is not None:
                for stream in (owner.child.stdout, owner.child.stderr):
                    if not stream.closed:
                        try:
                            stream.close()
                        except OSError as error:
                            errors.append({"errno": error.errno})
                owner._receipt("close", close_start, "error" if errors else "ok",
                               errno=errors[0]["errno"] if errors else None)
            if errors:
                fail(base.ProbeError("INCOMPLETE", "qemu_stream_close"))
        if interrupted[0]:
            fail(KeyboardInterrupt())

    if not failures:
        try:
            incomplete(observation is not None and observation.state is not None
                       and not observation.secondary_failures, "observation_incomplete")
            base.validate_profile(profile, Path(plan["inputs"]))
            deny(read_exact(Path(plan["inputs"]) / "profile.json", plan["profile_sha256"], 65536)
                 == profile_bytes and observer_source_bytes() == observer_bytes,
                 "capture_pins_changed")
            recheck_receipts = {}
            recheck_runtime(Path(plan["inputs"]), profile, abi_index, abi_blobs,
                            expected_identity=plan["launch_identity"], run=run,
                            receipts=recheck_receipts)
            final_vars = evidence.existing("vars.fd", vars_ref["length"])
            report["observer_ref"] = evidence.put("runtime-observer.json", canonical({
                "schema_version": 1, "kind": "run0_host_cpu_runtime_observer_v0",
                "run_id": run.name, "source_manifest_ref": report["observer_ref"],
                "abi_sha256": abi_ref["sha256"], "launch_env": clean_launch_env(run),
                "postcheck": recheck_receipts,
                "vars_initial_sha256": vars_ref["sha256"], "vars_final_ref": final_vars,
            }))
            retain_complete(evidence, report, qmp, observation, owner, before_spawn,
                            before_spawn_ns, abi_index["native_abi_ref"], grace)
            final_bytes = canonical(report)
            final_ref = evidence.ref("report.json", final_bytes)
            validate_report(final_ref, evidence.blobs | {final_ref["path"]: final_bytes})
        except (base.ProbeError, OSError, KeyboardInterrupt) as error:
            fail(error)

    if failures:
        status = "DENY" if any(item["status"] == "DENY" for item in failures) else "INCOMPLETE"
        first = failures[0]["reason"]
        owners = [owner]
        secondary = [item["reason"] for item in failures[1:]]
        if observation is not None:
            owners.extend(observation.helpers.values())
            secondary.extend(observation.secondary_failures)
        report["admission"] = {"status": status, "reason": first}
        report["termination"] = {
            "status": status, "first_failure": first, "secondary_failures": secondary[:16],
            "waits": [wait_result(item, grace if item is owner else "not_attempted")
                      for item in owners if item.child is not None], "streams_ref": None,
        }
        try:
            retain_partial(evidence, observation, owners, failures, qmp, wire, before_spawn)
        except (base.ProbeError, OSError) as error:
            if len(report["termination"]["secondary_failures"]) < 16:
                report["termination"]["secondary_failures"].append(failure_reason(error)[1])

    return report, persist_capture_report(run, report)


def emit_terminal(value):
    try:
        sys.stderr.write(canonical(value).decode())
    except (OSError, ValueError):
        pass


def persist_capture_report(run, report):
    data = canonical(report)
    incomplete(len(data) <= REPORT_LIMIT, "report_limit")
    try:
        write_private(run / "report.json", data)
    except OSError as error:
        terminal = report["termination"]
        if terminal["first_failure"] is not None:
            emit_terminal({"status": terminal["status"], "reason": terminal["first_failure"],
                           "secondary_failures": ["report_write_failed",
                                                  *terminal["secondary_failures"][:15]]})
            raise base.ProbeError(terminal["status"], terminal["first_failure"]) from error
        raise
    return CaptureEvidence.ref("report.json", data)


def collect_reset(inputs, run, source_dossier, host_abi, plan_path, plan_sha256):
    deny(type(plan_sha256) is str and HASH.fullmatch(plan_sha256), "plan_digest")
    plan_bytes = read_exact(plan_path, plan_sha256, REPORT_LIMIT)
    prepared = prepare_launch(inputs, run, source_dossier, host_abi)
    deny(canonical(prepared[0]) == plan_bytes, "plan_changed")
    return run_reset_capture(prepared, run)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    plan = modes.add_parser("plan")
    collect = modes.add_parser("collect")
    for mode in (plan, collect):
        for name in ("inputs", "source-dossier", "host-abi", "run"):
            mode.add_argument(f"--{name}", type=Path, required=True)
    plan.add_argument("--output", type=Path, required=True)
    collect.add_argument("--plan", type=Path, required=True)
    collect.add_argument("--plan-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        if args.mode == "plan":
            value, *_ = prepare_launch(args.inputs, args.run, args.source_dossier, args.host_abi)
            base.safe_path(args.output)
            deny(args.output.parent.resolve() == args.output.parent, "output_parent_symlink")
            data = canonical(value)
            write_private(args.output, data)
            print(canonical(CaptureEvidence.ref(args.output.name, data)).decode(), end="")
            return 0
        report, ref = collect_reset(args.inputs, args.run, args.source_dossier, args.host_abi,
                                    args.plan, args.plan_sha256)
        print(canonical({"report": ref, "termination": report["termination"]}).decode(), end="")
        return {"PASS": 0, "INCOMPLETE": 3, "DENY": 2}[report["termination"]["status"]]
    except (base.ProbeError, OSError, KeyboardInterrupt) as error:
        status, reason = failure_reason(error)
        emit_terminal({"status": status, "reason": reason})
        return 2 if status == "DENY" else 3


OBSERVER_SOURCE_NAMES = (
    "run0_host_cpu_witness.py", "run0_host_cpu_reader.py", "boot_profile_capture.py",
    "boot_profile_inputs.py", "run0_rsp_capability.py", "run0_rsp.py",
)


def verify_runtime_observer(report, blobs, profile, plan, abi):
    observer = json_index(report["observer_ref"], blobs, (
        "schema_version", "kind", "run_id", "source_manifest_ref", "abi_sha256",
        "launch_env", "postcheck", "vars_initial_sha256", "vars_final_ref",
    ), "runtime_observer")
    c0 = plan["kind"] == "run0_c0_owned_capture_plan_v0"
    names = C0_OBSERVER_SOURCE_NAMES if c0 else OBSERVER_SOURCE_NAMES
    deny(observer["kind"] == ("run0_c0_runtime_observer_v0" if c0
                              else "run0_host_cpu_runtime_observer_v0")
         and observer["run_id"] == report["run_id"]
         and observer["source_manifest_ref"] == plan["observer_ref"]
         and observer["abi_sha256"] == report["abi_ref"]["sha256"]
         and observer["launch_env"] == clean_launch_env(Path(plan["run"])), "runtime_observer_binding")
    source = json_index(plan["observer_ref"], blobs,
                        ("schema_version", "kind", "python", "sources"), "observer_sources", 65536)
    deny(source["kind"] == ("run0_c0_observer_v0" if c0 else "run0_host_cpu_observer_v0")
         and type(source["sources"]) is list
         and len(source["sources"]) == len(names), "observer_source_inventory")
    for name, row in zip(names, source["sources"], strict=True):
        object_fields(row, ("path", "length", "sha256"), "observer_source_fields")
        deny(row["path"] == name and exact_int(row["length"], 1, 1024 * 1024)
             and type(row["sha256"]) is str and HASH.fullmatch(row["sha256"]),
             "observer_source_pin")
    python = object_fields(source["python"], ("path", "length", "sha256"), "observer_python")
    deny(type(python["path"]) is str and exact_int(python["length"], 1, 64 * 1024 * 1024)
         and type(python["sha256"]) is str and HASH.fullmatch(python["sha256"]), "observer_python_pin")
    base.safe_path(Path(python["path"]))
    runtime = json_index(abi["runtime_dependencies_ref"], blobs, (
        "schema_version", "kind", "kernel_release", "libc_version", "loader", "libraries",
        "inspection_ref", "env", "module_closure_ref",
    ), "runtime_dependency_index")
    post = object_fields(observer["postcheck"], (
        "schema_version", "kind", "runtime_ref", "module_closure_ref", "kernel_release",
        "libc_version", "launch_identity", "env", "loader_listing_sha256",
        "normalized_aliases_sha256", "module_observations_sha256", "checked_absences",
        "module_raw_listing_sha256",
    ), "runtime_postcheck")
    deny(exact_int(post["schema_version"], 1, 1)
         and post["kind"] == "run0_host_cpu_runtime_recheck_v0"
         and post["runtime_ref"] == abi["runtime_dependencies_ref"]
         and post["module_closure_ref"] == runtime["module_closure_ref"]
         and post["kernel_release"] == runtime["kernel_release"]
         and post["libc_version"] == runtime["libc_version"]
         and canonical(post["launch_identity"]) == canonical(plan["launch_identity"])
         and post["env"] == clean_launch_env(Path(plan["run"]))
         and all(type(post[key]) is str and HASH.fullmatch(post[key]) for key in (
             "loader_listing_sha256", "normalized_aliases_sha256", "module_observations_sha256",
         )), "runtime_recheck_binding")
    inspection = strict_json(retained_blob(runtime["inspection_ref"], blobs, REPORT_LIMIT), REPORT_LIMIT)
    aliases = [(row["alias"], row["listed_path"]) for row in inspection["aliases"]]
    deny(post["normalized_aliases_sha256"] == hashlib.sha256(canonical(aliases)).hexdigest(),
         "runtime_alias_digest")
    modules = strict_json(retained_blob(runtime["module_closure_ref"], blobs, REPORT_LIMIT), REPORT_LIMIT)
    module_rows = modules["modules"]
    observations = modules["dependencies"] + [row["pin"] for row in module_rows] + [
        {"name": row["name"], "aliases": [(alias["alias"], alias["listed_path"])
                                          for alias in row["aliases"]]}
        for row in module_rows
    ]
    absences = runtime_module_absences(modules, Path(plan["inputs"]), profile["invocation_profile"])
    deny(post["checked_absences"] == absences
         and post["module_observations_sha256"] ==
         hashlib.sha256(canonical(observations)).hexdigest(), "runtime_module_recheck_binding")
    actual = post["module_raw_listing_sha256"]
    deny(type(actual) is list and len(actual) == len(module_rows), "runtime_raw_module_inventory")
    for row, expected in zip(actual, module_rows, strict=True):
        object_fields(row, ("name", "sha256"), "runtime_raw_module_fields")
        deny(row["name"] == expected["name"] and type(row["sha256"]) is str
             and HASH.fullmatch(row["sha256"]), "runtime_raw_module_pin")
    initial = profile["inputs"]["initial_vars"]
    deny(observer["vars_initial_sha256"] == initial["sha256"]
         and observer["vars_final_ref"]["path"] == "vars.fd", "runtime_vars_binding")
    final = retained_blob(observer["vars_final_ref"], blobs, initial["length"])
    deny(len(final) == initial["length"], "runtime_vars_length")


HOST_ABI_SHA256 = 'db5be432574e2d8631059a8a69d421c1163eee60c51fb61d7c358e2bb271aa73'
MODULE_CLOSURE_SHA256 = '4a0754fd813f17ce2bc191c1fbaa0323cabba3ea511d9fb1c7aca86163d3ba41'
MAX_ABI_BYTES = 192 * 1024 * 1024
MAX_ABI_FILES = 512
MAX_STATIC_OUTPUT = 65536


def clean_launch_env(run):
    base.safe_path(run)
    return {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'HOME': str(run)}


def _read_regular(path, limit, *, private, archive_name=False):
    """Bound before read; fd identity must agree with path and remain stable."""
    if archive_name:
        deny(path.is_absolute() and re.fullmatch(r'[A-Za-z0-9_./+-]+',str(path))
             and '..' not in path.parts,'unsafe_archive_path')
    else:
        base.safe_path(path)
    if private:
        base.private_regular(path)
        deny(path.resolve() == path, 'artifact_path_symlink')
    before = path.lstat()
    deny(stat.S_ISREG(before.st_mode) and not stat.S_ISLNK(before.st_mode),
         'pinned_not_regular')
    deny(0 <= before.st_size <= limit, 'pinned_file_size')
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        deny((opened.st_dev, opened.st_ino, opened.st_size) ==
             (before.st_dev, before.st_ino, before.st_size), 'pinned_file_race')
        pieces, remaining = [], before.st_size
        while remaining:
            piece = os.read(fd, min(65536, remaining))
            incomplete(bool(piece), 'pinned_file_short_read')
            pieces.append(piece)
            remaining -= len(piece)
        deny(os.read(fd, 1) == b'', 'pinned_file_grew')
        after = os.fstat(fd)
        def identity(s):
            return s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns
        deny(identity(before) == identity(after) == identity(path.lstat()),
             'pinned_file_changed')
        return b''.join(pieces), after
    finally:
        os.close(fd)


def _pinned_read(path, digest, limit, *, private=True, archive_name=False):
    raw, info = _read_regular(path, limit, private=private, archive_name=archive_name)
    deny(hashlib.sha256(raw).hexdigest() == digest, 'pinned_file_digest')
    return raw, info


def parse_loader_aliases(raw, interpreter, loader=None):
    deny(type(raw) is bytes and 0 < len(raw) <= MAX_STATIC_OUTPUT and raw.isascii()
         and b'\0' not in raw, 'loader_listing_bytes')
    aliases, virtual = {}, 0
    for line in raw.decode('ascii').splitlines():
        if re.fullmatch(r'\s*linux-vdso\.so\.1 \(0x[0-9a-f]+\)', line):
            virtual += 1
            continue
        match = re.fullmatch(r'\s*(\S+) => (/\S+) \(0x[0-9a-f]+\)', line)
        if match:
            alias, listed = match.groups()
        else:
            match = re.fullmatch(r'\s*(/\S+) \(0x[0-9a-f]+\)', line)
            deny(match is not None and match[1] in (interpreter,loader), 'loader_listing_grammar')
            alias = listed = match[1]
        deny(alias not in aliases and len(alias) <= 256 and len(listed) <= 512,
             'loader_alias_duplicate')
        aliases[alias] = listed
    deny(virtual == 1 and (interpreter in aliases or loader in aliases) and 1 <= len(aliases) <= 128,
         'loader_alias_inventory')
    return sorted(aliases.items())


def _closed_kind(value, fields, kind):
    object_fields(value, ('schema_version', 'kind', *fields), kind + '_fields')
    deny(type(value['schema_version']) is int and value['schema_version'] == 1
         and value['kind'] == kind, kind + '_kind')
    return value


def load_launch_abi(host_abi):
    base.safe_path(host_abi)
    deny(host_abi.name == 'host-abi.json' and host_abi.parent.resolve() == host_abi.parent,
         'abi_path_identity')
    root = host_abi.parent
    deny(root.is_dir() and root.stat().st_uid == os.getuid()
         and root.stat().st_mode & 0o077 == 0, 'abi_root_not_private')
    raw, _ = _pinned_read(host_abi, HOST_ABI_SHA256, 65536)
    abi_ref = {'path': 'host-abi.json', 'length': len(raw), 'sha256': HOST_ABI_SHA256}
    blobs, total = {'host-abi.json': raw}, len(raw)

    def get(ref, limit, prefix=''):
        nonlocal total
        object_fields(ref, ('path', 'length', 'sha256'), 'abi_blob_fields')
        name, size, digest = ref['path'], ref['length'], ref['sha256']
        grammar=r'[A-Za-z0-9_.+-]+' if prefix else r'[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*'
        deny(type(name) is str and len(name) <= 240 and re.fullmatch(grammar,name)
             and all(p not in ('.', '..') for p in name.split('/'))
             and exact_int(size, 0, limit) and type(digest) is str
             and re.fullmatch('[0-9a-f]{64}', digest), 'abi_blob_value')
        key = prefix + name
        if key not in blobs:
            deny(len(blobs) < MAX_ABI_FILES and size <= MAX_ABI_BYTES - total,
                 'abi_closure_budget')
            data, _ = _pinned_read(root / key, digest, limit,archive_name=bool(prefix))
            deny(len(data) == size, 'abi_blob_length')
            blobs[key] = data
            total += size
        deny(len(blobs[key]) == size and hashlib.sha256(blobs[key]).hexdigest() == digest,
             'abi_blob_conflict')
        return blobs[key]

    def index(ref, fields, kind, limit=1024 * 1024):
        return _closed_kind(strict_json(get(ref, limit), limit), fields, kind)

    def observation(row):
        object_fields(row, ('argv', 'env', 'returncode', 'stdout_ref', 'stderr_ref',
                            'started_ns', 'finished_ns', 'reaped'), 'inspection_command')
        deny(type(row['argv']) is list and 1 <= len(row['argv']) <= 256
             and all(type(x) is str and 0 < len(x) <= 1024 and '\0' not in x for x in row['argv']),
             'inspection_argv')
        object_fields(row['env'], ('PATH','LANG','HOME'), 'inspection_env')
        deny(row['env']['PATH'] == '/usr/bin:/bin' and row['env']['LANG'] == 'C'
             and type(row['env']['HOME']) is str and row['env']['HOME'].startswith('/')
             and exact_int(row['returncode'], 0, 1) and row['reaped'] is True
             and exact_int(row['started_ns'], 0, (1<<63)-1)
             and exact_int(row['finished_ns'], row['started_ns'], (1<<63)-1),
             'inspection_observation')
        get(row['stdout_ref'], 1024*1024)
        get(row['stderr_ref'], 1024*1024)

    def packages(ref):
        value = index(ref, ('commands',), 'run0_host_cpu_package_observations_v0')
        deny(type(value['commands']) is list and len(value['commands']) == 2,
             'package_command_count')
        for row in value['commands']:
            observation(row)
            deny(row['argv'][0] == '/usr/bin/dpkg-query', 'package_command_identity')

    value = strict_json(raw, 65536)
    object_fields(value, ('schema_version', 'kind', 'contract_abi_sha256',
                         'kernel_source_refs', *ABI_BLOB_LIMITS), 'host_abi_fields')
    for name, limit in ABI_BLOB_LIMITS.items(): get(value[name], limit)
    deny(type(value['kernel_source_refs']) is list and len(value['kernel_source_refs']) == 6,
         'kernel_source_count')
    for row in value['kernel_source_refs']:
        object_fields(row, ('role', 'ref'), 'kernel_source_fields')
        get(row['ref'], 2*1024*1024)
    native = index(value['native_abi_ref'], ('layout_ref','layout_source_ref','layout_binary_ref',
                   'headers','package_observation_ref','parser_source_refs'), 'run0_host_cpu_native_abi_v0')
    for name, limit in [('layout_ref',4096),('layout_source_ref',65536),('layout_binary_ref',1024*1024)]:
        get(native[name],limit)
    for name, count in [('headers',11),('parser_source_refs',1)]:
        deny(type(native[name]) is list and len(native[name]) == count, 'native_source_inventory')
        for row in native[name]:
            object_fields(row, ('role','ref'), 'native_source_row')
            get(row['ref'],1024*1024)
    deny(native['parser_source_refs'][0]['ref']['sha256'] ==
         'ce4b410a5c1bb6b412025a9e7ef1da880c8ef802530660d7b43638ab7f36ac8a', 'linux_dev_t_source_pin')
    packages(native['package_observation_ref'])
    runtime = index(value['runtime_dependencies_ref'], ('kernel_release','libc_version','loader',
                    'libraries','inspection_ref','env','module_closure_ref'), 'run0_host_cpu_runtime_dependencies_v0')
    object_fields(runtime['env'], ('PATH','LANG','HOME'), 'runtime_env')
    deny(runtime['env'] == {'PATH':'/usr/bin:/bin','LANG':'C','HOME':'${run}'}, 'runtime_environment')
    inspection = index(runtime['inspection_ref'], ('executable_ref','interpreter','command',
                       'aliases','virtual_aliases','package_observation_ref'), 'run0_host_cpu_loader_inspection_v0')
    deny(inspection['executable_ref'] == value['qemu_ref'], 'loader_executable_binding')
    object_fields(inspection['interpreter'], ('path','resolved_path'), 'loader_interpreter')
    observation(inspection['command'])
    deny(inspection['command']['returncode'] == 0, 'loader_inspection_failed')
    packages(inspection['package_observation_ref'])
    aliases = inspection['aliases']
    deny(type(aliases) is list and 1 <= len(aliases) <= 128, 'runtime_alias_count')
    for row in aliases: object_fields(row, ('alias','listed_path','resolved_path'), 'runtime_alias_fields')
    parsed = parse_loader_aliases(get(inspection['command']['stdout_ref'],65536), inspection['interpreter']['path'])
    deny(parsed == [(r['alias'],r['listed_path']) for r in aliases]
         and inspection['virtual_aliases'] == ['linux-vdso.so.1'], 'loader_raw_binding')
    deny(type(runtime['libraries']) is list and len(runtime['libraries']) <= 128,
         'runtime_library_count')
    pins = [runtime['loader'], *runtime['libraries']]
    for pin in pins:
        object_fields(pin, ('path','length','sha256'), 'runtime_pin_fields')
        deny(type(pin['path']) is str and pin['path'].startswith('/')
             and exact_int(pin['length'],1,64*1024*1024)
             and type(pin['sha256']) is str and re.fullmatch('[0-9a-f]{64}',pin['sha256']), 'runtime_pin_value')
    deny(len({p['path'] for p in pins}) == len(pins)
         and {p['path'] for p in pins} == {r['resolved_path'] for r in aliases}
         and runtime['loader']['path'] == inspection['interpreter']['resolved_path'], 'runtime_pin_inventory')
    deny(runtime['module_closure_ref']['sha256']==MODULE_CLOSURE_SHA256,'module_closure_pin')
    modules=index(runtime['module_closure_ref'],('directory','modules','dependencies','sources',
                  'package_observation_ref','checked_absences','bundle_rule','environment','scope'),
                  'run0_host_cpu_module_closure_v0')
    deny(modules['directory']=='/usr/lib/x86_64-linux-gnu/qemu'
         and modules['environment']==runtime['env']
         and type(modules['modules']) is list and len(modules['modules'])==37,
         'module_inventory')
    module_names=[];dep_paths=set()
    for row in modules['modules']:
        object_fields(row,('name','pin','ref','command','aliases','virtual_aliases','listing_kind'),'module_row')
        deny(type(row['name']) is str and re.fullmatch('[a-z0-9_-]+\\.so',row['name']), 'module_name')
        module_names.append(row['name']);get(row['ref'],1024*1024)
        object_fields(row['pin'],('path','length','sha256'),'module_pin')
        deny(row['pin']['path']==modules['directory']+'/'+row['name']
             and row['pin']['length']==row['ref']['length'] and row['pin']['sha256']==row['ref']['sha256'],
             'module_pin_binding')
        observation(row['command'])
        deny(row['command']['returncode']==0 and row['command']['stderr_ref']['length']==0,'module_inspection_failure')
        actual=get(row['command']['stdout_ref'],65536)
        if row['listing_kind']=='statically_linked':
            deny(actual==b'\tstatically linked\n' and row['aliases']==[] and row['virtual_aliases']==[],
                 'module_static_listing')
        else:
            deny(row['listing_kind']=='dynamic' and row['virtual_aliases']==['linux-vdso.so.1'], 'module_listing_kind')
            parsed=parse_loader_aliases(actual,inspection['interpreter']['path'],runtime['loader']['path'])
            deny(parsed==[(r['alias'],r['listed_path']) for r in row['aliases']], 'module_raw_alias_binding')
        for alias in row['aliases']:
            object_fields(alias,('alias','listed_path','resolved_path'),'module_alias_fields')
            dep_paths.add(alias['resolved_path'])
    deny(module_names==sorted(set(module_names)), 'module_unique_inventory')
    deny(type(modules['dependencies']) is list and len(modules['dependencies'])<=256, 'module_dependency_count')
    for pin in modules['dependencies']:
        object_fields(pin,('path','length','sha256'),'module_dependency_pin')
        deny(type(pin['path']) is str and pin['path'].startswith('/') and exact_int(pin['length'],1,64*1024*1024)
             and type(pin['sha256']) is str and re.fullmatch('[0-9a-f]{64}',pin['sha256']),'module_dependency_value')
    deny(len(dep_paths)==len(modules['dependencies'])
         and dep_paths=={p['path'] for p in modules['dependencies']}, 'module_dependency_inventory')
    deny(type(modules['sources']) is list and len(modules['sources'])==12, 'module_source_count')
    for row in modules['sources']:
        object_fields(row,('role','ref'),'module_source_row');get(row['ref'],2*1024*1024)
    package=index(modules['package_observation_ref'],('commands',),'run0_host_cpu_module_packages_v0')
    deny(type(package['commands']) is list and 2<=len(package['commands'])<=3,'module_package_count')
    for row in package['commands']:
        observation(row);deny(row['argv'][0]=='/usr/bin/dpkg-query','module_package_command')

    # The original source dossier uses directory-relative artifact paths; retain
    # its bytes unchanged and join each path explicitly into the assembly root.
    dossier = strict_json(get(value['source_dossier_ref'],65536),65536)
    object_fields(dossier, ('applied_patches','archive_signing_key','artifacts','byte_identical_paths',
                            'kind','patched_paths_compared','qemu_sha256','schema_version','source_version'), 'source_dossier_fields')
    deny(dossier['kind'] == 'qemu_source_package_correspondence'
         and type(dossier['artifacts']) is list and len(dossier['artifacts']) <= 64,
         'source_dossier_shape')
    prefix = str(Path(value['source_dossier_ref']['path']).parent) + '/'
    for row in dossier['artifacts']: get(row, 64*1024*1024, prefix)
    admitted_index, abi = resolve_abi(abi_ref, blobs, True)
    layout = native_layout_from_index(admitted_index['native_abi_ref'], blobs, True)
    return abi_ref, blobs, admitted_index, layout, abi


def _static_tool(argv, env, deadline):
    """One bounded static loader command; no ambient env and no QEMU entry."""
    incomplete(time.monotonic() + 1 < deadline, 'runtime_check_deadline')
    selector, streams = selectors.DefaultSelector(), {'stdout':bytearray(),'stderr':bytearray()}
    owner = OwnedWait("static_loader", deadline)
    primary = None
    cleanup_error = False
    try:
        with defer_cleanup_interrupt() as interrupted:
            started = time.monotonic_ns()
            owner.child = subprocess.Popen(
                argv, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, start_new_session=True, close_fds=True, umask=0o077,
            )
            owner._receipt("spawn", started, "ok")
        if interrupted[0]:
            raise KeyboardInterrupt
        for name in streams:
            pipe = getattr(owner.child, name)
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe,selectors.EVENT_READ,name)
        while selector.get_map():
            incomplete(time.monotonic() < deadline-1, 'runtime_check_timeout')
            for key,_ in selector.select(min(.05,max(0,deadline-1-time.monotonic()))):
                try: chunk = os.read(key.fd,4096)
                except (BlockingIOError,InterruptedError): continue
                if not chunk: selector.unregister(key.fileobj); continue
                incomplete(sum(map(len,streams.values()))+len(chunk)<=MAX_STATIC_OUTPUT,
                           'runtime_check_output_limit')
                streams[key.data].extend(chunk)
        incomplete(owner.wait() is not None, "runtime_check_wait_timeout")
    except (base.ProbeError, OSError, KeyboardInterrupt) as error:
        primary = error
    finally:
        with defer_cleanup_interrupt() as interrupted:
            try:
                owner.terminate()
            except OSError:
                cleanup_error = True
            pipes = [owner.child.stdout, owner.child.stderr] if owner.child is not None else []
            for stream in (selector, *pipes):
                try:
                    stream.close()
                except OSError:
                    cleanup_error = True
        if interrupted[0] and primary is None:
            primary = KeyboardInterrupt()
    if primary is not None:
        raise primary
    incomplete(owner.reaped and not cleanup_error, "runtime_check_cleanup_incomplete")
    return owner.returncode, bytes(streams["stdout"]), bytes(streams["stderr"])


def runtime_module_absences(modules, inputs, invocation_profile):
    fixed = ["/etc/ld.so.preload", "/etc/qemu/qemu.conf",
             "/var/run/qemu/Debian_1_8.2.2+ds-0ubuntu1.18"]
    legacy_bundle = "/tmp/wmw-debug-d21-YFXXNEg5/run0/inputs/qemu-bundle"
    deny(modules["checked_absences"] == [*fixed, legacy_bundle], "module_absence_profile")
    base.safe_path(inputs)
    bundle = str(inputs / "qemu-bundle")
    if invocation_profile not in (base.SATA_OFF_INVOCATION_PROFILE, base.VAPIC_OFF_INVOCATION_PROFILE):
        deny(invocation_profile == base.INVOCATION_PROFILE and bundle == legacy_bundle,
             "module_absence_profile")
    return [*fixed, bundle]


def require_module_closure(inputs, abi_index, abi_blobs, invocation_profile, *,
                           deadline=None, receipts=None, run=None):
    incomplete('runtime_dependencies_ref' in abi_index,'runtime_module_closure_pending')
    deadline=time.monotonic()+5 if deadline is None else deadline
    runtime=strict_json(retained_blob(abi_index['runtime_dependencies_ref'],abi_blobs,1024*1024),1024*1024)
    incomplete('module_closure_ref' in runtime,'runtime_module_closure_pending')
    deny(runtime['module_closure_ref']['sha256']==MODULE_CLOSURE_SHA256,'module_closure_pin')
    modules=strict_json(retained_blob(runtime['module_closure_ref'],abi_blobs,1024*1024),1024*1024)
    absences=runtime_module_absences(modules,inputs,invocation_profile)
    for path in absences: deny(not os.path.lexists(path),'module_injection_path_present')
    directory=Path(modules['directory'])
    for target in (directory,Path('/etc'),Path('/var/run/qemu')):
        existing=target.resolve(strict=True)
        for ancestor in (existing,*existing.parents):
            info=ancestor.stat()
            deny(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and info.st_mode & 0o022==0,
                 'module_directory_permissions')
    deny(directory.resolve()==directory and sorted(p.name for p in directory.iterdir())==
         [r['name'] for r in modules['modules']], 'module_directory_changed')
    observed=[];raw_listings=[]
    for pin in modules['dependencies']+[r['pin'] for r in modules['modules']]:
        incomplete(time.monotonic()<deadline-1,'runtime_check_deadline')
        path=Path(pin['path']);deny(str(path.resolve(strict=True))==pin['path'],'module_path_retargeted')
        data,info=_pinned_read(path,pin['sha256'],64*1024*1024,private=False,archive_name=True)
        deny(len(data)==pin['length'] and info.st_uid==0 and info.st_mode & 0o022==0, 'module_file_identity')
        observed.append(pin)
    for row in modules['modules']:
        for alias in row['aliases']:
            deny(str(Path(alias['listed_path']).resolve(strict=True))==alias['resolved_path'],'module_alias_retargeted')
        code,out,err=_static_tool([runtime['loader']['path'],'--list',row['pin']['path']],clean_launch_env(inputs if run is None else run),deadline)
        deny(code==0 and not err,'module_loader_failed')
        if row['listing_kind']=='statically_linked':
            deny(out==b'\tstatically linked\n','module_listing_changed')
            normalized=[]
        else:
            normalized=parse_loader_aliases(out,'/lib64/ld-linux-x86-64.so.2',runtime['loader']['path'])
            deny(normalized==[(r['alias'],r['listed_path']) for r in row['aliases']], 'module_listing_changed')
        observed.append({'name':row['name'],'aliases':normalized})
        raw_listings.append({'name':row['name'],'sha256':hashlib.sha256(out).hexdigest()})
    if receipts is not None:
        receipts['module_closure_ref']=runtime['module_closure_ref']
        receipts['module_observations_sha256']=hashlib.sha256(canonical(observed)).hexdigest()
        receipts['module_raw_listing_sha256']=raw_listings
        receipts['checked_absences']=absences


def recheck_runtime(inputs, profile, abi_index, abi_blobs, expected_identity=None, *, deadline=None, receipts=None, run=None):
    deadline = time.monotonic()+5 if deadline is None else deadline
    incomplete(sys.platform == 'linux' and os.uname().machine == 'x86_64'
               and sys.byteorder == 'little' and ctypes.sizeof(ctypes.c_void_p)==8
               and os.confstr('CS_GNU_LIBC_VERSION') == 'glibc 2.39', 'runtime_native_abi')
    runtime = strict_json(retained_blob(abi_index['runtime_dependencies_ref'],abi_blobs,1024*1024),1024*1024)
    deny(os.uname().release == runtime['kernel_release'] == '6.8.0-142-generic'
         and runtime['libc_version'] == '2.39-0ubuntu8.9', 'runtime_version')
    deny(not os.path.lexists('/etc/ld.so.preload'), 'runtime_preload_present')
    inspection = strict_json(retained_blob(runtime['inspection_ref'],abi_blobs,1024*1024),1024*1024)
    for pin in [runtime['loader'],*runtime['libraries']]:
        incomplete(time.monotonic()<deadline-1,'runtime_check_deadline')
        path=Path(pin['path']); deny(str(path.resolve(strict=True))==pin['path'],'runtime_path_retargeted')
        data,info=_pinned_read(path,pin['sha256'],64*1024*1024,private=False)
        deny(len(data)==pin['length'] and info.st_uid==0 and info.st_mode & 0o022==0,
             'runtime_file_identity')
    for row in inspection['aliases']:
        deny(str(Path(row['listed_path']).resolve(strict=True))==row['resolved_path'], 'runtime_alias_retargeted')
    deny(str(Path(inspection['interpreter']['path']).resolve(strict=True))==runtime['loader']['path'],
         'runtime_interpreter_retargeted')
    base.validate_profile(profile,inputs)
    data,info=_pinned_read(inputs/'qemu',QEMU_SHA256,64*1024*1024)
    deny(info.st_mode & 0o100 != 0 and len(data)==abi_index['qemu_ref']['length'], 'qemu_executable_identity')
    identity={'device':info.st_dev,'inode':info.st_ino,'size':info.st_size}
    deny(expected_identity is None or identity==expected_identity, 'launch_identity_changed')
    # No dependency lookup may execute before loader/executable pins are checked.
    code,out,err=_static_tool([runtime['loader']['path'],'--list',str(inputs/'qemu')],
                             clean_launch_env(inputs if run is None else run),deadline)
    deny(code==0 and not err,'runtime_loader_failed')
    deny(parse_loader_aliases(out,inspection['interpreter']['path']) ==
         [(r['alias'],r['listed_path']) for r in inspection['aliases']], 'runtime_loader_alias_changed')
    collected={}
    require_module_closure(inputs,abi_index,abi_blobs,profile['invocation_profile'],
                           deadline=deadline,receipts=collected,run=run)
    if receipts is not None:
        deny(type(receipts) is dict and not receipts,'runtime_receipts_not_empty')
        receipts.update(schema_version=1,kind='run0_host_cpu_runtime_recheck_v0',
                        runtime_ref=abi_index['runtime_dependencies_ref'],kernel_release=os.uname().release,
                        libc_version=runtime['libc_version'],launch_identity=identity,env=clean_launch_env(inputs if run is None else run),
                        loader_listing_sha256=hashlib.sha256(out).hexdigest(),
                        normalized_aliases_sha256=hashlib.sha256(canonical(parse_loader_aliases(out,inspection['interpreter']['path']))).hexdigest(),
                        **collected)
    return identity


def observer_source_bytes():
    directory=Path(base.__file__).resolve().parent
    names=('run0_host_cpu_witness.py','run0_host_cpu_reader.py','boot_profile_capture.py',
           'boot_profile_inputs.py','run0_rsp_capability.py','run0_rsp.py')
    sources=[]
    for name in names:
        data,_=_read_regular(directory/name,1024*1024,private=False)
        sources.append({'path':name,'length':len(data),'sha256':hashlib.sha256(data).hexdigest()})
    python=Path(sys.executable).resolve(strict=True)
    data,_=_read_regular(python,64*1024*1024,private=False)
    return canonical({'schema_version':1,'kind':'run0_host_cpu_observer_v0',
                      'python':{'path':str(python),'length':len(data),'sha256':hashlib.sha256(data).hexdigest()},
                      'sources':sources})


C0_OBSERVER_SOURCE_NAMES = OBSERVER_SOURCE_NAMES + (
    'build_trace_artifact.py', 'replay_protocol_trace.py', 'run0_c0_paging.py',
    'run0_c0_decode.py', 'run0_c0_wire.py', 'run0_c0_rsp.py', 'run0_c0_entry.py',
    'run0_c0_acquire.py', 'run0_c0_host.py', 'run0_c0_budget.py', 'run0_c0_capture.py',
)


def c0_observer_source_bytes():
    """Closed C0 source inventory; static identity alone releases no launch."""
    value = strict_json(observer_source_bytes(), 65536)
    directory = Path(base.__file__).resolve().parent
    for name in C0_OBSERVER_SOURCE_NAMES[len(OBSERVER_SOURCE_NAMES):]:
        data, _ = _read_regular(directory / name, 1024 * 1024, private=False)
        value['sources'].append({'path': name, 'length': len(data),
                                'sha256': hashlib.sha256(data).hexdigest()})
    deny(tuple(row['path'] for row in value['sources']) == C0_OBSERVER_SOURCE_NAMES
         and all(exact_int(row['length'], 1, 1024 * 1024) for row in value['sources']),
         'c0_observer_source_inventory')
    value['kind'] = 'run0_c0_observer_v0'
    return canonical(value)


def prepare_launch(inputs,run,dossier,host_abi):
    for path in (inputs,run,dossier,host_abi): base.safe_path(path)
    deny(re.fullmatch('[a-z0-9-]{1,64}',run.name) is not None,'run_id')
    deny(run.parent.resolve()==run.parent and run.parent.is_dir()
         and not os.path.lexists(run),'run_parent_or_freshness')
    profile_bytes,_=_read_regular(inputs/'profile.json',65536,private=True)
    profile=decode_pinned_profile(profile_bytes)
    base.validate_profile(profile,inputs)
    deny(profile['inputs']['qemu']['sha256']==QEMU_SHA256,'qemu_package_pin')
    abi_ref,abi_blobs,index,layout,abi=load_launch_abi(host_abi)
    dossier_bytes,_=_pinned_read(dossier,SOURCE_DOSSIER_SHA256,65536)
    deny(dossier_bytes==retained_blob(index['source_dossier_ref'],abi_blobs,65536),'source_dossier_binding')
    launch_identity=recheck_runtime(inputs,profile,index,abi_blobs,run=run)
    esp=base.check_esp(inputs,profile)
    observer_bytes=observer_source_bytes()
    observer_ref={'path':'observer.json','length':len(observer_bytes),'sha256':hashlib.sha256(observer_bytes).hexdigest()}
    plan={'schema_version':1,'kind':'run0_host_cpu_witness_plan_v0','inputs':str(inputs),'run':str(run),
          'argv':base.build_argv(inputs,run,profile['invocation_profile']),'uid':os.getuid(),'gid':os.getgid(),'launch_identity':launch_identity,
          'profile_sha256':profile_pin(profile),'abi_sha256':abi_ref['sha256'],
          'source_dossier_sha256':index['source_dossier_ref']['sha256'],'observer_ref':observer_ref,'esp_validation':esp}
    return plan,profile,profile_bytes,observer_bytes,abi_ref,abi_blobs,layout,abi


if __name__ == "__main__":
    raise SystemExit(main())
