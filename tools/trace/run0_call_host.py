"""Closed parent host observation. No public runtime or field-read issuer.

The old reset/C0 modules and reader protocol are unchanged. This parent-only
receiving body requires Root's exact held observation before effects. Its private
synthetic controls establish mechanics; whole source/copy/runtime qualification
and genuine Root graph publication remain separate prerequisites.
"""
from contextlib import ExitStack
from dataclasses import dataclass
import fcntl
import importlib
import os
from pathlib import Path
import secrets
import selectors
import stat
import subprocess
import sys
import threading
import time

from boot_profile_capture import ProbeError, deny, incomplete
from run0_c0_decode import C0DecodeError
import run0_call_wire as transport
from run0_call_budget import ParentAccounting, REGULAR_BYTES
from run0_call_owner import ParentDeadlines, ParentOwnedWait, ParentOwnedHelper
import run0_host_cpu_witness as witness

canonical = witness.canonical
decode_peer = witness.decode_peer
decode_sigchld = witness.decode_sigchld
parse_proc_stat = witness.parse_proc_stat
pidfd_check = witness.pidfd_check
NATIVE_LAYOUT = witness.NATIVE_LAYOUT
LOCAL_ROLES = ("metadata_before", "fields", "metadata_after")


def _root_module():
    try:
        return importlib.import_module("run0_call_capture")
    except ImportError as error:
        raise ProbeError("INCOMPLETE", "call_host_producer_pending") from error


def _root_method(observation, name):
    # Names are fixed at the two call sites, never supplied by a public caller.
    deny(name in ("_require_host_observation", "_register_host_helper"), "call_host_root_method")
    root = _root_module()
    try:
        registration = observation._registration
        runtime = registration._owner
        deny(type(registration) is root.ClosedOwnedCallRegistration
             and type(runtime) is root._OwnedCallRuntime
             and runtime._registration is registration
             and runtime._wire is observation._wire
             and registration.wire is observation._wire,
             "call_host_registration_identity")
        method = getattr(root._OwnedCallRuntime, name, None)
        incomplete(callable(method), "call_host_producer_pending" if name == "_require_host_observation"
                   else "call_host_helper_registration_pending")
    except AttributeError as error:
        raise ProbeError("INCOMPLETE", "call_host_producer_pending") from error
    return runtime, method


class _ParentBudget:
    def __init__(self, registration):
        root = _root_module()
        deny(type(registration) is root.ClosedOwnedCallRegistration
             and type(registration.accounting) is ParentAccounting
             and type(registration.deadlines) is ParentDeadlines
             and registration.accounting.started_ns == registration.deadlines.started_ns,
             "call_host_accounting")
        self.accounting = registration.accounting

    byte_limit = REGULAR_BYTES

    @property
    def retained_bytes(self):
        return self.accounting._regular

    def copy(self, count, purpose):
        deny(type(count) is int and count >= 0 and type(purpose) is str
             and 0 < len(purpose) <= 64, "call_host_copy_count")
        self.accounting.reserve_output(count)

    def retain(self, count):
        self.copy(count, "helper_retained_prefix")

    def metadata_parse(self, value, purpose):
        # text decode, split lines, split fields, retained parser strings;
        # map+smaps digest concatenations (two intermediates); stat parsing.
        lengths = sum(len(value[name]) for name in ("stat", "maps", "smaps"))
        self.copy(6 * lengths + 2, purpose)


class _ParentHostHelper(ParentOwnedHelper):
    """Exact parent helper; only fixed buffered IO is specialized for prepay."""
    def _step(self, deadline):
        incomplete(time.monotonic() < deadline, "helper_io_deadline")
        if self.pump is not None:
            self.pump()
        remaining = deadline - time.monotonic()
        incomplete(remaining > 0, "helper_io_deadline")
        for key, _ in self.selector.select(min(remaining, 0.025)):
            incomplete(time.monotonic() < deadline, "helper_io_deadline")
            name, data, limit = key.data
            # One lazily allocated buffer is held for this helper's lifetime.
            # readv reuses it; short reads/EOF/EAGAIN allocate no requested-size
            # byte string and must not spend a requested-size copy allowance.
            if not hasattr(self, "_host_read_storage"):
                self.budget.copy(65536, "helper_readv_buffer")
                buffer = bytearray(65536)
                self._host_read_storage = (buffer, memoryview(buffer))
            credit = self.budget.byte_limit - self.budget.retained_bytes
            available = min(limit - len(data), credit // 2)
            count = min(65536, available + 1)
            try:
                returned = os.readv(key.fd, [self._host_read_storage[1][:count]])
            except (BlockingIOError, InterruptedError):
                continue
            except OSError as error:
                self.io_errors.append({"name": name, "operation": "read", "errno": error.errno})
                self.selector.unregister(key.fileobj)
                raise
            if returned == 0:
                self.selector.unregister(key.fileobj)
                self.eofs.add(name)
                continue
            length = min(returned, available)
            # Charge the actual prefix bytes and destination copy before either
            # allocation/growth. The reusable buffer already holds any overflow.
            self.budget.copy(2 * length, "helper_actual_prefix_and_buffer")
            prefix = bytes(self._host_read_storage[1][:length])
            data.extend(prefix)
            if returned > available:
                self.io_errors.append({"name": name, "operation": "read", "errno": None,
                                       "observed_overflow_bytes": returned - available})
                self.selector.unregister(key.fileobj)
                incomplete(False, "helper_output_limit")


class _ParentObservationPort:
    def __init__(self, wire, lease):
        deny(type(wire) is transport.CallWire, "call_host_wire")
        wire._lease(lease)
        self.wire, self.lease = wire, lease
        self.deadline_ns = lease.deadline_ns
        self.deadline = self.deadline_ns / 1_000_000_000

    def peer(self):
        value = self.wire.host_peer_credentials(self.lease)
        return value.raw_bytes, value.observed_ns

    def bracket(self, phase):
        value = self.wire.host_bracket(self.lease, phase)
        return dict(value.operations), value.cpu_identity, value.hmp_bytes

    def pump(self):
        self.wire.pump_host_observation(self.lease)

    @staticmethod
    def field_mode(state):
        incomplete(state["cpl"] == 0 and state["cs64"] and state["lma"]
                   and all(state[key] for key in ("no_npt", "no_svm_guest", "no_smm")),
                   "call_field_mode")

    @staticmethod
    def changed():
        return "call_host_bracket_changed"


@dataclass(frozen=True, slots=True, init=False)
class ParentHostObservationReceipt:
    _owner: object
    _registration: object
    _wire: object
    epoch: str
    stop: object
    lease: object
    before_registers: object
    before_bracket: object
    after_bracket: object
    finished_ns: int
    process_identity: tuple
    field_state: tuple
    field_reads: tuple
    helper_lifecycles: tuple

    def __init__(self, *args, **kwargs):
        raise TypeError("only the held parent observation issues this receipt")


def _freeze(value):
    if type(value) is dict:
        return tuple((key, _freeze(item)) for key, item in sorted(value.items()))
    if type(value) in (tuple, list):
        return tuple(_freeze(item) for item in value)
    deny(type(value) in (type(None), bool, int, str, bytes), "call_host_receipt_value")
    return value


def _issued_parent_observation(receipt, wire, lease):
    root = _root_module()
    try:
        observation = receipt._owner
        registration = wire._registration
        runtime = registration._owner
        return (type(receipt) is ParentHostObservationReceipt
                and type(observation) is _OwnedParentObservation
                and type(wire) is transport.CallWire
                and type(registration) is root.ClosedOwnedCallRegistration
                and type(runtime) is root._OwnedCallRuntime
                and runtime._registration is registration and runtime._wire is wire
                and type(runtime._observations) is dict
                and runtime._observations.get(lease.stop.epoch) is observation
                and observation._receipt is receipt and observation._finished
                and observation._registration is registration
                and observation._wire is wire and observation._lease is lease
                and observation._confirmed is lease.stop
                and observation._registers is lease.before_registers
                and receipt._registration is registration and receipt._wire is wire
                and receipt.epoch == lease.stop.epoch and receipt.stop is lease.stop
                and receipt.lease is lease and receipt.before_registers is lease.before_registers
                and receipt.before_bracket is wire._host_before
                and receipt.after_bracket is wire._host_after
                and lease.started_ns <= receipt.finished_ns < lease.deadline_ns)
    except AttributeError:
        return False


class _OwnedParentObservation(witness.OwnedCPUObservation):
    """Inert derivation from the exact Root graph; observe is a separate effect."""
    def __init__(self, registration, stop, before_registers):
        root = _root_module()
        deny(type(registration) is root.ClosedOwnedCallRegistration,
             "call_host_registration_identity")
        try:
            runtime = registration._owner
            deny(type(runtime) is root._OwnedCallRuntime
                 and runtime._registration is registration
                 and type(runtime._wire) is transport.CallWire
                 and registration.wire is runtime._wire
                 and type(runtime.qemu_owner) is ParentOwnedWait
                 and registration.qemu_owner is runtime.qemu_owner
                 and registration.prepared is runtime.prepared,
                 "call_host_registration_identity")
            wire = runtime._wire
            deny(type(stop) is transport.EpochStopReceipt
                 and stop._registration is registration and stop._wire is wire
                 and stop.epoch in ("C0", "C1", "C2"), "call_host_stop_identity")
            wire._current_stop(stop)
            deny(type(before_registers) is transport.SelectedEpochRegisters
                 and before_registers is wire._before_registers
                 and before_registers._registration is registration
                 and before_registers._wire is wire and before_registers.stop is stop
                 and before_registers.phase == "before", "call_host_register_identity")
            from run0_c0_acquire import _registers
            _registers(before_registers.values)
            super().__init__(runtime.qemu_owner.child, None, _ParentBudget(registration),
                runtime.native, runtime.prepared.field_abi,
                str(Path(runtime.prepared.inputs) / "qemu"), runtime._launch_identity)
        except C0DecodeError as error:
            raise ProbeError(error.status, error.reason) from error
        except AttributeError as error:
            raise ProbeError("INCOMPLETE", "call_host_producer_pending") from error
        self._registration, self._wire = registration, wire
        self._confirmed, self._registers = stop, before_registers
        self._lease = self._receipt = None
        self._finished = False

    def _helper(self, role, result, output, descriptors, extra, limit):
        import run0_host_cpu_reader as reader
        deny(role in LOCAL_ROLES and role not in self.helpers
             and all(item.reaped for item in self.helpers.values()), "helper_ownership")
        self._time()
        runtime, guard = _root_method(self, "_require_host_observation")
        guard(runtime, self._wire, self)
        _, register = _root_method(self, "_register_host_helper")
        helper = self.helpers[role] = _ParentHostHelper(
            self._confirmed.epoch.lower() + "_" + role, result, self.deadline_ns,
            self._registration.deadlines, pump=self._pump, budget=self.budget)
        mode = "--field-reader" if role == "fields" else "--metadata-reader"
        argv = [sys.executable, "-E", "-s", "-B", str(Path(reader.__file__).resolve()), mode]
        inherited = dict(descriptors, result=output)
        for name, fd in inherited.items():
            argv.extend((f"--{name}-fd", str(fd)))
        primary = None
        try:
            helper.start(argv + extra, tuple(inherited.values()), limit, 16384)
        except BaseException as error:
            primary = error
            raise
        finally:
            if helper.child is not None:
                try:
                    register(runtime, self._wire, self, helper)
                except BaseException:
                    if primary is None:
                        raise
                    self.secondary_failures.append("host_helper_registration_failed")
        return helper

    def _close_helper(self, helper):
        primary = sys.exception()
        try:
            super()._close_helper(helper)
        except BaseException:
            self.secondary_failures.append("parent_helper_cleanup_failure")
            if primary is None:
                raise

    def _completed(self, helper):
        helper.drain()
        code = helper.wait(pump=self._pump)
        deny(code != 2, "reader_denied")
        incomplete(code == 0 and not helper.io_errors, "reader_incomplete")
        self._time()
        self.budget.copy(len(helper.output), "completed_output_bytes")
        return bytes(helper.output)

    def _send_frame(self, fd, frame, helper):
        # Canonical request buffers were prepaid before encoding; reserve the
        # full actual cumulative sent-prefix copy before the first write.
        self.budget.copy(len(frame), "actual_request_sent_prefix")
        remaining = memoryview(frame)
        while remaining:
            incomplete(time.monotonic() < helper.io_deadline, "field_request_deadline")
            try:
                count = os.write(fd, remaining)
            except (BlockingIOError, InterruptedError):
                helper._step(helper.io_deadline)
                continue
            incomplete(count > 0, "field_request_eof")
            self.request_sent.extend(remaining[:count])
            remaining = remaining[count:]

    def _field_receipts(self, raw, begin, maps, *, head_only=False):
        # splitlines, JSON text decode/parsed strings and per-line framing;
        # decoded reads104 plus fixed head/flag slices and concatenation<=128.
        self.budget.copy(4 * len(raw) + 128, "field_lines_json_hex_payload")
        return witness.field_receipts(raw, begin, maps, self.abi, head_only=head_only)

    def observe(self):
        deny(threading.current_thread() is threading.main_thread()
             and threading.active_count() == 1, "main_thread_owner_required")
        deny(type(self.child) is subprocess.Popen and self.child.returncode is None
             and self._lease is None and self._receipt is None, "owned_observation_state")
        runtime, guard = _root_method(self, "_require_host_observation")
        guard(runtime, self._wire, self)
        _root_method(self, "_register_host_helper")
        self._lease = self._wire.begin_host_observation(self._confirmed, self._registers)
        with self._wire._epoch_attempt(self._confirmed):
            import run0_host_cpu_reader as reader
            try:
                return self._observe_admitted()
            except reader.ReaderError as error:
                raise ProbeError(error.status, error.reason) from error

    def _observe_admitted(self):
        state = self._observe_body(_ParentObservationPort(self._wire, self._lease))
        self._time()
        incomplete(tuple(self.helpers) == LOCAL_ROLES
            and all(type(helper) is _ParentHostHelper and helper.closed and helper.reaped
                    and not helper.io_errors and helper.eofs == {"stdout", "stderr"}
                    and helper.returncode == 0 for helper in self.helpers.values()),
            "call_host_helper_receipts")
        incomplete(len(self.reads) == 14 and sum(row["length"] for row in self.reads) == 104,
                   "call_host_field_inventory")
        receipt = object.__new__(ParentHostObservationReceipt)
        values = dict(_owner=self, _registration=self._registration, _wire=self._wire,
            epoch=self._confirmed.epoch, stop=self._confirmed, lease=self._lease,
            before_registers=self._registers, before_bracket=self._wire._host_before,
            after_bracket=self._wire._host_after, finished_ns=time.monotonic_ns(),
            process_identity=(self.process["qemu_pid"], self.process["ppid"],
                              self.process["starttime_ticks"]), field_state=_freeze(state),
            field_reads=_freeze(self.reads), helper_lifecycles=tuple(
                (role, _freeze(helper.lifecycle)) for role, helper in self.helpers.items()))
        for name, value in values.items():
            object.__setattr__(receipt, name, value)
        self._finished, self._receipt = True, receipt
        try:
            self._wire.finish_host_observation(self._lease, receipt)
        except BaseException:
            self._finished, self._receipt = False, None
            raise
        return receipt

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
        self.budget.copy(len(raw) + 3 * 4096, "metadata_frame_slices_and_exe_json")
        value = reader.parse_metadata_output(raw)
        self.budget.copy(6 * len(value["mountinfo"]), "mount_decode_lines_fields_paths")
        reader.bind_mount_path(value["mountinfo"], self.launch_path, value["exe"])
        exe = value["exe"]
        deny((exe["device"], exe["inode"], exe["size"]) == self.launch_identity
             and exe["sha256"] == self.abi.elf.sha256
             and exe["build_id"] == self.abi.elf.build_id, "owned_exe_identity")
        return value

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
            self.budget.copy(3 * reader.FIELD_INPUT, "begin_json_text_encoded_buffer")
            self.begin_raw = canonical(begin)
            deny(len(self.begin_raw) <= reader.FIELD_INPUT, "field_request_limit")
            self._send_frame(writer, self.begin_raw, helper)
            admit = None

            def has_head():
                nonlocal admit
                self.budget.copy(len(helper.output), "head_output_bytes")
                admit = self._field_receipts(bytes(helper.output), begin, maps, head_only=True)
                return admit is not None

            helper.until(has_head)
            self.budget.copy(3 * reader.FIELD_INPUT, "admit_json_text_encoded_buffer")
            self.admit_raw = canonical(admit)
            deny(len(self.begin_raw) + len(self.admit_raw) <= reader.FIELD_INPUT,
                 "field_request_limit")
            self._send_frame(writer, self.admit_raw, helper)
            raw = self._completed(helper)
            derived, self.reads, state = self._field_receipts(raw, begin, maps)
            deny(derived == admit, "field_admission_changed")
        self._close_helper(helper)
        self._require_helper_closed(helper)
        return state, [*maps.global_maps, admit["map"]]

    def _observe_body(self, port):
        """Parent copy of the fixed descriptor/helper flow; no old port promotion."""
        import run0_host_cpu_reader as reader
        deny(type(port) is _ParentObservationPort and type(self) is _OwnedParentObservation,
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
        self.budget.copy(3 * 152, "sigchld_native_buffers")
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
                self.budget.copy(120, "statfs_native_buffer")
                magic = self.native.filesystem_magic(procdir)
                deny(stat.S_ISDIR(info.st_mode) and magic == NATIVE_LAYOUT["proc_super_magic"],
                     "owned_proc_directory")
                self.process["procdir_identity"] = {
                    "dev": info.st_dev, "inode": info.st_ino, "mode": info.st_mode,
                    "statfs_magic": magic,
                }
                self.before = self._metadata(procdir, "before")
                incomplete(not self.secondary_failures, "metadata_descriptor_cleanup")
                self.budget.metadata_parse(self.before, "before_stat_and_maps")
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
                self.budget.metadata_parse(self.before, "consistency_before")
                self.budget.metadata_parse(self.after, "consistency_after")
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
