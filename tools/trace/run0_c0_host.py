"""Closed C0 receiving port for the shared owned host-observation body.

Fixture-qualified adapter only. The collector's prepared-launch registration,
runtime observer/source join and live current-RAM issuer remain separate gates.
This module grants no guest-memory read and never finalizes retained C0 PASS.
"""

from dataclasses import dataclass
import subprocess
import threading
import time

from boot_profile_capture import ProbeError, deny, incomplete
import run0_c0_wire as transport
import run0_host_cpu_witness as witness


class _WireBudget:
    """Helper retention is charged to the original common wire, never reset."""

    def __init__(self, wire):
        deny(type(wire) is transport.C0Wire, "c0_host_wire")
        self._wire = wire

    @property
    def byte_limit(self):
        return transport.MAX_RETAINED_BYTES - transport.REPORT_RESERVE - transport.FAILURE_RESERVE

    @property
    def retained_bytes(self):
        return self._wire._charged

    def retain(self, count):
        self._wire.reserve_output(count)


class _C0ObservationPort:
    """Fixed peer/bracket/pump surface; no request/address callback exists."""

    def __init__(self, wire, lease):
        deny(type(wire) is transport.C0Wire, "c0_host_wire")
        wire._lease(lease)
        self.wire, self.lease = wire, lease
        self.deadline_ns = lease.deadline_ns
        # This is the only ns/seconds conversion. The wire already reserved
        # VM teardown; do not pass it through reset Budget's second subtraction.
        self.deadline = self.deadline_ns / 1_000_000_000

    def peer(self):
        receipt = self.wire.host_peer_credentials(self.lease)
        return receipt.raw_bytes, receipt.observed_ns

    def bracket(self, phase):
        receipt = self.wire.host_bracket(self.lease, phase)
        return dict(receipt.operations), receipt.cpu_identity, receipt.hmp_bytes

    def pump(self):
        self.wire.pump_host_observation(self.lease)

    @staticmethod
    def field_mode(state):
        incomplete(state["cpl"] == 0 and state["cs64"] and state["lma"]
                   and all(state[key] for key in ("no_npt", "no_svm_guest", "no_smm")),
                   "c0_field_mode")

    @staticmethod
    def changed():
        return "c0_host_bracket_changed"


@dataclass(frozen=True, slots=True, init=False)
class HostObservationReceipt:
    _owner: object
    stop_event_seq: int
    deadline_ns: int
    finished_ns: int
    process_identity: tuple[int, int, int]
    cpu_identity: tuple[str, int, int]
    field_state: tuple
    field_reads: tuple
    helper_lifecycles: tuple

    def __init__(self, *args, **kwargs):
        raise TypeError("host observation receipts are issued by the owned observation")


def _freeze(value):
    if type(value) is dict:
        return tuple((key, _freeze(item)) for key, item in sorted(value.items()))
    if type(value) in (tuple, list):
        return tuple(_freeze(item) for item in value)
    deny(type(value) in (type(None), bool, int, str, bytes), "c0_host_receipt_value")
    return value


def _issued_observation(receipt, wire, lease):
    return (type(receipt) is HostObservationReceipt
            and type(getattr(receipt, "_owner", None)) is _OwnedC0Observation
            and receipt._owner._receipt is receipt
            and receipt._owner._wire is wire and receipt._owner._lease is lease
            and receipt._owner._finished)


class _OwnedC0Observation(witness.OwnedCPUObservation):
    """Internal receiving adapter; source qualification is not launch authority."""

    def __init__(self, child, wire, confirmed, before_registers, native, abi,
                 launch_path, launch_identity):
        deny(type(wire) is transport.C0Wire, "c0_host_wire")
        wire._current_stop(confirmed)
        deny(type(before_registers) is transport.SelectedC0Registers
             and before_registers is wire._before_registers, "c0_host_register_identity")
        super().__init__(child, None, _WireBudget(wire), native, abi, launch_path, launch_identity)
        self._wire, self._confirmed, self._registers = wire, confirmed, before_registers
        self._lease = self._receipt = None
        self._finished = False

    def _metadata(self, procdir, phase):
        value = super()._metadata(procdir, phase)
        # Parsed retained byte slices coexist with the helper's raw transcript.
        self.budget.retain(sum(len(item) for item in value.values() if type(item) is bytes))
        return value

    def _send_frame(self, fd, frame, helper):
        # begin/admit bytes remain held beside the actual sent request prefix.
        self.budget.retain(len(frame))
        return super()._send_frame(fd, frame, helper)

    def observe(self):
        deny(threading.current_thread() is threading.main_thread()
             and threading.active_count() == 1, "main_thread_owner_required")
        deny(type(self.child) is subprocess.Popen and self.child.returncode is None
             and self._lease is None and self._receipt is None, "owned_observation_state")
        # The real collector must separately bind this child, executable/ABI and
        # borrowed wire to its prepared owned launch before invoking this port.
        self._lease = self._wire.begin_host_observation(self._confirmed, self._registers)
        with self._wire._entry_attempt():
            import run0_host_cpu_reader as reader
            try:
                return self._observe_admitted()
            except reader.ReaderError as error:
                raise ProbeError(error.status, error.reason) from error

    def _observe_admitted(self):
        state = self._observe_body(_C0ObservationPort(self._wire, self._lease))
        self._time()
        incomplete(set(self.helpers) == {"metadata_before", "fields", "metadata_after"}
                   and all(helper.closed and helper.reaped and not helper.io_errors
                           and set(helper.eofs) == {"stdout", "stderr"}
                           and helper.returncode == 0 for helper in self.helpers.values()),
                   "c0_host_helper_receipts")
        incomplete(len(self.reads) == 14 and sum(row["length"] for row in self.reads) == 104,
                   "c0_host_field_inventory")
        receipt = object.__new__(HostObservationReceipt)
        fields = {"_owner": self, "stop_event_seq": self._lease.stop_event_seq,
                  "deadline_ns": self._lease.deadline_ns, "finished_ns": time.monotonic_ns(),
                  "process_identity": (self.process["qemu_pid"], self.process["ppid"],
                                       self.process["starttime_ticks"]),
                  "cpu_identity": self._wire._host_after.cpu_identity,
                  "field_state": _freeze(state), "field_reads": _freeze(self.reads),
                  "helper_lifecycles": tuple((role, _freeze(helper.lifecycle))
                                             for role, helper in self.helpers.items())}
        for name, value in fields.items():
            object.__setattr__(receipt, name, value)
        self._finished, self._receipt = True, receipt
        try:
            self._wire.finish_host_observation(self._lease, receipt)
        except BaseException:
            self._finished, self._receipt = False, None
            raise
        return receipt
