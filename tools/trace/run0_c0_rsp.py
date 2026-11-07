"""Closed reset semantic backend for the C0 shared wire."""

from dataclasses import dataclass

from run0_rsp import TargetDescription, RegisterSnapshot, _ResetSequence


@dataclass(frozen=True, slots=True)
class ResetBootstrap:
    target: TargetDescription
    registers: RegisterSnapshot
    physical_mode: int


class _C0Reset(_ResetSequence):
    def __init__(self, wire):
        super().__init__()
        self._wire = wire

    def _exchange(self, name, payload):
        self._require_state('new', 'supported', 'thread_first', 'thread_next',
                            'thread_current', 'thread_general', 'thread_continue',
                            'target_read', 'described', 'registers', 'qemu_supported',
                            'physical_zero', 'physical_set')
        from run0_rsp import require
        require(type(payload) is bytes and self._payload_allowed(name, payload),
                'rsp_forbidden_operation', terminal=False)
        return self._wire._rsp_exchange(name, payload)

    def _semantic(self, condition, reason, *, status='DENY'):
        if not condition:
            self._state = 'failed'
            self._wire._rsp_semantic(reason, status)

    def prepare(self):
        self.query_supported()
        self.query_threads()
        self.select_thread()
        target = self.read_target_description()
        registers = self.read_reset_registers()
        self._semantic(registers.values[16] == 0xfff0, 'rsp_reset_rip')
        self.query_qemu_supported()
        self.query_physical_mode()
        self.enable_physical_mode()
        return ResetBootstrap(target, registers, self.query_physical_mode())
