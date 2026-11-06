#!/usr/bin/env python3
"""Owned QEMU provenance/capability/prior-diagnostic probe, not a CPU capture.

`plan` validates byte pins and independently checks the materialized FAT volume.
`probe` additionally launches exactly the fixed profile below in a fresh private
directory. Its only guest execution control is one QMP cont followed by teardown.
No RSP connection, physical/virtual memory read, breakpoint or injected guest
operation is implemented. Missing diagnostics never trigger another run or an
address-discovery fallback. An actual C0/C1/C2 collector is a later reviewed step.

Format/source references: QEMU v8.2.2 docs/interop/qmp-spec.rst and
qapi/misc-target.json; edk2-stable202402 OvmfPkg/OvmfPkg.dec (PcdDebugIoPort=0x402),
OvmfPkg/Library/PlatformDebugLibIoPort/DebugLib.c, and the load-diagnostic source
referenced by boot_profile_inputs.py. Actual archived source hashes and package/
build records belong to the prepared profile's required provenance references.
"""
import argparse
from collections import deque
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time

import boot_profile_inputs as entry


VM_SECONDS = 60
INVOCATION_PROFILE = 'q35-8.2-tcg-qemu64-virtio-ro-esp-debugcon-v0'
TEARDOWN_SECONDS = 5
BOOT_SECONDS = 20
RESPONSE_SECONDS = 5
MAX_MESSAGES = 128
MAX_FRAME = 65536
MAX_BYTES = 31 * 1024 * 1024  # One further MiB reserved for the final report.
INPUT_LIMITS = {name: entry.ARTIFACT_LIMITS[name] for name in (
    'efi', 'symbols', 'init', 'qemu', 'gdb', 'symbol_tool', 'ovmf_code', 'initial_vars', 'esp')}
INPUT_LIMITS.update(qemu_img=256 * 1024 * 1024, fsck_fat=16 * 1024 * 1024,
                    seven_zip=32 * 1024 * 1024, seven_zip_module=32 * 1024 * 1024)
PROVENANCE_KEYS = ('source_archive', 'build_record', 'build_log', 'package_record',
                   'symbol_record', 'primary_source_record')
COMMANDS = {
    'qmp_capabilities': {}, 'query-commands': {}, 'query-status': {},
    'query-cpus-fast': {}, 'query-cpu-model-expansion':
        {'type': 'full', 'model': {'name': 'qemu64'}}, 'cont': {}, 'quit': {},
}


class ProbeError(Exception):
    def __init__(self, status, reason):
        super().__init__(reason)
        self.status, self.reason = status, reason


def deny(condition, reason):
    if not condition:
        raise ProbeError('DENY', reason)


def incomplete(condition, reason):
    if not condition:
        raise ProbeError('INCOMPLETE', reason)


def utc():
    return datetime.now(timezone.utc).isoformat()


class Budget:
    def __init__(self, deadline, byte_limit=MAX_BYTES):
        self.deadline = deadline
        self.byte_limit = byte_limit
        self.message_count = 0
        self.retained_bytes = 0

    def remaining(self, reserve=0):
        left = self.deadline - reserve - time.monotonic()
        incomplete(left > 0, 'vm_deadline')
        return left

    def message(self, teardown=False):
        self.remaining(0 if teardown else TEARDOWN_SECONDS)
        incomplete(self.message_count < MAX_MESSAGES, 'event_limit')
        self.message_count += 1

    def retain(self, length):
        incomplete(length <= self.byte_limit - self.retained_bytes, 'storage_limit')
        self.retained_bytes += length


def decode_frame(data):
    incomplete(len(data) <= MAX_FRAME, 'qmp_frame_limit')
    try:
        value = entry.decode_packet(data)
    except entry.AdmissionError as error:
        raise ProbeError('DENY', 'qmp_json') from error
    deny(type(value) is dict, 'qmp_object')
    return value


class QMP:
    """Exact allowlist, request identity and paused-to-running control boundary."""
    def __init__(self, wire, budget):
        self.wire, self.budget = wire, budget
        self.next_id = 1
        self.negotiated = False
        self.paused_verified = False
        self.resumed = False
        self.events, self.operations = [], []

    def receive(self, deadline):
        frame = self.wire.next(deadline)
        self.budget.message()
        return decode_frame(frame)

    def negotiate(self):
        deadline = min(time.monotonic() + RESPONSE_SECONDS,
                       self.budget.deadline - TEARDOWN_SECONDS)
        greeting = self.receive(deadline)
        deny(set(greeting) == {'QMP'} and type(greeting['QMP']) is dict,
             'qmp_greeting')
        self.greeting = greeting
        self.request('qmp_capabilities')
        self.negotiated = True

    def unsolicited(self, value):
        deny('event' in value and set(value) <= {'event', 'timestamp', 'data'},
             'unsolicited_response')
        deny(type(value['event']) is str and type(value.get('timestamp')) is dict,
             'qmp_event_shape')
        if value['event'] == 'RESUME':
            deny(self.resumed, 'unsolicited_resume')
        if value['event'] in ('RESET', 'STOP'):
            raise ProbeError('INCOMPLETE', 'unexpected_guest_state_event')
        self.events.append({'received_ns': time.monotonic_ns(), 'raw_event': value})

    def request(self, command, arguments=None):
        arguments = {} if arguments is None else arguments
        hmp = command == 'human-monitor-command' and arguments in (
            {'command-line': 'info mtree -f'}, {'command-line': 'info registers'})
        deny(hmp or command in COMMANDS and arguments == COMMANDS[command], 'command_denied')
        deny(self.negotiated or command == 'qmp_capabilities', 'qmp_not_negotiated')
        if command == 'cont':
            deny(self.paused_verified and not self.resumed, 'resume_without_paused_witness')
        if command not in ('query-status', 'cont', 'quit'):
            deny(not self.resumed, 'inspection_while_running')
        self.budget.message()  # Refuse before dispatch if any operation budget expired.
        identifier = self.next_id
        self.next_id += 1
        request = {'execute': command, 'id': identifier}
        if arguments:
            request['arguments'] = arguments
        started = time.monotonic_ns()
        deadline = min(time.monotonic() + RESPONSE_SECONDS,
                       self.budget.deadline - TEARDOWN_SECONDS)
        if command == 'cont':
            self.resumed = True
        record = {'id': identifier, 'request': request, 'started_ns': started,
                  'finished_ns': None, 'result': 'pending'}
        self.operations.append(record)
        # QMP v8.2.2 requires CRLF on server output; client objects complete at
        # '}'. Avoid leaving optional whitespace unread during final quit.
        suffix = b'' if command == 'quit' else b'\r\n'
        self.wire.send(json.dumps(request, separators=(',', ':')).encode() + suffix, deadline)
        while True:
            response = self.receive(deadline)
            if 'event' in response:
                self.unsolicited(response)
                continue
            deny(set(response) in ({'return', 'id'}, {'error', 'id'}) and
                 type(response['id']) is int and response['id'] == identifier,
                 'qmp_response_identity')
            record['finished_ns'] = time.monotonic_ns()
            record['response'] = response
            record['result'] = 'error' if 'error' in response else 'ok'
            incomplete('error' not in response, 'qmp_command_error')
            result = response['return']
            if command == 'query-status' and not self.resumed:
                self.paused_verified = (type(result) is dict and
                    result.get('running') is False and result.get('status') in ('prelaunch', 'paused'))
            return result


def safe_path(path):
    text = str(path)
    deny(path.is_absolute() and re.fullmatch(r'[A-Za-z0-9_./-]+', text) and
         '..' not in path.parts, 'unsafe_resource_path')


def private_regular(path):
    info = path.lstat()
    deny(not stat.S_ISLNK(info.st_mode), 'input_symlink')
    deny(stat.S_ISREG(info.st_mode), 'input_not_regular')
    deny(info.st_nlink == 1, 'shared_input_inode')
    deny(info.st_uid == os.getuid() and info.st_mode & 0o077 == 0, 'input_not_private')


def create_run(path):
    safe_path(path)
    deny(path.parent.resolve() == path.parent, 'run_parent_symlink')
    try:
        path.mkdir(mode=0o700)
    except FileExistsError as error:
        raise ProbeError('DENY', 'run_directory_exists') from error
    deny(path.stat().st_uid == os.getuid() and path.stat().st_mode & 0o077 == 0,
         'run_not_private')


def build_argv(inputs, run):
    safe_path(inputs)
    safe_path(run)
    deny(len(str(run / 'serial.sock').encode()) < 104, 'unix_socket_path_length')
    return [str(inputs / 'qemu'), '-machine', 'pc-q35-8.2,accel=tcg',
        '-cpu', 'qemu64', '-smp', '1', '-m', '512M', '-nic', 'none', '-S',
        '-display', 'none', '-no-reboot',
        '-drive', 'if=pflash,format=raw,readonly=on,file=' + str(inputs / 'ovmf_code'),
        '-drive', 'if=pflash,format=raw,file=' + str(run / 'vars.fd'),
        '-drive', 'if=none,id=esp,format=raw,readonly=on,file=' + str(inputs / 'esp'),
        '-device', 'virtio-blk-pci,drive=esp',
        '-qmp', 'unix:' + str(run / 'qmp.sock') + ',server=on,wait=off',
        '-chardev', 'socket,path=' + str(run / 'gdb.sock') + ',server=on,wait=off,id=gdb0',
        '-gdb', 'chardev:gdb0',
        '-chardev', 'socket,path=' + str(run / 'serial.sock') + ',server=on,wait=off,id=serial0',
        '-serial', 'chardev:serial0',
        '-chardev', 'socket,path=' + str(run / 'debug.sock') + ',server=on,wait=off,id=debug',
        '-device', 'isa-debugcon,iobase=0x402,chardev=debug']


def reap_owned(child, deadline, *, acknowledged_quit=False):
    """Only the child started with start_new_session=True is eligible for signals."""
    actions = []
    grace = {}
    if acknowledged_quit:
        outcome = {'outcome': 'already_exited', 'wait_limit_seconds': 0}
        grace['quit_grace'] = outcome
        if child.poll() is None:
            wait_limit = min(0.5, max(0, deadline - time.monotonic()))
            outcome.update(outcome='deadline_exhausted', wait_limit_seconds=wait_limit)
            if wait_limit > 0:
                try:
                    child.wait(timeout=wait_limit)
                    outcome['outcome'] = 'exited'
                except subprocess.TimeoutExpired:
                    outcome['outcome'] = 'timeout'
    def signal_group(sig, label):
        try:
            os.killpg(child.pid, sig)
            actions.append(label)
        except ProcessLookupError:
            # Exit can race poll(). Only wait on this Popen child; never use a
            # caller-supplied PID or signal another numeric PID as a fallback.
            actions.append('owned_process_group_already_exited')
    if child.poll() is None:
        signal_group(signal.SIGTERM, 'SIGTERM_owned_process_group')
        try:
            child.wait(timeout=max(0.001, min(0.5, deadline - time.monotonic())))
        except subprocess.TimeoutExpired:
            pass
    if child.poll() is None:
        signal_group(signal.SIGKILL, 'SIGKILL_owned_process_group')
    try:
        child.wait(timeout=max(0.001, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        return {'reaped': False, 'returncode': None, 'actions': actions, **grace}
    return {'reaped': True, 'returncode': child.returncode, 'actions': actions, **grace}


def bounded_tool(argv, output_limit, seconds=5):
    """Independently check the image without unbounded subprocess capture buffers."""
    deadline = time.monotonic() + seconds
    child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             stdin=subprocess.DEVNULL, start_new_session=True)
    selector, streams = selectors.DefaultSelector(), {'stdout': bytearray(), 'stderr': bytearray()}
    for name in streams:
        pipe = getattr(child, name)
        os.set_blocking(pipe.fileno(), False)
        selector.register(pipe, selectors.EVENT_READ, name)
    try:
        while selector.get_map():
            incomplete(time.monotonic() < deadline, 'validation_tool_timeout')
            for key, _ in selector.select(min(0.05, max(0, deadline - time.monotonic()))):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                incomplete(sum(map(len, streams.values())) + len(chunk) <= output_limit,
                           'validation_tool_output_limit')
                streams[key.data].extend(chunk)
        child.wait(timeout=max(0.001, deadline - time.monotonic()))
        return child.returncode, bytes(streams['stdout']), bytes(streams['stderr'])
    finally:
        selector.close()
        cleanup = reap_owned(child, deadline + 1)
        child.stdout.close()
        child.stderr.close()
        incomplete(cleanup['reaped'], 'validation_tool_cleanup_incomplete')


def check_esp(inputs, profile):
    code, out, err = bounded_tool([str(inputs / 'fsck_fat'), '-n', '-v', str(inputs / 'esp')], 65536)
    deny(code == 0, 'esp_fsck_failed')
    records = {'fsck': {'exit_code': code, 'stdout': out.decode('utf-8', 'replace'),
                         'stderr': err.decode('utf-8', 'replace')}}
    for name, member in [('efi', 'EFI/BOOT/BOOTX64.EFI'), ('init', 'EFI/BOOT/init.img')]:
        code, out, err = bounded_tool([str(inputs / 'seven_zip'), 'x', '-so',
                                      str(inputs / 'esp'), member], INPUT_LIMITS[name] + 65536)
        ref = profile['inputs'][name]
        deny(code == 0 and len(out) == ref['length'] and
             hashlib.sha256(out).hexdigest() == ref['sha256'], 'esp_content_mismatch')
        records[name] = {'member': member, 'exit_code': code, 'length': len(out),
                         'sha256': hashlib.sha256(out).hexdigest(),
                         'stderr': err.decode('utf-8', 'replace')}
    return records


def validate_profile(profile, inputs):
    safe_path(inputs)
    deny(inputs.resolve() == inputs and inputs.is_dir() and
         inputs.stat().st_uid == os.getuid() and inputs.stat().st_mode & 0o077 == 0,
         'inputs_root_not_private')
    try:
        entry.fields(profile, ('schema_version', 'kind', 'invocation_profile', 'source_commit',
            'assembled_patch_sha256', 'diagnostic_image_name', 'inputs', 'provenance'), 'probe_profile_fields')
        entry.integer(profile['schema_version'], 1, 1, 'schema_version')
        deny(profile['kind'] == 'boot_profile_probe_inputs_v0', 'profile_kind')
        deny(type(profile['invocation_profile']) is str and
             profile['invocation_profile'] == INVOCATION_PROFILE, 'invocation_profile')
        deny(type(profile['source_commit']) is str and
             re.fullmatch('[0-9a-f]{40}', profile['source_commit']), 'source_commit')
        entry.sha(profile['assembled_patch_sha256'], 'assembled_patch_sha256')
        deny(type(profile['diagnostic_image_name']) is str and
             re.fullmatch(r'[A-Za-z0-9_-]{1,120}\.efi', profile['diagnostic_image_name']),
             'diagnostic_image_name')
        entry.fields(profile['inputs'], INPUT_LIMITS, 'probe_input_fields')
        entry.fields(profile['provenance'], PROVENANCE_KEYS, 'provenance_fields')
        data = None
        for group, limits in [('inputs', INPUT_LIMITS),
                              ('provenance', {k: 32 * 1024 * 1024 for k in PROVENANCE_KEYS})]:
            for name, limit in limits.items():
                ref = profile[group][name]
                entry.validate_ref(ref, limit)
                if group == 'inputs':
                    expected_path = '7z.so' if name == 'seven_zip_module' else name
                    deny(ref['path'] == expected_path, 'input_path_identity')
                private_regular(inputs / ref['path'])
                value = entry.read_blob(inputs, ref, limit, retain=name == 'efi')
                if name == 'efi':
                    data = value
        return entry.parse_pe(data)
    except entry.AdmissionError as error:
        raise ProbeError('DENY', str(error)) from error
    except (entry.UnavailableInput, FileNotFoundError, PermissionError) as error:
        raise ProbeError('INCOMPLETE', 'required_input_unavailable') from error


class Pump:
    """Drain capped byte streams; QMP framing and other logs never share a decoder."""
    def __init__(self, run, budget):
        self.run, self.budget = run, budget
        self.selector = selectors.DefaultSelector()
        self.sources, self.logs = {}, {}
        self.frames, self.partial = deque(), bytearray()
        self.eofs = []
        self.io_errors = []
        self.qmp_eof = False

    def log(self, name, data):
        self.budget.retain(len(data))
        if name not in self.logs:
            self.logs[name] = os.fdopen(os.open(self.run / (name + '.bin'),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb')
        self.logs[name].write(data)
        self.logs[name].flush()

    def add(self, name, stream):
        if isinstance(stream, socket.socket):
            stream.setblocking(False)
        else:
            os.set_blocking(stream.fileno(), False)
        self.sources[name] = stream
        self.selector.register(stream, selectors.EVENT_READ, name)
        self.log(name, b'')

    def step(self, deadline):
        if time.monotonic() >= deadline:
            return
        for key, _ in self.selector.select(min(0.05, max(0, deadline - time.monotonic()))):
            try:
                data = os.read(key.fd, 65536)
            except (BlockingIOError, InterruptedError):
                # Readiness can race; retry under the same absolute deadline.
                continue
            except OSError as error:
                self.selector.unregister(key.fileobj)
                self.io_errors.append({'stream': key.data, 'operation': 'read',
                                       'errno': error.errno})
                continue  # Other streams can still have independently retained tails.
            if not data:
                self.selector.unregister(key.fileobj)
                self.eofs.append({'stream': key.data, 'observed_ns': time.monotonic_ns()})
                if key.data == 'qmp':
                    self.qmp_eof = True
                continue
            self.log(key.data, data)
            if key.data == 'qmp':
                self.partial.extend(data)
                while b'\n' in self.partial:
                    line, _, tail = self.partial.partition(b'\n')
                    self.partial = bytearray(tail)
                    incomplete(len(line) <= MAX_FRAME, 'qmp_frame_limit')
                    self.frames.append(bytes(line).rstrip(b'\r'))
                    incomplete(len(self.frames) <= MAX_MESSAGES, 'event_limit')
                incomplete(len(self.partial) <= MAX_FRAME, 'qmp_frame_limit')

    def next(self, deadline):
        while not self.frames:
            incomplete(not any(x['stream'] == 'qmp' for x in self.io_errors),
                       'qmp_stream_io_error')
            incomplete(not self.qmp_eof, 'qmp_eof')
            incomplete(time.monotonic() < deadline, 'response_timeout')
            self.step(deadline)
        return self.frames.popleft()

    def send(self, data, deadline):
        self.log('qmp-requests', data)
        remaining = memoryview(data)
        while remaining:
            incomplete(time.monotonic() < deadline, 'request_timeout')
            try:
                count = self.sources['qmp'].send(remaining)
                incomplete(count > 0, 'qmp_send_eof')
                remaining = remaining[count:]
            except (BlockingIOError, InterruptedError):
                self.step(deadline)

    def close(self):
        errors = []
        for stream in [self.selector, *self.sources.values(), *self.logs.values()]:
            try:
                stream.close()
            except OSError as error:
                errors.append({'operation': 'close_stream', 'errno': error.errno})
        return errors

    def drain(self, deadline):
        """Preserve queued tails after owned shutdown, including real EOF witnesses."""
        late = []
        while self.selector.get_map() or self.frames:
            incomplete(time.monotonic() < deadline, 'stream_eof_deadline')
            if self.selector.get_map():
                self.step(deadline)
            while self.frames:
                self.budget.message(teardown=True)
                late.append({'received_ns': time.monotonic_ns(),
                             'raw_qmp': decode_frame(self.frames.popleft())})
        incomplete(not self.partial, 'qmp_trailing_partial_frame')
        return late


def connect(path, child, deadline):
    while time.monotonic() < deadline:
        incomplete(child.poll() is None, 'qemu_exited_before_connect')
        connection = socket.socket(socket.AF_UNIX)
        try:
            connection.settimeout(max(0.001, deadline - time.monotonic()))
            connection.connect(str(path))
            info = path.lstat()
            deny(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.getuid(), 'socket_identity')
            os.chmod(path, 0o600)
            connection.setblocking(False)
            return connection
        except (FileNotFoundError, ConnectionRefusedError, BlockingIOError, TimeoutError):
            connection.close()
            time.sleep(min(0.01, max(0, deadline - time.monotonic())))
        except BaseException:
            connection.close()
            raise
    raise ProbeError('INCOMPLETE', 'socket_connect_timeout')


def file_ref(path, limit=None):
    digest = hashlib.sha256()
    length = 0
    if limit is not None:
        incomplete(path.stat().st_size <= limit, 'retained_file_limit')
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            length += len(chunk)
            incomplete(limit is None or length <= limit, 'retained_file_limit')
            digest.update(chunk)
    return {'path': path.name, 'length': length, 'sha256': digest.hexdigest()}


def new_report(status, reason):
    return {'schema_version': 1, 'kind': 'boot_profile_probe_v0', 'status': status,
            'reason': reason, 'checkpoints': [], 'capture_complete': False,
            'profile_preconditions_met': False,
            'claims': {name: False for name in entry.CLAIM_NAMES}}


def record_failure(result, status, reason):
    result.setdefault('failures', []).append({'status': status, 'reason': reason})
    result.update(status=status, reason=reason)


def persist_report(result, run):
    encoded = (json.dumps(result, sort_keys=True, indent=2) + '\n').encode()
    if len(encoded) > 1024 * 1024:
        retained = {name: result[name] for name in (
            'failures', 'cleanup', 'profile_sha256', 'initial_vars', 'final_vars',
            'raw_files', 'started_utc', 'finished_utc', 'lifecycle_deadline_met',
            'streams_complete_to_eof', 'transport_eof_observations') if name in result}
        result = {**new_report('INCOMPLETE', 'report_limit'), **retained,
                  'report_details_omitted_due_to_limit': True}
        record_failure(result, 'INCOMPLETE', 'report_limit')
        encoded = (json.dumps(result, sort_keys=True, indent=2) + '\n').encode()
        # The retained shape contains only bounded scalar/ref records produced
        # internally, never arbitrary QMP response objects.
    try:
        with os.fdopen(os.open(run / 'report.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as stream:
            stream.write(encoded)
    except OSError:
        # Return the in-memory failure/cleanup record even if storage is lost.
        record_failure(result, 'INCOMPLETE', 'report_persistence_failed')
    return result


def classify_diagnostic(result, data, image_name, pe):
    try:
        incomplete(not result.get('stream_errors'), 'stream_io_error')
        incomplete(len(data) <= 65536, 'diagnostic_exceeds_entry_input_bound')
        parsed = entry.parse_diagnostic(data, image_name)
        result['candidate'] = entry.diagnostic_candidate(parsed, pe)
        result.update(status='CANDIDATE_RETAINED', reason='prior_diagnostic_only')
    except entry.UnavailableInput:
        result.update(status='INCOMPLETE', reason='diagnostic_missing_or_ambiguous')
    except entry.AdmissionError as error:
        result.update(status='DENY', reason=str(error))
    except ProbeError as error:
        result.update(status=error.status, reason=error.reason)
    return result


def run_probe(profile, inputs, run):
    pe = validate_profile(profile, inputs)
    esp = check_esp(inputs, profile)  # Both independent checks must pass before Popen.
    argv = build_argv(inputs, run)
    create_run(run)
    shutil.copyfile(inputs / 'initial_vars', run / 'vars.fd')
    os.chmod(run / 'vars.fd', 0o600)
    initial_vars = file_ref(run / 'vars.fd')
    deny(initial_vars['sha256'] == profile['inputs']['initial_vars']['sha256'], 'vars_clone_mismatch')
    result = new_report('INCOMPLETE', 'diagnostic_not_observed')
    result.update(started_utc=utc(), argv=argv, esp_validation=esp, profile=profile,
                  profile_sha256=entry.profile_digest(profile), initial_vars=initial_vars,
                  observation_scope='reset-state-and-prior-diagnostic-only')
    result['observer'] = {'python_version': sys.version,
        'python_executable': file_ref(Path(sys.executable).resolve()),
        'source_files': [file_ref(Path(__file__)), file_ref(Path(entry.__file__))]}
    child = None
    budget = Budget(time.monotonic() + VM_SECONDS,
                    byte_limit=32 * 1024 * 1024 - initial_vars['length'] - 1024 * 1024)
    pump = Pump(run, budget)
    control = None
    try:
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, start_new_session=True, umask=0o077,
            env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'HOME': str(run)})
        result['owned_pid'] = child.pid
        pump.add('qemu-stdout', child.stdout)
        pump.add('qemu-stderr', child.stderr)
        for name in ('qmp', 'serial', 'debug'):
            pump.add(name, connect(run / (name + '.sock'), child,
                min(time.monotonic() + RESPONSE_SECONDS, budget.deadline - TEARDOWN_SECONDS)))
        control = QMP(pump, budget)
        control.negotiate()
        commands = control.request('query-commands')
        incomplete(type(commands) is list and all(type(x) is dict and type(x.get('name')) is str
                   for x in commands), 'command_capability_shape')
        available = {x['name'] for x in commands}
        incomplete(set(COMMANDS) | {'human-monitor-command'} <= available, 'missing_qmp_capability')
        control.request('query-status')
        incomplete(control.paused_verified, 'reset_paused_unavailable')
        result['configured_cpu_expansion'] = control.request('query-cpu-model-expansion',
            {'type': 'full', 'model': {'name': 'qemu64'}})
        result['cpu_expansion_origin'] = 'qemu_model_configuration_not_executed_cpuid'
        result['reset_cpus'] = control.request('query-cpus-fast')
        result['reset_ram_layout_text'] = control.request('human-monitor-command', {'command-line': 'info mtree -f'})
        result['reset_register_text'] = control.request('human-monitor-command', {'command-line': 'info registers'})
        control.request('cont')
        boot_deadline = min(time.monotonic() + BOOT_SECONDS, budget.deadline - TEARDOWN_SECONDS)
        while time.monotonic() < boot_deadline and child.poll() is None:
            pump.step(boot_deadline)
            while pump.frames:
                control.unsolicited(control.receive(boot_deadline))
        if child.poll() is None:
            try:
                control.request('quit')
                result['quit_result'] = 'acknowledged'
            except ProbeError as error:
                result['quit_result'] = error.reason
                if error.reason != 'qmp_eof':
                    raise
    except ProbeError as error:
        record_failure(result, error.status, error.reason)
    except OSError as error:
        record_failure(result, 'INCOMPLETE', 'host_io_error')
        result['host_errno'] = error.errno
    finally:
        if child is not None:
            try:
                result['cleanup'] = reap_owned(child, budget.deadline,
                    acknowledged_quit=result.get('quit_result') == 'acknowledged')
            except OSError as error:
                result['cleanup'] = {'reaped': False, 'errno': error.errno}
                record_failure(result, 'INCOMPLETE', 'owned_cleanup_io_error')
        try:
            result['late_qmp_records'] = pump.drain(budget.deadline)
            result['streams_complete_to_eof'] = set(pump.sources) == {x['stream'] for x in pump.eofs}
            if control is not None:
                for late in result['late_qmp_records']:
                    control.unsolicited(late['raw_qmp'])
        except (ProbeError, OSError) as error:
            result['streams_complete_to_eof'] = False
            record_failure(result, 'INCOMPLETE', error.reason if isinstance(error, ProbeError) else 'drain_io_error')
            if isinstance(error, OSError):
                result['drain_error'] = {'operation': 'drain', 'errno': error.errno}
        result['stream_errors'] = pump.io_errors
        if pump.io_errors:
            result['streams_complete_to_eof'] = False
            record_failure(result, 'INCOMPLETE', 'stream_io_error')
        close_errors = pump.close()
        if close_errors:
            result['close_errors'] = close_errors
            record_failure(result, 'INCOMPLETE', 'close_io_error')
        result['finished_utc'] = utc()
        result['lifecycle_deadline_met'] = time.monotonic() <= budget.deadline
        if control is not None:
            result['operations'], result['async_events'] = control.operations, control.events
        result['message_count'] = budget.message_count
        result['retained_stream_bytes'] = budget.retained_bytes
        result['transport_eof_observations'] = pump.eofs
        try:
            result['final_vars'] = file_ref(run / 'vars.fd', initial_vars['length'])
        except (OSError, ProbeError) as error:
            result['final_vars'] = {'unavailable': True}
            record_failure(result, 'INCOMPLETE', 'final_vars_unavailable')
    try:
        validate_profile(profile, inputs)
        result['input_pins_unchanged_after_run'] = True
        if result['reason'] == 'diagnostic_not_observed' and result['streams_complete_to_eof']:
            data = (run / 'debug.bin').read_bytes()
            classify_diagnostic(result, data, profile['diagnostic_image_name'], pe)
    except ProbeError as error:
        record_failure(result, error.status, error.reason)
    except OSError as error:
        record_failure(result, 'INCOMPLETE', 'final_input_or_diagnostic_io_error')
    if not result.get('cleanup', {}).get('reaped') or not result['lifecycle_deadline_met']:
        record_failure(result, 'INCOMPLETE', 'owned_cleanup_or_deadline_incomplete')
    result['raw_files'] = []
    for path in sorted(run.glob('*.bin')):
        try:
            result['raw_files'].append(file_ref(path))
        except OSError:
            record_failure(result, 'INCOMPLETE', 'raw_hash_unavailable')
    return persist_report(result, run)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('plan', 'probe'))
    parser.add_argument('--profile', type=Path, required=True)
    parser.add_argument('--inputs-root', type=Path, required=True)
    parser.add_argument('--run-dir', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        private_regular(args.profile)
        with args.profile.open('rb') as stream:
            profile = entry.decode_packet(stream.read(entry.PACKET_LIMIT + 1))
        if args.mode == 'plan':
            validate_profile(profile, args.inputs_root)
            result = new_report('READY_FOR_REVIEW', 'no_vm_launched')
            result['esp_validation'] = check_esp(args.inputs_root, profile)
            result['argv'] = build_argv(args.inputs_root, args.run_dir)
            result['profile_sha256'] = entry.profile_digest(profile)
            result['invocation_profile'] = profile['invocation_profile']
        else:
            result = run_probe(profile, args.inputs_root, args.run_dir)
    except entry.AdmissionError as error:
        result = new_report('DENY', str(error))
    except ProbeError as error:
        result = new_report(error.status, error.reason)
    except OSError as error:
        result = new_report('INCOMPLETE', 'input_io_error')
        result['host_errno'] = error.errno
    print(json.dumps(result, sort_keys=True, indent=2))
    return {'READY_FOR_REVIEW': 0, 'CANDIDATE_RETAINED': 0, 'DENY': 2, 'INCOMPLETE': 3}[result['status']]


if __name__ == '__main__':
    raise SystemExit(main())
