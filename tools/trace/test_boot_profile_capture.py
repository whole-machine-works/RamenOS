#!/usr/bin/env python3
"""Synthetic control tests. These tests never launch QEMU or certify a capture."""
import json
import errno
import os
from pathlib import Path
import subprocess
import struct
import sys
import tempfile
import time
import unittest
from unittest import mock

import boot_profile_capture as probe
from test_boot_profile_inputs import pe_fixture


class Wire:
    def __init__(self, frames):
        self.frames = [json.dumps(x).encode() for x in frames]
        self.sent = []

    def send(self, data, deadline):
        self.sent.append(data)

    def next(self, deadline):
        if not self.frames:
            raise probe.ProbeError('INCOMPLETE', 'response_unavailable')
        return self.frames.pop(0)


def greeting():
    return {'QMP': {'version': {'qemu': {'major': 8, 'minor': 2, 'micro': 2},
                              'package': 'synthetic'}, 'capabilities': []}}


class ProbeTests(unittest.TestCase):
    def controller(self, replies=()):
        wire = Wire([greeting(), {'return': {}, 'id': 1}, *replies])
        budget = probe.Budget(time.monotonic() + 60)
        control = probe.QMP(wire, budget)
        control.negotiate()
        return control, wire

    def assertFailure(self, reason, action):
        with self.assertRaises(probe.ProbeError) as caught:
            action()
        self.assertEqual(reason, caught.exception.reason)

    def test_exact_safe_argv_and_distinct_mutable_vars(self):
        argv = probe.build_argv(Path('/inputs'), Path('/private/probe-001'))
        self.assertIn('pc-q35-8.2,accel=tcg', argv)
        self.assertIn('qemu64', argv)
        self.assertIn('-S', argv)
        self.assertIn('none', argv)
        self.assertIn('if=pflash,format=raw,readonly=on,file=/inputs/ovmf_code', argv)
        self.assertIn('if=none,id=esp,format=raw,readonly=on,file=/inputs/esp', argv)
        self.assertIn('virtio-blk-pci,drive=esp', argv)
        self.assertNotIn('format=raw,readonly=on,file=/inputs/esp', argv)
        self.assertIn('if=pflash,format=raw,file=/private/probe-001/vars.fd', argv)
        self.assertIn('isa-debugcon,iobase=0x402,chardev=debug', argv)
        self.assertNotIn('/inputs/initial_vars', argv)
        self.assertTrue(all('fat:' not in x for x in argv))
        self.assertFailure('unsafe_resource_path', lambda:
            probe.build_argv(Path('/inputs,injected=on'), Path('/private/run')))

    def test_forbidden_commands_never_reach_wire(self):
        control, wire = self.controller([{'return': {'running': False, 'status': 'prelaunch'}, 'id': 2}])
        before = len(wire.sent)
        for name, args in [('system_reset', {}), ('human-monitor-command',
                {'command-line': 'xp /1xb 0x1000'}), ('human-monitor-command',
                {'command-line': 'info tlb'}), ('human-monitor-command',
                {'command-line': 'info registers; cont'}), ('qom-set', {}),
                ('blockdev-add', {}), ('migrate', {}), ('Z0', {}), ('Z1', {}),
                ('write-memory', {}), ('cont', {'extra': True}),
                ('query-cpu-model-expansion', {'type': 'full', 'model': {'name': 'host'}})]:
            self.assertFailure('command_denied', lambda n=name, a=args: control.request(n, a))
        self.assertEqual(before, len(wire.sent))
        self.assertIs(control.request('query-status')['running'], False)

    def test_only_final_quit_omits_optional_client_whitespace(self):
        commands = [('query-status', None), ('query-commands', None),
                    ('query-cpus-fast', None), ('query-cpu-model-expansion',
                     {'type': 'full', 'model': {'name': 'qemu64'}}),
                    ('human-monitor-command', {'command-line': 'info mtree -f'}),
                    ('human-monitor-command', {'command-line': 'info registers'}),
                    ('cont', None), ('quit', None)]
        replies = [{'return': {'running': False, 'status': 'prelaunch'} if i == 2 else {},
                    'id': i} for i in range(2, 10)]
        control, wire = self.controller(replies)
        for name, arguments in commands:
            control.request(name, arguments)
        for payload, operation in zip(wire.sent[:-1], control.operations[:-1]):
            self.assertEqual(json.dumps(operation['request'], separators=(',', ':')).encode()
                             + b'\r\n', payload)
        self.assertEqual(b'{"execute":"quit","id":9}', wire.sent[-1])

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux AF_UNIX unread-tail semantics')
    def test_linux_unread_quit_tail_resets_but_complete_object_reaches_eof(self):
        control, wire = self.controller([{'return': {}, 'id': 2}])
        control.request('quit')
        current_quit = wire.sent[-1]
        old_quit = current_quit.rstrip(b'\r\n') + b'\r\n'
        for payload, expect_reset in [(old_quit, True), (current_quit, False)]:
            with self.subTest(suffix=payload[-3:]), tempfile.TemporaryDirectory() as directory:
                pump = probe.Pump(Path(directory), probe.Budget(time.monotonic() + 3))
                client, peer = probe.socket.socketpair(probe.socket.AF_UNIX, probe.socket.SOCK_STREAM)
                try:
                    client.settimeout(1)
                    peer.settimeout(1)
                    client.sendall(payload)
                    received = bytearray()
                    while True:
                        self.assertLess(len(received), 128)
                        byte = peer.recv(1)
                        self.assertTrue(byte)
                        received.extend(byte)
                        try:
                            request = json.loads(received)
                            break
                        except json.JSONDecodeError:
                            continue
                    self.assertEqual({'execute': 'quit', 'id': 2}, request)
                    ack = {'return': {}, 'id': request['id']}
                    peer.sendall(json.dumps(ack, separators=(',', ':')).encode() + b'\r\n')
                    peer.close()  # Deliberately leave any suffix unread; no QEMU claim.
                    pump.add('qmp', client)
                    late = pump.drain(pump.budget.deadline)
                    self.assertEqual([ack], [item['raw_qmp'] for item in late])
                    if expect_reset:
                        self.assertEqual([{'stream': 'qmp', 'operation': 'read',
                                           'errno': errno.ECONNRESET}], pump.io_errors)
                        self.assertEqual([], pump.eofs)
                    else:
                        self.assertEqual([], pump.io_errors)
                        self.assertEqual({'qmp'}, {item['stream'] for item in pump.eofs})
                finally:
                    peer.close()
                    pump.close()
                    client.close()

    def test_pause_witness_required_single_resume(self):
        control, wire = self.controller([
            {'return': {'running': False, 'status': 'prelaunch'}, 'id': 2},
            {'event': 'RESUME', 'timestamp': {'seconds': 1, 'microseconds': 0}},
            {'return': {}, 'id': 3},
        ])
        self.assertFailure('resume_without_paused_witness', lambda: control.request('cont'))
        control.request('query-status')
        control.request('cont')
        before = len(wire.sent)
        self.assertFailure('resume_without_paused_witness', lambda: control.request('cont'))
        self.assertFailure('inspection_while_running', lambda:
                           control.request('human-monitor-command', {'command-line': 'info registers'}))
        self.assertEqual(before, len(wire.sent))
        self.assertEqual(1, len(control.events))

    def test_wrong_response_id_and_duplicate_json_deny(self):
        control, wire = self.controller([{'return': {}, 'id': 99}])
        self.assertFailure('qmp_response_identity', lambda: control.request('query-status'))
        control, wire = self.controller()
        wire.frames.append(b'{"return":{},"id":2,"id":2}')
        self.assertFailure('qmp_json', lambda: control.request('query-status'))

    def test_unsolicited_resume_and_unbound_response_deny(self):
        control, _ = self.controller()
        self.assertFailure('unsolicited_resume', lambda: control.unsolicited(
            {'event': 'RESUME', 'timestamp': {'seconds': 1, 'microseconds': 0}}))
        self.assertFailure('unsolicited_response', lambda: control.unsolicited({'return': {}, 'id': 2}))

    def test_qmp_error_is_incomplete_not_success(self):
        control, _ = self.controller([
            {'error': {'class': 'CommandNotFound', 'desc': 'not supported'}, 'id': 2}])
        with self.assertRaises(probe.ProbeError) as caught:
            control.request('query-commands')
        self.assertEqual('INCOMPLETE', caught.exception.status)

    def test_frame_message_storage_and_absolute_deadline_limits(self):
        self.assertFailure('qmp_frame_limit', lambda: probe.decode_frame(b'x' * 65537))
        budget = probe.Budget(time.monotonic() + 60)
        budget.message_count = probe.MAX_MESSAGES
        self.assertFailure('event_limit', budget.message)
        budget = probe.Budget(time.monotonic() + 60)
        budget.retained_bytes = probe.MAX_BYTES - 1
        self.assertFailure('storage_limit', lambda: budget.retain(2))
        self.assertFailure('vm_deadline', probe.Budget(time.monotonic() - 1).remaining)
        control, wire = self.controller()
        control.budget.message_count = probe.MAX_MESSAGES
        before = len(wire.sent)
        self.assertFailure('event_limit', lambda: control.request('query-status'))
        self.assertEqual(before, len(wire.sent))

    def test_fresh_private_run_and_shared_or_linked_inputs_denied(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            run = root / 'run'
            probe.create_run(run)
            self.assertEqual(0o700, run.stat().st_mode & 0o777)
            self.assertFailure('run_directory_exists', lambda: probe.create_run(run))
            (root / 'input').write_bytes(b'one')
            (root / 'input').chmod(0o600)
            os.link(root / 'input', root / 'alias')
            self.assertFailure('shared_input_inode', lambda: probe.private_regular(root / 'input'))
            (root / 'alias').unlink()
            probe.private_regular(root / 'input')
            (root / 'link').symlink_to(root / 'input')
            self.assertFailure('input_symlink', lambda: probe.private_regular(root / 'link'))

    def test_owned_child_cleanup_then_fresh_child(self):
        child = subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(30)'],
                                 start_new_session=True)
        start = time.monotonic()
        result = probe.reap_owned(child, start + 3)
        self.assertTrue(result['reaped'])
        self.assertIsNotNone(child.returncode)
        self.assertLess(time.monotonic() - start, 3)
        other = subprocess.Popen([sys.executable, '-c', 'pass'], start_new_session=True)
        other.wait(timeout=3)
        self.assertTrue(probe.reap_owned(other, time.monotonic() + 3)['reaped'])
        self.assertEqual(0, other.returncode)

    def test_owned_exit_signal_race_still_waits_actual_child(self):
        child = mock.Mock()
        child.poll.side_effect = [None, 0]
        child.returncode = 0
        with mock.patch.object(probe.os, 'killpg', side_effect=ProcessLookupError):
            result = probe.reap_owned(child, time.monotonic() + 1)
        self.assertTrue(result['reaped'])
        self.assertGreaterEqual(child.wait.call_count, 1)
        self.assertIn('owned_process_group_already_exited', result['actions'])

    def test_acknowledged_quit_grace_reaps_cooperating_child_without_signals(self):
        script = ('import sys,time;print("ready",flush=True);'
                  'sys.stdin.buffer.read(1);time.sleep(0.05)')
        child = subprocess.Popen([sys.executable, '-c', script], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, start_new_session=True)
        ready = probe.selectors.DefaultSelector()
        try:
            ready.register(child.stdout, probe.selectors.EVENT_READ)
            self.assertTrue(ready.select(2))
            self.assertEqual(b'ready\n', child.stdout.readline())
            child.stdin.write(b'q')
            child.stdin.flush()
            with mock.patch.object(probe.os, 'killpg', wraps=probe.os.killpg) as signals:
                result = probe.reap_owned(child, time.monotonic() + 3, acknowledged_quit=True)
                signals.assert_not_called()
            self.assertTrue(result['reaped'])
            self.assertEqual(0, result['returncode'])
            self.assertEqual([], result['actions'])
            self.assertEqual('exited', result['quit_grace']['outcome'])
            self.assertGreater(result['quit_grace']['wait_limit_seconds'], 0)
            self.assertLessEqual(result['quit_grace']['wait_limit_seconds'], 0.5)
        finally:
            ready.close()
            probe.reap_owned(child, time.monotonic() + 2)
            child.stdin.close()
            child.stdout.close()

    def test_acknowledged_quit_stall_keeps_bounded_owned_signal_fallback(self):
        script = ('import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);'
                  'print("ready",flush=True);time.sleep(30)')
        child = subprocess.Popen([sys.executable, '-c', script], stdout=subprocess.PIPE,
                                 start_new_session=True)
        ready = probe.selectors.DefaultSelector()
        try:
            ready.register(child.stdout, probe.selectors.EVENT_READ)
            self.assertTrue(ready.select(2))
            self.assertEqual(b'ready\n', child.stdout.readline())
            start = time.monotonic()
            result = probe.reap_owned(child, start + 3, acknowledged_quit=True)
            self.assertLess(time.monotonic() - start, 3)
            self.assertTrue(result['reaped'])
            self.assertEqual(-probe.signal.SIGKILL, result['returncode'])
            self.assertEqual('timeout', result['quit_grace']['outcome'])
            self.assertLessEqual(result['quit_grace']['wait_limit_seconds'], 0.5)
            self.assertEqual(['SIGTERM_owned_process_group', 'SIGKILL_owned_process_group'],
                             result['actions'])
        finally:
            ready.close()
            probe.reap_owned(child, time.monotonic() + 2)
            child.stdout.close()

    def test_unreaped_validation_tool_cannot_return_success(self):
        real_reap = probe.reap_owned
        def uncertain(child, deadline):
            self.assertTrue(real_reap(child, deadline)['reaped'])
            return {'reaped': False}
        with mock.patch.object(probe, 'reap_owned', side_effect=uncertain):
            self.assertFailure('validation_tool_cleanup_incomplete', lambda:
                probe.bounded_tool([sys.executable, '-c', 'print("ok")'], 1024))

    def test_full_unix_socket_backlog_obeys_absolute_connect_deadline(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'qmp.sock'
            server = probe.socket.socket(probe.socket.AF_UNIX)
            clients = []
            try:
                server.bind(str(path))
                server.listen(1)
                for _ in range(8):
                    client = probe.socket.socket(probe.socket.AF_UNIX)
                    client.settimeout(0.01)
                    clients.append(client)
                    try:
                        client.connect(str(path))
                    except (TimeoutError, BlockingIOError, ConnectionRefusedError):
                        break
                else:
                    self.fail('could not fill bounded test socket backlog')
                child = mock.Mock()
                child.poll.return_value = None
                start = time.monotonic()
                self.assertFailure('socket_connect_timeout', lambda:
                    probe.connect(path, child, start + 0.05))
                self.assertLess(time.monotonic() - start, 0.3)
            finally:
                for client in clients:
                    client.close()
                server.close()

    def test_every_terminal_report_excludes_capture_claims(self):
        for status in ['DENY', 'INCOMPLETE', 'CANDIDATE_RETAINED']:
            result = probe.new_report(status, 'synthetic')
            self.assertEqual('boot_profile_probe_v0', result['kind'])
            self.assertEqual([], result['checkpoints'])
            self.assertIs(result['capture_complete'], False)
            self.assertIs(result['profile_preconditions_met'], False)
            self.assertEqual(set(probe.entry.CLAIM_NAMES), set(result['claims']))
            self.assertTrue(all(value is False for value in result['claims'].values()))

    def test_missing_ambiguous_and_real_line_fixture_never_claim_c0(self):
        pe = probe.entry.parse_pe(bytes(pe_fixture()))
        line = b'Loading driver at 0x200000 EntryPoint=0x201020 fixture.efi\n'
        for data, expected in [(b'', 'INCOMPLETE'), (line + line, 'INCOMPLETE'),
                               (line, 'CANDIDATE_RETAINED'),
                               (line.replace(b'201020', b'201021'), 'DENY')]:
            result = probe.classify_diagnostic(probe.new_report('INCOMPLETE', 'pending'),
                                               data, 'fixture.efi', pe)
            self.assertEqual(expected, result['status'])
            self.assertEqual([], result['checkpoints'])
            self.assertIs(result['capture_complete'], False)
            self.assertTrue(all(v is False for v in result['claims'].values()))

    def profile_fixture(self, root):
        root.chmod(0o700)
        profile = {'schema_version': 1, 'kind': 'boot_profile_probe_inputs_v0',
                   'invocation_profile': 'q35-8.2-tcg-qemu64-virtio-ro-esp-debugcon-v0',
                   'source_commit': 'a' * 40, 'assembled_patch_sha256': 'b' * 64,
                   'diagnostic_image_name': 'fixture.efi', 'inputs': {}, 'provenance': {}}
        for group, keys in [('inputs', probe.INPUT_LIMITS), ('provenance', probe.PROVENANCE_KEYS)]:
            for key in keys:
                name = '7z.so' if key == 'seven_zip_module' else key
                path = root / name
                path.write_bytes(bytes(pe_fixture()) if key == 'efi' else b'synthetic')
                path.chmod(0o600)
                profile[group][key] = probe.file_ref(path)
        return profile

    def test_wrong_invocation_profile_denies_without_launch_or_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            inputs = Path(directory).resolve()
            profile = self.profile_fixture(inputs)
            probe.validate_profile(profile, inputs)
            for name in ['ide-readonly', '', True, 0]:
                profile['invocation_profile'] = name
                with mock.patch.object(probe.subprocess, 'Popen') as spawn:
                    self.assertFailure('invocation_profile', lambda:
                        probe.run_probe(profile, inputs, inputs / 'run'))
                    spawn.assert_not_called()

    def test_pin_change_denies_before_child_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            inputs = Path(directory).resolve()
            profile = self.profile_fixture(inputs)
            probe.validate_profile(profile, inputs)
            (inputs / 'init').write_bytes(b'altered!!')
            with mock.patch.object(probe.subprocess, 'Popen') as spawn:
                self.assertFailure('blob_hash_mismatch', lambda:
                    probe.run_probe(profile, inputs, inputs / 'run'))
                spawn.assert_not_called()

    def test_malformed_esp_and_content_mismatch_deny_before_vm(self):
        with tempfile.TemporaryDirectory() as directory:
            inputs = Path(directory).resolve()
            profile = self.profile_fixture(inputs)
            for answers, reason in [([(1, b'bad FAT', b'')], 'esp_fsck_failed'),
                    ([(0, b'valid FAT', b''), (0, b'wrong EFI', b'')], 'esp_content_mismatch')]:
                with mock.patch.object(probe, 'bounded_tool', side_effect=answers), \
                     mock.patch.object(probe.subprocess, 'Popen') as spawn:
                    self.assertFailure(reason, lambda: probe.run_probe(profile, inputs, inputs / 'run'))
                    spawn.assert_not_called()

    def test_stream_frame_limit_and_eof_are_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            pump = probe.Pump(Path(directory), probe.Budget(time.monotonic() + 60))
            left, right = probe.socket.socketpair()
            try:
                pump.add('qmp', left)
                right.sendall(b'{"return":{},"id":1}\r\n')
                self.assertEqual(b'{"return":{},"id":1}', pump.next(time.monotonic() + 1))
                right.close()
                self.assertFailure('qmp_eof', lambda: pump.next(time.monotonic() + 1))
                self.assertEqual('qmp', pump.eofs[0]['stream'])
            finally:
                right.close()
                pump.close()

    def test_late_child_pipe_tail_is_drained_before_candidate_classification(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            line = b'Loading driver at 0x200000 EntryPoint=0x201020 fixture.efi\n'
            script = ('import os,sys;line=' + repr(line) +
                      ';os.write(1,line);sys.stdin.buffer.read(1);os.write(1,line);os.write(2,b"tail")')
            child = subprocess.Popen([sys.executable, '-c', script], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            budget = probe.Budget(time.monotonic() + 3)
            pump = probe.Pump(root, budget)
            try:
                pump.add('debug', child.stdout)
                pump.add('qemu-stderr', child.stderr)
                while (root / 'debug.bin').stat().st_size == 0:
                    pump.step(budget.deadline)
                self.assertEqual(line, (root / 'debug.bin').read_bytes())
                child.stdin.write(b'x')
                child.stdin.flush()
                child.wait(timeout=2)
                pump.drain(budget.deadline)
                self.assertEqual({'debug', 'qemu-stderr'}, {x['stream'] for x in pump.eofs})
                result = probe.classify_diagnostic(probe.new_report('INCOMPLETE', 'pending'),
                    (root / 'debug.bin').read_bytes(), 'fixture.efi', probe.entry.parse_pe(bytes(pe_fixture())))
                self.assertEqual('diagnostic_missing_or_ambiguous', result['reason'])
                self.assertEqual(b'tail', (root / 'qemu-stderr.bin').read_bytes())
            finally:
                child.stdin.close()
                probe.reap_owned(child, budget.deadline)
                pump.close()

    def test_reset_stream_keeps_error_and_drains_other_late_tail_without_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pump = probe.Pump(root, probe.Budget(time.monotonic() + 3))
            listener = probe.socket.socket(probe.socket.AF_INET, probe.socket.SOCK_STREAM)
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            failed = probe.socket.create_connection(listener.getsockname(), timeout=1)
            peer, _ = listener.accept()
            listener.close()
            tail, writer = probe.socket.socketpair()
            line = b'Loading driver at 0x200000 EntryPoint=0x201020 fixture.efi\n'
            try:
                pump.add('qmp', failed)
                pump.add('debug', tail)
                peer.setsockopt(probe.socket.SOL_SOCKET, probe.socket.SO_LINGER,
                                struct.pack('ii', 1, 0))
                peer.close()  # A real loopback TCP reset, portable across Mac/Linux.
                pump.step(pump.budget.deadline)
                self.assertEqual([{'stream': 'qmp', 'operation': 'read',
                                   'errno': errno.ECONNRESET}], pump.io_errors)
                writer.sendall(line)
                writer.close()
                pump.drain(pump.budget.deadline)
                self.assertEqual(line, (root / 'debug.bin').read_bytes())
                self.assertEqual({'debug'}, {x['stream'] for x in pump.eofs})
                self.assertEqual(1, len(pump.io_errors))
                self.assertEqual(0, len(pump.selector.get_map()))
                result = probe.new_report('INCOMPLETE', 'pending')
                result['stream_errors'] = pump.io_errors
                probe.classify_diagnostic(result, line, 'fixture.efi',
                                          probe.entry.parse_pe(bytes(pe_fixture())))
                self.assertEqual('INCOMPLETE', result['status'])
                self.assertEqual('stream_io_error', result['reason'])
                self.assertNotIn('candidate', result)
            finally:
                peer.close()
                writer.close()
                pump.close()

    def test_transient_read_races_retry_without_error_or_false_eof(self):
        with tempfile.TemporaryDirectory() as directory:
            pump = probe.Pump(Path(directory), probe.Budget(time.monotonic() + 3))
            left, right = probe.socket.socketpair()
            try:
                pump.add('debug', left)
                right.sendall(b'late bytes')
                for transient in (BlockingIOError(errno.EAGAIN, 'retry'), InterruptedError(errno.EINTR, 'retry')):
                    with mock.patch.object(probe.os, 'read', side_effect=transient):
                        pump.step(pump.budget.deadline)
                    self.assertEqual([], pump.io_errors)
                    self.assertEqual([], pump.eofs)
                    self.assertEqual(1, len(pump.selector.get_map()))
                right.close()
                pump.drain(pump.budget.deadline)
                self.assertEqual(b'late bytes', (Path(directory) / 'debug.bin').read_bytes())
                self.assertEqual({'debug'}, {x['stream'] for x in pump.eofs})
            finally:
                right.close()
                pump.close()

    def test_oversized_report_retains_bounded_incomplete_cleanup_record(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = probe.new_report('INCOMPLETE', 'original_failure')
            probe.record_failure(result, 'DENY', 'original_failure')
            result.update(cleanup={'reaped': True, 'returncode': 0},
                          operations=['x' * (1024 * 1024)], raw_files=[])
            result = probe.persist_report(result, root)
            self.assertEqual('INCOMPLETE', result['status'])
            self.assertEqual('report_limit', result['reason'])
            self.assertTrue(result['cleanup']['reaped'])
            self.assertIn({'status': 'DENY', 'reason': 'original_failure'}, result['failures'])
            self.assertLess((root / 'report.json').stat().st_size, 65536)

    def test_report_write_failure_preserves_original_failure_and_cleanup(self):
        result = probe.new_report('DENY', 'original_failure')
        probe.record_failure(result, 'DENY', 'original_failure')
        result['cleanup'] = {'reaped': True}
        with mock.patch.object(probe.os, 'open', side_effect=OSError('storage failed')):
            returned = probe.persist_report(result, Path('/missing'))
        self.assertTrue(returned['cleanup']['reaped'])
        self.assertEqual('report_persistence_failed', returned['reason'])
        self.assertEqual('original_failure', returned['failures'][0]['reason'])


if __name__ == '__main__':
    unittest.main()
