#!/usr/bin/env python3
"""Private diagnostics controls; no Docker or daemon queries are executed."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import agent_runner_diagnostics as diagnostics


class AgentRunnerDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name) / 'out' / 'agent-runner-diagnostics'
        self.addCleanup(patch.stopall)
        patch.object(diagnostics, 'OUTPUT', self.output).start()
        self.begin_stamp = {'utc': '2026-11-07T12:00:00.000000+00:00', 'monotonic_ns': 1000000000}
        self.end_stamp = {'utc': '2026-11-07T12:02:00.000000+00:00', 'monotonic_ns': 121000000000}
        self.clock = patch.object(diagnostics, 'stamp', side_effect=[self.begin_stamp, self.end_stamp]).start()
        patch.object(diagnostics, 'resources', return_value={'scope': 'mocked host observations'}).start()

    def begin(self):
        self.assertEqual(diagnostics.main(['begin']), 0)

    def read(self, name):
        return json.loads((self.output / name).read_text())

    def completed(self, argv, output, label, work_seconds):
        self.assertEqual(work_seconds, 5)
        (output / (label + '.stdout')).write_bytes(b'actual fixture output\n')
        (output / (label + '.stderr')).write_bytes(b'')
        row = {'argv': argv, 'pid': 123, 'exit_code': 0, 'reaped': True,
               'group_stop_before_reap': True}
        (output / (label + '.command.json')).write_text(json.dumps(row))
        return row

    def test_begin_records_actual_window_without_any_command(self):
        with patch.object(diagnostics.runner, 'run_owned') as command:
            self.begin()
        command.assert_not_called()
        row = self.read('begin.json')
        self.assertEqual(row['started'], self.begin_stamp)
        self.assertFalse(row['acceptance'])
        self.assertEqual(row['scope'], 'canonical_agent_lane_window_not_request_window')

    def test_failure_has_exact_two_finite_read_only_queries(self):
        self.begin()
        with patch.object(diagnostics.runner, 'run_owned', side_effect=self.completed) as command:
            self.assertEqual(diagnostics.main(['failure']), 0)
        self.assertEqual(command.call_count, 2)
        journal, events = [call.args[0] for call in command.call_args_list]
        self.assertEqual(journal, ['/usr/bin/prlimit', '--fsize=262144:262144', '--',
            '/usr/bin/journalctl', '--no-pager', '--utc', '--output=short-iso-precise',
            '--unit=docker.service', '--unit=containerd.service', '--lines=256',
            '--since', '2026-11-07 12:00:00.000000 UTC',
            '--until', '2026-11-07 12:02:00.000000 UTC'])
        self.assertEqual(events, ['/usr/bin/prlimit', '--fsize=262144:262144', '--',
            '/usr/bin/docker', 'events', '--since', self.begin_stamp['utc'],
            '--until', self.end_stamp['utc'], '--filter', 'type=container',
            '--format', '{{json .}}'])
        row = self.read('failure.json')
        self.assertEqual(row['started'], self.begin_stamp)
        self.assertEqual(row['ended'], self.end_stamp)
        self.assertEqual([r['status'] for r in row['queries']], ['observed', 'observed'])
        self.assertFalse(row['acceptance'])

    def test_missing_begin_records_unavailable_and_never_queries(self):
        with patch.object(diagnostics.runner, 'run_owned') as command:
            self.assertEqual(diagnostics.main(['failure']), 0)
        command.assert_not_called()
        row = self.read('failure.json')
        self.assertEqual(row['window_status'], 'unavailable')
        self.assertEqual(row['queries'], [])

    def test_bad_backward_or_oversized_window_never_queries(self):
        self.begin()
        original = self.read('begin.json')
        for altered in [dict(original, started={**self.begin_stamp, 'monotonic_ns': True}),
                        dict(original, started={**self.begin_stamp, 'utc': 'bad'}),
                        dict(original, started={**self.begin_stamp, 'monotonic_ns': 999000000000}),
                        dict(original, started={**self.begin_stamp, 'utc': '2026-11-08T12:00:00.000000+00:00'}),
                        dict(original, started={**self.begin_stamp, 'utc': '2026-11-01T12:00:00.000000+00:00'})]:
            with self.subTest(altered=altered), tempfile.TemporaryDirectory() as t:
                out = Path(t); (out / 'begin.json').write_text(json.dumps(altered))
                with patch.object(diagnostics, 'OUTPUT', out), \
                        patch.object(diagnostics, 'stamp', return_value=self.end_stamp), \
                        patch.object(diagnostics.runner, 'run_owned') as command:
                    self.assertEqual(diagnostics.main(['failure']), 0)
                    self.assertEqual(json.loads((out / 'failure.json').read_text())['window_status'], 'unavailable')
                command.assert_not_called()

    def test_existing_begin_and_failure_are_never_replaced(self):
        self.begin(); before = (self.output / 'begin.json').read_bytes()
        with patch.object(diagnostics, 'stamp', return_value=self.end_stamp), \
                patch.object(diagnostics.runner, 'run_owned', side_effect=self.completed) as command:
            self.assertEqual(diagnostics.main(['failure']), 0)
            failure = (self.output / 'failure.json').read_bytes()
            self.assertEqual(diagnostics.main(['failure']), 0)
            self.assertEqual(command.call_count, 2)
            self.assertEqual((self.output / 'failure.json').read_bytes(), failure)
            self.assertEqual((self.output / 'begin.json').read_bytes(), before)

    def test_repeated_begin_does_not_relabel_old_window_as_new_lane(self):
        self.begin(); before = (self.output / 'begin.json').read_bytes()
        self.assertEqual(diagnostics.main(['begin']), 0)
        with patch.object(diagnostics.runner, 'run_owned', side_effect=self.completed) as command:
            self.assertEqual(diagnostics.main(['failure']), 0)
        command.assert_not_called()
        self.assertEqual((self.output / 'begin.json').read_bytes(), before)
        self.assertEqual(self.read('failure.json')['window_status'], 'unavailable')

    def test_timeout_retains_actual_receipt_and_original_raw_bytes(self):
        self.begin()
        def timed_out(argv, output, label, work_seconds):
            row = self.completed(argv, output, label, work_seconds)
            row.update(exit_code=-9, error='owned command work deadline exceeded')
            (output / (label + '.command.json')).write_text(json.dumps(row))
            raise diagnostics.runner.RunnerError(row['error'])
        with patch.object(diagnostics.runner, 'run_owned', side_effect=timed_out):
            self.assertEqual(diagnostics.main(['failure']), 0)
        rows = self.read('failure.json')['queries']
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(r['status'] == 'error' and r['receipt']['reaped'] for r in rows))
        self.assertEqual((self.output / 'journal.stdout').read_bytes(), b'actual fixture output\n')

    def test_uncertain_cleanup_stops_before_second_query(self):
        self.begin()
        def uncertain(argv, output, label, work_seconds):
            row = self.completed(argv, output, label, work_seconds)
            row.update(reaped=False, group_stop_before_reap=False, cleanup_error='uncertain')
            (output / (label + '.command.json')).write_text(json.dumps(row))
            raise diagnostics.runner.RunnerError('uncertain')
        with patch.object(diagnostics.runner, 'run_owned', side_effect=uncertain) as command:
            self.assertEqual(diagnostics.main(['failure']), 0)
        self.assertEqual(command.call_count, 1)
        self.assertEqual(self.read('failure.json')['queries'][1]['status'], 'not_attempted_prior_cleanup_uncertain')

    def test_output_limit_is_not_misreported_as_complete(self):
        self.begin()
        def full(argv, output, label, work_seconds):
            row = self.completed(argv, output, label, work_seconds)
            (output / (label + '.stdout')).write_bytes(b'x' * 262144)
            row['exit_code'] = -25
            (output / (label + '.command.json')).write_text(json.dumps(row))
            return row
        with patch.object(diagnostics.runner, 'run_owned', side_effect=full):
            self.assertEqual(diagnostics.main(['failure']), 0)
        for row in self.read('failure.json')['queries']:
            self.assertEqual(row['status'], 'error')
            self.assertTrue(row['stdout']['at_limit'])
            self.assertFalse(row['complete'])

    def test_nonregular_begin_is_rejected_without_following_link(self):
        self.output.mkdir(parents=True)
        target = Path(self.temp.name) / 'other'; target.write_text('{}')
        (self.output / 'begin.json').symlink_to(target)
        with patch.object(diagnostics.runner, 'run_owned') as command:
            self.assertEqual(diagnostics.main(['failure']), 0)
        command.assert_not_called()
        self.assertEqual(target.read_text(), '{}')

    def test_resource_reads_are_fixed_bounded_and_explicit_about_errors(self):
        with patch.object(diagnostics, 'resources', wraps=self._real_resources), \
                patch.object(diagnostics.os, 'statvfs', side_effect=OSError(13, 'denied')), \
                patch.object(diagnostics, 'small_read', return_value={'status': 'unavailable', 'errno': 2}) as read:
            row = diagnostics.resources()
        self.assertEqual(row['filesystems'][0]['error_errno'], 13)
        self.assertEqual([c.args[0] for c in read.call_args_list], list(diagnostics.PROC_PATHS))
        self.assertTrue(all(c.args[1] == 4096 for c in read.call_args_list))

    def test_resource_prefix_overflow_and_nonregular_input_stay_explicit(self):
        path = Path(self.temp.name) / 'resource'
        path.write_bytes(b'x' * 4097)
        observed = diagnostics.small_read(path, 4096)
        self.assertEqual(observed['prefix_bytes'], 4096)
        self.assertTrue(observed['truncated'])
        self.assertEqual(len(observed['text']), 4096)
        link = Path(self.temp.name) / 'linked'; link.symlink_to(path)
        self.assertEqual(diagnostics.small_read(link, 4096)['status'], 'unavailable')

    def test_diagnostic_reporting_failure_cannot_escape(self):
        with patch.object(diagnostics, 'begin', side_effect=OSError('private unavailable')), \
                patch('builtins.print', side_effect=OSError('stderr unavailable')):
            self.assertEqual(diagnostics.main(['begin']), 0)

    def test_diagnostic_failure_cannot_replace_actual_canonical_exit(self):
        script = Path(diagnostics.__file__).resolve()
        with tempfile.TemporaryDirectory() as t:
            result = subprocess.run(['/bin/sh', '-c',
                '"$1" -c "raise SystemExit(37)"; lane_status=$?; '
                '"$1" -B "$2" failure; exit "$lane_status"',
                'diagnostic-control', sys.executable, str(script)], cwd=t,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            self.assertEqual(result.returncode, 37)
            row = json.loads((Path(t) / 'out/agent-runner-diagnostics/failure.json').read_text())
            self.assertEqual(row['window_status'], 'unavailable')
            self.assertEqual(row['queries'], [])


AgentRunnerDiagnosticsTests._real_resources = staticmethod(diagnostics.resources)

if __name__ == '__main__':
    unittest.main()
