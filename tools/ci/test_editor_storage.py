"""Storage preparation must never remove build inputs or test evidence."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    'editor_storage', Path(__file__).with_name('editor_storage.py'))
STORAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STORAGE)
HOSTED = {'GITHUB_ACTIONS': 'true', 'RUNNER_OS': 'Linux',
          'EDITOR_RUNNER_ENVIRONMENT': 'github-hosted'}


class EditorStorageTests(unittest.TestCase):
    def test_prepare_denies_local_self_hosted_and_incomplete_context_before_effects(self):
        contexts = [{}, {**HOSTED, 'GITHUB_ACTIONS': 'false'},
                    {**HOSTED, 'RUNNER_OS': 'macOS'},
                    {**HOSTED, 'EDITOR_RUNNER_ENVIRONMENT': 'self-hosted'}]
        contexts += [{k: v for k, v in HOSTED.items() if k != missing}
                     for missing in HOSTED]
        for env in contexts:
            with self.subTest(env=env), patch.dict(os.environ, env, clear=True), \
                    patch.object(STORAGE.subprocess, 'run') as run, \
                    patch.object(STORAGE, 'report') as report, \
                    patch.object(STORAGE.os, 'lstat') as lstat:
                with self.assertRaises(RuntimeError):
                    STORAGE.prepare()
                run.assert_not_called()
                report.assert_not_called()
                lstat.assert_not_called()

    def test_only_two_fixed_unused_sdks_can_be_deleted(self):
        with patch.dict(os.environ, HOSTED, clear=True), \
                patch.object(STORAGE, 'report'), \
                patch.object(STORAGE.os, 'lstat', return_value=SimpleNamespace(
                    st_mode=stat.S_IFDIR | 0o755)), \
                patch.object(STORAGE.subprocess, 'run') as run, \
                contextlib.redirect_stdout(io.StringIO()):
            STORAGE.prepare()
        self.assertEqual([call.args[0] for call in run.call_args_list], [
            ['sudo', '-n', 'rm', '--recursive', '--force', '--one-file-system',
             '--', '/usr/share/dotnet'],
            ['sudo', '-n', 'rm', '--recursive', '--force', '--one-file-system',
             '--', '/usr/local/lib/android']])
        self.assertTrue(all(call.kwargs.get('check') is True
                            for call in run.call_args_list))

    def test_absent_sdk_is_recorded_without_removal(self):
        out = io.StringIO()
        with patch.dict(os.environ, HOSTED, clear=True), \
                patch.object(STORAGE, 'report'), \
                patch.object(STORAGE.os, 'lstat', side_effect=FileNotFoundError), \
                patch.object(STORAGE.subprocess, 'run') as run, \
                contextlib.redirect_stdout(out):
            STORAGE.prepare()
        run.assert_not_called()
        rows = [json.loads(line) for line in out.getvalue().splitlines()]
        self.assertEqual([r['status'] for r in rows], ['absent', 'absent'])

    def test_symlinks_and_other_leaf_types_refuse_removal(self):
        for mode in (stat.S_IFLNK | 0o777, stat.S_IFREG | 0o644):
            with self.subTest(mode=mode), patch.dict(os.environ, HOSTED, clear=True), \
                    patch.object(STORAGE, 'report'), \
                    patch.object(STORAGE.os, 'lstat', return_value=SimpleNamespace(st_mode=mode)), \
                    patch.object(STORAGE.subprocess, 'run') as run:
                with self.assertRaises(RuntimeError):
                    STORAGE.prepare()
                run.assert_not_called()

    def test_failed_removal_stops_without_claiming_success_or_touching_second_sdk(self):
        out = io.StringIO()
        with patch.dict(os.environ, HOSTED, clear=True), \
                patch.object(STORAGE, 'report') as report, \
                patch.object(STORAGE.os, 'lstat', return_value=SimpleNamespace(
                    st_mode=stat.S_IFDIR | 0o755)), \
                patch.object(STORAGE.subprocess, 'run', side_effect=
                    subprocess.CalledProcessError(1, 'rm')) as run, \
                contextlib.redirect_stdout(out):
            with self.assertRaises(subprocess.CalledProcessError):
                STORAGE.prepare()
        self.assertEqual(run.call_count, 1)
        self.assertEqual(out.getvalue(), '')
        report.assert_called_once_with('before-preparation')

    def test_actual_space_and_inode_values_and_bounded_census_errors(self):
        disk = SimpleNamespace(f_frsize=4096, f_bavail=7, f_blocks=100,
                               f_favail=11, f_files=200)
        out = io.StringIO()
        with patch.object(STORAGE.os, 'statvfs', return_value=disk), \
                patch.object(STORAGE.subprocess, 'run', side_effect=STORAGE.subprocess.TimeoutExpired('du', 10)) as run, \
                contextlib.redirect_stdout(out):
            STORAGE.report('fixture')
        row = json.loads(out.getvalue())
        self.assertEqual(row['available_bytes'], 28672)
        self.assertEqual(row['available_inodes'], 11)
        self.assertEqual(row['census_status'], 'TimeoutExpired')
        self.assertEqual(run.call_args.kwargs['timeout'], 10)
        self.assertEqual(run.call_args.args[0], ['du', '-sk', '--',
            'out/desktop', 'out/foundry', 'out/ci-optimization/compiler-cache', 'target'])

    def test_report_failure_is_best_effort_and_cli_rejects_path_arguments(self):
        with patch.object(STORAGE.os, 'statvfs', side_effect=OSError(28, 'full')), \
                patch.object(STORAGE.subprocess, 'run', side_effect=FileNotFoundError), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            STORAGE.report('after-editor')
        row = json.loads(out.getvalue())
        self.assertEqual(row['space_error_errno'], 28)
        self.assertEqual(row['census_status'], 'FileNotFoundError')
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            STORAGE.main(['prepare', '/arbitrary/path'])

    def test_workflow_keeps_canonical_lane_and_failure_evidence(self):
        root = Path(__file__).resolve().parents[2]
        workflow = (root / '.github/workflows/ci.yml').read_text()
        editor = workflow.split('\n  editor:\n', 1)[1].split('\n  # This stable', 1)[0]
        self.assertEqual(workflow.count('editor_storage.py prepare'), 1)
        self.assertIn('EDITOR_RUNNER_ENVIRONMENT: ${{ runner.environment }}', editor)
        self.assertLess(editor.index('editor_storage.py prepare'),
                        editor.index('Cache Cargo downloads and pinned toolchain'))
        self.assertIn('run: python3 tools/ci/ci_lanes.py lane editor', editor)
        self.assertIn('Observe storage after editor lane\n        if: always()\n', editor)
        for evidence in ('editor-process-runtime-', 'editor-process-failure-',
                         'editor-process-binaries-', 'editor-process-linux-prerequisites-',
                         'foundry-editor-timings-'):
            self.assertIn(evidence, editor)


if __name__ == '__main__':
    unittest.main()
