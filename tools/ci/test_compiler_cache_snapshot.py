"""Disposable cache retention controls; real retirement, mocked receipt boundary."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import build_cache as cache
import compiler_cache_control as control
import compiler_cache_snapshot as snapshot


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name).resolve()
        (self.repo / 'Cargo.lock').write_text('lock')
        (self.repo / 'out/ci-optimization').mkdir(parents=True)
        self.root = self.repo / 'out/ci-optimization/compiler-cache'
        self.batch = self.repo / 'out/foundry/editor-process-stages' / ('a' * 32)
        self.batch.mkdir(parents=True)
        self.header = {'run_nonce': self.batch.name, 'toolchain': {'rustc': 'rustc', 'cargo': 'cargo'},
                       'lockfile_sha256': cache.file_digest(self.repo / 'Cargo.lock')}
        self.probes = []
        self.current = set()
        for stage, (identity, phases) in snapshot.REPORTS.items():
            manifest = self.batch / stage / 'semantic-source.json'
            manifest.parent.mkdir()
            manifest.write_text(stage)
            pin = snapshot.receipts.sha(manifest)
            records = []
            for phase, features in phases.items():
                inputs = cache.key_inputs(self.repo, pin, phase, features, 'rustc', 'cargo', {})
                with cache.CacheLease(self.root, inputs) as lease:
                    (lease.target / 'compiled').write_bytes(b'current')
                    self.current.add(lease.key)
                with cache.CacheLease(self.root, inputs) as lease:
                    records.append(lease.metadata.copy())
                    self.assertTrue(lease.metadata['hit'])
            value = {'status': 'PASS', 'source_manifest_sha256': pin,
                     'compiler_cache': {'enabled': True, 'cached_acceptance': False, 'phases': records}}
            if stage == 'desktop-editor-task':
                value['provenance'] = {'compiler_cache': value.pop('compiler_cache')}
            path = self.batch / stage / snapshot.REPORT_PATHS[stage]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(value))
            self.probes.append({'id': identity, 'gate_reports': [{**snapshot.receipts.ref(path),
                                'source_manifest': snapshot.receipts.ref(manifest)}]})
        self.stale_inputs = cache.key_inputs(self.repo, 'f' * 64, 'stale', [], 'rustc', 'cargo', {})
        with cache.CacheLease(self.root, self.stale_inputs) as lease:
            (lease.target / 'compiled').write_bytes(b'stale-data')
            self.stale = lease.key
        self.evidence = self.repo / 'out/evidence.json'
        self.evidence.write_text('preserve exact evidence')

    def tearDown(self):
        self.tmp.cleanup()

    def run_snapshot(self):
        with patch.object(snapshot.receipts, 'verify', return_value=(self.header, self.probes)) as verify:
            result = snapshot.snapshot(self.repo, self.batch)
            verify.assert_called_once_with(self.repo, self.batch)
            return result

    def change_report(self, mutate):
        ref = self.probes[0]['gate_reports'][0]
        path = Path(ref['path']); value = json.loads(path.read_bytes()); mutate(value)
        path.write_text(json.dumps(value)); ref['sha256'] = snapshot.receipts.sha(path)

    def assert_refusal_preserves_stale(self):
        with self.assertRaises((ValueError, RuntimeError, OSError, KeyError)):
            self.run_snapshot()
        self.assertTrue((self.root / self.stale / 'target/compiled').exists())
        self.assertEqual(self.evidence.read_text(), 'preserve exact evidence')

    def test_current_keep_stale_retirement_evidence_and_next_allocation(self):
        result = self.run_snapshot()
        self.assertEqual({row['key'] for row in result['kept']}, self.current)
        self.assertEqual([row['key'] for row in result['retired']], [self.stale])
        self.assertEqual(result['retired_logical_bytes'], len(b'stale-data'))
        self.assertEqual(result['kept_logical_bytes'], 11 * len(b'current'))
        self.assertFalse(result['cached_acceptance'])
        self.assertFalse((self.root / self.stale).exists())
        self.assertEqual(self.evidence.read_text(), 'preserve exact evidence')
        for key in self.current:
            self.assertEqual((self.root / key / 'target/compiled').read_bytes(), b'current')
        with cache.CacheLease(self.root, self.stale_inputs) as lease:
            self.assertFalse(lease.metadata['hit'])
        self.assertEqual(json.loads(self.batch.with_suffix('.cache-snapshot.json').read_bytes()), result)

    def test_receipt_failure_precedes_any_cache_inspection(self):
        with patch.object(snapshot.receipts, 'verify', side_effect=RuntimeError('incomplete')), \
                patch.object(snapshot.control, 'inspect_cache') as inspect:
            with self.assertRaises(RuntimeError): snapshot.snapshot(self.repo, self.batch)
            inspect.assert_not_called()
        self.assertTrue((self.root / self.stale).exists())

    def test_disabled_missing_duplicate_phase_and_wrong_scope_refuse(self):
        original = Path(self.probes[0]['gate_reports'][0]['path']).read_bytes()
        for mutate in (
            lambda v: v['compiler_cache'].update(enabled=False),
            lambda v: v['compiler_cache']['phases'].pop(),
            lambda v: v['compiler_cache']['phases'].append(copy.deepcopy(v['compiler_cache']['phases'][0])),
            lambda v: v['compiler_cache']['phases'][0].update(scope='development'),
            lambda v: v['compiler_cache']['phases'][0].update(admitted=False),
            lambda v: v['compiler_cache']['phases'][0].update(target='/other/target'),
        ):
            with self.subTest(mutate=mutate):
                Path(self.probes[0]['gate_reports'][0]['path']).write_bytes(original)
                self.change_report(mutate)
                self.assert_refusal_preserves_stale()

    def test_missing_ambiguous_or_changed_report_refuse(self):
        original = copy.deepcopy(self.probes)
        self.probes.pop(); self.assert_refusal_preserves_stale()
        self.probes = copy.deepcopy(original)
        self.probes[0]['gate_reports'] *= 2; self.assert_refusal_preserves_stale()
        self.probes = original
        Path(self.probes[0]['gate_reports'][0]['path']).write_text('{}')
        self.assert_refusal_preserves_stale()

    def test_active_quarantined_and_unknown_stale_entries_refuse(self):
        with cache.CacheLease(self.root, self.stale_inputs):
            self.assert_refusal_preserves_stale()
        marker = self.root / self.stale / '.inflight'
        marker.write_text('uncertain'); self.assert_refusal_preserves_stale(); marker.unlink()
        unknown = self.root / self.stale / 'unknown'
        unknown.write_text('unknown'); self.assert_refusal_preserves_stale()

    def test_current_context_must_match_source_and_phase(self):
        ref = self.probes[0]['gate_reports'][0]
        manifest = Path(ref['source_manifest']['path'])
        manifest.write_text('different source context')
        ref['source_manifest'] = snapshot.receipts.ref(manifest)
        self.change_report(lambda v: v.update(source_manifest_sha256=ref['source_manifest']['sha256']))
        self.assert_refusal_preserves_stale()

    def test_current_missing_or_context_drift_refuse_before_retiring_stale(self):
        inspect = snapshot.control.inspect_cache
        for mode in ('missing', 'drift'):
            def changed(repo, scope):
                result = inspect(repo, scope)
                row = next(row for row in result['entries'] if row['key'] in self.current)
                if mode == 'missing': result['entries'].remove(row)
                else: row['context_sha256'] = '0' * 64
                return result
            with self.subTest(mode=mode), patch.object(snapshot.control, 'inspect_cache', side_effect=changed):
                self.assert_refusal_preserves_stale()

    def test_active_refusal_then_next_successful_snapshot(self):
        with cache.CacheLease(self.root, self.stale_inputs):
            self.assert_refusal_preserves_stale()
        self.assertEqual(self.run_snapshot()['status'], 'PASS')
        self.assertFalse((self.root / self.stale).exists())

    def test_context_drift_during_retirement_refuses_and_retains_failure_report(self):
        real = snapshot.control.retire
        def drift(repo, scope, key, digest):
            return real(repo, scope, key, '0' * 64)
        with patch.object(snapshot.control, 'retire', side_effect=drift):
            self.assert_refusal_preserves_stale()
        report = json.loads(self.batch.with_suffix('.cache-snapshot.json').read_bytes())
        self.assertEqual(report['status'], 'REFUSED')
        self.assertEqual(report['retired'], [])

    def test_report_is_fresh_and_exact_batch_without_sibling_discovery(self):
        sibling = self.batch.parent / ('b' * 32); sibling.mkdir()
        (sibling / 'bad-receipt').write_text('ignored')
        self.run_snapshot()
        with self.assertRaises(FileExistsError): self.run_snapshot()
        self.assertTrue((sibling / 'bad-receipt').exists())


if __name__ == '__main__': unittest.main()
