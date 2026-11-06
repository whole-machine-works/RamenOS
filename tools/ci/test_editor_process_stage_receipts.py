"""Real bounded command capture and adversarial diagnostic receipt mutations."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import editor_process_stage_receipts as receipts
import editor_process_gate as gate


class StageReceipts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        (self.repo / 'tools/ci').mkdir(parents=True)
        shutil.copyfile(Path(receipts.__file__).with_name('stage_timer.py'), self.repo / 'tools/ci/stage_timer.py')
        (self.repo / 'fixture.txt').write_text('fixed candidate\n')
        (self.repo / 'Cargo.lock').write_text('lock\n')
        (self.repo / 'rust-toolchain.toml').write_text('[toolchain]\nchannel="unused-fixture"\n')
        subprocess.run(['git', 'init', '-q', str(self.repo)], check=True)
        subprocess.run(['git', 'add', '.'], cwd=self.repo, check=True)
        self.spec = {'desktop-launch': ('D30Launch17', 'desktop/ui1-0/result.json')}
        self.batch = self.repo / 'out/batch' / ('a' * 32)
        self.batch.mkdir(parents=True)
        receipts.publish(self.batch / 'source.json', receipts.source_rows(self.repo))
        receipts.publish(self.batch / 'batch.json', {'schema_version': 1, 'repo': str(self.repo),
            'run_nonce': self.batch.name, 'source_manifest': receipts.ref(self.batch / 'source.json'),
            'source_links': [], 'lockfile_sha256': receipts.sha(self.repo / 'Cargo.lock'),
            'toolchain': {}, 'toolchain_manifest_sha256': receipts.sha(self.repo / 'rust-toolchain.toml')})
        # Keep derived files out of the source inventory, as in the repository.
        (self.repo / '.git/info/exclude').write_text('out/\n')
        self.argv = ['python3', '-c', "from pathlib import Path; import json; p=Path('out/desktop/ui1-0'); p.mkdir(parents=True); (p/'raw.txt').write_text('genuine child output'); (p/'result.json').write_text(json.dumps({'status':'PASS','source_sha256':{'fixture.txt':'" + receipts.sha(self.repo / 'fixture.txt') + "'},'artifact_sha256':{}}))"]

    def capture(self):
        previous = Path.cwd()
        try:
            os.chdir(self.repo)
            with patch.dict(receipts.SPECS, self.spec, clear=True):
                self.assertEqual(receipts.stage(self.repo, self.batch, 'desktop-launch', self.argv, dict(os.environ)), 0)
                return receipts.verify(self.repo, self.batch)
        finally:
            os.chdir(previous)

    def test_real_outer_and_inner_command_are_owned_and_reaped(self):
        _, rows = self.capture()
        self.assertEqual(rows[0]['argv'], self.argv)
        self.assertTrue(rows[0]['wait_reaped'])

    def test_copied_raw_without_report_hash_cannot_be_mutated(self):
        self.capture()
        (self.batch / 'desktop-launch/evidence/raw.txt').write_text('forged')
        with patch.dict(receipts.SPECS, self.spec, clear=True), self.assertRaisesRegex(RuntimeError, 'raw closure'):
            receipts.verify(self.repo, self.batch)

    def test_extra_unreferenced_copy_is_rejected(self):
        self.capture()
        (self.batch / 'desktop-launch/evidence/extra.txt').write_text('extra')
        with patch.dict(receipts.SPECS, self.spec, clear=True), self.assertRaisesRegex(RuntimeError, 'raw closure'):
            receipts.verify(self.repo, self.batch)

    def test_changed_source_is_rejected(self):
        self.capture()
        (self.repo / 'fixture.txt').write_text('changed')
        with patch.dict(receipts.SPECS, self.spec, clear=True), self.assertRaisesRegex(RuntimeError, 'source unchanged'):
            receipts.verify(self.repo, self.batch)

    def test_symlink_targets_are_pinned_separately(self):
        link = self.repo / 'source-link'
        link.symlink_to('fixture.txt')
        before = receipts.source_links(self.repo)
        link.unlink()
        link.symlink_to('Cargo.lock')
        self.assertNotEqual(before, receipts.source_links(self.repo))

    def test_structured_parent_result_survives_nested_pretty_worker_output(self):
        log = self.repo / 'structured.log'
        rows = [{'type':'suite','event':'started','test_count':1},
                {'type':'test','event':'started','name':'required_case'},
                {'type':'test','event':'ok','name':'required_case'},
                {'type':'suite','event':'ok','passed':1,'failed':0,'ignored':0}]
        log.write_text('test nested_worker ... ok\n' + '\n'.join(json.dumps(r) for r in rows) + '\n')
        diagnostic = self.repo / 'structured.stderr'
        diagnostic.write_text('')
        probe = {'stdout':{'path':str(log)}, 'stderr':{'path':str(diagnostic)}}
        gate.selected(probe, ['required_case'])
        self.assertEqual(probe['passed'], ['required_case'])
        rows[2]['event']='failed'
        log.write_text('\n'.join(json.dumps(r) for r in rows)+'\n')
        with self.assertRaisesRegex(RuntimeError, 'structured selected'):
            gate.selected(probe, ['required_case'])

    def test_final_owned_consumer_cannot_pass_with_uncertain_cleanup(self):
        owner = gate.Gate.__new__(gate.Gate)
        owner.output, owner.probes = self.repo, []
        for suffix in ('stdout', 'stderr'):
            (self.repo / ('FinalConsumer.' + suffix)).write_text('')
        actual = {'exit_code': 0, 'reaped': True, 'cleanup_error': 'process group remains unknown'}
        with patch.object(gate.runner, 'run_owned', return_value=actual), patch.object(owner, 'save') as saved:
            with self.assertRaisesRegex(RuntimeError, 'uncertain cleanup'):
                owner.run('FinalConsumer', ['required-command'])
        saved.assert_called_once()
        self.assertTrue(owner.probes[0]['cleanup_uncertain'], 'failed evidence remains retained')

    def test_successful_rust_result_does_not_hide_incomplete_cleanup_on_stderr(self):
        log, diagnostic = self.repo / 'passed.log', self.repo / 'retained.stderr'
        log.write_text('test required_case ... ok\n')
        diagnostic.write_text('INCOMPLETE: actual owner cleanup failed\n')
        probe = {'stdout': {'path': str(log)}, 'stderr': {'path': str(diagnostic)}}
        with self.assertRaisesRegex(RuntimeError, 'complete actual test outcomes'):
            gate.selected(probe, ['required_case'])

    def test_zero_selected_success_does_not_satisfy_case(self):
        log = self.repo / 'empty.log'
        log.write_text('running 0 tests\ntest result: ok. 0 passed; 0 failed;\n')
        with self.assertRaisesRegex(RuntimeError, 'exact selected'):
            gate.selected({'stdout': {'path': str(log)}}, ['required_case'])


if __name__ == '__main__':
    unittest.main()
