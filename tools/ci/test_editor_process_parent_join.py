"""Synthetic parent-IO provenance joins; no Store/runtime acceptance is claimed."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import editor_process_reader as reader
import test_editor_process_reader as existing


class ParentJoinTests(unittest.TestCase):
    def setUp(self):
        self.fixture = existing.ReaderTests('test_complete_recording_has_no_runtime_acceptance_claim')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        # macOS exposes /var through a symlink; supply a canonical test root
        # without weakening the reader's no-follow traversal policy.
        self.base = Path(self.temp.name).resolve()
        self.base.chmod(0o700)
        self.root = self.base / 'parent-io'
        self.case = self.root / 'case' / 'leg'
        self.case.mkdir(parents=True, mode=0o700)
        self.root.chmod(0o700)
        self.case.parent.chmod(0o700)
        self.raw = b'synthetic parent IO payload, not a native receipt'
        self.binding = dict(schema_version=1, run_nonce=existing.NONCE, case='case')
        self.summary = dict(binding=copy.deepcopy(self.binding), scope='synthetic diagnostic fixture')
        self.events = dict(binding=copy.deepcopy(self.binding), raw=dict(
            file='wire.bin', byte_len=len(self.raw), sha256=reader.digest(self.raw)))
        self.put(self.case / 'wire.bin', self.raw)
        self.write_records()
        self.manifest = self.base / 'parent-manifest.json'
        self.manifest_value = dict(schema_version=1, run_nonce=existing.NONCE,
            source_manifest_sha256=existing.SOURCE, parent_root=str(self.root), files=[])
        self.refresh_manifest()

    def put(self, path, payload):
        path.write_bytes(payload)
        path.chmod(0o600)

    def write_records(self):
        for name, value in (('summary.json', self.summary), ('events.json', self.events)):
            self.put(self.case / name, json.dumps(value, separators=(',', ':')).encode() + b'\n')

    def refresh_manifest(self):
        rows = []
        for name in ('summary.json', 'events.json', 'wire.bin'):
            path = self.case / name
            raw = path.read_bytes()
            rows.append(dict(path=str(path.relative_to(self.root)), bytes=len(raw), sha256=reader.digest(raw)))
        self.manifest_value['files'] = rows
        self.save_manifest()

    def save_manifest(self):
        self.put(self.manifest, json.dumps(self.manifest_value, separators=(',', ':')).encode() + b'\n')

    def check(self):
        return reader.join_parent_recordings(self.fixture.check(), self.manifest)

    def test_complete_join_is_provenance_only_without_runtime_acceptance(self):
        result = self.check()
        self.assertEqual(result['status'], 'RECORDING_COMPLETE')
        join = result['parent_io_join']
        self.assertIn('no Reader93 or additional runtime acceptance claim', join['scope'])
        self.assertEqual(join['manifest_sha256'], reader.digest(self.manifest.read_bytes()))
        self.assertEqual(join['runs'], [dict(parent_case='case', process_run_ordinal=1,
            summary='case/leg/summary.json', raw_references=1)])

    def test_manifest_nonce_and_source_must_match_process_candidate(self):
        for key, value in (('run_nonce', 'e' * 32), ('source_manifest_sha256', 'd' * 64)):
            original = self.manifest_value[key]
            with self.subTest(key=key):
                self.manifest_value[key] = value
                self.save_manifest()
                with self.assertRaisesRegex(reader.Invalid, 'same candidate parent IO'): self.check()
            self.manifest_value[key] = original

    def test_summary_case_and_nonce_are_checked_after_manifest_hashes(self):
        for key, value in (('case', 'other'), ('run_nonce', 'e' * 32)):
            original = self.summary['binding'][key]
            with self.subTest(key=key):
                self.summary['binding'][key] = value
                self.write_records(); self.refresh_manifest()
                with self.assertRaisesRegex(reader.Invalid, 'case and nonce binding'): self.check()
            self.summary['binding'][key] = original

    def test_each_retained_json_record_has_the_same_parent_case(self):
        self.events['binding']['case'] = 'other'
        self.write_records(); self.refresh_manifest()
        with self.assertRaisesRegex(reader.Invalid, 'same parent case throughout'): self.check()

    def test_manifest_cannot_omit_or_add_actual_raw_leaves(self):
        self.put(self.case / 'unlisted.bin', b'unaccounted')
        with self.assertRaisesRegex(reader.Invalid, 'exact parent raw inventory'): self.check()
        (self.case / 'unlisted.bin').unlink()
        (self.case / 'wire.bin').unlink()
        with self.assertRaisesRegex(reader.Invalid, 'missing parent raw leaf'): self.check()

    def test_manifest_raw_hash_and_length_are_independent(self):
        self.put(self.case / 'wire.bin', b'substituted')
        with self.assertRaisesRegex(reader.Invalid, 'actual parent raw length and hash'): self.check()

    def test_declared_raw_reference_hash_and_length_are_checked(self):
        for key, value in (('sha256', 'f' * 64), ('byte_len', len(self.raw) + 1)):
            original = self.events['raw'][key]
            with self.subTest(key=key):
                self.events['raw'][key] = value
                self.write_records(); self.refresh_manifest()
                with self.assertRaisesRegex(reader.Invalid, 'parent declared raw reference intact'): self.check()
            self.events['raw'][key] = original

    def test_absolute_and_parent_traversal_raw_references_are_rejected(self):
        for path in ('../wire.bin', str(self.case / 'wire.bin')):
            with self.subTest(path=path):
                self.events['raw']['file'] = path
                self.write_records(); self.refresh_manifest()
                with self.assertRaisesRegex(reader.Invalid, 'relative parent raw reference'): self.check()

    def test_parent_file_and_directory_symlinks_are_not_followed(self):
        wire = self.case / 'wire.bin'
        wire.unlink(); wire.symlink_to(self.case / 'events.json')
        with self.assertRaises((reader.Invalid, OSError)): self.check()
        wire.unlink(); self.put(wire, self.raw)
        (self.root / 'linked').symlink_to(self.case, target_is_directory=True)
        with self.assertRaisesRegex(reader.Invalid, 'no parent directory link'): self.check()

    def test_parent_root_symlink_cannot_supply_a_join(self):
        link = self.base / 'parent-link'
        link.symlink_to(self.root, target_is_directory=True)
        self.manifest_value['parent_root'] = str(link)
        self.save_manifest()
        with self.assertRaisesRegex(reader.Invalid, 'actual parent recording root'): self.check()

    def test_process_case_requires_exactly_one_actual_summary(self):
        self.manifest_value['files'] = [r for r in self.manifest_value['files']
            if not r['path'].endswith('summary.json')]
        (self.case / 'summary.json').unlink()
        self.save_manifest()
        with self.assertRaisesRegex(reader.Invalid, 'one actual parent IO case'): self.check()

    def test_json_without_any_raw_reference_cannot_claim_parent_io(self):
        self.events.pop('raw')
        self.write_records(); self.refresh_manifest()
        with self.assertRaisesRegex(reader.Invalid, 'raw parent IO references required'): self.check()


if __name__ == '__main__':
    unittest.main()
