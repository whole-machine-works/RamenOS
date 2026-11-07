"""Pure prior-entry token controls; synthetic inputs grant no live authority."""
import copy
import dataclasses
import hashlib
import json
from pathlib import Path
from types import MappingProxyType
import tempfile
import unittest
from unittest.mock import patch

import boot_profile_capture as capture
import boot_profile_inputs as inputs
import run0_c0_decode as decoder
from test_run0_c0_decode import full_fixture
import run0_c0_entry as entry


class PriorEntryControls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.report, _, self.blobs, _, _ = full_fixture(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def validate(self, report=None, blobs=None):
        report = self.report if report is None else report
        return entry.validate_prior_entry(report['profile_ref'], report['prior_admission_ref'],
                                          report['profile_mapping_ref'], self.blobs if blobs is None else blobs)

    def json_value(self, ref):
        return json.loads(self.blobs[ref['path']])

    def replace(self, ref, value):
        raw = value if type(value) is bytes else json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
        self.blobs[ref['path']] = raw
        return {'path': ref['path'], 'sha256': hashlib.sha256(raw).hexdigest(), 'length': len(raw)}

    def failure(self, status='DENY', report=None, blobs=None):
        with self.assertRaises(decoder.C0DecodeError) as failure:
            self.validate(report, blobs)
        self.assertEqual(failure.exception.status, status)

    def test_original_sata_and_vapic_profiles_mint_recomputed_hint(self):
        for profile in (capture.INVOCATION_PROFILE, capture.SATA_OFF_INVOCATION_PROFILE,
                        capture.VAPIC_OFF_INVOCATION_PROFILE):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as folder:
                report, _, blobs, _, _ = full_fixture(Path(folder), profile)
                with patch.object(decoder, '_profile_binding', wraps=decoder._profile_binding) as proof:
                    result = entry.export_validated_prior_entry(self.validate(report, blobs))
                    proof.assert_called_once()
                admitted = json.loads(blobs[report['prior_admission_ref']['path']])['candidate']
                self.assertEqual(set(result), {'profile_ref', 'probe_profile_sha256', 'prior_admission_ref',
                    'profile_mapping_ref', 'entry_address', 'loaded_base', 'diagnostic_ref', 'diagnostic_line',
                    'prior_run_id', 'expected_entry_hex', 'invocation_profile', 'scope'})
                self.assertEqual(result['scope'], 'prior-run-hint-only')
                self.assertEqual(result['invocation_profile'], profile)
                for name, value in admitted.items(): self.assertEqual(result[name], value)
                for name in ('profile_ref', 'prior_admission_ref', 'profile_mapping_ref'):
                    self.assertEqual(result[name], report[name])
                self.assertEqual(result['probe_profile_sha256'], inputs.profile_digest(json.loads(blobs[report['profile_ref']['path']])))

    def test_constructor_export_exact_type_and_immutable_native_copy(self):
        with self.assertRaises(TypeError): entry.ValidatedPriorEntry(entry_address=0x1234)
        token = self.validate()
        with self.assertRaises((dataclasses.FrozenInstanceError, AttributeError)):
            token.entry_address = 0x1234
        first = entry.export_validated_prior_entry(token)
        first['profile_ref']['path'] = 'changed'
        first['diagnostic_ref']['length'] = 0
        second = entry.export_validated_prior_entry(token)
        self.assertEqual(second['profile_ref'], self.report['profile_ref'])
        self.assertNotEqual(second['diagnostic_ref']['length'], 0)
        for forged in (1234, {}, self.json_value(self.report['prior_admission_ref']),
                       object.__new__(entry.ValidatedPriorEntry)):
            with self.subTest(forged=type(forged)), self.assertRaises(decoder.C0DecodeError):
                entry.export_validated_prior_entry(forged)
        class Foreign(entry.ValidatedPriorEntry): pass
        with self.assertRaises(decoder.C0DecodeError):
            entry.export_validated_prior_entry(object.__new__(Foreign))

    def test_export_rejects_malformed_fields_without_callbacks(self):
        for field, malformed in (('entry_address', True), ('loaded_base', -1), ('diagnostic_line', False),
                                  ('scope', 'live-read-grant'), ('expected_entry_hex', '00'),
                                  ('profile_ref', self.report['profile_ref'])):
            with self.subTest(field=field):
                token = self.validate(); object.__setattr__(token, field, malformed)
                with self.assertRaises(decoder.C0DecodeError): entry.export_validated_prior_entry(token)

    def test_factory_has_no_acquiring_callback_or_wire_effect(self):
        with patch('builtins.open', side_effect=AssertionError('file acquisition')), \
                patch('pathlib.Path.open', side_effect=AssertionError('path acquisition')), \
                patch('os.open', side_effect=AssertionError('fd acquisition')), \
                patch('socket.socket', side_effect=AssertionError('wire acquisition')), \
                patch('subprocess.Popen', side_effect=AssertionError('process acquisition')):
            token = self.validate()
            self.assertEqual(entry.export_validated_prior_entry(token)['scope'], 'prior-run-hint-only')

    def test_factory_snapshots_envelope_and_token_is_reusable_after_input_mutation(self):
        report, blobs = copy.deepcopy(self.report), dict(self.blobs)
        token = self.validate(report, blobs)
        expected = entry.export_validated_prior_entry(token)
        for name in ('profile_ref', 'prior_admission_ref', 'profile_mapping_ref'):
            report[name].clear()
        blobs.clear()
        self.assertEqual(entry.export_validated_prior_entry(token), expected)
        self.assertEqual(entry.export_validated_prior_entry(token), expected)

    def test_missing_bytes_incomplete_then_next_valid_factory_succeeds(self):
        for reference in (self.report['profile_ref'], self.report['prior_admission_ref'],
                          self.report['profile_mapping_ref'], self.json_value(self.report['profile_ref'])['inputs']['efi']):
            with self.subTest(path=reference['path']):
                missing = dict(self.blobs); missing.pop(reference['path'])
                self.failure('INCOMPLETE', blobs=missing)
                self.assertEqual(entry.export_validated_prior_entry(self.validate())['scope'], 'prior-run-hint-only')

    def test_exact_native_refs_and_blobs_refuse_proxy_subclass_and_callbacks(self):
        calls = []
        class Callbacks(dict):
            def __iter__(self): calls.append('iter'); raise AssertionError('callback')
            def __getitem__(self, name): calls.append('getitem'); raise AssertionError('callback')
            def items(self): calls.append('items'); raise AssertionError('callback')
        for replacement in (Callbacks(self.blobs), MappingProxyType(Callbacks(self.blobs)), lambda _: b''):
            self.failure(blobs=replacement)
        for name in ('profile_ref', 'prior_admission_ref', 'profile_mapping_ref'):
            for replacement in (Callbacks(self.report[name]), MappingProxyType(Callbacks(self.report[name])),
                                dict(self.report[name], extra=1), dict(self.report[name], path='../escape'),
                                dict(self.report[name], length=True), dict(self.report[name], sha256='0')):
                with self.subTest(name=name, replacement=type(replacement)):
                    self.failure(report=self.report | {name: replacement})
        self.assertEqual(calls, [])

    def test_conflicting_same_path_identity_and_digest_length_changes_refuse(self):
        self.failure(report=self.report | {'prior_admission_ref': self.report['prior_admission_ref'] | {'path': self.report['profile_ref']['path']}})
        for name in ('profile_ref', 'prior_admission_ref', 'profile_mapping_ref'):
            for change in ({'sha256': '0'*64}, {'length': self.report[name]['length']+1}):
                self.failure(report=self.report | {name: self.report[name] | change})

    def test_changed_candidate_base_entry_bytes_and_bool_refuse(self):
        original = self.json_value(self.report['prior_admission_ref'])
        for name, value in (('entry_address', original['candidate']['entry_address']+1),
                            ('loaded_base', original['candidate']['loaded_base']+4096),
                            ('expected_entry_hex', '00'*32), ('entry_address', True), ('diagnostic_line', True)):
            with self.subTest(name=name, value=value):
                admission = copy.deepcopy(original); admission['candidate'][name] = value
                ref = self.replace(self.report['prior_admission_ref'], admission)
                self.failure(report=self.report | {'prior_admission_ref': ref})

    def test_mapping_profile_identity_and_changed_input_hash_refuse(self):
        original = self.json_value(self.report['profile_mapping_ref'])
        for name in ('admission_profile_sha256', 'probe_profile_sha256'):
            mapping = copy.deepcopy(original); mapping[name] = '0'*64
            ref = self.replace(self.report['profile_mapping_ref'], mapping)
            self.failure(report=self.report | {'profile_mapping_ref': ref})
        self.blobs['efi'] = self.blobs['efi'][:-1]+b'!'
        self.failure()

    def test_truncated_substituted_duplicate_diagnostic_and_wrong_probe_argv_refuse(self):
        mapping = self.json_value(self.report['profile_mapping_ref'])
        diagnostic = mapping['whole_unmodified_diagnostic_ref']
        original = self.blobs[diagnostic['path']]
        # Retain the whole original ref: any changed present bytes contradict it.
        for raw in (original[:-1], b'other diagnostic\n', original+original):
            with self.subTest(raw=raw):
                altered = dict(self.blobs); altered[diagnostic['path']] = raw
                self.failure(blobs=altered)
        probe_ref = mapping['probe_report_ref']
        probe = self.json_value(probe_ref); probe['argv'] = ['qemu', '-different']
        mapping['probe_report_ref'] = self.replace(probe_ref, probe)
        ref = self.replace(self.report['profile_mapping_ref'], mapping)
        self.failure(report=self.report | {'profile_mapping_ref': ref})

    def test_present_zero_or_duplicate_matching_records_contradict_saved_admit(self):
        original = dict(self.blobs)
        mapping = self.json_value(self.report['profile_mapping_ref'])
        admission = self.json_value(self.report['prior_admission_ref'])
        diagnostic_ref = mapping['whole_unmodified_diagnostic_ref']
        diagnostic = self.blobs[diagnostic_ref['path']]
        for raw in (b'no matching record\n', diagnostic+diagnostic):
            with self.subTest(raw=raw):
                self.blobs = dict(original)
                changed_mapping, changed_admission = copy.deepcopy(mapping), copy.deepcopy(admission)
                changed_ref = self.replace(diagnostic_ref, raw)
                changed_mapping['whole_unmodified_diagnostic_ref'] = changed_ref
                changed_admission['candidate']['diagnostic_ref'] = changed_ref
                report = self.report | {
                    'profile_mapping_ref': self.replace(self.report['profile_mapping_ref'], changed_mapping),
                    'prior_admission_ref': self.replace(self.report['prior_admission_ref'], changed_admission)}
                with self.assertRaises(decoder.C0DecodeError) as failure:
                    self.validate(report)
                self.assertEqual((failure.exception.status, failure.exception.reason),
                                 ('DENY', 'prior_diagnostic_invalid'))


if __name__ == '__main__': unittest.main()
