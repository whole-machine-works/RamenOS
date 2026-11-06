#!/usr/bin/env python3
"""Portable synthetic cases for the RUN0 entry-input prerequisite, not captures."""

import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

import boot_profile_inputs as subject


def put(data, offset, fmt, value):
    struct.pack_into('<' + fmt, data, offset, value)


def pe_fixture():
    """Synthetic PE with entry RVA 0x1020 at file offset 0x420."""
    data = bytearray(0x800)
    data[:2] = b'MZ'
    put(data, 60, 'I', 0x80)
    data[0x80:0x84] = b'PE\0\0'
    put(data, 0x84, 'H', 0x8664)
    put(data, 0x86, 'H', 2)
    put(data, 0x94, 'H', 240)
    put(data, 0x96, 'H', 0x22)
    opt = 0x98
    for offset, fmt, value in [(0, 'H', 0x20B), (16, 'I', 0x1020),
                               (24, 'Q', 0x100000), (32, 'I', 4096),
                               (36, 'I', 512), (56, 'I', 0x3000),
                               (60, 'I', 0x400), (68, 'H', 10),
                               (108, 'I', 16), (152, 'I', 0x2000),
                               (156, 'I', 12)]:
        put(data, opt + offset, fmt, value)
    for index, (name, rva, raw, flags) in enumerate([
            (b'.text', 0x1000, 0x400, 0x60000020),
            (b'.reloc', 0x2000, 0x600, 0x42000040)]):
        section = opt + 240 + index * 40
        data[section:section + len(name)] = name
        for offset, value in [(8, 512), (12, rva), (16, 512),
                              (20, raw), (36, flags)]:
            put(data, section + offset, 'I', value)
    data[0x400:0x600] = bytes(range(256)) * 2
    put(data, 0x428, 'Q', 0x101234)
    put(data, 0x600, 'I', 0x1000)
    put(data, 0x604, 'I', 12)
    put(data, 0x608, 'H', 0xA028)
    return data


class EntryInputsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.packet = {
            'schema_version': 1, 'kind': 'boot_entry_inputs_v0',
            'entry_length': 32,
            'profile': {
                'source_commit': 'a' * 40, 'assembled_patch_sha256': 'b' * 64,
                'machine': 'pc-q35-8.2', 'accelerator': 'tcg', 'cpu': 'qemu64',
                'vcpus': 1, 'ram_bytes': 512 * 1024 * 1024,
                'diagnostic_image_name': 'fixture.efi',
                'artifacts': {},
            },
            'prior_hint': None,
        }
        for name in ['efi', 'qemu', 'gdb', 'symbol_tool', 'symbols',
                     'ovmf_code', 'initial_vars', 'init', 'esp',
                     'expanded_cpu', 'invocation']:
            self.packet['profile']['artifacts'][name] = self.blob(
                name, bytes(pe_fixture()) if name == 'efi' else
                ('synthetic-' + name).encode())
        self.rehint()

    def blob(self, name, data):
        (self.root / name).write_bytes(data)
        return {'path': name, 'sha256': hashlib.sha256(data).hexdigest(),
                'length': len(data)}

    def rehint(self, diagnostic=None):
        self.packet['prior_hint'] = {
            'prior_run_id': 'synthetic-prior-run',
            'profile_sha256': subject.profile_digest(self.packet['profile']),
            'diagnostic_ref': self.blob('diagnostic', diagnostic or
                b'Loading driver at 0x00000200000 EntryPoint=0x00000201020 fixture.efi\n'),
        }

    def replace_pe(self, data):
        self.packet['profile']['artifacts']['efi'] = self.blob('efi', bytes(data))
        self.rehint()

    def result(self, status, packet=None):
        report = subject.admit(self.packet if packet is None else packet, self.root)
        self.assertEqual(status, report['status'], report)
        for name in ['capture_complete', 'profile_preconditions_met',
                     'fresh_c0_verified', 'opaque_profile_semantics_verified',
                     'symbols_match_verified', 'esp_efi_binding_verified']:
            self.assertIs(report[name], False, name)
        self.assertEqual(set(subject.CLAIM_NAMES), set(report['claims']))
        for value in report['claims'].values():
            self.assertIs(value, False)
        return report

    def test_valid_rva_file_mapping_and_relocated_entry(self):
        report = self.result('ADMIT')
        self.assertEqual(0x1020, report['pe']['entry_rva'])
        self.assertEqual(0x420, report['pe']['entry_file_offset'])
        self.assertEqual(0x201020, report['candidate']['entry_address'])
        expected = bytearray(pe_fixture()[0x420:0x440])
        put(expected, 8, 'Q', 0x201234)
        self.assertEqual(expected.hex(), report['candidate']['expected_entry_hex'])
        self.assertEqual(1, report['candidate']['diagnostic_line'])
        self.assertEqual('prior-run-hint-only', report['candidate']['scope'])

    def test_partial_relocation_overlap_at_both_sample_edges(self):
        for target in [0x101C, 0x103C]:
            with self.subTest(target=target):
                data = pe_fixture()
                put(data, 0x608, 'H', 0xA000 | (target - 0x1000))
                offset = target - 0x1000 + 0x400
                put(data, offset, 'Q', 0x101234)
                self.replace_pe(data)
                expected = bytearray(data)
                put(expected, offset, 'Q', 0x201234)
                self.assertEqual(expected[0x420:0x440].hex(),
                    self.result('ADMIT')['candidate']['expected_entry_hex'])

    def test_preferred_base_without_relocations(self):
        data = pe_fixture()
        put(data, 0x98 + 152, 'I', 0)
        put(data, 0x98 + 156, 'I', 0)
        self.replace_pe(data)
        self.result('DENY')
        self.rehint(b'Loading driver at 0x100000 EntryPoint=0x101020 fixture.efi\n')
        self.result('ADMIT')

    def test_stripped_relocations_cannot_change_base(self):
        data = pe_fixture()
        put(data, 0x96, 'H', 0x23)
        self.replace_pe(data)
        self.result('DENY')

    def test_truncation_of_every_structural_region(self):
        for end in [0, 1, 63, 0x83, 0x97, 0x98 + 112, 0x98 + 239,
                    0x98 + 240 + 79, 0x3FF, 0x421, 0x607, 0x7FF]:
            with self.subTest(end=end):
                with self.assertRaises(subject.AdmissionError):
                    subject.parse_pe(bytes(pe_fixture()[:end]))

    def test_header_and_section_denials(self):
        mutations = [(0x80, 'I', 0), (0x84, 'H', 0xAA64),
                     (0x86, 'H', 97), (0x86, 'H', 0),
                     (0x94, 'H', 111), (0x98, 'H', 0x10B),
                     (0x98 + 68, 'H', 11), (0x98 + 108, 'I', 17),
                     (0x98 + 60, 'I', 256), (0x98 + 56, 'I', 0x2000),
                     (0x98 + 16, 'I', 0x3000), (0x98 + 16, 'I', 0x11F0),
                     (0x98 + 32, 'I', 3), (0x98 + 36, 'I', 3),
                     (0x188 + 36, 'I', 0x40000040),
                     (0x1B0 + 12, 'I', 0x1000),
                     (0x1B0 + 20, 'I', 0x400),
                     (0x188 + 12, 'I', 0xFFFFF000),
                     (0x188 + 20, 'I', 0xFFFFFE00)]
        for offset, fmt, value in mutations:
            with self.subTest(offset=offset, value=value):
                data = pe_fixture()
                put(data, offset, fmt, value)
                self.replace_pe(data)
                self.result('DENY')
        self.replace_pe(pe_fixture())
        self.result('ADMIT')

    def test_zero_fill_entry_and_ambiguous_raw_sections_deny(self):
        data = pe_fixture()
        put(data, 0x188 + 8, 'I', 0x400)
        put(data, 0x98 + 16, 'I', 0x1250)
        self.replace_pe(data)
        self.result('DENY')

    def test_raw_alignment_padding_is_not_loaded_entry_code(self):
        data = pe_fixture()
        put(data, 0x188 + 8, 'I', 0x30)
        self.replace_pe(data)
        self.result('DENY')
        put(data, 0x188 + 8, 'I', 0)
        self.replace_pe(data)
        self.result('DENY')

    def test_relocation_must_not_modify_its_own_records(self):
        data = pe_fixture()
        put(data, 0x600, 'I', 0x2000)
        put(data, 0x608, 'H', 0xA004)
        self.replace_pe(data)
        self.result('DENY')

    def test_relocation_bounds_format_types_duplicates_and_overlap(self):
        for offset, fmt, value in [(0x604, 'I', 0), (0x604, 'I', 9),
                (0x604, 'I', 16), (0x600, 'I', 0x1001),
                (0x600, 'I', 0xFFFFF000), (0x608, 'H', 0x3028),
                (0x608, 'H', 0xAFFF), (0x60A, 'H', 0xA028),
                (0x60A, 'H', 0xA02C), (0x98 + 156, 'I', 0x100004),
                (0x98 + 152, 'I', 0x3000), (0x98 + 156, 'I', 0)]:
            with self.subTest(offset=offset, value=value):
                data = pe_fixture()
                put(data, offset, fmt, value)
                self.replace_pe(data)
                self.result('DENY')

    def test_loaded_image_entry_and_relocation_arithmetic(self):
        for base, entry in [(0xFFFFFFFFFFFFF000, 0x10),
                (0x7FFFFFFFF000, 0x800000000020), (0x200001, 0x201021),
                (0x200000, 0x201021), (0x10000000000000000, 0x101020)]:
            with self.subTest(base=base):
                self.rehint(f'Loading driver at 0x{base:X} EntryPoint=0x{entry:X} fixture.efi\n'.encode())
                self.result('DENY')
        for original, base in [(2**64 - 1, 0x200000), (0, 0x80000)]:
            data = pe_fixture()
            put(data, 0x428, 'Q', original)
            self.replace_pe(data)
            self.rehint(f'Loading driver at 0x{base:X} EntryPoint=0x{base + 0x1020:X} fixture.efi\n'.encode())
            self.result('DENY')

    def test_missing_and_ambiguous_diagnostics_are_incomplete(self):
        good = (self.root / 'diagnostic').read_bytes()
        for hint in [None, self.packet['prior_hint']]:
            packet = copy.deepcopy(self.packet)
            packet['prior_hint'] = hint
            if hint is not None:
                (self.root / 'diagnostic').unlink()
            self.result('INCOMPLETE', packet)
        for diagnostic in [b'No load diagnostic emitted\n', good + good,
                           good.replace(b'fixture.efi', b'other.efi')]:
            self.rehint(diagnostic)
            self.result('INCOMPLETE')
        self.rehint(good)
        self.result('ADMIT')

    def test_malformed_matching_diagnostic_denies(self):
        for line in [b'Loading driver at 0xZZ EntryPoint=0x201020 fixture.efi\n',
                     b'Loading driver at 0x200000 EntryPoint=0x201020 fixture.efi trailing\n',
                     b'Loading driver at 0x200000 EntryPoint=0x201020 fixture.efi\x00\n']:
            self.rehint(line)
            self.result('DENY')

    def test_exact_profile_binding_and_strict_nested_schema(self):
        for mutate in [lambda p: p['profile'].update(source_commit='c' * 40),
                lambda p: p['prior_hint'].update(profile_sha256='d' * 64),
                lambda p: p.update(extra=1),
                lambda p: p['profile'].update(extra=1),
                lambda p: p['prior_hint'].update(extra=1),
                lambda p: p['profile']['artifacts']['efi'].update(extra=1),
                lambda p: p['profile']['artifacts'].update(extra={}),
                lambda p: p['profile'].update(machine='q35'),
                lambda p: p['profile'].update(cpu='host')]:
            packet = copy.deepcopy(self.packet)
            mutate(packet)
            self.result('DENY', packet)
        self.result('ADMIT')

    def test_boolean_integer_and_out_of_range_fields(self):
        for field, values in [('schema_version', [True, False, 2, 1.0]),
                              ('entry_length', [True, False, 0, -1, 65, 2**64])]:
            for value in values:
                packet = copy.deepcopy(self.packet)
                packet[field] = value
                self.result('DENY', packet)
        for field, values in [('vcpus', [True, False, 0, 2]),
                             ('ram_bytes', [True, -1, 2**64])]:
            for value in values:
                packet = copy.deepcopy(self.packet)
                packet['profile'][field] = value
                self.result('DENY', packet)
        for value in [False, True, -1, 0, 2**64, 2048.0]:
            packet = copy.deepcopy(self.packet)
            packet['profile']['artifacts']['efi']['length'] = value
            self.result('DENY', packet)

    def test_missing_artifact_incomplete_but_existing_bad_hash_denies(self):
        (self.root / 'qemu').unlink()
        self.result('INCOMPLETE')
        (self.root / 'efi').write_bytes(b'bad')
        self.result('DENY')

    def test_missing_efi_does_not_hide_malformed_diagnostic(self):
        (self.root / 'efi').unlink()
        self.result('INCOMPLETE')
        for diagnostic, reason in [
                (b'Loading driver at 0xZZ EntryPoint=0x201020 fixture.efi\n',
                 'malformed_matching_diagnostic'),
                (b'\xff', 'diagnostic_not_ascii'),
                (b'\x00', 'diagnostic_control_byte')]:
            self.rehint(diagnostic)
            self.assertEqual(reason, self.result('DENY')['reason'])

    def test_length_hash_and_path_denials(self):
        for path in ['../efi', '/efi', './efi', 'a//efi', 'a/../efi', 'a\\efi']:
            packet = copy.deepcopy(self.packet)
            packet['profile']['artifacts']['efi']['path'] = path
            self.result('DENY', packet)
        for field, value, reason in [('sha256', 'f' * 64, 'blob_hash_mismatch'),
                                     ('length', 2049, 'blob_length_mismatch')]:
            packet = copy.deepcopy(self.packet)
            packet['profile']['artifacts']['efi'][field] = value
            packet['prior_hint']['profile_sha256'] = subject.profile_digest(packet['profile'])
            self.assertEqual(reason, self.result('DENY', packet)['reason'])
        self.result('ADMIT')

    def test_directory_fifo_and_symlink_deny_before_read(self):
        original = (self.root / 'efi').read_bytes()
        (self.root / 'efi').unlink()
        (self.root / 'efi').mkdir()
        self.result('DENY')
        (self.root / 'efi').rmdir()
        os.mkfifo(self.root / 'efi')
        self.result('DENY')
        (self.root / 'efi').unlink()
        (self.root / 'actual').write_bytes(original)
        (self.root / 'efi').symlink_to(self.root / 'actual')
        self.result('DENY')
        (self.root / 'efi').unlink()
        (self.root / 'efi').write_bytes(original)
        self.result('ADMIT')

    def test_intermediate_symlink_and_external_symlink_denied(self):
        (self.root / 'nested').mkdir()
        (self.root / 'nested' / 'efi').write_bytes((self.root / 'efi').read_bytes())
        packet = copy.deepcopy(self.packet)
        packet['profile']['artifacts']['efi']['path'] = 'nested/efi'
        packet['prior_hint']['profile_sha256'] = subject.profile_digest(packet['profile'])
        self.result('ADMIT', packet)
        (self.root / 'alias').symlink_to(self.root / 'nested', target_is_directory=True)
        packet['profile']['artifacts']['efi']['path'] = 'alias/efi'
        packet['prior_hint']['profile_sha256'] = subject.profile_digest(packet['profile'])
        self.result('DENY', packet)
        (self.root / 'efi').unlink()
        (self.root / 'efi').symlink_to('/etc/passwd')
        self.result('DENY')

    def test_json_duplicate_nonfinite_depth_and_packet_limit(self):
        for text in ['{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}', '{"a":1e999}',
                     '{"a":-Infinity}', '[' * 2000 + ']' * 2000,
                     ' ' * (65536 + 1), '\ufeff{}']:
            with self.assertRaises(subject.AdmissionError):
                subject.decode_packet(text.encode())

    def cli(self, data):
        packet_path = self.root / 'packet.json'
        packet_path.write_bytes(data)
        run = subprocess.run([sys.executable, subject.__file__, '--packet',
            str(packet_path), '--inputs-root', str(self.root)],
            capture_output=True, text=True, timeout=5, check=False)
        return run.returncode, json.loads(run.stdout)

    def test_cli_status_claims_and_next_valid_admission(self):
        for packet, status, code in [(self.packet, 'ADMIT', 0),
                ({**self.packet, 'prior_hint': None}, 'INCOMPLETE', 3),
                ({**self.packet, 'schema_version': True}, 'DENY', 2),
                (self.packet, 'ADMIT', 0)]:
            exit_code, report = self.cli(json.dumps(packet).encode())
            self.assertEqual(code, exit_code)
            self.assertEqual(status, report['status'])
            self.assertTrue(all(v is False for v in report['claims'].values()))
            self.assertIs(report['capture_complete'], False)
        for data in [b'{"schema_version":1,"schema_version":1}',
                     b'{"schema_version":NaN}', b'x' * 65537]:
            code, report = self.cli(data)
            self.assertEqual((2, 'DENY'), (code, report['status']))


if __name__ == '__main__':
    unittest.main()
