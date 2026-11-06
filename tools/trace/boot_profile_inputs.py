#!/usr/bin/env python3
"""Checked RUN0 entry-input subset; no debugger, VM launch or capture decoder.

CLI: boot_profile_inputs.py --packet PACKET --inputs-root DIRECTORY
Exit 0 = ADMIT (prior candidate only), 2 = DENY, 3 = INCOMPLETE.
All relationships beyond the checks below remain unverified. Hashes describe
bytes read by this invocation, not their authenticity or future immutability.

The strict packet has schema_version=1, kind=boot_entry_inputs_v0, profile,
prior_hint (null or the record below), and entry_length (1..64). Profile keys
are defined in validate_packet; artifacts are path/sha256/length references.
The prior hint binds the SHA256 of canonical JSON for the entire profile,
prior_run_id, and diagnostic_ref. The diagnostic retains its original bytes;
only a single exact matching load line supplies a candidate. Invocation and
expanded CPU records are opaque byte pins, not semantic profile validation.

Source definitions (checked 2026-11-05):
https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
  DOS/COFF/PE32+ headers, section mappings and base relocation table.
https://raw.githubusercontent.com/tianocore/edk2/edk2-stable202402/MdeModulePkg/Core/Dxe/Image/Image.c
  lines 825..870: DEBUG load address/entry and PDB-derived module name.
https://raw.githubusercontent.com/tianocore/edk2/edk2-stable202402/MdePkg/Library/BasePeCoffLib/BasePeCoff.c
  lines 1377..1414: only min(VirtualSize, SizeOfRawData) is copied for
  nonzero VirtualSize. This subset rejects zero VirtualSize sections.
These are format references, not evidence that installed OVMF emits the line.
This conservative subset supports ABSOLUTE and DIR64 only, rejects ambiguous
section/relocation layouts and checked-arithmetic wrap, and never masks bytes.
"""

import argparse
from dataclasses import dataclass
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct


U64_MAX = 2**64 - 1
PACKET_LIMIT = 65536
EFI_LIMIT = 16 * 1024 * 1024
CLAIM_NAMES = (
    'guest_access_executed', 'post_exit_verified', 'interrupt_masking_verified',
    'retention_complete', 'allocator_installed', 'target_user_execution',
    'physical_hardware',
)
ARTIFACT_LIMITS = {
    'efi': EFI_LIMIT, 'qemu': 256 * 1024 * 1024, 'gdb': 256 * 1024 * 1024,
    'symbol_tool': 256 * 1024 * 1024, 'symbols': 128 * 1024 * 1024,
    'ovmf_code': EFI_LIMIT, 'initial_vars': EFI_LIMIT, 'init': 4 * 1024 * 1024,
    'esp': 64 * 1024 * 1024, 'expanded_cpu': 65536, 'invocation': 65536,
}


class AdmissionError(ValueError):
    """Present input is malformed, unsupported or inconsistent."""


class UnavailableInput(Exception):
    """Required evidence has not been supplied or cannot be read."""


def require(condition, reason):
    if not condition:
        raise AdmissionError(reason)


def integer(value, low, high, reason):
    require(type(value) is int and low <= value <= high, reason)
    return value


def fields(value, names, reason):
    require(type(value) is dict and set(value) == set(names), reason)


def end(start, length, maximum, reason):
    integer(start, 0, maximum, reason)
    integer(length, 0, maximum, reason)
    require(length <= maximum - start, reason)
    return start + length


def span(data, offset, length):
    stop = end(offset, length, len(data), 'pe_truncated')
    return data[offset:stop]


def number(data, offset, fmt):
    return struct.unpack('<' + fmt, span(data, offset, struct.calcsize(fmt)))[0]


def overlaps(a, b):
    return a[0] < b[1] and b[0] < a[1]


def disjoint(ranges, reason):
    ordered = sorted(ranges)
    require(all(a[1] <= b[0] for a, b in zip(ordered, ordered[1:])), reason)


@dataclass(frozen=True)
class Section:
    rva: int
    size: int
    raw_offset: int
    raw_size: int
    executable: bool


@dataclass(frozen=True)
class PE:
    data: bytes
    image_base: int
    image_size: int
    header_size: int
    entry_rva: int
    entry_file_offset: int
    entry_length: int
    sections: tuple
    relocations: tuple
    relocations_present: bool
    relocations_stripped: bool


def file_offset(sections, rva, length):
    stop = end(rva, length, 2**32 - 1, 'rva_overflow')
    matches = [s for s in sections
               if s.rva <= rva and stop <= s.rva + s.size]
    require(len(matches) == 1, 'rva_mapping_ambiguous_or_missing')
    section = matches[0]
    require(stop <= section.rva + section.raw_size, 'rva_not_file_backed')
    return section.raw_offset + rva - section.rva, section


def parse_pe(data, entry_length=32):
    """Parse a conservative bounded PE32+ AMD64 EFI-application subset."""
    require(type(data) is bytes and 64 <= len(data) <= EFI_LIMIT, 'efi_length')
    integer(entry_length, 1, 64, 'entry_length')
    require(data[:2] == b'MZ', 'dos_signature')
    pe = number(data, 60, 'I')
    require(pe >= 64 and pe % 8 == 0, 'pe_offset')
    require(span(data, pe, 4) == b'PE\0\0', 'pe_signature')
    require(number(data, pe + 4, 'H') == 0x8664, 'pe_machine')
    count = integer(number(data, pe + 6, 'H'), 1, 96, 'section_count')
    optional_size = integer(number(data, pe + 20, 'H'), 112, 240, 'optional_size')
    flags = number(data, pe + 22, 'H')
    require(flags & 2 and not flags & 0x2000, 'not_executable_application')
    opt = pe + 24
    span(data, opt, optional_size)
    require(number(data, opt, 'H') == 0x20B, 'not_pe32_plus')
    require(number(data, opt + 68, 'H') == 10, 'not_efi_application')
    directory_count = integer(number(data, opt + 108, 'I'), 0, 16, 'directory_count')
    require(112 + directory_count * 8 <= optional_size, 'directory_bounds')
    image_base = number(data, opt + 24, 'Q')
    image_size = integer(number(data, opt + 56, 'I'), 1, 64 * 1024 * 1024, 'image_size')
    end(image_base, image_size, U64_MAX, 'preferred_image_overflow')
    require(image_base % 65536 == 0, 'preferred_base_alignment')
    section_align = number(data, opt + 32, 'I')
    file_align = number(data, opt + 36, 'I')
    require(512 <= file_align <= 65536 and file_align & (file_align - 1) == 0,
            'file_alignment')
    require(4096 <= section_align <= 65536 and
            section_align & (section_align - 1) == 0 and section_align >= file_align,
            'section_alignment_unsupported')
    header_size = number(data, opt + 60, 'I')
    section_table = opt + optional_size
    require(section_table + count * 40 <= header_size <= len(data) and
            header_size % file_align == 0 and header_size <= image_size and
            image_size % section_align == 0, 'header_image_bounds')
    sections = []
    virtual_ranges = [(0, (header_size + section_align - 1) // section_align * section_align)]
    raw_ranges = [(0, header_size)]
    for index in range(count):
        item = section_table + index * 40
        virtual_size = number(data, item + 8, 'I')
        rva = number(data, item + 12, 'I')
        raw_size = number(data, item + 16, 'I')
        raw_offset = number(data, item + 20, 'I')
        # Raw file-alignment padding beyond VirtualSize is not copied by the
        # pinned EDK II loader. Never mistake those bytes for entry code.
        size = virtual_size
        require(size > 0 and rva % section_align == 0, 'section_extent')
        mapped_end = end(rva, size, 2**32 - 1, 'section_rva_overflow')
        rounded_end = (mapped_end + section_align - 1) // section_align * section_align
        require(rounded_end <= image_size, 'section_outside_image')
        virtual_ranges.append((rva, rounded_end))
        if raw_size:
            require(raw_offset % file_align == 0 and raw_size % file_align == 0,
                    'section_raw_alignment')
            raw_end = end(raw_offset, raw_size, len(data), 'section_raw_bounds')
            raw_ranges.append((raw_offset, raw_end))
        else:
            require(raw_offset == 0, 'empty_raw_offset')
        sections.append(Section(rva, size, raw_offset, raw_size,
                                bool(number(data, item + 36, 'I') & 0x20000000)))
    disjoint(virtual_ranges, 'overlapping_mapped_sections')
    disjoint(raw_ranges, 'overlapping_raw_sections')
    entry_rva = number(data, opt + 16, 'I')
    entry_offset, entry_section = file_offset(sections, entry_rva, entry_length)
    require(entry_section.executable, 'entry_not_executable')

    relocation_rva, relocation_size = (0, 0)
    if directory_count > 5:
        relocation_rva = number(data, opt + 112 + 5 * 8, 'I')
        relocation_size = number(data, opt + 116 + 5 * 8, 'I')
    require((relocation_rva == 0) == (relocation_size == 0), 'relocation_directory_pair')
    require(relocation_size <= 1024 * 1024, 'relocation_directory_limit')
    relocations = []
    targets = []
    if relocation_size:
        require(relocation_rva % 4 == 0, 'relocation_directory_alignment')
        reloc_offset, _ = file_offset(sections, relocation_rva, relocation_size)
        stop = reloc_offset + relocation_size
        cursor = reloc_offset
        while cursor < stop:
            require(stop - cursor >= 8, 'relocation_header_truncated')
            page = number(data, cursor, 'I')
            block_size = number(data, cursor + 4, 'I')
            require(page % 4096 == 0 and page < image_size, 'relocation_page')
            require(block_size >= 8 and block_size % 4 == 0 and
                    block_size <= stop - cursor, 'relocation_block_size')
            for record in range(cursor + 8, cursor + block_size, 2):
                item = number(data, record, 'H')
                kind, offset = item >> 12, item & 0xFFF
                if kind == 0:  # IMAGE_REL_BASED_ABSOLUTE is padding, not a write.
                    continue
                require(kind == 10, 'unsupported_relocation_type')
                target = end(page, offset, 2**32 - 1, 'relocation_target_overflow')
                target_end = end(target, 8, image_size, 'relocation_target_bounds')
                target_file, _ = file_offset(sections, target, 8)
                require(not overlaps((target, target_end),
                    (relocation_rva, relocation_rva + relocation_size)),
                    'self_modifying_relocation_table')
                targets.append((target, target_end))
                relocations.append((target, target_file))
            cursor += block_size
    disjoint(targets, 'overlapping_relocation_targets')
    return PE(data, image_base, image_size, header_size, entry_rva,
              entry_offset, entry_length, tuple(sections), tuple(relocations),
              bool(relocation_size), bool(flags & 1))


def loaded_extent(base, size):
    integer(base, 0, U64_MAX, 'loaded_base')
    stop = end(base, size, U64_MAX, 'loaded_image_overflow')
    require(base % 4096 == 0, 'loaded_base_alignment')
    require(stop <= 2**47 or base >= 2**64 - 2**47,
            'loaded_image_noncanonical')
    return stop


def expected_entry(pe, loaded_base):
    """Expected bounded input bytes after DIR64 relocations; no live reads."""
    loaded_extent(loaded_base, pe.image_size)
    delta = loaded_base - pe.image_base
    if delta:
        require(pe.relocations_present and not pe.relocations_stripped,
                'changed_base_without_relocations')
    entry_end = end(pe.entry_rva, pe.entry_length, pe.image_size, 'entry_bounds')
    end(loaded_base, entry_end, U64_MAX, 'loaded_entry_overflow')
    sample = bytearray(pe.data[pe.entry_file_offset:pe.entry_file_offset + pe.entry_length])
    for target, file_pos in pe.relocations:
        value = number(pe.data, file_pos, 'Q') + delta
        integer(value, 0, U64_MAX, 'relocation_value_overflow')
        first, last = max(target, pe.entry_rva), min(target + 8, entry_end)
        if first < last:
            patched = value.to_bytes(8, 'little')
            sample[first - pe.entry_rva:last - pe.entry_rva] = patched[first - target:last - target]
    return bytes(sample)


def sha(value, reason):
    require(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), reason)


def validate_ref(ref, limit):
    fields(ref, ('path', 'sha256', 'length'), 'blob_fields')
    path = ref['path']
    require(type(path) is str and 1 <= len(path) <= 240 and
            re.fullmatch('[A-Za-z0-9._/-]+', path) and
            all(part not in ('', '.', '..') for part in path.split('/')),
            'blob_path')
    sha(ref['sha256'], 'blob_sha256')
    integer(ref['length'], 1, limit, 'blob_length')


def validate_packet(packet):
    fields(packet, ('schema_version', 'kind', 'profile', 'prior_hint', 'entry_length'),
           'packet_fields')
    integer(packet['schema_version'], 1, 1, 'schema_version')
    require(packet['kind'] == 'boot_entry_inputs_v0', 'packet_kind')
    integer(packet['entry_length'], 1, 64, 'entry_length')
    profile = packet['profile']
    fields(profile, ('source_commit', 'assembled_patch_sha256', 'machine',
        'accelerator', 'cpu', 'vcpus', 'ram_bytes', 'diagnostic_image_name', 'artifacts'),
        'profile_fields')
    require(type(profile['source_commit']) is str and
            re.fullmatch('[0-9a-f]{40}', profile['source_commit']), 'source_commit')
    sha(profile['assembled_patch_sha256'], 'assembled_patch_sha256')
    require(type(profile['machine']) is str and
            profile['machine'] in ('pc-q35-8.2', 'pc-q35-8.2,sata=off'), 'unsupported_machine')
    for key, expected in [('accelerator', 'tcg'), ('cpu', 'qemu64')]:
        require(profile[key] == expected, 'unsupported_' + key)
    integer(profile['vcpus'], 1, 1, 'vcpus')
    integer(profile['ram_bytes'], 512 * 1024 * 1024, 512 * 1024 * 1024, 'ram_bytes')
    require(type(profile['diagnostic_image_name']) is str and
            re.fullmatch(r'[A-Za-z0-9_-]{1,120}\.efi', profile['diagnostic_image_name']),
            'diagnostic_image_name')
    fields(profile['artifacts'], ARTIFACT_LIMITS, 'artifact_fields')
    for name, limit in ARTIFACT_LIMITS.items():
        validate_ref(profile['artifacts'][name], limit)
    hint = packet['prior_hint']
    if hint is not None:
        fields(hint, ('prior_run_id', 'profile_sha256', 'diagnostic_ref'), 'hint_fields')
        require(type(hint['prior_run_id']) is str and
                re.fullmatch('[a-z0-9-]{1,64}', hint['prior_run_id']), 'prior_run_id')
        sha(hint['profile_sha256'], 'hint_profile_sha256')
        validate_ref(hint['diagnostic_ref'], 65536)
        require(hint['profile_sha256'] == profile_digest(profile), 'hint_profile_mismatch')


def profile_digest(profile):
    return hashlib.sha256(json.dumps(profile, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def reject_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate_json_key')
        result[key] = value
    return result


def reject_constant(_):
    raise AdmissionError('nonfinite_json_number')


def decode_packet(data):
    require(type(data) is bytes and 0 < len(data) <= PACKET_LIMIT, 'packet_length')
    try:
        value = json.loads(data.decode('utf-8'), object_pairs_hook=reject_pairs,
                           parse_constant=reject_constant, parse_float=reject_constant)
        pending = [(value, 0)]
        nodes = 0
        while pending:
            current, depth = pending.pop()
            nodes += 1
            require(depth <= 16 and nodes <= 4096, 'json_structure_limit')
            children = current.values() if type(current) is dict else current if type(current) is list else ()
            pending.extend((child, depth + 1) for child in children)
        return value
    except (ValueError, UnicodeError, RecursionError) as error:
        raise AdmissionError('invalid_json') from error


def io_failure(error):
    if error.errno in (errno.ELOOP, errno.ENOTDIR, errno.EISDIR):
        raise AdmissionError('symlink_or_nondirectory_input') from error
    raise UnavailableInput('input_unavailable') from error


def read_fd(fd, limit, retain):
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode), 'input_not_regular_file')
        require(0 < info.st_size <= limit, 'input_file_length')
    except BaseException:
        os.close(fd)
        raise
    with os.fdopen(fd, 'rb') as stream:
        digest, size, chunks = hashlib.sha256(), 0, []
        while True:
            chunk = stream.read(min(1024 * 1024, limit + 1 - size))
            if not chunk:
                break
            size += len(chunk)
            require(size <= limit, 'input_file_limit')
            digest.update(chunk)
            if retain:
                chunks.append(chunk)
        require(size == info.st_size, 'input_changed_length')
        return digest.hexdigest(), size, b''.join(chunks) if retain else None


def read_blob(root, ref, limit, retain=False):
    """Traverse relative components without following links; reject FIFOs before read."""
    validate_ref(ref, limit)
    directory = None
    try:
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parts = ref['path'].split('/')
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=directory)
        digest, size, data = read_fd(fd, limit, retain)
        require(size == ref['length'], 'blob_length_mismatch')
        require(digest == ref['sha256'], 'blob_hash_mismatch')
        return data
    except OSError as error:
        io_failure(error)
    finally:
        if directory is not None:
            os.close(directory)


def parse_diagnostic(data, image_name):
    """Validate retained line syntax even when its EFI dependency is missing."""
    try:
        text = data.decode('ascii')
    except UnicodeError as error:
        raise AdmissionError('diagnostic_not_ascii') from error
    require(all(ch in '\r\n\t' or ' ' <= ch <= '~' for ch in text),
            'diagnostic_control_byte')
    pattern = re.compile(r'Loading driver at 0x[ ]*([0-9a-fA-F]{1,16}) '
        r'EntryPoint=0x[ ]*([0-9a-fA-F]{1,16}) ' + re.escape(image_name))
    matches = []
    for line_number, line in enumerate(text.splitlines(), 1):
        match = pattern.fullmatch(line)
        if match:
            matches.append((line_number, int(match[1], 16), int(match[2], 16)))
        elif line.startswith('Loading driver at ') and image_name in line:
            raise AdmissionError('malformed_matching_diagnostic')
    if len(matches) != 1:
        raise UnavailableInput('diagnostic_missing_or_ambiguous')
    return matches[0]


def diagnostic_candidate(parsed, pe):
    line_number, base, address = parsed
    loaded_extent(base, pe.image_size)
    expected_address = end(base, pe.entry_rva, U64_MAX, 'loaded_entry_overflow')
    require(address == expected_address, 'diagnostic_entry_mismatch')
    return {'scope': 'prior-run-hint-only', 'loaded_base': base,
            'entry_address': address, 'diagnostic_line': line_number,
            'expected_entry_hex': expected_entry(pe, base).hex()}


def report(status, reason):
    return {'schema_version': 1, 'kind': 'boot_entry_input_admission_v0',
            'status': status, 'reason': reason, 'capture_complete': False,
            'profile_preconditions_met': False, 'fresh_c0_verified': False,
            'opaque_profile_semantics_verified': False, 'symbols_match_verified': False,
            'esp_efi_binding_verified': False,
            'claims': {name: False for name in CLAIM_NAMES}}


def admit(packet, inputs_root):
    """Read supplied artifacts and admit at most one prior hint, with no side effects."""
    try:
        validate_packet(packet)
        profile = packet['profile']
        missing, blobs = [], {}
        for name, limit in ARTIFACT_LIMITS.items():
            try:
                blobs[name] = read_blob(inputs_root, profile['artifacts'][name],
                                        limit, retain=name == 'efi')
            except UnavailableInput:
                missing.append(name)
        pe = parse_pe(blobs['efi'], packet['entry_length']) if 'efi' in blobs else None
        hint = packet['prior_hint']
        diagnostic = None
        if hint is None:
            missing.append('prior_hint')
        else:
            try:
                diagnostic = read_blob(inputs_root, hint['diagnostic_ref'], 65536, True)
            except UnavailableInput:
                missing.append('diagnostic')
        parsed = None
        if diagnostic is not None:
            try:
                parsed = parse_diagnostic(diagnostic, profile['diagnostic_image_name'])
            except UnavailableInput as error:
                missing.append(str(error))
        candidate = diagnostic_candidate(parsed, pe) if pe is not None and parsed is not None else None
        if missing:
            result = report('INCOMPLETE', 'required_inputs_unavailable')
            result['missing'] = missing
            return result
        result = report('ADMIT', 'prior_candidate_inputs_checked')
        result['profile_sha256'] = profile_digest(profile)
        result['pe'] = {name: getattr(pe, name) for name in
            ('image_base', 'image_size', 'header_size', 'entry_rva', 'entry_file_offset', 'entry_length')}
        result['candidate'] = {**candidate, 'prior_run_id': hint['prior_run_id'],
                               'diagnostic_ref': dict(hint['diagnostic_ref'])}
        return result
    except AdmissionError as error:
        return report('DENY', str(error))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--packet', type=Path, required=True)
    parser.add_argument('--inputs-root', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        try:
            fd = os.open(args.packet, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            _, _, data = read_fd(fd, PACKET_LIMIT, True)
        except OSError as error:
            io_failure(error)
        result = admit(decode_packet(data), args.inputs_root)
    except AdmissionError as error:
        result = report('DENY', str(error))
    except UnavailableInput as error:
        result = report('INCOMPLETE', str(error))
    print(json.dumps(result, sort_keys=True, indent=2))
    return {'ADMIT': 0, 'DENY': 2, 'INCOMPLETE': 3}[result['status']]


if __name__ == '__main__':
    raise SystemExit(main())
