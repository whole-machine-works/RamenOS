#!/usr/bin/env python3
"""Fixed RUN0 host metadata/field workers; no QEMU launch or general reader.

The parent owns process/source identity, private proc opens and all supervision.
An inherited O_RDONLY descriptor is wider authority than these trusted workers'
finite read policy. Fixture success is not a QEMU or C0 observation.
"""
import argparse
import ctypes
from dataclasses import dataclass
import errno
import fcntl
import hashlib
import json
import os
import platform
import re
import select
import stat
import struct
import sys
import time

from boot_profile_capture import ProbeError


U64 = (1 << 64) - 1
PAGE = 4096
MAX_ROWS = 1024
MAP_LIMIT = 131072
SMAP_LIMIT = 1048576
MOUNT_LIMIT = 262144
EXE_LIMIT = 67108864
META_LIMIT = 1572864
FIELD_INPUT = 8192
FIELD_OUTPUT = 16384
SECONDS_NS = 5_000_000_000
QUEUE = 0x17ddad0
GENERATION = 0x1930b64
CPU_BYTES = 25888
NODE, INDEX, TID, HFLAGS, HFLAGS2 = 0x238, 0x2c8, 0xb8, 0x2870, 0x2874
REQUIRED_FLAGS = frozenset(('rd', 'wr', 'mr', 'mw', 'me', 'ac', 'sd'))
ALLOWED_FLAGS = REQUIRED_FLAGS | {'hg', 'nh'}
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
MAP_LINE = re.compile(r'([0-9a-f]+)-([0-9a-f]+) ([r-][w-][x-][ps]) '
                      r'([0-9a-f]+) ([0-9a-f]+):([0-9a-f]+) ([0-9]+)(?: +(.*))?\Z')
GRANT_KEYS = {'start', 'end', 'category', 'permissions', 'offset', 'dev_major',
              'dev_minor', 'inode', 'path', 'vm_flags', 'maps_row', 'smaps_row',
              'metadata_sha256'}
EXE_KEYS = {'device', 'inode', 'size', 'sha256', 'build_id', 'elf_class',
            'elf_machine', 'mount_fstype', 'statfs_magic'}

# Canonical exact ABI subsection of the independently reviewed contract.
ABI = {
    'pointer_bytes': 8, 'word_bytes': 4, 'endian': 'little',
    'cpus_queue_rva': '0x17ddad0', 'generation_rva': '0x1930b64',
    'generation_binding': 'exact installed cpu_list_generation_id_get@0x470890 RIP-relative load, not optimized-away DWARF address',
    'queue_bytes': 16, 'X86CPU_bytes': 25888, 'CPUState_bytes': 10176,
    'parent_offset': 0, 'env_offset': '0x27c0', 'node_offset': '0x238',
    'cpu_index_offset': '0x2c8', 'thread_id_offset': '0xb8',
    'hflags_offset': '0x2870', 'hflags2_offset': '0x2874',
    'masks': {'NPT': 'hflags2 bit6', 'SMM': 'hflags bit19', 'GUEST': 'hflags bit21',
              'CPL': 'hflags&3', 'LMA': 'hflags bit14', 'CS64': 'hflags bit15'},
    'queue_rule': 'QTAILQ union/circular-prev: head.first=CPU;head.prev=CPU+0x238;CPU.node.next=0;CPU.node.prev=head. No conventional tqh_last assumption.',
}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode()


ABI_SHA256 = hashlib.sha256(canonical(ABI)).hexdigest()


class ReaderError(ProbeError):
    pass


def require(value, reason, status='DENY'):
    if not value:
        raise ReaderError(status, reason)


def integer(value, low=0, high=U64):
    return type(value) is int and low <= value <= high


def linux_device(value):
    """Decode retained Linux/glibc dev_t, independent of the review host.

    Pinned bits/sysmacros.h SHA256
    ce4b410a5c1bb6b412025a9e7ef1da880c8ef802530660d7b43638ab7f36ac8a.
    """
    require(integer(value), 'linux_device')
    major = ((value & 0x00000000000fff00) >> 8) | ((value & 0xfffff00000000000) >> 32)
    minor = (value & 0x00000000000000ff) | ((value & 0x00000ffffff00000) >> 12)
    return major, minor


def end(start, length, bound=U64):
    require(integer(start, 0, bound) and integer(length, 0, bound) and
            length <= bound - start, 'span_overflow')
    return start + length


def chunk(data, start, length):
    return data[start:end(start, length, len(data))]


def fields(value, keys, reason):
    require(type(value) is dict and set(value) == set(keys), reason)


def strict_json(data, limit):
    require(type(data) is bytes and len(data) <= limit, 'json_limit')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'json_duplicate')
            result[key] = value
        return result
    def constant(_):
        raise ReaderError('DENY', 'json_nonfinite')
    try:
        return json.loads(data.decode('utf-8'), object_pairs_hook=pairs,
                          parse_constant=constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, ReaderError):
            raise
        raise ReaderError('DENY', 'json_syntax') from exc


def text(data, limit, reason):
    require(type(data) is bytes and len(data) <= limit and b'\0' not in data, reason)
    try:
        result = data.decode('ascii')
    except UnicodeError as exc:
        raise ReaderError('DENY', reason) from exc
    require(all(c in '\n\t' or ' ' <= c <= '~' for c in result), reason)
    return result


@dataclass(frozen=True)
class Load:
    offset: int
    vaddr: int
    filesz: int
    memsz: int
    flags: int


@dataclass(frozen=True)
class ELFImage:
    sha256: str
    size: int
    build_id: str
    loads: tuple


@dataclass(frozen=True)
class HostABI:
    elf: ELFImage
    source_sha256: str


def _elf(prefix, total, digest):
    require(integer(total, 64, EXE_LIMIT) and len(prefix) >= 64, 'elf_header')
    require(prefix[:7] == b'\x7fELF\x02\x01\x01', 'elf_header')
    typ, machine, version, _, phoff, _, _, hsize, psize, count, _, _, _ = \
        struct.unpack_from('<HHIQQQIHHHHHH', prefix, 16)
    require((typ, machine, version, hsize, psize) == (3, 62, 1, 64, 56)
            and 1 <= count <= 128, 'elf_header')
    require(end(phoff, count * 56, total) <= len(prefix), 'elf_phdr')
    loads, build_ids = [], []
    for index in range(count):
        kind, flags, offset, address, _, filesz, memsz, align = \
            struct.unpack_from('<IIQQQQQQ', prefix, phoff + index * 56)
        end(offset, filesz, total)
        end(address, memsz)
        if kind == 1:
            require(flags <= 7 and 0 < memsz and filesz <= memsz and align == PAGE
                    and offset % PAGE == address % PAGE, 'elf_load')
            loads.append(Load(offset, address, filesz, memsz, flags))
        elif kind == 4:
            require(filesz <= 65536 and end(offset, filesz) <= len(prefix),
                    'elf_note_prefix', 'INCOMPLETE')
            cursor, stop, notes = offset, offset + filesz, 0
            while cursor < stop:
                require(cursor + 12 <= stop and notes < 512, 'elf_notes')
                namesz, descsz, note_type = struct.unpack_from('<III', prefix, cursor)
                cursor += 12; notes += 1
                name = chunk(prefix, cursor, namesz)
                cursor = end(cursor, (namesz + 3) & ~3, stop)
                value = chunk(prefix, cursor, descsz)
                cursor = end(cursor, (descsz + 3) & ~3, stop)
                if name == b'GNU\0' and note_type == 3:
                    require(descsz == 20, 'elf_build_id')
                    build_ids.append(value.hex())
    require(loads and len(build_ids) == 1, 'elf_build_id')
    ordered = sorted(loads, key=lambda x: x.vaddr)
    require(all(a.vaddr + a.memsz <= b.vaddr for a, b in zip(ordered, ordered[1:])),
            'elf_load_overlap')
    return ELFImage(digest, total, build_ids[0], tuple(loads))


def parse_elf(data):
    require(type(data) is bytes and len(data) <= EXE_LIMIT, 'elf_limit')
    return _elf(data, len(data), hashlib.sha256(data).hexdigest())


def validate_exe(exe):
    fields(exe, EXE_KEYS, 'exe_shape')
    require(integer(exe['device']) and integer(exe['inode'], 1) and
            integer(exe['size'], 64, EXE_LIMIT) and type(exe['sha256']) is str and
            HEX64.fullmatch(exe['sha256']) and type(exe['build_id']) is str and
            re.fullmatch('[0-9a-f]{40}', exe['build_id']) and
            type(exe['elf_class']) is int and exe['elf_class'] == 64 and
            type(exe['elf_machine']) is int and exe['elf_machine'] == 62,
            'exe_identity')
    require(exe['mount_fstype'] == 'ext4' and exe['statfs_magic'] == '0xef53',
            'exe_filesystem', 'INCOMPLETE')


@dataclass(frozen=True)
class MapRow:
    start: int
    end: int
    permissions: str
    offset: int
    dev_major: int
    dev_minor: int
    inode: int
    path: str
    vm_flags: tuple = ()
    maps_row: int = 0
    smaps_row: int = 0

    def key(self):
        return (self.start, self.end, self.permissions, self.offset,
                self.dev_major, self.dev_minor, self.inode, self.path)


@dataclass(frozen=True)
class HostMapSet:
    rows: tuple
    global_maps: tuple
    load_bias: int
    metadata_sha256: str


def _map_line(line):
    match = MAP_LINE.fullmatch(line)
    require(match is not None, 'map_syntax')
    a, b, permissions, offset, major, minor, inode, path = match.groups()
    require(all(len(x) <= 16 for x in (a,b,offset)) and
            len(major) <= 8 and len(minor) <= 8 and len(inode) <= 20, 'map_range')
    values = [int(x, 16) for x in (a, b, offset, major, minor)]
    start, stop, off, maj, minr = values
    require(all(integer(x) for x in values) and integer(int(inode)) and
            start < stop and start % PAGE == stop % PAGE == off % PAGE == 0,
            'map_range')
    return MapRow(start, stop, permissions, off, maj, minr, int(inode), path or '')


def parse_maps_smaps(raw_maps, raw_smaps):
    lines = text(raw_maps, MAP_LIMIT, 'maps_limit').splitlines()
    require(0 < len(lines) <= MAX_ROWS, 'map_count')
    rows = [_map_line(line) for line in lines]
    require(all(a.end <= b.start for a, b in zip(rows, rows[1:])), 'map_overlap')
    sections, current, flags = {}, None, None
    def finish():
        if current is not None:
            require(flags is not None and current.key() not in sections, 'smaps_identity')
            sections[current.key()] = (tuple(sorted(flags)), len(sections))
    for line in text(raw_smaps, SMAP_LIMIT, 'smaps_limit').splitlines():
        if MAP_LINE.fullmatch(line):
            finish(); current, flags = _map_line(line), None
            require(len(sections) < MAX_ROWS, 'map_count')
        else:
            require(current is not None, 'smaps_header')
            if line.startswith('VmFlags:'):
                require(flags is None, 'smaps_flags')
                flags = line[8:].split()
                require(len(flags) <= 64 and len(set(flags)) == len(flags) and
                        all(re.fullmatch('[a-z]{2}', f) for f in flags), 'smaps_flags')
            else:
                require(re.fullmatch('[A-Za-z_][A-Za-z_0-9]*: *[0-9]+(?: kB)?', line),
                        'smaps_line')
    finish()
    require(len(sections) == len(rows) and all(x.key() in sections for x in rows),
            'smaps_identity')
    return tuple(MapRow(*x.key(), sections[x.key()][0], i, sections[x.key()][1])
                 for i, x in enumerate(rows))


def _ordinary(row):
    require(row.permissions == 'rw-p', 'map_permissions', 'INCOMPLETE')
    flags = set(row.vm_flags)
    require(REQUIRED_FLAGS <= flags <= ALLOWED_FLAGS and not {'hg', 'nh'} <= flags,
            'map_flags_unsupported', 'INCOMPLETE')
    require('\\' not in row.path and not row.path.endswith(' (deleted)'), 'map_path')


def _grant(row, category, digest):
    _ordinary(row)
    return dict(start=row.start, end=row.end, category=category,
                permissions=row.permissions, offset=row.offset, dev_major=row.dev_major,
                dev_minor=row.dev_minor, inode=row.inode, path=row.path,
                vm_flags=list(row.vm_flags), maps_row=row.maps_row, smaps_row=row.smaps_row,
                metadata_sha256=digest)


def validate_grant(grant, category=None):
    fields(grant, GRANT_KEYS, 'grant_shape')
    for key in ('start', 'end', 'offset', 'dev_major', 'dev_minor', 'inode', 'maps_row', 'smaps_row'):
        require(integer(grant[key]), 'grant_integer')
    require(grant['dev_major'] <= 2**32-1 and grant['dev_minor'] <= 2**32-1,
            'grant_integer')
    require(grant['start'] < grant['end'] and
            grant['start'] % PAGE == grant['end'] % PAGE == grant['offset'] % PAGE == 0 and
            grant['maps_row'] < MAX_ROWS and grant['smaps_row'] < MAX_ROWS,
            'grant_range')
    require(type(grant['path']) is str and len(grant['path']) <= 4096 and
            all(' ' <= c <= '~' for c in grant['path']) and
            type(grant['vm_flags']) is list and all(type(x) is str for x in grant['vm_flags'])
            and grant['vm_flags'] == sorted(set(grant['vm_flags'])), 'grant_flags')
    require(type(grant['metadata_sha256']) is str and HEX64.fullmatch(grant['metadata_sha256']),
            'grant_digest')
    require(grant['category'] in ('elf_data', 'elf_bss', 'cpu_allocation') and
            (category is None or grant['category'] == category), 'grant_category')
    row = MapRow(*(grant[k] for k in ('start', 'end', 'permissions', 'offset', 'dev_major',
                                     'dev_minor', 'inode', 'path')), tuple(grant['vm_flags']))
    _ordinary(row)
    if grant['category'] in ('elf_bss', 'cpu_allocation'):
        allowed_paths = ('', '[heap]') if grant['category'] == 'cpu_allocation' else ('',)
        require(grant['dev_major'] == grant['dev_minor'] == grant['inode'] == grant['offset'] == 0
                and grant['path'] in allowed_paths, 'grant_anonymous')
    else:
        require(grant['inode'] > 0 and grant['path'].startswith('/'), 'grant_file')


def _floor(x):
    return x & ~(PAGE - 1)


def _ceil(x):
    return end(x, PAGE - 1) & ~(PAGE - 1)


def _abi(abi):
    require(type(abi) is HostABI and type(abi.elf) is ELFImage and
            abi.source_sha256 == ABI_SHA256, 'abi_identity')


def admit_host_maps(raw_maps, raw_smaps, exe, abi):
    _abi(abi); validate_exe(exe)
    require((exe['sha256'], exe['size'], exe['build_id']) ==
            (abi.elf.sha256, abi.elf.size, abi.elf.build_id), 'elf_identity')
    rows = parse_maps_smaps(raw_maps, raw_smaps)
    digest = hashlib.sha256(raw_maps + b'\0' + raw_smaps).hexdigest()
    major, minor = linux_device(exe['device'])
    file_rows = [r for r in rows if (r.dev_major, r.dev_minor, r.inode) ==
                 (major, minor, exe['inode'])]
    require(file_rows, 'exe_mapping_missing', 'INCOMPLETE')
    candidates = None
    for row in file_rows:
        possible = set()
        for seg in abi.elf.loads:
            if _floor(seg.offset) <= row.offset < _ceil(seg.offset + seg.filesz):
                logical = _floor(seg.vaddr) + row.offset - _floor(seg.offset)
                if row.start >= logical:
                    bias = row.start - logical
                    if bias % PAGE == 0 and row.end <= end(bias, _ceil(seg.vaddr + seg.filesz)):
                        possible.add(bias)
        candidates = possible if candidates is None else candidates & possible
    require(candidates is not None and len(candidates) == 1, 'elf_load_bias')
    bias = candidates.pop()
    grants = []
    for rva, size in ((QUEUE, 16), (GENERATION, 4)):
        start, stop = end(bias, rva), end(end(bias, rva), size)
        segments = [s for s in abi.elf.loads if s.vaddr <= rva and
                    end(rva, size) <= s.vaddr + s.memsz and s.flags == 6]
        require(len(segments) == 1, 'global_segment')
        seg = segments[0]
        matched = [r for r in rows if r.start <= start and stop <= r.end]
        require(len(matched) == 1, 'global_mapping_missing', 'INCOMPLETE')
        row = matched[0]
        if row in file_rows:
            require(row.offset + start - row.start == seg.offset + rva - seg.vaddr and
                    stop <= bias + _ceil(seg.vaddr + seg.filesz), 'global_file_offset')
            category = 'elf_data'
        else:
            require(row.start == bias + _ceil(seg.vaddr + seg.filesz) and
                    row.end <= bias + _ceil(seg.vaddr + seg.memsz), 'global_bss_extent')
            category = 'elf_bss'
        grant = _grant(row, category, digest); validate_grant(grant)
        if grant not in grants:
            grants.append(grant)
    return HostMapSet(rows, tuple(grants), bias, digest)


def admit_cpu(head, maps, abi):
    _abi(abi)
    require(type(head) is bytes and len(head) == 16 and type(maps) is HostMapSet,
            'head_shape')
    cpu, prev = struct.unpack('<QQ', head)
    require(cpu != 0 and cpu % 8 == 0, 'cpu_pointer')
    stop = end(cpu, CPU_BYTES)
    require(prev == end(cpu, NODE), 'queue_head')
    rows = [r for r in maps.rows if r.start <= cpu and stop <= r.end]
    require(len(rows) == 1, 'cpu_mapping_missing', 'INCOMPLETE')
    grant = _grant(rows[0], 'cpu_allocation', maps.metadata_sha256)
    validate_grant(grant, 'cpu_allocation')
    return grant


def _unescape_mount(value):
    require(not re.search(r'\\(?![0-7]{3})', value), 'mount_escape')
    return re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), value)


def _mounts(raw):
    lines = text(raw, MOUNT_LIMIT, 'mountinfo_limit').splitlines()
    require(0 < len(lines) <= 2048, 'mountinfo_count')
    result, ids = [], set()
    for line in lines:
        tokens = line.split(' ')
        require(all(tokens) and tokens.count('-') == 1, 'mountinfo_syntax')
        split = tokens.index('-')
        require(split >= 6 and len(tokens) == split + 4 and
                all(x.isdigit() and len(x)<=20 for x in tokens[:2]) and tokens[0] not in ids,
                'mountinfo_syntax')
        ids.add(tokens[0])
        device = tokens[2].split(':')
        require(len(device) == 2 and all(x.isdigit() and len(x)<=10 for x in device)
                and all(int(x)<=2**32-1 for x in device), 'mount_device')
        point = _unescape_mount(tokens[4])
        require(point.startswith('/') and '..' not in point.split('/') and
                all(' ' <= c <= '~' for c in point), 'mount_path')
        result.append((int(device[0]), int(device[1]), point, tokens[split+1]))
    return result


def _mount_type(raw, device):
    types = {kind for major, minor, _, kind in _mounts(raw)
             if (major, minor) == linux_device(device)}
    require(types == {'ext4'}, 'mount_type', 'INCOMPLETE')
    return 'ext4'


def bind_mount_path(raw_mountinfo, launch_path, exe):
    validate_exe(exe)
    require(type(launch_path) is str and launch_path.startswith('/') and
            not any(c in ('','.','..') for c in launch_path.split('/')[1:]) and
            '\\' not in launch_path and all(' ' <= c <= '~' for c in launch_path),
            'launch_path')
    candidates = [x for x in _mounts(raw_mountinfo) if x[2] == '/' or
                  launch_path == x[2] or launch_path.startswith(x[2].rstrip('/') + '/')]
    require(candidates, 'mount_path_missing', 'INCOMPLETE')
    depth = max(len(x[2]) for x in candidates)
    winners = [x for x in candidates if len(x[2]) == depth]
    require(len(winners) == 1, 'mount_path_ambiguous')
    major, minor, _, kind = winners[0]
    require((major, minor) == linux_device(exe['device']) and
            kind == 'ext4', 'mount_path_identity')


def parse_stat(raw):
    value = text(raw, 4096, 'stat_limit').strip()
    left, right = value.find(' ('), value.rfind(') ')
    require(left > 0 and right > left and value[:left].isdigit(), 'stat_syntax')
    tail = value[right+2:].split()
    require(len(tail) >= 20 and len(tail[0]) == 1 and
            len(value[:left])<=10 and tail[1].isdigit() and len(tail[1])<=10 and
            tail[19].isdigit() and len(tail[19])<=20, 'stat_syntax')
    result = dict(pid=int(value[:left]), ppid=int(tail[1]), starttime_ticks=int(tail[19]))
    require(integer(result['pid'], 1, 2**31-1) and integer(result['ppid'], 1, 2**31-1)
            and integer(result['starttime_ticks']), 'stat_identity')
    return result


def parse_metadata_output(raw):
    require(type(raw) is bytes and len(raw) <= META_LIMIT, 'metadata_output_limit')
    result, offset = {}, 0
    for role, cap in (('stat',4096), ('maps',MAP_LIMIT), ('smaps',SMAP_LIMIT),
                      ('mountinfo',MOUNT_LIMIT), ('exe',4096)):
        require(offset + 4 <= len(raw), 'metadata_frame')
        size, = struct.unpack_from('>I', raw, offset); offset += 4
        require(0 < size <= cap and size <= len(raw) - offset, 'metadata_frame')
        result[role] = raw[offset:offset+size]; offset += size
    require(offset == len(raw), 'metadata_trailing')
    result['exe'] = strict_json(result['exe'], 4096)
    validate_exe(result['exe'])
    return result


def metadata_consistent(before, after, grants):
    require(type(before) is dict and type(after) is dict and
            set(before) == set(after) == {'stat','maps','smaps','mountinfo','exe'},
            'metadata_shape')
    validate_exe(before['exe']); validate_exe(after['exe'])
    require(parse_stat(before['stat']) == parse_stat(after['stat']) and
            before['exe'] == after['exe'], 'process_changed', 'INCOMPLETE')
    first = parse_maps_smaps(before['maps'], before['smaps'])
    second = parse_maps_smaps(after['maps'], after['smaps'])
    require(tuple(r.key() for r in first) == tuple(r.key() for r in second),
            'maps_changed', 'INCOMPLETE')
    require(1 <= len(grants) <= 3, 'grant_count')
    digest = hashlib.sha256(before['maps'] + b'\0' + before['smaps']).hexdigest()
    for grant in grants:
        validate_grant(grant)
        a = [r for r in first if r.start == grant['start'] and r.end == grant['end']]
        b = [r for r in second if r.start == grant['start'] and r.end == grant['end']]
        require(len(a) == len(b) == 1 and list(a[0].vm_flags) == grant['vm_flags'] and
                a[0].vm_flags == b[0].vm_flags, 'map_flags_changed', 'INCOMPLETE')
        require(_grant(a[0],grant['category'],digest) == grant, 'grant_metadata_identity')
        _ordinary(b[0])


def _remaining(deadline):
    left = deadline - time.monotonic_ns()
    require(left > 0, 'reader_deadline', 'INCOMPLETE')
    return left / 1e9


def _deadline(value):
    require(integer(value, 1, (1 << 63)-1) and value <= time.monotonic_ns() + SECONDS_NS,
            'deadline_bound')
    _remaining(value)
    return value


def _fd(fd, access, regular=False):
    require(integer(fd, 0, (1 << 31)-1), 'fd_number')
    try:
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        info = os.fstat(fd)
    except OSError as exc:
        raise ReaderError('INCOMPLETE', 'fd_unavailable') from exc
    require(flags & os.O_ACCMODE == access, 'fd_access')
    require(stat.S_ISREG(info.st_mode) if regular else stat.S_ISFIFO(info.st_mode), 'fd_kind')
    return info


def _write(fd, data, deadline):
    position = 0
    while position < len(data):
        remaining = _remaining(deadline)
        try:
            count = os.write(fd, data[position:])
            require(count > 0, 'output_eof', 'INCOMPLETE')
            position += count
        except (BlockingIOError, InterruptedError):
            select.select([], [fd], [], remaining)
        except OSError as exc:
            raise ReaderError('INCOMPLETE', 'output_error') from exc


class _Output:
    def __init__(self, fd, deadline, cap):
        _fd(fd, os.O_WRONLY)
        os.set_blocking(fd, False)
        self.fd, self.deadline, self.cap, self.used = fd, deadline, cap, 0

    def bytes(self, data):
        require(len(data) <= self.cap - self.used, 'output_limit', 'INCOMPLETE')
        self.used += len(data)
        _write(self.fd, data, self.deadline)

    def row(self, value):
        self.bytes(canonical(value) + b'\n')


class _Input:
    def __init__(self, fd):
        _fd(fd, os.O_RDONLY)
        os.set_blocking(fd, False)
        self.fd, self.buffer, self.total = fd, bytearray(), 0

    def _read(self, deadline):
        require(self.total < FIELD_INPUT, 'field_input_limit')
        while True:
            _remaining(deadline)
            try:
                data = os.read(self.fd, min(4096, FIELD_INPUT - self.total))
                break
            except InterruptedError:
                continue
            except BlockingIOError:
                return None
            except OSError as exc:
                raise ReaderError('INCOMPLETE', 'field_input_error') from exc
        require(data, 'field_cancelled', 'INCOMPLETE')
        self.total += len(data)
        return data

    def frame(self, deadline):
        while b'\n' not in self.buffer:
            remaining = _remaining(deadline)
            data = self._read(deadline)
            if data is None:
                select.select([self.fd], [], [], remaining)
            else:
                self.buffer.extend(data)
        line, rest = bytes(self.buffer).split(b'\n', 1)
        self.buffer = bytearray(rest)
        return strict_json(line, FIELD_INPUT)

    def check(self, deadline):
        _remaining(deadline)
        require(not self.buffer, 'unexpected_input')
        require(self._read(deadline) is None, 'unexpected_input')


def _within(grant, address, length):
    require(grant['start'] <= address and end(address, length) <= grant['end'],
            'read_outside_grant')
    require(address <= (1<<63)-1 and length <= (1<<63)-1-address,
            'host_offset_unsupported', 'INCOMPLETE')


def _begin(value):
    fields(value, ('kind','version','nonce','source_sha256','deadline_ns','load_bias',
                   'expected_cpu_index','expected_thread_id','global_maps'), 'begin_shape')
    require(value['kind'] == 'begin' and type(value['version']) is int and value['version'] == 1
            and type(value['nonce']) is str and HEX64.fullmatch(value['nonce']) and
            value['source_sha256'] == ABI_SHA256 and integer(value['load_bias']) and
            value['load_bias'] % PAGE == 0 and type(value['expected_cpu_index']) is int
            and value['expected_cpu_index'] == 0 and integer(value['expected_thread_id'],1,2**31-1)
            and type(value['global_maps']) is list and 1 <= len(value['global_maps']) <= 2,
            'begin_values')
    _deadline(value['deadline_ns'])
    for grant in value['global_maps']:
        validate_grant(grant)
        require(grant['category'] in ('elf_data','elf_bss'), 'global_category')
    require(len({g['metadata_sha256'] for g in value['global_maps']}) == 1, 'grant_digest')
    for rva, length in ((QUEUE,16),(GENERATION,4)):
        address = end(value['load_bias'], rva)
        matches = [g for g in value['global_maps'] if g['start'] <= address and
                   end(address,length) <= g['end']]
        require(len(matches) == 1, 'global_grant')
    return value


def field_worker(mem_fd, request_fd, result_fd):
    initial = time.monotonic_ns() + SECONDS_NS
    output = _Output(result_fd, initial, FIELD_OUTPUT)
    try:
        require(len({mem_fd, request_fd, result_fd}) == 3, 'fd_duplicate')
        _fd(mem_fd, os.O_RDONLY, True)
        channel = _Input(request_fd)
        begin = _begin(channel.frame(initial))
        require(begin['deadline_ns'] <= initial, 'deadline_extended')
        deadline = output.deadline = begin['deadline_ns']
        bias = begin['load_bias']; sequence = 0
        def read(phase, address, length, grant):
            nonlocal sequence
            channel.check(deadline); _within(grant,address,length)
            require(sequence < 14 and length in (4,16), 'read_inventory')
            sequence += 1
            output.row(dict(kind='read_started',seq=sequence,phase=phase,address=address,
                            length=length,started_ns=time.monotonic_ns()))
            # Output backpressure can consume time or allow cancellation to
            # arrive. A failed recheck leaves this actual start row pending.
            channel.check(deadline)
            try:
                data = os.pread(mem_fd,length,address); returned, err = len(data), None
            except OSError as exc:
                data, returned, err = b'', -1, exc.errno or errno.EIO
            output.row(dict(kind='read_finished',seq=sequence,finished_ns=time.monotonic_ns(),
                            returned=returned,errno=err,hex=data.hex()))
            require(err is None and returned == length, 'pread_incomplete', 'INCOMPLETE')
            return data
        def global_read(phase,rva,length):
            address=end(bias,rva)
            grant=next(g for g in begin['global_maps'] if g['start'] <= address < g['end'])
            return read(phase,address,length,grant)
        head = global_read(1,QUEUE,16); generation = global_read(1,GENERATION,4)
        cpu, tail = struct.unpack('<QQ',head)
        require(cpu != 0 and cpu % 8 == 0 and tail == end(cpu,NODE), 'queue_head')
        end(cpu,CPU_BYTES)
        output.row(dict(kind='head_ready',nonce=begin['nonce'],completed_phase=1))
        admitted = channel.frame(deadline)
        fields(admitted, ('kind','version','nonce','cpu','map'), 'admit_shape')
        require(admitted['kind']=='admit_cpu' and type(admitted['version']) is int and
                admitted['version']==1 and admitted['nonce']==begin['nonce'] and
                type(admitted['cpu']) is int and admitted['cpu']==cpu, 'admit_identity')
        grant=admitted['map'];validate_grant(grant,'cpu_allocation');_within(grant,cpu,CPU_BYTES)
        require(grant['metadata_sha256']==begin['global_maps'][0]['metadata_sha256'],'grant_digest')
        def cpuread(phase,offset,length): return read(phase,end(cpu,offset),length,grant)
        node=cpuread(2,NODE,16)
        require(struct.unpack('<QQ',node)==(0,end(bias,QUEUE)), 'cpu_node')
        index=cpuread(2,INDEX,4);require(struct.unpack('<i',index)[0]==0,'cpu_index')
        tid=cpuread(2,TID,4)
        require(struct.unpack('<i',tid)[0]==begin['expected_thread_id'],'cpu_tid')
        h=cpuread(3,HFLAGS,4); h2=cpuread(3,HFLAGS2,4)
        require(not (int.from_bytes(h,'little') & ((1<<19)|(1<<21))) and
                not (int.from_bytes(h2,'little') & (1<<6)), 'cpu_state', 'INCOMPLETE')
        for phase, offset, old in ((4,HFLAGS,h),(4,HFLAGS2,h2),(5,NODE,node),
                                   (5,INDEX,index),(5,TID,tid)):
            require(cpuread(phase,offset,len(old))==old,'cpu_changed','INCOMPLETE')
        require(global_read(6,QUEUE,16)==head,'queue_changed','INCOMPLETE')
        require(global_read(6,GENERATION,4)==generation,'generation_changed','INCOMPLETE')
        require(sequence==14,'read_inventory');channel.check(deadline)
        output.row(dict(kind='finished',status='ADMIT',reason='field_subset_complete'))
        return 0
    except ReaderError as exc:
        try:
            output.row(dict(kind='finished',status=exc.status,reason=exc.reason))
        except ReaderError:
            pass
        return 2 if exc.status=='DENY' else 3


class _Statfs(ctypes.Structure):
    _fields_ = [('f_type',ctypes.c_long),('f_bsize',ctypes.c_long),
                ('counts',ctypes.c_ulong*5),('fsid',ctypes.c_int*2),
                ('namelen',ctypes.c_long),('frsize',ctypes.c_long),('flags',ctypes.c_long),
                ('spare',ctypes.c_long*4)]


def _filesystem(fd):
    require(sys.platform=='linux' and platform.machine()=='x86_64' and
            ctypes.sizeof(ctypes.c_void_p)==ctypes.sizeof(ctypes.c_long)==8 and
            ctypes.sizeof(ctypes.c_int)==4 and ctypes.sizeof(_Statfs)==120 and
            ctypes.alignment(_Statfs)==8 and _Statfs.f_type.offset==0,
            'native_abi_unavailable','INCOMPLETE')
    libc=ctypes.CDLL(None,use_errno=True)
    function=libc.fstatfs
    function.argtypes=[ctypes.c_int,ctypes.POINTER(_Statfs)];function.restype=ctypes.c_int
    value=_Statfs()
    require(function(fd,ctypes.byref(value))==0,'fstatfs_failed','INCOMPLETE')
    return value.f_type


def _read_bounded(fd,cap,deadline):
    data=bytearray()
    while True:
        _remaining(deadline)
        require(len(data)<cap,'metadata_read_limit','INCOMPLETE')
        try: block=os.read(fd,min(65536,cap-len(data)))
        except OSError as exc: raise ReaderError('INCOMPLETE','metadata_read_error') from exc
        _remaining(deadline)
        if not block: return bytes(data)
        data.extend(block)


def metadata_worker(fds,result_fd,deadline):
    _deadline(deadline)
    require(set(fds)=={'stat','maps','smaps','mountinfo','exe'} and
            len(set(fds.values())|{result_fd})==6,'metadata_fd_roles')
    output=_Output(result_fd,deadline,META_LIMIT)
    for role,fd in fds.items():
        _remaining(deadline);_fd(fd,os.O_RDONLY,True)
        if role!='exe':require(_filesystem(fd)==0x9fa0,'metadata_not_proc')
    values={}
    for role,cap in [('stat',4096),('maps',MAP_LIMIT),('smaps',SMAP_LIMIT),('mountinfo',MOUNT_LIMIT)]:
        try:
            values[role]=_read_bounded(fds[role],cap,deadline)
        except ReaderError as exc:
            if exc.reason == 'metadata_read_limit':
                raise ReaderError(exc.status,f'metadata_{role}_read_limit') from exc
            raise
        output.bytes(struct.pack('>I',len(values[role]))+values[role])
    fd=fds['exe'];initial=os.fstat(fd)
    require(64<=initial.st_size<=EXE_LIMIT,'exe_limit')
    require(os.lseek(fd,0,os.SEEK_CUR)==0,'exe_offset')
    digest=hashlib.sha256();prefix=bytearray();seen=0
    while seen<initial.st_size:
        _remaining(deadline)
        block=os.read(fd,min(65536,initial.st_size-seen))
        require(block,'exe_truncated','INCOMPLETE')
        digest.update(block);seen+=len(block)
        prefix.extend(block[:max(0,65536-len(prefix))])
    _remaining(deadline);final=os.fstat(fd)
    require((initial.st_dev,initial.st_ino,initial.st_size,initial.st_mtime_ns,initial.st_ctime_ns)==
            (final.st_dev,final.st_ino,final.st_size,final.st_mtime_ns,final.st_ctime_ns),
            'exe_changed','INCOMPLETE')
    elf=_elf(bytes(prefix),seen,digest.hexdigest())
    require(_filesystem(fd)==0xef53,'exe_filesystem','INCOMPLETE')
    identity=dict(device=initial.st_dev,inode=initial.st_ino,size=seen,sha256=elf.sha256,
                  build_id=elf.build_id,elf_class=64,elf_machine=62,
                  mount_fstype=_mount_type(values['mountinfo'],initial.st_dev),statfs_magic='0xef53')
    validate_exe(identity);encoded=canonical(identity)
    require(len(encoded)<=4096,'exe_identity_limit')
    output.bytes(struct.pack('>I',len(encoded))+encoded)
    return 0


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    mode=parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--field-reader',action='store_true')
    mode.add_argument('--metadata-reader',action='store_true')
    for role in ('mem','request','result','stat','maps','smaps','mountinfo','exe'):
        parser.add_argument('--'+role+'-fd',type=int)
    parser.add_argument('--deadline-ns',type=int)
    args=parser.parse_args(argv)
    try:
        if args.field_reader:
            require(args.result_fd is not None and args.mem_fd is not None and args.request_fd is not None
                    and all(getattr(args,r+'_fd') is None for r in ('stat','maps','smaps','mountinfo','exe'))
                    and args.deadline_ns is None,'worker_arguments')
            return field_worker(args.mem_fd,args.request_fd,args.result_fd)
        roles=('stat','maps','smaps','mountinfo','exe')
        require(args.mem_fd is None and args.request_fd is None and args.result_fd is not None
                and args.deadline_ns is not None and all(getattr(args,r+'_fd') is not None for r in roles),
                'worker_arguments')
        return metadata_worker({r:getattr(args,r+'_fd') for r in roles},args.result_fd,args.deadline_ns)
    except ReaderError as exc:
        print(json.dumps(dict(status=exc.status,reason=exc.reason)),file=sys.stderr)
        return 2 if exc.status=='DENY' else 3
    except OSError as exc:
        print(json.dumps(dict(status='INCOMPLETE',reason='worker_io',errno=exc.errno)),file=sys.stderr)
        return 3


if __name__=='__main__':
    raise SystemExit(main())
