#!/usr/bin/env python3
"""Gate-first controls; synthetic field files never represent a QEMU witness."""
import copy
import errno
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import run0_host_cpu_reader as reader


CPU = 0x200000
FLAGS = 'rd wr mr mw me ac sd'
MAPS = (b'00000000-00001000 r-xp 00000000 08:01 7 /qemu\n'
        b'00200000-00210000 rw-p 00000000 00:00 0 [heap]\n'
        b'01700000-01940000 rw-p 00001000 08:01 7 /qemu\n'
        b'01940000-01a00000 rw-p 00000000 00:00 0\n')


def smaps(maps=MAPS, flags=FLAGS):
    return b''.join(line + b'\nSize:                  4 kB\nVmFlags: ' +
                    (flags if b'rw-p' in line else 'rd ex mr mw me sd').encode() +
                    b'\n' for line in maps.splitlines())


def elf_fixture():
    data = bytearray(0x241000)
    data[:16] = b'\x7fELF\x02\x01\x01' + bytes(9)
    struct.pack_into('<HHIQQQIHHHHHH', data, 16, 3, 62, 1, 0, 64, 0, 0,
                     64, 56, 3, 0, 0, 0)
    struct.pack_into('<IIQQQQQQ', data, 64, 1, 5, 0, 0, 0, 0x1000, 0x1000, 4096)
    struct.pack_into('<IIQQQQQQ', data, 120, 1, 6, 0x1000, 0x1700000, 0,
                     0x240000, 0x300000, 4096)
    struct.pack_into('<IIQQQQQQ', data, 176, 4, 4, 0x200, 0x200, 0, 36, 36, 4)
    struct.pack_into('<III', data, 0x200, 4, 20, 3)
    data[0x20c:0x210] = b'GNU\0'
    data[0x210:0x224] = bytes.fromhex('ab' * 20)
    return bytes(data)


def exe_identity(data):
    return dict(device=0x801, inode=7, size=len(data),
                sha256=hashlib.sha256(data).hexdigest(), build_id='ab' * 20,
                elf_class=64, elf_machine=62, mount_fstype='ext4', statfs_magic='0xef53')


def fixture():
    data = elf_fixture()
    abi = reader.HostABI(reader.parse_elf(data), reader.ABI_SHA256)
    maps = reader.admit_host_maps(MAPS, smaps(), exe_identity(data), abi)
    return abi, maps


def begin(maps, seconds=3):
    return dict(kind='begin', version=1, nonce='a' * 64,
                source_sha256=reader.ABI_SHA256,
                deadline_ns=time.monotonic_ns() + int(seconds * 1e9),
                load_bias=maps.load_bias, expected_cpu_index=0,
                expected_thread_id=123, global_maps=list(maps.global_maps))


class Session:
    def __init__(self, folder, mutate=None, seconds=3):
        self.abi, self.maps = fixture()
        path = Path(folder) / 'synthetic-fields.bin'
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        try:
            os.ftruncate(fd, 0x1a00000)
            os.pwrite(fd, struct.pack('<QQ', CPU, CPU + 0x238), 0x17ddad0)
            os.pwrite(fd, struct.pack('<I', 1), 0x1930b64)
            os.pwrite(fd, struct.pack('<QQ', 0, 0x17ddad0), CPU + 0x238)
            os.pwrite(fd, struct.pack('<i', 0), CPU + 0x2c8)
            os.pwrite(fd, struct.pack('<i', 123), CPU + 0xb8)
            os.pwrite(fd, struct.pack('<II', 0, 0), CPU + 0x2870)
            if mutate:
                mutate(fd)
        finally:
            os.close(fd)
        self.mem = os.open(path, os.O_RDONLY)
        request_read, self.request = os.pipe()
        self.child = subprocess.Popen(
            [sys.executable, str(Path(reader.__file__)), '--field-reader',
             '--mem-fd', str(self.mem), '--request-fd', str(request_read),
             '--result-fd', '1'], pass_fds=(self.mem, request_read),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        os.close(request_read)
        self.buffer = b''
        self.rows = []
        self.begin = begin(self.maps, seconds)

    def send(self, obj):
        os.write(self.request, json.dumps(obj, separators=(',', ':')).encode() + b'\n')

    def until(self, kind, timeout=4):
        deadline = time.monotonic() + timeout
        while True:
            if b'\n' in self.buffer:
                line, self.buffer = self.buffer.split(b'\n', 1)
                row = json.loads(line)
                self.rows.append(row)
                if row['kind'] == kind:
                    return row
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.child.stdout], [], [], remaining)[0]:
                raise AssertionError('fixture output timeout')
            chunk = os.read(self.child.stdout.fileno(), 16384)
            if not chunk:
                raise AssertionError('fixture EOF before ' + kind)
            self.buffer += chunk

    def admit(self):
        grant = reader.admit_cpu(struct.pack('<QQ', CPU, CPU + 0x238), self.maps, self.abi)
        self.send(dict(kind='admit_cpu', version=1, nonce=self.begin['nonce'], cpu=CPU, map=grant))

    def close(self):
        if self.request is not None:
            os.close(self.request)
            self.request = None
        try:
            self.child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.child.kill()
            self.child.wait(timeout=2)
        self.child.stdout.close()
        self.child.stderr.close()
        os.close(self.mem)


class MappingTests(unittest.TestCase):
    def error(self, reason, function, *args):
        with self.assertRaises(reader.ReaderError) as caught:
            function(*args)
        self.assertEqual(reason, caught.exception.reason)

    def test_exact_elf_and_map_admission(self):
        abi, maps = fixture()
        self.assertEqual(0, maps.load_bias)
        self.assertEqual(1, len(maps.global_maps))
        self.assertEqual('ab' * 20, abi.elf.build_id)
        self.assertEqual('cpu_allocation', reader.admit_cpu(
            struct.pack('<QQ', CPU, CPU + 0x238), maps, abi)['category'])

    def test_linux_device_literals_are_independent_of_review_host_encoding(self):
        for device,parts in [(0x801,(8,1)),(0xfd00,(253,0)),(0x100000,(0,256)),
                             (0x100000000000,(0x1000,0)),(2**64-1,(2**32-1,2**32-1))]:
            self.assertEqual(parts,reader.linux_device(device))
        for value in [True,-1,2**64]:
            with self.assertRaises(reader.ReaderError):reader.linux_device(value)

    def test_elf_truncated_wrong_machine_and_overflow(self):
        data = elf_fixture()
        for blob in (data[:40], data[:64], data[:200]):
            with self.assertRaises(reader.ReaderError):
                reader.parse_elf(blob)
        bad = bytearray(data); struct.pack_into('<H', bad, 18, 183)
        self.error('elf_header', reader.parse_elf, bytes(bad))
        bad = bytearray(data); struct.pack_into('<Q', bad, 120 + 40, 2**64 - 1)
        with self.assertRaises(reader.ReaderError):
            reader.parse_elf(bytes(bad))

    def test_each_required_flag_and_unsafe_flags_prevent_global_grants(self):
        data = elf_fixture(); abi = reader.HostABI(reader.parse_elf(data), reader.ABI_SHA256)
        for flags in ('rd mr mw me ac sd', FLAGS + ' io', FLAGS + ' pf', FLAGS + ' mm',
                      FLAGS + ' um', FLAGS + ' uw', FLAGS + ' ex', FLAGS + ' zz'):
            with self.subTest(flags=flags), self.assertRaises(reader.ReaderError):
                reader.admit_host_maps(MAPS, smaps(flags=flags), exe_identity(data), abi)

    def test_duplicate_flags_and_unpaired_rows_deny(self):
        data = elf_fixture(); abi = reader.HostABI(reader.parse_elf(data), reader.ABI_SHA256)
        for raw in (smaps(flags=FLAGS + ' rd'), smaps().replace(b'01700000-', b'01701000-')):
            with self.assertRaises(reader.ReaderError):
                reader.admit_host_maps(MAPS, raw, exe_identity(data), abi)

    def test_unknown_flags_on_unselected_maps_do_not_grant_authority(self):
        data = elf_fixture(); abi = reader.HostABI(reader.parse_elf(data), reader.ABI_SHA256)
        raw = smaps().replace(b'rd ex mr mw me sd', b'rd ex mr mw me sd zz')
        self.assertEqual(0, reader.admit_host_maps(MAPS, raw, exe_identity(data), abi).load_bias)

    def test_wrong_inode_hash_mount_and_ambiguous_bias(self):
        data = elf_fixture(); abi = reader.HostABI(reader.parse_elf(data), reader.ABI_SHA256)
        for key, value in [('inode', 8), ('sha256', '0' * 64), ('mount_fstype', 'xfs'),
                           ('statfs_magic', '0x1234'), ('inode', True)]:
            ex = exe_identity(data); ex[key] = value
            with self.subTest(key=key), self.assertRaises(reader.ReaderError):
                reader.admit_host_maps(MAPS, smaps(), ex, abi)
        extra = MAPS + b'03000000-03001000 r-xp 00000000 08:01 7 /qemu\n'
        with self.assertRaises(reader.ReaderError):
            reader.admit_host_maps(extra, smaps(extra), exe_identity(data), abi)

    def test_head_map_bounds_null_alignment_and_checked_extent(self):
        abi, maps = fixture()
        for pointer in (0, CPU + 1, CPU + 0x10000 - 16, 2**64 - 8):
            with self.subTest(pointer=pointer), self.assertRaises(reader.ReaderError):
                reader.admit_cpu(struct.pack('<QQ', pointer, pointer + 0x238 if pointer < 2**63 else 0), maps, abi)

    def test_bss_global_mapping_uses_exact_load_continuation(self):
        data = bytearray(elf_fixture())
        struct.pack_into('<Q', data, 120 + 32, 0x230000)
        # generation becomes an anonymous BSS address, while queue remains file-backed.
        m = MAPS.replace(b'01940000', b'01930000')
        abi = reader.HostABI(reader.parse_elf(bytes(data)), reader.ABI_SHA256)
        admitted = reader.admit_host_maps(m, smaps(m), exe_identity(bytes(data)), abi)
        self.assertIn('elf_bss', [x['category'] for x in admitted.global_maps])
        bad = m.replace(b'01930000-01a00000', b'01931000-01a00000')
        with self.assertRaises(reader.ReaderError):
            reader.admit_host_maps(bad, smaps(bad), exe_identity(bytes(data)), abi)

    def test_mount_binding_deepest_component_and_actual_device(self):
        mounts = (b'1 0 8:1 / / rw - ext4 /dev/root rw\n'
                  b'2 1 9:1 / /else rw - tmpfs none rw\n')
        ex = exe_identity(elf_fixture())
        reader.bind_mount_path(mounts, '/qemu', ex)
        with self.assertRaises(reader.ReaderError):
            reader.bind_mount_path(mounts, '/else/qemu', ex)
        reader.bind_mount_path(mounts, '/elsewhere/qemu', ex)

    def test_metadata_frames_exact_lengths_no_trailing_or_duplicate_json(self):
        frames = [b'stat', MAPS, smaps(), b'mounts', json.dumps(exe_identity(elf_fixture())).encode()]
        raw = b''.join(struct.pack('>I', len(x)) + x for x in frames)
        self.assertEqual(MAPS, reader.parse_metadata_output(raw)['maps'])
        for bad in (raw[:-1], raw + b'x', struct.pack('>I', 4097) + raw[4:]):
            with self.assertRaises(reader.ReaderError): reader.parse_metadata_output(bad)
        frames[-1] = b'{"device":1,"device":2}'
        with self.assertRaises(reader.ReaderError):
            reader.parse_metadata_output(b''.join(struct.pack('>I', len(x)) + x for x in frames))

    def test_metadata_consistency_ignores_accounting_not_identity_or_flags(self):
        abi, maps = fixture()
        statline = b'123 (toy) S 99 ' + b'0 ' * 17 + b'456 0\n'
        before = dict(stat=statline, maps=MAPS, smaps=smaps(), mountinfo=b'', exe=exe_identity(elf_fixture()))
        after = copy.deepcopy(before); after['smaps'] = after['smaps'].replace(b'4 kB', b'8 kB')
        reader.metadata_consistent(before, after, maps.global_maps)
        after['stat'] = statline.replace(b'456', b'457')
        with self.assertRaises(reader.ReaderError): reader.metadata_consistent(before, after, maps.global_maps)
        altered=copy.deepcopy(list(maps.global_maps));altered[0]['metadata_sha256']='0'*64
        with self.assertRaises(reader.ReaderError): reader.metadata_consistent(before,before,altered)
        malformed=copy.deepcopy(before);malformed['exe']={'unbound':True}
        with self.assertRaises(reader.ReaderError): reader.metadata_consistent(malformed,malformed,maps.global_maps)


class FieldWorkerTests(unittest.TestCase):
    def session(self, mutate=None, seconds=3):
        folder = tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        s = Session(folder.name, mutate, seconds); self.addCleanup(s.close); return s

    def test_real_worker_exact_fourteen_reads_and_actual_reap(self):
        s = self.session(); s.send(s.begin); s.until('head_ready'); s.admit()
        self.assertEqual('ADMIT', s.until('finished')['status'])
        self.assertEqual(0, s.child.wait(timeout=2))
        reads = [x for x in s.rows if x['kind'] == 'read_started']
        self.assertEqual(list(range(1, 15)), [x['seq'] for x in reads])
        self.assertEqual(104, sum(x['length'] for x in reads))
        self.assertEqual(14, len([x for x in s.rows if x['kind'] == 'read_finished']))

    def test_wrong_node_index_tid_blocks_hidden_state_reads(self):
        for offset, data in [(0x238, struct.pack('<Q', 1)), (0x240, struct.pack('<Q', 0)),
                             (0x2c8, struct.pack('<i', 1)), (0xb8, struct.pack('<i', 124))]:
            with self.subTest(offset=offset):
                s = self.session(lambda fd: os.pwrite(fd, data, CPU + offset))
                s.send(s.begin); s.until('head_ready'); s.admit()
                self.assertEqual('DENY', s.until('finished')['status'])
                self.assertFalse(any(x.get('phase', 0) >= 3 for x in s.rows))
                self.assertNotEqual(0, s.child.wait(timeout=2))

    def test_each_forbidden_state_bit_stops_after_first_state_phase(self):
        for h, h2 in [(1 << 19, 0), (1 << 21, 0), (0, 1 << 6)]:
            with self.subTest(h=h, h2=h2):
                s = self.session(lambda fd: os.pwrite(fd, struct.pack('<II', h, h2), CPU + 0x2870))
                s.send(s.begin); s.until('head_ready'); s.admit()
                self.assertNotEqual('ADMIT', s.until('finished')['status'])
                self.assertFalse(any(x.get('phase', 0) > 3 for x in s.rows))

    def test_invalid_begin_and_bool_integer_have_zero_reads_then_fresh_success(self):
        for key, value in [('version', True), ('expected_cpu_index', False),
                           ('load_bias', 2**64), ('source_sha256', '0' * 64)]:
            s = self.session(); b = dict(s.begin); b[key] = value; s.send(b)
            self.assertEqual('DENY', s.until('finished')['status'])
            self.assertFalse(any(x['kind'] == 'read_started' for x in s.rows))
        s = self.session(); s.send(s.begin); s.until('head_ready'); s.admit()
        self.assertEqual('ADMIT', s.until('finished')['status'])

    def test_duplicate_keys_nonfinite_and_unknown_field_denied(self):
        for raw in (b'{"kind":"begin","kind":"begin"}\n', b'{"x":NaN}\n',
                    b'{"x":Infinity}\n', b'{}\n'):
            s = self.session(); os.write(s.request, raw)
            self.assertEqual('DENY', s.until('finished')['status'])
            self.assertFalse(any(x['kind'] == 'read_started' for x in s.rows))

    def test_bad_second_frame_prevents_identity_reads(self):
        s = self.session(); s.send(s.begin); s.until('head_ready')
        s.send(dict(kind='admit_cpu', version=1, nonce='a'*64, cpu=CPU+8,
                    map=reader.admit_cpu(struct.pack('<QQ', CPU, CPU+0x238), s.maps, s.abi)))
        self.assertEqual('DENY', s.until('finished')['status'])
        self.assertEqual(2, len([x for x in s.rows if x['kind']=='read_started']))

    def test_cancel_waiting_for_second_frame_reaps_and_does_not_read_identity(self):
        s = self.session(); s.send(s.begin); s.until('head_ready')
        os.close(s.request); s.request = None
        self.assertEqual('INCOMPLETE', s.until('finished')['status'])
        self.assertEqual(2, len([x for x in s.rows if x['kind']=='read_started']))
        self.assertEqual(3, s.child.wait(timeout=2))

    def test_stalled_request_obeys_original_deadline_and_actual_reap(self):
        s = self.session(seconds=0.3); s.send(s.begin); s.until('head_ready')
        started = time.monotonic()
        # The output writer shares the deadline: EOF plus actual exit3 may be
        # the only terminal evidence after it expires, not a fabricated row.
        self.assertEqual(3, s.child.wait(timeout=2))
        tail = s.buffer + s.child.stdout.read()
        for line in tail.splitlines():
            row = json.loads(line)
            self.assertEqual('finished', row['kind'])
            self.assertEqual('INCOMPLETE', row['status'])
        self.assertLess(time.monotonic()-started, 1.5)
        self.assertEqual(2, len([x for x in s.rows if x['kind']=='read_started']))

    def test_nested_grant_unknown_bool_and_large_device_deny_before_reads(self):
        for key,value in [('extra',0),('start',False),('dev_major',2**32)]:
            s=self.session(); packet=copy.deepcopy(s.begin)
            packet['global_maps'][0][key]=value; s.send(packet)
            self.assertEqual('DENY',s.until('finished')['status'])
            self.assertFalse(any(x['kind']=='read_started' for x in s.rows))

    def test_short_pread_retains_actual_bytes_and_no_completion_retry(self):
        s = self.session(lambda fd: os.ftruncate(fd, 0x17ddad0 + 3)); s.send(s.begin)
        self.assertEqual('INCOMPLETE', s.until('finished')['status'])
        finished = [x for x in s.rows if x['kind']=='read_finished']
        self.assertEqual(1, len(finished)); self.assertEqual(3, finished[0]['returned'])
        self.assertEqual(6, len(finished[0]['hex']))

    def test_readwrite_fd_refused_without_read(self):
        with tempfile.TemporaryDirectory() as folder:
            fd = os.open(Path(folder)/'file', os.O_CREAT|os.O_RDWR, 0o600)
            a,b = os.pipe()
            try:
                child = subprocess.Popen([sys.executable, reader.__file__, '--field-reader',
                    '--mem-fd', str(fd), '--request-fd', str(a), '--result-fd', '1'],
                    pass_fds=(fd,a), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out,err = child.communicate(timeout=2)
                self.assertEqual(2, child.returncode); self.assertNotIn(b'read_started', out)
            finally: os.close(fd); os.close(a); os.close(b)


class InFlightControls(unittest.TestCase):
    def exercise(self, action):
        """Real file reads/pipes; hook only schedules the adversarial event."""
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'synthetic-fields.bin'
            writefd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_RDWR,0o600)
            os.ftruncate(writefd,0x1a00000)
            for offset,data in [(0x17ddad0,struct.pack('<QQ',CPU,CPU+0x238)),
                (0x1930b64,struct.pack('<I',1)),(CPU+0x238,struct.pack('<QQ',0,0x17ddad0)),
                (CPU+0x2c8,struct.pack('<i',0)),(CPU+0xb8,struct.pack('<i',123)),
                (CPU+0x2870,bytes(8))]: os.pwrite(writefd,data,offset)
            mem=os.open(path,os.O_RDONLY); reqread,reqwrite=os.pipe(); outread,outwrite=os.pipe()
            writer=[reqwrite]; result=[]; calls=[]; rows=[]; buffered=bytearray()
            output_entered=threading.Event();input_entered=threading.Event()
            filled=0
            if action=='backpressure':
                os.set_blocking(outwrite,False)
                while True:
                    try:filled+=os.write(outwrite,b'j'*4096)
                    except BlockingIOError:break
                self.assertGreater(filled,0)
            abi,maps=fixture(); packet=begin(maps)
            real_pread=os.pread
            real_write=reader._write;real_frame=reader._Input.frame
            def instrument_write(fd,data,deadline):
                if b'"kind":"read_started"' in data:output_entered.set()
                return real_write(fd,data,deadline)
            def instrument_frame(channel,deadline):
                input_entered.set()
                return real_frame(channel,deadline)
            def instrument(fd,n,offset):
                calls.append((offset,n)); data=real_pread(fd,n,offset)
                if action=='cancel' and len(calls)==3:
                    os.close(writer.pop())
                if action=='change' and len(calls)==7:
                    os.pwrite(writefd,struct.pack('<I',1),CPU+0x2870)
                return data
            worker=threading.Thread(target=lambda:result.append(reader.field_worker(mem,reqread,outwrite)))
            try:
                with mock.patch.object(reader.os,'pread',side_effect=instrument), \
                     mock.patch.object(reader,'_write',side_effect=instrument_write), \
                     mock.patch.object(reader._Input,'frame',instrument_frame):
                    worker.start()
                    if action=='delayed_begin':
                        self.assertTrue(input_entered.wait(1));time.sleep(0.03)
                        packet['deadline_ns']=time.monotonic_ns()+4_990_000_000
                    os.write(reqwrite,json.dumps(packet).encode()+b'\n')
                    if action=='backpressure':
                        self.assertTrue(output_entered.wait(1));os.close(writer.pop())
                        while filled:
                            filled-=len(os.read(outread,min(filled,65536)))
                    deadline=time.monotonic()+4
                    finished=False
                    while not finished:
                        if b'\n' not in buffered:
                            self.assertTrue(select.select([outread],[],[],max(0,deadline-time.monotonic()))[0])
                            buffered.extend(os.read(outread,16384))
                        while b'\n' in buffered:
                            line,rest=bytes(buffered).split(b'\n',1);buffered=bytearray(rest)
                            row=json.loads(line);rows.append(row)
                            if row['kind']=='head_ready':
                                grant=reader.admit_cpu(struct.pack('<QQ',CPU,CPU+0x238),maps,abi)
                                msg=dict(kind='admit_cpu',version=1,nonce=packet['nonce'],cpu=CPU,map=grant)
                                os.write(reqwrite,json.dumps(msg).encode()+b'\n')
                            if row['kind']=='finished':finished=True
                    worker.join(timeout=2);self.assertFalse(worker.is_alive())
                self.assertEqual([2 if action=='delayed_begin' else 3],result)
                self.assertEqual('DENY' if action=='delayed_begin' else 'INCOMPLETE',rows[-1]['status'])
                expected={'cancel':3,'change':8,'backpressure':0,'delayed_begin':0}[action]
                self.assertEqual(expected,len(calls))
                self.assertEqual(len(calls),len([r for r in rows if r['kind']=='read_finished']))
                if action=='backpressure':
                    self.assertEqual(1,len([r for r in rows if r['kind']=='read_started']))
            finally:
                if writer:os.close(writer.pop())
                worker.join(timeout=4)
                for fd in [writefd,mem,reqread,outread,outwrite]:os.close(fd)

    def test_cancel_after_dispatch_retains_inflight_result_and_blocks_next(self):
        self.exercise('cancel')

    def test_actual_changed_file_word_is_not_accepted_as_consistent(self):
        self.exercise('change')

    def test_record_backpressure_does_not_allow_read_after_observed_cancel(self):
        self.exercise('backpressure')

    def test_delayed_begin_cannot_extend_initial_absolute_deadline(self):
        self.exercise('delayed_begin')

    def test_eintr_never_certifies_empty_pipe_before_actual_eof_or_extra_byte(self):
        for variant in ('eof','extra'):
            r,w=os.pipe();channel=reader._Input(r);real=os.read;calls=[]
            if variant=='eof':os.close(w)
            else:os.write(w,b'x')
            def interrupted(fd,n):
                calls.append(1)
                if len(calls)==1:raise InterruptedError(errno.EINTR,'scheduled interruption')
                return real(fd,n)
            try:
                with mock.patch.object(reader.os,'read',side_effect=interrupted):
                    with self.assertRaises(reader.ReaderError):channel.check(time.monotonic_ns()+1_000_000_000)
                self.assertGreaterEqual(len(calls),2)
            finally:
                os.close(r)
                if variant=='extra':os.close(w)


@unittest.skipUnless(sys.platform == 'linux', 'actual Linux proc/libc metadata fixture')
class MetadataWorkerTests(unittest.TestCase):
    def test_real_owned_proc_metadata_and_separate_reaps(self):
        target = subprocess.Popen(['/bin/sleep', '10'])
        fds=[]
        try:
            args=[sys.executable,reader.__file__,'--metadata-reader','--result-fd','1',
                  '--deadline-ns',str(time.monotonic_ns()+4_000_000_000)]
            for role in ['stat','maps','smaps','exe','mountinfo']:
                path = '/proc/self/mountinfo' if role=='mountinfo' else f'/proc/{target.pid}/{role}'
                fd=os.open(path,os.O_RDONLY);fds.append(fd);args += ['--'+role+'-fd',str(fd)]
            child=subprocess.Popen(args,pass_fds=fds,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            out,err=child.communicate(timeout=5)
            self.assertEqual(0,child.returncode,err.decode())
            snapshot=reader.parse_metadata_output(out)
            self.assertEqual(target.pid,reader.parse_stat(snapshot['stat'])['pid'])
            self.assertEqual('ext4',snapshot['exe']['mount_fstype'])
            self.assertEqual('0xef53',snapshot['exe']['statfs_magic'])
        finally:
            for fd in fds:os.close(fd)
            target.terminate(); target.wait(timeout=2)
        self.assertIsNotNone(target.returncode)


class MetadataMapsCapTests(unittest.TestCase):
    """Fixed synthetic metadata; filesystem-role mocks confer no proc authority."""
    @staticmethod
    def large_maps():
        rows=[]
        for i in range(1024):
            start=0x30000000+i*4096
            line=f'{start:016x}-{start+4096:016x} rw-p 00000000 00:00 0 /synthetic-{i:04d}-'
            rows.append(line.ljust(99,'x').encode()+b'\n')
        return b''.join(rows)

    def test_100k_maps_and_matching_smaps_keep_1024_rows(self):
        maps=self.large_maps()
        self.assertEqual(102400,len(maps))
        parsed=reader.parse_maps_smaps(maps,smaps(maps))
        self.assertEqual(1024,len(parsed))
        self.assertEqual(0x30000000,parsed[0].start)
        self.assertEqual(0x30400000,parsed[-1].end)

    def test_100k_maps_metadata_frame_preserves_all_bytes(self):
        maps=self.large_maps()
        frames=[b'stat',maps,smaps(maps),b'mounts',reader.canonical(exe_identity(elf_fixture()))]
        raw=b''.join(struct.pack('>I',len(part))+part for part in frames)
        self.assertEqual(maps,reader.parse_metadata_output(raw)['maps'])

    def worker(self,maps):
        folder=tempfile.TemporaryDirectory();self.addCleanup(folder.cleanup)
        fds={};data={'stat':b'synthetic stat\n','maps':maps,'smaps':smaps(self.large_maps()),
                     'mountinfo':b'', 'exe':elf_fixture()}
        for role,value in data.items():
            path=Path(folder.name)/role;path.write_bytes(value)
            fds[role]=os.open(path,os.O_RDONLY);self.addCleanup(os.close,fds[role])
        major,minor=reader.linux_device(os.fstat(fds['exe']).st_dev)
        (Path(folder.name)/'mountinfo').write_bytes(
            f'1 0 {major}:{minor} / / rw - ext4 /dev/synthetic rw\n'.encode())
        reads=[];real_read=os.read
        outread,outfd=os.pipe();chunks=[];closed=[False]
        def drain():
            while True:
                chunk=real_read(outread,65536)
                if not chunk:return
                chunks.append(chunk)
        thread=threading.Thread(target=drain);thread.start()
        def finish():
            if not closed[0]:
                closed[0]=True;os.close(outfd);thread.join(timeout=2)
                self.assertFalse(thread.is_alive(),'synthetic metadata output drain stalled')
                os.close(outread)
            return b''.join(chunks)
        self.addCleanup(finish);out=(outfd,finish)
        def record(fd,size):
            reads.append(fd);return real_read(fd,size)
        return fds,out,reads,record

    def test_worker_reads_100k_maps_and_finishes_fixed_frames(self):
        maps=self.large_maps();fds,out,reads,record=self.worker(maps)
        with mock.patch.object(reader,'_filesystem',side_effect=lambda fd:0xef53 if fd==fds['exe'] else 0x9fa0), \
             mock.patch.object(reader.os,'read',side_effect=record):
            self.assertEqual(0,reader.metadata_worker(fds,out[0],time.monotonic_ns()+4_000_000_000))
        raw=out[1]()
        self.assertLess(len(raw),1572864)
        self.assertEqual(maps,reader.parse_metadata_output(raw)['maps'])
        self.assertIn(fds['exe'],reads)

    def test_worker_over_cap_names_maps_and_never_reads_later_role(self):
        fds,out,reads,record=self.worker(b'x'*131073)
        with mock.patch.object(reader,'_filesystem',side_effect=lambda fd:0xef53 if fd==fds['exe'] else 0x9fa0), \
             mock.patch.object(reader.os,'read',side_effect=record), \
             self.assertRaises(reader.ReaderError) as caught:
            reader.metadata_worker(fds,out[0],time.monotonic_ns()+4_000_000_000)
        self.assertEqual('INCOMPLETE',caught.exception.status)
        self.assertEqual('metadata_maps_read_limit',caught.exception.reason)
        self.assertNotIn(fds['smaps'],reads)
        self.assertNotIn(fds['mountinfo'],reads)
        self.assertNotIn(fds['exe'],reads)
        self.assertEqual(struct.pack('>I',15)+b'synthetic stat\n',out[1]())

    def test_1025_short_map_rows_remain_denied(self):
        maps=b''.join(f'{(i+1)*4096:08x}-{(i+2)*4096:08x} rw-p 00000000 00:00 0\n'.encode()
                      for i in range(1025))
        self.assertLess(len(maps),65536)
        with self.assertRaises(reader.ReaderError) as caught:reader.parse_maps_smaps(maps,smaps(maps))
        self.assertEqual('map_count',caught.exception.reason)

    def test_other_metadata_field_and_deadline_caps_are_unchanged(self):
        self.assertEqual((1024,1048576,262144,1572864,8192,16384,5_000_000_000),
                         (reader.MAX_ROWS,reader.SMAP_LIMIT,reader.MOUNT_LIMIT,reader.META_LIMIT,
                          reader.FIELD_INPUT,reader.FIELD_OUTPUT,reader.SECONDS_NS))


if __name__ == '__main__':
    unittest.main()
