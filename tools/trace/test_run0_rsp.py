"""Gate-first reset-only RSP controls; peers are synthetic, never a QEMU claim."""
import base64
from dataclasses import replace
import gzip
import hashlib
import select
import socket
import threading
import time
import unittest

import boot_profile_capture as capture
import run0_rsp as rsp


# Exact QEMU v8.2.2 gdb-xml/i386-64bit.xml, compressed without changing bytes.
# Original FSF copyright/permission notice is preserved inside the fixture.
CORE_XML = gzip.decompress(base64.b64decode("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"))
TARGET_XML = (b'<?xml version="1.0"?>'
              b'<!DOCTYPE target SYSTEM "gdb-target.dtd">'
              b'<target><architecture>i386:x86-64</architecture>'
              b'<xi:include href="i386-64bit.xml"/></target>')


def packet(payload):
    """Independent test encoder, not the implementation under test."""
    escaped = bytearray()
    for value in payload:
        escaped.extend((125, value ^ 32) if value in b'#$}*' else (value,))
    return b'$' + escaped + b'#' + f'{sum(escaped) & 255:02x}'.encode()


class Wire:
    def __init__(self, sock):
        self.sock, self.writes, self.reads = sock, [], []

    def write_all(self, data, deadline):
        self.sock.settimeout(max(0.000001, deadline - time.monotonic()))
        self.writes.append(data)
        self.sock.sendall(data)

    def read_chunk(self, deadline, max_bytes):
        ready, _, _ = select.select([self.sock], [], [], max(0, deadline-time.monotonic()))
        if not ready:
            raise TimeoutError('test deadline')
        data = self.sock.recv(max_bytes)
        self.reads.append(data)
        return data


class Peer:
    def __init__(self, script):
        self.local, self.remote = socket.socketpair()
        self.wire, self.script, self.errors = Wire(self.local), script, []
        self.thread = threading.Thread(target=self.serve, daemon=True)

    def serve(self):
        try:
            self.remote.settimeout(2)
            for expected, response in self.script:
                got = bytearray()
                while b'#' not in got or len(got)-got.index(b'#') < 3:
                    part = self.remote.recv(1)
                    if not part:
                        raise AssertionError('client closed before scripted request')
                    got.extend(part)
                if bytes(got) != packet(expected):
                    raise AssertionError((bytes(got), packet(expected)))
                framed = b'+' + packet(response)
                for part in (framed[:1], framed[1:3], framed[3:9], framed[9:]):
                    if part:
                        self.remote.sendall(part)
                if self.remote.recv(1) != b'+':
                    raise AssertionError('missing response acknowledgement')
        except BaseException as error:
            self.errors.append(error)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.local.close()
        self.remote.close()
        self.thread.join(2)


def description_script():
    result = []
    for name, content in ((b'target.xml', TARGET_XML), (b'i386-64bit.xml', CORE_XML)):
        for start in range(0, len(content), 1024):
            part = content[start:start+1024]
            marker = b'l' if start+len(part) == len(content) else b'm'
            result.append((b'qXfer:features:read:'+name+b':'+f'{start:x},400'.encode(), marker+part))
    return result


def initial_script():
    return [(b'qSupported:qXfer:features:read+', b'PacketSize=1000;qXfer:features:read+;multiprocess+'),
            (b'qfThreadInfo', b'm01'), (b'qsThreadInfo', b'l'), (b'qC', b'QC01'),
            (b'Hg01', b'OK'), (b'Hc01', b'OK')]


def client(wire, seconds=8):
    return rsp.RSPClient(wire, capture.Budget(time.monotonic()+seconds))


def to_description(session):
    session.query_supported()
    session.query_threads()
    session.select_thread()
    return session.read_target_description()


class ResetRSPTests(unittest.TestCase):
    def test_rsp01_fragmented_and_coalesced_exact_wire(self):
        encoded = packet(b'a#$}*z')
        self.assertEqual(rsp.encode_packet(b'a#$}*z'), encoded)
        decoder = rsp.AckDecoder()
        frames = []
        for byte in b'+'+encoded+b'+':
            frames.extend(decoder.feed(bytes([byte])))
        self.assertEqual([f.kind for f in frames], ['ACK', 'PACKET', 'ACK'])
        self.assertEqual(frames[1].payload, b'a#$}*z')
        self.assertEqual(frames[1].raw, encoded)
        self.assertEqual(len(rsp.AckDecoder().feed(b'+'+packet(b'OK'))), 2)

    def test_rsp02_hostile_codec_and_bounds(self):
        for malformed in (b'$abc#00', b'$}#7d', b'$a*~#09', b'noise', b'%stop#00', b'$x$y#00'):
            with self.subTest(malformed=malformed), self.assertRaises(rsp.RSPError):
                rsp.AckDecoder().feed(malformed)
        with self.assertRaises(rsp.RSPError) as caught:
            rsp.AckDecoder().feed(b'$a*~#09')
        self.assertEqual(caught.exception.reason, 'rsp_rle_unsupported')
        with self.assertRaises(rsp.RSPError):
            rsp.AckDecoder().feed(packet(b'x'*4097))
        with self.assertRaises(rsp.RSPError):
            rsp.AckDecoder().feed(b'$'+b'x'*8192)
        decoder = rsp.AckDecoder()
        with self.assertRaises(rsp.RSPError):
            decoder.feed(b'+'*257)

    def test_rsp03_complete_reset_sequence_and_operation_rows(self):
        raw = bytearray(608)
        raw[128:136] = (0xfff0).to_bytes(8, 'little')
        script = initial_script()+description_script()+[
            (b'g', raw.hex().encode()), (b'qqemu.Supported', b'sstepbits;sstep;PhyMemMode'),
            (b'qqemu.PhyMemMode', b'0'), (b'Qqemu.PhyMemMode:1', b'OK'),
            (b'qqemu.PhyMemMode', b'1')]
        with Peer(script) as peer:
            session = client(peer.wire)
            target = to_description(session)
            registers = session.read_reset_registers()
            self.assertEqual(registers.values[16], 0xfff0)
            self.assertEqual(target.packet_bytes, 608)
            session.query_qemu_supported()
            self.assertEqual(session.query_physical_mode(), 0)
            session.enable_physical_mode()
            self.assertEqual(session.query_physical_mode(), 1)
            peer.thread.join(1)
            self.assertFalse(peer.errors)
            self.assertEqual(len(session.operations), len(script))
            for row, (request, response) in zip(session.operations, script):
                self.assertEqual(row.request_packet, packet(request))
                self.assertEqual(row.response_packet, packet(response))
                self.assertEqual(row.response_payload, response)
                self.assertEqual(row.result, 'ok')
                self.assertLessEqual(row.started_ns, row.finished_ns)
            self.assertNotIn(b'multiprocess+', peer.wire.writes[0])

    def test_rsp03_bad_or_missing_capabilities_terminalize(self):
        for response, status in ((b'', 'INCOMPLETE'),
                                 (b'PacketSize=1000;PacketSize=1000;qXfer:features:read+', 'DENY'),
                                 (b'PacketSize=1000;qXfer:features:read+;qXfer:features:read-', 'DENY'),
                                 (b'PacketSize=fff;qXfer:features:read+', 'INCOMPLETE'),
                                 (b'PacketSize=true;qXfer:features:read+', 'DENY')):
            with self.subTest(response=response), Peer([(initial_script()[0][0], response)]) as peer:
                session = client(peer.wire)
                with self.assertRaises(rsp.RSPError) as caught:
                    session.query_supported()
                self.assertEqual(caught.exception.status, status)
                self.assertEqual(session.operations[-1].result, 'error')
                sent = len(peer.wire.writes)
                with self.assertRaises(rsp.RSPError):
                    session.query_supported()
                self.assertEqual(len(peer.wire.writes), sent)

    def test_rsp03_wrong_thread_and_nack(self):
        with Peer(initial_script()[:1]+[(b'qfThreadInfo', b'm02')]) as peer:
            session = client(peer.wire)
            session.query_supported()
            with self.assertRaises(rsp.RSPError):
                session.query_threads()
            self.assertEqual(session.operations[-1].result, 'error')
        left, right = socket.socketpair()
        try:
            right.sendall(b'-')
            wire = Wire(left)
            session = client(wire)
            with self.assertRaises(rsp.RSPError):
                session.query_supported()
            self.assertEqual(len(wire.writes), 1)
        finally:
            left.close(); right.close()

    def test_rsp04_exact_xml_and_hostile_annexes(self):
        self.assertEqual(hashlib.sha256(CORE_XML).hexdigest(), '1b3acc75743d5cea86aadda52e75a9ecdcbaefa89050d1aae8c4d8f3dd880953')
        target = rsp.decode_target_description(TARGET_XML, CORE_XML)
        self.assertEqual(len(target.registers), 66)
        for bad in (TARGET_XML.replace(b'i386-64bit.xml', b'../secret'),
                    TARGET_XML.replace(b'<target>', b'<target xmlns:xi="anything">'),
                    TARGET_XML.replace(b'</target>', b'<xi:include href="extra.xml"/></target>'),
                    TARGET_XML.replace(b'gdb-target.dtd', b'file:///etc/passwd')):
            with self.subTest(bad=bad), self.assertRaises(rsp.RSPError):
                rsp.decode_target_description(bad, CORE_XML)
        with self.assertRaises(rsp.RSPError):
            rsp.decode_target_description(TARGET_XML, CORE_XML+b' ')

    def test_rsp04_chunk_no_progress_and_oversize(self):
        for response in (b'm', b'm'+b'x'*1025, b'?bad'):
            script = initial_script()+[(b'qXfer:features:read:target.xml:0,400', response)]
            with self.subTest(response=response[:4]), Peer(script) as peer:
                session = client(peer.wire)
                with self.assertRaises(rsp.RSPError):
                    to_description(session)
                self.assertEqual(session.operations[-1].result, 'error')

    def test_rsp05_independent_register_widths_and_denials(self):
        target = rsp.decode_target_description(TARGET_XML, CORE_XML)
        raw = bytes(range(256))*2+bytes(range(96))
        snapshot = rsp.decode_reset_registers(raw.hex().upper().encode(), target)
        for name, offset, bits in [('rip',128,64),('eflags',136,32),('cr3',204,64),
                                   ('cr8',220,64),('st0',236,80),('mxcsr',604,32)]:
            spec = next(x for x in target.registers if x.name == name)
            self.assertEqual((spec.offset_bytes, spec.bits), (offset,bits))
            self.assertEqual(snapshot.values[spec.regnum], int.from_bytes(raw[offset:offset+bits//8], 'little'))
        for bad in (b'0'*1215, b'0'*1217, b'x'*1216, b' '*1216):
            with self.subTest(length=len(bad)), self.assertRaises(rsp.RSPError):
                rsp.decode_reset_registers(bad, target)

    def test_rsp06_false_mode_reply_is_not_success(self):
        script = initial_script()+description_script()+[(b'g', b'0'*1216),
                  (b'qqemu.Supported', b'PhyMemMode'), (b'qqemu.PhyMemMode', b'0'),
                  (b'Qqemu.PhyMemMode:1', b'OK'), (b'qqemu.PhyMemMode', b'0')]
        with Peer(script) as peer:
            session = client(peer.wire)
            to_description(session)
            session.read_reset_registers(); session.query_qemu_supported()
            session.query_physical_mode(); session.enable_physical_mode()
            with self.assertRaises(rsp.RSPError):
                session.query_physical_mode()
            self.assertEqual(session.operations[-1].result, 'error')
            self.assertFalse(any(data.startswith(b'$m') for data in peer.wire.writes))

    def test_rsp07_forbidden_dispatch_then_allowed_query(self):
        with Peer(initial_script()[:1]) as peer:
            session = client(peer.wire)
            for forbidden in (b'?',b'p10',b'P10=00',b'g',b'm0,1',b'M0,1:00',b'X0,1:x',
                              b'Z0,0,1',b'Z1,0,1',b'z1,0,1',b'c',b's',b'vCont;c',
                              b'D',b'k',b'R',b'qRcmd,00',b'QStartNoAckMode'):
                with self.subTest(forbidden=forbidden), self.assertRaises(rsp.RSPError):
                    session._exchange('supported', forbidden)
            with self.assertRaises(rsp.RSPError):
                session.read_reset_registers()
            self.assertEqual(peer.wire.writes, [])
            self.assertEqual(session.operations, ())
            self.assertIn(b'PacketSize=1000', session.query_supported())
            self.assertEqual(len(session.operations), 1)

    def test_rsp08_absolute_deadline_and_fresh_consumer(self):
        left, right = socket.socketpair()
        try:
            session = client(Wire(left), seconds=5.06)
            start = time.monotonic()
            with self.assertRaises(rsp.RSPError) as caught:
                session.query_supported()
            self.assertEqual(caught.exception.status, 'INCOMPLETE')
            self.assertLess(time.monotonic()-start, .5)
            self.assertEqual(session.operations[-1].result, 'timeout')
        finally:
            left.close(); right.close()
        with Peer(initial_script()[:1]) as peer:
            self.assertIn(b'PacketSize', client(peer.wire).query_supported())

    def test_rsp08_message_budget_prevents_dispatch(self):
        left, right = socket.socketpair()
        try:
            wire = Wire(left)
            session = client(wire)
            session.budget.message_count = 128
            with self.assertRaises(rsp.RSPError):
                session.query_supported()
            self.assertEqual(wire.writes, [])
        finally:
            left.close(); right.close()

    def test_rsp05_forged_target_is_not_a_source_binding(self):
        target = rsp.decode_target_description(TARGET_XML, CORE_XML)
        for fake in (replace(target, core_xml=b'changed'), replace(target, architecture='i386'),
                     replace(target, annexes=('target.xml', '../secret'))):
            with self.subTest(fake=fake.architecture), self.assertRaises(rsp.RSPError):
                rsp.decode_reset_registers(b'0'*1216, fake)

    def test_rsp04_cumulative_xml_limit_no_seventeenth_chunk(self):
        chunks = [(b'qXfer:features:read:target.xml:'+f'{i*1024:x},400'.encode(), b'm'+b'x'*1024)
                  for i in range(16)]
        with Peer(initial_script()+chunks) as peer:
            session = client(peer.wire)
            with self.assertRaises(rsp.RSPError) as caught:
                to_description(session)
            self.assertEqual(caught.exception.reason, 'rsp_xml_limit')
            self.assertEqual(len(session.operations), 22)

    def test_rsp08_cumulative_wire_limit_precedes_write(self):
        left, right = socket.socketpair()
        try:
            wire = Wire(left)
            session = client(wire)
            session._wire_bytes = 262140
            with self.assertRaises(rsp.RSPError) as caught:
                session.query_supported()
            self.assertEqual(caught.exception.reason, 'rsp_wire_limit')
            self.assertEqual(wire.writes, [])
            self.assertEqual(session.operations, ())
        finally:
            left.close(); right.close()

    def test_rsp08_actual_nonblocking_read_retry(self):
        class NonblockingWire(Wire):
            def __init__(self, sock):
                super().__init__(sock)
                self.blocked = 0
                self.interrupted = False

            def read_chunk(self, deadline, max_bytes):
                if not self.interrupted:
                    self.interrupted = True
                    raise InterruptedError('synthetic EINTR')
                self.sock.setblocking(False)
                try:
                    data = self.sock.recv(max_bytes)
                except BlockingIOError:
                    self.blocked += 1
                    raise
                self.reads.append(data)
                return data

        left, right = socket.socketpair()
        wire = NonblockingWire(left)
        def serve():
            try:
                right.settimeout(1)
                right.recv(4096)
                time.sleep(.02)
                right.sendall(b'+'+packet(initial_script()[0][1]))
                right.recv(1)
            finally:
                right.close()
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            self.assertIn(b'PacketSize', client(wire).query_supported())
            self.assertGreater(wire.blocked, 0)
            self.assertTrue(wire.interrupted)
        finally:
            left.close(); thread.join(1)

    def test_rsp02_partial_write_is_terminal_and_not_replayed(self):
        class PartialWire:
            def __init__(self):
                self.actual = bytearray()
                self.calls = 0
            def write_all(self, data, deadline):
                self.calls += 1
                self.actual.extend(data[:3])
                raise InterruptedError('prefix emitted')
            def read_chunk(self, deadline, max_bytes):
                raise AssertionError('read after uncertain write')
        wire = PartialWire()
        session = client(wire)
        with self.assertRaises(rsp.RSPError) as caught:
            session.query_supported()
        self.assertEqual(caught.exception.reason, 'rsp_write_interrupted')
        self.assertEqual((wire.calls, bytes(wire.actual)), (1, b'$qS'))
        self.assertEqual(session.operations[-1].result, 'error')
        with self.assertRaises(rsp.RSPError):
            session.query_supported()
        self.assertEqual(wire.calls, 1)

    def test_rsp08_ack_and_partial_fragments_do_not_reset_deadline(self):
        left, right = socket.socketpair()
        errors = []
        def serve():
            try:
                right.settimeout(1)
                right.recv(4096)
                right.sendall(b'+')
                time.sleep(.02)
                right.sendall(b'$Pack')
                time.sleep(.02)
                right.sendall(b'et')
            except OSError as error:
                errors.append(error)
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            wire = Wire(left)
            session = client(wire, seconds=5.08)
            start = time.monotonic()
            with self.assertRaises(rsp.RSPError):
                session.query_supported()
            self.assertLess(time.monotonic()-start, .5)
            self.assertEqual(session.operations[-1].result, 'timeout')
            self.assertIsNone(session.operations[-1].response_packet)
            self.assertEqual(b''.join(wire.reads), b'+$Packet')
            self.assertEqual(len(wire.writes), 1)
            thread.join(1)
            self.assertEqual(errors, [])
        finally:
            left.close(); right.close(); thread.join(1)

    def test_rsp08_read_allowance_clips_before_wire_allocation(self):
        class LimitedWire:
            def __init__(self):
                self.calls = []
            def write_all(self, data, deadline):
                pass
            def read_chunk(self, deadline, max_bytes):
                self.calls.append(max_bytes)
                if len(self.calls) == 1:
                    return b'+'
                if len(self.calls) == 2:
                    return b'$'
                raise AssertionError('read dispatched after all wire bytes consumed')
        wire = LimitedWire()
        session = client(wire)
        session._wire_bytes = 262144-len(packet(initial_script()[0][0]))-2
        with self.assertRaises(rsp.RSPError) as caught:
            session.query_supported()
        self.assertEqual(caught.exception.reason, 'rsp_wire_limit')
        self.assertEqual(wire.calls, [2, 1])
        self.assertEqual(session.operations[-1].result, 'error')

    def test_rsp02_actual_eof_retains_incomplete_packet(self):
        left, right = socket.socketpair()
        errors = []
        def serve():
            try:
                right.settimeout(1)
                right.recv(4096)
                right.sendall(b'+$PacketSize=1000')
                right.shutdown(socket.SHUT_WR)
            except OSError as error:
                errors.append(error)
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            wire = Wire(left)
            session = client(wire)
            with self.assertRaises(rsp.RSPError) as caught:
                session.query_supported()
            self.assertEqual((caught.exception.status, caught.exception.reason), ('INCOMPLETE','rsp_eof'))
            self.assertEqual(session.operations[-1].result, 'error')
            self.assertIsNone(session.operations[-1].response_packet)
            self.assertEqual(b''.join(wire.reads), b'+$PacketSize=1000')
            self.assertEqual(wire.reads[-1], b'')
            self.assertEqual(len(wire.writes), 1)
            with self.assertRaises(rsp.RSPError):
                session.query_supported()
            self.assertEqual(len(wire.writes), 1)
            thread.join(1)
            self.assertEqual(errors, [])
        finally:
            left.close(); right.close(); thread.join(1)

    def test_rsp08_supplied_wire_timeout_classification(self):
        for reason, stage, expected in (
                ('rsp_request_timeout', 'write', 'timeout'),
                ('rsp_response_timeout', 'read', 'timeout'),
                ('other_timeout', 'read', 'error')):
            with self.subTest(reason=reason):
                class TimeoutWire:
                    def __init__(self):
                        self.writes = 0
                    def write_all(self, data, deadline):
                        self.writes += 1
                        if stage == 'write':
                            raise capture.ProbeError('INCOMPLETE', reason)
                    def read_chunk(self, deadline, max_bytes):
                        raise capture.ProbeError('INCOMPLETE', reason)
                wire = TimeoutWire()
                session = client(wire)
                with self.assertRaises(rsp.RSPError) as caught:
                    session.query_supported()
                self.assertEqual((caught.exception.status, caught.exception.reason), ('INCOMPLETE', reason))
                self.assertEqual(session.operations[-1].result, expected)
                self.assertIsNone(session.operations[-1].response_packet)
                self.assertEqual(wire.writes, 1)
                with self.assertRaises(rsp.RSPError):
                    session.query_supported()
                self.assertEqual(wire.writes, 1)


if __name__ == '__main__':
    unittest.main()
