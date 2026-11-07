"""Private socket controls for typed physical dispatch and closed teardown."""
from dataclasses import replace
from itertools import product
import json
import socket
import time
import unittest
from unittest.mock import patch

from boot_profile_capture import ProbeError
import run0_rsp as rsp
import run0_c0_acquire as acquire
import run0_c0_budget as budget
import run0_c0_wire as wire_module
import test_run0_c0_host as host_fixture
import test_run0_c0_acquire as acquire_fixture
from test_run0_c0_wire import frame


class OwnedWireControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        host_fixture.HostJoinControls.setUpClass.__func__(cls)
        acquire_fixture.AcquisitionControls.setUpClass()

    @classmethod
    def tearDownClass(cls):
        acquire_fixture.AcquisitionControls.tearDownClass()
    setUp = host_fixture.HostJoinControls.setUp
    endpoints = host_fixture.HostJoinControls.endpoints
    pipe = host_fixture.HostJoinControls.pipe
    peer_task = host_fixture.HostJoinControls.peer_task
    recv_exact = host_fixture.HostJoinControls.recv_exact
    wire = host_fixture.HostJoinControls.wire
    fixture = host_fixture.HostJoinControls.fixture
    no_next_request = host_fixture.HostJoinControls.no_next_request
    session = host_fixture.HostJoinControls.session
    script = host_fixture.HostJoinControls.script
    ready = host_fixture.HostJoinControls.ready
    install = host_fixture.HostJoinControls.install
    successful_stop = host_fixture.HostJoinControls.successful_stop
    stopped = host_fixture.HostJoinControls.stopped
    mode = host_fixture.HostJoinControls.mode
    registers = host_fixture.HostJoinControls.registers

    def test_ordinary_rsp_replies_never_become_async_events(self):
        wire, _, peer, confirmed, values = self.stopped()
        self.mode(wire, peer, confirmed)
        self.registers(wire, peer, confirmed, values)
        self.assertEqual([(event.name, event.seq) for event in wire.events if event.protocol == 'rsp'],
                         [('T05thread:01;', confirmed.stop.stop_event_seq)])

    def test_closed_owned_wire_methods_exist(self):
        for name in ('bind_acquisition', 'read_physical', 'complete_acquisition',
                     'clear_entry_breakpoint', 'request_quit', 'drain_after_quit'):
            self.assertTrue(callable(getattr(wire_module.C0Wire, name, None)),
                            'owned wire method absent: expected gate-first RED: '+name)

    def packet_fixture(self):
        """Private synthetic prefix only; never calls/promotes public registration."""
        qmp, qpeer = self.endpoints()
        endpoint, peer = self.endpoints()
        started = time.monotonic_ns()
        accounting = budget.C0Accounting(started)
        wire = wire_module.C0Wire(qmp, {'rsp': endpoint}, started_ns=started, accounting=accounting)
        self.addCleanup(wire.close)
        if wire.transport_identity[1] < 0:
            # macOS reports dev=-1 for socketpair; this private packet fixture
            # uses an explicitly synthetic tuple, never a production issuer.
            self.stack.enter_context(patch.object(wire_module.C0Wire, 'transport_identity',
                new=property(lambda owner: ('fixture-rsp', 0, owner._rsp_socket.fileno()))))
        fixture = acquire_fixture.AcquisitionControls()
        binding = fixture.binding(transport_identity=wire.transport_identity,
                                  vm_deadline_ns=wire._deadline)
        wire._session = binding.wire_identity
        wire._entry_stop = binding.confirmed_stop.stop
        wire._confirmed_stop = binding.confirmed_stop
        wire._stop_epoch = binding.admission_epoch
        wire._entry_state = 'confirmed'
        wire._rsp_ready = wire._rsp_active = True
        wire._rsp_decoder = rsp._C0AckDecoder()
        for seq in range(1, binding.proof_prefix[-1][1]+1):
            accounting._reserve_operation('fixture_prefix')
            wire._operations.append(wire_module.Operation(seq, 'rsp', 'fixture_prefix',
                                                         binding.stop_ns, binding.stop_ns, result='ok'))
        ledger = accounting.make_acquisition_ledger()
        session = acquire.AcquisitionSession(fixture.prior, fixture.pinned, binding, ledger)
        accounting.attach_acquisition(ledger)
        wire._registered_binding = object()  # explicit private protocol seam, not producer receipt
        wire._current_binding, wire._current_acquisition = binding, session
        wire._ram_transport_identity, wire._admission_epoch = wire.transport_identity, wire.admission_epoch
        grant = session.next_request()
        memory = fixture.memory()
        data = bytes(memory[grant.intent.physical+i] for i in range(grant.intent.length))
        return wire, qpeer, endpoint, peer, accounting, session, grant, data

    def test_actual_packet_receipt_redeems_one_credit_and_accepts_without_event_pollution(self):
        wire, _, _, peer, accounting, session, grant, data = self.packet_fixture()
        before = dict(session.ledger.values)
        payload = f'm{grant.intent.physical:x},{grant.intent.length:x}'.encode()
        done = self.script(peer, [(payload, data.hex().encode())])
        receipt = wire.read_physical(grant)
        done()
        self.assertEqual(receipt.data, data)
        self.assertEqual(receipt.operation_seq, wire.operations[-1].seq)
        self.assertEqual(receipt.finished_ns, wire.operations[-1].finished_ns)
        self.assertEqual(wire.events, ())
        self.assertEqual(dict(session.ledger.values), before)  # prepaid raw/receipt/driver data
        session.accept(grant, receipt)
        self.assertIsNone(session.failure)
        with self.assertRaises(ProbeError):
            wire.read_physical(grant)
        self.assertLessEqual(accounting.actual_bytes, accounting.committed_bytes)

    def test_named_read_credit_exhaustion_uses_extra_common_space_without_borrowing(self):
        wire, _, _, peer, accounting, session, grant, data = self.packet_fixture()
        done = self.script(peer, [(f'm{grant.intent.physical:x},{grant.intent.length:x}'.encode(),
                                  data.hex().encode())])
        receipt = wire.read_physical(grant)
        done()
        key = ('read', grant.intent.request_id, receipt.operation_seq)
        remaining = accounting._credits[key]['remaining']
        before = session.ledger.values['retained_bytes']
        accounting.reserve_output(remaining+1, key)
        self.assertEqual(session.ledger.values['retained_bytes'], before+1)
        self.assertEqual(accounting._credits[key]['remaining'], 0)
        with self.assertRaises(ProbeError):
            accounting.redeem_read(grant, receipt.operation_seq)
        with self.assertRaises(ProbeError):
            accounting.reserve_output(1, ('read', grant.intent.request_id+1, receipt.operation_seq))
        accounting.reserve_output(accounting.available(), 'output')
        exhausted = dict(session.ledger.values)
        with self.assertRaises(ProbeError):
            accounting.reserve_output(1, key)
        self.assertEqual(dict(session.ledger.values), exhausted)
        self.assertLessEqual(accounting.actual_bytes, accounting.committed_bytes)

    def test_oversize_physical_reply_is_retained_and_never_accepted(self):
        wire, _, _, peer, _, session, grant, data = self.packet_fixture()
        command = rsp.encode_packet(f'm{grant.intent.physical:x},{grant.intent.length:x}'.encode())
        payload = (data+b'x').hex().encode()
        response = b'$'+payload+b'#'+f'{sum(payload) & 255:02x}'.encode()
        done = self.peer_task(lambda: (self.recv_exact(peer, command), peer.sendall(b'+'+response)))
        with self.assertRaises(ProbeError):
            wire.read_physical(grant)
        done()
        self.assertIsNotNone(wire.failure)
        self.assertIsNotNone(session.failure)
        self.assertTrue(wire.raw('rsp').startswith(b'+$'))
        self.assertNotEqual(wire.operations[-1].result, 'ok')

    def test_pending_row_and_quiet_wait_precede_the_only_consume(self):
        wire, _, _, peer, _, session, grant, _ = self.packet_fixture()
        quiet = wire._rsp_quiet
        calls = []
        def stale(deadline):
            self.assertEqual(wire.operations[-1].result, 'pending')
            calls.append('quiet')
            quiet(deadline)
            wire._stop_epoch += 1
        with patch.object(wire, '_rsp_quiet', side_effect=stale), \
             patch.object(session, 'consume_for_dispatch', wraps=session.consume_for_dispatch) as consume:
            with self.assertRaisesRegex(ProbeError, 'acquire_stale_epoch'):
                wire.read_physical(grant)
            self.assertEqual(consume.call_count, 1)
        self.assertEqual(calls, ['quiet'])
        self.assertIsNone(wire.operations[-1].request)
        self.assertIsNotNone(session.failure)
        self.no_next_request(peer)

    def test_first_send_backpressure_rechecks_epoch_cancel_deadline_or_close_without_reconsume(self):
        for syscall_error, change in product((BlockingIOError, InterruptedError),
                                            ('epoch', 'cancel', 'deadline', 'close')):
            wire, _, endpoint, peer, _, session, grant, _ = self.packet_fixture()
            send, poll = socket.socket.send, wire._poll
            attempted = []
            def blocked(sock, data, *args):
                if sock is endpoint and not attempted:
                    attempted.append(bytes(data))
                    raise syscall_error()
                return send(sock, data, *args)
            def altered(deadline, reason, **kwargs):
                if kwargs.get('writing') == 'rsp':
                    if change == 'cancel':
                        raise KeyboardInterrupt()
                    if change == 'epoch':
                        wire._stop_epoch += 1
                    elif change == 'deadline':
                        wire._deadline = time.monotonic_ns()-1
                    else:
                        wire._closed = True
                        wire._latch_failure(wire_module.Failure('INCOMPLETE', 'c0_wire_closed'))
                return poll(deadline, reason, **kwargs)
            with self.subTest(syscall_error=syscall_error, change=change), patch.object(socket.socket, 'send', blocked), \
                 patch.object(wire, '_poll', side_effect=altered), \
                 patch.object(session, 'consume_for_dispatch', wraps=session.consume_for_dispatch) as consume:
                with self.assertRaises((ProbeError, KeyboardInterrupt)):
                    wire.read_physical(grant)
                self.assertEqual(consume.call_count, 1)
            wire._closed = False  # private fixture permits normal selector cleanup
            self.assertEqual(wire.raw('rsp-out'), b'')
            self.assertIsNone(wire.operations[-1].request)
            self.assertIsNotNone(session.failure)
            self.no_next_request(peer)

    def test_partial_read_send_retains_prefix_and_never_refunds_the_credit(self):
        wire, _, endpoint, peer, accounting, session, grant, _ = self.packet_fixture()
        send = socket.socket.send
        calls = []
        def partial(sock, data, *args):
            if sock is endpoint:
                calls.append(bytes(data))
                if len(calls) == 1:
                    return send(sock, data[:3], *args)
                raise OSError(5, 'fixture write failure')
            return send(sock, data, *args)
        reserved = dict(session.ledger.values)
        with patch.object(socket.socket, 'send', partial), self.assertRaisesRegex(ProbeError, 'rsp_write_error'):
            wire.read_physical(grant)
        self.assertEqual(len(wire.raw('rsp-out')), 3)
        self.assertEqual(wire.operations[-1].request.length, 3)
        self.assertEqual(dict(session.ledger.values), reserved)
        self.assertIsNotNone(session.failure)
        self.assertEqual(len(accounting._credits), 1)

    def test_blocked_stop_ack_rejects_a_new_partial_rsp_tail_before_plus(self):
        wire, qmp, endpoint, peer, token = self.ready()
        self.install(wire, peer, token)
        send = socket.socket.send
        blocked = []
        def inject(sock, data, *args):
            if sock is endpoint and bytes(data) == b'+' and not blocked:
                blocked.append(True)
                peer.sendall(b'$')
                raise BlockingIOError()
            return send(sock, data, *args)
        def exchange():
            self.recv_exact(peer, host_fixture.entry_fixture.packet(b'c'))
            qmp.sendall(host_fixture.entry_fixture.RESUME + host_fixture.entry_fixture.STOP)
            peer.sendall(b'+' + host_fixture.entry_fixture.RSP_STOP)
        done = self.peer_task(exchange)
        before = len(wire.raw('rsp-out'))
        with patch.object(socket.socket, 'send', inject), self.assertRaisesRegex(ProbeError, 'rsp_unsolicited'):
            wire.resume_to_entry()
        done()
        self.assertEqual(wire.raw('rsp-out')[before:], host_fixture.entry_fixture.packet(b'c'))
        self.assertIsNone(wire.operations[-1].request)

    def test_real_prefix_usage_is_seeded_and_non_factory_ledger_cannot_attach(self):
        qmp, peer = self.endpoints()
        started = time.monotonic_ns()
        accounting = budget.C0Accounting(started)
        wire = wire_module.C0Wire(qmp, {}, started_ns=started, accounting=accounting)
        self.addCleanup(wire.close)
        self.fixture(wire, peer)
        accounting.reserve_output(29, 'output')  # immutable collector prefix copy
        ledger = accounting.make_acquisition_ledger()
        self.assertEqual(ledger.values['operations'], len(wire.operations))
        self.assertEqual(ledger.values['retained_bytes'], wire._charged)
        self.assertEqual(accounting.actual_operations, 3)
        with self.assertRaises(ProbeError):
            accounting.attach_acquisition(acquire.AcquisitionLedger(tuple(ledger.values.items())))
        accounting.attach_acquisition(ledger)
        with self.assertRaises(ProbeError):
            accounting.attach_acquisition(ledger)

    def quit_fixture(self, *, reply=True, tail=None):
        qmp, peer = self.endpoints()
        streams, peers = {}, {}
        for name in ('rsp', 'serial', 'debug', 'qemu_stdout', 'qemu_stderr'):
            streams[name], peers[name] = self.endpoints()
        wire = self.wire(qmp, streams)
        self.fixture(wire, peer)
        wire._rsp_active = True
        wire._rsp_decoder = rsp._C0AckDecoder()
        expected = b'{"execute":"quit","id":4}'
        def exchange():
            self.recv_exact(peer, expected)
            if tail == 'wrong_id':
                peer.sendall(frame({'return': {}, 'id': 99}))
            elif reply:
                peer.sendall(frame({'event':'SHUTDOWN','timestamp':{'seconds':1,'microseconds':0},
                                   'data':{'guest':False,'reason':'host-qmp-quit'}})
                             +frame({'return':{},'id':4}))
            if tail == 'rsp':
                peers['rsp'].sendall(host_fixture.entry_fixture.packet(b'W00'))
            elif tail == 'partial_qmp':
                peer.sendall(b'{"event":')
            elif tail == 'duplicate_shutdown':
                peer.sendall(frame({'event':'SHUTDOWN','timestamp':{'seconds':1,'microseconds':1},
                                   'data':{'guest':False,'reason':'host-qmp-quit'}}))
            peer.shutdown(socket.SHUT_WR)
            peers['rsp'].shutdown(socket.SHUT_WR)
            # These actual later tails must still be read after control EOFs.
            time.sleep(0.01)
            for name in ('serial', 'debug', 'qemu_stdout', 'qemu_stderr'):
                peers[name].sendall(name.encode())
                peers[name].shutdown(socket.SHUT_WR)
        done = self.peer_task(exchange)
        receipt = wire.request_quit()
        drained = wire.drain_after_quit(receipt, deadline_ns=wire._owner_deadline)
        done()
        self.assertTrue(wire.raw('qmp-out').endswith(expected))
        return wire, receipt, drained

    def test_undelimited_quit_actual_reply_shutdown_and_all_six_late_eofs(self):
        wire, receipt, drained = self.quit_fixture()
        self.assertEqual(receipt.operation.result, 'ok')
        self.assertIsNotNone(receipt.operation.response)
        self.assertIsNotNone(receipt.shutdown_event_seq)
        self.assertEqual(len(drained.eofs), 6)
        self.assertIsNone(drained.first_failure)
        for name in ('serial', 'debug', 'qemu_stdout', 'qemu_stderr'):
            self.assertEqual(wire.raw(name), name.encode())
        with self.assertRaises(ProbeError):
            wire.request_quit()

    def test_quit_poll_observing_existing_eof_sends_nothing_and_creates_no_operation(self):
        endpoint, peer = self.endpoints()
        wire = self.wire(endpoint)
        self.fixture(wire, peer)
        before_bytes, before_operations = wire.raw('qmp-out'), wire.operations
        peer.shutdown(socket.SHUT_WR)
        with self.assertRaises(ProbeError):
            wire.request_quit()
        self.assertTrue(wire._qmp_eof)
        self.assertEqual(wire.raw('qmp-out'), before_bytes)
        self.assertEqual(wire.operations, before_operations)
        self.assertIsNone(wire._quit)
        self.assertFalse(wire._quitting)
        peer.settimeout(0.02)
        with self.assertRaises(socket.timeout):
            peer.recv(1)

    def test_eof_only_quit_is_retained_incomplete_and_never_fabricates_reply(self):
        _, receipt, drained = self.quit_fixture(reply=False)
        self.assertEqual(receipt.operation.result, 'error')
        self.assertIsNone(receipt.operation.response)
        self.assertEqual(drained.first_failure.reason, 'qmp_quit_reply_missing')
        self.assertEqual(len(drained.eofs), 6)

    def test_wrong_quit_id_or_unexpected_rsp_exit_packet_keeps_first_cause(self):
        for tail, reason in (('wrong_id','qmp_quit_response'),('rsp','rsp_quit_tail'),
                             ('partial_qmp','qmp_quit_partial'),
                             ('duplicate_shutdown','qmp_quit_shutdown')):
            with self.subTest(tail=tail):
                _, receipt, drained = self.quit_fixture(tail=tail)
                self.assertEqual(drained.first_failure.reason, reason)
                self.assertEqual(len(drained.eofs), 6)
                if tail == 'rsp':
                    self.assertEqual(drained.rsp_pending_frames, 1)

    def test_late_matching_reply_never_repairs_timed_out_quit(self):
        qmp, peer = self.endpoints()
        streams, peers = {}, {}
        for name in ('rsp', 'serial', 'debug', 'qemu_stdout', 'qemu_stderr'):
            streams[name], peers[name] = self.endpoints()
        wire = self.wire(qmp, streams)
        self.fixture(wire, peer)
        wire._rsp_active, wire._rsp_decoder = True, rsp._C0AckDecoder()
        done = self.peer_task(lambda: self.recv_exact(peer, b'{"execute":"quit","id":4}'))
        with patch.object(wire_module, 'RESPONSE_NS', 10_000_000):
            receipt = wire.request_quit()
        done()
        self.assertEqual(receipt.operation.result, 'timeout')
        self.assertIsNone(receipt.operation.response)
        first = receipt.first_failure
        peer.sendall(frame({'return':{},'id':4}))
        peer.shutdown(socket.SHUT_WR)
        for endpoint in peers.values():
            endpoint.shutdown(socket.SHUT_WR)
        drained = wire.drain_after_quit(receipt, deadline_ns=wire._owner_deadline)
        self.assertEqual(len(drained.eofs), 6)
        self.assertEqual(drained.first_failure, first)
        self.assertEqual(receipt.operation.result, 'timeout')
        self.assertIsNone(receipt.operation.response)

    def test_clear_requires_finished_after_state_then_sends_only_the_original_z1(self):
        wire, _, _, peer, accounting, session, _, _ = self.packet_fixture()
        confirmed = wire._confirmed_stop
        with self.assertRaisesRegex(ProbeError, 'c0_clear_state'):
            wire.clear_entry_breakpoint(confirmed)
        # Only a private packet fixture: this does not issue a producer receipt,
        # synthesize live origin, or activate the public acquisition registration.
        wire._layout_after = wire._final_register_view = object()
        session._finished = True
        accounting._tail = 31
        request = f'z1,{confirmed.stop.entry_address:x},1'.encode()
        done = self.script(peer, [(request,b'OK')])
        receipt = wire.clear_entry_breakpoint(confirmed)
        done()
        self.assertEqual(receipt.entry_address, confirmed.stop.entry_address)
        self.assertEqual(receipt.operation.operation, 'hardware_breakpoint_clear')
        self.assertEqual(receipt.operation.result, 'ok')
        with self.assertRaises(ProbeError):
            wire.clear_entry_breakpoint(confirmed)
        self.no_next_request(peer)

    def test_public_registration_rejects_missing_or_unissued_binding_without_read(self):
        wire, qmp, peer, confirmed, _ = self.stopped()
        for binding in (None, {}, object()):
            with self.assertRaises(ProbeError):
                wire.bind_acquisition(binding, object())
        self.assertIsNone(wire._registered_binding)
        self.assertIsNone(wire._current_acquisition)
        self.no_next_request(qmp)
        self.no_next_request(peer)

    def test_failed_owner_without_quit_drains_actual_tails_but_never_flushes_pending_write(self):
        qmp, peer = self.endpoints()
        streams, peers = {}, {}
        for name in ('rsp', 'serial', 'debug', 'qemu_stdout', 'qemu_stderr'):
            streams[name], peers[name] = self.endpoints()
        wire = self.wire(qmp, streams)
        wire._rsp_active, wire._rsp_decoder = True, rsp._C0AckDecoder()
        # A retained failed prefix is evidence, never bytes to resume sending.
        wire._raw['qmp-out'].extend(b'{"execute":')
        wire._latch_failure(wire_module.Failure('DENY','fixture_ambiguous_qmp'))
        with self.assertRaises(ProbeError):
            wire.request_quit()  # no greeting and no quit receipt
        before = wire.raw('qmp-out'), wire.raw('rsp-out')
        peer.sendall(b'{"return":')
        peer.shutdown(socket.SHUT_WR)
        peers['rsp'].sendall(b'$')
        for name, endpoint in peers.items():
            if name != 'rsp':
                endpoint.sendall(name.encode())
            endpoint.shutdown(socket.SHUT_WR)
        receipt = wire._drain_failed_owner(deadline_ns=wire._owner_deadline)
        self.assertIsNone(receipt.quit_receipt)
        self.assertEqual(len(receipt.eofs), 6)
        self.assertEqual(receipt.first_failure.reason, 'fixture_ambiguous_qmp')
        self.assertEqual(receipt.qmp_pending_bytes, len(b'{"return":'))
        self.assertEqual(receipt.rsp_pending_bytes, 1)
        self.assertEqual((wire.raw('qmp-out'), wire.raw('rsp-out')), before)
        self.assertEqual(wire.operations, ())
        self.no_next_request(peer)
        with self.assertRaises(ProbeError):
            wire.request_quit()

    def test_failed_owner_pump_requires_failure_and_preserves_original_deadline(self):
        qmp, _ = self.endpoints()
        wire = self.wire(qmp)
        with self.assertRaisesRegex(ProbeError, 'c0_failed_drain_state'):
            wire._drain_failed_owner(deadline_ns=wire._owner_deadline)
        wire._latch_failure(wire_module.Failure('INCOMPLETE','fixture_first'))
        with patch.object(wire_module.time, 'monotonic_ns', return_value=wire._owner_deadline):
            receipt = wire._drain_failed_owner(deadline_ns=wire._owner_deadline+100_000_000)
        self.assertEqual(receipt.first_failure.reason, 'fixture_first')
        self.assertEqual(receipt.eofs, ())
        self.assertIsNone(receipt.quit_receipt)

    def test_failed_drain_can_retain_later_eofs_without_renewing_quit_or_sending_again(self):
        qmp, peer = self.endpoints()
        streams, peers = {}, {}
        for name in ('rsp', 'serial', 'debug', 'qemu_stdout', 'qemu_stderr'):
            streams[name], peers[name] = self.endpoints()
        wire = self.wire(qmp, streams)
        self.fixture(wire, peer)
        wire._rsp_active, wire._rsp_decoder = True, rsp._C0AckDecoder()
        def exchange():
            self.recv_exact(peer, b'{"execute":"quit","id":4}')
            peer.sendall(frame({'return':{},'id':4}))
        done = self.peer_task(exchange)
        quit_receipt = wire.request_quit()
        done()
        first = wire.drain_after_quit(quit_receipt, deadline_ns=time.monotonic_ns()+5_000_000)
        self.assertEqual(first.first_failure.reason, 'c0_drain_timeout')
        before = wire.raw('qmp-out'), wire.raw('rsp-out')
        peer.shutdown(socket.SHUT_WR)
        for endpoint in peers.values():
            endpoint.shutdown(socket.SHUT_WR)
        second = wire.drain_after_quit(quit_receipt, deadline_ns=wire._owner_deadline+100_000_000)
        self.assertEqual(len(second.eofs), 6)
        self.assertEqual(second.first_failure, first.first_failure)
        self.assertEqual(quit_receipt.operation.result, 'ok')
        self.assertEqual((wire.raw('qmp-out'), wire.raw('rsp-out')), before)

    def test_terminal_drain_clips_even_failure_cleanup_to_original_owner_deadline(self):
        qmp, peer = self.endpoints()
        wire = self.wire(qmp)
        self.fixture(wire, peer)
        done = self.peer_task(lambda: (self.recv_exact(peer, b'{"execute":"quit","id":4}'),
                                      peer.sendall(frame({'return':{},'id':4}))))
        receipt = wire.request_quit()
        done()
        wire._latch_failure(wire_module.Failure('INCOMPLETE','fixture_original_failure'))
        with patch.object(wire_module.time, 'monotonic_ns', return_value=wire._owner_deadline):
            drained = wire.drain_after_quit(receipt, deadline_ns=wire._owner_deadline+10_000_000)
        self.assertEqual(drained.first_failure.reason, 'fixture_original_failure')
        self.assertEqual(drained.eofs, ())


if __name__ == '__main__':
    unittest.main()
