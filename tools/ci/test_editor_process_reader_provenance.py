"""Synthetic adversarial DTO checks; these are never native runtime evidence."""
import base64
import copy
import json
import unittest

import editor_process_reader as reader
import test_editor_process_reader as existing


def syscall(operation, result, descriptor=None, sender=None, aliases=()):
    return dict(operation=operation, origin='Native', result=result, errno=None,
                sender=sender, msg_flags=0, received_fds=0,
                descriptor_id=descriptor, poll_revents=0, ancillary=[],
                ancillary_descriptor_ids=list(aliases))


def descriptor(identity, role, *, closed=True):
    return dict(role=role, descriptor_id=identity, device=1, inode=1000 + identity,
                byte_len=0, owner_process_id=None, offer_id=None, event='Other',
                mode=0o100500, seals=15, mapping='None',
                disposition='Closed' if closed else 'Held')


def process(pid, pidfd=None):
    return dict(parent_pid=123, child_pid=pid, birth_ticks=5000 + pid,
                pidfd_ledger_id=pidfd, supervisor_native_tid=pid + 100,
                supervisor_rust_id=f'ThreadId({pid})', wait_raw_status=0,
                wait_outcome='Exited(0)', supervisor_joined=True, quarantined=False)


def executable(inode=1010):
    result = dict.fromkeys(('registered_sha256', 'held_sha256', 'source_before_sha256',
                           'source_after_sha256', 'executed_sha256'), 'c' * 64)
    result.update(dict.fromkeys(('source_before_device', 'source_after_device',
                                'held_device', 'executed_device'), 1))
    result.update(dict.fromkeys(('source_before_inode', 'source_after_inode',
                                'held_inode', 'executed_inode'), inode))
    result.update(held_mode=0o100500, held_seals=15, checkpoint_sequence=0,
                  action=None, source_header=[127, 69, 76, 70])
    return result


def bootstrap(channel):
    frame = bytearray(88)
    for offset, value, width in ((0, 384, 4), (4, 1, 4), (8, channel, 8),
                                 (16, 64, 4), (20, 1, 8), (28, channel, 8),
                                 (36, 100, 8), (44, 1, 8), (52, 73, 4),
                                 (56, 640, 4), (60, 480, 4), (64, 2560, 4)):
        frame[offset:offset + width] = value.to_bytes(width, 'little')
    return bytes(frame)


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        # Reuse the existing filesystem/budget fixture, without inheriting its
        # tests or changing its synthetic, diagnostic-only interpretation.
        self.fixture = existing.ReaderTests('test_complete_recording_has_no_runtime_acceptance_claim')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.meta = self.fixture.meta
        self.meta['scope']['channel_generation'] = 2
        self.owners = copy.deepcopy(self.meta['before']['owners'])

    def save(self):
        f = self.fixture
        count = len(list(f.run.iterdir()))
        f.progress['files_written'] = count
        f.save()
        # The old fixture has one raw leaf. Histories add a genuine synthetic
        # file, so recompute the complete declared inventory and budget here.
        ledger = dict(schema_version=1, run_nonce=existing.NONCE, next_run=1,
                      files=count + 1, entries=count + 3,
                      bytes=sum(p.stat().st_size for p in f.run.iterdir()) + 4096,
                      controls=self.meta['controls']['rows'])
        payload = json.dumps(ledger, sort_keys=True, separators=(',', ':')).encode()
        f.put(f.root / '.budget.json', json.dumps(dict(ledger=ledger,
              sha256=reader.digest(payload))).encode().ljust(4096, b' '))

    def check(self):
        self.save()
        return self.fixture.check()

    def scenario(self, name):
        f = self.fixture
        following = f.run.parent / f'{name}-1'
        f.run.rename(following)
        f.run = following
        self.meta['scope']['scenario_id'] = name

    def primary(self):
        self.meta['descriptors'] = [descriptor(10, 'Executable'), descriptor(11, 'Pidfd')]
        self.meta['syscalls'] = [syscall('Fork', 456), syscall('Execveat', 0, 10),
                                 syscall('PidfdOpen', 0, 11), syscall('Waitpid', 456)]
        self.meta['processes'] = [process(456, 11)]
        self.meta.update(executable=executable(), native_wait_outcome='Exited(0)',
                         supervisor_joined=True)

    def sibling(self):
        self.primary()
        sibling = dict(role='ReferencedSibling', source_scope=dict(parent_case='case',
                       scenario_id=None, channel_generation=1),
                       processes=[process(654, 61)],
                       syscalls=[syscall('Fork', 654), syscall('Execveat', 0, 60),
                                 syscall('PidfdOpen', 0, 61), syscall('Waitpid', 654)],
                       descriptors=[descriptor(60, 'Executable'), descriptor(61, 'Pidfd')],
                       executable=executable(1060), owners_after_cleanup=copy.deepcopy(self.owners))
        self.meta['referenced_processes'] = [sibling]
        return sibling

    def history(self):
        self.primary()
        raw = bootstrap(1)
        self.fixture.put(self.fixture.run / 'raw-0002.bin', raw)
        history = dict(role='RetiredBootstrapSource', source_scope=dict(parent_case='case',
                       scenario_id=None, channel_generation=1), raw=dict(index=2,
                       path='raw-0002.bin', bytes=len(raw), sha256=reader.digest(raw)),
                       send=syscall('Sendmsg', 88, 44, aliases=[41, 42, 43]),
                       processes=[process(654, 46)],
                       proof_syscalls=[syscall('Fork', 654), syscall('Execveat', 0, 45),
                           syscall('PidfdOpen', 0, 46), syscall('Waitpid', 654),
                           *[syscall('Close', 0, i) for i in (41, 42, 43, 44)]],
                       descriptors=[descriptor(i, role) for i, role in
                           ((41, 'Selected'), (42, 'TextState'), (43, 'Surface'),
                            (44, 'Control'), (45, 'Executable'), (46, 'Pidfd'))],
                       executable=executable(1045), owners_after_cleanup=copy.deepcopy(self.owners))
        self.meta['retired_bootstraps'] = [history]
        return history

    def helper(self):
        self.scenario('D04CreationPeercredIsNotSender')
        self.primary()
        self.meta['descriptors'] += [descriptor(i, role) for i, role in
            ((20, 'Selected'), (21, 'TextState'), (22, 'Surface'),
             (30, 'Control'), (31, 'Control'))]
        calls = self.meta['syscalls']
        calls += [syscall('PeerCredentials', 0, 30, [123, 1000, 1000]),
                  syscall('Fork', 789), syscall('Waitpid', 789), syscall('Close', 0, 31),
                  syscall('Sendmsg', 88, 30, aliases=[20, 21, 22]),
                  syscall('Recvmsg', 88, 30, [789, 1000, 1000])]
        helper = dict(role='AssertionForkHelper', execution_kind='ForkOnlyNoExec',
                      source_scope=copy.deepcopy({k: self.meta['scope'][k] for k in
                          ('parent_case', 'scenario_id', 'channel_generation')}),
                      process=process(789), syscall_indices=[4, 5, 6, 7],
                      received_syscall_index=9, descriptors=[descriptor(31, 'Control')],
                      creation_peer_credentials=[123, 1000, 1000],
                      received_credentials=[789, 1000, 1000],
                      endpoint_aliases_after_cleanup=0, helper_slots_after_cleanup=0)
        self.meta['fork_helpers'] = [helper]
        self.controls(bootstrap(2))
        return helper

    def controls(self, raw, received=None):
        rows = []
        for i, (kind, index, frame, creds, aliases) in enumerate((
                ('send', 8, raw, None, [20, 21, 22]),
                ('recv', 9, received or raw, [789, 1000, 1000], []))):
            q, s = reader.wire_projection(frame)
            rows.append(dict(i=i + 1, k=kind, d=i, b=base64.b64encode(frame).decode(),
                             c=creds, o=aliases, q=q, s=s, t=i, f=0, r=0))
        payload = b''.join(json.dumps(row, separators=(',', ':')).encode() + b'\n' for row in rows)
        self.fixture.put(self.fixture.run / 'controls.jsonl', payload)
        self.meta['controls'].update(bytes=len(payload), sha256=reader.digest(payload),
                                     rows=2, first_row=1, last_row=2, syscall_indices=[8, 9])

    def test_synthetic_sibling_scope_is_recording_complete_only(self):
        self.sibling()
        self.assertEqual(self.check()['status'], 'RECORDING_COMPLETE')

    def test_sibling_birth_wait_and_elf_are_independently_required(self):
        sibling = self.sibling()
        original = copy.deepcopy(sibling)
        mutations = (('birth_ticks', 0, 'actual birth'),
                     ('wait_raw_status', 256, 'raw wait outcome'),
                     ('child_pid', 655, 'fork-derived'))
        for field, value, diagnostic in mutations:
            with self.subTest(field=field):
                sibling.clear(); sibling.update(copy.deepcopy(original))
                sibling['processes'][0][field] = value
                with self.assertRaisesRegex(reader.Invalid, diagnostic): self.check()
        sibling.clear(); sibling.update(copy.deepcopy(original))
        sibling['executable']['held_sha256'] = 'd' * 64
        with self.assertRaisesRegex(reader.Invalid, 'held ELF'): self.check()

    def test_sibling_scope_channel_and_closed_owners_are_bound(self):
        sibling = self.sibling()
        for key, value in (('parent_case', 'other'), ('scenario_id', 'D12ForeignChildText'),
                           ('channel_generation', 2)):
            original = sibling['source_scope'][key]
            with self.subTest(key=key):
                sibling['source_scope'][key] = value
                with self.assertRaisesRegex(reader.Invalid, 'unarmed sibling channel'): self.check()
            sibling['source_scope'][key] = original
        sibling['owners_after_cleanup']['maps'] = 1
        with self.assertRaisesRegex(reader.Invalid, 'sibling owners closed'): self.check()

    def test_sibling_cannot_hide_a_missing_terminal_wait_or_unknown_fd(self):
        sibling = self.sibling()
        wait = sibling['syscalls'].pop()
        with self.assertRaisesRegex(reader.Invalid, 'actual consuming wait'): self.check()
        sibling['syscalls'].append(wait)
        sibling['syscalls'][1]['descriptor_id'] = 999
        with self.assertRaisesRegex(reader.Invalid, 'syscall descriptor'): self.check()

    def test_complete_dto_does_not_override_root_source_or_run_nonce(self):
        self.sibling()
        for key, value in (('source_manifest_sha256', 'd' * 64), ('run_nonce', 'e' * 32)):
            original = self.meta[key]
            with self.subTest(key=key):
                self.meta[key] = value
                with self.assertRaisesRegex(reader.Invalid, 'record provenance'): self.check()
            self.meta[key] = original

    def test_synthetic_retired_bootstrap_has_complete_separate_provenance(self):
        self.history()
        self.assertEqual(self.check()['status'], 'RECORDING_COMPLETE')

    def test_retired_bootstrap_requires_each_alias_actual_close(self):
        history = self.history()
        history['proof_syscalls'] = [c for c in history['proof_syscalls']
            if not (c['operation'] == 'Close' and c['descriptor_id'] == 42)]
        with self.assertRaisesRegex(reader.Invalid, 'old alias close proof'): self.check()

    def test_retired_channel_and_same_parent_case_are_bound(self):
        history = self.history()
        for key, value in (('channel_generation', 2), ('parent_case', 'other')):
            prior = history['source_scope'][key]
            with self.subTest(key=key):
                history['source_scope'][key] = value
                with self.assertRaisesRegex(reader.Invalid, 'retired channel'): self.check()
            history['source_scope'][key] = prior

    def test_retired_alias_roles_and_held_image_cannot_be_substituted(self):
        history = self.history()
        history['descriptors'][0]['role'] = 'Surface'
        with self.assertRaisesRegex(reader.Invalid, 'old offered alias roles'): self.check()
        history['descriptors'][0]['role'] = 'Selected'
        history['executable']['executed_inode'] += 1
        with self.assertRaisesRegex(reader.Invalid, 'executed held ELF'): self.check()

    def test_retired_cleanup_and_real_birth_are_required(self):
        history = self.history()
        history['owners_after_cleanup']['fixed'] = 1
        with self.assertRaisesRegex(reader.Invalid, 'owners genuinely closed'): self.check()
        history['owners_after_cleanup']['fixed'] = 0
        history['processes'][0]['birth_ticks'] = None
        with self.assertRaisesRegex(reader.Invalid, 'genuine birth'): self.check()

    def test_retired_source_cannot_reuse_current_pid_or_duplicate_aliases(self):
        history = self.history()
        history['send']['ancillary_descriptor_ids'] = [41, 42, 42]
        with self.assertRaisesRegex(reader.Invalid, 'old bootstrap send'): self.check()
        history['send']['ancillary_descriptor_ids'] = [41, 42, 43]
        history['processes'][0]['child_pid'] = 456
        for call in history['proof_syscalls']:
            if call['operation'] in ('Fork', 'Waitpid'):
                call['result'] = 456
        with self.assertRaisesRegex(reader.Invalid, 'distinct retired source'): self.check()

    def test_synthetic_fork_only_helper_joins_actual_recv_and_peercred(self):
        self.helper()
        self.assertEqual(self.check()['status'], 'RECORDING_COMPLETE')

    def test_helper_close_must_be_in_its_actual_indexed_native_calls(self):
        helper = self.helper()
        helper['syscall_indices'].remove(7)
        with self.assertRaisesRegex(reader.Invalid, 'helper endpoint close proof'): self.check()

    def test_helper_closed_label_does_not_replace_successful_native_close(self):
        self.helper()
        self.meta['syscalls'][7].update(result=-1, errno=5)
        with self.assertRaisesRegex(reader.Invalid, 'helper endpoint close proof'): self.check()

    def test_helper_kernel_pid_and_creation_credentials_are_distinct_actual_joins(self):
        helper = self.helper()
        helper['received_credentials'][0] = 790
        with self.assertRaisesRegex(reader.Invalid, 'helper kernel sender'): self.check()
        helper['received_credentials'][0] = 789
        helper['creation_peer_credentials'][0] = 124
        with self.assertRaisesRegex(reader.Invalid, 'same-socket creation credentials'): self.check()

    def test_helper_cannot_claim_exec_pidfd_or_other_scope(self):
        helper = self.helper()
        helper['process']['pidfd_ledger_id'] = 11
        with self.assertRaisesRegex(reader.Invalid, 'invented pidfd'): self.check()
        helper['process']['pidfd_ledger_id'] = None
        helper['source_scope']['channel_generation'] = 3
        with self.assertRaisesRegex(reader.Invalid, 'helper scope'): self.check()
        helper['source_scope']['channel_generation'] = 2
        helper['execution_kind'] = 'EditorExec'
        with self.assertRaisesRegex(reader.Invalid, 'never claims editor ELF'): self.check()

    def test_helper_receive_must_follow_its_copied_actual_bootstrap(self):
        self.helper()
        altered = bytearray(bootstrap(2)); altered[36] ^= 1
        self.controls(bootstrap(2), bytes(altered))
        with self.assertRaisesRegex(reader.Invalid, 'copied bootstrap'): self.check()

    def test_helper_join_label_cannot_replace_birth_and_raw_wait(self):
        helper = self.helper()
        helper['process']['birth_ticks'] = None
        with self.assertRaisesRegex(reader.Invalid, 'genuine birth'): self.check()
        helper['process']['birth_ticks'] = 5789
        helper['process']['wait_raw_status'] = 9
        with self.assertRaisesRegex(reader.Invalid, 'raw wait outcome decode'): self.check()


if __name__ == '__main__':
    unittest.main()
