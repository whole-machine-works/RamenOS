"""Adversarial diagnostic-reader checks; synthetic data never proves native behavior."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
import editor_process_reader as reader

NONCE='a'*32
SOURCE='b'*64
class ReaderTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.run=self.root/'case'/'D02WrongRegisteredDigest-1';self.run.mkdir(parents=True,mode=0o700);self.run.parent.chmod(0o700)
        raw={'index':1,'path':'raw-0001.bin','bytes':0,'sha256':reader.digest(b'')}
        owners={k:0 for k in ('data','fixed','combined','maps','children','supervisors','pending_inputs','ordinary_queue','reset_queue','lifetime_objects','lifetime_offers','lifetime_bytes')}
        snapshot={'app_pixels':raw,'composed_pixels':raw,'app_sha256':reader.digest(b''),'composed_sha256':reader.digest(b''),'owners':owners}
        self.meta={'schema_version':1,'run_nonce':NONCE,'source_manifest_sha256':SOURCE,'scope':{'parent_case':'case','scenario_id':'D02WrongRegisteredDigest','run_ordinal':1,'parent_pid':123,'channel_generation':0},'recording_complete':True,'before':snapshot,'after':copy.deepcopy(snapshot),'objects':[],'descriptors':[],'syscalls':[],'processes':[],'controls':{'path':'controls.jsonl','bytes':0,'sha256':reader.digest(b''),'rows':0,'first_row':0,'last_row':0,'syscall_indices':[]}}
        for snapshot in (self.meta['before'],self.meta['after']):
            snapshot.update({'core_ordinary_queue':0,'core_reset_queue':0,'offer_cursor':0,'frame_surface_id':None,'frame_surface_generation':None,'frame_surface_epoch':None,'frame_surface_live':None,'owner_confirm_request':None,'owner_confirm_status':None,'document':None,'adoption_status':None,'pending_offer_id':None})
            snapshot.update({k:0 for k in ('focus_epoch','service_epoch','channel_generation','publication_generation','delivered_sequence','acknowledged_sequence','request_sequence','syscall_count','control_count','descriptor_count')})
            snapshot.update({k:None for k in ('admitted_at_ns','child_deadline_ns','captured_at_ns','save_deadline_ns')})
        self.meta.update({'checkpoints':[],'executable':None,'native_wait_outcome':None,'supervisor_joined':False,'quarantined':False,'referenced_processes':[],'retired_bootstraps':[],'fork_helpers':[]})
        self.progress={'schema_version':1,'run_nonce':NONCE,'run_ordinal':1,'recording_complete':True,'files_written':4}
        self.put(self.run/'raw-0001.bin',b'');self.put(self.run/'controls.jsonl',b'');self.save()
    def put(self,path,raw):
        path.write_bytes(raw);path.chmod(0o600)
    def save(self):
        self.put(self.run/'metadata.json',json.dumps(self.meta,separators=(',',':')).encode()+b'\n')
        self.put(self.run/'progress.json',json.dumps(self.progress).encode().ljust(4096,b' '))
        size=sum(p.stat().st_size for p in self.run.iterdir())+4096
        ledger={'schema_version':1,'run_nonce':NONCE,'next_run':1,'files':5,'entries':7,'bytes':size,'controls':self.meta['controls']['rows']}
        payload=json.dumps(ledger,sort_keys=True,separators=(',',':')).encode()
        self.put(self.root/'.budget.json',json.dumps({'ledger':ledger,'sha256':reader.digest(payload)}).encode().ljust(4096,b' '))
    def check(self):return reader.inspect(self.root,NONCE,SOURCE)
    def native_control(self, *, duplicate=False, wrong_request=False):
        import base64
        frame=bytearray(88)
        for offset,value in [(0,384),(4,4),(16,64),(20,7),(36,1)]:frame[offset:offset+4]=value.to_bytes(4,'little')
        call={'operation':'Sendmsg','origin':'Native','result':88,'errno':None,'sender':None,'msg_flags':0,'received_fds':0,'descriptor_id':None,'poll_revents':0,'ancillary':[],'ancillary_descriptor_ids':[]}
        self.meta['syscalls']=[call]
        count=2 if duplicate else 1
        lines=[]
        for i in range(count):
            row={'i':i+1,'k':'send','d':0,'b':base64.b64encode(frame).decode(),'c':None,'o':[],'q':8 if wrong_request else 7,'s':0,'t':i,'f':0,'r':0}
            lines.append(json.dumps(row,separators=(',',':')).encode()+b'\n')
        raw=b''.join(lines);self.put(self.run/'controls.jsonl',raw)
        self.meta['controls'].update({'bytes':len(raw),'sha256':reader.digest(raw),'rows':count,'first_row':1,'last_row':count,'syscall_indices':[0]*count})
        self.save()
    def test_duplicate_rows_cannot_reuse_one_native_event(self):
        self.native_control(duplicate=True)
        with self.assertRaisesRegex(reader.Invalid,'one complete ordered row'):self.check()
    def test_wire_request_is_independently_decoded(self):
        self.native_control(wrong_request=True)
        with self.assertRaisesRegex(reader.Invalid,'wire request'):self.check()
    def test_complete_native_event_projection(self):
        self.native_control()
        self.assertEqual(self.check()['controls'],1)
    def test_complete_recording_has_no_runtime_acceptance_claim(self):
        self.assertEqual(self.check()['status'],'RECORDING_COMPLETE')
    def test_missing_raw_leaf_cannot_be_complete(self):
        (self.run/'raw-0001.bin').unlink()
        with self.assertRaises((reader.Invalid,OSError)):self.check()
    def test_incomplete_progress_rejects_complete_metadata(self):
        self.progress['recording_complete']=False;self.save()
        with self.assertRaisesRegex(reader.Invalid,'incomplete'):self.check()
    def test_valid_json_partial_budget_mix_fails_checksum(self):
        p=self.root/'.budget.json';frame=json.loads(p.read_bytes());frame['ledger']['controls']=1
        self.put(p,json.dumps(frame).encode().ljust(4096,b' '))
        with self.assertRaisesRegex(reader.Invalid,'checksum'):self.check()
    def test_joined_child_requires_actual_birth_and_held_elf(self):
        call={'operation':'Fork','origin':'Native','result':456,'errno':None,'sender':None,'msg_flags':0,'received_fds':0,'descriptor_id':None,'poll_revents':0,'ancillary':[],'ancillary_descriptor_ids':[]}
        self.meta['syscalls']=[call,{**call,'operation':'Waitpid'}]
        self.meta['processes']=[{'parent_pid':123,'child_pid':456,'wait_raw_status':0,'wait_outcome':'Exited(0)','supervisor_joined':True,'birth_ticks':None,'pidfd_ledger_id':None,'supervisor_native_tid':789,'supervisor_rust_id':'ThreadId(1)','quarantined':False}]
        self.meta.update({'native_wait_outcome':'Exited(0)','supervisor_joined':True});self.save()
        with self.assertRaisesRegex(reader.Invalid,'genuine birth'):self.check()
    def test_numeric_pid_without_native_fork_is_rejected(self):
        self.meta['processes']=[{'parent_pid':123,'child_pid':456,'wait_raw_status':None,'wait_outcome':None,'supervisor_joined':False,'birth_ticks':None,'pidfd_ledger_id':None,'supervisor_native_tid':789,'supervisor_rust_id':'ThreadId(1)','quarantined':False}];self.save()
        with self.assertRaisesRegex(reader.Invalid,'fork-derived'):self.check()
    def test_extra_unaccounted_raw_leaf_is_rejected(self):
        self.put(self.run/'raw-0002.bin',b'extra')
        with self.assertRaises(reader.Invalid):self.check()
    def test_claimed_join_without_process_is_rejected(self):
        self.meta.update({'native_wait_outcome':'Exited(0)','supervisor_joined':True});self.save()
        with self.assertRaisesRegex(reader.Invalid,'top-level'):self.check()
    def test_symlink_leaf_is_rejected(self):
        p=self.run/'raw-0001.bin';p.unlink();p.symlink_to(self.run/'controls.jsonl')
        with self.assertRaises(reader.Invalid):self.check()
if __name__=='__main__':unittest.main()
