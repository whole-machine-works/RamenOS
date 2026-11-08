"""Synthetic comparison and packaged-byte controls; no C2 engine execution."""
import copy
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
import correspondence as c

class CompareControls(unittest.TestCase):
    def setUp(self):
        self.cases=[{'id':'a','input_hex':'00'*336,'expected_return':0,'expected_output_hex':'00'*16},
                    {'id':'b','input_hex':'01'*336,'expected_return':0,'expected_output_hex':'11'*16}]
        self.typed={'cases':[{'id':i,'expected':('RecoveryError::InvalidOriginal' if e=='invalid_original' else 'RecoveryError::ArtifactIdentity' if e=='artifact_identity' else e)} for i,e in zip(c.IDS,c.EXPECTED,strict=True)]}
        raw=[{'id':x['id'],'input_sha256':hashlib.sha256(bytes.fromhex(x['input_hex'])).hexdigest(),
              'guest_return':0,'output_hex':x['expected_output_hex'],'error':None} for x in self.cases]
        typed=[]
        for id,expected in zip(c.IDS,c.EXPECTED,strict=True):
            actual=({'disposition':None,'error':{'kind':expected,'detail':'observed'}}
                    if expected in ('invalid_original','artifact_identity') else {'disposition':expected,'error':None})
            typed.append({'id':id,'actual':actual,'fresh_id':'fresh_after_'+id,
                          'fresh':{'disposition':'Committed','error':None}})
        self.report={'schema_version':1,'kind':'recovery_c2_engine_result_v1','plan_sha256':'plan',
                     'registration_sha256':c.REGISTRATION,'raw_rows':raw,'typed_rows':typed}

    def test_packaged_inputs_match_the_frozen_module_registration_and_typed_matrix(self):
        package = Path(__file__).resolve().parent
        registration = c.read(package / 'registration-v1.json', c.MAX_JSON)
        typed = c.read(package / 'typed-expectations-v1.json', c.MAX_JSON)
        module = c.read(package.parents[1] / 'services/native_runner/tests/fixtures/recovery-c2.wasm', 65536)
        self.assertEqual(c.digest(registration), c.REGISTRATION)
        self.assertEqual(c.parse(registration)['typed_cases']['fresh_success'], 'after_all_13_rows')
        self.assertEqual(len(c.validate_typed(typed)['cases']), 13)
        self.assertEqual((len(module), c.digest(module)), (1347, c.MODULE))

    def test_actual_errors_and_fresh_failure_are_retained_as_mismatch(self):
        self.assertEqual(c.check_rows(self.cases,self.typed,self.report,'plan'),[])
        r=copy.deepcopy(self.report)
        r['raw_rows'][0].update(guest_return=None,output_hex=None,error={'kind':'trap','detail':'real synthetic trap'})
        r['typed_rows'][1]['fresh']={'disposition':None,'error':{'kind':'fuel','detail':'actual synthetic fuel'}}
        failures=c.check_rows(self.cases,self.typed,r,'plan')
        self.assertEqual([(v['leg'],v['id']) for v in failures],[('raw','a'),('typed','denied')])
        self.assertEqual(failures[0]['actual']['error']['kind'],'trap')
        self.assertEqual(failures[1]['actual']['fresh']['error']['kind'],'fuel')
        self.assertEqual(c.check_rows(self.cases,self.typed,self.report,'plan'),[])

    def test_raw_errors_never_invent_unavailable_output_and_order_is_fixed(self):
        r=copy.deepcopy(self.report);r['raw_rows'][0].update(guest_return=7,output_hex=None,error={'kind':'guest_return','detail':'actual 7'})
        self.assertEqual(c.check_rows(self.cases,self.typed,r,'plan')[0]['actual']['guest_return'],7)
        r['raw_rows'][0]['output_hex']='00'*16
        with self.assertRaises(c.Invalid):c.check_rows(self.cases,self.typed,r,'plan')
        r=copy.deepcopy(self.report);r['raw_rows'].reverse()
        with self.assertRaises(c.Invalid):c.check_rows(self.cases,self.typed,r,'plan')
        r=copy.deepcopy(self.report);r['typed_rows'][0]['fresh_id']='fresh_after_denied'
        with self.assertRaises(c.Invalid):c.check_rows(self.cases,self.typed,r,'plan')

    def test_duplicate_json_and_nonfinite_refuse_then_fresh_valid_parses(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}'):
            with self.assertRaises(c.Invalid):c.parse(raw)
        self.assertEqual(c.parse(b'{"x":1}'),{'x':1})

    def test_wrong_typed_expectation_is_refused_then_fresh_matrix_passes(self):
        bad=copy.deepcopy(self.typed)
        bad['cases'][0]['expected']='Committed'
        with self.assertRaises(c.Invalid):c.check_rows(self.cases,bad,self.report,'plan')
        self.assertEqual(c.check_rows(self.cases,self.typed,self.report,'plan'),[])

    def test_result_requires_private_mode_then_fresh_private_read_succeeds(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'result.json';path.write_bytes(b'{}');os.chmod(path,0o644)
            with self.assertRaises(c.Invalid):c.read_private(path,16)
            os.chmod(path,0o600)
            self.assertEqual(c.read_private(path,16),b'{}')

if __name__=='__main__':unittest.main()
