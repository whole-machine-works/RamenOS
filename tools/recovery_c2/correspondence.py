#!/usr/bin/env python3
"""Fixed-input C2 correspondence staging and offline result comparison only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

ABI = '49daf52dd669411376770b3bc2a007d7c6a8b346843bcd123a45da8139b0da60'
MODULE = 'fbcceae4411b17f2e517a8539991bfb41b097b2aa2b037ca58a828972a3b3ce4'
CORPUS = '84eece3246d9b4521a5b8ac48fa6324cb4be4e98889277ab46837f6764aeda49'
TYPED = '7c171588e54f7af16b63fdd86a075c57cc8bca4bfbf346bd84c2b397bce329a9'
REGISTRATION = '27758558349696918c0325ce692f0cdb1ba52ef1f1cd2904cb0cacf6a7012b2a'
IDS = ('pending','denied','invalid','committed','noncommit','foreign_operation',
       'foreign_epoch','foreign_binding','malformed_receipt','zero_epoch',
       'invalid_original','module_identity','abi_identity')
EXPECTED = ('Pending','Denied','Invalid','Committed','DefinitiveNoncommit',
            'Invalid','Invalid','Invalid','Invalid','invalid_original','invalid_original',
            'artifact_identity','artifact_identity')
MAX_JSON = 2 * 1024 * 1024

class Invalid(ValueError):
    pass

def require(condition, message):
    if not condition:
        raise Invalid(message)

def unique(pairs):
    result = {}
    for key,value in pairs:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result

def parse(raw):
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(Invalid('nonfinite JSON')))
    except (UnicodeError,json.JSONDecodeError) as error:
        raise Invalid('invalid JSON') from error

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def read(path, bound, *, private=False):
    path=Path(path)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=bound,'regular bounded input')
        if private:
            require(before.st_uid==os.getuid() and not before.st_mode & 0o077,'owned private input')
        raw=stream.read(bound+1)
        after=os.fstat(stream.fileno())
    present=os.stat(path,follow_symlinks=False)
    identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    require(identity(before)==identity(after)==identity(present) and len(raw)==before.st_size,'stable complete input')
    return raw

def read_private(path,bound):
    return read(path,bound,private=True)

def private_dir(path):
    m=os.stat(path,follow_symlinks=False)
    require(stat.S_ISDIR(m.st_mode) and m.st_uid==os.getuid() and not m.st_mode & 0o077,'owned private directory')

def exclusive(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())

def plan_bytes():
    value={'schema_version':1,'kind':'recovery_c2_plan_v1','abi_sha256':ABI,
           'corpus_sha256':CORPUS,'module_sha256':MODULE,'typed_sha256':TYPED,
           'registration_sha256':REGISTRATION,'case_count':627}
    return (json.dumps(value,indent=2,sort_keys=True)+'\n').encode()

def validate_corpus(raw):
    require(digest(raw)==CORPUS,'corpus digest')
    v=parse(raw)
    require(type(v) is dict and set(v)=={'schema_version','packet','contract_sha256','ramenos_reference_revision','canonical_call','derivation','cases'},'corpus shape')
    require(v['schema_version']==1 and type(v['schema_version']) is int and v['packet']=='recovery-r0-v1' and v['contract_sha256']==ABI and v['ramenos_reference_revision']=='958a6f1713129930b217c16b1a21140e8fab9ed0','corpus identity')
    require(v['canonical_call']=={'input_pointer':4096,'input_length':336,'output_pointer':4448,'output_capacity':16} and type(v['derivation']) is str and bool(v['derivation']),'corpus call')
    cases=v['cases'];require(type(cases) is list and len(cases)==627,'corpus count');seen=set()
    for c in cases:
        require(type(c) is dict and set(c)=={'id','family','reason','input_hex','expected_return','expected_output_hex'},'case shape')
        require(type(c['id']) is str and 0<len(c['id'])<=96 and c['id'] not in seen and c['id'].isascii() and all(x.isalnum() or x in '_-' for x in c['id']),'case ID');seen.add(c['id'])
        require(type(c['expected_return']) is int and c['expected_return']==0 and type(c['family']) is str and bool(c['family']) and type(c['reason']) is str and bool(c['reason']),'case metadata')
        for key,size in (('input_hex',336),('expected_output_hex',16)):
            s=c[key];require(type(s) is str and len(s)==2*size and all(x in '0123456789abcdef' for x in s),'canonical case hex')
    return cases

def validate_typed_value(v):
    require(type(v) is dict and type(v.get('cases')) is list and len(v['cases'])==13,'typed matrix')
    for row,id,expected in zip(v['cases'],IDS,EXPECTED,strict=True):
        require(type(row) is dict and row.get('id')==id,'typed ID')
        actual=row.get('expected');norm=actual.removeprefix('RecoveryError::') if type(actual) is str else ''
        norm={'InvalidOriginal':'invalid_original','ArtifactIdentity':'artifact_identity'}.get(norm,norm)
        require(norm==expected,'typed expected')
    return v

def validate_typed(raw):
    require(digest(raw)==TYPED,'typed digest')
    return validate_typed_value(parse(raw))

def inputs(module,corpus,typed,registration, *, private=False):
    raw={'module.wasm':read(module,65536,private=private),'corpus.json':read(corpus,MAX_JSON,private=private),
         'typed.json':read(typed,MAX_JSON,private=private),'registration.json':read(registration,MAX_JSON,private=private)}
    require(len(raw['module.wasm'])==1347 and digest(raw['module.wasm'])==MODULE,'module identity')
    validate_corpus(raw['corpus.json']);validate_typed(raw['typed.json'])
    require(digest(raw['registration.json'])==REGISTRATION,'registration identity');parse(raw['registration.json'])
    return raw

def stage(args):
    raw=inputs(args.module,args.corpus,args.typed,args.registration)
    dest=Path(args.output);private_dir(dest.parent);os.mkdir(dest,0o700)
    for name in ('module.wasm','corpus.json','typed.json','registration.json'):exclusive(dest/name,raw[name])
    exclusive(dest/'plan.json',plan_bytes())
    print('C2_STAGE_COMPLETE_NO_CANDIDATE_EXECUTION')

def validate_error(value):
    kinds={'artifact_identity','module_shape','engine','invalid_original','fuel','stack',
           'trap','guest_return','invalid_output','disagreement'}
    require(type(value) is dict and set(value)=={'kind','detail'} and value['kind'] in kinds
            and type(value['detail']) is str and 0<len(value['detail'])<=512,'bounded actual error')

def check_rows(cases, typed, report, plan_hash):
    validate_typed_value(typed)
    require(type(report) is dict and set(report)=={'schema_version','kind','plan_sha256','registration_sha256','raw_rows','typed_rows'},'result shape')
    require(type(report['schema_version']) is int and report['schema_version']==1 and report['kind']=='recovery_c2_engine_result_v1' and report['plan_sha256']==plan_hash and report['registration_sha256']==REGISTRATION,'result identity')
    rows=report['raw_rows'];require(type(rows) is list and len(rows)==len(cases),'raw count');failures=[]
    for c,r in zip(cases,rows,strict=True):
        require(type(r) is dict and set(r)=={'id','input_sha256','guest_return','output_hex','error'},'raw shape')
        require(r['id']==c['id'] and r['input_sha256']==digest(bytes.fromhex(c['input_hex'])),'raw order or input')
        returned,output,error=r['guest_return'],r['output_hex'],r['error']
        require(returned is None or type(returned) is int and -(1<<31)<=returned<(1<<31),'raw return type')
        if output is not None:
            require(type(output) is str and len(output)==32 and all(x in '0123456789abcdef' for x in output),'raw output bytes')
        if error is None:
            require(returned==0 and output is not None,'successful raw observation')
        else:
            validate_error(error)
            if error['kind']=='guest_return':require(returned is not None and returned!=0 and output is None,'guest return observation')
            elif error['kind']=='invalid_output':require(returned==0 and output is not None,'invalid output observation')
            else:require(returned is None and output is None,'error observation')
        if r['error'] is not None or type(r['guest_return']) is not int or r['guest_return']!=c['expected_return'] or r['output_hex']!=c['expected_output_hex']:
            failures.append({'leg':'raw','id':c['id'],'actual':r,'expected_return':c['expected_return'],'expected_output_hex':c['expected_output_hex']})
    rows=report['typed_rows'];require(type(rows) is list and len(rows)==len(IDS),'typed count')
    for r,id,expected in zip(rows,IDS,EXPECTED,strict=True):
        require(type(r) is dict and set(r)=={'id','actual','fresh_id','fresh'} and r['id']==id and r['fresh_id']=='fresh_after_'+id,'typed identity')
        actual=r['actual'];fresh=r['fresh'];require(type(actual) is dict and set(actual)=={'disposition','error'} and type(fresh) is dict and set(fresh)=={'disposition','error'},'typed result shape')
        for item in (actual,fresh):
            if item['error'] is not None:
                validate_error(item['error']);require(item['disposition'] is None,'typed error disposition')
            else:
                require(item['disposition'] in ('Pending','Committed','DefinitiveNoncommit','Denied','Invalid','UnexpectedAdmitted'),'typed disposition')
        good=(actual['disposition']==expected and actual['error'] is None) if expected not in ('invalid_original','artifact_identity') else (actual['disposition'] is None and type(actual['error']) is dict and actual['error'].get('kind')==expected)
        if not good or fresh['disposition']!='Committed' or fresh['error'] is not None:
            failures.append({'leg':'typed','id':id,'expected':expected,'actual':r})
    return failures

def verify(args):
    stage=Path(args.stage);private_dir(stage)
    raw=inputs(stage/'module.wasm',stage/'corpus.json',stage/'typed.json',stage/'registration.json',private=True)
    plan=read_private(stage/'plan.json',4096);require(plan==plan_bytes(),'plan identity')
    result=read_private(args.result,MAX_JSON);failures=check_rows(validate_corpus(raw['corpus.json']),validate_typed(raw['typed.json']),parse(result),digest(plan))
    summary={'schema_version':1,'kind':'recovery_c2_comparison_v1','status':'mismatch' if failures else 'match','registration_sha256':REGISTRATION,'plan_sha256':digest(plan),'result_sha256':digest(result),'raw_count':627,'typed_count':13,'fresh_count':13,'failures':failures,'qualified':False,'adopted':False}
    output=Path(args.output);private_dir(output.parent);exclusive(output,(json.dumps(summary,indent=2,sort_keys=True)+'\n').encode())
    print('C2_COMPARISON_'+summary['status'].upper())
    return 1 if failures else 0

def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='command',required=True)
    a=sub.add_parser('stage');a.add_argument('--module',required=True);a.add_argument('--corpus',required=True);a.add_argument('--typed',required=True);a.add_argument('--registration',required=True);a.add_argument('--output',required=True)
    b=sub.add_parser('verify');b.add_argument('--stage',required=True);b.add_argument('--result',required=True);b.add_argument('--output',required=True)
    args=p.parse_args()
    try:
        return stage(args) if args.command=='stage' else verify(args)
    except (Invalid,OSError,ValueError,TypeError,KeyError) as error:
        print('C2_REFUSED: '+str(error),file=sys.stderr);return 1

if __name__=='__main__':
    raise SystemExit(main())
