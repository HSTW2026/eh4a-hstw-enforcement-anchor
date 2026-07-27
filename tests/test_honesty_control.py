#!/usr/bin/env python3
import hashlib,json,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
VALIDATOR=ROOT/'tools/validate_honesty_claim.py'

def h(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def run(claim,subject):
    cp=subject.parent/'claim.json'; cp.write_text(json.dumps(claim),encoding='utf-8')
    return subprocess.run(['python3',str(VALIDATOR),str(cp),str(subject)],capture_output=True,text=True)

def base(subject,evidence,status='EXECUTED_MATCHING_CONTROLLED_ENVIRONMENT',claim_text='Exact prompt tested in a matching controlled environment.'):
    return {'claim_id':'C-1','subject':str(subject.resolve()),'subject_sha256':h(subject),'claim_text':claim_text,'status':status,'method':'exact end-to-end execution','environment':'matching controlled environment','executed_at_utc':'2026-07-27T12:00:00Z','result':'pass','evidence':[{'path':str(evidence.resolve()),'sha256':h(evidence)}],'limitations':['Not execution on the user live machine.']}

def main():
  with tempfile.TemporaryDirectory() as td:
    d=Path(td); s=d/'prompt.txt'; e=d/'result.txt'; s.write_text('do exact thing'); e.write_text('pass')
    cases=[]
    c=base(s,e); cases.append(('valid',c,0))
    x=dict(c); x['subject_sha256']='0'*64; cases.append(('subject hash mismatch',x,1))
    x=dict(c); x['evidence']=[{'path':str(e.resolve()),'sha256':'0'*64}]; cases.append(('evidence hash mismatch',x,1))
    x=dict(c); x['status']='REVIEWED_NOT_EXECUTED'; cases.append(('review called tested',x,1))
    x=dict(c); x['status']='SIMULATION_ONLY'; x['claim_text']='Validated in the user live environment'; cases.append(('simulation called live',x,1))
    x=dict(c); x['limitations']='none'; cases.append(('limitations wrong type',x,1))
    x=dict(c); x.pop('method'); cases.append(('missing field',x,1))
    x=dict(c); x['status']='EXECUTED_LIVE'; x['environment']='test environment'; cases.append(('live status without live environment',x,1))
    x=dict(c); x['evidence']=[]; cases.append(('missing evidence',x,1))
    for name,claim,expected in cases:
      r=run(claim,s)
      if r.returncode!=expected:
        print(name,'FAILED',r.stdout,r.stderr); return 1
    print(f'HONESTY_CONTROL_TESTS_PASS {len(cases)}/{len(cases)}')
  return 0
if __name__=='__main__': raise SystemExit(main())
