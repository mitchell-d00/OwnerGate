"""Reproduce the release sequence against a separately running HTTP server.

Uses fresh in-memory DEMONSTRATION machine keys. Requires an administrator token
from the environment. Writes evidence, never private keys, to the chosen directory.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ownergate.cli import machine_request
from ownergate.crypto import public


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--url',default='http://127.0.0.1:8000')
    p.add_argument('--output',type=Path,default=Path('/tmp/ownergate-demo'))
    args=p.parse_args()
    token=os.environ['OWNERGATE_ADMIN_TOKEN']
    args.output.mkdir(parents=True,exist_ok=True)
    id='demo-'+secrets.token_hex(4)
    resource='/resources/'+id
    key=Ed25519PrivateKey.generate()
    now=int(time.time())
    with httpx.Client(base_url=args.url,trust_env=False,timeout=10) as client:
        headers={'Authorization':'Bearer '+token}
        def admin(method,path,data):
            r=client.request(method,'/api/admin/'+path,headers=headers,json=data)
            r.raise_for_status()
        admin('POST','machines',{'id':id,'operator':'Disposable pilot demonstration','public_key':public(key),'scopes':[resource],'issued_at':now-1,'expires_at':now+3600})
        admin('PUT','resources',{'path':resource,'title':'Pilot protected document','content':'OwnerGate authorized content'})
        admin('PUT','policies',{'id':id,'machine':id,'resource':resource,'actions':['read'],'effect':'allow','not_before':now-1,'expires_at':now+3600})
        allowed,_=machine_request(client,key,id,resource)
        unknown=client.get(resource)
        admin('PATCH','machines/'+id,{'state':'revoked'})
        revoked,_=machine_request(client,key,id,resource)
        assert [allowed.status_code,unknown.status_code,revoked.status_code]==[200,401,403]
        snapshot=client.get('/api/admin/snapshot',headers=headers).json()
        actual=[e for e in snapshot['events'] if e.get('resource')==resource and e['kind']=='gateway']
        assert [e['decision'] for e in actual]==['allow','deny','deny']
        export=client.get('/api/admin/audit/export',headers=headers).json()
    evidence=args.output/'audit.json'
    evidence.write_text(json.dumps(export,indent=2)+'\n')
    checkpoint=args.output/'checkpoint.json'
    checkpoint.write_text(json.dumps(export['checkpoint'])+'\n')
    # Key is obtained from authenticated control-plane snapshot, independently of export.
    subprocess.run([sys.executable,'-m','ownergate.cli','verify',str(evidence),'--public-key',snapshot['audit_public_key'],'--checkpoint',str(checkpoint)],check=True)
    print(json.dumps({'allowed':allowed.status_code,'unknown':unknown.status_code,'revoked':revoked.status_code,'dashboard_decisions':[e['decision'] for e in actual],'evidence':str(evidence)}))


if __name__=='__main__':main()
