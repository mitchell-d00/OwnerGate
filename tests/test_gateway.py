import concurrent.futures
import copy
import json
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ownergate.app import create_app
from ownergate.cli import machine_request
from ownergate.crypto import b64, canonical, public, verify_export
from conftest import TOKEN


def request(setup, **kw):
    _,client,_,_,key,*_=setup
    return machine_request(client,key,'pilot','/resources/pilot',**kw)


def test_required_end_to_end(setup):
    app,client,_,_,_,write,*_=setup
    response,_=request(setup)
    assert response.status_code==200 and response.json()['content']=='SECRET CONTENT'
    assert response.json()['restrictions']==['No redistribution']
    assert client.get('/resources/pilot').status_code==401
    write('machines/pilot','PATCH',{'state':'revoked'})
    response,_=request(setup)
    assert response.status_code==403 and response.json()['detail']=='credential_revoked'
    events=[e for e in app.state.store.events() if e['kind']=='gateway']
    assert [e['decision'] for e in events]==['allow','deny','deny']
    export=client.get('/api/admin/audit/export',headers={'Authorization':'Bearer '+TOKEN}).json()
    assert verify_export(export,app.state.store.public_key)['count']==len(export['records'])


@pytest.mark.parametrize('mode,reason',[('tampered','invalid_signature'),('replay','missing_or_replayed_challenge')])
def test_bad_proofs(setup,mode,reason):
    _,client,*_=setup
    if mode=='tampered':
        response,_=request(setup,mode=mode)
    else:
        first,headers=request(setup)
        assert first.status_code==200
        response=client.get('/resources/pilot',headers=headers)
    assert response.status_code==401 and response.json()['detail']==reason


@pytest.mark.parametrize('delta,reason',[(60,'challenge_expired_or_clock_invalid'),(-1,'challenge_expired_or_clock_invalid'),(3600,'challenge_expired_or_clock_invalid')])
def test_challenge_clock(setup,delta,reason):
    _,client,current,_,key,*_=setup
    body=client.post('/api/challenges',json={'machine':'pilot','resource':'/resources/pilot','action':'read'}).json()
    current[0]+=delta
    r=client.get('/resources/pilot',headers={'X-OwnerGate-Machine':'pilot','X-OwnerGate-Nonce':body['nonce'],'X-OwnerGate-Signature':b64(key.sign(canonical(body)))})
    assert r.status_code==401 and r.json()['detail']==reason


@pytest.mark.parametrize('state,reason',[('revoked','credential_revoked'),('suspended','credential_suspended'),('expired','credential_expired'),('future','credential_not_yet_valid'),('scope','resource_outside_scope')])
def test_lifecycle_and_scope(setup,state,reason):
    app,client,current,_,key,write,machine,_=setup
    if state in ('revoked','suspended'):
        write('machines/pilot','PATCH',{'state':state})
    else:
        # Register through the real admin API, never edit authoritative state.
        machine['id']='other'
        if state=='expired':
            machine['issued_at']=current[0]-100
            machine['expires_at']=current[0]-1
        if state=='future':
            machine['issued_at']=current[0]+50
        if state=='scope':
            machine['scopes']=['/resources/outside']
        write('machines',body=machine)
    response,_=machine_request(client,key,'pilot' if state in ('revoked','suspended') else 'other','/resources/pilot')
    assert response.status_code==403 and response.json()['detail']==reason


def test_unknown_claim_never_attributed(setup):
    app,client,_,_,key,*_=setup
    r,_=machine_request(client,key,'unknown-caller','/resources/pilot')
    assert r.status_code==401
    e=app.state.store.events()[-1]
    assert e['machine']=='unknown' and not e['identity_verified']
    r,_=machine_request(client,Ed25519PrivateKey.generate(),'pilot','/resources/pilot')
    assert r.status_code==401 and app.state.store.events()[-1]['machine']=='unknown'


@pytest.mark.parametrize('machine',['pilot','*'])
def test_deny_overrides_allow(setup,machine):
    *_,write,_,policy=setup
    write('policies','PUT',{**policy,'id':'deny','machine':machine,'effect':'deny'})
    r,_=request(setup)
    assert r.status_code==403 and r.json()['detail']=='explicit_deny'


@pytest.mark.parametrize('action',['crawl','index','summarize','download','redistribute','made-up'])
def test_no_implicit_permission(setup,action):
    _,client,_,_,key,*_=setup
    if action=='made-up':
        assert client.post('/api/challenges',json={'machine':'pilot','resource':'/resources/pilot','action':action}).status_code==422
    else:
        r,_=request(setup,action=action)
        assert r.status_code==403 and r.json()['detail']=='no_allow_policy'


@pytest.mark.parametrize('action',['read','crawl','index','summarize','download','redistribute'])
def test_each_action_can_be_authorized(setup,action):
    *_,write,_,policy=setup
    write('policies','PUT',{**policy,'actions':[action]})
    r,_=request(setup,action=action)
    assert r.status_code==200


def test_policy_validity(setup):
    _,_,current,_,_,write,_,policy=setup
    write('policies','PUT',{**policy,'expires_at':current[0]})
    r,_=request(setup)
    assert r.status_code==403
    write('policies','PUT',{**policy,'not_before':current[0]+1})
    r,_=request(setup)
    assert r.status_code==403


@pytest.mark.parametrize('endpoint,method', [('snapshot','GET'),('audit/export','GET'),('audit/verify','GET'),('machines','POST'),('machines/pilot','PATCH'),('machines/pilot/rotate','POST'),('resources','PUT'),('policies','PUT')])
def test_admin_authentication(setup,endpoint,method):
    _,client,*_=setup
    for header in ({},{'Authorization':'Bearer wrong'},{'Cookie':'admin='+TOKEN},{'X-Forwarded-For':'127.0.0.1'}):
        r=client.request(method,'/api/admin/'+endpoint,headers=header,json={})
        assert r.status_code==401


@pytest.mark.parametrize('body',[[],None,{'machine':[]},{'machine':'pilot','resource':'/resources/pilot','action':'read','extra':True},{'machine':'pilot','resource':'/public','action':'read'}])
def test_malformed_challenge(setup,body):
    _,client,*_=setup
    assert client.post('/api/challenges',json=body).status_code==422


def test_malformed_inputs(setup):
    _,client,*_=setup
    assert client.post('/api/challenges',content='{',headers={'Content-Type':'application/json'}).status_code==422
    assert client.post('/api/challenges',content='x'*65537).status_code==413
    r=client.get('/resources/pilot',headers={'X-OwnerGate-Signature':'@@@','X-OwnerGate-Nonce':'bogus','X-OwnerGate-Machine':'pilot'})
    assert r.status_code==401


@pytest.mark.parametrize('method,path',[('POST','/resources/pilot'),('HEAD','/resources/pilot'),('GET','/resources/pilot?copy=1'),('GET','/resources/../resources/pilot'),('GET','/upstream/pilot'),('GET','/static/../state/audit.pem'),('GET','/ownergate.db'),('GET','/state/audit.pem'),('GET','/resources/pilot/extra'),('GET','/resources/%70ilot')])
def test_route_isolation(setup,method,path):
    _,client,*_=setup
    r=client.request(method,path)
    assert r.status_code>=400 and 'SECRET CONTENT' not in r.text


def test_request_binding(setup):
    _,client,_,_,_,write,*_=setup
    write('resources','PUT',{'path':'/resources/second','title':'Second','content':'SECOND SECRET'})
    _,headers=request(setup)
    r=client.get('/resources/second',headers=headers)
    assert r.status_code==401
    body=client.post('/api/challenges',json={'machine':'pilot','resource':'/resources/pilot','action':'read'}).json()
    key=setup[4]
    headers.update({'X-OwnerGate-Nonce':body['nonce'],'X-OwnerGate-Signature':b64(key.sign(canonical(body)))})
    r=client.get('/resources/second',headers=headers)
    assert r.status_code==401 and r.json()['detail']=='request_binding_mismatch'
    assert client.get('/resources/pilot',headers=headers).status_code==401


def test_rotation_invalidates_old_keys_and_pending_proofs(setup):
    _,client,_,_,old,write,*_=setup
    body=client.post('/api/challenges',json={'machine':'pilot','resource':'/resources/pilot','action':'read'}).json()
    new=Ed25519PrivateKey.generate()
    write('machines/pilot/rotate',body={'public_key':public(new)})
    headers={'X-OwnerGate-Machine':'pilot','X-OwnerGate-Nonce':body['nonce'],'X-OwnerGate-Signature':b64(old.sign(canonical(body)))}
    assert client.get('/resources/pilot',headers=headers).json()['detail']=='request_binding_mismatch'
    assert machine_request(client,old,'pilot','/resources/pilot')[0].status_code==401
    assert machine_request(client,new,'pilot','/resources/pilot')[0].status_code==200
    write('machines/pilot','PATCH',{'state':'revoked'})
    assert client.patch('/api/admin/machines/pilot',headers={'Authorization':'Bearer '+TOKEN},json={'state':'active'}).status_code==409


def test_concurrent_nonce_consumption(setup):
    app,client,_,_,key,*_=setup
    body=client.post('/api/challenges',json={'machine':'pilot','resource':'/resources/pilot','action':'read'}).json()
    headers={'X-OwnerGate-Machine':'pilot','X-OwnerGate-Nonce':body['nonce'],'X-OwnerGate-Signature':b64(key.sign(canonical(body)))}
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        results=list(pool.map(lambda _:client.get('/resources/pilot',headers=headers).status_code,range(10)))
    assert results.count(200)==1 and results.count(401)==9
    assert verify_export(app.state.store.export(),app.state.store.public_key)['count']==13


def test_restart_recovery(setup):
    app,client,current,path,*_=setup
    first,headers=request(setup)
    export=app.state.store.export()
    recovered=create_app(path,TOKEN,clock=lambda:current[0])
    assert recovered.state.store.export()==export
    from fastapi.testclient import TestClient
    with TestClient(recovered) as new:
        assert new.get('/resources/pilot',headers=headers).status_code==401
        assert machine_request(new,setup[4],'pilot','/resources/pilot')[0].status_code==200
    recovered.state.store.db.close()


@pytest.mark.parametrize('tamper',['signature','payload','delete','reorder','key','truncate'])
def test_audit_tampering(setup,tamper):
    app,*_=setup
    request(setup)
    trusted=app.state.store.export()
    export=copy.deepcopy(trusted)
    key=app.state.store.public_key
    if tamper in ('signature','payload'):
        parts=export['records'][0].split('.')
        i=2 if tamper=='signature' else 1
        parts[i]=('A' if parts[i][0]!='A' else 'B')+parts[i][1:]
        export['records'][0]='.'.join(parts)
    if tamper=='delete':export['records'].pop(0)
    if tamper=='reorder':export['records'].reverse()
    if tamper=='key':key=public(Ed25519PrivateKey.generate())
    if tamper=='truncate':
        export['records'].pop()
        import hashlib
        export['checkpoint']={'count':len(export['records']),'head':hashlib.sha256(export['records'][-1].encode()).hexdigest()}
    with pytest.raises(Exception):
        verify_export(export,key,trusted['checkpoint'])


def test_fail_start_missing_key_or_corrupt_history(setup):
    app,_,_,path,*_=setup
    app.state.store.db.execute("UPDATE audit SET token='invalid' WHERE sequence=1")
    with pytest.raises(Exception):create_app(path,TOKEN)
    (path/'audit.pem').unlink()
    with pytest.raises(RuntimeError,match='Audit key missing'):create_app(path,TOKEN)


def test_rate_limits_and_secure_start(tmp_path):
    from fastapi.testclient import TestClient
    with pytest.raises(RuntimeError):create_app(tmp_path,'short')
    app=create_app(tmp_path,TOKEN,rate_limit=2)
    with TestClient(app) as client:
        assert client.get('/resources/x').status_code==401
        assert client.get('/resources/x').status_code==401
        assert client.get('/resources/x').status_code==429
    assert app.state.store.events()[-1]['reason']=='rate_limited'
    app.state.store.db.close()
