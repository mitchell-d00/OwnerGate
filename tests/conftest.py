import socket
import threading
import time
import httpx
import pytest
import uvicorn
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ownergate.app import create_app
from ownergate.crypto import public

TOKEN = 'test-administrator-token-32-characters-minimum'


@pytest.fixture
def pilot(tmp_path):
    current = [int(time.time())]
    app = create_app(tmp_path, TOKEN, rate_limit=10000, clock=lambda:current[0] if current[0] is not None else int(time.time()))
    sock = socket.socket()
    sock.bind(('127.0.0.1',0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app,log_level='warning',proxy_headers=False))
    thread = threading.Thread(target=server.run,kwargs={'sockets':[sock]},daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(.02)
    assert server.started
    with httpx.Client(base_url=f'http://127.0.0.1:{port}',trust_env=False,timeout=15) as client:
        yield app,client,current,tmp_path
    server.should_exit=True
    thread.join(5)
    assert not thread.is_alive()
    app.state.store.db.close()


@pytest.fixture
def setup(pilot):
    app,client,current,path=pilot
    admin={'Authorization':'Bearer '+TOKEN}
    def write(endpoint,method='POST',body=None):
        r=client.request(method,'/api/admin/'+endpoint,headers=admin,json=body)
        assert r.is_success,r.text
        return r.json()
    key=Ed25519PrivateKey.generate()
    machine={'id':'pilot','public_key':public(key),'operator':'Declared test operator','scopes':['/resources/pilot'],'issued_at':current[0]-10,'expires_at':current[0]+3600}
    write('machines',body=machine)
    write('resources','PUT',{'path':'/resources/pilot','title':'Confidential pilot','content':'SECRET CONTENT'})
    policy={'id':'allow-read','machine':'pilot','resource':'/resources/pilot','actions':['read'],'effect':'allow','not_before':current[0]-10,'expires_at':current[0]+3600,'restrictions':'No redistribution'}
    write('policies','PUT',policy)
    return app,client,current,path,key,write,machine,policy
