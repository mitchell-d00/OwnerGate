"""OwnerGate server, machine key generation, request client and offline verifier."""
import argparse
import json
import os
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import httpx
from .crypto import b64, canonical, public, verify_export


def machine_request(client, key, machine, resource, action="read", mode="valid"):
    challenge = client.post('/api/challenges',json={"machine":machine,"resource":resource,"action":action})
    challenge.raise_for_status()
    body = challenge.json()
    headers = {"X-OwnerGate-Machine":machine,"X-OwnerGate-Nonce":body["nonce"],"X-OwnerGate-Action":action,
        "X-OwnerGate-Signature":b64(key.sign(canonical(body)))}
    if mode == "tampered":
        headers["X-OwnerGate-Signature"] = b64(bytes(64))
    response = client.get(resource,headers=headers)
    return response, headers


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest="command",required=True)
    serve=sub.add_parser("serve")
    serve.add_argument("--host",default="127.0.0.1")
    serve.add_argument("--port",type=int,default=8000)
    gen=sub.add_parser("keygen")
    gen.add_argument("path",type=Path)
    req=sub.add_parser("request")
    req.add_argument("--url",default="http://127.0.0.1:8000")
    req.add_argument("--key",type=Path,required=True)
    req.add_argument("--machine",required=True)
    req.add_argument("--resource",default="/resources/pilot")
    req.add_argument("--action",default="read")
    verify=sub.add_parser("verify")
    verify.add_argument("export",type=Path)
    verify.add_argument("--public-key",required=True,help="Trusted pinned base64url Ed25519 key")
    verify.add_argument("--checkpoint",type=Path)
    args=parser.parse_args()
    if args.command == "serve":
        import uvicorn
        from .app import create_app
        uvicorn.run(create_app(),host=args.host,port=args.port,proxy_headers=False,workers=1)
    elif args.command == "keygen":
        key=Ed25519PrivateKey.generate()
        with args.path.open("xb") as f:
            os.chmod(args.path,0o600)
            f.write(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        print(public(key))
    elif args.command == "request":
        key=serialization.load_pem_private_key(args.key.read_bytes(),password=None)
        with httpx.Client(base_url=args.url,trust_env=False,timeout=10) as client:
            response,_=machine_request(client,key,args.machine,args.resource,args.action)
        print(response.status_code,response.text)
        if response.status_code != 200:
            raise SystemExit(1)
    else:
        try:
            checkpoint=json.loads(args.checkpoint.read_text()) if args.checkpoint else None
            print(json.dumps({"valid":True,**verify_export(json.loads(args.export.read_text()),args.public_key,checkpoint)}))
        except Exception as error:
            parser.exit(1,"Verification failed: "+type(error).__name__+"\n")


if __name__ == "__main__":
    main()
