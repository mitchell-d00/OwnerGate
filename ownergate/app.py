"""HTTP boundary. The protected application is callable only after authorization."""
import hmac
import json
import os
import secrets
import threading
import time
import uuid
from pathlib import Path
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from .crypto import canonical, digest, verify_export
from .engine import authorize, state
from .models import Challenge, Lifecycle, Machine, Policy, ResourceInput, Rotation
from .store import Store


class Limiter:
    def __init__(self, limit):
        self.limit = limit
        self.lock = threading.Lock()
        self.windows = {}

    def allow(self, ip):
        window = int(time.monotonic() // 60)
        with self.lock:
            self.windows = {k:v for k,v in self.windows.items() if v[0] == window}
            if len(self.windows) >= 4096 and ip not in self.windows:
                return False
            _, count = self.windows.get(ip, (window, 0))
            self.windows[ip] = (window, count + 1)
            return count < self.limit


def create_app(directory=None, admin_token=None, audience=None, rate_limit=240, clock=None):
    token = admin_token or os.environ.get("OWNERGATE_ADMIN_TOKEN", "")
    if len(token) < 32:
        raise RuntimeError("Set OWNERGATE_ADMIN_TOKEN to a random secret of at least 32 characters")
    audience = audience or os.environ.get("OWNERGATE_AUDIENCE", "http://127.0.0.1:8000")
    now = clock or (lambda: int(time.time()))
    store = Store(directory or os.environ.get("OWNERGATE_STATE", "state"))
    app = FastAPI(title="OwnerGate", version="0.1.0", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.store = store
    limiter = Limiter(rate_limit)
    admin_limiter = Limiter(60)

    def record_gate(request, decision, reason, machine="unknown", verified=False, action="read", restrictions=None):
        return store.record({"kind":"gateway", "request_id":request.state.request_id, "timestamp":now(),
            "machine":machine or "unknown", "identity_verified":verified, "resource":request.url.path,
            "action":action, "method":request.method, "policy_version":store.version(),
            "policy_hash":digest(store.all("policy")), "verification_result":"valid" if verified else "unverified",
            "decision":decision, "reason":reason, "restrictions":restrictions or [], "traffic_source":"actual_http"})

    @app.middleware("http")
    async def boundary(request, call_next):
        request.state.request_id = str(uuid.uuid4())
        protected = request.url.path.startswith("/resources/")
        ip = request.client.host if request.client else "unknown"
        reason, code = None, None
        if not limiter.allow(ip):
            reason, code = "rate_limited", 429
        elif request.url.path.startswith("/api/admin"):
            if not admin_limiter.allow(ip):
                reason, code = "admin_rate_limited", 429
            elif not hmac.compare_digest(request.headers.get("authorization", ""), "Bearer " + token):
                reason, code = "admin_authentication_required", 401
        if code:
            if protected:
                with store.transaction():
                    record_gate(request, "deny", reason)
            response = JSONResponse({"detail":reason}, status_code=code)
        else:
            length = 0
            chunks = []
            async for chunk in request.stream():
                length += len(chunk)
                if length > 65536:
                    if protected:
                        with store.transaction():
                            record_gate(request,"deny","request_too_large")
                    return JSONResponse({"detail":"request_too_large"}, status_code=413)
                chunks.append(chunk)
            request._body = b"".join(chunks)
            request.state.body_nonempty = bool(length)
            response = await call_next(request)
        response.headers.update({"X-Request-ID":request.state.request_id, "X-Content-Type-Options":"nosniff",
            "Cache-Control":"no-store", "Referrer-Policy":"no-referrer",
            "Content-Security-Policy":"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"})
        return response

    def admin(request: Request):
        # Defense in depth; APIs never use cookies or browser storage for auth.
        if not hmac.compare_digest(request.headers.get("authorization", ""), "Bearer " + token):
            raise HTTPException(401, "admin_authentication_required")

    def change(kind, id, body):
        version = store.version(bump=True)
        store.put(kind, id, body)
        store.record({"kind":"administration", "request_id":str(uuid.uuid4()), "timestamp":now(),
            "operation":kind, "object_id":id, "body":body, "policy_version":version})

    @app.get("/health")
    def health():
        return {"status":"ok", "version":"0.1.0"}

    @app.get("/public")
    def public_site():
        return {"title":"OwnerGate test website", "message":"Public resource. Protected documents require a signed machine request."}

    @app.get("/api/info")
    def info():
        return {"audience":audience, "protocol":"ownergate.challenge.v1", "challenge_ttl":60}

    @app.post("/api/challenges")
    def challenge(data: Challenge):
        with store.transaction():
            store.db.execute("DELETE FROM challenges WHERE expires<=?", (now(),))
            if store.db.execute("SELECT count(*) FROM challenges").fetchone()[0] >= 2048:
                raise HTTPException(429, "challenge_capacity_reached")
            machine = store.get("machine", data.machine)
            body = {**data.model_dump(), "schema":"ownergate.challenge.v1", "nonce":secrets.token_urlsafe(32),
                "issued_at":now(), "expires_at":now()+60, "method":"GET", "body_sha256":__import__('hashlib').sha256(b'').hexdigest(),
                "audience":audience, "key_version":machine["key_version"] if machine else 0}
            store.db.execute("INSERT INTO challenges VALUES(?,?,?)", (body["nonce"], canonical(body).decode(), body["expires_at"]))
            return body

    @app.api_route("/resources/{slug:path}", methods=["GET","HEAD","POST","PUT","PATCH","DELETE","OPTIONS","TRACE","CONNECT"])
    def gateway(slug: str, request: Request):
        machine_id = request.headers.get("x-ownergate-machine", "")[:72]
        action = request.headers.get("x-ownergate-action", "read")[:32]
        with store.transaction():
            resource = store.get("resource", request.url.path)
            if request.method != "GET" or request.url.query or request.state.body_nonempty:
                allow, reason, verified, restrictions = False, "unsupported_request_shape", False, []
            elif not resource:
                allow, reason, verified, restrictions = False, "unknown_protected_resource", False, []
            else:
                allow, reason, verified, restrictions = authorize(store, machine_id=machine_id,
                    nonce=request.headers.get("x-ownergate-nonce", "")[:128], signature=request.headers.get("x-ownergate-signature", "")[:128],
                    resource=request.url.path, action=action, now=now(), audience=audience)
            # Claimed identifiers never become attributed machine identities without proof.
            event = record_gate(request, "allow" if allow else "deny", reason, machine_id if verified else "unknown", verified, action, restrictions)
            event["claimed_machine"] = machine_id  # response hint only, never attribution
        if not allow:
            return JSONResponse({"detail":reason, "request_id":event["request_id"]}, status_code=403 if verified else 401)
        # Minimal upstream is an in-process test application with no unguarded mount/socket.
        return JSONResponse({"title":resource["title"], "content":resource["content"], "restrictions":restrictions, "request_id":event["request_id"]})

    @app.get("/api/admin/snapshot", dependencies=[Depends(admin)])
    def snapshot():
        with store.transaction():
            machines = [{**m,"effective_state":state(m,now()),"operator_assurance":"self-declared"} for m in store.all("machine")]
            return {"machines":machines,"resources":store.all("resource"),"policies":store.all("policy"),"events":store.events(),"policy_version":store.version(),"audit_public_key":store.public_key}

    @app.post("/api/admin/machines", dependencies=[Depends(admin)], status_code=201)
    def register(data: Machine):
        with store.transaction():
            if store.get("machine",data.id):
                raise HTTPException(409,"identity_already_exists")
            body = {**data.model_dump(),"state":"active","key_version":1,"history":[{"event":"issued","timestamp":now(),"public_key":data.public_key}]}
            change("machine",data.id,body)
            return body

    @app.patch("/api/admin/machines/{id}", dependencies=[Depends(admin)])
    def lifecycle(id: str, data: Lifecycle):
        with store.transaction():
            machine = store.get("machine",id)
            if not machine:
                raise HTTPException(404,"identity_not_found")
            if machine["state"] == "revoked":
                raise HTTPException(409,"revocation_is_permanent")
            machine["state"] = data.state
            machine["history"].append({"event":data.state,"timestamp":now()})
            change("machine",id,machine)
            return machine

    @app.post("/api/admin/machines/{id}/rotate", dependencies=[Depends(admin)])
    def rotate(id: str, data: Rotation):
        with store.transaction():
            machine = store.get("machine",id)
            if not machine:
                raise HTTPException(404,"identity_not_found")
            if machine["state"] == "revoked" or data.public_key == machine["public_key"]:
                raise HTTPException(409,"rotation_not_permitted")
            machine["public_key"] = data.public_key
            machine["key_version"] += 1
            machine["history"].append({"event":"rotated","timestamp":now(),"public_key":data.public_key})
            change("machine",id,machine)
            return machine

    @app.put("/api/admin/resources", dependencies=[Depends(admin)])
    def protect(data: ResourceInput):
        with store.transaction():
            change("resource",data.path,data.model_dump())
        return data

    @app.put("/api/admin/policies", dependencies=[Depends(admin)])
    def policy(data: Policy):
        with store.transaction():
            if not store.get("resource",data.resource):
                raise HTTPException(422,"resource_not_registered")
            if data.machine != "*" and not store.get("machine",data.machine):
                raise HTTPException(422,"machine_not_registered")
            change("policy",data.id,data.model_dump())
        return data

    @app.get("/api/admin/audit/export", dependencies=[Depends(admin)])
    def export():
        return JSONResponse(store.export(),headers={"Content-Disposition":'attachment; filename="ownergate-audit.json"'})

    @app.get("/api/admin/audit/verify", dependencies=[Depends(admin)])
    def verify():
        try:
            return {"valid":True,**verify_export(store.export(),store.public_key)}
        except Exception:
            return JSONResponse({"valid":False,"detail":"audit_integrity_failure"},status_code=409)

    static = Path(__file__).parent / "static"
    app.mount("/static", StaticFiles(directory=static), name="static")

    @app.get("/")
    def dashboard():
        return FileResponse(static/"index.html")

    return app
