"""Single-process serialization plus SQLite BEGIN IMMEDIATE transactions."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import threading
from contextlib import contextmanager
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from .crypto import canonical, public, sign_record, verify_export


class Store:
    def __init__(self, directory):
        root = Path(directory)
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        keyfile = root / "audit.pem"
        database = root / "ownergate.db"
        if not keyfile.exists():
            if database.exists():
                raise RuntimeError("Audit key missing for existing database; restore it from backup")
            key = Ed25519PrivateKey.generate()
            with keyfile.open("xb") as f:
                os.chmod(keyfile, 0o600)
                f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        self.key = serialization.load_pem_private_key(keyfile.read_bytes(), password=None)
        self.public_key = public(self.key)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(database, check_same_thread=False, isolation_level=None)
        os.chmod(database, 0o600)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS objects(kind TEXT, id TEXT, body TEXT NOT NULL, PRIMARY KEY(kind,id));
        CREATE TABLE IF NOT EXISTS challenges(nonce TEXT PRIMARY KEY, body TEXT NOT NULL, expires INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS audit(sequence INTEGER PRIMARY KEY, token TEXT NOT NULL, hash TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS meta(id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL);
        INSERT OR IGNORE INTO meta VALUES(1,0);
        ''')
        verify_export(self.export(), self.public_key)

    @contextmanager
    def transaction(self):
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                yield self
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def get(self, kind, id):
        row = self.db.execute("SELECT body FROM objects WHERE kind=? AND id=?", (kind, id)).fetchone()
        return json.loads(row[0]) if row else None

    def put(self, kind, id, body):
        self.db.execute("INSERT OR REPLACE INTO objects VALUES(?,?,?)", (kind, id, canonical(body).decode()))

    def all(self, kind):
        return [json.loads(r[0]) for r in self.db.execute("SELECT body FROM objects WHERE kind=? ORDER BY id", (kind,))]

    def version(self, bump=False):
        if bump:
            self.db.execute("UPDATE meta SET version=version+1 WHERE id=1")
        return self.db.execute("SELECT version FROM meta WHERE id=1").fetchone()[0]

    def record(self, payload):
        row = self.db.execute("SELECT sequence, hash FROM audit ORDER BY sequence DESC LIMIT 1").fetchone()
        payload = {**payload, "schema": "ownergate.audit.v1", "sequence": row[0]+1 if row else 1, "previous_hash": row[1] if row else "0"*64}
        token = sign_record(self.key, payload)
        self.db.execute("INSERT INTO audit VALUES(?,?,?)", (payload["sequence"], token, hashlib.sha256(token.encode()).hexdigest()))
        return payload

    def export(self):
        with self.lock:
            rows = self.db.execute("SELECT token,hash FROM audit ORDER BY sequence").fetchall()
            return {"public_key": self.public_key, "records": [r[0] for r in rows], "checkpoint": {"count": len(rows), "head": rows[-1][1] if rows else "0"*64}}

    def events(self):
        from .crypto import unb64
        return [json.loads(unb64(t.split('.')[1])) for t in self.export()["records"]]
