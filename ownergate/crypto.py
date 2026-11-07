"""RFC 8032 Ed25519 and RFC 7515 compact JWS (EdDSA). No custom crypto."""
import base64
import hashlib
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def unb64(value):
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    if b64(raw) != value:
        raise ValueError("Noncanonical base64url")
    return raw


def public(key):
    return b64(key.public_key().public_bytes_raw())


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def sign_record(key, payload):
    header = b64(canonical({"alg": "EdDSA", "typ": "ownergate-audit+jws"}))
    signing = header + "." + b64(canonical(payload))
    return signing + "." + b64(key.sign(signing.encode()))


def verify_export(export, trusted_key, checkpoint=None):
    """Caller must obtain trusted_key/checkpoint independently of the export."""
    previous = "0" * 64
    for sequence, token in enumerate(export["records"], 1):
        head, body, signature = token.split(".")
        if json.loads(unb64(head)) != {"alg": "EdDSA", "typ": "ownergate-audit+jws"}:
            raise ValueError("Unsupported JWS header")
        Ed25519PublicKey.from_public_bytes(unb64(trusted_key)).verify(unb64(signature), (head + "." + body).encode())
        payload = json.loads(unb64(body))
        if payload["sequence"] != sequence or payload["previous_hash"] != previous:
            raise ValueError("Broken audit chain")
        previous = hashlib.sha256(token.encode()).hexdigest()
    result = {"count": len(export["records"]), "head": previous}
    if export["checkpoint"] != result:
        raise ValueError("Export checkpoint mismatch")
    if checkpoint and checkpoint != result:
        raise ValueError("Trusted checkpoint mismatch (possible truncation)")
    return result
