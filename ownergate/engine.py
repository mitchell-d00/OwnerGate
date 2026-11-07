"""Authentication and deterministic deny-overrides policy evaluation."""
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from .crypto import canonical, unb64


def state(machine, now):
    if machine["state"] != "active":
        return machine["state"]
    return "expired" if now >= machine["expires_at"] else "active"


def authorize(store, *, machine_id, nonce, signature, resource, action, now, audience):
    """Inside one transaction: consume nonce, verify current key/state and policy."""
    machine = store.get("machine", machine_id) if machine_id else None
    verified = False
    row = store.db.execute("DELETE FROM challenges WHERE nonce=? RETURNING body", (nonce,)).fetchone() if nonce else None
    if not machine:
        return False, "unknown_identity", verified, []
    if not row:
        return False, "missing_or_replayed_challenge", verified, []
    challenge = json.loads(row[0])
    if not challenge["issued_at"] <= now < challenge["expires_at"]:
        return False, "challenge_expired_or_clock_invalid", verified, []
    if any(challenge[k] != v for k, v in {"machine":machine_id,"resource":resource,"action":action,"audience":audience,"key_version":machine["key_version"]}.items()):
        return False, "request_binding_mismatch", verified, []
    try:
        Ed25519PublicKey.from_public_bytes(unb64(machine["public_key"])).verify(unb64(signature), canonical(challenge))
        verified = True
    except (ValueError, TypeError, InvalidSignature):
        return False, "invalid_signature", False, []
    current = state(machine, now)
    if current != "active":
        return False, "credential_" + current, verified, []
    if now < machine["issued_at"]:
        return False, "credential_not_yet_valid", verified, []
    if resource not in machine["scopes"]:
        return False, "resource_outside_scope", verified, []
    matches = [p for p in store.all("policy") if p["resource"] == resource and p["machine"] in (machine_id,"*") and action in p["actions"] and p["not_before"] <= now < p["expires_at"]]
    if any(p["effect"] == "deny" for p in matches):
        return False, "explicit_deny", verified, []
    allows = [p for p in matches if p["effect"] == "allow"]
    if not allows:
        return False, "no_allow_policy", verified, []
    return True, "policy_allow", verified, [p["restrictions"] for p in allows if p["restrictions"]]
