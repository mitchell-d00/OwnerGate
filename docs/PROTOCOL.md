# Machine proof protocol v1

OwnerGate uses RFC 8032 Ed25519 via `cryptography`. Public keys are raw 32-byte
Ed25519 values encoded as unpadded canonical base64url. Proof signatures are raw
64-byte RFC 8032 signatures encoded the same way. Operational keys are generated
and retained by the machine client, never placed in the dashboard.

1. POST `/api/challenges` with strict JSON
   `{"machine":"my-agent","resource":"/resources/pilot","action":"read"}`.
2. Server returns a JSON challenge containing schema, random 256-bit nonce,
   machine, exact resource, action, issued/expiry epoch times, key version,
   configured audience, method `GET`, and SHA-256 of an empty body.
3. Sign the **entire server-returned object** using JSON sorted by key, compact
   separators, ASCII escaped strings, no whitespace, UTF-8 bytes. This protocol's
   fields are constrained to ASCII strings and integer times, avoiding general
   JSON canonicalization ambiguity. See `crypto.canonical` and the client command.
4. GET the exact resource, with no query string or body, carrying headers:
   `X-OwnerGate-Machine`, `X-OwnerGate-Action`, `X-OwnerGate-Nonce`, and
   `X-OwnerGate-Signature`.
5. Server atomically deletes the pending nonce, validates `issued_at <= now <
   expires_at` (60 seconds), checks audience, machine, key version, resource/action,
   then verifies signature using the current registered key. Method, body and
   query shape are enforced separately before content delivery. Policies and
   credential expiry use the same trusted server clock.

The client cannot change challenge times, audience, or binding: the server
verifies the stored challenge, not client-supplied replacement JSON. Challenges
are single use even for invalid signatures and binding failures. Unsupported
request shapes are rejected before redemption, so a rejected shape cannot grant
access. Rate limits apply at issuance and request ingress. Client clock is not
trusted; server clock rollback rejects future-issued challenges. A privileged
operator can change the server clock, which remains a documented trust boundary.
Only GET content retrieval is supported in v1; the six actions are distinct
owner-approved purposes attached to that retrieval, not six different HTTP verbs.
The server cannot observe what the client ultimately does with returned bytes.

Signatures bind the configured audience rather than untrusted Host/forwarding
headers. Give every deployment a distinct audience URL and use TLS outside
loopback. Run the client against that configured deployment. TLS remains
necessary: a stolen fresh proof could race its legitimate holder for the same
request, even though replay after redemption fails.

## Audit format

Each record is compact RFC 7515 JWS with protected header
`{"alg":"EdDSA","typ":"ownergate-audit+jws"}`. Payload includes schema, monotonically
increasing sequence and SHA-256 of the preceding compact token (`0`×64 for genesis).
The exported checkpoint contains record count and SHA-256 of the last token.
The verifier checks the trusted external key, JWS signature, sequence, chain, and
checkpoint. Pin the public key outside the export; trusting an attacker-supplied
export key defeats verification. Save a checkpoint externally to detect deletion
of a suffix; re-signed history under a stolen key cannot be detected without an
external trusted checkpoint. Export includes administration snapshots so a
reviewer can inspect the policy and registry changes behind recorded versions.
The verifier checks integrity, not legal identity, policy correctness, downstream
compliance, response delivery completion, or completeness outside its checkpoint.
