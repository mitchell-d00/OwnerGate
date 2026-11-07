# Threat model and operating boundaries

Assets: protected document bytes; machine key bindings and status; owner policies;
admin token; audit signing key; audit evidence. Actors: legitimate machines,
unregistered crawlers, registered but unauthorized machines, a malicious or
compromised machine with a valid key, owner administrator, host/storage operator.

Trust boundaries: untrusted HTTP to gateway; browser presentation to authenticated
admin API; external client key custody to proof verifier; gateway to local
SQLite/private filesystem; exported evidence to an independent verifier.
The owner controls policies and enrollment; a registry entry authenticates key
control only. It does not certify a legal person, honesty, ownership rights,
or actual downstream intent. Unknown machines receive no privileged content.

| Threat | Control | Remaining limit |
| --- | --- | --- |
| Anonymous/spoofed bot | Fresh signed challenge, current public key, default deny | Stolen credentials authenticate their holder |
| Replayed or substituted request | Atomic nonce deletion, 60-second lifetime, audience/resource/action/key-version binding; GET-only empty-body shape | A stolen fresh proof can race for the bound request without TLS |
| Excess permission | Scope, credential validity, deny overrides allow, owner-only policy writes | Owner misconfiguration or stolen admin token is authoritative |
| Bypass HTTP boundary | Test upstream has no separate socket or mount; explicit resource lookup only | Arbitrary existing external origins are not protected by this pilot |
| Registry abuse / exhaustion | Per-IP 240 requests/minute, admin 60/minute, bounded 4,096 IP windows, 2,048 challenges, 64 KiB app body limit | Not DDoS defense; proxy aggregation, slow clients, logs and persistent object growth need external quotas |
| Browser injection | User text rendered with textContent; external assets absent; restrictive CSP and frame denial | Malicious extension, compromised browser or served app code can read supplied token |
| CSRF | Bearer-only admin API, no cookie auth, no permissive CORS | Same-origin XSS or token theft remains powerful |
| Audit modification | Ed25519 JWS, sequence and hash linking, startup verify, independent CLI | Uncheckpointed suffix deletion, signed lies by key holder, full host compromise |
| Secret exposure | No fixed secrets, no token response, restrictive state/key modes, no private-key download routes | File owners/root and backups can read plaintext audit key and token environment |
| Restarts / concurrency | WAL transactions, lock, durable nonce consume + audit, current lifecycle check | One process only; no HA or distributed replay/rate store |

## Key management

Set the admin token through an environment or secret manager; it is one owner
role with no MFA, login sessions, per-user accountability, or automatic expiry.
Rotate by restarting with a new token. Configure a unique audience per instance.
Audit key is generated once using OS randomness in `state/audit.pem`, mode 0600,
unencrypted on the local filesystem, never sent to the browser. Registry and
policy/audit state live in `state/ownergate.db`; protect the entire directory and
backups. Pin the public audit key separately. Never replace a lost key over an
existing database: restore a consistent backup or create an explicitly new
instance with new identity. Audit key rotation is not implemented. Machine key
rotation is owner-authorized and retains old public keys in signed history;
old outstanding challenges fail key-version checks. Revocation is permanent.
Disposable lab keys exist only in browser memory, are clearly labeled, are not
exported, and never represent operational credentials. The CLI demo also uses
fresh temporary keys. No Virtual DMV seeds are included.

## Deployment and recovery

Bind locally by default. Compose publishes only 127.0.0.1. For a nonlocal pilot,
place a trusted TLS reverse proxy in front; configure upstream body/header/time
limits and network-level rate limiting. Disable caches and prevent every alternate
origin route. The app ignores forwarded address headers. Default rate limiting
therefore groups requests by proxy address; design trusted proxy handling before
wider access. Use one worker; do not start competing instances on one state path.

Take a consistent SQLite online backup (Python `sqlite3.Connection.backup`) while
holding the instance's store lock, or stop the app and back up the whole state
directory including WAL files and audit key. Restore only trusted, consistent
snapshots; startup signature checks cannot detect a valid old snapshot without
an externally retained checkpoint. Test recovery and checkpoint verification.
Protect exports: administration records can include resource contents and declared
operator information. Retention/pagination/erasure policy is not implemented.

Abuse controls are application-level pilot controls. Use server/proxy request
header limits, connection timeouts, disk monitoring, retention and IP controls
for an exposed service. A compromised host, signing key, admin token or external
origin can defeat the model. A passing test suite is not a security audit or a
claim of production readiness. Report vulnerabilities privately to the repository
owner; avoid posting secrets in public issues.
