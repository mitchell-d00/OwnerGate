# Actual verification results — 2026-11-07

These are local implementation results for v0.1.0, not an independent security
audit, deployment certification, benchmark, or claim about the research papers.
Python 3.12.14, Linux, system Chromium via Playwright 1.64.1. Exact dependency
versions are in the two lock files. Tests use fresh temporary state and keys.

| Check | Actual result | Retained evidence |
| --- | --- | --- |
| Gateway, crypto, policy, API, lifecycle, concurrency, recovery | 63 passed | `evidence/pytest-debug.txt` |
| Full suite including real Chromium owner journey | 64 passed; one dependency deprecation warning | `evidence/pytest-final.txt`, `evidence/junit.xml` |
| Final UI after readable reasons and horizontally scrollable mobile tables | 1 browser journey passed | `evidence/browser-final.txt`, desktop/mobile PNGs |
| Separate server process, actual HTTP MVP and independent verifier subprocess | 200 authorized, 401 unknown, 403 revoked; signed audit valid | `evidence/http-demo.txt`, `evidence/http-server.txt`, `evidence/http-demo/` |
| Final Docker image build | Completed successfully | `evidence/docker-build-final.txt` |
| Disposable Compose pilot and container restart | Same 200/401/403 sequence; seven signed records and signing key survived restart | `evidence/compose-demo.txt`, `evidence/compose-demo/` |
| Pinned runtime dependency scan | No known vulnerabilities found at scan time | `evidence/dependency-audit.txt` |

The browser journey verifies failed administrator login; all eight real HTTP
lab cases; exact overview counts; registry/policy screens; malformed policy
editor feedback; traffic decision filtering; audit integrity and download;
desktop and 390px mobile layout; reload locking; no localStorage credential
persistence; and no JavaScript page errors. It is Chromium coverage, not a
physical iPad/Safari or assistive-technology audit. Only the lab writes and
selected dashboard actions are automated; not every form/control has a full
browser journey.

The 63 gateway checks cover valid/invalid proofs, nonce replay and concurrent
redemption (exactly one of ten succeeds), expiry and backwards server clock,
suspended/revoked/future/expired credentials, scope failure, explicit deny
conflicts (specific and wildcard), each of the six actions allowed and refused,
policy validity, unknown identity attribution, all administrative endpoints
without valid authentication, malformed JSON and oversized input, request path
and action binding, key rotation, irreversible revocation, restarts, replay after
restart, audit signature/payload/order/deletion/key tampering, trusted-checkpoint
truncation detection, missing key/corrupt-audit startup rejection, request limits,
and protected-route isolation. Parameterized cases are checks, not independent
scientific experiments.

## Reproduction commands

From the repository root after creating `.venv` and installing pinned dependencies:

```bash
.venv/bin/python -m pip install -r requirements-dev.lock
.venv/bin/python -m pip install --no-deps --no-build-isolation -e .
# Use system Chromium, or install the Playwright-managed browser:
.venv/bin/python -m playwright install --with-deps chromium
OWNERGATE_SCREENSHOTS=docs/evidence .venv/bin/python -m pytest -q --junitxml=docs/evidence/junit.xml
.venv/bin/pip-audit -r requirements.lock --disable-pip --no-deps
```

The managed sandbox initially prohibited sockets. Real HTTP/browser tests were
run with permitted loopback network access. Production defaults were retained;
the test fixture raises the general rate limit to permit adversarial checks and
injects a controllable server clock for expiry tests. The browser test uses
actual wall time so it agrees with its disposable client's time.

For the separate-process example, start the server with the README commands,
then run `python scripts/pilot_demo.py --output /tmp/ownergate-demo`. It verifies
its export with a separate CLI process and a public key taken from the
authenticated control plane independently of the exported file. For an actual
external verifier, retain that key/checkpoint through a separate trusted channel.
The checked-in audit exports are disposable demonstration evidence only.

The managed Docker build used the session CA without disabling TLS verification:

```bash
env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
  docker --host=unix:///var/run/docker.sock build \
  --secret id=proxy_ca,src=/etc/ssl/certs/ca-certificates.crt -t ownergate:0.1.0 .
```

Compose verification used a disposable project `ownergate-verification`, the
checked-in `compose.yaml` plus an override setting `image: ownergate:0.1.0`, and
`up --no-build -d --wait`. A fresh random administrator token was supplied only
through the environment. The HTTP demo ran against published loopback port 8000,
then `compose restart` and authenticated `/api/admin/audit/verify` confirmed seven
persisted records. Finally `compose down -v` removed only this disposable project's
container/network/volume. The ordinary README setup builds directly with Compose;
CI automates that path, but a remote CI run has not been observed in this session.

## Failures and corrections retained

- `evidence/pytest-initial.txt`: interrupted initial run under a socket-prohibited
  sandbox, producing fixture errors; a focused diagnostic identified
  `PermissionError: [Errno 1] Operation not permitted` at `socket.socket()`.
  The permitted-network run completed all 63 gateway checks.
- `evidence/browser-initial.txt`: first browser run failed the authorized lab case
  because the fixture's frozen clock preceded a later browser-generated policy
  start. The browser fixture now uses wall time; deterministic expiry tests retain
  the controlled clock. This was a test harness correction.
- `evidence/browser-debug.txt`: all lab cases completed, then the mobile check
  failed because viewport size was called on BrowserContext instead of Page.
  Corrected the test API call and reran successfully.
- `evidence/dependency-audit-initial.txt`: scan invocation required `--no-deps`
  for the fully pinned, non-hashed requirements. Corrected the command in docs/CI
  and reran; final scan found no known vulnerabilities. Pins are not artifact
  hashes; dependency lock hashing remains a release improvement.
- The first Docker build completed but its final offline package install emitted
  a nonfatal pip version-check TLS warning. Added `--no-index` to that local
  installation step; final Docker build completed without that warning.
- Full tests emit Starlette's deprecation warning about its httpx TestClient
  integration in two in-process recovery/rate checks. Actual gateway/browser
  tests use real sockets. The warning is retained, not suppressed.

No failed check is represented as passing. No remote deployment, production load,
federation, real operator verification, external-origin gateway integration, or
third-party penetration test was performed.
