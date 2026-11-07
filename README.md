# OwnerGate

**Your resources. Your rules. Verified machine access.**

v0.1.0 — Machine Access Gateway. An independent, executable single-host pilot
for owner-controlled machine access. FastAPI enforces authorization at an actual
HTTP boundary, backed by an Ed25519 machine registry, one-use request proofs,
deny-first policies, SQLite, signed audit records and a responsive owner dashboard.

This release protects an included test website, with public `/public` and
owner-created protected `/resources/name` endpoints. It is not yet an adapter
for arbitrary existing websites. A verified machine proves control of a key,
not a legal identity or entitlement. Downstream-use restrictions are declarations;
the gateway cannot prove what someone does with bytes after receiving them.

## Run locally (Python 3.12+)

```bash
git clone https://github.com/mitchell-d00/OwnerGate.git
cd OwnerGate
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.lock
python -m pip install --no-deps --no-build-isolation -e .
export OWNERGATE_ADMIN_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export OWNERGATE_AUDIENCE=http://127.0.0.1:8000
ownergate serve
```

Open **http://127.0.0.1:8000**. Paste the token from your local shell environment
into the owner login (retrieve it privately; do not publish it or put it in URLs).
The token stays in tab memory and a reload locks the workspace. State and the
audit signing key persist in `state/`; do not commit or publish that directory.
Run one process and one worker only. Use a trusted TLS reverse proxy outside
loopback; see [security boundaries](docs/SECURITY.md).

In a second terminal with the same virtual environment and administrator token:

```bash
python scripts/pilot_demo.py --output /tmp/ownergate-demo
```

This registers a fresh demo public key, protects a real endpoint, grants read,
sends an authorized HTTP request (200), sends an unknown request (401), revokes
the machine, retries (403), checks the actual dashboard records, exports signed
evidence, and launches an independent verifier process. Open Overview to inspect
the decisions. Private demonstration keys are ephemeral and are never saved.

## Use your own machine client

```bash
ownergate keygen /tmp/my-agent.pem
```

Register the printed public key in **Machine Registry**, with scope
`/resources/pilot`. Use **Resource Policies** to create that exact protected
endpoint and a valid allow rule for the registered machine's `read` action.
All six actions are supported: read, crawl, index, summarize, download and
redistribute. Rule forms contain editable validated JSON examples. A deny rule
always takes precedence. Scope and credential status are checked independently.

```bash
ownergate request --key /tmp/my-agent.pem --machine my-agent --resource /resources/pilot
```

Use **Revoke** in the registry to permanently block that machine. The same client
then receives a denial. Use **Testing Laboratory** for eight clearly labeled
adversarial HTTP scenarios with disposable browser-held demonstration keys.
These tests write real registry/policy/audit entries; use a disposable pilot.

## Independent audit verification

Export signed evidence in Audit Center. Obtain and pin the audit public key
through a trusted channel independently of the exported file. Save a trusted
checkpoint (`count` and `head`) externally to detect suffix deletion.

```bash
ownergate verify /tmp/ownergate-demo/audit.json \
  --public-key YOUR_PINNED_BASE64URL_PUBLIC_KEY \
  --checkpoint /tmp/ownergate-demo/checkpoint.json
```

The command exits nonzero on invalid signatures, chain/order changes, key
mismatch or checkpoint mismatch. Without a trusted checkpoint, a valid truncated
prefix can pass. Evidence establishes the gateway's recorded decision under its
signing key; it does not prove complete response delivery, global history,
downstream compliance, or the identity of an unknown attacker.

## Docker Compose

Set the random `OWNERGATE_ADMIN_TOKEN` as above, then:

```bash
docker compose up --build -d --wait
# Open http://127.0.0.1:8000
docker compose down
```

Compose publishes loopback only, uses a non-root user, read-only root filesystem,
no added capabilities, and a persistent state volume. `down` retains state;
`down -v` deletes it and should only be used for disposable test instances.
Do not run the Python and Compose examples on the same port simultaneously.

## Tests and verification

```bash
python -m pip install -r requirements-dev.lock
python -m playwright install --with-deps chromium
python -m pytest -q
pip-audit -r requirements.lock --disable-pip --no-deps
```

Tests start temporary loopback HTTP servers. Chromium is required. Set
`CHROMIUM_EXECUTABLE=/path/to/chromium` to use a system browser; otherwise the
suite uses `/usr/bin/chromium` when available or Playwright's installed browser.
See [actual results and retained failure logs](docs/TEST_RESULTS.md),
[release checklist](docs/RELEASE.md), [research review](docs/RESEARCH.md),
[architecture/API](docs/ARCHITECTURE.md) and [proof protocol](docs/PROTOCOL.md).
GitHub Actions runs gateway/browser tests, dependency scanning and a Compose
HTTP demonstration. Local results do not establish a successful remote CI run.

## Research foundation and limits

OwnerGate draws on Mitchell D. McPhetridge's Virtual DMV, Networked MPLPB,
Combined MPLPB and OneOwner research. Exact inspected revisions and licensing
boundaries are recorded in [RESEARCH.md](docs/RESEARCH.md). Their original code,
papers and demonstration private keys have not been imported or modified.

This pilot has one administrator role, a local plaintext audit key, in-memory
rate limits, unpaginated audit history and no external-origin proxy adapter.
A stolen credential, bypassed external origin, compromised host or stolen owner
token remains a risk. Passing tests do not make it production-secure. The
repository owner must choose a project license before redistribution; research
licenses do not automatically license this independent product.
