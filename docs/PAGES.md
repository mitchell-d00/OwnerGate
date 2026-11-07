# OwnerGate on GitHub Pages

Public site: **https://mitchell-d00.github.io/OwnerGate/**

The site follows the repository-based publishing pattern of Virtual DMV and
Combined MPLPB while preserving OwnerGate's enforcement boundary. The existing
Pages configuration is **Deploy from a branch → main → / (root)**. Root
`index.html`, `.nojekyll`, and `site/` are the complete buildless public site.
No hosting change or second hosting service is required. Merging those files
into main triggers the repository's existing Pages deployment. The root demo
and the server dashboard at `ownergate/static/` are separate applications.

## Public experience

- Product overview with the principle, research links and simulated access trials.
- Demo machine registry with self-declared operator labels, scopes, suspension,
  activation and permanent revocation within a session.
- Demo policy controls for six actions and an explicit deny override.
- Simulated traffic with machine/resource/action/decision/time filters.
- Hash-linked, signed demonstration records, integrity verification, tampering
  exercise and downloadable evidence explicitly marked demonstration-only.
- Eight isolated adversarial scenarios, unaffected by workspace policy edits.
- A setup guide for the real FastAPI HTTP gateway and its end-to-end pilot client.

All generated identities and audit keys are disposable browser keys. The model
uses maintained browser WebCrypto Ed25519/SHA-256 implementations. Demo export
uses the distinct `ownergate-demo+jws` type and `ownergate.pages-demo.v1` schema,
not the operational audit format. The Python operational verifier deliberately
does not accept this demonstration JWS header. No operational key, administrator
token, production identity, remote API connection, or third-party dependency is
needed. No demo data is persisted in localStorage; reload/reset discards the
session and creates fresh keys and three simulated example decisions.

## What this does and does not prove

Browser signatures are real cryptographic operations. The *authorization
choices* are simulated in a separate JavaScript teaching model, not requests
processed by the Python gateway. The browser owns every demo key and policy;
anyone controlling that browser can alter the simulation. Signed demo exports
prove no server enforcement, legal identity, downstream compliance, or external
history. Their public key is not an independently authenticated identity.

GitHub Pages cannot run FastAPI, host protected resources behind the Python
gateway, or safely hold operational secrets. Its files are public. Actual HTTP
protection remains in the single-host Python/Docker pilot. A real origin adapter,
origin isolation and trusted TLS are required before protecting another website.
The static site never asks users to paste a server administrator token.

## Verification

```bash
node --check site/demo.js
node --check site/app.js
OWNERGATE_SCREENSHOTS=docs/evidence .venv/bin/python -m pytest -q tests/test_pages.py
```

The retained `docs/evidence/pages-browser.txt` records the actual local Chromium
journey. Screenshots are `pages-desktop.png` and `pages-mobile.png`. Tests serve a
copy of the exact static files at the `/OwnerGate/` path, covering relative assets,
seeded decisions, allowed/unknown trials, deny policy, revocation, all eight lab
cases with a conflicting workspace deny, filters, signature verification,
tampering detection, marked exports, setup guidance, reset/reload, 390px layout,
no script errors, and no remote/API requests. The normal CI pytest command also
collects this test. This is not a physical iPad/Safari certification.

For local preview, run `python -m http.server 8080` in the repository and visit
`http://127.0.0.1:8080/`. WebCrypto requires HTTPS or localhost; opening a downloaded
HTML file directly may be unsupported by the browser. Use the public HTTPS URL
for iPad. Browsers without WebCrypto Ed25519 show an initialization error and a
link to the GitHub source/install instructions; use a current browser.

After deployment, check the served bytes against your checkout:

```bash
python scripts/check_pages.py
```

This checks HTTPS status and SHA-256 of the live HTML, JavaScript, stylesheet and
icon; it does not equate HTTP retrieval with a live-device browser journey.
