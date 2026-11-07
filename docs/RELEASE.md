# v0.1.0 — Machine Access Gateway

Controlled single-host pilot candidate. The original research repositories were
read only and remain separate. See [actual results](TEST_RESULTS.md).

## Implemented and locally checked

- [x] Independent FastAPI project, maintainable backend layers and minimal frontend.
- [x] Actual protected HTTP endpoints; public test page; no exposed upstream socket.
- [x] Owner-authenticated public-key enrollment, expiry, suspension, permanent
  revocation, rotation and history; self-declared operator labels.
- [x] One-use 60-second request-bound Ed25519 proof, current key/lifecycle/scope
  validation and deterministic deny-overrides policies for six actions.
- [x] Signed/hash-linked gateway and administration evidence, export and
  independent pinned-key/checkpoint verification command.
- [x] Six responsive dashboard views and eight actual-HTTP disposable lab cases.
- [x] Negative/concurrent/recovery tests and desktop/mobile Chromium journey.
- [x] Dependency scan, Docker build and Compose HTTP/restart verification.
- [x] Reproducible commands, threat model, protocol, licensing review and failure logs.
- [x] GitHub Actions workflow for tests, scanning, artifact retention and Compose pilot.

## Before a public or production deployment

- [ ] Repository owner chooses an explicit OwnerGate license.
- [ ] Observe a successful CI run on the final candidate; local checks do not
  establish a GitHub-hosted CI result.
- [ ] Review external-origin integration and ensure the origin cannot be reached
  through any alternate route before protecting an existing website.
- [ ] Complete independent security review, operational load/abuse evaluation,
  proxy/TLS configuration, and documented incident response.
- [ ] Decide multi-user owner authentication, MFA and token lifecycle requirements.
- [ ] Provide appropriate signing-key custody/rotation, encrypted backups,
  externally retained checkpoints and tested recovery procedures.
- [ ] Implement storage quotas, audit retention/pagination and privacy controls.
- [ ] Add dependency artifact hashes, image/Actions digest pinning and scheduled
  vulnerability review appropriate to the deployment.
- [ ] Evaluate supported mobile browsers and accessibility with real users/tools.

## Known limitations

Only the included GET-only document test application is protected. OwnerGate is
not yet a drop-in reverse proxy for arbitrary websites. Requested action is a
signed purpose declaration; downstream indexing, redistribution, training and
other use cannot be observed or enforced after bytes are delivered. Credentials
are server-held registry records, not federated legal identities or independently
attested portable licenses. Audit integrity does not prove that the gateway
reported truthfully, that a client received all bytes, that an unknown attacker
has been identified, or that an uncheckpointed suffix was not removed.

One process, one SQLite database, one owner token. No high availability,
distributed limits, audit key rotation, automatic renewal, policy delete API,
remote discovery, billing or reputation. State and local audit private key are
plaintext to the filesystem owner. Policy/configuration tables are trusted local
state, not reconstructed from signed history at startup. Administrator actions
share one role; a stolen token can change every policy. Revocation blocks new
decisions, not already authorized in-flight responses or content previously
received. Host compromise and stolen machine credentials remain meaningful risks.

This is an executable and tested pilot, not a production-security certification.
