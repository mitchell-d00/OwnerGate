# Research review and provenance

Reviewed 2026-11-07, before implementation. Exact checkouts are pinned in
[research-lock.json](research-lock.json). Original repositories remain unchanged.
OwnerGate is an independent implementation, not a fork, distributor of their
papers, or production deployment of their reference engines.

Research by **Mitchell D. McPhetridge**:

| Repository | Sources inspected | Useful foundation | Boundary / missing capability |
| --- | --- | --- | --- |
| [Virtual DMV](https://github.com/mitchell-d00/Virtual-DMV-Bot-Traffic-Research-Rig) | README; `src/virtual_dmv/engine.py`; crypto and policy-matrix tests; `docs/THREAT-MODEL.md`; LICENSE | Short-lived one-use challenges, identity distinct from permission, scoped authorization, lifecycle and receipt chains | Page-local simulation, browser-exported demo seeds, educational pure-Python crypto; no network enforcement or real admin boundary |
| [Networked MPLPB](https://github.com/mitchell-d00/networked-mplpb) | README; `Docs/PROTOCOL.md`; `mplpb_net/{node,router,retrieve}.py`; network tests; LICENSE | Independently verifiable evidence envelopes; discovery versus authority; ambiguous ownership remains visible | Declared scope is not ownership certification; educational crypto; resource discovery does not authorize HTTP requests |
| [Combined MPLPB](https://github.com/mitchell-d00/Combined-MPLPB-A-closed-local-ledger-of-pages-that-answers-only-from-those-pages) | README; `mplpb_combined/{ledger,provenance_gate}.py`; provenance tests; production threat model; LICENSE | Evidence preservation, explicit refusal, deterministic verification boundaries | Page declarations do not authenticate legal authorship; lexical support does not establish truth or permission |
| [OneOwner](https://github.com/mitchell-d00/OneOwner-powered-by-MPLPB) | README; AGENTS; `oneowner/app.js`; `scripts/build_oneowner.py`; `tests/browser_oneowner.py` | Independent product workspace, plain-language outcomes with expandable raw evidence, text-safe DOM construction, actual browser journeys | Browser storage and presentation are not access control; pinned research engine serves another purpose |

No source, cryptographic routines, private keys, papers, or packaged research
engines were copied into OwnerGate. Reused ideas: evidence disclosure, explicit
refusal, scope checks, independent verification and a separate product surface.
The tests here were newly written; upstream reported counts were not rerun or
claimed as OwnerGate results.

## Licensing review

Virtual DMV software is MIT; its original papers are excluded from that license.
Networked MPLPB software is MIT; documentation/specification/seed prose is CC BY
4.0. Combined MPLPB software is MIT, documentation/examples CC BY 4.0, and vendored
parts retain their individual licenses; separate UI/paper notices also exist.
OneOwner's build preserves upstream licensing and packages a pinned engine; its
presentation was inspected, not imported. No root LICENSE was present in the
inspected OneOwner checkout, so do not assume permission to copy its product code.
If future contributors copy code or prose, review the exact file's license and
carry required notices; this review does not grant rights to research papers.
OwnerGate's initial checkout had no license. No new project license has been
asserted on behalf of its owner; choose one before public redistribution.

## Architecture risks resolved in this pilot

No self-signed participant credential confers authority: the owner registers a
public key and independently sets permissions. No discovery, reputation, or
federated registry is trusted. Deny overrides all allows; protected resources
have no anonymous allow rule. There are no imported demo credentials. Operational
machine keys remain on the client; the lab generates explicitly disposable keys.
The test upstream is not exposed as a second socket or unguarded application.

## Deferred work

External origin integration needs a separate reviewed adapter plus network
isolation. Federation, independent operator attestation, distributed replay
stores, hardware-backed keys, legal ownership certification, billing and
reputation are outside v0.1.0.
