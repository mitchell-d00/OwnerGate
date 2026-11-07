/* Browser-only teaching model. It never connects to or protects a resource server.
 * Uses real WebCrypto primitives with ephemeral demo keys, independent of the
 * Python gateway. Its decisions are not operational authorization evidence. */
"use strict";
window.OwnerGateDemo = (() => {
  const enc = new TextEncoder();
  const actions = [
    "read",
    "crawl",
    "index",
    "summarize",
    "download",
    "redistribute",
  ];
  const b64 = (raw) =>
    btoa(String.fromCharCode(...new Uint8Array(raw)))
      .replaceAll("+", "-")
      .replaceAll("/", "_")
      .replaceAll("=", "");
  const decode = (str) =>
    Uint8Array.from(
      atob(
        str.replaceAll("-", "+").replaceAll("_", "/") +
          "=".repeat((4 - (str.length % 4)) % 4),
      ),
      (c) => c.charCodeAt(0),
    );
  const canonical = (value) =>
    JSON.stringify(value, (key, v) =>
      v && typeof v === "object" && !Array.isArray(v)
        ? Object.fromEntries(
            Object.keys(v)
              .sort()
              .map((k) => [k, v[k]]),
          )
        : v,
    );
  const hash = async (text) =>
    Array.from(
      new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(text))),
      (v) => v.toString(16).padStart(2, "0"),
    ).join("");
  const epoch = () => Math.floor(Date.now() / 1000);
  let machines,
    policies,
    events,
    records,
    pending,
    auditKey,
    version,
    serial = Promise.resolve();
  async function identity(id, state = "active", options = {}) {
    const key = await crypto.subtle.generateKey("Ed25519", true, [
      "sign",
      "verify",
    ]);
    const m = {
      id,
      operator: "Self-declared demonstration operator",
      public_key: b64(await crypto.subtle.exportKey("raw", key.publicKey)),
      scopes: ["/resources/research"],
      issued_at: epoch() - 60,
      expires_at: epoch() + 3600,
      state,
      key_version: 1,
      history: [],
      ...options,
    };
    machines.set(id, { ...m, key });
    return m;
  }
  function visible(m) {
    const { key, ...body } = m;
    return {
      ...body,
      effective_state:
        body.state === "active" && epoch() >= body.expires_at
          ? "expired"
          : body.state,
    };
  }
  async function append(payload) {
    const event = {
      ...payload,
      schema: "ownergate.pages-demo.v1",
      traffic_source: "browser_simulation",
      timestamp: epoch(),
      request_id: crypto.randomUUID(),
      sequence: records.length + 1,
      previous_hash: records.length
        ? await hash(records.at(-1))
        : "0".repeat(64),
      policy_version: version,
    };
    const input =
      b64(enc.encode(canonical({ alg: "EdDSA", typ: "ownergate-demo+jws" }))) +
      "." +
      b64(enc.encode(canonical(event)));
    records.push(
      input +
        "." +
        b64(
          await crypto.subtle.sign(
            "Ed25519",
            auditKey.privateKey,
            enc.encode(input),
          ),
        ),
    );
    events.push(event);
    return event;
  }
  async function init() {
    machines = new Map();
    policies = [];
    events = [];
    records = [];
    pending = new Map();
    version = 1;
    auditKey = await crypto.subtle.generateKey("Ed25519", true, [
      "sign",
      "verify",
    ]);
    await identity("research-agent");
    await identity("registered-without-permission");
    await identity("revoked-agent", "revoked");
    policies.push({
      id: "research-read",
      machine: "research-agent",
      resource: "/resources/research",
      actions: ["read"],
      effect: "allow",
      not_before: epoch() - 60,
      expires_at: epoch() + 3600,
      restrictions:
        "Attribution required; no redistribution (declarations only).",
    });
    await evaluate("research-agent");
    await evaluate("unknown-agent");
    await evaluate("revoked-agent");
  }
  function snapshot() {
    return {
      machines: [...machines.values()].map(visible),
      policies: structuredClone(policies),
      events: structuredClone(events),
      version,
    };
  }
  async function evaluate(id, action = "read", options = {}) {
    const m = machines.get(id),
      resource = options.resource || "/resources/research";
    const challenge = {
      schema: "ownergate.pages-demo.challenge.v1",
      nonce: crypto.randomUUID(),
      machine: id,
      resource,
      action,
      issued_at: epoch(),
      expires_at: epoch() + 60,
      key_version: m?.key_version || 0,
      audience: "browser-demonstration-only",
    };
    pending.set(challenge.nonce, challenge);
    const sig = m
      ? new Uint8Array(
          await crypto.subtle.sign(
            "Ed25519",
            m.key.privateKey,
            enc.encode(canonical(challenge)),
          ),
        )
      : new Uint8Array(64);
    if (options.tamper) sig[0] ^= 1;
    async function redeem() {
      const stored = pending.get(challenge.nonce);
      pending.delete(challenge.nonce);
      let verified = false,
        reason = "unknown_identity",
        allow = false;
      if (m) {
        if (!stored) reason = "missing_or_replayed_challenge";
        else if (epoch() >= stored.expires_at) reason = "challenge_expired";
        else {
          verified = await crypto.subtle.verify(
            "Ed25519",
            m.key.publicKey,
            sig,
            enc.encode(canonical(stored)),
          );
          if (!verified) reason = "invalid_signature";
          else if (m.state !== "active") reason = "credential_" + m.state;
          else if (epoch() >= m.expires_at) reason = "credential_expired";
          else if (epoch() < m.issued_at) reason = "credential_not_yet_valid";
          else if (!m.scopes.includes(resource))
            reason = "resource_outside_scope";
          else {
            const matches = policies.filter(
              (p) =>
                [id, "*"].includes(p.machine) &&
                p.resource === resource &&
                p.actions.includes(action) &&
                p.not_before <= epoch() &&
                epoch() < p.expires_at,
            );
            if (matches.some((p) => p.effect === "deny"))
              reason = "explicit_deny";
            else if (matches.some((p) => p.effect === "allow")) {
              allow = true;
              reason = "policy_allow";
            } else reason = "no_allow_policy";
          }
        }
      }
      return append({
        kind: "decision",
        machine: verified ? id : "unknown",
        claimed_machine: id,
        identity_verified: verified,
        resource,
        action,
        decision: allow ? "allow" : "deny",
        reason,
      });
    }
    const first = await redeem();
    return options.replay ? redeem() : first;
  }
  function queue(fn) {
    const next = serial.then(fn);
    serial = next.catch(() => {});
    return next;
  }
  async function lab(mode) {
    const id = "lab-" + mode + "-" + crypto.randomUUID().slice(0, 8);
    const resource = "/resources/" + id;
    if (mode !== "unknown") {
      await identity(id, mode === "revoked" ? "revoked" : "active", {
        scopes: [resource],
        ...(mode === "expired"
          ? { expires_at: epoch() - 1 }
          : mode === "scope"
            ? { scopes: ["/resources/other"] }
            : {}),
      });
      if (mode !== "unauthorized")
        policies.push({
          ...policies[0],
          id,
          machine: id,
          resource,
          actions: ["read"],
          effect: "allow",
        });
    }
    version++;
    const event = await evaluate(id, "read", {
      tamper: mode === "tampered",
      replay: mode === "replay",
      resource,
    });
    const expected = {
      authorized: "policy_allow",
      unauthorized: "no_allow_policy",
      unknown: "unknown_identity",
      revoked: "credential_revoked",
      expired: "credential_expired",
      scope: "resource_outside_scope",
      tampered: "invalid_signature",
      replay: "missing_or_replayed_challenge",
    }[mode];
    return { pass: event.reason === expected, event };
  }
  async function exportAudit() {
    return {
      kind: "BROWSER_DEMONSTRATION_ONLY",
      notice:
        "Simulated decisions signed with a disposable browser key; no server-enforced HTTP access occurred.",
      public_key: b64(await crypto.subtle.exportKey("raw", auditKey.publicKey)),
      records: [...records],
      checkpoint: {
        count: records.length,
        head: records.length ? await hash(records.at(-1)) : "0".repeat(64),
      },
    };
  }
  async function verify(data) {
    const expected = b64(
      await crypto.subtle.exportKey("raw", auditKey.publicKey),
    );
    if (
      data.public_key !== expected ||
      data.kind !== "BROWSER_DEMONSTRATION_ONLY"
    )
      throw Error("Wrong demo key or evidence type");
    let previous = "0".repeat(64);
    for (let i = 0; i < data.records.length; i++) {
      const [h, b, s] = data.records[i].split(".");
      if (
        !(await crypto.subtle.verify(
          "Ed25519",
          auditKey.publicKey,
          decode(s),
          enc.encode(h + "." + b),
        ))
      )
        throw Error("Signature check failed: record " + (i + 1));
      const p = JSON.parse(new TextDecoder().decode(decode(b)));
      if (
        p.schema !== "ownergate.pages-demo.v1" ||
        p.sequence !== i + 1 ||
        p.previous_hash !== previous
      )
        throw Error("Demo chain check failed");
      previous = await hash(data.records[i]);
    }
    if (
      data.checkpoint.count !== data.records.length ||
      data.checkpoint.head !== previous
    )
      throw Error("Demo checkpoint mismatch");
    return {
      valid: true,
      count: data.records.length,
      head: previous,
      scope: "browser demonstration only",
    };
  }
  async function lifecycle(id, state) {
    const m = machines.get(id);
    if (m.state === "revoked")
      throw Error("Demo revocation is permanent. Reset to start over.");
    m.state = state;
    m.history.push({ state, timestamp: epoch() });
    version++;
    await append({ kind: "configuration", machine: id, operation: state });
  }
  async function policy(allowed, deny) {
    if (allowed.some((a) => !actions.includes(a)))
      throw Error("Unknown action");
    policies[0].actions = allowed;
    policies = policies.filter((p) => p.id !== "owner-deny");
    if (deny)
      policies.push({
        ...policies[0],
        id: "owner-deny",
        machine: "*",
        effect: "deny",
        actions: [...actions],
      });
    version++;
    await append({
      kind: "configuration",
      operation: "policy_changed",
      allowed,
      deny,
    });
  }
  return {
    actions,
    snapshot,
    init: () => queue(init),
    request: (...args) => queue(() => evaluate(...args)),
    lab: (mode) => queue(() => lab(mode)),
    lifecycle: (...args) => queue(() => lifecycle(...args)),
    policy: (...args) => queue(() => policy(...args)),
    exportAudit,
    verify,
  };
})();
