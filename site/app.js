"use strict";
const demo = window.OwnerGateDemo,
  $ = (s) => document.querySelector(s);
let view = "overview",
  state,
  ready = false;
const titles = {
  overview: [
    "Make machine access a decision.",
    "Recognize the key. Check permission. Inspect the evidence.",
  ],
  machines: [
    "Machine Registry",
    "A recognized key is an identity, not automatic permission.",
  ],
  policies: [
    "Resource Policies",
    "Decide which operations your demo research library permits.",
  ],
  traffic: [
    "Traffic Monitor",
    "Every row below is a browser-simulated decision.",
  ],
  audit: [
    "Audit Center",
    "Real signatures. Disposable keys. Demonstration evidence only.",
  ],
  lab: [
    "Testing Laboratory",
    "Eight adversarial cases, isolated from your workspace policy.",
  ],
  guide: [
    "Run the real gateway",
    "Move from this browser demonstration to actual HTTP enforcement.",
  ],
};
function el(tag, text, cls) {
  const n = document.createElement(tag);
  if (text !== undefined) n.textContent = text;
  if (cls) n.className = cls;
  return n;
}
function tell(text) {
  $("#message").textContent = text;
}
function card(title) {
  const n = el("div", undefined, "card");
  if (title) n.append(el("h2", title));
  return n;
}
function button(text, fn, cls) {
  const b = el("button", text, cls);
  b.type = "button";
  b.onclick = async () => {
    b.disabled = true;
    try {
      await fn();
    } catch (e) {
      tell(e.message);
    } finally {
      b.disabled = false;
    }
  };
  return b;
}
function details(data) {
  const d = el("details");
  d.append(
    el("summary", "Inspect demo evidence"),
    el("pre", JSON.stringify(data, null, 2)),
  );
  return d;
}
function table(heads, rows) {
  const w = el("div", undefined, "table-wrap");
  w.tabIndex = 0;
  w.setAttribute("aria-label", "Scrollable demonstration records");
  if (!rows.length) {
    w.append(el("p", "No matching demonstration records.", "empty"));
    return w;
  }
  const t = el("table"),
    th = el("thead"),
    tr = el("tr"),
    tb = el("tbody");
  heads.forEach((h) => tr.append(el("th", h)));
  th.append(tr);
  t.append(th, tb);
  rows.forEach((row) => {
    const r = el("tr");
    row.forEach((v) => {
      const c = el("td");
      c.append(
        v instanceof Node ? v : document.createTextNode(String(v ?? "")),
      );
      r.append(c);
    });
    tb.append(r);
  });
  w.append(t);
  return w;
}
function pill(text) {
  return el("span", text, "pill " + text);
}
const explanations = {
  policy_allow: "Valid proof and an owner allow rule.",
  no_allow_policy: "Identity recognized; no rule grants permission.",
  unknown_identity: "No recognized identity was proven.",
  credential_revoked: "The owner permanently revoked this identity.",
  credential_suspended: "The owner suspended this identity.",
  credential_expired: "The credential expired.",
  resource_outside_scope: "The resource is outside this credential’s scope.",
  invalid_signature: "The signature does not verify.",
  missing_or_replayed_challenge:
    "This one-use challenge has already been consumed.",
  explicit_deny: "An owner deny rule takes precedence.",
};
function eventTable(events) {
  return table(
    ["Time", "Machine", "Resource / action", "Decision", "Why"],
    events.map((e) => [
      new Date(e.timestamp * 1000).toLocaleTimeString(),
      e.machine,
      e.resource + " · " + e.action,
      pill(e.decision),
      explanations[e.reason] || e.reason,
    ]),
  );
}
function link(text, href) {
  const a = el("a", text);
  a.href = href;
  return a;
}
function go(v) {
  view = v;
  render();
}
async function request(id, action = "read") {
  const e = await demo.request(id, action);
  render();
  tell(
    "SIMULATED · " +
      e.decision.toUpperCase() +
      " · " +
      (explanations[e.reason] || e.reason),
  );
}
function render() {
  if (!ready) return;
  state = demo.snapshot();
  $("#title").textContent = titles[view][0];
  $("#subtitle").textContent = titles[view][1];
  document.querySelectorAll("[data-view]").forEach((b) => {
    if (b.dataset.view === view) b.setAttribute("aria-current", "page");
    else b.removeAttribute("aria-current");
  });
  const c = $("#content");
  c.replaceChildren();
  tell("");
  const events = state.events.filter((e) => e.kind === "decision").reverse();
  if (view === "overview") {
    const hero = card();
    hero.classList.add("hero");
    const intro = el("div");
    intro.append(
      el("p", "THE PRINCIPLE", "eyebrow"),
      el(
        "h2",
        "Reaching a resource does not establish permission to consume it.",
      ),
      el(
        "p",
        "OwnerGate gives resource owners a cryptographic identity check, explicit access policies, and inspectable decisions. Explore the model here, then run the server to enforce it at a real HTTP boundary.",
      ),
    );
    const actions = el("div", undefined, "buttons");
    actions.append(
      button(
        "Try an authorized machine →",
        () => request("research-agent"),
        "primary",
      ),
      button("Try an unknown machine", () => request("unknown-agent")),
      button("Run the gateway", () => go("guide")),
    );
    intro.append(actions);
    const flow = el("div", undefined, "flow");
    for (const [title, note] of [
      [
        "01 / Identify the machine",
        "Verify control of a recognized public key.",
      ],
      [
        "02 / Evaluate the owner’s rules",
        "Scope, action, expiry, and deny rules all matter.",
      ],
      ["03 / Inspect the decision", "See why access was permitted or refused."],
    ]) {
      const step = el("div");
      step.append(el("strong", title), el("small", note));
      flow.append(step);
    }
    hero.append(intro, flow);
    c.append(hero);
    const stats = el("div", undefined, "stats");
    for (const [label, n] of [
      ["Simulated requests", events.length],
      ["Simulated allows", events.filter((e) => e.decision === "allow").length],
      ["Simulated denials", events.filter((e) => e.decision === "deny").length],
      ["Unidentified", events.filter((e) => !e.identity_verified).length],
    ]) {
      const s = el("div", undefined, "stat");
      s.append(
        el("span", label),
        el("strong", n),
        el("small", "This tab · demonstration only"),
      );
      stats.append(s);
    }
    c.append(stats);
    const recent = card("Demonstration decisions");
    recent.append(eventTable(events.slice(0, 8)));
    c.append(recent);
    const research = card("A new product, grounded in existing research");
    research.append(
      el(
        "p",
        "Built independently from Mitchell D. McPhetridge’s machine participation and evidence research. Original repositories, papers, and demonstration credentials remain separate.",
      ),
    );
    const links = el("div", undefined, "research-links");
    for (const [name, repo] of [
      ["Virtual DMV / Bot Traffic", "Virtual-DMV-Bot-Traffic-Research-Rig"],
      [
        "Combined MPLPB",
        "Combined-MPLPB-A-closed-local-ledger-of-pages-that-answers-only-from-those-pages",
      ],
      ["Networked MPLPB", "networked-mplpb"],
      ["OneOwner", "OneOwner-powered-by-MPLPB"],
    ])
      links.append(
        link(name + " ↗", "https://github.com/mitchell-d00/" + repo),
      );
    research.append(links);
    c.append(research);
  }
  if (view === "machines") {
    const list = card("Disposable demonstration identities");
    list.append(
      el(
        "p",
        "Public keys below belong to disposable keys generated in this tab. Operator labels are self-declared. Reset or reload creates a fresh workspace; no private keys are exported.",
        "muted",
      ),
    );
    list.append(
      table(
        ["Identity", "Lifecycle", "Credential scope", "Controls"],
        state.machines.map((m) => {
          const controls = el("div", undefined, "buttons");
          controls.append(
            button("Request read", () => request(m.id)),
            button(
              "Revoke",
              async () => {
                await demo.lifecycle(m.id, "revoked");
                render();
                tell(
                  "Demo identity revoked. Its next simulated request will be denied.",
                );
              },
              "danger",
            ),
          );
          if (m.state !== "revoked")
            controls.append(
              button(
                m.state === "suspended" ? "Activate" : "Suspend",
                async () => {
                  await demo.lifecycle(
                    m.id,
                    m.state === "suspended" ? "active" : "suspended",
                  );
                  render();
                },
              ),
            );
          const d = el("div");
          d.append(el("span", m.id), details(m));
          return [d, pill(m.effective_state), m.scopes.join(", "), controls];
        }),
      ),
    );
    c.append(list);
  }
  if (view === "policies") {
    const p = card("Research library · /resources/research");
    p.append(
      el(
        "p",
        "Grant actions to research-agent. All other recognized machines still need their own allow rule. A matching deny overrides every allow. These controls change only this browser demonstration.",
      ),
    );
    const form = el("form"),
      checks = el("div", undefined, "policy-controls");
    for (const a of demo.actions) {
      const l = el("label"),
        i = el("input");
      i.type = "checkbox";
      i.name = "action";
      i.value = a;
      i.checked = state.policies[0].actions.includes(a);
      l.append(i, document.createTextNode(a));
      checks.append(l);
    }
    const denyLabel = el("label"),
      deny = el("input");
    deny.type = "checkbox";
    deny.name = "deny";
    deny.checked = state.policies.some((p) => p.id === "owner-deny");
    denyLabel.append(
      deny,
      document.createTextNode("Explicitly deny all machines for this resource"),
    );
    form.append(checks, denyLabel, el("button", "Save demo policy", "primary"));
    form.onsubmit = async (e) => {
      e.preventDefault();
      try {
        await demo.policy(
          [...form.querySelectorAll('[name="action"]:checked')].map(
            (i) => i.value,
          ),
          deny.checked,
        );
        render();
        tell("Demo policy saved. Deny takes precedence.");
      } catch (e) {
        tell(e.message);
      }
    };
    p.append(form);
    const trial = el("div", undefined, "buttons");
    demo.actions.forEach((a) =>
      trial.append(button("Try " + a, () => request("research-agent", a))),
    );
    p.append(trial, details(state.policies));
    c.append(p);
    const limit = card("Permission has a boundary");
    limit.append(
      el(
        "p",
        "The gateway controls whether it returns content for the declared action. It cannot prove that a recipient obeys redistribution, indexing, summarization, or training restrictions after receiving the bytes. Identity proves key control, not a legal identity or good behavior.",
      ),
    );
    c.append(limit);
  }
  if (view === "traffic") {
    const filters = card("Filter simulated traffic"),
      row = el("div", undefined, "row"),
      inputs = {};
    for (const [name, label, type] of [
      ["machine", "Machine", "text"],
      ["resource", "Resource", "text"],
      ["action", "Action", "text"],
      ["decision", "Decision", "text"],
      ["from", "From (UTC)", "datetime-local"],
    ]) {
      const l = el("label", label),
        i = el("input");
      i.type = type;
      inputs[name] = i;
      l.append(i);
      row.append(l);
    }
    const out = el("div");
    function update() {
      out.replaceChildren(
        eventTable(
          events.filter((e) =>
            Object.entries(inputs).every(
              ([k, i]) =>
                !i.value ||
                (k === "from"
                  ? e.timestamp >= Date.parse(i.value + "Z") / 1000
                  : String(e[k]).includes(i.value)),
            ),
          ),
        ),
      );
    }
    Object.values(inputs).forEach((i) => (i.oninput = update));
    filters.append(row);
    c.append(filters, out);
    update();
  }
  if (view === "audit") {
    const a = card("Inspect the demonstration chain");
    a.append(
      el(
        "p",
        "Each simulated decision and demo configuration change is hash-linked and signed with an ephemeral Ed25519 browser key. This illustrates tamper detection; it is not evidence of real HTTP enforcement. Export files are explicitly marked BROWSER_DEMONSTRATION_ONLY.",
      ),
    );
    const buttons = el("div", undefined, "buttons");
    buttons.append(
      button("Verify demo integrity", async () =>
        tell(
          JSON.stringify(await demo.verify(await demo.exportAudit()), null, 2),
        ),
      ),
      button("Test a tampered record", async () => {
        const data = await demo.exportAudit();
        const p = data.records[0].split(".");
        p[2] = (p[2][0] === "A" ? "B" : "A") + p[2].slice(1);
        data.records[0] = p.join(".");
        let rejected = false;
        try {
          await demo.verify(data);
        } catch (e) {
          rejected = true;
          tell("TAMPERING DETECTED · " + e.message);
        }
        if (!rejected) throw Error("Tampering check unexpectedly passed");
      }),
      button("Export demo evidence", async () => {
        const data = await demo.exportAudit(),
          url = URL.createObjectURL(
            new Blob([JSON.stringify(data, null, 2)], {
              type: "application/json",
            }),
          ),
          a = el("a");
        a.href = url;
        a.download = "ownergate-browser-demo.json";
        a.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
      }),
    );
    a.append(
      buttons,
      el(
        "p",
        "A signature does not prove downstream compliance or a complete history. A self-contained export cannot establish its own key’s trustworthiness. External trusted checkpoints are needed to detect deleted suffixes. Reset discards this demo key and history.",
        "muted",
      ),
    );
    c.append(a);
    state.events
      .slice(-30)
      .reverse()
      .forEach((e) => {
        const r = card(
          "Demo #" + e.sequence + " · " + (e.reason || e.operation),
        );
        r.append(details(e));
        c.append(r);
      });
  }
  if (view === "lab") {
    const intro = card("Explore the failure cases");
    intro.append(
      el(
        "p",
        "Each case creates an isolated, disposable demo identity and policy. Real Ed25519 signatures are checked locally. No HTTP request is sent to a gateway, no resource is protected, and no operational credentials are used.",
      ),
    );
    c.append(intro);
    const grid = el("div", undefined, "lab-grid");
    for (const [mode, title, note] of [
      [
        "authorized",
        "Known authorized machine",
        "Valid signature, current credential, permitted scope and action.",
      ],
      [
        "unauthorized",
        "Unauthorized registered machine",
        "A verified key with no matching permission.",
      ],
      ["unknown", "Unknown machine", "No recognized cryptographic identity."],
      [
        "revoked",
        "Revoked credential",
        "The owner has permanently revoked the credential.",
      ],
      [
        "expired",
        "Expired credential",
        "The key still signs, but its credential is expired.",
      ],
      [
        "replay",
        "Replayed challenge",
        "A valid challenge is accepted once; reuse is refused.",
      ],
      [
        "tampered",
        "Tampered signature",
        "Altered signature bytes must fail verification.",
      ],
      [
        "scope",
        "Invalid resource scope",
        "A policy cannot broaden the credential’s scope.",
      ],
    ]) {
      const box = el("div", undefined, "lab-case");
      box.append(
        el("h3", title),
        el("p", note),
        button("Run demo check →", async () => {
          const r = await demo.lab(mode);
          render();
          tell(
            (r.pass ? "PASS" : "FAIL") +
              " · SIMULATED · " +
              mode +
              " · " +
              r.event.reason,
          );
        }),
      );
      grid.append(box);
    }
    c.append(grid);
  }
  if (view === "guide") {
    const intro = card("This site explores the model. The server enforces it.");
    intro.append(
      el(
        "p",
        "GitHub Pages serves static files and cannot run FastAPI, hold operational secrets, or block requests to your own website. OwnerGate’s Python application provides the actual HTTP authorization boundary, administrator authentication, SQLite registry and signed gateway audit log. Start with a controlled local pilot.",
      ),
    );
    c.append(intro);
    const install = card("01 / Start OwnerGate locally");
    install.append(
      el(
        "pre",
        `git clone https://github.com/mitchell-d00/OwnerGate.git
cd OwnerGate
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.lock
python -m pip install --no-deps --no-build-isolation -e .
export OWNERGATE_ADMIN_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export OWNERGATE_AUDIENCE=http://127.0.0.1:8000
ownergate serve`,
      ),
      el(
        "p",
        "Open http://127.0.0.1:8000 on the machine running the server. Supply your token only to that trusted local dashboard. This public demonstration never asks for it.",
      ),
    );
    c.append(install);
    const trial = card("02 / Run the complete HTTP pilot");
    trial.append(
      el(
        "p",
        "In a second terminal with the same environment and owner token:",
      ),
      el("pre", "python scripts/pilot_demo.py --output /tmp/ownergate-demo"),
      el(
        "p",
        "The client registers a fresh demo machine, protects an endpoint, grants access, receives 200, tries an unknown caller (401), revokes the machine and retries (403). It exports actual signed gateway decisions and starts the independent verifier.",
      ),
    );
    c.append(trial);
    const docs = card("03 / Review the boundary before deployment");
    docs.append(
      el(
        "p",
        "v0.1.0 protects the included GET-only test application. An adapter and origin isolation are needed for an existing website. Use a trusted TLS reverse proxy for any nonlocal deployment. Host compromise, stolen credentials and content already delivered remain risks.",
      ),
    );
    for (const [text, file] of [
      ["Installation and Docker Compose", "README.md"],
      ["Threat model and key custody", "docs/SECURITY.md"],
      ["Protocol and verification", "docs/PROTOCOL.md"],
      ["Actual test results and limitations", "docs/TEST_RESULTS.md"],
      ["Research provenance", "docs/RESEARCH.md"],
    ]) {
      const p = el("p");
      p.append(
        link(
          text + " ↗",
          "https://github.com/mitchell-d00/OwnerGate/blob/main/" + file,
        ),
      );
      docs.append(p);
    }
    c.append(docs);
  }
}
document.querySelectorAll("[data-view]").forEach(
  (b) =>
    (b.onclick = () => {
      if (ready) go(b.dataset.view);
    }),
);
$("#reset").onclick = async () => {
  if (!ready) return;
  ready = false;
  $("#reset").disabled = true;
  tell("Resetting disposable demo keys…");
  try {
    await demo.init();
    ready = true;
    view = "overview";
    render();
    tell(
      "Demo reset. Fresh keys and three clearly simulated example decisions.",
    );
  } catch (e) {
    tell(e.message);
  } finally {
    $("#reset").disabled = false;
  }
};
(async () => {
  try {
    await demo.init();
    ready = true;
    render();
  } catch (e) {
    tell(
      "Your browser could not initialize Ed25519: " +
        e.message +
        ". Use a current browser over HTTPS, or run the Python gateway from GitHub. No access enforcement is provided by this page.",
    );
  }
})();
