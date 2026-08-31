/*
  Test harness for the explanation byline's provenance modifier (#109).

  WHAT IS AT STAKE
      The byline lives in CSS -- `.ai-explanation::before` says "AI
      explanation", `.ai-explanation.fallback::before` says "Plain-English
      summary". CSS cannot read `explanation_source`. The ONLY thing deciding
      which byline a reader sees is the class app.js puts on that div.

      So a bug here does not look like a bug. It looks like a working
      dashboard attributing to a model text that no model wrote, which is the
      claim #109 was filed about. Nothing else in the stack can catch it:
      web/main.py sends the right value, ai/explain.py computes it correctly,
      and the CSS is right for whichever class it is handed.

  WHY A DOM SHIM AND NOT jsdom
      Same reasoning as tests/js/chat_render_harness.js and
      findings_render_harness.js: the suite is pure pytest and needs neither
      Batfish nor Docker, jsdom would mean an npm toolchain in a Python repo,
      and Node ships on ubuntu-latest so this runs in CI as it stands.

      This loads the REAL web/static/app.js -- not a copy -- so if the render
      block changes, this moves with it.

  Prints one JSON object; tests/test_explanation_byline.py asserts on it.
*/
"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

/* --- The smallest DOM renderFinding() needs ----------------------------- */

function makeElement(tag) {
  return {
    tagName: tag,
    className: "",
    textContent: "",
    children: [],
    style: {},
    appendChild(child) {
      this.children.push(child);
      return child;
    },
    replaceChildren(...nodes) {
      this.children = nodes;
    },
    addEventListener() {},
    // app.js sets aria-disabled on the report links via the real
    // DOM API, so the shim has to model it. Attributes are kept in
    // their own map rather than as properties, so a test cannot
    // read one that was never set.
    setAttribute(key, value) {
      this.attributes = this.attributes || {};
      this.attributes[key] = String(value);
    },
    getAttribute(key) {
      return (this.attributes || {})[key] ?? null;
    },
    querySelector() {
      return null;
    },
  };
}

const byId = new Map();
const document = {
  createElement: makeElement,
  getElementById(id) {
    if (!byId.has(id)) byId.set(id, makeElement("div"));
    return byId.get(id);
  },
};

const APP = path.join(__dirname, "..", "..", "web", "static", "app.js");
const sandbox = {
  document,
  console,
  fetch: () => Promise.reject(new Error("no network in this harness")),
  JSON,
  Promise,
};
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(APP, "utf8"), sandbox, { filename: APP });

/* --- Render one finding and report the explanation div's class ---------- */

function findExplanation(node) {
  if (String(node.className).split(" ")[0] === "ai-explanation") return node;
  for (const child of node.children || []) {
    const hit = findExplanation(child);
    if (hit) return hit;
  }
  return null;
}

function classFor(finding) {
  const container = document.getElementById("findings");
  container.replaceChildren();
  sandbox.renderFindings([finding]);
  const el = findExplanation(container);
  return el ? el.className : null;
}

function finding(extra) {
  return Object.assign(
    {
      id: "AC-001",
      check: "access_control",
      severity: "high",
      device: "rtr-us5",
      summary: "Unencrypted web traffic reaches the internal server",
      evidence: { detail: "Expected DENY but got PERMIT", source: "rtr-us5:acl_in" },
      status: "found",
      explanation: "Some plain-English text.",
    },
    extra
  );
}

/* Each case is one server response. The `explanation_source` values are the
   point: "model" earns the AI byline, and everything else must not. */
const CASES = {
  source_model: finding({ explanation_source: "model" }),
  source_fallback: finding({ explanation_source: "fallback" }),
  source_missing: finding({}),
  source_null: finding({ explanation_source: null }),
  source_unexpected: finding({ explanation_source: "cached" }),
  source_capitalised: finding({ explanation_source: "Model" }),
  source_true: finding({ explanation_source: true }),
  // No explanation at all -- nothing should be rendered, no byline to be wrong.
  no_explanation: finding({ explanation: undefined, explanation_source: "model" }),
};

const out = {};
for (const [name, f] of Object.entries(CASES)) out[name] = classFor(f);
process.stdout.write(JSON.stringify(out, null, 2));
