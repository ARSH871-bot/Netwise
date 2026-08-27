/*
  Test harness for explanation provenance (#236, phase A).

  WHAT THIS PROTECTS
      web/static/app.js links every explanation back to the evidence it
      paraphrases: an anchor inside .ai-explanation pointing at the id of the
      .evidence block in the SAME card. The id comes from a per-render
      counter, not from finding.id -- the file's own comment already
      documents finding.id as non-unique (see test_findings_rendering.py's
      RT-000 pair). If the link were built from finding.id instead, two
      findings sharing an id in one render would both produce the SAME href,
      and following either link could land on the wrong finding's evidence --
      a broken trail dressed as a working one, which is worse than no link at
      all.

      This harness renders that exact shape -- two findings, same
      finding.id, both status="found" -- and checks each explanation's link
      points at its OWN evidence block, not the other one's.

      It also covers the two edges the acceptance criteria name directly:
      a fallback explanation must show provenance too, not just a model one;
      and a found finding with no explanation at all must say so in words,
      not render silently as if there were nothing to explain.

  HOW
      Same approach as findings_render_harness.js: the real app.js is loaded
      into a small DOM shim and the real renderFindings() is called. The shim
      here additionally records `id` and `href` when app.js sets them as
      plain properties (evidence.id = ...; link.href = ...), which is how
      this file builds them -- see the comment on renderEvidenceLink().

  OUTPUT
      One JSON object on stdout; tests/test_explanation_provenance.py asserts
      on it.
*/

"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

function makeElement(tag) {
  return {
    tagName: tag,
    className: "",
    textContent: "",
    id: "",
    href: "",
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

/* --- Walk the whole tree, flat, keeping the fields provenance needs ------ */
function flatten(node, out) {
  out = out || [];
  out.push({
    tagName: node.tagName,
    className: node.className,
    id: node.id,
    href: node.href,
    textContent: node.textContent,
  });
  (node.children || []).forEach((c) => flatten(c, out));
  return out;
}

function renderAndFlatten(findings) {
  sandbox.renderFindings(findings);
  return flatten(document.getElementById("findings"));
}

const BASE = {
  check: "access_control",
  severity: "high",
  device: "rtr-us5",
  evidence: { detail: "acl_in line 10 denies 10.10.10.0/24", source: "rtr-us5:acl_in" },
  status: "found",
};

const MODEL_EXPLAINED = {
  ...BASE,
  id: "AC-001",
  summary: "An internal subnet is blocked",
  explanation: "This rule blocks an internal network from reaching the device.",
  explanation_source: "model",
};

const FALLBACK_EXPLAINED = {
  ...BASE,
  id: "AC-002",
  summary: "A second, unrelated finding",
  explanation: "An internal subnet is blocked. acl_in line 10 denies 10.10.10.0/24.",
  explanation_source: "fallback",
};

const UNEXPLAINED = {
  ...BASE,
  id: "AC-003",
  summary: "A finding the explanation attempt left no prose for",
  // No `explanation` key at all -- what web/main.py sends when explaining
  // this particular finding failed or was skipped.
};

// The collision case: same finding.id, both status="found", so BOTH go
// through the explanation branch and BOTH need their own evidence id.
const COLLIDING_EXPLAINED_PAIR = [
  {
    ...BASE,
    id: "AC-999",
    summary: "First of a colliding pair",
    evidence: { detail: "first detail", source: "first source" },
    explanation: "Explanation of the first finding.",
    explanation_source: "model",
  },
  {
    ...BASE,
    id: "AC-999",
    summary: "Second of a colliding pair",
    evidence: { detail: "second detail", source: "second source" },
    explanation: "Explanation of the second finding.",
    explanation_source: "model",
  },
];

const CLEAN = {
  ...BASE,
  id: "AC-CLEAN",
  status: "none",
  summary: "Nothing found",
  evidence: { detail: "d", source: "s" },
};

const BLIND = {
  ...BASE,
  id: "AC-BLIND",
  status: "error",
  summary: "Could not run",
  evidence: { detail: "d", source: "s" },
};

const out = {
  modelAndFallback: renderAndFlatten([MODEL_EXPLAINED, FALLBACK_EXPLAINED]),
  unexplained: renderAndFlatten([UNEXPLAINED]),
  collidingPair: renderAndFlatten(COLLIDING_EXPLAINED_PAIR),
  cleanAndBlind: renderAndFlatten([CLEAN, BLIND]),
};

process.stdout.write(JSON.stringify(out, null, 2));
