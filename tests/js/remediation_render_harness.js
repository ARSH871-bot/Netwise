/*
  Test harness for the remediation-text rendering (#221).

  WHY THIS EXISTS
      web/main.py's /api/findings JSON is correct in every case -- only
      web/static/app.js decides what it looks like, so a Python test alone
      cannot catch a rendering mistake (a remediation block using the wrong
      byline, or a found finding with no remediation rendering silently
      instead of saying so). Same reasoning as the four harnesses beside
      this one: the real app.js is loaded, not a copy.

  WHAT THIS PINS
      1. A found finding WITH remediation text gets a ".remediation" block,
         byline "Suggested fix" (in CSS, not asserted directly here -- see
         tests/test_findings_rendering.py's sibling CSS tests for that
         pattern), never the violet ".ai-explanation" styling.
      2. A found finding WITHOUT remediation text gets a ".no-remediation"
         paragraph, not silence -- the same "absence is not information"
         reasoning #31 already applies to explanation.
      3. "none" and "error" cards never acquire either -- they were never
         asked for remediation, and must not start claiming otherwise.

  OUTPUT
      One JSON object on stdout; tests/test_remediation_rendering.py asserts
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

/* --- Walk whatever was built -------------------------------------------- */

function flatten(node, out) {
  out = out || [];
  (node.children || []).forEach((child) => {
    out.push({ tag: child.tagName, cls: child.className, text: child.textContent });
    flatten(child, out);
  });
  return out;
}

function renderAndDescribe(findings) {
  sandbox.renderFindings(findings);
  const findingsEl = document.getElementById("findings");
  const nodes = flatten(findingsEl);

  const find = (cls) => nodes.filter((n) => n.cls === cls);

  return {
    remediationBlocks: find("remediation").map((n) => n.text),
    noRemediationBlocks: find("no-remediation").map((n) => n.text),
    // Confirms remediation never lands inside the AI-explanation styling --
    // a real risk if a future edit merged the two blocks by mistake.
    aiExplanationBlocks: find("ai-explanation").length + find("ai-explanation fallback").length,
  };
}

/* --- The scripted findings ------------------------------------------------ */

function finding(overrides) {
  return Object.assign(
    {
      id: "AC-001",
      check: "access_control",
      severity: "high",
      device: "rtr-us5",
      summary: "A finding",
      evidence: { detail: "some evidence", source: "rtr-us5:acl_in" },
      status: "found",
    },
    overrides || {}
  );
}

const WITH_REMEDIATION = [
  finding({
    remediation: "Change the rule `permit ip any any` so the outcome is DENY instead.",
    remediation_source: "deterministic",
  }),
];

const WITHOUT_REMEDIATION = [
  // No `remediation` key at all -- what web/main.py sends when nothing
  // matched a known evidence shape.
  finding({ id: "AC-002" }),
];

const CLEAN_AND_BLIND = [
  finding({
    id: "AC-CLEAN",
    status: "none",
    summary: "Nothing found",
    remediation: "This must never render.",
    remediation_source: "deterministic",
  }),
  finding({
    id: "AC-BLIND",
    status: "error",
    summary: "Could not run",
    remediation: "This must never render either.",
    remediation_source: "deterministic",
  }),
];

const out = {
  withRemediation: renderAndDescribe(WITH_REMEDIATION),
  withoutRemediation: renderAndDescribe(WITHOUT_REMEDIATION),
  cleanAndBlind: renderAndDescribe(CLEAN_AND_BLIND),
};

process.stdout.write(JSON.stringify(out, null, 2));
