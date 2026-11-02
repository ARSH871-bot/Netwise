/*
  Test harness for the propose-a-change comparison view's diff logic (#298
  review, @shubhamkataria2005 and @ARSH871-bot).

  WHAT WENT WRONG, AND WHY PYTHON COULD NOT CATCH IT
      diffFindings() in web/static/app.js used to split `before`/`after` into
      introduced/resolved/unchanged by set membership alone, with no regard
      for `status`. Two reviewers independently reproduced the same two bugs
      by loading the real app.js into a vm context exactly as this harness
      does:

        1. A check going from clean/found to error rendered under
           "problems this change FIXES" -- going blind shown as good news.
        2. A check going from error to clean rendered under "a new problem
           this change INTRODUCES" -- a green tick shown as a new problem.

      Both are F-4 failures in the one view whose whole job is to answer
      "is this change safe". Every existing test for this feature used only
      status="found" findings (0 none/error cases across three modules), so
      nothing caught it -- the same "both halves tested, the join between
      them is not" shape CLAUDE.md section 11 already names for the PF
      Sense/policy join.

  THE FIX THIS HARNESS PINS
      diffFindings() now filters both `before` and `after` to status="found"
      before computing any of the three buckets. A separate function,
      detectBlindTransitions(), reports status TRANSITIONS (something
      checkable becoming uncheckable, or the reverse) as its own signal,
      never folded into introduced/resolved/unchanged.

  WHY A DOM SHIM AND NOT jsdom
      Same reasoning as every other harness beside it: no npm toolchain in a
      Python repo, Node ships on ubuntu-latest, and this loads the REAL
      web/static/app.js so it moves with the renderer.

  Prints one JSON object; tests/test_comparison_diff.py asserts on it.
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
    hidden: false,
    disabled: false,
    value: "",
    files: [],
    scrollTop: 0,
    scrollHeight: 0,
    appendChild(child) {
      this.children.push(child);
      return child;
    },
    replaceChildren(...nodes) {
      this.children = nodes;
    },
    addEventListener() {},
    setAttribute(key, value) {
      this.attributes = this.attributes || {};
      this.attributes[key] = String(value);
    },
    getAttribute(key) {
      return (this.attributes || {})[key] ?? null;
    },
    get classList() {
      const self = this;
      return {
        add(cls) {
          const classes = self.className ? self.className.split(/\s+/) : [];
          if (!classes.includes(cls)) classes.push(cls);
          self.className = classes.join(" ");
        },
        remove(cls) {
          const classes = self.className ? self.className.split(/\s+/) : [];
          self.className = classes.filter((c) => c !== cls).join(" ");
        },
        contains(cls) {
          return (self.className ? self.className.split(/\s+/) : []).includes(cls);
        },
      };
    },
    removeEventListener() {},
    remove() {},
    focus() {},
    scrollIntoView() {},
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

/* --- Finding fixtures, matching the two reviewers' exact repro cases ---- */

function finding(overrides) {
  return Object.assign(
    {
      id: "AC-001",
      check: "access_control",
      severity: "high",
      device: "rtr-us5",
      summary: "The guest LAN can reach the finance server",
      evidence: { detail: "permit ip any any", source: "rtr-us5.cfg:14" },
      status: "found",
    },
    overrides || {}
  );
}

// A finding that is present, unmodified, on both sides -- the ordinary case
// diffFindings() must still get right after the fix.
const UNCHANGED_FOUND = finding({});

// @shubhamkataria2005's case 1: a proposed change makes a check go blind.
const CASE1_BEFORE = [
  finding({
    id: "PC-000",
    check: "policy_compliance",
    status: "none",
    severity: "low",
    summary: "All 3 policy rules hold on rtr-us5",
    evidence: { detail: "3/3 rules satisfied", source: "policy_compliance" },
  }),
  UNCHANGED_FOUND,
];
const CASE1_AFTER = [
  finding({
    id: "PC-000",
    check: "policy_compliance",
    status: "error",
    severity: "high",
    summary: "Could not check rtr-us5: the proposed ACL failed to parse",
    evidence: { detail: "parse error at line 4", source: "policy_compliance" },
  }),
  UNCHANGED_FOUND,
];

// @ARSH871-bot's case 2: the reverse -- a blind check becomes clean.
const CASE2_BEFORE = [
  finding({
    id: "RT-000",
    check: "routing",
    device: "rtr-branch",
    status: "error",
    severity: "high",
    summary: "Could not check: rtr-branch is not in this snapshot",
    evidence: { detail: "node absent from snapshot", source: "routing" },
  }),
  UNCHANGED_FOUND,
];
const CASE2_AFTER = [
  finding({
    id: "RT-000",
    check: "routing",
    device: "rtr-branch",
    status: "none",
    severity: "low",
    summary: "HQ reaches the branch server as required",
    evidence: { detail: "traceroute: ACCEPTED", source: "routing" },
  }),
  UNCHANGED_FOUND,
];

// A genuinely new found problem, unrelated to any status transition -- the
// ordinary "introduced" case must still work.
const CASE3_BEFORE = [UNCHANGED_FOUND];
const CASE3_AFTER = [
  UNCHANGED_FOUND,
  finding({
    id: "AC-002",
    summary: "The change newly permits traffic that was blocked",
  }),
];

// A found problem that got fixed -- the ordinary "resolved" case.
const CASE4_BEFORE = [
  UNCHANGED_FOUND,
  finding({ id: "AC-003", summary: "A separate problem this change fixes" }),
];
const CASE4_AFTER = [UNCHANGED_FOUND];

// error -> found for the SAME (check, device): already correctly reported by
// diffFindings() as "introduced". detectBlindTransitions() must not ALSO
// list it under newlySighted -- that would be the same fact disclosed twice
// under two different framings.
const CASE5_BEFORE = [
  finding({
    id: "PC-000",
    check: "policy_compliance",
    status: "error",
    severity: "high",
    summary: "Could not check rtr-us5: the proposed ACL failed to parse",
    evidence: { detail: "parse error", source: "policy_compliance" },
  }),
];
const CASE5_AFTER = [
  finding({
    id: "PC-001",
    check: "policy_compliance",
    status: "found",
    summary: "The proposed rule violates policy rule 3",
  }),
];

function describeDiff(before, after) {
  const { introduced, resolved, unchanged } = sandbox.diffFindings(before, after);
  const { newlyBlind, newlySighted } = sandbox.detectBlindTransitions(before, after);
  return {
    introducedIds: introduced.map((f) => f.id),
    introducedStatuses: introduced.map((f) => f.status),
    resolvedIds: resolved.map((f) => f.id),
    resolvedStatuses: resolved.map((f) => f.status),
    unchangedIds: unchanged.map((f) => f.id),
    newlyBlindIds: newlyBlind.map((f) => f.id),
    newlySightedIds: newlySighted.map((f) => f.id),
  };
}

/* --- End-to-end: showComparison() actually renders the disclosure ------- */

// Walks the raw (unflattened) tree looking for the hidden `findings_json`
// input renderComparisonDownload() creates -- that is the actual payload a
// download form POSTs, so this is what proves newlyBlind/newlySighted were
// threaded all the way into the request rather than just computed and
// dropped (#298 review, round two, @shubhamkataria2005).
function findFindingsJsonPayload(node) {
  for (const child of node.children || []) {
    if (child.tagName === "input" && child.name === "findings_json") {
      return JSON.parse(child.value);
    }
    const found = findFindingsJsonPayload(child);
    if (found) return found;
  }
  return null;
}

function describeRenderedComparison(before, after, description) {
  // showComparison() reads the module-level `allFindings` as "before". That
  // is a `let` binding inside app.js's own scope, not a property of the vm
  // sandbox object -- assigning `sandbox.allFindings` directly would create
  // an unrelated property and silently leave the real binding at whatever
  // the last call set it to. renderFindings() is the actual code path the
  // app uses to set it, so use that rather than reach around it.
  sandbox.renderFindings(before);

  sandbox.showComparison(after, description || "test change");
  const container = document.getElementById("findings");

  function flatten(node, out) {
    (node.children || []).forEach((child) => {
      out.push({ tag: child.tagName, cls: child.className, text: child.textContent });
      flatten(child, out);
    });
    return out;
  }
  const nodes = flatten(container, []);

  return {
    // Every finding card actually in the DOM, by class and the status it
    // carries -- so a "found" card in the wrong section, or a "blind"/
    // "clean" card from a transition landing in the wrong place, is
    // directly visible rather than inferred from counts.
    findingCards: nodes
      .filter((n) => n.cls && n.cls.startsWith("finding "))
      .map((n) => n.cls),
    blindTransitionsPresent: nodes.filter((n) => n.cls === "comparison-blind-transitions").length,
    // Order matters: the blind-transitions block must render BEFORE the
    // two sections, per the review's "above both sections" ask.
    topLevelOrder: (container.children || []).map((c) => c.className),
    allText: nodes.map((n) => n.text).join(" | "),
    // The actual download payload -- proves the disclosure survives past
    // the DOM and into the request the server will see.
    downloadPayloadIds: (() => {
      const payload = findFindingsJsonPayload(container);
      if (!payload) return null;
      return {
        newlyBlindIds: (payload.newly_blind || []).map((f) => f.id),
        newlySightedIds: (payload.newly_sighted || []).map((f) => f.id),
      };
    })(),
  };
}

const out = {
  // Pure diff logic, both reviewers' exact repro cases plus the ordinary
  // cases that must keep working.
  case1GoesBlind: describeDiff(CASE1_BEFORE, CASE1_AFTER),
  case2BecomesClean: describeDiff(CASE2_BEFORE, CASE2_AFTER),
  case3NewProblem: describeDiff(CASE3_BEFORE, CASE3_AFTER),
  case4FixedProblem: describeDiff(CASE4_BEFORE, CASE4_AFTER),
  case5ErrorBecomesFound: describeDiff(CASE5_BEFORE, CASE5_AFTER),
  noChange: describeDiff([UNCHANGED_FOUND], [UNCHANGED_FOUND]),
  bothEmpty: describeDiff([], []),

  // Rendered end to end, so a fix to the pure functions that never gets
  // wired into showComparison() would still be caught.
  renderedGoesBlind: describeRenderedComparison(CASE1_BEFORE, CASE1_AFTER),
  renderedBecomesClean: describeRenderedComparison(CASE2_BEFORE, CASE2_AFTER),
  renderedNoTransition: describeRenderedComparison(CASE3_BEFORE, CASE3_AFTER),
};

console.log(JSON.stringify(out, null, 2));
