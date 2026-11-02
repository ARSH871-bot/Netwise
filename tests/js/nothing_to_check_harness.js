/*
  Test harness for the "nothing to check" card treatment (#266).

  WHY THIS EXISTS
      web/static/app.js now renders two different cards for the SAME status.
      A `status="none"` finding is a clean result -- unless it is the
      sentinel a check emits when the user supplied no rules for it, whose
      own detail says "nothing was asserted ... and nothing was checked".
      Both used to render identically, under a green tick.

      The distinction has to be provable at the RENDERED level rather than by
      reading the source, for the same reason findings_render_harness.js
      exists: a fixture that merely contains the case is not a test of it.

      It also has to be provable WITHOUT the stylesheet. The harness has no
      CSS at all, so anything this file can see is carried by markup and
      words -- which is exactly the property #266 needs, since a distinction
      resting on a shade of grey fails in greyscale, in print and in a screen
      reader.

  OUTPUT
      One JSON object on stdout; tests/test_nothing_to_check_rendering.py
      asserts on it.
*/

"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

/* --- The smallest DOM that renderFindings() needs ----------------------- */

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
    setAttribute(key, value) {
      this.attributes = this.attributes || {};
      this.attributes[key] = String(value);
    },
    getAttribute(key) {
      return (this.attributes || {})[key] ?? null;
    },
    // classList, backed by the same className string every other part of
    // this shim already reads -- added because renderFindings() calls
    // classList.add()/remove() to toggle comparison-mode styling, which
    // this harness's own scenarios never exercise directly but still runs
    // through on every call. A live accessor, not a snapshot, so it stays
    // correct across repeated add/remove calls on the same element.
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

/* --- Load the real app.js, not a copy of it ----------------------------- */

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

/* --- Walk the rendered tree --------------------------------------------- */

function allText(node, out) {
  out = out || [];
  if (node.textContent) out.push(node.textContent);
  (node.children || []).forEach((c) => allText(c, out));
  return out;
}

function allClasses(node, out) {
  out = out || [];
  if (node.className) out.push(node.className);
  (node.children || []).forEach((c) => allClasses(c, out));
  return out;
}

function describeCards(container) {
  const cards = [];
  (container.children || []).forEach((section) => {
    // Cards are every child of a section after its heading and lede.
    (section.children || []).slice(2).forEach((card) => {
      cards.push({
        section: ((section.children || [])[0] || {}).textContent || null,
        className: card.className,
        classes: allClasses(card),
        text: allText(card).join(" | "),
      });
    });
  });
  return cards;
}

/* --- The three findings, differing only in the way that matters --------- */

// The sentinel. `status="none"` and `device="n/a"`: the check ran fine and
// had nothing to run.
const NOTHING = {
  id: "PC-000",
  check: "policy_compliance",
  severity: "low",
  device: "n/a",
  summary: "No policy compliance rules to check",
  evidence: {
    detail:
      "Your policy file has no policy_compliance entries, so nothing was " +
      "asserted about this configuration and nothing was checked.",
    source: "the policy file you supplied",
  },
  status: "none",
};

// A GENUINE clean result. Same status, real device. Must be untouched by
// #266 -- this is the regression half of the test.
const GENUINE_CLEAN = {
  id: "AC-000",
  check: "access_control",
  severity: "low",
  device: "rtr-us5",
  summary: "No issues found by access control",
  evidence: { detail: "3 policy statement(s) hold", source: "rtr-us5" },
  status: "none",
};

// A could-not-check, included so the third claim can be shown to differ from
// BOTH of the two that already existed rather than only from the green one.
const BLIND = {
  id: "RT-050",
  check: "routing",
  severity: "high",
  device: "unknown",
  summary: "2 route assertion(s) could not be checked",
  evidence: { detail: "rtr-hq is not in this snapshot", source: "n/a" },
  status: "error",
};

sandbox.renderFindings([GENUINE_CLEAN, NOTHING, BLIND]);

const findingsEl = document.getElementById("findings");
const summaryEl = document.getElementById("summary");

/* --- The predicate on its own, not only through the one call site -------
   WHY THIS BLOCK EXISTS: A MUTATION SURVIVED WITHOUT IT.

   Deleting the `status === "none"` half of isNothingToCheck() -- leaving it
   keyed on `device` alone -- passed the whole suite. It is equivalent at the
   ONE place the function is called today, because `clean` has already been
   filtered to status="none" before the renderer ever asks, so the status
   half can never be the deciding term there.

   Equivalent today is not equivalent tomorrow. The moment a second caller
   appears -- a report link, a filter, a count -- a predicate keyed on
   `device` alone would claim a could-not-check finding carrying `n/a`
   anywhere is a "nothing to check". The Python twin is already tested
   directly for exactly this; this is the JS side of the same guard, and it
   is recorded here rather than left as a known survivor. */
const predicate = {
  sentinel: sandbox.isNothingToCheck(NOTHING),
  genuineClean: sandbox.isNothingToCheck(GENUINE_CLEAN),
  // status="error" with an "n/a" DEVICE. Only the status half can reject
  // this one, so it dies the instant that half is removed.
  blindOnNaDevice: sandbox.isNothingToCheck({ ...BLIND, device: "n/a" }),
  // Same again for status="found".
  foundOnNaDevice: sandbox.isNothingToCheck({
    id: "AC-001",
    status: "found",
    device: "n/a",
    evidence: {},
  }),
};

process.stdout.write(
  JSON.stringify(
    {
      predicate,
      cards: describeCards(findingsEl),
      // The tile totals must not move: the card is distinguished, the count
      // is not split. See analysis/report.py's is_nothing_to_check().
      summaryTiles: (summaryEl.children || []).map((t) => ({
        className: t.className,
        text: allText(t).join(" "),
      })),
    },
    null,
    2
  )
);
