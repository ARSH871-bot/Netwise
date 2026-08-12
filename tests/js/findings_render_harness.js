/*
  Test harness for the FINDINGS list rendering.

  WHY THIS EXISTS
      web/static/app.js carries a deliberate design rule, in a comment:

        "`id` is NOT treated as unique ... If this file keyed cards by id --
         the obvious thing to do, and what a framework would do by default --
         one of that pair would be silently dropped. The dropped one could be
         the error, leaving the user reading 'policy compliance: all clear'
         with no sign that the change-impact check never ran. That is the F-4
         failure exactly, arriving through the id field rather than the status
         field.

         So: no keying by id until ids are actually unique. The mock data
         keeps that collision on purpose so this stays tested."

      That last sentence was not true. The mock data does preserve the
      PC-000 collision -- but the existing Node harness drives only the CHAT
      pane, and nothing exercised renderFindings() at all. Preserving a
      fixture is not a test. Refactor render() to use a Map keyed by id and
      every test in the project would still have passed.

      This is the sibling of chat_render_harness.js and shares its reasoning:
      the real app.js is loaded, not a copy, because a re-implementation would
      prove only that the copy works.

  OUTPUT
      One JSON object on stdout; tests/test_findings_rendering.py asserts on it.
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

/* --- Load the real app.js ----------------------------------------------- */

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

/* --- Walk whatever was built and describe it ---------------------------- */

function allText(node, out) {
  out = out || [];
  if (node.textContent) out.push(node.textContent);
  (node.children || []).forEach((c) => allText(c, out));
  return out;
}

function describeSections(container) {
  return (container.children || []).map((section) => {
    const heading = (section.children || [])[0];
    // Cards are every child after the heading and the note.
    const cards = (section.children || []).slice(2);
    return {
      heading: heading ? heading.textContent : null,
      cardCount: cards.length,
      cardText: cards.map((c) => allText(c).join(" | ")),
    };
  });
}

/* --- The case under test ------------------------------------------------ */

// The exact collision that lives in web/mock_findings.py: policy_compliance
// clean and change_impact errored, both numbering their sentinel 000.
const COLLIDING_PAIR = [
  {
    id: "PC-000",
    check: "policy_compliance",
    severity: "low",
    device: "rtr-us5",
    summary: "No issues found by policy compliance",
    evidence: { detail: "d", source: "s" },
    status: "none",
  },
  {
    id: "PC-000",
    check: "change_impact",
    severity: "high",
    device: "rtr-us5",
    summary: "Change impact check could not run: no baseline",
    evidence: { detail: "d", source: "s" },
    status: "error",
  },
];

function renderAndDescribe(findings) {
  sandbox.renderFindings(findings);
  const findingsEl = document.getElementById("findings");
  const summaryEl = document.getElementById("summary");
  const sections = describeSections(findingsEl);
  return {
    sections,
    totalCards: sections.reduce((n, s) => n + s.cardCount, 0),
    summaryTiles: (summaryEl.children || []).map((t) => ({
      className: t.className,
      text: allText(t).join(" "),
    })),
  };
}

// BOTH ORDERS, and the second is the one that matters.
//
// De-duplicating with a Map keeps the LAST value for a key. With the error
// last it survives and the clean result is dropped -- bad, but visible. With
// the error FIRST it is the error that disappears, leaving the user reading
// "policy compliance: all clear" and no sign that change impact never ran.
//
// A test using only one order would half-catch the bug it exists for, which
// is the same shape as the defect this file was written to close.
const out = {
  errorLast: renderAndDescribe(COLLIDING_PAIR),
  errorFirst: renderAndDescribe([COLLIDING_PAIR[1], COLLIDING_PAIR[0]]),
};

process.stdout.write(JSON.stringify(out, null, 2));
