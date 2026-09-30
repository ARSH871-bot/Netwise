/*
  Test harness for the saved-scans comparison (#223).

  WHAT IT PROTECTS
      renderComparison() in web/static/app.js decides which heading each
      difference goes under. "Fixed: checked again and no longer found" must
      hold ONLY what the server called resolved -- a problem that merely
      disappeared goes under "Gone, but not confirmed fixed", with the reason.
      Swapping those two lists is a one-word edit that every Python test would
      still pass, and it would tell a user their network is fixed when nobody
      looked. Same approach as chat_render_harness.js: the real app.js, loaded
      into a DOM shim with no dependencies.

  Prints one JSON object to stdout; tests/test_history_rendering.py asserts on it.
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
    disabled: false,
    value: "",
    appendChild(child) {
      this.children.push(child);
      return child;
    },
    replaceChildren(...nodes) {
      this.children = nodes;
    },
    addEventListener() {},
    setAttribute() {},
    getAttribute() {
      return null;
    },
    remove() {},
    focus() {},
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
  // Every load at boot catches its own failure, so a rejection is the normal
  // path here, not an error in the test.
  fetch: () => Promise.reject(new Error("no network in this harness")),
  JSON,
  Promise,
  Number,
  Date,
  encodeURIComponent,
};
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(APP, "utf8"), sandbox, { filename: APP });

/* --- Describe what renderComparison() built ----------------------------- */

function describe(diff) {
  sandbox.renderComparison(diff);
  const box = document.getElementById("history-result");
  const out = { sections: {}, notes: [] };
  for (const node of box.children) {
    if (node.className === "history-section") {
      const title = node.children[0].textContent.replace(/ \(\d+\)$/, "");
      out.sections[title] = node.children[1].children.map((li) => ({
        text: li.textContent,
        reason: li.children.length ? li.children[0].textContent : null,
      }));
    } else {
      out.notes.push({ className: node.className, text: node.textContent });
    }
  }
  return out;
}

const finding = (summary) => ({ summary, device: "rtr-us5" });
const SAVED = { id: 1, name: "Head office", created_at: "2026-09-29T02:16:36+00:00", is_sample: false };
const EMPTY = {
  resolved: [], unverified: [], new: [], newly_visible: [], newly_blind: [],
  newly_checked: [], unchanged_count: 0, possibly_same: [], caveats: [],
};

const CASES = {
  every_category: Object.assign({}, EMPTY, {
    saved: SAVED, current_is_sample: false,
    resolved: [finding("RESOLVED ONE")],
    unverified: [{ finding: finding("UNVERIFIED ONE"), reason: "the later scan could not check this" }],
    new: [finding("NEW ONE")],
    newly_visible: [{ finding: finding("VISIBLE ONE"), reason: "the earlier scan could not check this" }],
    newly_blind: [{ check: "routing", device: "rtr-hq", reason: "reported nothing for this device" }],
    newly_checked: [{ check: "access_control", device: "rtr-us5" }],
    unchanged_count: 2,
    caveats: ["The policy changed between these scans."],
  }),
  nothing_resolved: Object.assign({}, EMPTY, {
    saved: SAVED, current_is_sample: false,
    unverified: [{ finding: finding("UNVERIFIED ONE"), reason: "Batfish is not reachable" }],
  }),
  sample_involved: Object.assign({}, EMPTY, {
    saved: Object.assign({}, SAVED, { is_sample: true }), current_is_sample: false,
  }),
};

const out = {};
for (const [name, diff] of Object.entries(CASES)) out[name] = describe(diff);

// Staging a new config makes any comparison on screen stale: it describes
// the previous config. clearStaleResults() is what every staging path calls.
sandbox.renderComparison(CASES.every_category);
sandbox.clearStaleResults("A new config is staged.");
out.after_new_config = { comparison_children: document.getElementById("history-result").children.length };

process.stdout.write(JSON.stringify(out, null, 2));
