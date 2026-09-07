/*
  Test harness for the persistent conversion-gaps notice (#302 review, round
  two, @shubhamkataria2005 and @ARSH871-bot).

  WHAT THIS GUARDS
      Two failures the on-screen dashboard used to have, both now fixed via
      updateConversionGapsNotice():

      1. THE DISCLOSURE WAS TRANSIENT. Before this, a pfSense conversion's
         skip notes reached the user exactly once, appended to the
         transient #upload-message box by addSkippedNotes(). A page reload
         followed by Scan Now showed clean summary tiles with no trace
         anything had been excluded -- /api/findings itself said nothing
         about it. This harness drives loadFindings() (the real fetch path)
         directly, not just the pure function, so a fix that works in
         isolation but never gets wired into the fetch call would still be
         caught.

      2. AN UNREADABLE SKIP RECORD MUST NOT LOOK LIKE "NOTHING EXCLUDED".
         X-Netwise-Conversion-Gaps-Unreadable: "true" must win over the
         count header, and must render a DIFFERENT sentence from "N parts
         were excluded" -- conflating the two would be the exact
         false-completeness bug the backend fix (analysis/coverage.py,
         web/main.py) exists to remove, reappearing on the frontend.

  WHY A DOM SHIM AND NOT jsdom -- same reasoning as every other harness
  beside it: no npm toolchain in a Python repo, Node ships on ubuntu-latest,
  and this loads the REAL web/static/app.js so it moves with the renderer.

  Prints one JSON object; tests/test_conversion_gaps_notice.py asserts on it.
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

/* --- A fetch mock whose Response DOES model .headers, unlike every other
   harness's -- this is the one place that distinction is the point. ------- */

const FINDINGS = [
  {
    id: "AC-001", check: "access_control", severity: "high",
    device: "rtr-us5", summary: "A rule allows traffic that policy forbids",
    evidence: { detail: "flow permitted", source: "testFilters" },
    status: "found",
  },
];

let nextHeaders = { "X-Netwise-Conversion-Gap-Count": "0",
                     "X-Netwise-Conversion-Gaps-Unreadable": "false" };
let nextOk = true;

function makeHeaders(map) {
  return { get: (name) => (name in map ? map[name] : null) };
}

const APP = path.join(__dirname, "..", "..", "web", "static", "app.js");
const sandbox = {
  document,
  console,
  fetch: () =>
    nextOk
      ? Promise.resolve({
          ok: true,
          headers: makeHeaders(nextHeaders),
          json: () => Promise.resolve(FINDINGS),
        })
      : Promise.reject(new Error("network is down")),
  JSON,
  Promise,
};
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(APP, "utf8"), sandbox, { filename: APP });

function noticeState() {
  const el = document.getElementById("conversion-gaps-notice");
  return { hidden: el.hidden, text: el.textContent };
}

(async () => {
  const out = {};

  // --- End to end, through the real fetch path (loadFindings) -----------

  // Nothing excluded: the notice must stay hidden.
  nextHeaders = { "X-Netwise-Conversion-Gap-Count": "0",
                   "X-Netwise-Conversion-Gaps-Unreadable": "false" };
  await sandbox.loadFindings();
  out.zeroCount = noticeState();

  // A real exclusion: persistent, visible, names the count.
  nextHeaders = { "X-Netwise-Conversion-Gap-Count": "2",
                   "X-Netwise-Conversion-Gaps-Unreadable": "false" };
  await sandbox.loadFindings();
  out.twoExcluded = noticeState();

  // An unreadable record: visible, but a DIFFERENT sentence from the count
  // case -- must never read as "nothing excluded" or "N excluded".
  nextHeaders = { "X-Netwise-Conversion-Gap-Count": "0",
                   "X-Netwise-Conversion-Gaps-Unreadable": "true" };
  await sandbox.loadFindings();
  out.unreadable = noticeState();

  // Reload simulation: the notice must be rebuilt fresh from the NEXT
  // fetch's headers, not carried over from a previous state that no
  // longer applies -- the "reload then Scan Now" case Shubham's review
  // named directly.
  nextHeaders = { "X-Netwise-Conversion-Gap-Count": "0",
                   "X-Netwise-Conversion-Gaps-Unreadable": "false" };
  await sandbox.loadFindings();
  out.afterUnreadableThenClean = noticeState();

  // A failed fetch must not leave a stale disclosure on screen.
  nextHeaders = { "X-Netwise-Conversion-Gap-Count": "3",
                   "X-Netwise-Conversion-Gaps-Unreadable": "false" };
  await sandbox.loadFindings();
  out.beforeFailure = noticeState();
  nextOk = false;
  await sandbox.loadFindings();
  out.afterFailedLoad = noticeState();
  nextOk = true;

  // Missing headers (an older server, or a harness that models no headers
  // at all) must degrade to "nothing to disclose", not throw.
  out.missingHeadersDidNotThrow = (() => {
    try {
      sandbox.updateConversionGapsNotice(null, null);
      return { threw: false, state: noticeState() };
    } catch (e) {
      return { threw: true, message: e.message };
    }
  })();

  console.log(JSON.stringify(out, null, 2));
})();
