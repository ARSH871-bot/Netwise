/*
  Test harness for the report download control (#222).

  WHAT IS AT STAKE
      The control is two anchors that the browser follows natively. That is
      the right design -- no fetch, no Blob -- but it means the ONLY thing
      standing between an unavailable state and a real download is a click
      handler calling preventDefault(). An anchor has no `disabled`
      attribute, so a link that merely LOOKS greyed still downloads.

      And the state it guards is not cosmetic. After an upload but before
      Scan Now, the findings pane is deliberately empty (#82). Following the
      link there starts a real Batfish analysis nobody asked for and returns
      a report describing results the screen has never shown.

  WHY THE URLS ARE ASSERTED HERE AND NOT ONLY IN THE MARKUP TEST
      `format=html|csv` is #233's contract. If either href drifts, the server
      answers 400 with a message about valid formats and the user sees a
      failed download with no explanation -- so the exact query string is
      worth pinning at the point it is used.

  Prints one JSON object; tests/test_report_download.py asserts on it.
*/
"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

/* --- The smallest DOM this needs ---------------------------------------- */

function makeElement(tag) {
  return {
    tagName: tag,
    className: "",
    textContent: "",
    href: "",
    children: [],
    style: {},
    listeners: {},
    attributes: {},
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
    addEventListener(name, fn) {
      this.listeners[name] = fn;
    },
    setAttribute(key, value) {
      this.attributes[key] = String(value);
    },
    getAttribute(key) {
      return this.attributes[key] ?? null;
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
  createTextNode(text) {
    return { tagName: "#text", textContent: text, children: [] };
  },
  getElementById(id) {
    if (!byId.has(id)) byId.set(id, makeElement("div"));
    return byId.get(id);
  },
};

/* --- Seed the two anchors with the hrefs index.html actually ships ------- */

const HTML_HREF = "/api/report?format=html";
const CSV_HREF = "/api/report?format=csv";

// Seeded to match what index.html actually SHIPS: both links present, both
// already aria-disabled. The shim's getElementById invents a bare element
// for any id, so without this the harness would model a page whose links
// start with no state at all -- and the boot behaviour it is here to check
// (disabled until the first render succeeds) would be untestable, because
// "never set" and "set to available" both read as not-disabled.
["report-html", "report-csv"].forEach((id) => {
  document.getElementById(id).setAttribute("aria-disabled", "true");
});
document.getElementById("report-html").href = HTML_HREF;
document.getElementById("report-csv").href = CSV_HREF;
document.getElementById("report-hint").textContent =
  "Nothing to export yet — run a scan first.";

/* --- A findings response, so loadFindings() can succeed ------------------ */

const FINDINGS = [
  {
    id: "AC-001",
    check: "access_control",
    severity: "high",
    device: "rtr-us5",
    summary: "A rule allows traffic that policy forbids",
    evidence: { detail: "flow permitted", source: "testFilters" },
    status: "found",
  },
];

let nextFetch = { ok: true, body: FINDINGS };

const APP = path.join(__dirname, "..", "..", "web", "static", "app.js");
const sandbox = {
  document,
  console,
  fetch: () =>
    nextFetch.ok
      ? Promise.resolve({ ok: true, json: () => Promise.resolve(nextFetch.body) })
      : Promise.reject(new Error("network is down")),
  FormData: function () {
    this.append = () => {};
  },
  JSON,
  Promise,
};
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(APP, "utf8"), sandbox, { filename: APP });

/* --- Helpers ------------------------------------------------------------- */

const linkIds = ["report-html", "report-csv"];

function state() {
  const links = linkIds.map((id) => document.getElementById(id));
  return {
    ariaDisabled: links.map((l) => l.getAttribute("aria-disabled")),
    hrefs: links.map((l) => l.href),
    hint: document.getElementById("report-hint").textContent,
  };
}

/** Click a link and report whether the navigation was prevented. */
function click(id) {
  const link = document.getElementById(id);
  let prevented = false;
  const event = {
    preventDefault() {
      prevented = true;
    },
  };
  const handler = link.listeners.click;
  if (!handler) return { error: `no click handler on #${id}` };
  handler(event);
  return { prevented };
}

/* --- Drive the real code through every state ---------------------------- */

/* What a genuinely clean scan looks like on the wire: every check ran, none
 * of them found anything. NOT an empty list -- see afterCleanResult below. */
const CLEAN_FINDINGS = [
  {
    id: "PC-000",
    check: "policy_compliance",
    severity: "low",
    device: "rtr-us5",
    summary: "No issues found by policy compliance",
    evidence: { detail: "All policy rules held.", source: "analysis/checks/policy_compliance.py" },
    status: "none",
  },
  {
    id: "AC-000",
    check: "access_control",
    severity: "low",
    device: "rtr-us5",
    summary: "No issues found by access control",
    evidence: { detail: "All access-control assertions held.", source: "analysis/checks/access_control.py" },
    status: "none",
  },
];

(async () => {
  const out = {};

  // BEFORE anything resolves. app.js calls loadFindings() at boot but does
  // not await it, so this is the state a user sees for the first few
  // hundred milliseconds: the shipped HTML, links unavailable. Asserting it
  // is the point -- a control that is briefly live before the first render
  // is a control that can be clicked before there is anything to export.
  out.atBoot = state();

  // Now let the first load settle.
  await sandbox.loadFindings();
  out.afterSuccessfulRender = state();
  out.clickWhenAvailable = {
    html: click("report-html"),
    csv: click("report-csv"),
  };

  // A config or policy upload clears the pane.
  sandbox.clearStaleResults("Config staged, nothing analysed yet.");
  out.afterClear = state();
  out.clickWhenUnavailable = {
    html: click("report-html"),
    csv: click("report-csv"),
  };

  // Scanning again puts findings back.
  nextFetch = { ok: true, body: FINDINGS };
  await sandbox.loadFindings();
  out.afterRescan = state();

  // And a failed load takes it away again.
  nextFetch = { ok: false };
  await sandbox.loadFindings();
  out.afterFailedLoad = state();

  // "We checked and found nothing" is a real result, and a report of it is
  // one somebody may need to hand to whoever asked. So it stays exportable.
  //
  // NOTE THE BODY. This used to be `[]`, which the server can never send
  // for a completed scan: every registered check contributes a found, none
  // or error finding, so a clean run arrives as `status="none"` findings.
  // Measured -- rtr-us5-secure returns 0 found, 2 none, 1 error.
  //
  // The old encoding was a hazard rather than merely inaccurate. Three zero
  // tiles and a live export button, presented as a completed scan of a
  // clean network, for a response that measured nothing.
  nextFetch = { ok: true, body: CLEAN_FINDINGS };
  await sandbox.loadFindings();
  out.afterCleanResult = state();

  // AND THE CASE THAT IS NOW REACHABLE. An empty body means one thing:
  // nothing has been uploaded in this session. It is not a clean result and
  // must not offer an export -- a live Download button beside "nothing has
  // been checked" contradicts the sentence next to it.
  nextFetch = { ok: true, body: [] };
  await sandbox.loadFindings();
  out.afterNothingUploaded = state();

  console.log(JSON.stringify(out, null, 2));
})();
