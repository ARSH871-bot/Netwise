/*
  Test harness for the first-run empty state and the sample banner (#347).

  WHY THIS EXISTS
      #352 removed six fabricated findings that greeted a visitor before any
      upload, and left an honest but bare screen. #347 fills it -- and the
      way it fills it is the whole risk. Two claims have to survive:

        1. The empty state still says nothing has been checked and that this
           is NOT a clean result. Softening that sentence while adding
           friendly next steps would walk straight back into #352.

        2. When the sample is loaded, every surface says so. The findings it
           produces are genuine Batfish output about a real file, which is
           precisely why an unlabelled sample is dangerous: there is nothing
           in the results themselves to raise a doubt.

  WITHOUT ANY CSS, DELIBERATELY
      Same argument as nothing_to_check_harness.js. The harness has no
      stylesheet, so anything it can see is carried by markup and words --
      the property that has to hold in greyscale, in print, and in a screen
      reader. A banner that is only a shade of amber is not a label.

  OUTPUT
      One JSON object on stdout; tests/test_sample_empty_state.py asserts.
*/

"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

/* --- The smallest DOM the code under test needs ------------------------- */

function makeElement(tag) {
  return {
    tagName: tag,
    className: "",
    textContent: "",
    children: [],
    style: {},
    listeners: {},
    appendChild(child) {
      this.children.push(child);
      return child;
    },
    replaceChildren(...nodes) {
      this.children = nodes;
    },
    addEventListener(event, handler) {
      (this.listeners[event] = this.listeners[event] || []).push(handler);
    },
    setAttribute(key, value) {
      this.attributes = this.attributes || {};
      this.attributes[key] = String(value);
    },
    removeAttribute(key) {
      if (this.attributes) delete this.attributes[key];
    },
    getAttribute(key) {
      return (this.attributes || {})[key] ?? null;
    },
    hasAttribute(key) {
      return Object.prototype.hasOwnProperty.call(this.attributes || {}, key);
    },
    querySelector() {
      return null;
    },
  };
}

const byId = new Map();
// The banner starts hidden, exactly as index.html ships it -- so "it was
// revealed" is a real observation rather than an artefact of the harness.
byId.set("sample-banner", (() => {
  const node = makeElement("p");
  node.setAttribute("hidden", "");
  return node;
})());

const document = {
  createElement: makeElement,
  getElementById(id) {
    if (!byId.has(id)) byId.set(id, makeElement("div"));
    return byId.get(id);
  },
};

/* --- Load the real app.js, not a copy of it ----------------------------- */

const APP = path.join(__dirname, "..", "..", "web", "static", "app.js");

// What POST /api/sample really answers.
//
// READ FROM web/main.py, NOT TYPED OUT HERE, AND THAT MATTERS.
//     The first draft of this harness hard-coded a plausible-looking message
//     and the test then asserted "invented" and "not your data" against it.
//     Both passed. Neither word was in the server's actual sentence, which
//     says "invented data, not a real device" -- so the test was checking
//     the fixture against itself and would have gone on passing over a
//     server that said nothing about the data being invented at all.
//
//     That is the same defect this project keeps finding in its own tests:
//     a harness compared to its own fixture rather than to the thing it
//     claims to cover. Extracted from the source so the two cannot diverge.
const MAIN_PY = fs.readFileSync(
  path.join(__dirname, "..", "..", "web", "main.py"),
  "utf8"
);

function sampleMessageFromServer() {
  const marker = '"message": (';
  const at = MAIN_PY.indexOf("Sample network loaded");
  if (at === -1) throw new Error("web/main.py no longer sends a sample message");
  const open = MAIN_PY.lastIndexOf(marker, at) + marker.length;
  const close = MAIN_PY.indexOf("),", open);
  // The source writes it as adjacent string literals across lines. Pull the
  // quoted pieces out and join them exactly as Python would.
  const pieces = MAIN_PY.slice(open, close).match(/"([^"]*)"/g) || [];
  return pieces.map((piece) => piece.slice(1, -1)).join("");
}

const SAMPLE_RESPONSE = {
  accepted: true,
  is_sample: true,
  message: sampleMessageFromServer(),
};

let lastFetch = null;

// Routed by URL rather than a single canned reply: this harness has to drive
// BOTH the empty first load (/api/findings returning []) and the sample
// click (/api/sample), and a one-size answer would make the first of those
// untestable.
const sandbox = {
  document,
  console,
  fetch: (url, options) => {
    lastFetch = { url, options };
    if (url === "/api/sample") {
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve(SAMPLE_RESPONSE),
      });
    }
    if (url === "/api/findings") {
      // An empty list, which per loadFindings()'s own comment means exactly
      // one thing: nothing has been staged in this session.
      return Promise.resolve({ ok: true, json: () => Promise.resolve([]) });
    }
    return Promise.reject(new Error(`unexpected request to ${url}`));
  },
  JSON,
  Promise,
  setTimeout,
};
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(APP, "utf8"), sandbox, { filename: APP });

/* --- Walkers ------------------------------------------------------------- */

function allText(node, out) {
  out = out || [];
  if (node.textContent) out.push(node.textContent);
  (node.children || []).forEach((c) => allText(c, out));
  return out;
}

function describe(node) {
  return {
    text: allText(node).join(" "),
    hidden: node.hasAttribute ? node.hasAttribute("hidden") : null,
  };
}

/* --- Collect ------------------------------------------------------------- */

function findButtons(node, out) {
  out = out || [];
  if (node.tagName === "button") out.push(node);
  (node.children || []).forEach((c) => findButtons(c, out));
  return out;
}

const result = {};
const findings = document.getElementById("findings");

// 1. The empty first load -- what a visitor sees before touching anything.
sandbox
  .loadFindings()
  .then(() => {
    result.emptyState = describe(findings);
    result.emptyStateButtons = findButtons(findings).map((b) => ({
      text: b.textContent,
      className: b.className,
      type: b.getAttribute("type"),
    }));
    // The export control's real signal is the hint text beside it --
    // setDownloadAvailable() sets aria-disabled on the links and writes the
    // reason here. Asserted rather than a `.disabled` property, because
    // there is no button: an earlier draft of this harness read
    // `getElementById("download-report").disabled`, which fabricated a node
    // and returned undefined, and JSON.stringify then dropped the key
    // entirely -- a test that asserted nothing and said nothing about it.
    result.reportHintWhenEmpty =
      document.getElementById("report-hint").textContent;

    // Wired by setUpUpload(), which ran when app.js was evaluated. This is
    // the OTHER sample button -- the one beside the file picker.
    const beside = document.getElementById("load-sample");
    result.pickerButtonWired = ((beside.listeners || {}).click || []).length;

    result.bannerBefore = describe(document.getElementById("sample-banner"));

    // 2. Clicking the offer inside that empty state -- the real node the
    //    visitor would click, not a direct call to the handler. If it was
    //    never wired, this throws and the harness fails loudly.
    const offer = findButtons(findings)[0];
    if (!offer) throw new Error("the empty state rendered no sample button");
    const handlers = offer.listeners.click || [];
    if (handlers.length === 0) {
      throw new Error("the empty state's sample button has no click handler");
    }
    return handlers[0]();
  })
  .then(() => {
    result.fetched = lastFetch;
    result.bannerAfter = describe(document.getElementById("sample-banner"));
    result.uploadMessage = describe(document.getElementById("upload-message"));
    result.scanDisabled = document.getElementById("scan-now").disabled;
    result.findingsAfterLoad = describe(findings);
    result.reportHintAfterLoad =
      document.getElementById("report-hint").textContent;

    // 3. The banner must come back down when the session stops being a
    //    sample -- the mislabel that runs in the reassuring direction.
    sandbox.setSampleBanner(false);
    result.bannerCleared = describe(document.getElementById("sample-banner"));

    process.stdout.write(JSON.stringify(result, null, 2));
  })
  .catch((error) => {
    process.stderr.write(String((error && error.stack) || error));
    process.exit(1);
  });
