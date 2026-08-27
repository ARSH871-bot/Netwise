/*
  Test harness for the business-context picker (#87, risk side).

  WHAT IS AT STAKE, AND WHY IT IS NOT THE SAME AS THE POLICY HARNESS
      A policy upload has two outcomes. This one has three, and the third is
      the reason the feature needed a UI at all:

          accepted, every entry usable
          accepted, SOME ENTRIES UNUSABLE      <- 200, `accepted: true`
          rejected

      The middle case is a success as far as HTTP is concerned. If the
      dashboard renders it as a plain green "accepted", a user who tagged
      their finance VLAN by subnet reads success, sees no severity move, and
      concludes their context was applied. The server already refuses to be
      silent about this -- `unusable_entries()` names each one -- and that
      honesty is thrown away if the pane shows green anyway.

      Nothing in the Python suite can catch that. The endpoint's JSON is
      correct in every case; only app.js decides what colour it wears.

  WHY A DOM SHIM AND NOT jsdom
      Same reasoning as the harnesses beside it: no npm toolchain in a Python
      repo, and Node ships on ubuntu-latest so this runs in CI as it stands.
      It loads the REAL web/static/app.js, so if the handler changes, this
      moves with it.

  Prints one JSON object; tests/test_business_context_rendering.py asserts.
*/
"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

/* --- The smallest DOM the upload handlers need -------------------------- */

function makeElement(tag) {
  return {
    tagName: tag,
    className: "",
    textContent: "",
    value: "",
    disabled: false,
    files: [],
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
    addEventListener(name, fn) {
      this.listeners[name] = fn;
    },
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

/* --- A scripted server -------------------------------------------------- */

let nextResponse = null;
const fetchCalls = [];

function fakeFetch(url, options) {
  fetchCalls.push({ url, method: options && options.method });
  return Promise.resolve({
    ok: nextResponse.ok,
    json: () => Promise.resolve(nextResponse.body),
  });
}

function FormDataShim() {
  this.parts = [];
  this.append = (name, value) => this.parts.push([name, value]);
}

const APP = path.join(__dirname, "..", "..", "web", "static", "app.js");
const sandbox = {
  document,
  console,
  fetch: fakeFetch,
  FormData: FormDataShim,
  JSON,
  Promise,
};
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(APP, "utf8"), sandbox, { filename: APP });

/* --- Drive one upload and report what the pane looks like ---------------- */

function seedFindings() {
  // Whatever was on screen before. If it survives, the user is reading
  // findings scored WITHOUT this context under its success message.
  document
    .getElementById("findings")
    .replaceChildren(makeElement("div"), makeElement("div"));
  document.getElementById("summary").replaceChildren(makeElement("div"));
}

function resetMessage(id) {
  // Children, text AND class. The policy harness learned this the hard way:
  // clearing only the children let one case inherit the previous case's
  // `warn` class and look like it had reported something. A harness that
  // carries state between cases produces the exact false pass these tests
  // exist to prevent, one layer up.
  const box = document.getElementById(id);
  box.replaceChildren();
  box.textContent = "";
  box.className = "";
}

async function upload(inputId, fileName, response) {
  seedFindings();
  nextResponse = response;
  resetMessage("business-context-message");
  resetMessage("policy-message");

  // Seed the context picker with a filename BEFORE every case.
  //
  // Without this, a mutation removing the picker reset from the config
  // handler survived: the input happened to be "" already, left over from an
  // earlier case, so "was it cleared?" and "was it ever set?" gave the same
  // answer. A harness that cannot tell those apart is asserting nothing --
  // the same false-pass shape the resetMessage() comment above describes.
  document.getElementById("business-context-input").value = "seeded.json";

  const input = document.getElementById(inputId);
  input.files = [{ name: fileName, size: 42 }];
  input.value = fileName;

  const handler = input.listeners.change;
  if (!handler) return { error: `no change handler on #${inputId}` };
  await handler();

  const findings = document.getElementById("findings");
  const notice = findings.children[0];
  const box = document.getElementById("business-context-message");

  return {
    findingsCount: findings.children.length,
    summaryCount: document.getElementById("summary").children.length,
    noticeClass: notice ? notice.className : null,
    noticeText: notice ? notice.textContent : null,
    message: box.textContent,
    // The TONE, not just the words. An accepted-but-unusable context must
    // not wear the same green as one where everything applied.
    messageClass: box.className,
    // Notes are appended as child NODES (textContent, never innerHTML), so
    // they are counted and read out of the tree rather than out of a string.
    noteClasses: box.children.map((c) => c.className),
    noteTexts: box.children.map((c) => c.textContent),
    policyMessage: document.getElementById("policy-message").textContent,
    policyMessageClass: document.getElementById("policy-message").className,
    // The input that was driven, AND the context picker specifically. For a
    // CONFIG upload those are different elements, and the one that matters
    // is the context picker: the handler resets it so the cleared file is
    // not still named in a control that no longer reflects the server.
    inputValue: input.value,
    contextInputValue: document.getElementById("business-context-input").value,
    posted: fetchCalls.length ? fetchCalls[fetchCalls.length - 1].url : null,
    postCount: fetchCalls.length,
  };
}

/* --- The scripted responses --------------------------------------------- */

const ALL_USABLE = {
  ok: true,
  body: {
    accepted: true,
    asset_count: 2,
    is_empty: false,
    unusable: [],
    message:
      "'bc.json' accepted (120 bytes) and staged. 2 asset(s): critical 1, " +
      "standard 1. Findings on a 'critical' asset will be raised one " +
      "severity level.",
  },
};

const ONE_UNUSABLE = {
  ok: true,
  body: {
    accepted: true,
    asset_count: 2,
    is_empty: false,
    unusable: [
      "entry 2 (Finance VLAN) names a subnet. Netwise matches business " +
        "context by device name only, so this entry did not affect any finding",
    ],
    message: "'bc.json' accepted (150 bytes) and staged. 2 asset(s): critical 2.",
  },
};

const TWO_UNUSABLE = {
  ok: true,
  body: {
    accepted: true,
    asset_count: 3,
    is_empty: false,
    unusable: [
      "entry 2 (Finance VLAN) names a subnet. ...",
      "entry 3 (Payroll) names a subnet. ...",
    ],
    message: "'bc.json' accepted and staged. 3 asset(s): critical 3.",
  },
};

// Every entry unusable: still a 200, and the most misleading green of all.
const ALL_UNUSABLE = {
  ok: true,
  body: {
    accepted: true,
    asset_count: 1,
    is_empty: false,
    unusable: ["entry 1 (Finance VLAN) names a subnet. ..."],
    message: "'bc.json' accepted and staged. 1 asset(s): critical 1.",
  },
};

const REJECTED = {
  ok: false,
  body: {
    detail:
      "entry 1 (device 'rtr-us5'): unknown tier 'Critical' -- did you mean " +
      "'critical'? (tiers are lower-case)",
  },
};

const EMPTY_CONTEXT = {
  ok: true,
  body: {
    accepted: true,
    asset_count: 0,
    is_empty: true,
    unusable: [],
    message:
      "'bc.json' accepted (2 bytes) and staged. It names no assets, which " +
      "is a valid choice.",
  },
};

// A hostile entry description, arriving through a path that looks like our
// own text. It must be inserted as text and never interpreted.
const SCRIPTED_NOTE = {
  ok: true,
  body: {
    accepted: true,
    asset_count: 1,
    is_empty: false,
    unusable: ["entry 1 (<img src=x onerror=alert(1)>) names a subnet. ..."],
    message: "'bc.json' accepted and staged.",
  },
};

const CONFIG_CLEARS_CONTEXT = {
  ok: true,
  body: {
    accepted: true,
    filename: "device.cfg",
    size_bytes: 42,
    policy_cleared: false,
    business_context_cleared: true,
    message: "'device.cfg' accepted and staged.",
  },
};

const CONFIG_NOTHING_STAGED = {
  ok: true,
  body: {
    accepted: true,
    filename: "device.cfg",
    size_bytes: 42,
    policy_cleared: false,
    business_context_cleared: false,
    message: "'device.cfg' accepted and staged.",
  },
};

(async () => {
  const out = {};

  out.allUsable = await upload("business-context-input", "bc.json", ALL_USABLE);
  out.oneUnusable = await upload("business-context-input", "bc.json", ONE_UNUSABLE);
  out.twoUnusable = await upload("business-context-input", "bc.json", TWO_UNUSABLE);
  out.allUnusable = await upload("business-context-input", "bc.json", ALL_UNUSABLE);
  out.rejected = await upload("business-context-input", "bc.json", REJECTED);
  out.emptyContext = await upload("business-context-input", "bc.json", EMPTY_CONTEXT);
  out.scriptedNote = await upload("business-context-input", "bc.json", SCRIPTED_NOTE);

  // A non-JSON context never reaches the server at all.
  fetchCalls.length = 0;
  out.wrongExtension = await upload("business-context-input", "bc.yaml", ALL_USABLE);

  // A config upload clears the staged context, visibly.
  out.configClears = await upload("file-input", "device.cfg", CONFIG_CLEARS_CONTEXT);
  out.configNothingStaged = await upload(
    "file-input",
    "device.cfg",
    CONFIG_NOTHING_STAGED
  );

  console.log(JSON.stringify(out, null, 2));
})();
