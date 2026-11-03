/*
  Test harness for the policy upload's stale-results clearing (#87, #82).

  WHAT IS AT STAKE
      Findings on screen describe a config checked against a policy. Change
      EITHER and they stop describing anything currently staged. #82 already
      established that for a new config; a new POLICY makes them exactly as
      stale, because they were computed against the old rules.

      There is no server-side findings cache on `main` -- /api/findings
      recomputes on every request -- so the clearing lives entirely in
      app.js. That means nothing in the Python suite can catch it. If
      clearStaleResults() stops being called on a policy upload, the
      dashboard shows one policy's findings under another policy's success
      message, and every server-side test still passes.

  WHY A DOM SHIM AND NOT jsdom
      Same reasoning as the three harnesses beside it: no npm toolchain in a
      Python repo, and Node ships on ubuntu-latest so this runs in CI as it
      stands. It loads the REAL web/static/app.js, so if the handler changes,
      this moves with it.

  Prints one JSON object; tests/test_policy_upload_rendering.py asserts on it.
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
    // app.js sets aria-disabled on the report links via the real
    // DOM API, so the shim has to model it. Attributes are kept in
    // their own map rather than as properties, so a test cannot
    // read one that was never set.
    setAttribute(key, value) {
      this.attributes = this.attributes || {};
      this.attributes[key] = String(value);
    },
    getAttribute(key) {
      return (this.attributes || {})[key] ?? null;
    },
    // classList, backed by the same className string every other part of
    // this shim already reads -- added when app.js started calling
    // classList.add()/remove() for comparison mode. A live accessor, not a
    // snapshot, so it stays correct across repeated add/remove calls on
    // the same element.
    get classList() {
      const self = this;
      return {
        add(cls) {
          const classes = self.className ? self.className.split(/\s+/) : [];
          if (!classes.includes(cls)) classes.push(cls);
          self.className = classes.join(' ');
        },
        remove(cls) {
          const classes = self.className ? self.className.split(/\s+/) : [];
          self.className = classes.filter((c) => c !== cls).join(' ');
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
  createTextNode(text) {
    return { tagName: "#text", textContent: text, children: [] };
  },
  getElementById(id) {
    if (!byId.has(id)) byId.set(id, makeElement("div"));
    return byId.get(id);
  },
};

/* --- A scripted server ---------------------------------------------------
   Each case sets `nextResponse` before firing the change event, so the
   handler's own fetch call is what drives the assertions. */

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

/* --- Drive one upload and report what the results pane looks like ------- */

function seedFindings() {
  // Whatever was on screen before this upload. If it survives, the user is
  // reading the previous policy's results under the new policy's message.
  document
    .getElementById("findings")
    .replaceChildren(makeElement("div"), makeElement("div"));
  document.getElementById("summary").replaceChildren(makeElement("div"));
}

async function upload(inputId, fileName, response) {
  seedFindings();
  nextResponse = response;

  // Reset the message element FULLY -- children, text AND class.
  //
  // Clearing only the children was not enough, and the gap was visible: the
  // "config upload with no staged policy" case inherited the previous case's
  // `warn` class and looked like it had reported something. A harness that
  // carries state between cases produces exactly the false pass these tests
  // exist to prevent, one layer up.
  const message = document.getElementById("policy-message");
  message.replaceChildren();
  message.textContent = "";
  message.className = "";

  const input = document.getElementById(inputId);
  input.files = [{ name: fileName, size: 42 }];
  input.value = fileName;

  const handler = input.listeners.change;
  if (!handler) return { error: `no change handler on #${inputId}` };
  await handler();

  const findings = document.getElementById("findings");
  const notice = findings.children[0];
  return {
    findingsCount: findings.children.length,
    summaryCount: document.getElementById("summary").children.length,
    noticeClass: notice ? notice.className : null,
    noticeText: notice ? notice.textContent : null,
    policyMessage: document.getElementById("policy-message").textContent,
    // The TONE, not just the words. "nothing failed but something was
    // discarded" is amber; green would invite the reader past it.
    policyMessageClass: document.getElementById("policy-message").className,
    renameNoteClasses: document
      .getElementById("policy-message")
      .children.map((c) => c.className),
    // Rename notes are appended as child nodes (textContent, never innerHTML),
    // so they are counted rather than read out of the string.
    renameNoteNodes: document.getElementById("policy-message").children.length,
    uploadMessage: document.getElementById("upload-message").textContent,
    posted: fetchCalls.length ? fetchCalls[fetchCalls.length - 1].url : null,
  };
}

// The message is deliberately a SENTINEL rather than a copy of the server's
// real wording.
//
// It used to read "...staged. Not yet applied.", and the Python test asserted
// "not yet applied" was on screen. That asserted nothing about the product:
// the string was in THIS file, so the test compared the harness to itself and
// would have passed against a frontend that ignored the server entirely.
//
// It also outlived the truth. #181 made "not yet applied" false, and this
// fixture went on saying it -- a fixture, unlike a document, is never reread.
//
// A sentinel with no plausible wording of its own can only appear on screen if
// the frontend relayed what the server sent, which is the property the test
// is named for. Whether the server's own sentence is CORRECT is a server-side
// question, tested in tests/test_web_policy_upload.py.
const SERVER_MESSAGE_SENTINEL =
  "SERVER-AUTHORED-SENTINEL-9f3a: this exact text must reach the screen.";

const OK_POLICY = {
  ok: true,
  body: {
    accepted: true,
    rule_count: 2,
    is_empty: false,
    renamed: [],
    message: SERVER_MESSAGE_SENTINEL,
  },
};

const REJECTED_POLICY = {
  ok: false,
  body: {
    detail:
      "policy_compliance entry 1 ('Typo'): unknown key 'nodes'. Allowed here: node",
  },
};

const RENAMED_POLICY = {
  ok: true,
  body: {
    accepted: true,
    rule_count: 1,
    is_empty: false,
    renamed: ["policy_compliance entry 1 ('x'): 'severity' was renamed"],
    message: "'p.json' accepted and staged. Not yet applied.",
  },
};

(async () => {
  const out = {};

  out.accepted = await upload("policy-input", "p.json", OK_POLICY);
  out.rejected = await upload("policy-input", "p.json", REJECTED_POLICY);
  out.renamed = await upload("policy-input", "p.json", RENAMED_POLICY);

  // A non-JSON policy never reaches the server at all.
  fetchCalls.length = 0;
  out.wrongExtension = await upload("policy-input", "p.yaml", OK_POLICY);
  out.wrongExtensionPosted = fetchCalls.length;

  // A CONFIG upload that discarded a staged policy. The server reports it
  // with `policy_cleared`; the pane must say so, and say it in amber.
  out.configClearedPolicy = await upload("file-input", "device.cfg", {
    ok: true,
    body: {
      accepted: true,
      message: "'device.cfg' accepted (42 bytes) and staged.",
      policy_cleared: true,
    },
  });

  // The same upload when no policy was staged: nothing to report.
  out.configNoPolicy = await upload("file-input", "device.cfg", {
    ok: true,
    body: {
      accepted: true,
      message: "'device.cfg' accepted (42 bytes) and staged.",
      policy_cleared: false,
    },
  });

  process.stdout.write(JSON.stringify(out, null, 2));
})();
