/*
  Test harness for the chat pane's rendering decisions (US-11).

  WHY THIS EXISTS, AND WHY IT IS NOT jsdom
      web/static/app.js decides, from one server response, whether an answer
      renders as a normal reply or as an amber refusal. That decision is
      safety-critical -- it is the chat pane's version of F-4 -- and until now
      nothing enforced it. A future edit could flip `grounded !== true` to
      `=== false` and every test in the project would still pass.

      This project's suite deliberately needs neither Batfish nor Docker, and
      is pure pytest. Adding jsdom would mean an npm toolchain and a
      package.json in a Python repo; adding Playwright would mean a ~115 MB
      browser download in CI. Neither is proportionate to checking which CSS
      class a div gets.

      So: a hand-written DOM shim, about forty lines, with no dependencies at
      all. Node ships on ubuntu-latest, so this runs in CI as it stands.

  WHAT IT DOES
      Loads the real web/static/app.js -- not a copy, not a re-implementation
      -- into a sandbox holding the shim, then calls the real addResponse()
      with server responses and reports what came out. If app.js changes, this
      changes with it.

  Prints one JSON object to stdout; tests/test_chat_rendering.py asserts on it.
*/
"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

/* --- The smallest DOM that app.js needs -------------------------------- */

function makeElement(tag) {
  return {
    tagName: tag,
    className: "",
    textContent: "",
    children: [],
    style: {},
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
    removeEventListener() {},
    remove() {},
    focus() {},
    // app.js only ever asks for the submit button, which no assertion here
    // needs; returning null is honest and keeps the shim small.
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
  // loadFindings() runs on load and calls this. It catches its own failure,
  // so a rejection here is the normal path, not an error in the test.
  fetch: () => Promise.reject(new Error("no network in this harness")),
  JSON,
  Promise,
};
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(APP, "utf8"), sandbox, { filename: APP });

/* --- Drive addResponse() and describe what it built --------------------- */

const chatLog = document.getElementById("chat-log");

function renderAndDescribe(result) {
  const before = chatLog.children.length;
  sandbox.addResponse(result);
  const added = chatLog.children.slice(before);

  const exchange = added.find((n) => n.className === "exchange");
  if (!exchange) return { error: "no .exchange element was appended" };

  const understood = exchange.children.find((c) => c.className === "understood");
  const message = exchange.children.find((c) =>
    String(c.className).startsWith("message")
  );

  return {
    understoodShown: Boolean(understood),
    understoodText: understood ? understood.textContent : null,
    messageClass: message ? message.className : null,
    // The property under test: does this response render as a refusal?
    isRefusal: message ? String(message.className).includes("refusal") : null,
    answerText: message ? message.textContent : null,
  };
}

/* Each case is one server response. The `grounded` values below are the point:
   true, false, and then four ways of being neither. */
const CASES = {
  grounded_true: {
    question_understood: "Can rtr-us5 reach 10.20.0.5?",
    answer: "Yes. Traffic from rtr-us5 reaches 10.20.0.5.",
    grounded: true,
  },
  grounded_false: {
    question_understood: null,
    answer: "I could not find a known device name on the source side.",
    grounded: false,
  },
  grounded_missing: {
    question_understood: "Can rtr-us5 reach 10.20.0.5?",
    answer: "Yes. Traffic from rtr-us5 reaches 10.20.0.5.",
  },
  grounded_null: {
    question_understood: "Can rtr-us5 reach 10.20.0.5?",
    answer: "Yes. Traffic from rtr-us5 reaches 10.20.0.5.",
    grounded: null,
  },
  grounded_string_true: {
    question_understood: "Can rtr-us5 reach 10.20.0.5?",
    answer: "Yes. Traffic from rtr-us5 reaches 10.20.0.5.",
    grounded: "true",
  },
  grounded_one: {
    question_understood: "Can rtr-us5 reach 10.20.0.5?",
    answer: "Yes. Traffic from rtr-us5 reaches 10.20.0.5.",
    grounded: 1,
  },
  // A refusal that still carries a translated question: the query was built,
  // then could not be run. Both parts must show.
  refused_after_translation: {
    question_understood: "Can rtr-us5 reach 10.20.0.5?",
    answer: "I could not run this check. The underlying reason: ...",
    grounded: false,
  },
};

const out = {};
for (const [name, result] of Object.entries(CASES)) {
  out[name] = renderAndDescribe(result);
}
process.stdout.write(JSON.stringify(out, null, 2));
