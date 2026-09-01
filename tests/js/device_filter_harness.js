/*
  Test harness for the device filter (#219).

  WHAT IS AT STAKE
      Filtering is a view control, and the risk it carries is not a
      rendering bug -- it is F-4. Filtering to one device hides findings
      about the others, INCLUDING status="error" ones. A reader who filters,
      sees a green summary, and forgets the selector is set has been shown
      "all clear" for a network where a check never ran.

      So these cases check what the pane SAYS about what it is hiding, not
      only which cards survive the filter.

  WHY A DOM SHIM AND NOT jsdom
      Same reasoning as the six harnesses beside it: no npm toolchain in a
      Python repo, and Node ships on ubuntu-latest. It loads the REAL
      web/static/app.js, so if the filter changes, this moves with it.

  Prints one JSON object; tests/test_device_filter_rendering.py asserts.
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
    value: "",
    href: "",
    hidden: false,
    children: [],
    style: {},
    listeners: {},
    attributes: {},
    disabled: false,
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

const APP = path.join(__dirname, "..", "..", "web", "static", "app.js");
const sandbox = {
  document,
  console,
  fetch: () => Promise.reject(new Error("no network in this harness")),
  FormData: function () {
    this.append = () => {};
  },
  JSON,
  Promise,
};
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(APP, "utf8"), sandbox, { filename: APP });

/* --- Findings ------------------------------------------------------------ */

function finding(id, device, status, severity) {
  return {
    id,
    check: "access_control",
    severity,
    device,
    summary: `${id} on ${device}`,
    evidence: { detail: `detail for ${id}`, source: "testFilters" },
    status,
  };
}

const MULTI = [
  finding("AC-001", "rtr-us5", "found", "high"),
  finding("AC-002", "rtr-us5", "found", "medium"),
  finding("RT-000", "rtr-hq", "error", "high"),
  finding("PC-001", "rtr-hq", "found", "high"),
  finding("PC-002", "sw-lab-1", "none", "low"),
];

const SINGLE = [
  finding("AC-001", "rtr-us5", "found", "high"),
  finding("AC-002", "rtr-us5", "none", "low"),
];

const NO_BLIND_ELSEWHERE = [
  finding("AC-001", "rtr-us5", "found", "high"),
  finding("PC-001", "rtr-hq", "found", "medium"),
];

/* --- Describe what the pane looks like ---------------------------------- */

function cardIds() {
  const out = [];
  (function walk(node) {
    (node.children || []).forEach((child) => {
      if (child.className && String(child.className).startsWith("finding ")) {
        // The id lives in the first .finding-meta span.
        const meta = [];
        (function inner(n) {
          (n.children || []).forEach((c) => {
            if (c.className === "finding-meta") meta.push(c.textContent);
            inner(c);
          });
        })(child);
        if (meta.length) out.push(meta[0]);
      }
      walk(child);
    });
  })(document.getElementById("findings"));
  return out;
}

function state() {
  const row = document.getElementById("device-filter-row");
  const select = document.getElementById("device-filter");
  const notice = document.getElementById("filter-notice");
  return {
    rowHidden: row.hidden,
    options: select.children.map((o) => ({ value: o.value, label: o.textContent })),
    selected: select.value,
    noticeHidden: notice.hidden,
    noticeClass: notice.className,
    noticeText: notice.textContent,
    visibleIds: cardIds(),
  };
}

/** Change the selector the way a browser would, then fire the handler. */
function choose(device) {
  const select = document.getElementById("device-filter");
  select.value = device;
  const handler = select.listeners.change;
  if (!handler) return { error: "no change handler on #device-filter" };
  handler();
  return state();
}

/* --- Drive the real code ------------------------------------------------- */

const out = {};

sandbox.setUpDeviceFilter();

sandbox.renderFindings(MULTI);
out.multiUnfiltered = state();
out.filteredToUs5 = choose("rtr-us5");
out.filteredToHq = choose("rtr-hq");
out.backToAll = choose("");

// A device whose hidden set contains NO blind finding -- the notice should
// still appear, but not in amber.
sandbox.renderFindings(NO_BLIND_ELSEWHERE);
out.noBlindHidden = choose("rtr-us5");

// One device: the control has nothing to offer.
sandbox.renderFindings(SINGLE);
out.singleDevice = state();

// A rescan that still contains the chosen device keeps the choice; one that
// does not falls back to all.
sandbox.renderFindings(MULTI);
choose("rtr-hq");
sandbox.renderFindings(MULTI);
out.choiceSurvivesRescan = state();

sandbox.renderFindings(MULTI);
choose("sw-lab-1");
sandbox.renderFindings(NO_BLIND_ELSEWHERE);
out.choiceDroppedWhenDeviceGone = state();

console.log(JSON.stringify(out, null, 2));
