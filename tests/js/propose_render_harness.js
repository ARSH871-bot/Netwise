/*
  Test harness for the propose pane's response rendering (US-13/US-14).

  WHAT IS AT STAKE
      This pane shows a CONFIG LINE that Netwise generated, next to a verdict
      about what applying it would do. Three things about that must hold, and
      none of them can be checked from Python -- /api/propose's JSON is
      correct in every case, and only app.js decides what it looks like:

        1. A REFUSAL MUST NEVER RENDER AS A LESSER SUCCESS. grounded=false
           means nothing ran. Rendered like an answer, it becomes "here is a
           fact about your network" -- F-4 in the propose pane.

        2. A PROVED OPENING MUST BE IMPOSSIBLE TO MISS, AND MUST SURVIVE AN
           UNRELATED ERROR IN THE SAME DIFF. #183 made `verified` and
           `warning` separate booleans after review found exactly that
           suppression in the backend. ANDing them here would re-create the
           bug one layer later.

        3. THE GENERATED LINE MUST NEVER READ AS APPLIED. ai/propose.py holds
           the real constraint structurally -- it only ever writes to a
           throwaway copy. This holds the user's belief about it.

  WHY A DOM SHIM AND NOT jsdom
      Same reasoning as the four harnesses beside it: no npm toolchain in a
      Python repo, and Node ships on ubuntu-latest so this runs in CI as it
      stands. It loads the REAL web/static/app.js, so if the renderer
      changes, this moves with it.

  Prints one JSON object; tests/test_propose_rendering.py asserts on it.
*/
"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

/* --- The smallest DOM that app.js needs --------------------------------- */

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
    removeEventListener() {},
    remove() {},
    focus() {},
    // Records rather than acts. The shim has no geometry, so the only thing
    // worth asserting is WHICH element the renderer chose to bring into
    // view and with what alignment.
    scrollIntoView(options) {
      this.scrolledIntoView = options || {};
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

/* --- Drive addProposeResponse() and describe what it built --------------- */

const log = document.getElementById("propose-log");

/** Flatten a subtree to {cls, tag, text} rows, so assertions can look anywhere. */
function flatten(node, out) {
  (node.children || []).forEach((child) => {
    out.push({
      tag: child.tagName,
      cls: child.className,
      text: child.textContent,
    });
    flatten(child, out);
  });
  return out;
}

function renderAndDescribe(result) {
  log.replaceChildren();
  log.scrollTop = 0;
  log.scrollHeight = 500;
  const exchange = sandbox.addProposeResponse(result);

  const nodes = flatten(exchange, []);
  const classesInOrder = (exchange.children || []).map((c) => c.className);

  const find = (cls) => nodes.filter((n) => n.cls === cls);
  const first = (cls) => (find(cls)[0] ? find(cls)[0].text : null);

  return {
    // Which element the renderer scrolled to, and how. A warned response
    // must bring its own START into view; anything else leaves the log
    // scrolled to the newest content as usual.
    scrolledTo: exchange.scrolledIntoView ? exchange.scrolledIntoView.block : null,
    logScrolledToBottom: log.scrollTop === log.scrollHeight,

    // The exchange's own direct children, IN ORDER. Order is a safety
    // property here: the warning must come before the answer and the
    // verification note after it, so their independence is structural.
    order: classesInOrder,

    understood: first("understood"),

    // The answer bubble's exact class. "message system" is an answer;
    // "message system refusal" is a refusal. Nothing else is either.
    answerClass: (classesInOrder.find((c) => c.startsWith("message system")) || null),
    answerText: first("message system") || first("message system refusal"),

    warningPresent: find("propose-warning").length,
    warningText: first("propose-warning"),
    unverifiedPresent: find("propose-unverified").length,

    proposedPresent: find("proposed-change").length,
    proposedDevice: first("proposed-device"),
    proposedFilter: first("proposed-filter"),
    proposedLine: first("proposed-line"),
    proposedLineTag: find("proposed-line")[0] ? find("proposed-line")[0].tag : null,
    notAppliedText: first("proposed-not-applied"),

    impactPresent: find("impact").length,
    impactHeading: first("impact-heading"),
    // Finding cards, by variant. These classes are renderFinding()'s, which
    // is the point: if the impact list stopped reusing it, these vanish.
    findingClasses: nodes
      .filter((n) => n.cls && n.cls.startsWith("finding "))
      .map((n) => n.cls),
    // The sentence renderFinding() puts on a blind card. A hand-rolled
    // impact renderer would almost certainly omit it.
    blindNoteCount: nodes.filter(
      (n) => n.text && n.text.indexOf("this check did not run") !== -1
    ).length,
    allText: nodes.map((n) => n.text).join(" | "),
  };
}

/* --- The scripted responses --------------------------------------------- */

function finding(overrides) {
  return Object.assign(
    {
      id: "CH-001",
      check: "change_impact",
      severity: "high",
      device: "rtr-us5",
      summary: "The change newly permits traffic that was blocked",
      evidence: {
        detail: "differentialReachability: 10.10.10.5 -> 10.20.0.5:443 now ACCEPTED",
        source: "differentialReachability",
      },
      status: "found",
    },
    overrides || {}
  );
}

const CHANGE = {
  device: "rtr-us5",
  filter: "acl_in",
  line: "deny tcp host 10.10.10.5 host 10.20.0.5 eq 443",
};

const REFUSED = {
  request_understood: null,
  proposed_change: null,
  impact: [],
  verified: false,
  warning: false,
  grounded: false,
  answer:
    'Could not read "block YouTube" as a change. A destination must be an ' +
    "IP address or CIDR written out -- a service name cannot be resolved offline.",
};

const NO_UPLOAD = {
  request_understood: null,
  proposed_change: null,
  impact: [],
  verified: false,
  warning: false,
  grounded: false,
  answer: "Upload a config first, there is nothing to propose a change against yet.",
};

const CLEAN = {
  request_understood:
    "On rtr-us5, add to 'acl_in' (at the top): deny tcp host 10.10.10.5 host 10.20.0.5 eq 443",
  proposed_change: CHANGE,
  impact: [],
  verified: true,
  warning: false,
  grounded: true,
  answer:
    "Generated: deny tcp host 10.10.10.5 host 10.20.0.5 eq 443, on rtr-us5's " +
    "'acl_in' filter. Simulating this change shows no detected effect on " +
    "filter lines or reachability.",
};

const NARROWS = {
  request_understood: "On rtr-us5, add to 'acl_in' (at the top): deny tcp ...",
  proposed_change: CHANGE,
  impact: [finding({ severity: "medium", summary: "The change narrows access" })],
  verified: true,
  warning: false,
  grounded: true,
  answer: "Generated: ... it narrows access; it does not appear to newly open anything.",
};

// The headline case: a PROVED high-severity opening.
const WARNING = {
  request_understood: "On rtr-us5, add to 'acl_in' (at the top): permit tcp ...",
  proposed_change: {
    device: "rtr-us5",
    filter: "acl_in",
    line: "permit tcp host 10.10.10.5 host 10.20.0.5 eq 443",
  },
  impact: [finding({})],
  verified: true,
  warning: true,
  grounded: true,
  answer:
    "Generated: permit tcp host 10.10.10.5 host 10.20.0.5 eq 443, on rtr-us5's " +
    "'acl_in' filter. Warning: simulating this change shows it newly opens " +
    "access that was previously blocked -- see the impact list.",
};

// #183's case: a PROVED opening beside an UNRELATED error. Both must show.
const WARNING_AND_UNVERIFIED = {
  request_understood: "On rtr-us5, add to 'acl_in' (at the top): permit tcp ...",
  proposed_change: CHANGE,
  impact: [
    finding({}),
    finding({
      id: "CH-000",
      status: "error",
      severity: "high",
      summary: "differentialReachability could not run",
      evidence: { detail: "Batfish returned no answer", source: "change_impact" },
    }),
  ],
  verified: false,
  warning: true,
  grounded: true,
  answer: "Generated: ... Warning: ... Some of the impact analysis also could not run.",
};

const UNVERIFIED_ONLY = {
  request_understood: "On rtr-us5, add to 'acl_in' (at the top): deny tcp ...",
  proposed_change: CHANGE,
  impact: [
    finding({
      id: "CH-000",
      status: "error",
      summary: "differentialReachability could not run",
      evidence: { detail: "Batfish returned no answer", source: "change_impact" },
    }),
  ],
  verified: false,
  warning: false,
  grounded: true,
  answer:
    "Generated: ... Its impact could not be fully verified. This is NOT a claim " +
    "that the change is safe.",
};

const MIXED_IMPACT = {
  request_understood: "On rtr-us5, add to 'acl_in' (at the top): deny tcp ...",
  proposed_change: CHANGE,
  impact: [
    finding({ id: "CH-003", severity: "medium", status: "found" }),
    finding({ id: "CH-004", status: "none", severity: "low", summary: "No change" }),
    finding({ id: "CH-001", severity: "high", status: "found" }),
    finding({ id: "CH-000", status: "error", summary: "could not run" }),
  ],
  verified: false,
  warning: true,
  grounded: true,
  answer: "Generated: ...",
};

// A backend that stops sending the keys, or sends junk. Every one of these
// must land on the side that claims LESS.
const MISSING_KEYS = {
  request_understood: "On rtr-us5, add to 'acl_in' (at the top): deny tcp ...",
  proposed_change: CHANGE,
  impact: [],
  answer: "Generated: ...",
};

const JUNK_KEYS = {
  request_understood: "On rtr-us5, add to 'acl_in' (at the top): deny tcp ...",
  proposed_change: CHANGE,
  impact: [],
  verified: "yes",
  warning: "no",
  grounded: "yes",
  answer: "Generated: ...",
};

// grounded EXACTLY true, but the two flags malformed. The combination no
// test covered until a mutation survived: both `warning` and `verified`
// mutations were invisible because every malformed case also had a
// malformed `grounded` and rendered as a refusal before reaching them.
const GROUNDED_JUNK_FLAGS = {
  request_understood: "On rtr-us5, add to 'acl_in' (at the top): deny tcp ...",
  proposed_change: CHANGE,
  impact: [],
  verified: "yes",
  warning: "no",
  grounded: true,
  answer: "Generated: ...",
};

// verified EXACTLY true, only `warning` malformed. Distinguishes "the
// verified flag was junk" from "the warning flag was junk": without the
// flags-usable term, this case would report a fully verified result while
// having no idea whether the change opens access.
const GROUNDED_JUNK_WARNING_ONLY = {
  request_understood: "On rtr-us5, add to 'acl_in' (at the top): deny tcp ...",
  proposed_change: CHANGE,
  impact: [],
  verified: true,
  warning: "no",
  grounded: true,
  answer: "Generated: ...",
};

// A device name containing markup, arriving by a path that looks like ours.
const SCRIPTED = {
  request_understood: "On <img src=x onerror=alert(1)>, add to 'acl_in': deny ...",
  proposed_change: {
    device: "<img src=x onerror=alert(1)>",
    filter: "acl_in",
    line: "deny tcp any any",
  },
  impact: [],
  verified: true,
  warning: false,
  grounded: true,
  answer: "Generated: ...",
};

const out = {
  refused: renderAndDescribe(REFUSED),
  noUpload: renderAndDescribe(NO_UPLOAD),
  clean: renderAndDescribe(CLEAN),
  narrows: renderAndDescribe(NARROWS),
  warning: renderAndDescribe(WARNING),
  warningAndUnverified: renderAndDescribe(WARNING_AND_UNVERIFIED),
  unverifiedOnly: renderAndDescribe(UNVERIFIED_ONLY),
  mixedImpact: renderAndDescribe(MIXED_IMPACT),
  missingKeys: renderAndDescribe(MISSING_KEYS),
  junkKeys: renderAndDescribe(JUNK_KEYS),
  groundedJunkFlags: renderAndDescribe(GROUNDED_JUNK_FLAGS),
  groundedJunkWarningOnly: renderAndDescribe(GROUNDED_JUNK_WARNING_ONLY),
  scripted: renderAndDescribe(SCRIPTED),
};

console.log(JSON.stringify(out, null, 2));
