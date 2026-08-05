/*
  Netwise dashboard -- rendering logic.

  It does three things:
    1. fetches findings from /api/findings and renders them
    2. validates a chosen config file before it is uploaded
    3. runs the chat panel

  THE RULE THIS FILE FOLLOWS THROUGHOUT
      Findings are grouped by STATUS first and severity second.

      That order is the whole point. Every finding carries a severity, but for
      status="none" and status="error" that value is contract plumbing rather
      than a judgement -- the F-1 helpers pin "none" to low and "error" to
      high. Sort by severity alone and an errored check ("we could not look")
      lands in the middle of the real high-severity problems, while a clean
      result ("we looked, all good") sinks to the bottom with the trivia. Both
      readings are wrong, and one of them is dangerous.

      So: status decides which SECTION a finding goes in, and severity only
      orders findings within the "problems found" section.
*/

// Severity order, worst first. Used only inside the "problems found" section.
const SEVERITY_ORDER = { high: 0, medium: 1, low: 2 };

/*
  A SECOND RULE, learned the hard way: `id` is NOT treated as unique.

  Findings are rendered in list order and never keyed, de-duplicated or looked
  up by id. That is deliberate, because ids are not currently unique -- see the
  PC-000 collision documented in web/mock_findings.py. `policy_compliance` and
  `change_impact` share the "PC" prefix and both number their sentinel finding
  000, so a run where one is clean and the other errored produces two findings
  called PC-000.

  If this file keyed cards by id -- the obvious thing to do, and what a
  framework would do by default -- one of that pair would be silently dropped.
  The dropped one could be the error, leaving the user reading "policy
  compliance: all clear" with no sign that the change-impact check never ran.
  That is the F-4 failure exactly, arriving through the id field rather than
  the status field.

  So: no keying by id until ids are actually unique. The mock data keeps that
  collision on purpose so this stays tested.
*/

/* ------------------------------------------------------------------------ *
 * Small DOM helper
 *
 * Findings contain raw config text and Batfish output -- other people's
 * strings. Building elements and assigning textContent means that text is
 * always shown as text. If we assembled HTML strings instead, a config line
 * containing angle brackets would be interpreted as markup, which is both a
 * rendering bug and an injection route.
 * ------------------------------------------------------------------------ */
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = text;
  return node;
}

/* ------------------------------------------------------------------------ *
 * Findings
 * ------------------------------------------------------------------------ */

/** Build one finding card. `variant` is the CSS class driving its appearance. */
function renderFinding(finding, variant, icon, badgeText) {
  const card = el("article", `finding ${variant}`);

  const head = el("div", "finding-head");
  head.appendChild(el("span", "icon", icon));
  head.appendChild(el("span", "badge", badgeText));
  head.appendChild(el("span", "finding-meta", finding.id));
  card.appendChild(head);

  card.appendChild(el("p", "finding-summary", finding.summary));
  card.appendChild(
    el("p", "finding-meta", `${finding.check} • ${finding.device}`)
  );

  // The evidence is Batfish's own words. We display it verbatim and never
  // paraphrase it here -- paraphrasing is the AI layer's job, and it is
  // grounded in exactly this string.
  const evidence = el("div", "evidence", finding.evidence.detail);
  evidence.appendChild(el("span", "source", finding.evidence.source));
  card.appendChild(evidence);

  // Where the AI layer's plain-English explanation will go, once it exists.
  //
  // Gated to status="found" cards on purpose. A status="none" card has nothing
  // to explain, and a status="error" card has no Batfish output to ground an
  // explanation IN -- asking a model to write prose about a check that never
  // ran is exactly the invented-network-behaviour failure constraint 2 forbids.
  // So the slot only appears where real evidence exists directly above it.
  //
  // The "placeholder" modifier is doing real work, not decoration. Once the AI
  // layer lands, "the model has not run yet" and "the model said this" are two
  // different claims, and they must not look alike -- the same reasoning that
  // keeps status="none" and status="error" visually distinct. So the unwired
  // state is dashed and muted, and wiring it up means dropping the modifier
  // (and this literal string) rather than restyling anything.
  if (variant !== "blind" && variant !== "clean") {
    const explanation = el(
      "div",
      "ai-explanation placeholder",
      "This is a placeholder for the plain-English explanation the AI layer " +
        "will generate here once it's wired in. Example length: a sentence or " +
        "two describing what the finding means and why it matters, grounded " +
        "in the evidence above."
    );
    card.appendChild(explanation);
  }

  // Spell it out in words as well as colour. An amber card is a signal; a
  // sentence saying "this is not a clean result" cannot be misread.
  if (variant === "blind") {
    card.appendChild(
      el(
        "p",
        "blind-warning",
        "This is not a clean result — this check did not run, so nothing is known here."
      )
    );
  }

  return card;
}

/** Build one titled section, or nothing at all if it has no findings. */
function renderSection(heading, note, items, build) {
  if (items.length === 0) return null;

  const section = el("section", "section");
  section.appendChild(el("h3", "section-heading", heading));
  section.appendChild(el("p", "section-note", note));
  items.forEach((finding) => section.appendChild(build(finding)));
  return section;
}

/** Render the three coverage tiles. */
function renderSummary(problems, clean, blind) {
  const summary = document.getElementById("summary");
  summary.replaceChildren();

  // "Could not check" is rendered even when it is zero. An explicit "0 could
  // not check" is a statement of coverage; an absent tile is an absence of
  // information, and the two should not be confused.
  const tiles = [
    ["problems", problems.length, "problems found"],
    ["clean", clean.length, "checked, nothing found"],
    ["blind", blind.length, "could not check"],
  ];

  tiles.forEach(([variant, count, label]) => {
    const tile = el("div", `tile ${variant}`);
    tile.appendChild(el("div", "count", String(count)));
    tile.appendChild(el("div", "label", label));
    summary.appendChild(tile);
  });
}

/** Render the whole findings list, grouped by status. */
function renderFindings(findings) {
  const container = document.getElementById("findings");
  container.replaceChildren();

  const problems = findings
    .filter((f) => f.status === "found")
    .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  const clean = findings.filter((f) => f.status === "none");
  const blind = findings.filter((f) => f.status === "error");

  renderSummary(problems, clean, blind);

  // Errors come FIRST. A check that did not run is the thing most likely to
  // mislead someone reading quickly, so it is put where it cannot be missed --
  // above the results, not below them.
  const sections = [
    renderSection(
      "Could not check",
      "These checks did not run. Nothing is known about what they cover.",
      blind,
      (f) => renderFinding(f, "blind", "⚠", "could not check")
    ),
    renderSection(
      "Problems found",
      "Issues the analysis identified, most serious first.",
      problems,
      (f) => renderFinding(f, f.severity, "●", f.severity)
    ),
    renderSection(
      "Checked — nothing found",
      "These checks ran successfully and found no issues.",
      clean,
      (f) => renderFinding(f, "clean", "✓", "checked")
    ),
  ];

  sections.filter(Boolean).forEach((s) => container.appendChild(s));
}

/**
 * Fetch findings and render them.
 *
 * If the request fails we show a warning and NO findings list. We do not fall
 * back to an empty list, because an empty list renders as three zeroes and
 * reads as "nothing wrong" -- which would be the same lie the status field
 * exists to prevent, told at the frontend instead of the backend.
 */
async function loadFindings() {
  const container = document.getElementById("findings");
  try {
    const response = await fetch("/api/findings");
    if (!response.ok) throw new Error(`server returned ${response.status}`);
    renderFindings(await response.json());
  } catch (error) {
    document.getElementById("summary").replaceChildren();
    container.replaceChildren(
      el(
        "div",
        "notice",
        `Could not load findings: ${error.message}. This is not a clean ` +
          `result — no analysis has been shown. Is the server running?`
      )
    );
  }
}

/* ------------------------------------------------------------------------ *
 * Upload
 *
 * These checks mirror the ones in web/main.py. They exist for speed of
 * feedback, not for safety: anyone can bypass the browser, so the SERVER is
 * where the rules are actually enforced. Keep the two in step.
 * ------------------------------------------------------------------------ */
const ALLOWED_EXTENSIONS = [".cfg", ".conf", ".txt"];
const MAX_UPLOAD_BYTES = 2 * 1024 * 1024;

// Recognised but not analysable yet -- mirrors UNSUPPORTED_EXTENSIONS in
// web/main.py. The client's real firewall is PF Sense, and "that is not a
// config file we can read" would be both wrong and embarrassing when they try
// their own export. It plainly is a config file; we just cannot read it yet.
const UNSUPPORTED_EXTENSIONS = {
  ".xml": "PF Sense XML",
  ".pfsense": "PF Sense XML",
};

function showUploadMessage(text, ok) {
  const box = document.getElementById("upload-message");
  box.textContent = text;
  box.className = `upload-message ${ok ? "ok" : "bad"}`;
}

function setUpUpload() {
  const input = document.getElementById("file-input");

  input.addEventListener("change", async () => {
    const file = input.files[0];
    if (!file) return;

    const name = file.name;
    const extension = name.slice(name.lastIndexOf(".")).toLowerCase();

    // Recognised-but-unsupported is checked first, so a PF Sense export gets
    // the explanation rather than the generic rejection.
    if (extension in UNSUPPORTED_EXTENSIONS) {
      showUploadMessage(
        `'${name}' looks like a ${UNSUPPORTED_EXTENSIONS[extension]} export. ` +
          `Netwise cannot analyse that format yet — our analysis engine does ` +
          `not read it natively. Cisco IOS configs ` +
          `(${ALLOWED_EXTENSIONS.join(", ")}) work today.`,
        false
      );
      input.value = "";
      return;
    }

    if (!ALLOWED_EXTENSIONS.includes(extension)) {
      showUploadMessage(
        `'${name}' is not a config file we can read. Netwise accepts ` +
          `${ALLOWED_EXTENSIONS.join(", ")} files.`,
        false
      );
      input.value = "";
      return;
    }

    if (file.size > MAX_UPLOAD_BYTES) {
      const sizeMb = (file.size / (1024 * 1024)).toFixed(1);
      showUploadMessage(
        `'${name}' is ${sizeMb} MB, over the 2 MB limit. Network configs ` +
          `are normally well under this — is this definitely a config file?`,
        false
      );
      input.value = "";
      return;
    }

    if (file.size === 0) {
      showUploadMessage(`'${name}' is empty.`, false);
      input.value = "";
      return;
    }

    // Passed the local checks -- now let the server decide, because it is the
    // server's answer that counts.
    const body = new FormData();
    body.append("file", file);
    try {
      const response = await fetch("/api/upload", { method: "POST", body });
      const result = await response.json();
      if (response.ok) {
        showUploadMessage(result.message, true);

        // Clear the old findings BEFORE fetching the new ones.
        //
        // Whatever is on screen right now describes the PREVIOUS config. The
        // upload has already been accepted, so leaving it there puts a success
        // message above results that do not belong to the file just uploaded --
        // and the analysis takes seconds, not milliseconds, because
        // /api/findings runs Batfish for real. Someone reading during that gap
        // would be looking at another network's findings under the heading of
        // this one.
        //
        // The summary tiles go too. Three stale counts beside a "loading"
        // message are the same false claim in smaller type.
        document.getElementById("summary").replaceChildren();
        document.getElementById("findings").replaceChildren(
          el(
            "div",
            "notice loading",
            "Analysing your upload, this can take up to 15 seconds..."
          )
        );

        // loadFindings() replaces this message with the real results, and
        // handles its own failure -- so a failed fetch shows its own notice
        // rather than leaving "Analysing..." on screen forever.
        await loadFindings();
      } else {
        showUploadMessage(result.detail, false);
        input.value = "";
      }
    } catch (error) {
      showUploadMessage(`Upload failed: ${error.message}`, false);
    }
  });
}

/* ------------------------------------------------------------------------ *
 * Chat
 *
 * The panel works; the model behind it does not exist yet. So it says so.
 *
 * It deliberately does NOT reply with a plausible-sounding placeholder answer.
 * A security tool that invents network behaviour is broken in the worst way,
 * and a mock that invents it during a demo teaches everyone watching to trust
 * an answer nothing produced. The honest stub is the one that admits it.
 * ------------------------------------------------------------------------ */
function addMessage(text, who) {
  const log = document.getElementById("chat-log");
  log.appendChild(el("div", `message ${who}`, text));
  log.scrollTop = log.scrollHeight;
}

function setUpChat() {
  addMessage(
    "The explanation layer is not connected yet. Once it is, answers here " +
      "will be grounded strictly in the findings on the left.",
    "system"
  );

  document.getElementById("chat-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const input = document.getElementById("chat-input");
    const question = input.value.trim();
    if (!question) return;

    addMessage(question, "user");
    input.value = "";
    addMessage(
      "Not connected yet — no model has seen this question, so there " +
        "is no answer to give.",
      "system"
    );
  });
}

/* ------------------------------------------------------------------------ */
loadFindings();
setUpUpload();
setUpChat();
