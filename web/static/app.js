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
  up by id. If this file keyed cards by id -- the obvious thing to do, and what
  a framework would do by default -- one of a colliding pair would be silently
  dropped. The dropped one could be the error, leaving the user reading "policy
  compliance: all clear" with no sign that a check never ran. That is the F-4
  failure exactly, arriving through the id field rather than the status field.

  THE COLLISION THIS RULE WAS WRITTEN FOR IS FIXED. IT IS STILL THE RULE.

  This paragraph used to say ids "are not currently unique", citing the PC-000
  pair: `policy_compliance` and `change_impact` shared the "PC" prefix and both
  numbered their sentinel 000, so a run where one was clean and the other
  errored produced two findings called PC-000. It named the A-2 amendment as
  the thing that "would" make them unique.

  A-2 landed -- #102, merged 13 August. `change_impact` owns "CH-" now, and
  those two checks cannot collide with each other any more.

  The rule does not relax, because A-2 removed a collision rather than the
  possibility of one. It made two NAMED checks unable to share an id. It did
  not make ids structurally unique: `make_finding()` takes `number` from its
  caller, so two findings from the SAME check that pass the same number still
  produce the same id -- convention, not structure. Any future prefix or
  numbering mistake lands in exactly this code path.

  `analysis/pipeline.duplicate_id_findings()` exists for the same reason and is
  the other half of the answer: it DETECTS what the contract cannot PREVENT.
  A guard that is only correct while a convention holds has to stay.

  Keeping a fixture is not a test, and for a while this comment claimed
  otherwise. Nothing called renderFindings() at all; the only Node harness
  drove the chat pane. The refactor this paragraph warns about would have
  passed the whole suite.

  tests/test_findings_rendering.py now drives THIS function through the real
  file, with a colliding pair in BOTH orders. Since A-2 the pair it uses is
  RT-000 twice -- `routing` clean and `routing` errored, one check colliding
  with itself -- rather than the old cross-check PC-000, precisely because a
  distinct prefix removes the second kind and not the first.

  The order matters: keying by id keeps the last value, so with the error
  first it is the ERROR that disappears -- which is the dangerous direction,
  and the one a single-order test would have missed.
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

  // The AI layer's plain-English explanation (US-19 / #31). web/main.py
  // attaches `finding.explanation` server-side, only for status="found"
  // findings that were actually explained -- see _attach_explanations()
  // there for why "none"/"error" are excluded, and why a failed
  // explanation attempt means the key is simply absent rather than an
  // error message here.
  //
  // TWO SOURCES, TWO BYLINES (#109). THE MODIFIER IS WHAT KEEPS THE LABEL
  // HONEST.
  //
  //     "model"       -> class "ai-explanation"          -> "AI EXPLANATION"
  //     anything else -> class "ai-explanation fallback" -> "PLAIN-ENGLISH SUMMARY"
  //
  // This comment used to argue the opposite: that keeping the label in CSS
  // meant it "can never drift out of sync", because app.js built exactly one
  // element and there was only one thing it could be. That stopped being true
  // the moment #52 made explain() degrade instead of raising. On a machine
  // with no Ollama -- the default, and how the whole test suite runs -- the
  // text under the byline is `_fallback_plain_restatement()`, the finding's
  // own summary and detail concatenated. Correct and grounded, but no model
  // wrote it, and the label said one did (#109).
  //
  // The label still lives in CSS, so it still cannot drift from the styling.
  // What changed is that the CLASS now carries the provenance, so the styling
  // it cannot drift from is the correct one of two. #143 supplies the fact as
  // `explanation_source`; this line is the only place it is consumed.
  //
  // `=== "model"` rather than `!== "fallback"`, for the same reason
  // `grounded !== true` is written that way in the chat pane below: a missing,
  // misspelled or unexpected value must land on the side that claims LESS. A
  // backend that stops sending the key should quietly stop claiming AI
  // authorship, never quietly start.
  //
  // Absent `explanation` still renders nothing at all -- not an empty labelled
  // box promising prose that does not exist, which is what the pre-#31
  // placeholder did.
  if (variant !== "blind" && variant !== "clean" && finding.explanation) {
    const fromModel = finding.explanation_source === "model";
    const explanation = el(
      "div",
      fromModel ? "ai-explanation" : "ai-explanation fallback",
      finding.explanation
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

/**
 * Run the analysis on whatever config is currently staged, and show it.
 *
 * This is the block that used to run automatically at the end of a successful
 * upload. It is unchanged in what it does -- clear, show the loading state,
 * fetch -- and changed only in what starts it: a click rather than an upload.
 */
async function runScan() {
  const button = document.getElementById("scan-now");

  // Locked for the duration. /api/findings runs Batfish for real, so a second
  // click part-way through would start an overlapping analysis and the two
  // would race to render into the same container.
  button.disabled = true;
  document.getElementById("summary").replaceChildren();
  document.getElementById("findings").replaceChildren(
    el(
      "div",
      "notice loading",
      "Analysing your upload, this can take up to 15 seconds..."
    )
  );

  // loadFindings() replaces this message with the real results, and handles
  // its own failure -- so a failed fetch shows its own notice rather than
  // leaving "Analysing..." on screen forever.
  await loadFindings();

  // Re-enabled so the same staged config can be scanned again -- useful after
  // a failure, and harmless otherwise.
  button.disabled = false;
}

function setUpUpload() {
  const input = document.getElementById("file-input");
  const scanButton = document.getElementById("scan-now");

  scanButton.addEventListener("click", runScan);

  input.addEventListener("change", async () => {
    const file = input.files[0];
    if (!file) return;

    // Choosing a file invalidates whatever was staged before it, so the button
    // goes off here and is turned back on in exactly one place: a successful
    // server-side accept. Every rejection path below -- wrong extension, PF
    // Sense, too large, empty, and the server's own refusal -- therefore
    // leaves it disabled without having to remember to say so.
    scanButton.disabled = true;

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

        // The upload no longer starts the analysis -- Scan Now does. But the
        // old findings must still go, and for the SAME reason they always did:
        // whatever is on screen describes the PREVIOUS config, and a success
        // message about this file sitting above another network's results is a
        // false claim regardless of what triggered the analysis. The summary
        // tiles go too; three stale counts are the same claim in smaller type.
        //
        // What replaces them is a neutral prompt rather than a loading state,
        // because nothing is running yet and saying otherwise would be the
        // same lie in the other direction.
        document.getElementById("summary").replaceChildren();
        document.getElementById("findings").replaceChildren(
          el(
            "div",
            "notice staged",
            "Config staged, nothing analysed yet. Click Scan Now to check it."
          )
        );

        scanButton.disabled = false;
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
 * Chat -- asking a question (US-11)
 *
 * Wired to POST /api/ask, which always returns the same three keys whether it
 * answered or refused:
 *
 *     { question_understood: string | null, answer: string, grounded: bool }
 *
 * TWO RULES THIS SECTION EXISTS TO ENFORCE
 *
 *   1. The translated question is always shown back, above the answer.
 *      CLAUDE.md §7c: no model is called in either direction, and the intent
 *      is matched against a closed set of three. That narrow scope is only
 *      SAFE, rather than merely limited, because the person who asked can see
 *      what was actually run and say "that is not what I meant". A confidently
 *      wrong QUERY produces a real, evidenced, confidently wrong answer that
 *      every other guard in this project passes.
 *
 *   2. A refusal never looks like an answer.
 *      grounded=false means nothing ran, or nothing could. That is the same
 *      claim as an amber "could not check" card, and it is rendered with the
 *      same vocabulary. The failure this prevents is F-4 in the chat pane:
 *      "I could not work out what you meant" sitting in the log styled
 *      exactly like a fact about the network.
 * ------------------------------------------------------------------------ */

/** Append one chat bubble. Returns the node so callers can remove it later. */
function addMessage(text, who) {
  const log = document.getElementById("chat-log");
  const node = el("div", `message ${who}`, text);
  log.appendChild(node);
  log.scrollTop = log.scrollHeight;
  return node;
}

/**
 * Render one response: the translated question, then the answer.
 *
 * Both are built with el(), so textContent -- an answer quotes Batfish output
 * and a config's own device names, which are other people's strings.
 */
function addResponse(result) {
  const log = document.getElementById("chat-log");
  const exchange = el("div", "exchange");

  // Shown whenever the server translated the question at all. On a refusal
  // question_understood is null, because there is no query to show -- the
  // answer itself then carries the reason.
  if (result.question_understood) {
    exchange.appendChild(el("div", "understood", result.question_understood));
  }

  // `!== true` rather than `=== false` on purpose. A missing, misspelled or
  // malformed `grounded` key lands on the CAUTIOUS side: it renders as a
  // refusal rather than as a confident answer. Defaulting the other way would
  // mean a backend bug silently upgrades "we do not know" into "here is a
  // fact about your network".
  const refused = result.grounded !== true;
  exchange.appendChild(
    el("div", `message system${refused ? " refusal" : ""}`, result.answer)
  );

  log.appendChild(exchange);
  log.scrollTop = log.scrollHeight;
}

function setUpChat() {
  addMessage(
    "Ask a question about the uploaded network. I'll always show you the " +
      "question I understood before giving an answer.",
    "system"
  );

  const form = document.getElementById("chat-form");
  const input = document.getElementById("chat-input");
  const button = form.querySelector("button");

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const question = input.value.trim();
    if (!question) return;

    addMessage(question, "user");
    input.value = "";

    // Locked while in flight. /api/ask connects to Batfish and loads the
    // snapshot on every call, so this takes seconds -- long enough that
    // someone would otherwise send a second question and watch two answers
    // arrive in an order neither of them chose.
    input.disabled = true;
    button.disabled = true;
    const pending = addMessage("Checking against the network…", "system pending");

    try {
      const response = await fetch("/api/ask", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question }),
      });
      if (!response.ok) throw new Error(`server returned ${response.status}`);
      pending.remove();
      addResponse(await response.json());
    } catch (error) {
      // The request never completed, so nothing was checked. Rendered through
      // the same refusal path rather than as a bare error string, because
      // "the question could not be asked" and "the question was refused" are
      // the same thing to the person reading: no answer, and no grounds.
      pending.remove();
      addResponse({
        question_understood: null,
        answer: `Could not ask that question: ${error.message}. Nothing was checked, so nothing is known either way.`,
        grounded: false,
      });
    } finally {
      input.disabled = false;
      button.disabled = false;
      input.focus();
    }
  });
}

/* ------------------------------------------------------------------------ */
loadFindings();
setUpUpload();
setUpChat();
