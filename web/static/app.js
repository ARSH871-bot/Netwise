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

// Recognised as a PF Sense export and converted server-side before staging --
// mirrors PFSENSE_EXTENSIONS in web/main.py. Accepted here rather than
// rejected: the client's real firewall is PF Sense, and analysis.pfsense_convert
// now turns this into Cisco IOS text server-side, the same way it always has
// for a plain .cfg upload.
const PFSENSE_EXTENSIONS = [".xml", ".pfsense"];

function showUploadMessage(text, ok) {
  const box = document.getElementById("upload-message");
  box.textContent = text;
  box.className = `upload-message ${ok ? "ok" : "bad"}`;
}

/**
 * Show the policy pane's message in one of three tones.
 *
 * THREE, NOT TWO, AND THE THIRD IS THE POINT
 *     "ok"    accepted, nothing lost
 *     "bad"   rejected, nothing staged
 *     "warn"  nothing failed, but something was DISCARDED -- a new config
 *             clearing the staged policy. Green would invite the user to
 *             skim past a file of theirs being thrown away; red would say a
 *             failure happened, and none did. Amber is what a "could not
 *             check" finding already wears, for the same reason.
 */
function showPolicyMessage(text, tone) {
  const box = document.getElementById("policy-message");
  box.replaceChildren();
  box.textContent = text;
  box.className = `upload-message ${tone}`;
}

/**
 * Show the business-context pane's message, in the same three tones.
 *
 * Deliberately a sibling of showPolicyMessage() rather than a generalised
 * helper taking an element id. The two panes are the same shape today and
 * there is a real chance they stop being -- this one has a fourth state the
 * policy pane does not (accepted WITH entries that could not be used), and
 * folding them together now would make that difference harder to see, not
 * easier.
 */
function showBusinessContextMessage(text, tone) {
  const box = document.getElementById("business-context-message");
  box.replaceChildren();
  box.textContent = text;
  box.className = `upload-message ${tone}`;
}

/**
 * Clear the results, and say why nothing is on screen.
 *
 * ONE FUNCTION, BOTH UPLOADS, AND THAT IS THE POINT (#82, #87).
 *     Findings on screen describe a config checked against a policy. Change
 *     EITHER and they stop describing anything that is currently staged --
 *     a new config makes them another network's results, and a new policy
 *     makes them the old rules' results. #82's argument does not depend on
 *     which of the two moved.
 *
 *     Clearing lived inline in the config upload handler until #87 needed
 *     the same behaviour. Copying it would have left two clearing paths free
 *     to drift, which is how one of them ends up quietly not clearing.
 *
 * The replacement is a neutral notice, never a loading state: nothing is
 * running, and saying otherwise is the same false claim in the other
 * direction.
 */
function clearStaleResults(reason) {
  document.getElementById("summary").replaceChildren();
  document.getElementById("findings").replaceChildren(
    el("div", "notice staged", reason)
  );
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

    const isPfSense = PFSENSE_EXTENSIONS.includes(extension);

    if (!isPfSense && !ALLOWED_EXTENSIONS.includes(extension)) {
      showUploadMessage(
        `'${name}' is not a config file we can read. Netwise accepts ` +
          `${ALLOWED_EXTENSIONS.join(", ")} files, or a PF Sense config.xml ` +
          `export.`,
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
        clearStaleResults(
          "Config staged, nothing analysed yet. Click Scan Now to check it."
        );

        // The server discards a staged policy when a new config arrives, so
        // a new network is never checked against the previous one's rules.
        // Reported here rather than left to be noticed: a user who staged a
        // policy and then a config would otherwise wonder where it went.
        if (result.policy_cleared) {
          showPolicyMessage(
            "The staged policy was cleared, because it was written for the " +
              "previous config. Upload it again if it applies to this one.",
            "warn"
          );
          document.getElementById("policy-input").value = "";
        }

        // A converted PF Sense export names every interface it could not
        // model (#78) rather than converting it silently short. Shown the
        // same way a policy loader's rename notes are: under the message,
        // never merged into the success sentence above it.
        if (result.skipped && result.skipped.length > 0) {
          addSkippedNotes(result.skipped);
        }

        // Same for the business context, and if anything the silence would
        // be worse here. A cleared policy makes checks report "could not
        // check"; a cleared context makes a severity quietly drop back one
        // level, with nothing on screen to say why. A user watching a high
        // finding become medium after uploading a config deserves the
        // sentence rather than the puzzle.
        if (result.business_context_cleared) {
          showBusinessContextMessage(
            "The staged business context was cleared, because it named " +
              "devices on the previous config. Upload it again if it " +
              "applies to this one.",
            "warn"
          );
          document.getElementById("business-context-input").value = "";
        }

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

/**
 * The policy picker (#87).
 *
 * WHAT IT DOES NOT CLAIM
 *     A staged policy is not an applied policy. The server says so in its
 *     own message and this pane repeats nothing beyond it -- the message is
 *     rendered verbatim rather than summarised, so the one place that
 *     sentence can drift is the server.
 *
 * WHY IT CLEARS THE FINDINGS
 *     Whatever is on screen was computed against the PREVIOUS policy, so it
 *     is exactly as stale as it would be after a new config. Same call, same
 *     reason -- see clearStaleResults().
 */
function setUpPolicyUpload() {
  const input = document.getElementById("policy-input");
  if (!input) return;

  input.addEventListener("change", async () => {
    const file = input.files[0];
    if (!file) return;

    const name = file.name;
    const extension = name.slice(name.lastIndexOf(".")).toLowerCase();

    // A courtesy check only. The server decides, and its answer is the one
    // that counts -- the same division of labour as the config upload.
    if (extension !== ".json") {
      showPolicyMessage(
        `'${name}' is not a policy file. A policy is .json — YAML is not ` +
          `supported yet.`,
        "bad"
      );
      input.value = "";
      return;
    }

    const body = new FormData();
    body.append("file", file);
    try {
      const response = await fetch("/api/policy", { method: "POST", body });
      const result = await response.json();

      if (!response.ok) {
        // The server's own words. PolicyError names the entry and suggests a
        // correction for an unknown key; rewording it here would lose the
        // part that makes it actionable.
        showPolicyMessage(result.detail, "bad");
        input.value = "";
        return;
      }

      showPolicyMessage(result.message, "ok");

      // Corrected legacy names, surfaced rather than swallowed. The user
      // wrote a key that no longer exists and we accepted it -- they should
      // learn that, or they will keep writing it.
      if (result.renamed && result.renamed.length) {
        addRenameNotes(result.renamed);
      }

      clearStaleResults(
        "Policy staged. Previous findings cleared — they were checked " +
          "against the old rules. Click Scan Now to check again."
      );
    } catch (error) {
      showPolicyMessage(
        `Could not upload that policy: ${error.message}. Nothing was staged.`,
        "bad"
      );
      input.value = "";
    }
  });
}

/**
 * Show the loader's rename notes under the policy message.
 *
 * textContent, never innerHTML -- these strings quote the user's own file
 * back at them, which is untrusted input arriving through a path that looks
 * like our own text.
 */
function addRenameNotes(notes) {
  const box = document.getElementById("policy-message");
  notes.forEach((note) => {
    // Its own element, so CSS can make it read as a heads-up rather than as
    // another sentence of the success message. textContent, never innerHTML:
    // these strings quote the user's own file back at them, which is
    // untrusted input arriving by a path that looks like our own text.
    const line = el("span", "rename-note", note);
    box.appendChild(line);
  });
}

/**
 * Show which interfaces a converted PF Sense export could not model (#78),
 * under the upload message. Same idiom as addRenameNotes() above -- its own
 * element per note, textContent only, reusing the same "heads-up, not a
 * second success sentence" styling rather than inventing a new one.
 *
 * Called only for a PF Sense upload with a non-empty `skipped` list --
 * see setUpUpload() below. A normal .cfg/.conf/.txt upload always returns
 * skipped: [], so there is nothing to show and this is never called for it.
 */
function addSkippedNotes(notes) {
  const box = document.getElementById("upload-message");
  notes.forEach((note) => {
    const line = el("span", "rename-note", note);
    box.appendChild(line);
  });
}

/* ------------------------------------------------------------------------ *
 * Propose a change (US-13/US-14)
 *
 * Talks to the real POST /api/propose, which landed on `main` with #183 and
 * #184 on 27 August. This pane built against it as a shell first, calling
 * the endpoint for real and falling back only on a 404 -- the one status
 * meaning "not here yet" rather than "your request was wrong". That fallback
 * is now unreachable and has been deleted rather than left as dead code
 * nobody dares remove.
 * ------------------------------------------------------------------------ */

/**
 * Render one /api/propose response.
 *
 * THE SHAPE, from ai/propose.py:
 *
 *     { request_understood: string | null,
 *       proposed_change:   {device, filter, line} | null,
 *       impact:            F-1 findings,
 *       verified:          bool,
 *       warning:           bool,
 *       grounded:          bool,
 *       answer:            string }
 *
 * TWO RULES INHERITED FROM addResponse(), FOR THE SAME REASONS
 *
 *   1. The translated request is always shown back, above everything else.
 *      ai/propose.py matches against a closed template and calls no model
 *      in either direction; that narrow scope is only SAFE, rather than
 *      merely limited, because the person who asked can read what was
 *      actually generated and say "that is not what I meant". Here it
 *      matters MORE than in the chat pane: a mistranslated question
 *      produces a wrong answer, while a mistranslated request produces a
 *      config line somebody might paste into a device.
 *
 *   2. A refusal never looks like a lesser success.
 *      `grounded !== true`, not `=== false`, so a missing or malformed key
 *      lands on the side that claims LESS -- the same cautious default the
 *      chat pane and the explanation byline both use.
 */
function addProposeResponse(result) {
  const log = document.getElementById("propose-log");
  const exchange = el("div", "exchange");

  // Shown whenever the server understood the request at all. On a refusal
  // this is null, because there is no generated line to show -- the answer
  // then carries the reason on its own.
  if (result.request_understood) {
    exchange.appendChild(el("div", "understood", result.request_understood));
  }

  const refused = result.grounded !== true;

  // THREE INDEPENDENT FACTS, NEVER FOLDED INTO ONE.
  //
  //     refused          nothing ran
  //     warning === true a high-severity OPENING was proved in the diff
  //     verified !== true some of the impact analysis could not run
  //
  // #183 made `verified` and `warning` separate booleans after review found
  // a proved opening being suppressed by an unrelated error in the same
  // diff. ANDing them here would re-create that bug in the UI after the
  // backend was fixed for it -- the same fact, lost one layer later.
  //
  // `=== true` and `!== true` both lean the cautious way, matching
  // `grounded !== true` above: a missing or malformed key must never
  // silently drop the warning, and must never silently claim verification.
  const warned = result.warning === true;

  // A NON-BOOLEAN `warning` IS NOT A "NO".
  //     `=== true` alone would render a malformed flag as silence, and
  //     silence in this pane implicitly claims "this change does not open
  //     access". That is F-4 in a boolean: "we could not determine" is not
  //     "we determined it is fine".
  //
  //     Leaning the other way (`!== false`) is no better -- it fires the
  //     warning on every malformed response, and a warning that appears
  //     regardless is one the reader learns to skip, which costs exactly
  //     the case it exists for.
  //
  //     So a malformed flag is neither warned nor ignored: it feeds the
  //     "could not fully verify" note below, which is the honest reading of
  //     a response we cannot interpret. A mutation surviving is what
  //     exposed this -- both directions passed, because every malformed
  //     case tested also had a malformed `grounded` and never reached here.
  const flagsAreUsable =
    typeof result.warning === "boolean" && typeof result.verified === "boolean";
  const unverified = result.verified !== true || !flagsAreUsable;

  if (warned) {
    exchange.appendChild(
      el(
        "div",
        "propose-warning",
        "This change opens access that is currently blocked. Read the " +
          "simulated impact below before applying it."
      )
    );
  }

  exchange.appendChild(
    el("div", `message system${refused ? " refusal" : ""}`, result.answer)
  );

  // Shown on a grounded response whose impact analysis was incomplete. Not
  // shown on a refusal: there, nothing ran at all and the answer already
  // says so, and a second "could not verify" line would imply a partial
  // result existed.
  if (!refused && unverified) {
    exchange.appendChild(
      el(
        "div",
        "propose-unverified",
        "Some of the impact analysis could not run, so this is not the " +
          "whole picture. This is not a claim that the change is safe."
      )
    );
  }

  // The generated line itself. Only ever shown when the server actually
  // produced one -- a refusal carries proposed_change: null, and inventing
  // a placeholder card for it would be showing a change that does not
  // exist.
  if (result.proposed_change) {
    exchange.appendChild(renderProposedChange(result.proposed_change));
  }

  // What the simulation actually found. Empty on a refusal, and empty on a
  // change with no detected effect -- both correctly render nothing here,
  // because the answer text already says which of the two it was.
  if (result.impact && result.impact.length) {
    exchange.appendChild(renderImpact(result.impact));
  }

  log.appendChild(exchange);

  // WHERE THE LOG SCROLLS TO IS A SAFETY DECISION HERE, NOT A NICETY.
  //     `.propose-log` is capped at 18rem and scrolls. Scrolling to the
  //     newest content -- what every other log in this app does, and what
  //     this one did -- puts the END of the exchange in view: the impact
  //     list. The warning is at the TOP of the exchange, so on any response
  //     long enough to scroll, the one element that must be read first is
  //     the one element off screen.
  //
  //     Found by rendering it in a real browser. The DOM shim has no
  //     geometry, so every assertion about the warning being "first" passed
  //     while it was, in practice, out of view.
  //
  //     So a warned response scrolls to the START of its exchange and a
  //     clean one keeps the usual behaviour. Guarded on the method existing
  //     because the test shim is not a browser.
  if (warned && typeof exchange.scrollIntoView === "function") {
    exchange.scrollIntoView({ block: "start" });
  } else {
    log.scrollTop = log.scrollHeight;
  }

  return exchange;
}

/**
 * The generated config line, shown as GENERATED and never as APPLIED.
 *
 * WHY THE REMINDER IS PERMANENT AND NOT DISMISSIBLE
 *     CLAUDE.md's non-negotiable constraint: "Netwise GENERATES and
 *     SIMULATES config changes. It must never push changes to a live
 *     device." ai/propose.py holds that end structurally -- the candidate
 *     line is written only into a throwaway copy that is deleted before the
 *     function returns, and `before_dir` is never written to.
 *
 *     What this element defends is the OTHER end: the user's belief. A
 *     monospace config line in a tool that just analysed their network
 *     reads as something that happened. The difference between "here is a
 *     line you could apply" and "here is a line that has been applied" is
 *     one word, and the consequence of getting it wrong is somebody not
 *     making a change they think they already made.
 *
 *     So the reminder is part of the card rather than a one-off notice at
 *     the top of the pane: it cannot scroll away from the line it is about,
 *     and a log with five proposals in it carries five reminders rather
 *     than one the reader passed twenty minutes ago.
 *
 * The line is `el()`-built like everything else -- it is generated text
 * containing addresses from the user's own request.
 */
function renderProposedChange(change) {
  const card = el("div", "proposed-change");

  card.appendChild(el("div", "proposed-heading", "Proposed change"));

  // Device and filter first: a line without them is not actionable, and
  // "which box, which ACL" is the first thing anyone asks.
  const where = el("div", "proposed-where");
  where.appendChild(el("span", "proposed-device", change.device));
  where.appendChild(el("span", "proposed-filter", change.filter));
  card.appendChild(where);

  card.appendChild(el("code", "proposed-line", change.line));

  // Spelled out in words, not only in colour or position -- the same
  // reasoning as the "this is not a clean result" sentence on a blind
  // finding card. A style can be overridden, missed, or read past; a
  // sentence cannot be misread.
  card.appendChild(
    el(
      "div",
      "proposed-not-applied",
      "Not applied. Netwise generated this line and simulated it against a " +
        "throwaway copy of your config — nothing has been written to any " +
        "device or to the config you uploaded."
    )
  );

  return card;
}

/**
 * The simulated impact, rendered with the EXISTING finding-card renderer.
 *
 * WHY renderFinding() AND NOT A SECOND CARD BUILDER
 *     These are ordinary F-1 findings. `analysis/change_impact.py` produced
 *     them, the pipeline validated them, and /api/propose attaches the same
 *     plain-English explanation /api/findings attaches. Building a second
 *     renderer for them would mean two places that decide what an amber
 *     "could not check" card looks like -- and the moment those two drift,
 *     one of them is showing a blind spot as something else.
 *
 *     That is not hypothetical for this pane specifically. A propose
 *     response can carry a PROVEN high-severity opening beside a check that
 *     could not run (#183: `verified` and `warning` are separate booleans
 *     precisely so one cannot swallow the other). Both of those have to
 *     render correctly, and renderFinding() is the code that already knows
 *     how -- including the "this is not a clean result" sentence on a blind
 *     card, which a hand-rolled version here would almost certainly omit.
 *
 * ORDERING MATCHES THE DASHBOARD, AND FOR THE DASHBOARD'S REASON
 *     Errors first, then found worst-first, then clean. A check that did
 *     not run is the thing most likely to mislead someone reading quickly,
 *     so it goes where it cannot be missed. Sorting the impact list by
 *     severity alone would bury a "could not verify" under three
 *     medium-severity diffs.
 */
function renderImpact(impact) {
  const box = el("div", "impact");

  box.appendChild(
    el(
      "div",
      "impact-heading",
      "Simulated impact — what changed when this line was applied to a copy"
    )
  );

  const blind = impact.filter((f) => f.status === "error");
  const problems = impact
    .filter((f) => f.status === "found")
    .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  const clean = impact.filter((f) => f.status === "none");

  // Exactly the variant/icon/badge triples renderFindings() uses, so an
  // impact card and a dashboard card of the same status are the same card.
  blind.forEach((f) => box.appendChild(renderFinding(f, "blind", "⚠", "could not check")));
  problems.forEach((f) => box.appendChild(renderFinding(f, f.severity, "●", f.severity)));
  clean.forEach((f) => box.appendChild(renderFinding(f, "clean", "✓", "checked")));

  return box;
}

function addProposeMessage(text, who) {
  const log = document.getElementById("propose-log");
  const node = el("div", `message ${who}`, text);
  log.appendChild(node);
  log.scrollTop = log.scrollHeight;
  return node;
}

function setUpProposeChange() {
  const form = document.getElementById("propose-form");
  if (!form) return;

  const input = document.getElementById("propose-input");
  const button = form.querySelector("button");

  addProposeMessage(
    "Describe one change, e.g. \"block 10.10.10.5 to 10.20.0.5 on " +
      "tcp/443 on rtr-us5\". Addresses must be written out -- a name like " +
      "\"YouTube\" is refused rather than guessed at.",
    "system"
  );

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const request = input.value.trim();
    if (!request) return;

    addProposeMessage(request, "user");
    input.value = "";

    // Locked while in flight, for a stronger version of setUpChat()'s
    // reason. /api/propose connects to Batfish, loads the snapshot, writes a
    // scratch copy and runs change_impact TWICE -- slower than /api/ask, so
    // a second submission mid-flight is likelier, not less.
    input.disabled = true;
    button.disabled = true;
    const pending = addProposeMessage(
      "Simulating the change against a copy of your config…",
      "system pending"
    );

    try {
      const response = await fetch("/api/propose", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ request }),
      });

      pending.remove();

      if (!response.ok) throw new Error(`server returned ${response.status}`);

      addProposeResponse(await response.json());
    } catch (error) {
      // Nothing was simulated, so nothing is known. Same reasoning as the
      // chat pane's catch: "could not be asked" and "was refused" are the
      // same thing to the person reading.
      pending.remove();
      addProposeMessage(
        `Could not propose that change: ${error.message}. Nothing was ` +
          `simulated, so nothing is known either way.`,
        "system refusal"
      );
    } finally {
      input.disabled = false;
      button.disabled = false;
      input.focus();
    }
  });
}

/**
 * The business-context picker (#87, risk side).
 *
 * WHAT MAKES THIS ONE DIFFERENT FROM THE POLICY PICKER
 *     A policy upload has two outcomes: accepted, or rejected. This one has
 *     THREE, and the third is the whole reason the feature needed a UI at
 *     all:
 *
 *         accepted, and every entry can be used
 *         accepted, and SOME ENTRIES CANNOT BE USED
 *         rejected
 *
 *     The middle case is a 200 with `accepted: true`. Rendered as a plain
 *     green success message it would be indistinguishable from the first --
 *     and a user who tagged their finance VLAN by subnet, read "accepted",
 *     and saw no severity move would reasonably conclude their context had
 *     been applied. That is precisely the silent failure `unusable_entries()`
 *     exists to prevent, and it would be re-created here, one layer up, by
 *     showing green.
 *
 *     So an accepted context with unusable entries is AMBER, not green, and
 *     each unusable entry is named. Amber is what a "could not check"
 *     finding already wears, for the identical reason: nothing failed, and
 *     you still need to know.
 *
 * WHY IT CLEARS THE FINDINGS
 *     Whatever is on screen was scored WITHOUT this context. Same staleness
 *     as a new policy, same call -- see clearStaleResults().
 */
function setUpBusinessContextUpload() {
  const input = document.getElementById("business-context-input");
  if (!input) return;

  input.addEventListener("change", async () => {
    const file = input.files[0];
    if (!file) return;

    const name = file.name;
    const extension = name.slice(name.lastIndexOf(".")).toLowerCase();

    // A courtesy check only. The server decides, and its answer is the one
    // that counts -- the same division of labour as the other two pickers.
    if (extension !== ".json") {
      showBusinessContextMessage(
        `'${name}' is not a business context file. A business context ` +
          `is .json.`,
        "bad"
      );
      input.value = "";
      return;
    }

    const body = new FormData();
    body.append("file", file);
    try {
      const response = await fetch("/api/business-context", {
        method: "POST",
        body,
      });
      const result = await response.json();

      if (!response.ok) {
        // The server's own words. BusinessContextError names the entry and
        // suggests a correction for a miscased tier; rewording it here would
        // lose the part that makes it actionable.
        showBusinessContextMessage(result.detail, "bad");
        input.value = "";
        return;
      }

      // The tone is decided by whether anything was unusable, NOT by the
      // status code. Both are 200. See this function's docstring.
      const unusable = result.unusable || [];
      showBusinessContextMessage(result.message, unusable.length ? "warn" : "ok");
      if (unusable.length) {
        addUnusableNotes(unusable);
      }

      clearStaleResults(
        "Business context staged. Previous findings cleared — they were " +
          "scored without it. Click Scan Now to check again."
      );
    } catch (error) {
      showBusinessContextMessage(
        `Could not upload that business context: ${error.message}. ` +
          `Nothing was staged.`,
        "bad"
      );
      input.value = "";
    }
  });
}

/**
 * Name the entries that were accepted but cannot affect any finding.
 *
 * A HEADING FIRST, THEN THE ENTRIES
 *     The server's notes each explain one entry. Without a line saying what
 *     they collectively mean, three of them read as three separate oddities
 *     rather than as "part of your file did nothing".
 *
 * textContent, never innerHTML -- these strings quote the user's own file
 * back at them, which is untrusted input arriving through a path that looks
 * like our own text. Same rule as addRenameNotes(), and the same reason.
 */
function addUnusableNotes(notes) {
  const box = document.getElementById("business-context-message");

  box.appendChild(
    el(
      "span",
      "unusable-heading",
      notes.length === 1
        ? "1 entry was accepted but did not apply to anything:"
        : `${notes.length} entries were accepted but did not apply to anything:`
    )
  );

  notes.forEach((note) => {
    box.appendChild(el("span", "unusable-note", note));
  });
}

/* ------------------------------------------------------------------------ */
loadFindings();
setUpUpload();
setUpPolicyUpload();
setUpBusinessContextUpload();
setUpChat();
setUpProposeChange();
