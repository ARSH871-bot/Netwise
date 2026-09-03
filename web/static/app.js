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
    if (finding.explanation_notice) {
      card.appendChild(
        el("p", "model-boundary-notice", finding.explanation_notice)
      );
    }
  }

  // Remediation -- what to CHANGE, not what is wrong (#221). A different
  // claim from the explanation above, so its own block with its own byline
  // rather than an extra sentence tacked onto .ai-explanation -- the same
  // "different claims stay honestly separate" discipline #109 established
  // for model vs. fallback.
  //
  // NEVER MODEL-WRITTEN. web/main.py's _attach_remediation() only ever
  // calls ai.explain.remediate_with_source(), which never touches Ollama --
  // every string it can produce is built from a regex-captured piece of
  // evidence.detail a check already produced. So there is no "model" vs.
  // "fallback" distinction to make here the way explanation has one; the
  // byline says "deterministic" because that is the only thing it could
  // honestly say.
  //
  // ABSENT ON A "found" CARD IS NOT SILENCE, THE SAME REASONING #31 GIVES
  // EXPLANATION.
  //     Most found findings do not match one of the three shapes
  //     remediate_with_source() knows -- silence here would read as
  //     "nothing to add" when the true state is "no mechanical suggestion
  //     is available for this one". So a found finding with no remediation
  //     says so in words, the same instinct behind `.no-explanation`-style
  //     states elsewhere in this file.
  if (variant !== "blind" && variant !== "clean") {
    if (finding.remediation) {
      card.appendChild(
        el("div", "remediation", finding.remediation)
      );
    } else {
      card.appendChild(
        el(
          "p",
          "no-remediation",
          "No mechanical remediation is available for this finding yet."
        )
      );
    }
  }

  // Spell it out in words as well as colour. An amber card is a signal; a
  // sentence saying "this is not a clean result" cannot be misread.
  if (variant === "blind") {
    card.appendChild(
      el(
        "p",
        "blind-warning",
        "This is not a clean result -- this check did not run, so nothing is known here."
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
  //
  // EACH TILE CARRIES ITS OWN ONE-LINE DEFINITION.
  //     The paragraph above the tiles explains all three together, and it
  //     stays -- but a reader looking at "5 / 0 / 1" is looking at the
  //     BOXES, and an explanation they have to glance back up to is one
  //     they skip. Reported from real use: the three numbers read as though
  //     they should relate to each other.
  //
  //     The three captions are deliberately PARALLEL --
  //     "ran and found ... / ran and found nothing ... / did not run" --
  //     because the distinction being missed is precisely whether the check
  //     ran at all, and putting the three in the same grammatical shape is
  //     what makes that comparable at a glance.
  //
  //     THE THIRD ONE NEVER RELIES ON COLOUR. Amber is the signal, but the
  //     words carry the whole claim on their own: "did not run" and
  //     "nothing is known" say it for anyone who cannot see the border,
  //     is reading a screenshot in greyscale, or has the page printed.
  //     Same F-4 discipline as the "this is not a clean result" sentence on
  //     the blind finding cards.
  const tiles = [
    [
      "problems",
      problems.length,
      "problems found",
      "The check ran and found a real issue",
    ],
    [
      "clean",
      clean.length,
      "checked, nothing found",
      "The check ran and found nothing wrong",
    ],
    [
      "blind",
      blind.length,
      "could not check",
      "The check did not run -- nothing is known",
    ],
  ];

  tiles.forEach(([variant, count, label, caption]) => {
    const tile = el("div", `tile ${variant}`);
    tile.appendChild(el("div", "count", String(count)));
    tile.appendChild(el("div", "label", label));
    tile.appendChild(el("div", "caption", caption));
    summary.appendChild(tile);
  });
}

/** Render the whole findings list, grouped by status. */
/* ------------------------------------------------------------------------ *
 * Filter by device (#219)
 *
 * A view over findings already fetched. Every finding carries `device`, so
 * nothing here asks the server anything -- there is no second source of
 * truth about what the scan found.
 *
 * THE LAST RENDERED LIST IS KEPT so changing the selector can re-render
 * without a round trip. It is the findings as the server sent them, never a
 * filtered copy: filtering a filtered list would narrow it further on every
 * change and there would be no way back to "all".
 * ------------------------------------------------------------------------ */

let allFindings = [];

/** Distinct devices in a findings list, in first-seen order. */
function devicesIn(findings) {
  const seen = [];
  findings.forEach((f) => {
    if (f.device && !seen.includes(f.device)) seen.push(f.device);
  });
  return seen;
}

/** The device currently selected, or "" for all of them. */
function selectedDevice() {
  const select = document.getElementById("device-filter");
  return select ? select.value || "" : "";
}

/**
 * Fill the selector, and hide it unless there is a real choice to make.
 *
 * HIDDEN AT ONE DEVICE, NOT DISABLED. A disabled control still asks the
 * reader to notice it and work out why it cannot be used. With one device
 * there is nothing to choose, and the honest presentation of no choice is
 * no control -- the same reasoning as not rendering an empty section.
 *
 * The chosen device is preserved across re-renders when it is still
 * present, so a rescan does not silently throw the reader back to "all"
 * and show them findings they had deliberately filtered away.
 */
function updateDeviceFilter(findings) {
  const row = document.getElementById("device-filter-row");
  const select = document.getElementById("device-filter");
  if (!row || !select) return;

  const devices = devicesIn(findings);
  const previous = select.value || "";

  select.replaceChildren();
  select.appendChild(el("option", "", `All devices (${findings.length})`)).value = "";
  devices.forEach((device) => {
    const count = findings.filter((f) => f.device === device).length;
    const option = el("option", "", `${device} (${count})`);
    option.value = device;
    select.appendChild(option);
  });

  // Keep the reader's choice only if it still exists in these results.
  select.value = devices.includes(previous) ? previous : "";

  row.hidden = devices.length < 2;

  // A HIDDEN CONTROL MUST NOT LEAVE A FILTER ON.
  //     Found by the harness: filter to rtr-us5 on a multi-device scan,
  //     then rescan a single-device one. The device is still present, so
  //     the choice was preserved -- while the control hid itself, because
  //     there is now only one device. The result was an active filter with
  //     no visible way to clear it, and a "0 finding(s) hidden" notice
  //     explaining a control the reader cannot see.
  //
  //     Harmless in effect, since with one device the filter selects
  //     everything. Incoherent as a state, and the kind of thing that
  //     becomes a real bug the moment anything else reads the selector.
  if (row.hidden) select.value = "";
}

/** The subset the reader is currently looking at. */
function visibleFindings() {
  const device = selectedDevice();
  return device ? allFindings.filter((f) => f.device === device) : allFindings;
}

/**
 * Say what the filter is hiding, and how much of it could not be checked.
 *
 * THIS IS THE F-4 PROBLEM ARRIVING THROUGH A VIEW CONTROL.
 *     Filtering to one device hides findings about the others -- including
 *     `status="error"` ones. A reader who filters to rtr-us5, sees a green
 *     summary, and forgets the selector is set has been shown "all clear"
 *     for a network where a check never ran. The summary tiles are honest
 *     about what they count; they cannot be honest about what is not in
 *     front of them.
 *
 *     So a filtered view states the hidden count, and states the
 *     could-not-check part of it separately, because those are the two
 *     different claims F-4 exists to keep apart. It carries the amber
 *     "could not check" tokens when a blind spot is among the hidden, and
 *     the neutral note otherwise.
 *
 * Nothing is shown when no filter is active -- there is nothing hidden to
 * disclose, and a permanent "0 hidden" line is noise that teaches the
 * reader to skip this element.
 */
function renderFilterNotice(device) {
  const notice = document.getElementById("filter-notice");
  if (!notice) return;

  notice.replaceChildren();
  if (!device) {
    notice.textContent = "";
    notice.className = "filter-notice";
    notice.hidden = true;
    return;
  }

  const hidden = allFindings.filter((f) => f.device !== device);
  const blind = hidden.filter((f) => f.status === "error").length;

  let text =
    `Showing ${device} only. ` +
    `${hidden.length} finding(s) about other devices are hidden`;
  text += blind
    ? `, including ${blind} that could not be checked.`
    : ".";

  notice.textContent = text;
  // Amber only when a blind spot is among the hidden. Using it always would
  // make the colour mean "a filter is on" rather than "something is not
  // known", which is the distinction it carries everywhere else here.
  notice.className = blind ? "filter-notice blind" : "filter-notice";
  notice.hidden = false;
}

/** Re-render from the stored findings, honouring the selector. */
function applyDeviceFilter() {
  const device = selectedDevice();
  renderFilterNotice(device);
  renderFindingSections(visibleFindings());
}

function renderFindings(findings) {
  allFindings = findings;
  updateDeviceFilter(findings);
  renderFilterNotice(selectedDevice());
  renderFindingSections(visibleFindings());

  // A real scan's own findings, not a comparison -- close out any
  // comparison view left open from a previous proposal. Without this, a
  // fresh upload after viewing a comparison would show new findings under
  // a banner still describing an old, unrelated proposed change.
  const banner = document.getElementById("comparison-banner");
  if (banner) banner.hidden = true;
  const explainer = document.getElementById("results-explainer");
  if (explainer) explainer.hidden = false;
  const summaryEl = document.getElementById("summary");
  if (summaryEl) summaryEl.classList.remove("comparison-mode");
  const findingsEl = document.getElementById("findings");
  if (findingsEl) findingsEl.classList.remove("comparison-mode");
}

/* ------------------------------------------------------------------------ *
 * Before/after comparison for a proposed change (strengthening propose)
 *
 * WHY THIS EXISTS, AND WHY IT LIVES HERE RATHER THAN IN THE PROPOSE PANE
 *     A full scan of a proposed config answers a narrower question than the
 *     one anyone actually asks: not "what does the proposed config look
 *     like" but "what does this CHANGE do to what I already know about my
 *     network". That is a before/after comparison, and this panel -- with
 *     its tiles, its sections, its device-aware finding cards -- is already
 *     the UI built to show a set of findings clearly. Building a second,
 *     smaller copy of it inside the narrow propose pane would be worse on
 *     every axis that panel already got right.
 *
 * NEVER KEYED BY finding.id, THE SAME RULE EVERY OTHER PART OF THIS FILE
 * FOLLOWS.
 *     id is not guaranteed stable or unique across two separate runs of the
 *     pipeline (see the "SECOND RULE" comment near the top of this file).
 *     Two findings are "the same finding" here if they agree on WHAT was
 *     found, not on which number the pipeline happened to assign it.
 * ------------------------------------------------------------------------ */

/** A stable identity for one finding, for comparing two separate scans --
 * never `finding.id`, see the block comment above. */
function findingIdentity(finding) {
  return `${finding.check}|${finding.device}|${finding.status}|${finding.summary}`;
}

/**
 * Split `after` against `before` into three buckets:
 *   introduced  in after, not in before -- a NEW problem this change causes
 *   resolved    in before, not in after -- a problem this change FIXES
 *   unchanged   in both -- present either way, this change did not move it
 *
 * Deliberately simple set comparison, not a smarter fuzzy match. A finding
 * that changed severity or evidence but kept the same summary reads as
 * "unchanged" here -- correct, because the CLAIM (what was found, on what,
 * by what check) is what a reader means by "the same problem", not the
 * exact bytes of its evidence string.
 */
function diffFindings(before, after) {
  const beforeKeys = new Set(before.map(findingIdentity));
  const afterKeys = new Set(after.map(findingIdentity));

  return {
    introduced: after.filter((f) => !beforeKeys.has(findingIdentity(f))),
    resolved: before.filter((f) => !afterKeys.has(findingIdentity(f))),
    unchanged: after.filter((f) => beforeKeys.has(findingIdentity(f))),
  };
}

/** Render the three comparison tiles -- same shape as renderSummary(),
 * different claim: not "what is true", but "what changed". */
function renderComparisonSummary(introduced, resolved, unchanged) {
  const summary = document.getElementById("summary");
  summary.replaceChildren();

  const tiles = [
    ["problems", introduced.length, "new problems this change introduces"],
    ["clean", resolved.length, "problems this change fixes"],
    ["blind", unchanged.length, "unaffected -- true either way"],
  ];

  tiles.forEach(([variant, count, label]) => {
    const tile = el("div", `tile ${variant}`);
    tile.appendChild(el("div", "count", String(count)));
    tile.appendChild(el("div", "label", label));
    summary.appendChild(tile);
  });
}

/**
 * Show a before/after comparison in the main results panel, and remember
 * how to get back. `description` is the plain-English request that was
 * understood, shown in the banner so the comparison is never mistaken for
 * the reader's own uploaded config.
 */
function showComparison(afterFindings, description) {
  const { introduced, resolved, unchanged } = diffFindings(allFindings, afterFindings);

  document.getElementById("results-explainer").hidden = true;
  const filterRow = document.getElementById("device-filter-row");
  if (filterRow) filterRow.hidden = true;
  document.getElementById("filter-notice").hidden = true;

  const banner = document.getElementById("comparison-banner");
  document.getElementById("comparison-banner-text").textContent =
    `COMPARISON -- not your uploaded config. Proposed change: ${description}`;
  banner.hidden = false;

  // The normal report links point at /api/report, which serves the
  // READER'S OWN scan -- never what a comparison is showing. Left enabled,
  // clicking "Download this report" while looking at a comparison would
  // silently download something that does not match the screen at all.
  // The comparison gets its own download further down instead.
  setDownloadAvailable(
    false,
    "Not available for a comparison -- use the buttons below, or go back " +
      "to your own scan first."
  );

  // A dashed border on both containers, on for as long as the comparison
  // is on screen -- one visual signal that survives a glance, not just the
  // banner text, so this can never be mistaken for a real scan even by
  // someone scrolled past the top of the panel.
  document.getElementById("summary").classList.add("comparison-mode");
  document.getElementById("findings").classList.add("comparison-mode");

  renderComparisonSummary(introduced, resolved, unchanged);

  const container = document.getElementById("findings");
  container.replaceChildren();

  const sections = [
    renderSection(
      "New problems this change introduces",
      "Not present in your uploaded config -- caused by this specific change.",
      introduced.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]),
      (f) => renderFinding(f, f.severity, "●", f.severity)
    ),
    renderSection(
      "Problems this change fixes",
      "Present in your uploaded config, gone after this change.",
      resolved.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]),
      (f) => renderFinding(f, f.severity, "●", f.severity)
    ),
  ];
  sections.filter(Boolean).forEach((s) => container.appendChild(s));

  // Unaffected findings are not rendered as cards -- every one of them is
  // already visible in the reader's own scan, unchanged, and repeating
  // that whole list here would bury the two sections that actually answer
  // the question this view exists for. The count above already discloses
  // how many there are; nothing here is hidden, only not repeated.
  if (unchanged.length) {
    container.appendChild(
      el(
        "p",
        "comparison-unchanged-note",
        `${unchanged.length} other finding(s) are unaffected -- true whether ` +
          `or not this change is made. See your own scan results for those.`
      )
    );
  }

  container.appendChild(
    renderComparisonDownload(introduced, resolved, unchanged.length, description)
  );
}

/**
 * Download the comparison itself, HTML or CSV -- two real forms, same "the
 * browser handles it natively" reasoning as every other download on this
 * page. Posts the EXACT introduced/resolved/unchanged split already on
 * screen, not a re-request for the server to recompute -- see
 * POST /api/propose/comparison-report's own docstring for why: a full
 * scan is real seconds-to-minutes of work, and the data to render a
 * report of it is already sitting right here.
 */
function renderComparisonDownload(introduced, resolved, unchangedCount, description) {
  const wrap = el("div", "comparison-download-wrap");
  wrap.appendChild(el("div", "comparison-download-label", "Download this comparison"));

  const row = el("div", "comparison-download-row");
  const payload = JSON.stringify({
    introduced,
    resolved,
    unchanged_count: unchangedCount,
    description,
  });

  [["html", "HTML"], ["csv", "CSV"]].forEach(([format, label]) => {
    const form = el("form", "comparison-download-form");
    form.method = "post";
    form.action = "/api/propose/comparison-report";
    form.target = "_blank";

    const findingsField = document.createElement("input");
    findingsField.type = "hidden";
    findingsField.name = "findings_json";
    findingsField.value = payload;
    form.appendChild(findingsField);

    const formatField = document.createElement("input");
    formatField.type = "hidden";
    formatField.name = "format";
    formatField.value = format;
    form.appendChild(formatField);

    const button = document.createElement("button");
    button.type = "submit";
    button.className = "comparison-download-button";
    button.textContent = label;
    form.appendChild(button);

    row.appendChild(form);
  });

  wrap.appendChild(row);
  return wrap;
}

/** Restore the panel to the reader's own scan -- allFindings was never
 * touched, so this is a re-render, not a re-fetch. */
function hideComparison() {
  // The normal report links describe the reader's own scan again the
  // moment this view goes away -- loadFindings() would set this too, but
  // going "back" is a re-render of allFindings, not a re-fetch, so nothing
  // else would restore it.
  setDownloadAvailable(
    true,
    "Downloads what is shown above. The report states what it describes."
  );

  // renderFindings() itself closes the banner and restores the explainer --
  // see the comment there. Calling it with the SAME list it already holds
  // is a re-render, not a re-fetch: allFindings was never touched by
  // showComparison() in the first place.
  renderFindings(allFindings);
}

function renderFindingSections(findings) {
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
      "Checked -- nothing found",
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
/** Show or hide the "this is demo data" notice -- read from the response
 * header /api/findings sets, never guessed at from the findings themselves.
 * A header, not a body field, so this stays a pure presentation decision
 * layered on top of the exact same F-1 list every other caller already
 * expects -- see get_findings()'s own docstring in web/main.py. */
function setMockDataNotice(isMock) {
  const notice = document.getElementById("mock-data-notice");
  if (notice) notice.hidden = !isMock;
}

async function loadFindings() {
  const container = document.getElementById("findings");
  try {
    const response = await fetch("/api/findings");
    if (!response.ok) throw new Error(`server returned ${response.status}`);
    setMockDataNotice(response.headers.get("X-Netwise-Mock-Data") === "true");
    renderFindings(await response.json());

    // Findings are on screen, so there is something to export.
    //
    // Set HERE and not inside renderFindings(), which is a pure renderer of
    // its own container and should stay one. Reaching out of it to mutate an
    // unrelated control coupled every caller to the report links -- measured,
    // it broke 84 tests across four DOM harnesses that have no reason to
    // model a download button. Worth recording: the first version did that,
    // and the harnesses were right to object.
    setDownloadAvailable(
      true,
      "Downloads what is shown above. The report states what it describes."
    );
  } catch (error) {
    document.getElementById("summary").replaceChildren();
    container.replaceChildren(
      el(
        "div",
        "notice",
        `Could not load findings: ${error.message}. This is not a clean ` +
          `result -- no analysis has been shown. Is the server running?`
      )
    );

    // The third path with nothing on screen, and the one most worth
    // guarding: the notice above says explicitly that no analysis has been
    // shown, and an available Download button beside it would contradict
    // that sentence.
    setDownloadAvailable(
      false,
      "Nothing to export -- the findings could not be loaded."
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

  // Nothing on screen means nothing to export. Without this, the control
  // would stay available over a cleared pane and a click would start a real
  // analysis to produce a report of results nobody has seen.
  setDownloadAvailable(
    false,
    "Nothing to export yet -- click Scan Now to check the staged config."
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
          `are normally well under this -- is this definitely a config file?`,
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
        `'${name}' is not a policy file. A policy is .json -- YAML is not ` +
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
        "Policy staged. Previous findings cleared -- they were checked " +
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
function addProposeResponse(result, requestText) {
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
    exchange.appendChild(renderProposedChange(result.proposed_change, requestText));
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
/**
 * The affected filter, before and after, as a single ordered list -- every
 * line from `after`, with the ones that were not already in `before` marked
 * as added. Answers "what does this actually change" the way a bare
 * generated line cannot: a line in isolation says nothing about where it
 * lands or what it sits beside.
 *
 * COUNTS OCCURRENCES, NOT JUST MEMBERSHIP. Two rules that happen to read
 * identically both count once each -- `before.filter(x => x === line).length`
 * decremented per match, not `.includes()` -- so a config that already
 * contains the exact text of the generated line does not get it marked
 * "added" by mistake.
 *
 * Returns null if either list is empty, so a config `_acl_body_lines()`
 * could not parse degrades to no diff shown rather than a false one, and
 * the caller falls back to the bare line it already rendered.
 */
function renderAclDiff(beforeLines, afterLines) {
  if (!beforeLines || !afterLines || afterLines.length === 0) return null;

  const remaining = beforeLines.slice();
  const list = el("ul", "acl-diff");
  afterLines.forEach((line) => {
    const seenIndex = remaining.indexOf(line);
    const isNew = seenIndex === -1;
    if (!isNew) remaining.splice(seenIndex, 1);
    const item = el("li", isNew ? "acl-diff-line added" : "acl-diff-line", line);
    if (isNew) {
      item.appendChild(el("span", "acl-diff-tag", "added"));
    }
    list.appendChild(item);
  });
  return list;
}

/**
 * A real HTML form posting to /api/propose/download, opened in a new tab.
 * Not fetch + Blob -- same reasoning as the report-download links elsewhere
 * on this page: a native submission lets the browser handle the file
 * (Content-Disposition) on its own, with no object URL to build or revoke.
 *
 * `requestText` travels as a hidden field's VALUE, a DOM property
 * assignment rather than a string built into markup -- the same
 * textContent-not-innerHTML discipline el() uses, applied to a value
 * instead of a text node, so a request containing quotes or angle brackets
 * can never break out of the form.
 */
function renderProposeDownload(requestText) {
  const form = el("form", "propose-download-form");
  form.method = "post";
  form.action = "/api/propose/download";
  form.target = "_blank";

  const hidden = document.createElement("input");
  hidden.type = "hidden";
  hidden.name = "request";
  hidden.value = requestText;
  form.appendChild(hidden);

  const button = document.createElement("button");
  button.type = "submit";
  button.className = "propose-download-button";
  button.textContent = "Download this config with the change applied";
  form.appendChild(button);

  return form;
}

/**
 * The proposed change card, in three visually separate groups rather than
 * one long stack -- WHAT CHANGES, then the not-applied guarantee on its
 * own line where it cannot be lost among the other text, then WHAT YOU CAN
 * DO with it. Each group carries a small-caps label, the same convention
 * .proposed-heading already uses one level up, so the eye can find "which
 * part is this" without reading every line.
 */
function renderProposedChange(change, requestText) {
  const card = el("div", "proposed-change");

  card.appendChild(el("div", "proposed-heading", "Proposed change"));

  // --- Group 1: what changes -----------------------------------------
  const whatChanges = el("div", "pc-group pc-what");

  const where = el("div", "proposed-where");
  where.appendChild(el("span", "proposed-device", change.device));
  where.appendChild(el("span", "proposed-filter", change.filter));
  whatChanges.appendChild(where);

  whatChanges.appendChild(el("code", "proposed-line", change.line));

  // The full filter, before and after, not just the one generated line --
  // see renderAclDiff()'s own docstring. Absent rather than guessed if the
  // backend could not extract the block; the bare line above still stands
  // on its own either way.
  const diff = renderAclDiff(change.before_lines, change.after_lines);
  if (diff) {
    whatChanges.appendChild(
      el("div", "acl-diff-label", `${change.filter}, with this change:`)
    );
    whatChanges.appendChild(diff);
  }
  card.appendChild(whatChanges);

  // --- Group 2: the safety guarantee, alone, between the two groups it
  // separates. Spelled out in words, not only in colour or position -- the
  // same reasoning as the "this is not a clean result" sentence on a blind
  // finding card. A style can be overridden, missed, or read past; a
  // sentence cannot be misread.
  card.appendChild(
    el(
      "div",
      "proposed-not-applied",
      "Not applied. Netwise generated this line and simulated it against a " +
        "throwaway copy of your config -- nothing has been written to any " +
        "device or to the config you uploaded."
    )
  );

  // --- Group 3: what you can do with it -------------------------------
  // Offered only when there is a real request to resubmit.
  if (requestText) {
    const actions = el("div", "pc-group pc-actions");
    actions.appendChild(el("div", "pc-actions-label", "What you can do next"));
    const row = el("div", "pc-actions-row");
    row.appendChild(renderProposeDownload(requestText));
    row.appendChild(renderFullScanButton(requestText));
    actions.appendChild(row);
    card.appendChild(actions);
  }

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
function renderImpact(
  impact,
  heading = "Simulated impact -- what changed when this line was applied to a copy"
) {
  const box = el("div", "impact");

  box.appendChild(el("div", "impact-heading", heading));

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

/**
 * "Run a full scan against this proposed config" -- the recommended
 * strengthening. propose_change()'s own impact list only ever proves
 * change_impact's narrow before/after diff; this runs every check
 * (access_control, routing, policy_compliance) against the exact config
 * the change would produce, the same way manually downloading it and
 * uploading it as a new scan already does today, without the round trip.
 *
 * A REAL FETCH, NOT A FORM -- unlike renderProposeDownload() beside it.
 * This result is rendered INLINE on the same page, not saved as a file, so
 * there is no download for the browser to hand off and no reason to avoid
 * fetch here the way the download button does.
 *
 * ONE RUN PER CLICK, NOT PER KEYSTROKE OR PER RENDER. This is deliberately
 * NOT called automatically when the proposed-change card first renders --
 * see /api/propose/full-scan's own docstring for why it is a second,
 * explicit click rather than a cost folded into the button everyone
 * already uses.
 */
function renderFullScanButton(requestText) {
  const wrap = el("div", "full-scan-wrap");
  const button = document.createElement("button");
  button.type = "button";
  button.className = "full-scan-button";
  button.textContent = "Run a full scan against this proposed config";
  wrap.appendChild(button);

  const results = el("div", "full-scan-results");
  wrap.appendChild(results);

  button.addEventListener("click", async () => {
    button.disabled = true;
    const originalLabel = button.textContent;
    button.textContent = "Scanning every check against the proposed config…";
    results.replaceChildren();

    try {
      const response = await fetch("/api/propose/full-scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ request: requestText }),
      });
      if (!response.ok) throw new Error(`server returned ${response.status}`);
      const result = await response.json();

      // Re-fetch the CURRENT baseline rather than trust allFindings to
      // still be accurate. allFindings is set by the last render of the
      // reader's own scan, and nothing forces "Scan Now" to have been the
      // most recent action before this button is clicked -- a stale
      // in-memory baseline here would make the comparison compare against
      // the wrong "before" without any error to show for it. This costs
      // one extra fast request against results already sitting in the
      // server-side cache; correctness is worth more than saving it.
      if (result.grounded === true) {
        const baselineResponse = await fetch("/api/findings");
        if (baselineResponse.ok) {
          allFindings = await baselineResponse.json();
        }
      }

      // grounded !== true, not === false -- the same cautious-default
      // reasoning every other flag on this page already follows: a
      // missing or malformed key must land on the side that claims LESS.
      if (result.grounded !== true) {
        results.appendChild(el("div", "full-scan-refusal", result.answer));
      } else {
        // Shown in the MAIN results panel, not here -- see showComparison()
        // for why a before/after comparison belongs in the panel that
        // already has tiles, sections and a device-aware finding renderer,
        // not a second, smaller copy of that UI in this narrow pane.
        showComparison(result.findings || [], requestText);
        results.appendChild(
          el(
            "div",
            "full-scan-clean",
            "Comparison ready -- see the Scan results panel on the left."
          )
        );
      }
    } catch (error) {
      results.appendChild(
        el(
          "div",
          "full-scan-refusal",
          `Could not run the full scan: ${error.message}. Nothing was ` +
            `checked, so nothing is known either way.`
        )
      );
    } finally {
      button.disabled = false;
      button.textContent = originalLabel;
    }
  });

  return wrap;
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

      addProposeResponse(await response.json(), request);
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
        "Business context staged. Previous findings cleared -- they were " +
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

/* ------------------------------------------------------------------------ *
 * Download the report (#222, backend from #233)
 *
 * The download itself is the browser's. `GET /api/report` returns
 * `Content-Disposition: attachment`, so following the link IS the download --
 * there is no fetch here, no Blob, and no object URL that has to be revoked
 * on a path somebody will eventually forget.
 *
 * So what is this function for? Exactly one thing: STOPPING the navigation
 * while the control is unavailable. An anchor has no `disabled` attribute,
 * so without a handler an aria-disabled link is still a working link -- it
 * would look unavailable and download anyway, which is worse than either
 * honest state.
 * ------------------------------------------------------------------------ */

/** The two report links, in one place so nothing has to list ids twice. */
function reportLinks() {
  return [
    document.getElementById("report-html"),
    document.getElementById("report-csv"),
  ].filter(Boolean);
}

/**
 * Make the report links available, or not, and say which in words.
 *
 * DRIVEN BY WHAT IS ON SCREEN, NOT BY WHETHER A CONFIG IS STAGED.
 *     The two are different, and the gap between them is the state worth
 *     guarding. After an upload but before Scan Now, a config IS staged and
 *     the findings pane deliberately shows nothing -- #82 cleared it so a
 *     staged file could never be confused with a checked one. Following the
 *     link in that state would start a real Batfish analysis nobody asked
 *     for and hand back a report describing results the screen has never
 *     shown.
 *
 *     So availability tracks loadFindings() -- both its success and its
 *     failure path -- and clearStaleResults(). Those are the places that
 *     already decide whether findings exist, so there is no third source
 *     of truth to drift out of step with them.
 *
 * THE HINT CHANGES WITH IT, because a greyed control with no explanation is
 * a puzzle. Same reasoning as the disabled Scan Now button, which this
 * borrows its colour from.
 */
function setDownloadAvailable(available, reason) {
  reportLinks().forEach((link) => {
    // Set to "false" rather than removed. An absent attribute also reads as
    // available to the click guard, but leaving it present means the state
    // is legible in the DOM either way -- and a screen reader announces the
    // change rather than an attribute quietly vanishing.
    link.setAttribute("aria-disabled", available ? "false" : "true");
  });

  const hint = document.getElementById("report-hint");
  if (hint) {
    hint.textContent = reason;
  }
}

function setUpReportDownload() {
  reportLinks().forEach((link) => {
    link.addEventListener("click", (event) => {
      // getAttribute, not a property: `aria-disabled` is an attribute and
      // reading `link.ariaDisabled` is not supported everywhere this has to
      // run. Compared to the string "true" so that a missing attribute, or
      // any other value, means AVAILABLE -- the state that does nothing
      // surprising. A control that silently stopped working because an
      // attribute was misspelled would be the harder failure to notice.
      if (link.getAttribute("aria-disabled") === "true") {
        event.preventDefault();
      }
    });
  });
}

function setUpDeviceFilter() {
  const select = document.getElementById("device-filter");
  if (!select) return;
  select.addEventListener("change", applyDeviceFilter);
}

function setUpComparisonBanner() {
  const button = document.getElementById("comparison-back-button");
  if (!button) return;
  button.addEventListener("click", hideComparison);
}

/* ------------------------------------------------------------------------ */
loadFindings();
setUpUpload();
setUpPolicyUpload();
setUpBusinessContextUpload();
setUpChat();
setUpProposeChange();
setUpReportDownload();
setUpDeviceFilter();
setUpComparisonBanner();
