"""ONE source for the Phase 3 backlog. It writes the document AND creates the
issues, so the two cannot disagree.

That is not tidiness. This project's recurring defect -- named in CLAUDE.md,
in the final report, and in three separate post-mortems -- is one fact recorded
in two places with only one of them updated. A backlog written in a document
and then retyped into GitHub is that defect with a fresh coat of paint. So the
stories live here once, and both artefacts are generated.

WHERE THE STORIES COME FROM
    US-20..US-39  Discussion #296, unchanged. They were designed, argued and
                  never turned into work. Their acceptance criteria are copied
                  from the discussion rather than rewritten, so anyone who
                  reviewed the discussion has already reviewed the issue.
    US-40..US-56  New. Each closes a gap a paying customer hits in the first
                  week, or one a buyer's security review asks about and we
                  currently cannot answer. Nothing is here because it sounds
                  impressive.

WHAT IS DELIBERATELY NOT CREATED
    Three stories already exist as issues. Creating them again would be the
    duplicate-fact defect committed by the script written to avoid it:
        US-28  ->  #78    the client's real pfSense export
        US-53  ->  #220   one real compliance benchmark pack (CIS Cisco IOS)
        US-57  ->  #308   coverage on every surface or none
    They are folded into the milestone instead, keeping their history.

THE SPLIT, STATED RATHER THAN ARRANGED
    Arsh asked for the other three to carry small slices so the critical path
    stays short. That is a legitimate call for a SCRUM Master. It is made in
    the open: this file says so, the milestone says so, the document says so,
    and #249 -- where Arsh published his own over-authorship as a fairness
    problem -- gets a comment recording that the ratio is being widened on
    purpose and what it costs.
"""
import json
import pathlib
import re
import subprocess
import sys

REPO = "ARSH871-bot/Netwise"
DOC = (pathlib.Path(__file__).resolve().parent.parent
       / "docs" / "design" / "phase-3-backlog.md")
NUMBERS = DOC.with_suffix(".issues.json")
MILESTONE = "Phase 3 - market readiness"
A, N, S, K = "ARSH871-bot", "patelankeet2", "shubhamkataria2005", "SamikaPerera"
NAME = {A: "Arsh", N: "Ankeet", S: "Shubham", K: "Samika"}

# id, title, story, [acceptance], why, assignee, epic, size, refs
STORIES = [
 # ------------------------------------------------------------ from #296 ----
 ("US-20", "Check my configs in CI, before the change merges",
  "As a network engineer, I want Netwise to run in my pipeline and fail the "
  "build when a change introduces a high-severity finding, so a bad rule never "
  "reaches a device.",
  ["`python -m netwise check <dir>` exits non-zero when a `found` finding is at "
   "or above a configurable severity, zero otherwise",
   "`--format json` writes the F-1 findings to stdout unchanged",
   "A `status=\"error\"` finding fails the build by default -- *we could not "
   "check* must never be a silent pass in automation",
   "Documented as a GitHub Actions snippet in `README.md`"],
  "Turns the tool from something you remember to run into something that runs "
  "itself. Of everything in this milestone it is the one that changes how the "
  "product is used rather than what it can see.",
  A, "Automation", "M", [], "#296"),

 ("US-21", "Analyse my whole network at once, not device by device",
  "As an engineer with forty switches, I want one scan over all of them, so I "
  "see problems that only exist between devices.",
  ["**Already true, verified:** a snapshot of N devices is analysed, scoped "
   "per device, with wall-clock recorded at 10 and 50 in `docs/scale.md`",
   "Still missing: 100 devices, and MEMORY at every size -- only time was taken",
   "Still missing: the finding that matters. At 50 devices the analysis "
   "returns 3 findings, the same as at one, because every rule names a "
   "specific device. Fifty devices in, one device examined",
   "So the real deliverable is that a multi-device scan reports coverage "
   "honestly: N devices present, M examined, and the difference stated",
   "`tests/fixtures/multi-device-10` and `tools/make_scale_fixture.py` already "
   "exist and are extended rather than replaced"],
  "RESCOPED after reading `docs/scale.md`, which #218 already produced. "
  "Discussion #296 asked for timings that had been taken six weeks earlier: "
  "10 devices in 4.3 s, 50 in 6.9 s, roughly linear. Speed was never the risk. "
  "The document's own second half says so -- the analysis does not grow with "
  "the network, which is #87 wearing a different hat. What is genuinely "
  "outstanding is memory, 100 devices, and making the coverage gap visible "
  "rather than leaving a user to infer it from a suspiciously short list.",
  A, "Scale", "M", [87, 218], "#296"),

 ("US-22", "Tell me only what changed since the last scan",
  "As someone who scans weekly, I want the diff, so I am not re-reading forty "
  "findings I already triaged.",
  ["Findings persisted per snapshot with a content fingerprint, not an id "
   "(ids are not stable identity -- this is #240's problem C and it blocks this)",
   "Output partitions into **new**, **resolved**, **unchanged**",
   "A check that has newly gone blind is its own category, never counted as "
   "*resolved* -- that is F-4 arriving one level up",
   "Depends on **US-33**; ship after it"],
  "Needs the store #223 describes. Together they turn a one-off audit into "
  "something worth running on a schedule.",
  A, "UX", "M", [223], "#296"),

 ("US-23", "Make `access_control` read my policy",
  "As a user with my own network, I want the access-control check to use my "
  "rules, so it stops reporting \"could not check\" on every device I own.",
  ["`access_control` reads `rules_in_use()` exactly as `policy_compliance` does",
   "With no policy supplied, behaviour is byte-identical to today",
   "`tools/stranger_config.py` re-run and the FOUND column recorded on the issue",
   "**Half of #87.** The other half is US-26"],
  "#87 is the largest measured gap in the product: one rename of a device "
  "removes half the detection. This is half of closing it.",
  A, "Honesty", "M", [87], "#296"),

 ("US-24", "Show me what Netwise could not read",
  "As a user, I want to know which parts of my config were not understood, so "
  "I know how much of the file the result actually covers.",
  ["Parse coverage reported as a first-class number: lines recognised / total",
   "Unrecognised constructs listed by kind, never silently dropped",
   "Feeds the coverage section already in the exported report",
   "Renders on every surface that renders findings, per #308's rule"],
  "The coverage statement exists; what it does not yet know is how much of the "
  "file was legible in the first place.",
  A, "Honesty", "M", [308], "#296"),

 ("US-25", "Let me ask a follow-up",
  "As a user, I want to ask \"and what would fix that?\" after an answer, so I "
  "am not re-typing the whole question.",
  ["A question may reference the previous answer's resolved entities only",
   "The grounding guarantee is unchanged: every sub-query still runs for real",
   "`question_understood` shows the **fully resolved** question, not my shorthand",
   "This is #240's problem B, scoped"],
  "The narrow scope of the query layer is what makes it safe rather than merely "
  "limited (CLAUDE.md 7c). Widening it must not widen what the model decides.",
  N, "AI", "L", [240], "#296"),

 ("US-26", "Make `routing` read my policy",
  "As a user, I want routing checks against my devices, not `rtr-hq` and "
  "`rtr-branch`.",
  ["Same shape as US-23, same no-policy guarantee",
   "A device named in the policy but absent from the snapshot produces a "
   "could-not-check, never silence",
   "The two together close #87; either alone only halves it"],
  "The other half of #87. Landing only one of the two is worse than it sounds: "
  "a user who supplies a policy would find one check reading it and another "
  "silently naming our fixtures, which is a more confusing state than today's, "
  "where both are honestly wrong in the same way.",
  A, "Honesty", "M", [87], "#296"),

 ("US-27", "Analyse a vendor that is not Cisco, end to end",
  "As an engineer with a mixed estate, I want Arista, NX-OS and Juniper to work "
  "as well as IOS does.",
  ["`vendor-asa` joins the other three: a deliberate fault, and an end-to-end "
   "test that finds it. It is the only fixture Batfish reports as "
   "`PARTIALLY_UNRECOGNIZED`, so this depends on resolving parse strictness",
   "Any check that is IOS-specific says so as `status=\"error\"`, per F-4",
   "A per-vendor support table in `README.md`, generated rather than typed -- "
   "nothing a user reads currently says which vendors work",
   "The table distinguishes *parses* from *produces findings*, because "
   "`tests/test_vendor_fixtures.py` is emphatic that these are different claims"],
  "RESCOPED after measuring, and the original scope was wrong in our favour "
  "twice. Discussion #296 asked for \"the three existing vendor fixtures\" to "
  "run through the full pipeline. There are four fixtures, and three of them "
  "already do -- `pytest tests/test_vendor_fixtures.py` passes 10 tests "
  "against real Batfish today. What remains is `vendor-asa`, which parses only "
  "partially, and the fact that no user-facing document says any of this.",
  N, "Vendors", "L", [], "#296"),

 ("US-29", "Explain related findings as one story",
  "As a user looking at five findings caused by one bad rule, I want one "
  "explanation, not five.",
  ["Findings grouped by shared evidence source before explanation",
   "The group explanation cites every finding in it; no finding loses its own card",
   "Model still never chooses what to group -- grouping is deterministic"],
  "Distinct from #238, which chains findings that are jointly exploitable. This "
  "one is about not saying the same thing five times.",
  A, "Trust", "M", [238], "#296"),

 ("US-30", "Tell me if my own policy contradicts itself",
  "As someone writing a policy, I want to know that rule 3 requires what rule 7 "
  "forbids, before I run anything against a network.",
  ["Pure logic over the policy file; no Batfish, no config",
   "Reports the contradicting pair with both rule numbers and the overlap",
   "A contradiction blocks the scan rather than producing arbitrary results",
   "This is #240's problem D, and it is the one that needs no network at all"],
  "The only story here that can be built and tested with nothing running -- no "
  "Docker, no Batfish, no Ollama.",
  S, "Policy", "M", [240], "#296"),

 ("US-31", "Check a proposed change against my whole policy",
  "As an engineer, I want to know whether an edit breaks any rule I have, not "
  "just the one flow I thought about.",
  ["`analyse_change` runs every policy rule across before and after",
   "Direction reported per rule: opening, tightening, unchanged",
   "A change that resolves one breach and creates another reports both",
   "Extends the existing `compareFilters` + `differentialReachability` pairing"],
  "Change impact and policy compliance both exist on `main` today and never "
  "meet.",
  S, "Policy", "M", [], "#296"),

 ("US-32", "Tell me which of my policy rules never fire",
  "As a policy author, I want dead rules found in my policy the way dead ACL "
  "lines are found in my config.",
  ["A rule that no flow in the snapshot can match is reported as a finding",
   "Reported as **hygiene**, never as a violation",
   "Distinguished from a rule that matched and passed",
   "Symmetric with `filterLineReachability`, and states that symmetry"],
  "`filterLineReachability` already does this for the config. Nothing does it "
  "for the rules the user wrote.",
  S, "Policy", "S", [], "#296"),

 ("US-33", "Recognise the same problem across two scans",
  "As someone tracking progress, I want to know whether this is last week's "
  "problem or a new one.",
  ["A content fingerprint over structured fields plus a similarity measure on "
   "the free-text evidence",
   "Measured against the known collision: `rtr-us5-insecure` and `rtr-us5-messy` "
   "both emit `AC-001` for different problems",
   "**US-22 depends on this.** This is #240's problem C"],
  "A hard prerequisite for US-22 and US-46. Nothing that compares two scans is "
  "trustworthy until identity is stable.",
  A, "Policy", "M", [240], "#296"),

 ("US-34", "Draft a policy from a config I already have",
  "As a new user with no written policy, I want a starting point derived from "
  "what my firewall already does.",
  ["Produces a policy file, clearly marked as a draft, never applied automatically",
   "Every generated rule cites the config line it came from",
   "Refuses where the config is ambiguous instead of guessing"],
  "The blank page is the main reason a user supplies no policy at all -- which "
  "is the gap US-23 and US-26 exist to close.",
  A, "Content", "M", [87], "#296"),

 ("US-35", "Sign in, so my scans are mine",
  "As one of several users on a shared install, I want my configs and results "
  "private to me.",
  ["Real identity on top of the session isolation from #242",
   "A user can only read their own snapshots; enforced server-side and tested "
   "by trying to read someone else's",
   "No credential is ever logged, including on failure",
   "Sessions expire"],
  "Session isolation exists. There is no identity behind it, so there is "
  "nothing to isolate *to*.",
  K, "Multi-tenant", "L", [], "#296"),

 ("US-36", "Rank by what it would cost me, not just what kind of bug it is",
  "As an owner, I want the finding on my payroll server above the same finding "
  "on a lab switch.",
  ["Extends `business_context.py` beyond three tiers to a stated impact model",
   "The ruleset is written down before it is coded, the way `severity-rules.md` was",
   "Every position is explainable: traceable to a stated rule",
   "`risk` still may not downgrade or drop a `status=\"error\"` finding"],
  "Extends #254, which proved the mechanism on three tiers and one level of "
  "escalation. What is missing is the model behind it: today a device is "
  "critical or it is not, and every finding on it moves by the same single "
  "step regardless of what the finding actually is.",
  A, "UX", "M", [], "#296"),

 ("US-37", "Give me something I can hand to an auditor",
  "As someone facing an audit, I want a dated evidence pack, not a screenshot.",
  ["Export includes: what was checked, what could not be checked, the policy "
   "used, the tool version, and the snapshot fingerprint",
   "The \"could not check\" section appears **first**, as it already does in the report",
   "Deterministic: the same snapshot and policy produce a byte-identical pack",
   "Signed or checksummed so it cannot be quietly edited after the fact"],
  "The export exists since #233. What is missing is the framing that lets it "
  "survive the meeting it is carried into.",
  A, "UX", "M", [], "#296"),

 ("US-38", "Let me use it with a keyboard and a screen reader",
  "As a user who does not use a mouse, I want the whole dashboard operable.",
  ["Every control reachable and operable by keyboard, with a visible focus state",
   "Landmarks and headings correct -- #284 did this for the four areas; this "
   "finishes it for the cards, filters and dialogs",
   "Colour is never the only carrier of severity or status",
   "An automated check in CI so it cannot regress silently"],
  "Begun in #284. Also a procurement requirement anywhere public money is "
  "involved, so it is a commercial gate as well as a right one.",
  K, "UX", "M", [], "#296"),

 ("US-39", "Show me progress during a long scan",
  "As a user, I want to see what is happening while a scan runs, so I can tell "
  "work from a hang.",
  ["Per-stage progress: parsing, model build, each check",
   "An estimate that is honest about being an estimate",
   "A stalled stage is reported rather than displayed as still working"],
  "The first scan of a session already costs about 22 seconds of engine warm-up "
  "with no feedback at all.",
  K, "UX", "S", [], "#296"),

 # -------------------------------------------------------------- new -------
 ("US-40", "Prove that nothing left my machine",
  "As a security reviewer, I want a record of every outbound connection Netwise "
  "attempted, so I can verify the offline claim instead of believing it.",
  ["A runtime egress record naming host, port and the component that tried",
   "An allowlist covering only the local Batfish and the local Ollama",
   "Anything outside it is **refused** and recorded, not merely recorded",
   "`python -m tools.egress_audit` prints the record for a scan",
   "A test that plants an outbound call in a check and proves it is refused"],
  "Constraint N-1 is the product's main commercial differentiator, and today it "
  "rests entirely on code review. Every other claim in this project is measured; "
  "this one is asserted. A buyer's security team will ask, and *we read the "
  "source carefully* is not an answer.",
  A, "Honesty", "M", [], "new"),

 ("US-41", "Install Netwise with one command",
  "As an IT administrator, I want a single command that brings the whole product "
  "up, so I do not need to clone a repository to try it.",
  ["`docker compose up` starts app, Batfish and Ollama with pinned image tags",
   "No git clone, no manual pip install, no separate model build step",
   "First run works on a machine that has only Docker",
   "The README's eight steps become one, with the long form kept for developers"],
  "Installation today assumes a developer. It is the single largest barrier "
  "between this tool and anybody who might evaluate it.",
  A, "Distribution", "M", [], "new"),

 ("US-42", "Upgrade without losing my data",
  "As an administrator, I want to move to a new version and keep my policies, "
  "history and settings, so upgrading is not a reason to avoid upgrading.",
  ["Versioned releases with semantic version numbers",
   "A documented and tested upgrade path between adjacent versions",
   "Stored data carries a schema version and is migrated forward",
   "A downgrade is refused, never allowed to corrupt"],
  "Nothing persists across a restart today, so this is free now and expensive "
  "the moment US-22 or US-35 lands.",
  A, "Distribution", "M", [], "new"),

 ("US-43", "Tell me how big a network you can actually handle",
  "As an engineer with a real estate, I want a stated supported ceiling, so I "
  "am not the person who discovers it.",
  ["A generated fixture estate of 500 devices in the repository",
   "Measured and published: time, memory, and where it degrades",
   "A documented supported ceiling rather than an unstated one",
   "Beyond it, a clear refusal -- never a partial result presented as whole"],
  "`docs/scale.md` already measures 10 and 50 devices and is careful to call "
  "its figure \"a floor, not an estimate\" -- the fixtures are fifty copies of "
  "one router with no topology between them. This is the story that turns that "
  "floor into a number we are willing to put in writing, on an estate that is "
  "not synthetic. Unknown is not sellable, and a silent partial result is F-4 "
  "at estate scale.",
  A, "Scale", "L", [], "new"),

 ("US-44", "Run a long scan in the background",
  "As a user, I want to start a scan, close the tab, and come back to the "
  "result, so a large scan is not hostage to my browser.",
  ["Scans become jobs with an id, a status and a result",
   "A job survives an application restart",
   "Progress is reported while it runs (US-39)",
   "A job that dies is reported as **failed**, never as complete with no findings"],
  "The request-response model caps the product at whatever fits inside one HTTP "
  "timeout. The last acceptance line is the one that matters: a crashed scan "
  "rendering as a clean result is the worst failure this product could have.",
  A, "Scale", "L", [], "new"),

 ("US-45", "Give my team shared access, with roles",
  "As a team lead, I want an organisation with members, so we share policies and "
  "history instead of each keeping our own copy.",
  ["Organisations own policies, scan history and business context",
   "Roles: admin, member, read-only",
   "An invitation flow that does not require sharing a password",
   "Every destructive action records who did it in the audit log"],
  "Depends on US-35. This is the difference between a utility one engineer runs "
  "and a product a company buys a seat of.",
  A, "Multi-tenant", "L", [], "new"),

 ("US-46", "Scan on a schedule, without me starting it",
  "As an engineer, I want a nightly re-scan that tells me only what changed, so "
  "drift is caught without anyone remembering to look.",
  ["Scheduled scans per target, configurable",
   "Results retained so US-22's diff has something to compare against",
   "A notification only when something changed -- never a nightly all-clear",
   "A scheduled scan that failed is reported, never silently skipped"],
  "Depends on US-22 and US-44. This is what makes Netwise a monitoring product "
  "rather than an audit tool you run twice a year.",
  A, "Automation", "M", [], "new"),

 ("US-47", "Read my configs from where they already are",
  "As an engineer, I want Netwise to pull from my config backup repository, so "
  "I am not copying files by hand every time.",
  ["A read-only connector for a git repository of configs",
   "A watched directory as a second source",
   "Credentials stored encrypted, never logged, never inside a finding",
   "Read-only is **enforced**, not merely intended -- a test proves a push is refused"],
  "Every organisation with more than ten devices already backs its configs up "
  "somewhere. Meeting them there removes the manual step that stops this being "
  "used weekly.",
  A, "Automation", "M", [], "new"),

 ("US-48", "Send findings to the tools my team already uses",
  "As a team lead, I want high-severity findings to reach our ticketing and "
  "chat, so the finding reaches a person without anyone watching a dashboard.",
  ["An outbound webhook carrying F-1 findings, **off by default**",
   "Explicit configuration required, and the act of enabling it is recorded in "
   "the audit log",
   "The offline guarantee restated precisely in the README: *the user may choose "
   "to send findings out; Netwise never does so on its own*",
   "Redaction options for evidence detail"],
  "The one place constraint N-1 needs a documented, consenting exception -- "
  "which is exactly why it must be opt-in, audited, and described in the same "
  "breath as the guarantee it qualifies. This story is as much a documentation "
  "task as a code one.",
  A, "Automation", "M", [], "new"),

 ("US-49", "Install it with no internet at all",
  "As the operator of an air-gapped network, I want an offline bundle, so I can "
  "run it in the environment that needs it most.",
  ["A single archive that installs with no network access",
   "The language model included, with its licence terms",
   "A checksum manifest so the bundle can be verified before it is trusted",
   "Documented as the supported path for isolated sites"],
  "The customers who most need an offline analyser are the ones who cannot "
  "download one. This turns the project's core constraint into its distribution "
  "channel rather than a footnote about it.",
  A, "Distribution", "M", [], "new"),

 ("US-50", "Give me an SBOM and a stated dependency policy",
  "As a security reviewer, I want a bill of materials and a policy on updates, "
  "so I can clear this through supply-chain review.",
  ["A generated SBOM published with every release",
   "A written policy for how quickly advisories are acted on",
   "Dependency scanning in CI, failing on a known critical",
   "Netwise runs its own CVE check against its own dependencies"],
  "A standard procurement gate. Dependabot already runs here; this turns it "
  "from a habit into an answer we can hand over.",
  A, "Trust", "S", [], "new"),

 ("US-51", "Point Netwise at its own deployment",
  "As an administrator, I want the tool to check the configuration of the box it "
  "runs on, so the security tool is not the weakest thing on the network.",
  ["A self-check: exposed ports, default credentials, TLS, file permissions",
   "Reported through the same three-state contract as everything else",
   "Shipped as a first-class check, not a script somebody remembers to run"],
  "A security product that has never been pointed at itself is a fair thing for "
  "a buyer to ask about, and an embarrassing thing to be asked in a demo. Note "
  "that `tools/preflight.py` already checks whether this machine can RUN "
  "Netwise -- Python, dependencies, Docker, Batfish, Ollama, Node. That is a "
  "readiness check, not a security one, and this story must extend it rather "
  "than grow a second thing that looks like it.",
  A, "Trust", "S", [], "new"),

 ("US-52", "Tell me what you keep, and delete it when I say",
  "As a data protection officer, I want a written and enforced retention policy, "
  "so I can approve this tool without a legal argument.",
  ["Documented retention for uploads, findings, history and logs",
   "Configurable retention, enforced by a scheduled job rather than by hope",
   "A delete that genuinely removes, including derived artefacts",
   "The audit log records the deletion without recording the content"],
  "Any customer handling regulated data asks this in the first meeting. "
  "`web/audit_log.py` already has the redaction boundary this needs.",
  A, "Multi-tenant", "M", [], "new"),

 ("US-54", "Give me the fix, not just the problem",
  "As an engineer, I want a concrete config change that resolves a finding, so "
  "I do not have to work out the remedy myself.",
  ["A generated fix per finding, where one can be derived",
   "Shown as a diff against the uploaded config -- **never applied**",
   "Simulated through `analyse_change` before it is offered",
   "A finding with no safe derivable fix says so rather than guessing"],
  "#221 delivered remediation *text*. This is the change itself. The line that "
  "must not move is CLAUDE.md 4: generate and simulate, never push.",
  A, "Remediation", "L", [], "new"),

 ("US-55", "Show me the explanation layer is any good",
  "As a supervisor, I want a measured evaluation of explanation quality, so the "
  "AI claim rests on evidence like everything else here.",
  ["A held-out set of findings with human-rated reference explanations",
   "A repeatable score, run in CI, with the number published",
   "A documented threshold below which the deterministic fallback is preferred"],
  "The roadmap names this as Tier 2.1. The explanation layer is the one "
  "component in this product with no measurement behind it, in a project whose "
  "whole argument is that claims should be measured.",
  N, "AI", "M", [], "new"),

 ("US-56", "Make my first five minutes work",
  "As someone evaluating the tool, I want a guided first run with sample data, "
  "so I see what it does before I have to supply anything.",
  ["A bundled sample network with planted faults, one click to scan",
   "Empty states that say what to do next rather than showing nothing",
   "Every error state says what happened and what to try",
   "The sample is labelled so it can never be mistaken for real data"],
  "Every evaluation of this product currently begins with a blank screen and a "
  "file picker. This is the cheapest story in the milestone and probably the "
  "one that changes the most minds.",
  A, "UX", "S", [], "new"),
]

# Already issues. Folded into the milestone rather than created again.
EXISTING = [
    ("US-28", 78, N, "Convert my whole pfSense export, including NAT",
     "Vendors", "L"),
    ("US-53", 220, A, "One real compliance benchmark pack (CIS Cisco IOS)",
     "Content", "L"),
    ("US-57", 308, A, "Coverage on every surface that shows findings, or none",
     "Honesty", "M"),
]

EPIC_ORDER = ["Honesty", "Distribution", "Scale", "Multi-tenant", "Automation",
              "Content", "Remediation", "Vendors", "AI", "Policy", "UX", "Trust"]

EPIC_WHY = {
 "Honesty": "The product's central claim is that it never says “clean” when it "
            "means “unchecked”. These are the places that claim is "
            "still only half-kept.",
 "Distribution": "Nobody can buy something they cannot install.",
 "Scale": "Speed was measured in #218 and is not the problem: fifty devices "
          "analyse in 6.9 seconds. What `docs/scale.md` found instead is that "
          "the analysis does not GROW with the network -- fifty devices in, "
          "one device examined. These stories are about that.",
 "Multi-tenant": "One person on one laptop is a tool. Several people in one "
                 "company is a product.",
 "Automation": "A scan somebody has to remember to run is a scan that stops "
               "happening in week three.",
 "Content": "Our rules are ours. A buyer wants a standard's rules, and a way "
            "into writing their own.",
 "Remediation": "Finding the problem is half the value. The other half is the "
                "line of config that fixes it.",
 "Vendors": "Four vendor fixtures exist and three of them -- Arista, Juniper "
            "and NX-OS -- already produce a real finding end to end. What is "
            "left is the fourth, and saying so anywhere a user can see it.",
 "AI": "The layer with the most attention on it and the least measurement "
       "behind it.",
 "Policy": "The user's own rules are a first-class artefact and deserve the "
           "same scrutiny we give their configs.",
 "UX": "Most of these are cheap. Together they are the difference between a "
       "demo and a thing someone uses on a Tuesday.",
 "Trust": "The questions a buyer's security and procurement teams ask before "
          "they ask anything about features.",
}


def load(assignee):
    return [s for s in STORIES if s[5] == assignee]


def counts():
    out = {}
    for who in (A, N, S, K):
        out[who] = len(load(who)) + len([e for e in EXISTING if e[2] == who])
    return out


def issue_body(sid, title, story, acc, why, who, epic, size, refs, src):
    lines = [f"*{story}*", ""]
    lines.append("## Acceptance criteria")
    lines.append("")
    lines += [f"- {a}" for a in acc]
    lines += ["", "## Why this is in the milestone", "", why, ""]
    lines.append("---")
    lines.append("")
    lines.append(f"**Epic:** {epic}  |  **Size:** {size}  |  "
                 f"**Assigned:** @{who}")
    if src == "#296":
        lines.append("")
        lines.append("Story and acceptance criteria come from **Discussion "
                     "#296** unchanged, so anyone who reviewed the discussion "
                     "has already reviewed this issue.")
    if refs:
        lines.append("")
        lines.append("Related: " + ", ".join(f"#{r}" for r in refs))
    lines.append("")
    lines.append("Part of **" + MILESTONE + "**. The distribution of this "
                 "milestone is deliberately uneven and is explained in "
                 "`docs/design/phase-3-backlog.md` and on #249.")
    return "\n".join(lines)


# --------------------------------------------------------------- document ---
def document():
    n = counts()
    total = len(STORIES) + len(EXISTING)
    L = []
    w = L.append
    live = {}
    if NUMBERS.exists():
        live = json.loads(NUMBERS.read_text(encoding="utf-8"))
    w("<!-- GENERATED by tools/make_phase3_backlog.py. Do not hand-edit.")
    w("     The stories live in that script once, and both this document")
    w("     and the GitHub issues are produced from them, so the two")
    w("     cannot disagree. Hand-editing removes that guarantee. -->")
    w("")
    w("# Phase 3 — market readiness")
    w("")
    w("*Everything between Netwise today and a product that could be sold.*")
    w("")
    w("Phase 0 was consolidation. Phase 1 was the four capabilities. Phase 2 "
      "was direction only. This is the first backlog written against a "
      "different question: not *what would make this a better capstone* but "
      "**what would stop a stranger who paid for it from asking for a refund**.")
    w("")
    w("---")
    w("")
    w("## Where these came from")
    w("")
    w("| Range | Source |")
    w("|---|---|")
    w("| `US-20` – `US-39` | **Discussion #296**, unchanged. Twenty stories "
      "designed and argued in early September and never turned into work. "
      "Their acceptance criteria are copied rather than rewritten. |")
    w("| `US-40` – `US-56` | **New.** Each one closes a gap a paying customer "
      "hits in the first week, or one a buyer's security review asks about and "
      "we currently cannot answer. |")
    w("")
    w("Three stories already existed as issues and are folded in rather than "
      "created again — creating them twice would be this project's own "
      "recurring defect, committed by the backlog written to avoid it:")
    w("")
    w("| Story | Existing issue |")
    w("|---|---|")
    for sid, num, who, t, _e, _s in EXISTING:
        w(f"| `{sid}` | [#{num}]"
          f"(https://github.com/{REPO}/issues/{num}) — {t} |")
    w("")
    w("Nothing here is a feature because it sounds impressive. Every story "
      "names the thing that is currently untrue, unmeasured or unreachable.")
    w("")
    w("---")
    w("")
    w("## The distribution, stated rather than arranged")
    w("")
    w(f"**{total} stories. Arsh has {n[A]}. Ankeet has {n[N]}, Shubham has "
      f"{n[S]}, Samika has {n[K]}.**")
    w("")
    w("That is deliberate, and it is a decision rather than an accident, so it "
      "is written down where the people affected by it can read it.")
    w("")
    w("**Why.** The remaining calendar is short and most of this milestone is "
      "sequential: US-22 waits on US-33, US-45 waits on US-35, US-46 waits on "
      "US-22 and US-44. A dependency chain moves at the speed of whoever is "
      "slowest to pick up their link. Concentrating the chain on one person "
      "removes the hand-off latency, which is the largest single cost in a "
      "four-person team working part-time around other papers.")
    w("")
    w("**What each of the other three gets** is a short, self-contained slice "
      "inside the vertical they already own, with no story in it that blocks "
      "anybody else. They can finish, stop, and not be the reason something "
      "else is waiting.")
    w("")
    w("**What it costs, which is the part worth saying out loud.** #249 "
      "measured that Arsh authored 61% of pull requests and consumed 62% of "
      "the team's review capacity, and — more importantly — that **review, not "
      "authorship, is where this project's defects have actually been caught**. "
      "The fixture corruption in #304, the student IDs in #311, the stale "
      "amendment table, the false claim in the portfolio: every one was found "
      "by somebody reading somebody else's work.")
    w("")
    w("So this split does not reduce the team's work. It moves it from "
      "authoring to reviewing. **Every story here still needs a current "
      "approving review from someone who did not write it (M-1), and new work "
      "still voids an approval (M-2 rule 1).** If the other three treat a "
      "light authoring load as a light total load, this milestone will ship "
      "faster and be worse, and the failure will not be visible until "
      "something built on an unreviewed foundation has to be unpicked.")
    w("")
    w("The honest summary: **three people are being asked to write less and "
      "read more.** That is the trade, and it is only a good trade if the "
      "reading actually happens.")
    w("")
    w("---")
    w("")
    w("## The backlog")
    w("")
    for epic in EPIC_ORDER:
        rows = [r for r in STORIES if r[6] == epic]
        if not rows and not [e for e in EXISTING if e[4] == epic]:
            continue
        w(f"### {epic}")
        w("")
        w(f"*{EPIC_WHY[epic]}*")
        w("")
        w("| | Story | Issue | Size | Owner |")
        w("|---|---|---|---|---|")
        merged = [(r[0], r[1], r[7], r[5], "") for r in rows]
        merged += [(e[0], e[3], e[5], e[2], " *(already open)*")
                   for e in EXISTING if e[4] == epic]
        for sid, title, size, who, note in sorted(merged):
            num = live.get(sid)
            link = (f"[#{num}](https://github.com/{REPO}/issues/{num})"
                    if num else "_not created_")
            w(f"| `{sid}` | {title}{note} | {link} | {size} | {NAME[who]} |")
        w("")
    w("---")
    w("")
    w("## Order of work")
    w("")
    w("Not a schedule. A dependency order, so nothing is started before the "
      "thing it needs exists.")
    w("")
    w("```")
    w("1  install and honesty      US-41  US-40  US-56  US-23  US-26  US-24")
    w("                            US-57")
    w("     a stranger can run it, and it tells the truth about what it read")
    w("")
    w("2  identity and persistence US-35  US-42  US-33  US-22")
    w("     results stop being disposable, and a finding keeps its name")
    w("")
    w("3  scale and automation     US-21  US-43  US-44  US-20  US-46  US-47")
    w("     it survives a real estate and runs without being asked")
    w("")
    w("4  breadth and content      US-27  US-28  US-53  US-34  US-54  US-31")
    w("     more vendors, real benchmarks, and the fix as well as the fault")
    w("")
    w("5  the buyer's questions    US-50  US-51  US-52  US-45  US-37  US-48")
    w("                            US-49")
    w("     procurement, security review, and the team-sized product")
    w("")
    w("throughout                  US-25  US-29  US-30  US-32  US-36")
    w("                            US-38  US-39  US-55")
    w("     independent of the chain; can start any time")
    w("```")
    w("")
    w("---")
    w("")
    w("## What would make this milestone a failure")
    w("")
    w("Worth writing down now, while it is cheap to say.")
    w("")
    w("1. **A story marked done that widened a claim rather than a "
      "capability.** US-24, US-40 and US-43 are all one careless commit away "
      "from asserting more coverage than they deliver. That is the exact "
      "failure this product exists to catch in other people's networks.")
    w("2. **Reviews thinning as authoring concentrates.** See the section "
      "above. This is the most likely way it goes wrong.")
    w("3. **This document going stale.** It is generated from a single source "
      "along with the issues themselves, precisely so it cannot disagree with "
      "them. If it is ever hand-edited, that guarantee is gone and it becomes "
      "one more copy of a fact — which is the defect family this project "
      "has been recording since the first sprint.")
    w("")
    text = "\n".join(L) + "\n"

    # The ordering block is written by hand, which is exactly how US-49 and
    # US-57 fell out of it the first time this document was generated -- a
    # list maintained beside the thing it describes, going out of step with
    # it. So the block is checked against the stories rather than trusted.
    block = text.split("## Order of work", 1)[1].split("```")[1]
    listed = set(re.findall(r"US-\d+", block))
    every = {r[0] for r in STORIES} | {e[0] for e in EXISTING}
    missing = sorted(every - listed)
    stray = sorted(listed - every)
    if missing or stray:
        raise SystemExit(
            f"order-of-work block disagrees with the backlog:\n"
            f"  missing: {missing or 'none'}\n"
            f"  unknown: {stray or 'none'}")
    return text


def gh(args):
    return subprocess.run(["gh", *args], capture_output=True, text=True,
                          check=True).stdout.strip()


def create():
    """Create every story that does not already have a number recorded.

    Re-runnable. A story already in the numbers file is skipped rather than
    created again, so an interrupted run resumes instead of duplicating --
    which is the exact failure this script exists to make impossible.
    """
    live = {}
    if NUMBERS.exists():
        live = json.loads(NUMBERS.read_text(encoding="utf-8"))
    tmp = pathlib.Path(__file__).resolve().parent / ".issue-body.md"
    for row in STORIES:
        sid = row[0]
        if sid in live:
            print(f"  {sid:<7} already #{live[sid]}, skipped")
            continue
        tmp.write_text(issue_body(*row), encoding="utf-8")
        try:
            url = gh(["issue", "create", "--repo", REPO,
                      "--title", f"{sid} \u2014 {row[1]}",
                      "--body-file", str(tmp),
                      "--assignee", row[5],
                      "--milestone", MILESTONE,
                      "--label", "phase: 3",
                      "--label", f"size: {row[7]}"])
        finally:
            tmp.unlink(missing_ok=True)
        live[sid] = int(url.rstrip("/").rsplit("/", 1)[-1])
        NUMBERS.write_text(json.dumps(live, indent=1, sort_keys=True) + "\n",
                           encoding="utf-8")
        print(f"  {sid:<7} #{live[sid]:<5} {NAME[row[5]]:<9} {row[1][:50]}")
    for sid, num, _who, _t, _e, _s in EXISTING:
        live.setdefault(sid, num)
    NUMBERS.write_text(json.dumps(live, indent=1, sort_keys=True) + "\n",
                       encoding="utf-8")
    print(f"\n  {len(live)} stories carry an issue number")


def update():
    """Push the current body of every created story back onto its issue.

    Without this, editing a story here fixes the document and leaves the
    issue saying the old thing -- one fact in two places with one of them
    updated, which is the defect this whole script is arranged against.
    Creating the issues was never the end of the coupling; keeping them is.
    """
    live = json.loads(NUMBERS.read_text(encoding="utf-8"))
    tmp = pathlib.Path(__file__).resolve().parent / ".issue-body.md"
    changed = 0
    for row in STORIES:
        num = live.get(row[0])
        if num is None:
            continue
        current = gh(["issue", "view", str(num), "--repo", REPO,
                      "--json", "body", "--jq", ".body"])
        wanted = issue_body(*row)
        if current.replace("\r\n", "\n").strip() == wanted.strip():
            continue
        tmp.write_text(wanted, encoding="utf-8")
        try:
            gh(["issue", "edit", str(num), "--repo", REPO,
                "--title", f"{row[0]} \u2014 {row[1]}",
                "--body-file", str(tmp)])
        finally:
            tmp.unlink(missing_ok=True)
        changed += 1
        print(f"  {row[0]:<7} #{num:<5} body updated")
    print(f"\n  {changed} issue(s) changed, "
          f"{len(STORIES) - changed} already current")


if __name__ == "__main__":
    if sys.argv[1:2] == ["create"]:
        create()
    elif sys.argv[1:2] == ["update"]:
        update()
    elif sys.argv[1:2] == ["doc"]:
        out = pathlib.Path(sys.argv[2]) if sys.argv[2:3] else DOC
        out.write_text(document(), encoding="utf-8")
        n = counts()
        print(f"wrote {out}  ({len(document().splitlines())} lines)")
        print(f"stories: {len(STORIES)} new + {len(EXISTING)} existing "
              f"= {len(STORIES) + len(EXISTING)}")
        for who in (A, N, S, K):
            print(f"   {NAME[who]:<9} {n[who]}")
    elif sys.argv[1:2] == ["json"]:
        print(json.dumps([{
            "id": s[0], "title": s[1], "body": issue_body(*s),
            "assignee": s[5], "epic": s[6], "size": s[7],
        } for s in STORIES], indent=1))
