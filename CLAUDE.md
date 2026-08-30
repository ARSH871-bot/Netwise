# Netwise — project brief

Netwise reads exported network device configuration files, finds security
misconfigurations in them, and explains those findings in plain English.

Everything runs offline and locally. The tool never touches a live network.

---

## Read these two first

| Document | What it governs |
|---|---|
| [`docs/finding-format.md`](docs/finding-format.md) | **The finding contract (F-1).** The exact shape every check returns. Agreed by all four members; changing it needs all four. Summarised in §7a below. |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | **The workflow.** Feature branches, pull requests, and how to add a check. Nobody commits directly to `main`. |

---

## 1. The problem

Routers, switches and firewalls are controlled by plain-text configuration
files: long lists of rules deciding which traffic is allowed, which is blocked,
and how packets move. These files grow messy over years of edits by different
people. Small mistakes hide in them — a rule that accidentally exposes an
internal system, a rule that contradicts another, a rule that silently never
takes effect. Misconfigurations like these are a leading cause of real
breaches, and they are very hard to catch by reading the files by hand.

Netwise finds those mistakes automatically and explains them in plain English.

## 2. End-to-end flow

1. User uploads network device configuration files.
2. Netwise loads them into **Batfish**, which builds an offline model of the
   network and runs security analyses purely by reading the configs.
3. The raw Batfish findings (technical tables) go to a **locally hosted LLM**,
   which explains each finding in plain language and classifies its risk.
4. The user sees a **two-pane dashboard**: config upload on one side, a chat
   pane on the other for plain-English questions with grounded answers.

## 3. Architecture — three layers

**Layer 1 — Batfish (analysis engine).** Open-source network verification tool.
Parses configs, builds a vendor-neutral model, answers structured "questions".
Runs in Docker; driven from Python via `pybatfish`. **Batfish already exists —
we orchestrate it, we do not implement network analysis ourselves.**

**Layer 2 — AI explanation layer.** A local LLM served by Ollama, so no config
data leaves this machine. Its job is translation and Q&A: turn structured
Batfish output into plain-English risk explanations, and map natural-language
questions onto Batfish queries.

**Layer 3 — Web interface.** FastAPI backend plus a simple frontend. Findings
shown by severity (high/medium/low) with plain-English explanations.

## 4. What the client asked for

Two directions for the AI, both in scope:

- **Output direction (explanation).** Turn Batfish output into human language.
  Not "port 80 is denied" but "websites are blocked". Not "ACL line 460 denies
  10.10.10.42" but "one machine can't reach the DNS server because an earlier
  rule blocks it".
- **Input direction (instruction).** The user types "block YouTube" or "stop the
  guest network reaching the finance server", and the AI proposes a config
  change. If the change would create a security flaw, the system **pushes back
  and warns** rather than silently applying it.

**Scope limit:** Netwise GENERATES and SIMULATES config changes. It must never
push changes to a live device. Application-level blocking (e.g. YouTube) is
genuinely hard and may only be partly achievable — treat it as a
proposal/simulation feature, never live enforcement.

## 5. Non-negotiable constraints

1. **Everything local.** No config data to any cloud AI service. No config
   files in git — see `.gitignore`, which was deliberately the first commit.
2. **The AI is grounded strictly in real Batfish output.** It must never invent
   or guess network behaviour. This is enforced *structurally* — the model only
   ever receives real Batfish results and is only ever asked to rephrase them.
   A hallucinated finding in a security tool is a critical failure, not a bug.
3. **Passive and offline.** Netwise reads exported files. It never connects to,
   scans, or modifies a live network.
4. **Readable code.** All four team members must be able to read and explain
   any part of it in a project review. Keep it simple and well-commented;
   prefer the obvious solution over the clever one.
5. **Acknowledge AI-assisted code**, per the university's academic integrity
   policy.

## 6. Batfish workflow

```python
from pybatfish.client.session import Session

bf = Session(host="localhost")                       # 1. connect
bf.init_snapshot(path, name=..., overwrite=True)     # 2. load configs
bf.q.<question>(...).answer().frame()                # 3. ask -> pandas DataFrame
```

The questions this project relies on:

| Question | What it does |
|---|---|
| `testFilters` | Does a filter permit or deny ONE specific flow, and why — names the exact matching line. |
| `searchFilters` | Checks a whole SPACE of flows at once for policy violations. **Our strongest capability** — it *proves* properties rather than spot-checking. Empty result = policy holds; a returned flow = a violation. |
| `filterLineReachability` | Finds ACL lines that can never trigger because an earlier line shadows them ("dead rules"). |
| `undefinedReferences` | Finds config referencing a structure (route-map, ACL, object group) that is never defined — a silent failure risk. |
| `traceroute` | Simulates hop-by-hop whether traffic reaches a destination; shows ACCEPTED/DENIED and the path. |

Batfish runs in Docker container `batfish` (image `batfish/allinone`), exposing
8888 (Jupyter) and 9996/9997 (the service `pybatfish` talks to).

## 7. Vendors and data

- Start with **Cisco IOS** — natively supported, and Batfish ships example
  networks with ready-to-use Cisco configs for development.
- The client's real firewall is **PF Sense**, which exports XML that Batfish
  cannot read at all. `analysis/pfsense_convert.py` translates it into Cisco
  IOS text, so a converted config re-enters the same `analyse()` as everything
  else. Interfaces and filter rules are covered; NAT, aliases, DHCP, VPN, IPv6
  and combined `tcp/udp` rules are not, and each raises rather than guessing.

  **Rule order: PF Sense and Cisco disagree, and the converter now MODELS the
  difference where it can and refuses where it cannot.** PF Sense evaluates
  *last-match-wins* unless a rule is marked `quick`; a Cisco ACL — and so this
  converter — is *first-match-wins*. Where two overlapping rules have different
  actions and the earlier one is not `quick`, the two models decide the same
  traffic **differently**. Measured: a block followed by a narrower HTTPS
  permit, neither `quick`, once converted into an ACL that denied traffic the
  real firewall permits.

  **Zero `quick` rules on an interface — convert exactly (#104).** With no
  quick rule anywhere in that interface's list, "stop immediately" never fires,
  so PF Sense's decision for any flow is simply the action of the *last* rule
  that matches it. Evaluating the same rules first-match-wins in *reversed*
  order gives the first match of the reversed list, which is by construction
  the last match of the original. **Same decision, every flow — not an
  approximation**, so `_check_rule_order_is_unambiguous()` is skipped there
  rather than weakened. Verified against Batfish on the exact pair above:

  ```
  emitted:  permit tcp any host 10.20.0.5 eq 443
            deny   tcp any host 10.20.0.5
  HTTPS -> PERMIT   (PF Sense permits: it is the last match)
  HTTP  -> DENY
  ```

  This matters because the client's whole rule set is zero-quick.

  **All `quick`** — already exactly modelled by first-match-wins in original
  order, since a quick rule stops evaluation the instant it matches.

  **Mixed — still refuses.** `_check_rule_order_is_unambiguous()` detects the
  ambiguous pair and raises rather than emitting something that parses cleanly
  and is wrong (#58, closing #47). Only the *earlier* rule's `quick` flag can
  make a pair safe — PF Sense has already moved past a non-quick earlier rule
  before the later one is reached. Getting that the wrong way round is easy;
  `tests/test_pfsense_convert.py` carries a comment saying which is which,
  because the author of this paragraph got it backwards while writing the test
  for it.

  **Our own fixture was wrong about this until #58**, which is worth recording
  because the earlier version of this section cited it as reassurance. Its
  comment claimed every rule matched a disjoint slice of traffic; the trailing
  catch-all deny overlaps every rule before it by definition, so under real PF
  Sense semantics that deny would have overridden both permits and the fixture
  demonstrated the opposite of its stated policy. Both pass rules now carry
  `<quick/>` — also what a PF Sense GUI normally produces — and a test strips
  the tag from a copy to prove the refusal still fires.

  **ANSWERED, 10 August, and it is the answer that reorders the roadmap.** The
  client provided an anonymised export. Measured with `tools/pfsense_shape.py`,
  which reports structure and never a value: **zero of seven filter rules are
  marked `quick`.** Last-match-wins applies to his whole rule set, so the
  converter's first-match-wins model disagrees with his firewall wherever two
  overlapping rules differ.

  **Two of the four blockers are now gone (#104).** Multi-interface rule sets
  are supported — each interface gets its own ACL, checked independently — and
  rule order is modelled as above. His export is still 1,998 elements against
  our fixture's 54, carrying `nat`, `openvpn`, `ipsec`, `aliases`, `dhcpd` and
  `shaper`.

  What still refuses, and the message now names all of it at once, each
  attributed to its real cause rather than one blanket reason:

  ```
  REFUSED: filter rules apply to interface(s) that cannot be modelled:
  ['wan'] have no static address configured (DHCP or unconfigured) -- a
  Cisco ACL needs an address to bind rules to; ['WireGuard', 'openvpn'] are
  not declared under <interfaces> at all -- most likely VPN/tunnel policy
  (e.g. OpenVPN, WireGuard), which this module does not parse and is out of
  scope, not LAN filtering
  ```

  Two different problems, not one. A **DHCP WAN carrying rules** (a Cisco ACL
  needs an address to write rules against) and **rules naming two VPN
  interfaces absent from `<interfaces>` entirely**. The earlier version of
  this message called both "no static address configured", which is only true
  of the first, a WireGuard role does not become convertible by giving it an
  address, tunnel policy is not LAN filtering regardless. Split so the two
  remedies are not conflated. Neither was on #78's item list, which was
  written before we knew which interfaces carried rules.

  Analysing his firewall now needs, in order: **an address for the DHCP WAN
  that carries rules**, **a decision on the two VPN interfaces his rules name
  but `<interfaces>` never declares**, a decision on NAT (two of his rules
  carry `associated-rule-id` and are meaningless without it), and rules that
  omit `<type>` or `<protocol>`. **That is a sprint, plausibly more.** See #78.

  > **This list previously began "multi-interface rule sets, real PF Sense
  > evaluation order" — both of which #104 had already delivered**, and it sat
  > three paragraphs below the sentence saying so. Corrected 17 August after a
  > teammate's status update repeated the stale version from `README.md`, which
  > carried the same error. Left visible because it is the clearest instance
  > this project has of the failure family it keeps naming: one fact in two
  > places, one copy updated, and the wrong copy is the one somebody read.

  **What it does not change:** the converter did not emit a plausible, wrong ACL
  for a real firewall. It stopped and named the construct it could not handle.
  That is #53, #54 and #58 working on the first real file they have ever seen,
  and the strongest evidence yet that refusing rather than guessing was right.

  > **UPDATE, 23 August.** The example above no longer matches current
  > behaviour and is left as the historical record of what #78 measured, not
  > edited in place. The DHCP-WAN and undeclared-VPN-interface cases stopped
  > refusing the whole file: the rule(s) naming an unmodellable interface are
  > now skipped and named in `ConversionResult.skipped`, and every other
  > interface in the same file converts normally. Verified live on a
  > client-shaped file (one DHCP interface, one undeclared VPN interface, two
  > good interfaces): the two good interfaces converted and parsed cleanly
  > against real Batfish with zero problems, while the skipped list named
  > exactly the two excluded interfaces and why. What is still true: nothing
  > here is guessed. An unmodellable rule is still refused, individually,
  > just no longer at the cost of the whole file. The NAT decision and the
  > missing `<type>`/`<protocol>` question (#80) are unaffected by this and
  > remain open.

## 7a. The finding format (F-1) — the one contract

**`docs/finding-format.md` is authoritative.** It was agreed by all four team
members and supersedes any earlier schema discussion. Do not change it, or the
field vocabulary in `analysis/findings.py`, without full team agreement.

Every check returns a **list of findings**, each a dict with exactly these
fields: `id`, `check`, `severity`, `device`, `summary`, `evidence`
(`detail` + `source`), `status`.

The `status` field is safety-critical (**F-4**):

| `status` | Meaning | Dashboard shows |
|---|---|---|
| `found` | The check ran and found a problem | The finding |
| `none` | The check ran and found nothing | Green tick |
| `error` | The check **could not run** | Amber warning |

`none` and `error` must never look alike. "We checked and found nothing" and
"we could not check" are different claims, and conflating them is how a
security tool ends up telling a user they are safe when nobody looked.

Findings are built with the helpers in `analysis/findings.py`, which validate
every field — a malformed finding fails loudly in the check that made it
rather than quietly downstream.

## 7b. The pipeline (F-3) — how features plug together

`analysis/pipeline.py` is the shared backbone. It connects to Batfish, loads a
snapshot, runs the registered checks, and returns one combined list of
findings. The checks — the features that fit this contract — are:

```
analysis/checks/access_control.py     Arsh     (written — the template)
analysis/checks/routing.py            Ankeet   (written)
analysis/checks/policy_compliance.py  Shubham  (written)
```

A check is one file with one function, `run(bf: Session) -> list[dict]`, plus
one line in the `CHECKS` registry in `pipeline.py`. Checks do not connect,
load snapshots, or handle their own crashes — the pipeline isolates each one,
so a bug in one feature cannot take down the other three.

**After the checks run, post-processors refine the combined list**
(`POST_PROCESSORS` in `pipeline.py`, `refine(results) -> results`). That is how
`risk` sees every finding rather than a Batfish session. Two limits are
enforced there rather than documented: a post-processor may not downgrade a
`status="error"` finding, and may not drop one. A violation is restored *and*
reported.

```bash
python -m analysis.pipeline tests/fixtures/rtr-us5-secure
```

Synthetic test configs live in `tests/fixtures/` and **are** committed — they
are the single exception to the no-configs-in-git rule, because we invented
them and they describe nobody's real network. Real configs stay in the ignored
`configs/` folder.

**Two features are NOT checks**, and `analysis/checks/` says so too:
`change_impact` needs two snapshots and becomes `analyse_change(before, after)`;
`risk` needs the combined findings and becomes a post-processor. Neither goes
in `CHECKS`. See `docs/design/pipeline-feature-shapes.md`.

CI (`.github/workflows/tests.yml`) runs the suite on every pull request, on
Python 3.12 and 3.13. **It does not block a merge today, and that is now a
choice rather than a limitation.** Branch protection needs GitHub Pro or a
public repo — and this repository is public, so every setting is available to
us, free. Measured 27 August:

```
private    : False
visibility : public
GET /repos/ARSH871-bot/Netwise/branches/main/protection
   -> {"message":"Branch not protected"}
```

So a red cross is a signal rather than a gate **because nobody has turned the
gate on**, not because we cannot. What to enable is #245, and the measurement
there is worth reading before assuming the answer is "all of it": across 45
PRs merged since 20 August, requiring a review would have blocked **none**,
and `dismiss_stale_reviews` would **contradict** M-2 rule 2 by voiding an
approval on a merge-only push.

## 7c. Asking questions (US-11) — the other direction, and why it refuses

`ai/explain.py` goes **findings → English**: a finding already exists, produced
by a check that ran a specific Batfish question with parameters a human wrote.
`ai/query.py` goes **English → findings**, and something has to choose the query
first. That choice is more dangerous than a wrong finding, and
**`docs/design/query-grounding-problem.md` explains why — read it before
changing anything here.**

In one line: every other guard in this project checks that the *answer* is
grounded in the *query*. None of them check that the query was the right one. A
mistranslated question produces a real, evidenced, confidently wrong answer that
passes all of them.

So `answer_question(question, bf) -> dict` is built to refuse:

- **Intent is matched against a closed set, not inferred.** Three intents —
  reachability (`traceroute`), dead rules (`filterLineReachability`), undefined
  references (`undefinedReferences`). `testFilters` and `searchFilters` are
  deliberately unreachable: both need a filter name up front, and nobody asks a
  question that names an ACL.
- **No model is called, in either direction.** Not to classify the question, not
  to write the answer. Classifying with a model is guessing at intent in the one
  place guessing is worst; the answer text is built from Batfish's own
  disposition and path. This is why the whole feature is testable with no Ollama
  running.
- **Every parameter is resolved against the real snapshot.** The source must
  resolve to a device Batfish actually found (`analysis/snapshot.py`); the
  destination must be a literal IP or CIDR. Anything else is refused with a
  reason, not approximated.
- **The source becomes `@enter(device)`, never the bare device name** (#108,
  fixed in #141). A bare device name is a *node* location — traffic
  ORIGINATING at the device — which never traverses an inbound ACL. So the
  feature answered identically for a config that blocked the traffic and one
  that permitted everything, **both `grounded: True`**, which is the worst
  possible shape for a wrong answer: evidenced, confident, and reproducible.
  Measured after the fix, on two configs differing only in their ACL:

  ```
  rtr-us5-secure    -> No.  ... DENIED_IN
  rtr-us5-insecure  -> Yes. Traffic from rtr-us5 reaches 10.10.10.5.
  ```

  **Nothing in §7c's refusal design caught this**, and that is the lesson worth
  keeping: every guard here checks that the *answer* is grounded in the
  *query*, and this was a correct answer to the wrong query. The same trap hit
  `analysis/change_impact.py` the same week from the same cause — see its
  module docstring, which names the general shape: *a template must be able to
  observe the thing it claims to answer about.*
- **The translated question is always shown back** — `question_understood`. This
  is not decoration. It is the only thing in the design that lets the person who
  asked notice a mistranslation, which is what makes a narrow scope safe rather
  than merely limited. **If the UI ever hides or shrinks it, the safety argument
  goes with it.**

The return shape is three keys — `question_understood`, `answer`, `grounded` —
and it keeps F-4's distinction: a query that could not run comes back with
`grounded=False` and an answer saying so, never a confident sentence.

**Known and deliberate:** this is narrower than CLAUDE.md §4's own example. "Can
the guest network reach the finance server" is **refused**, because resolving a
plain-English name to an address needs interface enumeration the project does
not have. Refusing it is the correct behaviour today; widening it is future work
that must keep the refusal path intact.

## 8. Repository layout

**What each folder is _for_. Deliberately no build status here** — that lives in
§11, and duplicating it is how this section came to claim `ai/` was empty while
§11 correctly said it was done, one screen apart. One fact, one place.

```
analysis/   Layer 1 — Batfish orchestration
  findings.py     the F-1 format in code, with validation
  pipeline.py     connect, load snapshot, dispatch checks, guard ids
  checks/         one module per feature
  change_impact.py  shape C — analyse_change(before, after), NOT a check
ai/         Layer 2 — local LLM explanation and Q&A
web/        Layer 3 — FastAPI backend and dashboard
tests/      pytest suite + synthetic fixtures (committed, see §7b)
tools/      Standalone helpers, run by hand, not imported by the product
              make_traceability.py  regenerate docs/traceability.md from the repo
              pfsense_shape.py    describe an export's structure, never a value
              preflight.py        is this machine set up to run Netwise?
              stranger_config.py  measure the #87 policy gap on every fixture
docs/       Sprint records, design notes, evidence for reviews
configs/    Config files under test — GIT-IGNORED, never committed
```

Every script in `tools/` must run **both** documented ways, from the repository
root:

```bash
python -m tools.stranger_config      # module form
python tools/stranger_config.py      # script form
```

The two put different things on `sys.path`, so a tool that imports the product
package needs the `__package__` guard or the second form dies with
`ModuleNotFoundError`. #172 fixed that in `preflight.py`; it was still live in
`stranger_config.py` for as long as it had been fixed in the first — a fix
applied to the instance rather than the property. `tests/test_tools_invocation.py`
now enforces it across the whole folder, so the next tool added is covered on
the day it lands.

Run the tests from the repository root — they need neither Batfish nor Docker:

```bash
pytest tests/ -v
```

## 9. Tech stack

Python, pybatfish, Docker, Ollama (local LLM), FastAPI, GitHub (repo + Kanban
board for sprints).

FastAPI was chosen over Flask for auto-generated API docs (useful evidence in
reviews) and native async/streaming, which the chat pane will need.

## 10. Team and process

Studio 5 & 6 capstone, Graduate Diploma in Information Technology, Auckland
International Campus. Delivered in weekly SCRUM sprints.

- **Client / sponsor:** Senaka Amarakeerthi (Senior Lecturer) — uses their own
  network as the test case.

Each member owns a **vertical slice**: their own analysis, through the shared
format, to the screen. This replaced the earlier engine/frontend split.

| Member | Owns |
|---|---|
| **Arsh** | Access-control analysis + the shared pipeline + SCRUM Master |
| **Ankeet** | Routing analysis + the local AI assistant (Ollama) |
| **Shubham** | Policy-compliance + change-impact analysis |
| **Samika** | Risk prioritisation + the interface + secure upload |

## 11. Status — last updated 2026-08-13

> **⚠️ This section goes stale faster than anything else in the file.** It has
> been wrong about `main` repeatedly, in both directions — claiming work that
> had not landed, and calling finished work blocked. Every instance so far was
> the same cause: a fact recorded here *and* somewhere else, and only one of
> them updated. If a decision depends on this section, check the repo rather
> than trusting it:
>
> ```bash
> sed -n '/^CHECKS = {/,/^}/p' analysis/pipeline.py   # what actually runs
> ls -A ai/ web/                                       # what layers exist
> pytest tests/ -q                                     # what is tested
> ```
>
> Everything above section 11 is slow-moving and can be trusted. This section
> is a snapshot, and snapshots rot.

**Sprint 1 — complete.** Batfish installed and running; the five core questions
run and understood on bundled example configs. See `docs/sprint1/SPRINT1.md`.

**Sprint 2 — complete** (30 July – 5 August 2026). The output-schema question
that once blocked it is **settled**: the team agreed F-1 (see §7a). Do not
reopen it casually. The record is `docs/sprint2/SPRINT2.md`, written inside the
sprint rather than reconstructed after it.

**Sprint 3 — complete** (6–12 August 2026). Milestone closed at 8 of 8, tagged
`v0.3.0`. All five analysis features joined end to end, which first became true
on 8 August. The record is `docs/sprint3/SPRINT3.md`, and its closing section
was written the day after the sprint ended rather than reconstructed later.

**Sprint 4 — in progress** (13–19 August 2026). Scope is @shubhamkataria2005's
counter-proposal on #86, which Arsh accepted over his own: **#78 timeboxed to
item 1 with an explicit stop**, #16 split, #30 with A-2 raised on day 1. The
record is `docs/sprint4/SPRINT4.md`. **#87 is the open question against all of
it** and is deliberately unassigned.

**Five pull requests landed together on 17 August** — #141, #140, #143, #144,
#137 — taking `main` to 370 tests, CI green at `dba64f8`. That merge closed
#30 (`change_impact`) and #108 (the query-layer entry-location bug), and put
the `explanation_source` signal behind #109 without closing it. Merged as one
batch only after the combination was tested locally: each had a green tick
earned against a different `main`, which is precisely the §5a rule 3a case
that produced two red `main`s in two days.

**Releases exist now**, for the first time. `v0.1.0`, `v0.2.0` and `v0.3.0` were
tagged retroactively on 13 August, each on the last commit of that sprint's
*work* per `CONTRIBUTING.md` §5b, verified with the ancestry check the section
prescribes. Worth recording *why* they did not exist: the convention was written
down, reviewed, and its worked examples corrected by two people — and then never
performed. A documented practice standing in for a performed one, which is this
project's recurring failure family arriving through process rather than code.

### What is built and on `main`

| Piece | Owner | State |
|---|---|---|
| Shared pipeline (F-3) | Arsh | Done — connect, snapshot, parse check, dispatch, error isolation, duplicate-`id` guard |
| F-1 format in code | team | Done — `analysis/findings.py`, validated |
| `access_control` check | Arsh | Done — four analyses: `testFilters`, `searchFilters`, `filterLineReachability`, `undefinedReferences` |
| `policy_compliance` check | Shubham | Done — see `docs/policy-rules.md` |
| `routing` check | Ankeet | Done — `traceroute`-based reachability, two-router fixtures |
| **AI explanation layer** | Ankeet | Done — `ai/explain.py` + `ai/Modelfile` (Warden, local Ollama). Explains one finding, and **never raises**: an unreachable Ollama, an unbuilt model, or a finding with no real evidence all degrade to deterministic text (#52) |
| **AI explanation on screen** | Ankeet + Samika | Done (#56, closing #31). `/api/findings` attaches an `explanation` to every `status="found"` finding, **not** an F-1 field, added downstream of validation so the contract is untouched. Since #109/#143, also attaches `explanation_source` (`"model"` or `"fallback"`), same reasoning, so the dashboard can eventually stop labelling deterministic fallback text as AI-authored, which it still does today (#109 stays open until the byline itself changes) |
| **`risk` scoring** | Samika | Done (#60) — `POST_PROCESSORS`, ruleset in `docs/severity-rules.md`. Re-rates severity and sorts worst-first; the two limits are enforced in `pipeline.run_post_processors()`, not trusted |
| Dashboard + secure upload | Samika | Done — real findings on screen since #39 |
| PF Sense conversion | Ankeet | Done — `analysis/pfsense_convert.py`, and **hardened**: refuses config injection and path traversal via free-text fields (#53), an unbound ACL / empty rule set / unvalidated addressing (#54), and ambiguous rule order (#58, closing #47). See §7 |
| **`change_impact`** | Shubham | Done (#140, merged 17 August) — `analysis/change_impact.py`, `analyse_change(before, after)`. Shape C: **not** in `CHECKS`, and both the module docstring and the registry comment say so. Pairs `compareFilters` (which ACL *lines* moved) with `differentialReachability` (which *traffic* changed fate), because a changed line that moves no traffic is noise and moved traffic with no changed line is the case a filter diff alone misses. Direction-aware per `docs/policy-rules.md`: opening `high`, tightening `medium`, both reported |
| Test suite | team | Needs neither Batfish nor Ollama. For the count, run it — a number written here rots the next time anyone adds a test |

**All five features are now on `main` together**, which first became true on
8 August. **The sixth, `change_impact`, joined them on 17 August.**

### What is NOT built

| Piece | Owner | Note |
|---|---|---|
| **A way for the user to state their own policy** | unassigned | **The biggest gap in the product** (#87). Every policy assertion is hardcoded to our fixtures. See below |
| AI: natural-language questions | Ankeet + Samika | **Backend built** (#66) and **now actually crosses the ACL** (#108, fixed in #141) — `ai/query.py` + `/api/ask`. The dashboard wiring is Samika's half and is not done. See §7c |
| The AI byline tells the truth | Samika | #109. `/api/findings` now carries `explanation_source` (#143), but `style.css`'s `content: "AI explanation"` is still unconditional, so on any machine without Ollama the dashboard attributes deterministic text to a model. The signal exists; the label has not changed |

**The policy is ours, not the user's — but one check now takes theirs.**
`access_control` and `policy_compliance` name `rtr-us5`; `routing` names
`rtr-hq`/`rtr-branch`.

**What exists now.** `analysis/policy.py` loads and validates a user policy
(#173), and since #87's vertical slice `policy_compliance` actually reads it:

```bash
python -m analysis.pipeline my-configs/ --policy my-policy.json
```

The rules travel via `analyse(policy=...)`, which installs them and clears
them in a `finally` — **not** by widening `run(bf)`, because F-3 fixes that
signature and changing it needs all four. Every finding says whose policy
produced it, because a finding from the user's rules and one from our example
look identical on screen otherwise.

Measured with `tools/stranger_config.py`, which now carries a third column:

```
                            ours        stranger    + their policy
                           f/n/e      our policy             f/n/e
TOTAL                   12 /  3 /  7     3 /  0 / 15       8 /  1 / 20
```

**Policy-driven detections on a network that is not ours: 3 → 8.**

**What is still missing.** `access_control` and `routing` still ignore a
supplied policy, and there is no UI — a user can only pass `--policy` on the
command line. So the gap is narrowed for one check, not closed.

The original measurement, still true for a user who supplies nothing, on
`rtr-us5-messy` by renaming the device and changing nothing else:

```
our device name      6 findings   access_control + policy_compliance
a stranger's name    3 findings   access_control only
```

**One rename removes half the detection.** What survives is the two analyses
that need no policy — dead rules and undefined references. The scoping work
(#29, #45, #50) made that *honest*, not solved: the user is told "could not
check" rather than shown a green tick. It outranks even #78, and unlike #78 it
waits on nobody outside the team. Full ordering in
[`docs/design/product-roadmap.md`](docs/design/product-roadmap.md).

### End to end — what is joined, and what is not

**The product runs.** Uploading a config stages it; clicking **Scan Now** runs
the analysis and puts real findings on screen. The upload no longer analyses by
itself — #82 separated them, so a staged file is never confused with a checked
one, and stale findings are cleared on upload rather than left sitting under a
success message for a different network. `web/main.py` stages the upload;
`/api/findings` calls `analysis.pipeline.analyse()`. Mocks are served only until
the first upload. Verified against opposite fixtures:

```
upload rtr-us5-insecure  ->  5 problems found, 1 could not check
upload rtr-us5-secure    ->  0 problems, 2 checked clean, 1 could not check
```

The remaining "could not check" is honest rather than noise: it is the routing
assertions saying, once, that they are written about `rtr-hq`/`rtr-branch` and
so do not apply to a single-router upload. Every check is now scoped to the
devices actually present — `access_control` (#45), `policy_compliance` (#50),
`routing` (#29) — so an inapplicable statement is reported once, together,
instead of one amber card each. It stays a `status="error"`: not applicable is
not the same as checked and clean.

**The last link closed on 8 August.** The AI explanation now renders: #56 joined
`ai/explain.py` to the dashboard slot built in #40, closing #31. Three rules are
enforced in that join rather than assumed:

- only `status="found"` findings are explained — the model is never *called* for
  a `none` or an `error`, so a card that could not be checked can never acquire
  prose that reads as if it had been
- the explanation is an extra key on the JSON response, **not** a new F-1 field,
  so `analyse()` still returns and validates exactly the shape it always has
- one explanation failing cannot take down the response, and the frontend
  inserts it with `textContent`, never `innerHTML`

Nothing in Layer 1 or 2 is now unjoined. What remains is features, not plumbing.

### Settled — do not reopen without the team

- **Three shapes for pipeline features.** `docs/design/pipeline-feature-shapes.md`,
  **ADOPTED**, all four signatures. Producers keep `run(bf) -> list[dict]`;
  `risk` is a post-processor; `change_impact` is a separate entry point and
  **must not** be registered in `CHECKS`. The post-processor stage is built —
  see §7b. **All three shapes now exist in code** (#140, 17 August), so this is
  a decision that survived contact rather than one still waiting to be tested:
  `change_impact` was written to the shape agreed before it existed, and
  needed no amendment to fit.
- **Severity ownership.** Checks set a default; `risk` may re-rate; **`risk`
  must never downgrade a `status="error"` finding, or drop one.** Both limits
  are enforced in `pipeline.run_post_processors()` rather than trusted. Only
  the `docs/finding-format.md:36` wording still needs changing, and that is an
  F-1 edit needing all four — see below.
- **F-1 amendment A-1 — RATIFIED by all four** (#59, merged 10 August). Severity
  is set by the check as a **default**, `risk` may **re-rate** it, and the AI
  **never** sets it. The ratification table lives in `docs/finding-format.md`,
  because "agreed" should be a fact anyone can check rather than something
  inferred from a merge. This closes the last outstanding piece of the shapes
  decision.
- **F-1 amendment A-2 — RATIFIED by all four** (#102, raised and written by
  Shubham on day 1 of Sprint 4). `change_impact` moves from the `PC-` prefix to
  its own **`CH-`**, so `id` uniqueness *across* checks is now structural rather
  than a convention split over two documents. Done before the code existed, so
  no finding changed id — free now, a migration later.

  **The duplicate-`id` guard stays, and deleting it would be a mistake.** A
  distinct prefix removes that particular pair; uniqueness *within* one check is
  still only discipline, because `make_finding()` takes `number` as a required
  argument and both sentinel helpers default to 0. One check emitting a clean
  sentinel and an error sentinel in the same run still collides with itself.
  Defence in depth, not duplication.
- **PF Sense rule order** (issue #47, closed by #58, **modelled in #104, merged
  13 August**). §7 above is updated to match.

  With **zero** quick rules the converter reverses the list,
  which is provably the same decision as last-match-wins for every flow, and
  converts exactly the pair §7 documents as the measured failure instead of
  refusing it. Verified against Batfish, not just unit tests. Mixed
  quick/non-quick lists still refuse. This was the client's whole rule set, so
  it removes #78's headline blocker.
- **PF Sense rule order, original refusal** (issue #47, closed by #58). The converter refuses to
  convert when two overlapping rules disagree and the earlier is not `quick`,
  instead of silently mistranslating them. See §7. What remains is a **client
  question, not a decision of ours**: whether the real export uses `quick`.

### Open decisions — do not settle these alone

1. **Parse strictness.** *(Was item 2; item 1 is settled — see below.)*
   `find_parse_problems()` currently treats any status
   other than `PASSED` as fatal, including `PARTIALLY_UNRECOGNIZED`. Safe for
   test configs, likely too strict for real ones. The fix is to run the checks
   and attach a loud "results may be incomplete" finding — never to ignore it.

   It used to carry a second argument: that it was *the only thing catching a
   mis-converted PF Sense config*. **That is no longer true** — #58 catches
   ambiguous rule order in the converter itself, where the fault actually is.
   Relaxing parse strictness is now a question about parse strictness alone,
   which is the shape it should always have had.
