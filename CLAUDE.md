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

  **Read this before showing the client their own config.** PF Sense evaluates
  rules *last-match-wins* unless a rule is marked "quick"; the converter treats
  them as *first-match-wins*, like a Cisco ACL. Our fixture is written so both
  models agree, so the tests cannot catch the difference. A real export that
  relies on last-match semantics between overlapping rules **converts to
  something that parses cleanly and decides differently from the real
  firewall** — findings would be confidently wrong about a network that does
  not behave that way. Tracked as an open risk, not a bug: see the module
  docstring and the linked issue.

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
Python 3.12 and 3.13. It cannot block a merge — branch protection needs GitHub
Pro or a public repo — so a red cross is a signal rather than a gate.

## 8. Repository layout

**What each folder is _for_. Deliberately no build status here** — that lives in
§11, and duplicating it is how this section came to claim `ai/` was empty while
§11 correctly said it was done, one screen apart. One fact, one place.

```
analysis/   Layer 1 — Batfish orchestration
  findings.py     the F-1 format in code, with validation
  pipeline.py     connect, load snapshot, dispatch checks, guard ids
  checks/         one module per feature
ai/         Layer 2 — local LLM explanation and Q&A
web/        Layer 3 — FastAPI backend and dashboard
tests/      pytest suite + synthetic fixtures (committed, see §7b)
docs/       Sprint records, design notes, evidence for reviews
configs/    Config files under test — GIT-IGNORED, never committed
```

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

## 11. Status — last updated 2026-08-06

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

**Sprint 3 — starting.** Not yet planned or recorded. Anything below describing
work in flight is Sprint 2 carry-over until a `docs/sprint3/` record exists.

### What is built and on `main`

| Piece | Owner | State |
|---|---|---|
| Shared pipeline (F-3) | Arsh | Done — connect, snapshot, parse check, dispatch, error isolation, duplicate-`id` guard |
| F-1 format in code | team | Done — `analysis/findings.py`, validated |
| `access_control` check | Arsh | Done — four analyses: `testFilters`, `searchFilters`, `filterLineReachability`, `undefinedReferences` |
| `policy_compliance` check | Shubham | Done — see `docs/policy-rules.md` |
| `routing` check | Ankeet | Done — `traceroute`-based reachability, two-router fixtures |
| **AI explanation layer** | Ankeet | Done — `ai/explain.py` + `ai/Modelfile` (Warden, local Ollama). Explains one finding; the natural-language-question direction is not started |
| Dashboard + secure upload | Samika | Done — real findings on screen since #39 |
| PF Sense conversion | Ankeet | Done — `analysis/pfsense_convert.py`. **Read the rule-order caveat in §7** before using it on a real export |
| Test suite | team | Needs neither Batfish nor Ollama. For the count, run it — a number written here rots the next time anyone adds a test |

### What is NOT built

| Piece | Owner | Note |
|---|---|---|
| `risk` scoring | Samika | Not started. **No longer blocked** — the post-processor stage it plugs into is built (#44) and `POST_PROCESSORS` is waiting for one line. See §7b |
| `change_impact` | Shubham | Not started, and does not fit the `run(bf)` contract |
| AI: natural-language questions | Ankeet | Not started — the other half of Layer 2 |
| AI explanation on screen | Samika + Ankeet | Slot built (#40); `explain()` not yet called — #31 |

### End to end — what is joined, and what is not

**The product runs.** Uploading a config produces real findings on screen, as
of 5 August (#39). `web/main.py` stages the upload and calls
`analysis.pipeline.analyse()` on it; mocks are served only until the first
upload. Verified against opposite fixtures:

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

**One link is still open: the AI explanation does not render.** `ai/explain.py`
works and the dashboard has a slot for it (#40), deliberately marked *"not
generated yet"* so a placeholder can never be mistaken for model output. Joining
those two is #31, and it is now a small job rather than a redesign.

### Settled — do not reopen without the team

- **Three shapes for pipeline features.** `docs/design/pipeline-feature-shapes.md`,
  **ADOPTED**, all four signatures. Producers keep `run(bf) -> list[dict]`;
  `risk` is a post-processor; `change_impact` is a separate entry point and
  **must not** be registered in `CHECKS`. The post-processor stage is built —
  see §7b.
- **Severity ownership.** Checks set a default; `risk` may re-rate; **`risk`
  must never downgrade a `status="error"` finding, or drop one.** Both limits
  are enforced in `pipeline.run_post_processors()` rather than trusted. Only
  the `docs/finding-format.md:36` wording still needs changing, and that is an
  F-1 edit needing all four — see below.

### Open decisions — do not settle these alone

1. **`change_impact` needs its own ID prefix.** It shares `PC` with
   `policy_compliance`, so their findings collide.
   `pipeline.duplicate_id_findings()` detects it; only a distinct prefix makes
   it impossible. Amending F-1 needs all four members.
2. **The F-1 wording on severity.** `docs/finding-format.md:36` still says
   severity is "assigned by Samika's rules, not by the AI". The rule agreed
   above is subtly different — checks default it, `risk` may re-rate. The
   behaviour is settled; the sentence is not.
3. **Parse strictness.** `find_parse_problems()` currently treats any status
   other than `PASSED` as fatal, including `PARTIALLY_UNRECOGNIZED`. Safe for
   test configs, likely too strict for real ones. The fix is to run the checks
   and attach a loud "results may be incomplete" finding — never to ignore it.
   **This is also the only thing catching a mis-converted PF Sense config**, so
   relaxing it has a consequence beyond convenience — see §7 and issue #47.
4. **PF Sense rule order** (issue #47). The converter assumes first-match-wins;
   PF Sense is last-match-wins unless a rule is marked `quick`. Our fixture is
   correct under both, so the tests cannot catch the difference.
