# Current state audit

**Measured 31 August 2026 against `main` at `c9ee421`.** Deliverable 1 of the
production readiness brief.

Every claim below was produced by running a command in this repository. Where a
thing could not be verified, it says so instead of guessing — which is the same
rule the product itself follows.

---

## 1. Method, and what this audit can and cannot see

```bash
pytest tests/ -q                     # 1030 passed, 8 skipped
pytest tests/ --collect-only -q      # 1038 collected
ruff check .                         # All checks passed
gh api repos/ARSH871-bot/Netwise     # visibility, protection
```

Available and used: the full test suite, `ruff`, real Batfish in Docker, real
Ollama with `netwise-warden` built, Chrome via Playwright, and the GitHub API
for issue/PR/milestone state.

**Not verified here:** behaviour on any real production network. Every
published result is on synthetic configs we wrote. `docs/evaluation.md` already
says so and that has not changed.

---

## 2. Source-of-truth hierarchy

Adopted as written in the brief, because it is correct and this project has
been bitten repeatedly by the opposite order:

1. **Current code and executable tests**
2. **Current contracts** — `docs/finding-format.md`, `analysis/findings.py`,
   `docs/architecture.md`
3. **Current operating guidance** — `README.md`, `docs/user-guide.md`,
   `SECURITY.md`
4. **Historical design, sprint and roadmap documents** — context, never proof

`CLAUDE.md` §11 carries its own warning to this effect and has still been wrong
in both directions. Two false claims about team agreement were found and
corrected on 31 August alone.

---

## 3. Where the brief itself is stale or wrong

The brief was written from a ZIP with no git history and says so. Three of its
factual claims do not survive measurement, and they are recorded here first
because an audit that only checks the product and not its own inputs is doing
half the job.

| Brief's claim | Measured | Verdict |
|---|---|---|
| "769 statically discoverable Python tests" | **1038 collected**, 1030 passing | **stale by 269** |
| "48 Python test modules" | 48 | confirmed |
| "seven JavaScript render harnesses" | 7 | confirmed |
| "`/api/findings` returns mock findings **and a report can export them**" | true, but the report is **labelled** | **partly wrong — see §5** |

Everything else it asserts about the current code is confirmed below.

---

## 4. Confirmed: the P0 gaps, with file-and-line evidence

### 4.1 Single mutable workspace — confirmed

```
web/main.py   SNAPSHOT_NAME  = "current"          one shared Batfish namespace
              CONFIG_ROOT    = web/uploaded_configs
              CONFIGS_DIR    = CONFIG_ROOT/current/configs
              POLICY_PATH    = CONFIG_ROOT/current/policy.json
web/main.py:836   shutil.rmtree(CONFIGS_DIR)      an upload destroys the previous
```

Three mutable process globals: `_uploaded`, `_explanation_cache`,
`_analysis_cache`. There is no project, snapshot or run identity of any kind —
a second concurrent user would overwrite the first's configuration and read
their cached findings.

**Accurate, and the highest-value gap on the list.**

### 4.2 Single-file upload — confirmed

```
async def upload_config(file: UploadFile)
'List[UploadFile]' present in web/main.py:  False
```

Batfish and `analysis/pipeline.py` both model multi-device snapshots — the
committed `multi-device-10` fixture has ten. **Only the web upload is
single-file.** That makes this a UI/API gap rather than an engine gap, which
lowers its cost considerably.

### 4.3 Incomplete policy coverage — confirmed

```
policy_compliance   reads a user policy   (rules_in_use / active_policy)
access_control      does NOT
routing             does NOT
```

This is issue **#87**, the largest open gap in the product and already tracked.
Since **#261** the two checks that ignore a policy now *say so*
(`AC-005 [error] "1 supplied rule(s) for this check were not read"`), which
makes the gap visible rather than smaller.

> **UPDATE, 12 September 2026 — #87 is closed, and this block is left as the
> record of what 31 August measured rather than edited in place.**
>
> `access_control` reads a user policy since #316 and `routing` since #319, so
> the table above now reads "reads a user policy" on all three rows. The #261
> cards are gone too: a check that reads your rules and also says it did not
> read them makes two contradictory claims, and one of them had to go.
>
> Re-measured with `python -m tools.stranger_config`: 3 policy-driven
> detections on a stranger's network became 13, of which 3 are an artefact of
> rebinding our two-router routing assertions onto a single router — so the
> comparable figure is **10**.
>
> What #87 did **not** close: `access_control.GUARANTEES`. The policy format
> cannot express a whole flow space, so those assertions remain ours.

### 4.4 No production deployment boundary — confirmed

```
Dockerfile           ABSENT
docker-compose.yml   ABSENT
pyproject.toml       ABSENT
logging imports      0 files across web/, analysis/, ai/
health endpoint      none
```

`SECURITY.md`, `docs/architecture.md` and `docs/user-guide.md` **do** exist —
the brief lists them in its hierarchy and does not claim otherwise.

**Zero logging is the sharpest item here.** Not one module imports `logging`.
A failure reported by the client after a demo currently leaves no trace to
investigate.

### 4.5 The local-AI promise can be bypassed — confirmed

`ai/explain.py` honours `OLLAMA_HOST` in `_ollama_endpoint()` with no
loopback check and no allow-list. Setting it to a remote address would send
finding evidence — which is derived from customer configuration — off the
machine, silently, while every document still promises local-only.

**This is the most serious item in the whole brief**, because it contradicts
CLAUDE.md constraint 1 rather than merely falling short of a target.

### 4.6 Reproducibility — confirmed

```
requirements.txt    == pinned:  pybatfish
                    >= floor:   pandas, ollama, fastapi, uvicorn[standard],
                                python-multipart, pytest
Batfish image       batfish/allinone     (tag, no digest)
CI                  advisory; branch protection unavailable while the
                    repository is private
```

---

## 5. Where the brief overstates: the demo-data P0

The brief lists *"Demo data appears before upload"* as P0 with the outcome
*"Default empty state"*, implying a truthfulness failure. Measured:

```
GET /api/report?format=html   (nothing uploaded)

  <h1> Netwise analysis report
  <p>  example findings (no upload yet) · generated 2026-08-31 07:57 UTC
```

**The report says what it is, in its subtitle, above the findings.** So the
F-4 half of this — a document that could be mistaken for a real analysis — is
already handled.

What remains is genuinely a UX issue: six fabricated findings render on a
dashboard a first-time user has not yet uploaded to, and the *screen* is less
explicit about it than the *report* is. Worth fixing, **not P0**, and not for
the reason given.

Recorded because acting on a P0 that is already half-solved would spend effort
on the solved half.

---

## 6. What the brief cannot see, and it matters

It was written from a ZIP without `.git`, so it has no view of:

- **Issue and PR state.** #87, #234, #245, #266, #267 already track five of the
  gaps it identifies. Filing them again would duplicate work the team has
  already scoped.
- **What landed recently.** 62 PRs merged between 20 and 31 August; the suite
  went 384 → 1030 in that window.
- **The team's own contracts.** F-1 amendments A-1/A-2/A-3, the M-1/M-2 merge
  rules, and their ratification state.

---

## 7. The structural tension the brief does not know about

`CLAUDE.md` constraint 4 is a hard project constraint:

> **Readable code.** All four team members must be able to read and explain any
> part of it in a project review. Keep it simple and well-commented; prefer the
> obvious solution over the clever one.

The brief's target architecture introduces a durable domain model, a job queue
with workers, cancellation and timeouts, per-run Batfish namespaces, tenant
isolation, RBAC and audit events. **Every one of those is correct for a
production service and in tension with constraint 4 for a four-person capstone
that is assessed on explainability.**

This is not an argument against the brief. It is an argument that the sequence
matters more than the list, and that some items on it may be out of scope for
this team in this timeframe — which is a decision for the four members and the
client, not one to make by adopting a document.

---

## 8. Recommended order, on the evidence above

1. **Bind local inference (§4.5).** It contradicts a stated non-negotiable
   constraint, and the fix is small: default to loopback, refuse a remote host
   unless a visible opt-in is set.
2. **Add structured, redacted logging (§4.4).** Zero today. Nothing else on
   this list can be debugged in the field without it.
3. **Pin dependencies and the Batfish image by digest (§4.6).** Cheap,
   reproducible, and it is the precondition for any integration test lane
   meaning anything.
4. **Multi-file upload (§4.2).** The engine already does this; only the
   API/UI does not.
5. **Run identity and isolation (§4.1).** The largest and most valuable, and
   the one that most needs a team decision about scope first.

Policy coverage (#87) sits outside this ordering because it is already the
team's tracked priority and is a product-capability gap rather than a
production-readiness one.

---

## 9. Status of this document

**Current audit.** Supersedes nothing; contradicted by nothing at the time of
writing. Re-derive rather than quote:

```bash
pytest tests/ -q
gh api repos/ARSH871-bot/Netwise --jq '.private, .visibility'
python -m tools.stranger_config
```

If this file disagrees with those, this file is the bug.
