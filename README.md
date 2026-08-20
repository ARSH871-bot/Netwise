# Netwise

**Network Configuration Analysis and Risk Evaluation Tool**

Netwise reads exported network device configuration files, finds security
misconfigurations, and explains them in plain English. It runs entirely
offline — it never connects to, scans, or modifies a live network.

> Studio 5 & 6 capstone project — Graduate Diploma in Information Technology,
> Auckland International Campus.

---

## Why

Routers, switches and firewalls are governed by long, messy configuration
files. Small mistakes hide in them: a rule that accidentally exposes an
internal system, a rule contradicting another, a rule that silently never
takes effect. These misconfigurations are a leading cause of real breaches and
are very hard to catch by reading the files manually.

Netwise catches them automatically and explains them in language a human can
act on.

## How it works

```
config files  ->  Batfish  ->  local LLM  ->  dashboard
                (analysis)   (explanation)   (upload + chat)
```

1. **Batfish** builds an offline model of the network from the config files and
   runs security analyses against it.
2. A **locally hosted LLM** (via Ollama) turns those technical findings into
   plain-English explanations with a risk rating.
3. A **two-pane dashboard** lets you upload configs on one side and ask
   questions in plain English on the other.

Every explanation is grounded strictly in real Batfish output. The AI never
invents network behaviour.

## Status

🚧 **In development.** The product runs end to end: upload a config, click
**Scan Now**, and real findings appear with plain-English explanations, sorted
worst-first. All five analysis features are joined; what remains is features
rather than plumbing.

**The per-feature breakdown lives in [`CLAUDE.md`](CLAUDE.md) §11 and nowhere
else.** It used to be duplicated here, and this copy went stale — it still
described uploading as the thing that runs the analysis, months after #82
separated staging a file from scanning it. Every staleness bug this project has
had came from one fact living in two places with only one copy updated, so the
second copy is gone rather than merely corrected.

For what is *not* built and in what order, see
[`docs/design/product-roadmap.md`](docs/design/product-roadmap.md).

## What Netwise cannot do yet

Stated here rather than buried, because the headline above is easy to read as a
larger claim than it is.

**The security policy is currently ours, not yours.** Two of the three analyses
check assertions written against this project's own test fixtures — that a
particular device denies a particular flow, and so on. There is **no way to
supply your own policy**: no file format, no loader, no interface. Measured, on
one config with only the device name changed:

```
our device name      6 findings   access-control + policy-compliance
a stranger's name    3 findings   access-control only
```

So on a network that is not ours, Netwise reports **dead ACL rules** and
**references to structures that do not exist** — both genuinely useful, and
both a long way short of the description at the top of this file. Everything
else says, honestly, "could not check". Tracked as
[#87](https://github.com/ARSH871-bot/Netwise/issues/87); it is the single
largest gap in the product.

**Two further limits worth knowing before you try it:**

- **PF Sense configs may be refused.** The converter handles interfaces and
  filter rules, including **multi-interface rule sets** — each interface gets
  its own ACL, checked independently — and it **models** PF Sense's
  last-match-wins order rather than refusing it wherever it can do so exactly
  (#104). It **refuses rather than guesses** on NAT, aliases, VPN, IPv6,
  interfaces with no static address, interfaces named by a rule but never
  declared, and rule orders it cannot model exactly. A real client export is
  still refused, on the last two of those.
- **Nothing has been verified against a real production network.** Every
  published result is on synthetic configs we wrote, which is a much weaker
  claim than it sounds — see [`docs/evaluation.md`](docs/evaluation.md), whose
  second half is about exactly this.

Sprint records live in [`docs/`](docs/): [Sprint
1](docs/sprint1/SPRINT1.md), [Sprint 2](docs/sprint2/SPRINT2.md), [Sprint
3](docs/sprint3/SPRINT3.md).

## Requirements

- **Git**, to clone the repository.
- **Docker** (for the Batfish container).
- **Python 3.12 or 3.13** — the two versions CI actually runs. Earlier versions
  may work and are untested, which is not the same thing.
- **Ollama** (optional), for the local LLM that writes the plain-English
  explanations. Install it from <https://ollama.com/download>, then build the
  model once:

  ```bash
  ollama create netwise-warden -f ai/Modelfile
  ```

  That model is built on `llama3.2:3b`, so the first build pulls roughly **2 GB**
  over the network. Budget the time and the disk before a demo.

  **Only the explanation layer needs it.** The analysis pipeline and the whole
  test suite run without it. What you lose is stated rather than hidden:
  **without Ollama the dashboard shows deterministic fallback text**, labelled
  *"Plain-English summary"* instead of *"AI explanation"*, so nothing on screen
  claims a model wrote something a model did not. `tools/preflight.py` reports
  the same thing before you start.

## Getting started

**1. Clone the repository and enter it:**

```bash
git clone https://github.com/ARSH871-bot/Netwise.git
cd Netwise
```

Every command below is run from this folder — the repository root. Several of
them import Netwise's own packages, so running them from elsewhere fails.

**2. Create and activate a virtual environment:**

```bash
python -m venv .venv

source .venv/bin/activate      # macOS / Linux
.venv\Scripts\activate        # Windows (PowerShell or CMD)
```

Not optional housekeeping. Activating it also puts `pytest` and `uvicorn` on
your PATH, which is what makes the short forms in steps 7 and 8 work; without
it those commands may not be found even though the packages are installed.

**3. Start Batfish** (first run pulls the image, which takes a few minutes):

```bash
docker run -d --name batfish -p 9997:9997 -p 9996:9996 -p 8888:8888 batfish/allinone
```

**4. Install the Python dependencies:**

```bash
pip install -r requirements.txt
```

That is everything needed to run Netwise and its test suite. There is also a
`requirements-dev.txt`, holding **playwright** for driving a real browser
against the dashboard. You only need it if you are doing UI testing; normal
use and `pytest tests/` do not:

```bash
pip install -r requirements-dev.txt   # optional, UI testing only
```

**5. Check your environment is actually ready:**

```bash
python -m tools.preflight
```

Worth doing before the first analysis rather than after it fails. It reports
Python, packages, **package versions**, the Docker daemon, the Batfish
container and the Batfish service separately — because they fail separately,
and `docker start batfish` cannot fix a stopped Docker daemon. Optional pieces
(Ollama, Node) are reported as optional, with what their absence costs, and
never fail the check.

**"Packages" and "package versions" are two checks on purpose.** A package
that imports is not necessarily the version `requirements.txt` declares, and
CI installs that file on a clean machine every time. If the two disagree, your
local test run is not testing what CI tests — which is how the same suite came
to be green on pandas 2.x locally and pandas 3.x in CI, on the same commit.

Exit code is 0 when everything required works, so it is safe to put in front of
a demo script.

**6. Run an analysis** on one of the bundled synthetic configs:

```bash
python -m analysis.pipeline tests/fixtures/rtr-us5-insecure
```

You should get JSON findings describing the deliberate flaw in that fixture.
The first run after starting the container is slow — Batfish's engine has to
warm up and parse the configs. That is normal, not a hang.

**7. Start the dashboard:**

```bash
python -m uvicorn web.main:app --reload
```

(`uvicorn web.main:app --reload` works too once the virtual environment from
step 2 is active. The `python -m` form is written here because it works either
way, which matters on Windows where the short form is frequently not on PATH.)

Then open <http://127.0.0.1:8000>. API documentation is at `/docs`.

Upload a config, then click **Scan Now**. Those are two steps on purpose:
uploading only *stages* the file, so a file that is merely present is never
mistaken for one that has been checked, and any previous findings are cleared
the moment you upload rather than left sitting under a fresh success message
describing a different network.

**8. Run the tests** (these need neither Batfish nor Docker):

```bash
python -m pytest tests/ -v
```

(Again, plain `pytest tests/ -v` works with the virtual environment active.)

Two test files drive the real dashboard JavaScript through a small Node shim.
**Without Node installed they skip rather than fail** — and a skipped test looks
identical to a passing one in pytest's summary line, so the suite would read
green while the dashboard's rendering rules went unchecked. `tools/preflight.py`
reports whether Node is present for exactly this reason. CI installs it
explicitly rather than relying on the runner image happening to ship it.

## Repository layout

| Path | Contents |
|---|---|
| `analysis/` | Batfish orchestration — the pipeline, the finding format, one module per check, the PF Sense converter, and snapshot helpers |
| `ai/` | Layer 2 — `explain.py` turns a finding into plain English; `query.py` turns a plain-English question into a grounded Batfish answer; `Modelfile` defines the model `explain.py` calls |
| `web/` | FastAPI backend and dashboard frontend |
| `tests/` | Test suite, plus synthetic configs used as fixtures |
| `docs/` | Sprint records, the finding contract, design notes |
| `configs/` | Real config files under test — **git-ignored, never committed** |

## A note on data

No network configuration data is committed to this repository, and none is ever
sent to a cloud service. `configs/` and common config file extensions are
git-ignored by design.

## Usage

**Analyse a config folder from the command line:**

```bash
python -m analysis.pipeline <folder>
```

The folder is the snapshot root; device files live one level down, in a
`configs/` subfolder inside it. Seven synthetic examples are included, each
demonstrating something different:

| Fixture | What it demonstrates |
|---|---|
| `rtr-us5-secure` | A clean config — reports no issues |
| `rtr-us5-insecure` | A blanket `permit ip any any` — reports real findings |
| `rtr-us5-messy` | Dead ACL rules and a reference to an ACL that does not exist |
| `routing-secure` | Two routers with a working route between them |
| `routing-missing-route` | The same pair with the route removed |
| `unparseable` | A file Batfish cannot read — reports an error, not a clean result |
| `pfsense-source` | A PF Sense `config.xml`, for the converter rather than the pipeline |

All live under `tests/fixtures/`.

**From Python:**

```python
from analysis.pipeline import analyse

findings = analyse("tests/fixtures/rtr-us5-insecure")
```

`analyse()` returns a list of findings in the shared format described in
[`docs/finding-format.md`](docs/finding-format.md). It does not raise when
something goes wrong operationally — an unreachable Batfish or an unreadable
config comes back *as a finding*, so a failure is always reported rather than
lost.

**Compare two configs — what would this change actually do?**

```bash
python -m analysis.change_impact <before-folder> <after-folder>
```

```python
from analysis.change_impact import analyse_change

findings = analyse_change("tests/fixtures/rtr-us5-secure",
                          "tests/fixtures/rtr-us5-insecure")
```

Every other analysis reads **one** config and says whether it is bad. This
reads **two** and says what moved — asked before the change reaches a real
device. Try it in both directions on the fixtures above; they are not the same
news:

```
secure -> insecure    2 findings, high     something was opened
insecure -> secure    2 findings, medium   something was closed
secure -> secure      no change detected
```

A change that **opens** traffic is graded higher than one that closes it, not
because closing is safe but because opening is *silent* — nothing breaks,
nobody complains, and it is still there at the breach. A tightening is loud
within minutes, and is reported rather than filed as an improvement, because
it is also how you break DNS for a whole site.

This is **not** one of the pipeline checks and does not appear in `CHECKS` —
it needs two snapshots, and a check is handed one. See
[`docs/design/pipeline-feature-shapes.md`](docs/design/pipeline-feature-shapes.md).

## Team

Each member owns a vertical slice: their own analysis, through the shared
finding format, to the screen.

| Name | Owns |
|---|---|
| Arsh | Access-control analysis, the shared pipeline, SCRUM Master |
| Ankeet | Routing analysis, the local AI assistant |
| Shubham | Policy-compliance and change-impact analysis |
| Samika | Risk prioritisation, the interface, secure upload |

Client / sponsor: **Senaka Amarakeerthi**, Senior Lecturer.

## Licence

**[Apache License 2.0](LICENSE).** See [`NOTICE`](NOTICE) for attribution,
third-party components and the AI-assistance declaration.

Apache 2.0 rather than MIT for three reasons that are specific to this project:
it is the licence of [Batfish](https://github.com/batfish/batfish) and
`pybatfish`, the two things Netwise exists to orchestrate; it carries an
**express patent grant** (§3), which MIT and BSD do not; and its warranty and
liability disclaimers (§7, §8) are the most explicit of the permissive
licences, which matters for a tool that reports on whether a network is safe.

**A clean result from Netwise is not a statement that a network is secure.**
It checks specific properties, against configurations it can parse, using
policy assertions someone wrote. That is why it distinguishes *"we checked and
found nothing"* from *"we could not check"* — see [F-4](docs/finding-format.md).

## Acknowledgements

Built on [Batfish](https://github.com/batfish/batfish), an open-source network
configuration analysis tool. Netwise orchestrates Batfish — it does not
reimplement network analysis.

Portions of this codebase were developed with AI assistance, disclosed in line
with the university's academic integrity policy and recorded in
[`NOTICE`](NOTICE).
