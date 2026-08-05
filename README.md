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

🚧 **In development — Sprint 2.**

| Layer | State |
|---|---|
| Batfish analysis engine | Running; core questions validated |
| Backend analysis pipeline | **Built** — loads configs, runs checks, returns structured findings |
| Access-control analysis | **Built** — four analyses |
| Policy-compliance analysis | **Built** |
| Routing analysis | **Built** |
| AI explanation layer | **Built** — explains a finding in plain English; answering typed questions is still to come |
| Web dashboard + upload | **Built** — upload a config, get real findings |
| PF Sense conversion | **Built** — interfaces and filter rules; see the caveat in `analysis/pfsense_convert.py` |
| Risk prioritisation | Not started |
| Change-impact analysis | Not started |

**Upload a config and you get real findings.** The one link still open is the
AI explanation: the dashboard reserves a place for it and labels it *"not
generated yet"*, so a placeholder is never mistaken for something the model
produced. Connecting `explain()` to that slot is the next piece of work.

See [`docs/sprint1/SPRINT1.md`](docs/sprint1/SPRINT1.md) for the Sprint 1 record.

## Requirements

- Docker (for the Batfish container)
- Python 3.11+
- Ollama, for the local LLM that writes the plain-English explanations. Build
  the model once with `ollama create netwise-warden -f ai/Modelfile`. Only the
  explanation layer needs it — the analysis pipeline and the test suite both
  run without it.

## Getting started

**1. Start Batfish** (first run pulls the image, which takes a few minutes):

```bash
docker run -d --name batfish -p 9997:9997 -p 9996:9996 -p 8888:8888 batfish/allinone
```

**2. Install the Python dependencies:**

```bash
pip install -r requirements.txt
```

**3. Run an analysis** on one of the bundled synthetic configs:

```bash
python -m analysis.pipeline tests/fixtures/rtr-us5-insecure
```

You should get JSON findings describing the deliberate flaw in that fixture.
The first run after starting the container is slow — Batfish's engine has to
warm up and parse the configs. That is normal, not a hang.

**4. Start the dashboard:**

```bash
uvicorn web.main:app --reload
```

Then open <http://127.0.0.1:8000>. API documentation is at `/docs`.

**5. Run the tests** (these need neither Batfish nor Docker):

```bash
pytest tests/ -v
```

## Repository layout

| Path | Contents |
|---|---|
| `analysis/` | Batfish orchestration — the pipeline, the finding format, one module per check, and the PF Sense converter |
| `ai/` | Local LLM layer — `explain.py` turns a finding into plain English; `Modelfile` defines the model it calls |
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

## Acknowledgements

Built on [Batfish](https://github.com/batfish/batfish), an open-source network
configuration analysis tool. Netwise orchestrates Batfish — it does not
reimplement network analysis.

Portions of this codebase were developed with AI assistance, disclosed in line
with the university's academic integrity policy.
