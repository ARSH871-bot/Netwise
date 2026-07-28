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
| Batfish analysis engine | Running; core questions validated (Sprint 1) |
| Backend analysis pipeline | In progress |
| AI explanation layer | Not started |
| Web dashboard | Not started |

See [`docs/sprint1/SPRINT1.md`](docs/sprint1/SPRINT1.md) for the Sprint 1 record.

## Requirements

- Docker (for the Batfish container)
- Python 3.11+
- Ollama (for the local LLM — later sprints)

## Getting started

<!-- TODO: expand once the analysis pipeline lands. -->

Start the Batfish container:

```bash
docker run -d --name batfish -p 9997:9997 -p 9996:9996 -p 8888:8888 batfish/allinone
```

Install the Python dependencies:

```bash
pip install -r requirements.txt
```

## Repository layout

| Path | Contents |
|---|---|
| `analysis/` | Batfish orchestration — snapshots, questions, results |
| `ai/` | Local LLM explanation and Q&A layer |
| `web/` | FastAPI backend and dashboard frontend |
| `docs/` | Sprint records and design notes |
| `configs/` | Config files under test — **git-ignored, never committed** |

## A note on data

No network configuration data is committed to this repository, and none is ever
sent to a cloud service. `configs/` and common config file extensions are
git-ignored by design.

## Usage

<!-- TODO: document the CLI / API once the pipeline is agreed. -->

## Team

| Name | Role |
|---|---|
| Arsh | Engine / backend, SCRUM Master |
| Ankeet | Engine / backend |
| Shubham | Frontend / dashboard |
| Samika | Frontend / dashboard |

Client / sponsor: **Senaka Amarakeerthi**, Senior Lecturer.

## Acknowledgements

Built on [Batfish](https://github.com/batfish/batfish), an open-source network
configuration analysis tool. Netwise orchestrates Batfish — it does not
reimplement network analysis.

Portions of this codebase were developed with AI assistance, disclosed in line
with the university's academic integrity policy.
