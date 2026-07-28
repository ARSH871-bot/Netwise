# Sprint 1 — Batfish setup and capability study

**Status:** Complete
**Record written:** 2026-07-29
**Sprint dates:** <!-- TODO: fill in actual sprint start/end dates -->

> This record was written retrospectively to bring Sprint 1 into version
> control. The work itself was done before the repository was populated, using
> the Batfish container's bundled Jupyter environment on port 8888.

---

## Sprint goal

Get Batfish running locally and understand what it can actually do, so that
Sprint 2 can automate it with confidence rather than guesswork.

## What we did

### 1. Batfish installed and running

Batfish runs in Docker from the official all-in-one image:

```bash
docker run -d --name batfish -p 9997:9997 -p 9996:9996 -p 8888:8888 batfish/allinone
```

| Port | Purpose |
|---|---|
| 8888 | Bundled Jupyter environment (where this sprint's exploration happened) |
| 9996 / 9997 | The service the `pybatfish` client talks to |

Confirmed working: container `batfish`, image `batfish/allinone`, up and
listening on all three ports.

### 2. Core workflow understood

The four-step loop that Sprint 2 will automate:

```python
from pybatfish.client.session import Session

bf = Session(host="localhost")                       # 1. connect
bf.init_snapshot(path, name=..., overwrite=True)     # 2. load configs as a snapshot
bf.q.<question>(...)                                 # 3. ask a question
                     .answer().frame()               # 4. get a pandas DataFrame
```

A *snapshot* is a set of configuration files that Batfish reads and models. A
*question* is a structured query against that model. Answers come back as
pandas DataFrames — which is exactly why Sprint 2 exists: those frames need
converting to structured data before an AI layer can consume them.

### 3. The five core questions studied

Run and understood against the bundled example Cisco configs:

| Question | What it answers | Why it matters to Netwise |
|---|---|---|
| `testFilters` | Does a filter permit or deny ONE specific flow, and why — it names the exact matching line. | Powers specific "can X reach Y?" checks, and gives us the line number needed to explain *why*. |
| `searchFilters` | Checks a whole SPACE of flows at once and returns any that violate an intended policy. | **Our strongest capability.** It *proves* properties ("no unwanted traffic can cross this boundary") rather than spot-checking one packet. Empty result = policy holds; a returned flow = a violation. |
| `filterLineReachability` | Finds ACL/firewall lines that can never trigger because an earlier line shadows them. | "Dead rules" are a classic misconfiguration — a rule meant to allow something that silently never takes effect. |
| `undefinedReferences` | Finds config referencing a structure (route-map, ACL, object group) that is never defined. | A silent failure risk: the config looks intentional but does nothing. |
| `traceroute` | Simulates hop-by-hop whether traffic reaches a destination, purely from the config model. Shows ACCEPTED/DENIED and the path taken. | Turns an abstract finding into a concrete, explainable journey — good raw material for plain-English explanation. |

## Key findings

1. **Batfish does the network analysis; we orchestrate it.** We are not
   implementing verification logic ourselves. This meaningfully de-risks the
   project and keeps the team's effort on the layers that don't exist yet — the
   AI explanation layer and the dashboard.
2. **`searchFilters` is the differentiator.** Most of the other questions are
   diagnostic. `searchFilters` can prove a property holds across an entire
   space of flows, which is a much stronger claim than "we found some issues".
3. **Answers arrive as pandas DataFrames, not JSON.** Feeding a printed table
   to an LLM is not grounding. Sprint 2 must convert these to structured data
   with a stable shape.
4. **Vendor support constrains the data.** Cisco IOS is natively supported and
   the bundled examples are Cisco, so development starts there. The client's
   real firewall is PF Sense, which exports XML that Batfish does not support
   natively — conversion is a known hard problem and is timeboxed.

## Environment verified

| Component | State at end of sprint |
|---|---|
| Batfish container | Running (`batfish/allinone`) |
| Exploration environment | Container's bundled Jupyter, port 8888 |
| Host-side `pybatfish` | Not yet installed — addressed in Sprint 2 |
| Ollama | Not yet installed — Layer 2, later sprint |

## Screenshots

<!-- TODO: add screenshots here as evidence for the project review.
     Suggested set:
       - docker ps showing the batfish container running
       - a testFilters result showing permit/deny plus the matching line
       - a searchFilters result (both an empty "policy holds" result and a
         violation, if one can be produced)
       - a filterLineReachability result showing a shadowed line
     Save images in this folder and link them below. -->

_Screenshots to be added._

## Outcome and handover to Sprint 2

Sprint 1 answered "can Batfish do what this project needs?" — yes, and we know
which questions to use.

Sprint 2 builds the backend pipeline that:

- loads a chosen config folder as a snapshot programmatically,
- runs the key analyses,
- returns results as **structured data (dicts/JSON)** rather than printed
  tables, ready for the AI explanation layer.

The structured output schema is a pending team decision, since the dashboard
has to live with whatever shape is chosen.
