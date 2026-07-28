# Proposal: structured output schema for the analysis pipeline

**Status:** PROPOSAL — for team decision. Nothing is built against this yet.
**Decide with:** Ankeet (engine), Shubham + Samika (dashboard).
**Written:** 2026-07-29

---

## The decision

Batfish answers come back as pandas DataFrames, and every question returns
*different columns*. `testFilters` gives you `Action` and `Line_Content`;
`filterLineReachability` gives you `Unreachable_Line` and `Blocking_Lines`;
`undefinedReferences` gives you `Structure_Type` and `Ref_Name`. There is no
shared shape.

Something has to impose one, because two consumers depend on it:

- **The AI layer** needs input it can be grounded in — stable field names it can
  be told to quote from and never go beyond.
- **The dashboard** needs to render a severity-sorted list without special-casing
  five different table shapes in the frontend.

Whatever we pick, the frontend has to live with it, which is why this is a team
call rather than mine.

## Option A — Flat findings list

One uniform `finding` object per issue. The pipeline translates every question's
native columns into a shared shape.

```json
{
  "snapshot": "client-network-2026-07",
  "generated_at": "2026-07-29T10:15:00Z",
  "findings": [
    {
      "id": "flr-rtr-with-acl-acl_in-460",
      "check": "filterLineReachability",
      "severity": "medium",
      "device": "rtr-with-acl",
      "location": "acl_in line 460",
      "title": "Unreachable ACL line",
      "evidence": {
        "unreachable_line": "permit tcp 10.10.10.0/24 any eq 53",
        "blocking_lines": ["deny ip 10.10.10.0/24 any"]
      }
    }
  ]
}
```

**For:** the dashboard renders one component for everything. Sorting and
filtering by severity is trivial. The AI gets a predictable shape, so the
grounding prompt is simple and identical for every finding.

**Against:** we invent the `severity` and `title` fields — Batfish does not
supply them, so we're adding judgement the tool didn't make. `evidence` becomes
a grab-bag whose keys vary by check, which quietly reintroduces the problem we
were solving. Detail gets lost in translation, and *lost detail cannot be
recovered* if the AI later needs it.

## Option B — Grouped by question, raw-faithful

Keep Batfish's own structure. One block per question, each holding that
question's native rows unchanged.

```json
{
  "snapshot": "client-network-2026-07",
  "results": {
    "filterLineReachability": {
      "status": "ok",
      "columns": ["Sources", "Unreachable_Line", "Blocking_Lines"],
      "rows": [{ "Sources": ["rtr-with-acl: acl_in"], "...": "..." }]
    },
    "undefinedReferences": { "status": "ok", "columns": [], "rows": [] }
  }
}
```

**For:** zero information loss and no invented fields, which makes AI grounding
maximally defensible — every value traces directly to a Batfish cell. Adding a
sixth question is a pure addition, no schema change. Simplest pipeline code.

**Against:** pushes all the work onto the frontend, which now needs per-question
rendering logic and has nowhere to get severity from. "Show me the high-risk
items" becomes hard. This optimises for the layer that's easiest to build and
penalises the two that are hardest.

## Option C — Two tiers: raw evidence + normalised findings *(recommended)*

Keep Option B's raw blocks *and* derive Option A's findings list from them, with
each finding carrying a pointer back to the rows it came from.

```json
{
  "snapshot": "client-network-2026-07",
  "generated_at": "2026-07-29T10:15:00Z",
  "raw": {
    "filterLineReachability": { "status": "ok", "columns": [], "rows": [] }
  },
  "findings": [
    {
      "id": "flr-0001",
      "check": "filterLineReachability",
      "severity": "medium",
      "device": "rtr-with-acl",
      "summary": "ACL line 460 can never match; an earlier line shadows it.",
      "source": { "check": "filterLineReachability", "row_index": 0 }
    }
  ]
}
```

**For:** each consumer gets the shape it actually needs — the dashboard reads
`findings`, the AI reads the raw row named by `source`. The `source` pointer is
the important part: it makes grounding *auditable*, because any explanation can
be traced back to the exact Batfish cell that justifies it. That directly serves
constraint 2 in `CLAUDE.md`, and it's strong material for the project review.

**Against:** the largest payload, and roughly 30–40% more pipeline code than
Option B. Two representations of the same truth can drift if we're careless, so
`findings` must always be *derived* from `raw`, never hand-maintained alongside
it.

## Recommendation

**Option C.** The extra cost is real but modest, and it's the only option that
doesn't force one of our two hardest layers to absorb the mess. The `source`
pointer in particular turns "the AI is grounded" from a claim into something we
can demonstrate.

If the team wants to move faster, **Option B is the safer fallback than A** —
it's a subset of C, so starting at B and adding the `findings` tier later is
additive work, whereas starting at A means throwing away detail we can't get
back.

## Open questions for the team

1. **Who assigns severity, and by what rule?** Batfish does not provide it. A
   fixed per-check mapping is simplest and defensible; asking the LLM to rate
   severity is *not* — that's judgement, not grounded rephrasing.
2. **Where does the AI's explanation live** — added to each finding by the
   pipeline, or fetched separately by the dashboard? Affects whether analysis
   and explanation can run independently.
3. **How do we represent a check that errored** (e.g. a config that won't parse)
   versus one that ran and cleanly found nothing? These must not look alike — an
   empty `searchFilters` result means "policy holds", which is a *strong
   positive*, and it must never be confused with "the check failed".
4. **Do we need stable finding IDs across runs**, so the dashboard can show what
   changed since the last upload? Cheap to design in now, expensive to retrofit.
