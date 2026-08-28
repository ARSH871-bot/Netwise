# Why Batfish, and not something else

**Asked by the client twice in the meeting of 24 August 2026**, the second time
after an answer about offline models — which was an answer to a different
question. This document exists so any of the four of us can answer it, in one
minute, without reaching for a laptop.

> *"No, no, I'm asking, no, just you have to understand why Batfish? Why not
> something else?"* — Senaka Amarakeerthi, 24 August 2026

---

## The one-minute answer

Netwise has to decide whether a configuration file is safe **without touching
the network it describes.** That single constraint eliminates most of the
alternatives before capability is even considered.

Batfish is the only open-source tool we found that builds a **vendor-neutral
model of the network from the config text alone** and then answers questions
against that model *formally* — proving a property across an entire space of
flows, rather than sampling a few and hoping.

Everything else we looked at does one of three other things:

| Approach | What it actually does | Why it is not this project |
|---|---|---|
| **Batfish** | Builds a behavioural model from config text; answers questions by formal analysis | ✅ Offline, vendor-neutral, and *proves* properties |
| A live scanner (Nmap, OpenVAS) | Sends packets at a running network and reports what answered | Requires a live network. Netwise is passive and offline by constraint NFR-3 |
| Config-push tooling (Ansible, Netmiko, NAPALM) | Connects to devices to read or change state | Connects to live devices. Also *transports* config; it does not reason about it |
| A linter / regex ruleset (custom, `ciscoconfparse`) | Pattern-matches config text against known-bad strings | Cannot answer "can A reach B" — that is a property of rules *interacting*, not of any one line |
| An LLM reading the config directly | Predicts likely-sounding problems from text | Ungrounded. It cannot distinguish a rule that is dead from one that fires, and would invent findings |
| State collectors (SuzieQ, Batfish-adjacent NMS) | Gather and query operational state from live devices | Live again, and describes what *is* happening, not what *could* |

## The distinction that actually matters

Most tools in this space **spot-check**. Netwise's strongest capability is that
Batfish **proves**.

- `testFilters` answers *"is this one flow permitted, and which line decided
  it?"* — a spot check, and useful.
- `searchFilters` answers *"is there **any** flow at all that violates this
  policy?"* across the whole space of possible packets. An empty result is a
  proof that the policy holds. A returned flow is a counter-example.

No amount of manual testing, and no linter, gives you the second one. That is
the reason for the dependency, and it is the sentence to say out loud if asked.

## The honest limits

Stated here because a justification that only lists strengths is not one, and
because the client is more likely to respect the answer that includes them.

- **Batfish cannot read PF Sense**, which is the client's actual firewall. Its
  XML export is not a format Batfish parses at all. We wrote
  `analysis/pfsense_convert.py` to translate it into Cisco IOS text — and that
  converter refuses rather than guesses wherever the two firewalls' semantics
  genuinely differ. See CLAUDE.md §7.
- **Batfish models the config, not the world.** It cannot know a cable is
  unplugged, that an upstream provider filters something, or that a rule is
  deliberate. It answers "what do these files say happens", which is a narrower
  and much more checkable question.
- **It is a large dependency** — a Java service in a Docker container. We
  orchestrate it; we did not write network analysis ourselves, and CLAUDE.md §3
  says so plainly.

## What is ours, then?

The question behind the question, and worth answering in the same breath,
because "we just paste config into Batfish" is the criticism this invites.

Batfish answers *questions we choose to ask, about parameters we resolve, and
returns tables*. Everything between that and a person understanding their
network is ours:

1. **Which questions to ask, and with what parameters** — a Batfish question
   with the wrong source location returns a confident, evidenced, wrong answer.
   We shipped exactly that bug and fixed it in #141.
2. **The finding contract (F-1)** and the `found` / `none` / `error`
   distinction (F-4) — "we checked and found nothing" and "we could not check"
   are different claims, and keeping them apart is ours, not Batfish's.
3. **The pipeline** — error isolation, so one broken check cannot take the
   others down, plus the guards that refuse to let a check report silence as
   safety.
4. **The refusal design in the query layer** — a mistranslated question is more
   dangerous than a wrong answer, so intent is matched against a closed set and
   every parameter is resolved against the real snapshot.
5. **The PF Sense converter**, which is the only reason the client's own
   firewall can be analysed at all.
6. **The explanation layer**, which is grounded structurally: the model only
   ever receives real Batfish output and is only ever asked to rephrase it.

## Sources

- Batfish documentation — <https://batfish.readthedocs.io>
- Fogel, A. et al. (2015) *A General Approach to Network Configuration
  Analysis*, NSDI. The paper the tool is built on.
