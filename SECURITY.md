# Security

Netwise reads exported network device configuration files. That makes it a tool
people point at the most sensitive text their organisation owns, so this
document says plainly what it does with that data and how to tell us if
something is wrong.

## What Netwise does with your configuration

**Nothing leaves your machine.** That is the first constraint in `CLAUDE.md`,
and `.gitignore` — which blocks configuration data from the repository — was
deliberately the first commit in this project's history.

Concretely:

- Analysis runs against **Batfish in a local Docker container**, not a service.
- Explanations are written by a **local LLM via Ollama**, not a hosted API.
- No configuration data is sent to any cloud AI service, including ones the
  developers use. When a client offered a real export for AI-assisted debugging,
  it was declined and `tools/pfsense_shape.py` was written instead — it reports
  structure and never a value, so a file can be reasoned about without moving.
- Netwise **never connects to, scans, or modifies a live network.** It reads
  files you already exported.

## Reporting a vulnerability

Open a **private** security advisory on this repository, or contact the SCRUM
master directly. Please do not open a public issue for a vulnerability in the
handling of configuration data.

Include what you can: the construct that triggers it, and — if it involves a
real configuration — a **structural** description rather than the file.
`python tools/pfsense_shape.py <file>` produces exactly that for PF Sense
exports and is safe to paste.

We will confirm receipt and tell you what we found, including if we conclude it
is not a vulnerability and why.

## Classes of problem we treat as security bugs

Not only the obvious ones. In a tool that reports on firewalls, **being
confidently wrong is a security bug**, because a user acts on it:

| Class | Why it counts | Precedent |
|---|---|---|
| Anything that reveals configuration content it promised not to | The core guarantee | #74 |
| A config that can inject content into converted output | Changes the analysed policy | #53 |
| A translation that silently changes what a rule means | The user acts on a firewall that isn't theirs | #47, #58, #80 |
| Reporting a config as clean when it was never analysed | "We checked" vs "we could not check" — F-4 | throughout |
| An answer grounded in the wrong question | Passes every guard and still misleads | #64, #70 |

The last two are the ones that look least like security bugs and matter most.
A crash is visible. A confident wrong answer about a firewall is not.

## What we do not claim

- **No real production configuration has been analysed yet.** Every published
  result is against synthetic fixtures we wrote — see `docs/evaluation.md`,
  which states this as prominently as its results.
- Netwise is a **capstone project**, not a supported product. There is no
  release cadence beyond sprint tags and no security-response SLA.
- It analyses **Cisco IOS**, and PF Sense via conversion. The converter refuses
  constructs it cannot translate faithfully rather than guessing — that refusal
  is the security feature, and it means a file being rejected is working as
  intended.
