# Netwise — user guide

**Who this is for.** Someone who wants to *use* Netwise, without us in the
room. For how it is built, see [`architecture.md`](architecture.md).

Every command below was run before being written down.

---

## What Netwise does, in one paragraph

You give it exported network device configuration files. It finds security
misconfigurations in them and explains each one in plain English. It runs
entirely on your machine — nothing is sent anywhere — and it is **passive**:
it reads exported files and never connects to, scans, or changes a live
device. Not even the "propose a change" feature, which only ever simulates.

---

## 1. Check the machine is ready

```bash
python -m tools.preflight
```

It tells you three separate things, because they fail separately: whether the
Python packages are importable, whether the **installed versions** match what
the project declares, and whether Docker, the Batfish container and the
Batfish service are each reachable.

A healthy machine ends with:

```
READY -- with 1 optional item(s) absent: Ollama (optional)
Everything required works. See the notes above for what that costs.
```

**Ollama is optional.** Without it you still get every finding — the
explanations are built deterministically from the finding's own fields
instead of written by a model, and the dashboard labels them
*"Plain-English summary"* rather than *"AI explanation"* so nothing claims a
model wrote something it did not.

If Batfish is not running:

```bash
docker start batfish
```

The first analysis after starting it takes a few minutes while the container
warms up. That is normal, not a hang.

---

## 2. Analyse a config from the command line

```bash
python -m analysis.pipeline <config-folder>
```

The folder must contain a `configs/` subfolder holding the device files:

```
my-network/
  configs/
    rtr-us5.cfg
```

Try it on a config that has a real flaw, and then on the clean version of the
same network:

```bash
python -m analysis.pipeline tests/fixtures/rtr-us5-insecure
python -m analysis.pipeline tests/fixtures/rtr-us5-secure
```

To run only some checks, name them:

```bash
python -m analysis.pipeline tests/fixtures/rtr-us5-messy access_control
```

### Using your own security policy

By default Netwise checks **our** example rules, which name our example
devices. To check *your* rules against *your* network:

```bash
python -m analysis.pipeline my-network/ --policy my-policy.json
```

**Start from the example rather than a blank file:**

```bash
cp docs/examples/policy.example.json my-policy.json
```

Change `"device"` to your device's hostname, edit the addresses, and run it.
That file is validated by the test suite on every run
(`tests/test_policy_example_is_valid.py`), so it cannot quietly stop being a
policy the loader accepts.

**What reads it, today.** `policy_compliance` asserts your rules instead of
our built-in ones, and every finding says which of the two it used.
`access_control` and `routing` do not read a supplied policy yet — they say
so rather than staying silent about it (#196), so you are never left
believing rules were checked that were not.

**A policy that cannot be loaded stops the run** and names the entry and the
missing field. It never analyses against half a policy.

The format is JSON. `docs/examples/policy.example.json` is the reference —
it shows both rule kinds and a multi-arm rule, which are the two things that
are not obvious. `docs/design/user-policy-format.md` is a **decisions**
document arguing why the format is shaped this way; it is worth reading if
you want the reasoning, and it is not a format reference.

> This section previously said *"NOT AVAILABLE YET — do not expect a
> `--policy` flag to work"*, which was true when it was written and stopped
> being true when #181 merged on 28 August. It was a deliberate placeholder
> pointing at #195; this is #195.

---

## 3. Use the dashboard

```bash
uvicorn web.main:app --reload
```

Then open <http://127.0.0.1:8000>. API documentation is at `/docs`.

1. **Upload** a config file. Uploading *stages* it — it does not analyse it.
   The message says so.
2. Click **Scan Now**. This is what runs the analysis.
3. Findings appear worst-first, each with an explanation.
4. Use the **chat pane** to ask a plain-English question.

---

## 4. Reading the results

Every finding is one of three states, and the difference matters more than
anything else in the product:

| What you see | What it means |
|---|---|
| A finding, red or amber | **We checked, and found this problem.** |
| A green tick | **We checked, and found nothing wrong.** |
| An amber warning | **We could not check.** Not the same as clean. |

The third is the one to read carefully. *"We could not check"* is never
reported as *"you are fine"*.

---

## 5. Asking questions

In the chat pane, or via `POST /api/ask`:

```
Can rtr-us5 reach 10.20.0.5?
```

**It always shows you what it understood before it answers.** Read that line.
It is the only way to notice that your question was taken differently than
you meant, and it is the reason a narrow feature is safe rather than merely
limited.

It will **refuse** questions it cannot resolve — for example anything naming
a network by a friendly name rather than an address, because turning "the
guest network" into an address range would be guessing. A refusal says why.

---

## 6. Proposing a change

Via `POST /api/propose`, or the dashboard:

```
allow 10.10.10.5 to 10.20.0.5 on tcp/443 on rtr-us5
```

Netwise will:

1. Parse the request against a fixed template, and **refuse** it if it does
   not resolve — `block YouTube` is refused, because we have no way to know
   which addresses "YouTube" means.
2. Generate a candidate config line.
3. Apply it to a **disposable copy** of your network model and re-analyse.
4. Report what actually changed — and **warn** if the change opens access
   that was previously blocked.

**Nothing is ever applied to your device.** The generated line is text for
you to review. Your uploaded config is never modified; a test asserts it is
byte-identical afterwards.

---

## 7. PF Sense firewalls

Batfish cannot read PF Sense XML, so Netwise translates it into Cisco IOS
first:

```bash
python -m analysis.pfsense_convert <config.xml> <output-folder>
```

**It refuses rather than guesses.** If part of your configuration uses
something the translator cannot model exactly — NAT, VPN or tunnel
interfaces, an interface with no fixed address — it says so, names the
interface, and says how many rules were skipped, rather than producing a
config that looks right and behaves differently from your real firewall.

To see the shape of an export without revealing anything in it:

```bash
python -m tools.pfsense_shape <config.xml>
```

That reports structure and counts only — never an address, a hostname, or a
rule.

---

## 8. Limits, stated plainly

- **Never verified against a real production network.** Every published
  result is on synthetic configs we wrote.
- **PF Sense support is partial.** NAT, aliases, VPN and IPv6 are not
  modelled, and each is refused rather than approximated.
- **Application-level blocking is out of scope.** "Block YouTube" is refused
  by design, not by omission.
- **Two of the three checks do not yet read a supplied policy** —
  `access_control` and `routing` still use our example rules.
- **Nothing is ever pushed to a live device.** That is a permanent
  guarantee, not a current limitation.

---

## 9. If something goes wrong

| Symptom | Try |
|---|---|
| Everything reports "could not check" | `docker start batfish`, then `python -m tools.preflight` |
| It seems to hang on the first scan | The container is warming up. A few minutes is normal. |
| Explanations look mechanical | Ollama is not running. This is fine — see step 1. |
| A test count disagrees with CI | Believe CI, then run `preflight`; your installed versions may not match what the project declares. |
