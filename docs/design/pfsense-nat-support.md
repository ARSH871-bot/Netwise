# Scoping full NAT support for the PF Sense converter — not started here

**Status:** OPEN PROBLEM — no decision proposed here, deliberately. This
document exists to make the question decidable, not to decide it.
**Raised by:** Ankeet, having just shipped the skip-and-name half (#264).
**Needed from:** whoever picks this up next, if anyone does — reading this
is the first task, not building.

---

## What #264 actually built, and its real limit

`analysis/pfsense_convert.py` now excludes a filter rule carrying
`<associated-rule-id>` — PF Sense's marker for a rule it auto-generated as
a side effect of a NAT rule (a port-forward, for example) — instead of
converting it blindly. The exclusion is named in `skipped`, and if every
rule in a file is NAT-generated, the file refuses with a message that says
so specifically.

That is honest, and it is not coverage. Two of the client's seven real
filter rules are excluded this way. Nothing about those two rules is
understood by this module; they are simply no longer *misunderstood*. Any
security property that actually depends on NAT-generated traffic — whether
a port-forward exposes something it should not, for instance — is
currently invisible to every check this project runs.

## The three options considered, and why one was picked and two were not

This came up while scoping #264 itself. Recorded here rather than only in
conversation, so the next person does not have to re-derive it.

**Rejected outright: convert NAT-generated rules as ordinary rules,
undocumented.** This is the "looks plausible, is wrong" failure
`pfsense_convert.py`'s own module docstring exists to refuse rather than
produce. A NAT-generated rule's addresses often describe *translated*
(post-NAT) traffic, not the literal ones written in the rule — converting
it as if it were an ordinary filter rule risks a security check drawing a
conclusion about traffic that isn't what the rule actually governs. Not a
real option given how every prior version of this same question has been
decided in this codebase (#53, #54, #58, #104, #197 all chose refuse-and-
name over guess-and-convert).

**Shipped in #264: detect and skip, named individually.** Smallest,
matches the already-established pattern (#197's interface exclusions),
needed nothing from the client, and preserves the converter's existing
honesty guarantee. Cost: those rules stay permanently invisible to
analysis until real NAT support exists.

**Deferred, this document's actual subject: parse `<nat>` properly.**
Understand pfSense's NAT constructs (at minimum outbound NAT, 1:1 NAT, and
port-forward, which are the three that generate an
`<associated-rule-id>`-marked filter rule) well enough to translate a
NAT-generated rule into what it actually permits post-translation, rather
than excluding it.

## Why this is not scoped further than naming it

Nobody currently knows how much of the client's real network depends on
NAT. Two of seven rules in the one export measured so far (#78) — real,
but not evidence either way about whether NAT support is worth a sprint or
worth nothing, since the export's own scale (1,998 XML elements against
this project's 54-element fixture, per #78) makes two rules a small
fraction of what is genuinely unmodelled overall (also unscoped: aliases,
DHCP, VPN, traffic shaping, IPv6, combined tcp/udp rules — all listed as
out of scope in `pfsense_convert.py`'s own module docstring already).

Building NAT parsing now would be sizing work done blind — the same
mistake #86/#182's threads already flagged elsewhere in this project
("committing to work we haven't scoped"). What would actually inform the
decision, in order:

1. **Measure real scale first**, the same way `tools/pfsense_shape.py` (#74)
   already measures filter-rule count, interface count and quick-rule
   count without reading a value: how many `<nat>` entries the client's
   export actually has, and how many filter rules reference one. If the
   answer is "two, and no more will ever exist," this is not worth
   building. If it is "a third of his rule set," that changes the
   calculus.
2. **Ask the client** whether the NAT-dependent rules matter to the
   security question he actually cares about, rather than assuming they
   do because they exist.
3. Only then decide whether this is worth a sprint, and if so, scope the
   actual XML shape of pfSense's `<nat>` section (outbound vs. 1:1 vs.
   port-forward have different translation semantics) the way
   `docs/design/config-change-and-pushback.md` scoped shapes A/B/C for a
   different feature before committing to one.

## What this is not

Not a decision. Not started. Filed so the choice is visible rather than
re-derived from scratch, the same reason `remediation-phase-b.md` and
`config-change-and-pushback.md` exist as separate documents from the
features they scoped.

## Revisited without waiting for the client, and reaffirmed (#78)

The rest of #78 was picked up without waiting for Senaka's answers to the
four questions in Discussion #294, on the reasoning that a decision genuinely
blocked on him should stay blocked, but nothing else should sit idle in the
meantime. NAT was checked against that reasoning specifically, and it does
not clear the bar the other three items did.

The WAN-address and undeclared-VPN-interface problems, and the whole-file
blast radius fixed alongside missing `<type>` (see `CLAUDE.md` section 7),
were all fixable without any guess about network behaviour — they are
questions about how far one bad input's damage should spread, not about
what any field means. NAT is a different shape of problem: there is no
version of "convert the NAT rule" that does not require inventing
translation semantics (source, destination, or port rewriting) this module
has never observed in any real or synthetic `<nat>` element. Option 1 above
was already rejected for exactly that reason before this revisit, and
nothing about proceeding without the client changes the argument — it is
not a decision waiting on permission, it is a guess waiting on evidence
that still does not exist.

So: unchanged. Detection and exclusion (Option 2, already shipped as #264)
remains the only NAT-related behaviour in this module. The three
information-gathering steps above are still the right next steps, in the
same order, whenever someone picks this up.
