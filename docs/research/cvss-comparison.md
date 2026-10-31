# Our severity rules compared with CVSS

**Issue:** #425 · **Author:** Shubham · **Measured:** 30 October 2026, against
`main` at `dc93ccb` and the local `batfish/allinone` container

`docs/severity-rules.md` is @SamikaPerera's. This document compares and
recommends; it changes nothing in his ruleset, and the one recommendation that
touches a rule is a question for him.

## The question

Netwise rates findings `high` / `medium` / `low`: a default from the check,
then re-rated by `risk` (R-1 to R-4) and by business context. CVSS, the
FIRST standard behind every NVD score, rates vulnerabilities 0.0–10.0 in five
bands [1, 2]. Where do the two agree on our real finding types, where do they
disagree, and which is right for Netwise?

## How the two differ in kind

| | CVSS | Netwise |
|---|---|---|
| Rates | one vulnerability in a product | one finding about one config |
| Scale | 0.0–10.0; None, Low (0.1–3.9), Medium (4.0–6.9), High (7.0–8.9), Critical (9.0–10.0) | low, medium, high |
| Inputs | how it is exploited (vector, complexity, privileges, user interaction) and what it costs (confidentiality, integrity, availability) | the finding's check and evidence text |
| Your environment | optional Environmental metrics, including how much you need C, I and A [1, 2] | business-context tiers: `critical` raises a finding one level (#254) |
| "We couldn't check" | no concept | `status="error"`, never re-rated (F-4) |

CVSS v4.0 says plainly that a Base score is not a risk score, and names
scores by which metric groups were used (CVSS-B, CVSS-BE and so on) so a
reader can tell [2]. That is the same split we already make: the check's
default plays the role of the base, and business context plays the role of
the environment.

## Our finding types against CVSS

I scored each finding type with CVSS 3.1 and 4.0 using the reference
implementation [4]. **A config doesn't say what sits behind a hole**, so I
scored each one twice: with the lowest plausible impact (it exposes something
minor) and the highest (it exposes everything). The vectors are in the
appendix.

| Finding type | Example | Ours (check → after `risk`) | CVSS 3.1 | CVSS 4.0 |
|---|---|---|---|---|
| Forbidden traffic permitted | PC-001, PC-002 | high → high | 4.3 Medium – 8.8 High | 5.3 Medium – 8.7 High |
| Blanket permit, internet-facing | `permit ip any any` (R-2) | high → high | 5.3 Medium – **10.0 Critical** | 6.9 Medium – **10.0 Critical** |
| Forged source permitted | PC-003 | medium → medium | 3.7 Low – 6.5 Medium | 6.3 Medium – 8.3 High |
| Opening change | CH, opening direction | high → high | as "forbidden traffic permitted" | same |
| Dead `deny` line | AC, `filterLineReachability` | high → **low** (R-1) | as "forbidden traffic permitted" (see below) | same |
| Required traffic blocked | PC-004, PC-005 | medium → medium | **not applicable**: no attacker | not applicable |
| Reachability failure | RT-001 | high → medium (R-3) | not applicable | not applicable |
| Dead `permit` line, unused filter, routing hygiene | AC, RT-1xx | medium → low / medium | not applicable | not applicable |
| CVE match on a software train | `cve_mapping` | medium (capped) | the advisory's own: 7.5 (CVE-2016-6415), 9.8 (CVE-2017-3881) | — |
| Could not check | any `status="error"` | never re-rated | no concept | no concept |

## What the table shows

### 1. CVSS can't be computed from a config alone

Every row that CVSS applies to spans two or three bands, and the spread
always comes from the impact metrics, meaning what an attacker reaches
through the hole. A config doesn't contain that. So a CVSS number on a
Netwise finding would be a guess dressed up as a measurement. **Ours is
right for Netwise here:** three qualitative levels claim only what the
evidence supports. `severity-rules.md` §5 refuses to weight by device for the
same reason.

### 2. Where they agree

On the rows CVSS can score, our level sits inside its range every time: high
for forbidden traffic and blanket permits, medium for a forged source under
3.1. The business-context `critical` tier does what CVSS's Environmental
"security requirements" do: the same weakness on a more important asset
scores higher. In both, it comes from the user, not from the tool.

### 3. Availability-only findings: CVSS doesn't apply, and ours is right

A blocked DNS server or a broken route has no attacker, so it has no attack
vector. Forcing it into CVSS as if it were a denial-of-service gives 5.3–7.5
(3.1), which treats our own outage like a remote attack. Netwise is asked to
guard reachability as well as security (CLAUDE.md §4), so these findings
belong in the list, and `medium` (R-3's reasoning) is a judgement CVSS has no
way to make.

### 4. A disagreement where CVSS is right: R-1 and a dead `deny` (measured)

R-1 rates every dead line `low`, because "a line that can never match cannot
expose anything", and says the exposure "is reported separately, on its own
finding, by R-2". That holds when the line shadowing the dead one is a
blanket permit. I measured a case where it isn't: a one-router config whose
ACL `lan_in`, applied inbound on the LAN interface, reads

```
permit tcp 10.10.10.0 0.0.0.255 host 10.20.0.5
deny   tcp host 10.10.10.66 host 10.20.0.5 eq telnet     <- dead
deny   ip any any
```

```
AC-002  found  low   ACL rule never takes effect in lan_in
        Unreachable line: deny tcp host 10.10.10.66 host 10.20.0.5 eq telnet
        (action DENY). Blocked by: permit tcp 10.10.10.0 0.0.0.255 host 10.20.0.5
```

`access_control` rated this `high`, since its own comment says a dead deny
"lets through traffic someone meant to block". R-1 lowered it to `low`. R-2
didn't fire, because the blocker is not "any to any". So the only finding
about telnet from `.66` reaching the server, which the author clearly meant to
block, is at the bottom of the list. CVSS scores the *effect*: the traffic
gets through, so the score is the "forbidden traffic permitted" range,
4.3–8.8.

**For Samika:** should R-1 apply only to dead `permit` lines, or to a dead
`deny` only when its blocker is a blanket permit that R-2 already rates? I
haven't changed anything. It's his ruleset, and §6.2 records that R-2 itself
fires on none of our fixtures, so the "reported separately" half may need a
look too.

### 5. CVSS has a Critical band and we don't: keep it that way

A blanket permit on an internet-facing filter reaches 10.0 at the top of its
range. We stop at `high`. Adding `critical` would change F-1's vocabulary
(all four of us), and a config alone can't tell 10.0 from 5.3 (point 1). The
business-context tier already lets the user say which devices matter most.
**Ours is right for Netwise.**

### 6. `cve_mapping`'s cap: ours is right, and CVSS explains why

The dataset holds the real CVSS scores (7.5 and 9.8 above), and the check
still caps itself at `medium`. CVSS scores a vulnerability *assuming it is
present*. Even 4.0's threat metric, Exploit Maturity, is about whether
exploits exist, not whether this device has the flaw [2]. Our match is on the
software train, not the build, and most advisories need a feature switched
on. Copying 9.8 onto the finding would claim a certainty the match doesn't
have. The cap is the right reading of the standard, not a departure from it.

## Recommendations

1. **Don't add CVSS scores to findings.** It would be false precision (point 1).
2. **Keep three levels; no `critical`** (point 5).
3. **Ask Samika about R-1 and dead `deny` lines** (point 4). It's the one
   place I measured CVSS being right and us being wrong. Raised on this PR,
   not changed.
4. In `docs/severity-rules.md`, if Samika agrees: one line saying the business
   context tier is our equivalent of CVSS Environmental metrics. A reviewer
   who knows CVSS would find the design faster.

## Appendix: vectors

Scored with `cvss==3.2` [4]. Lower bound / upper bound for each row.

```
forbidden traffic permitted (LAN -> internal server; AV:A, the attacker is on the LAN)
  3.1  AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N = 4.3    AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 8.8
  4.0  AV:A/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N = 5.3
       AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N = 8.7
blanket permit, internet-facing (AV:N; upper bound reaches systems behind the device)
  3.1  AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N = 5.3    AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H = 10.0
  4.0  AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N = 6.9
       AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H = 10.0
forged source permitted (spoofing; replies don't come back to the attacker)
  3.1  AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N = 3.7    AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:L = 6.5
  4.0  AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N = 6.3
       AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:H/VA:L/SC:N/SI:N/SA:N = 8.3
required traffic blocked, forced into CVSS as if an attack (shown only to make point 3)
  3.1  AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L = 5.3    AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H = 7.5
```

The forged-source row moves a band between versions: 3.1 puts spoofing's
difficulty in Attack Complexity, 4.0 moves it to Attack Requirements, and
the two are weighted differently. So the two CVSS versions don't fully agree
with each other either.

## Sources

1. FIRST, *Common Vulnerability Scoring System v3.1: Specification Document*,
   <https://www.first.org/cvss/v3.1/specification-document>
2. FIRST, *Common Vulnerability Scoring System v4.0: Specification Document*,
   <https://www.first.org/cvss/v4.0/specification-document>
3. NIST, National Vulnerability Database, "Vulnerability Metrics",
   <https://nvd.nist.gov/vuln-metrics/cvss>, and the two advisories quoted:
   <https://nvd.nist.gov/vuln/detail/CVE-2016-6415>,
   <https://nvd.nist.gov/vuln/detail/CVE-2017-3881>
4. Red Hat Product Security, `cvss` Python library (version 3.2 used),
   <https://github.com/RedHatProductSecurity/cvss>
5. `docs/severity-rules.md`, `analysis/checks/risk.py`,
   `analysis/checks/cve_mapping.py` and `analysis/data/cisco_ios_cves.json`
   in this repository.
