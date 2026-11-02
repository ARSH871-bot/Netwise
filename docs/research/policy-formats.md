# Our policy format compared with formats used in industry

**Issue:** #424 · **Author:** Shubham · **Checked against:** `main` at `dc93ccb`

## The question

How does the policy file Netwise reads (`analysis/policy.py`,
`docs/examples/policy.example.json`) compare with real policy formats, what
can't ours express, and what should we borrow?

## Our format in one paragraph

A JSON file with up to three sections: `access_control`, `policy_compliance`
and `routing`. Each rule names a **device** (`node`) and, in the first two
sections, a **filter**. A `policy_compliance` rule is a `prohibition` or a
`requirement` over one or more header spaces (`srcIps`, `dstIps`, ports,
`ipProtocols`) written in Batfish's specifier syntax, including set
difference (`0.0.0.0/0 \ (218.8.104.58, 10.20.0.5)`). Every rule carries its
own severity and summary. The loader refuses unknown keys: an `expiration`
field gets `unknown key 'expiration'`, measured. So every gap below is a
format change, and widening the format needs all four of us.

## The formats compared

| | Netwise | Capirca / Aerleon [1, 2] | Kubernetes NetworkPolicy [3] | AWS security groups / network ACLs [4, 5] | OpenConfig ACL [6] | CIS Benchmarks [7] |
|---|---|---|---|---|---|---|
| **What it is** | assertions checked against configs | source that **generates** ACLs for many vendors | allow-lists enforced on pods | cloud firewall rules | a vendor-neutral data model for ACLs | hardening checklists |
| **Bound to** | a device name + filter name | a target platform + filter name in the header | **labels** (any pod that matches) | an instance's security group / a subnet | an interface binding | a device type |
| **Named addresses/services** | no, a CIDR in every rule | **yes**: `NETWORK.net`, `SERVICES.svc` | labels and namespaces | prefix lists, other security groups | defined sets | n/a |
| **Except / set difference** | yes, `\` | yes, `source-exclude`, `destination-exclude` | `ipBlock.except` | no | no | n/a |
| **Deny rules** | prohibitions | yes | **no**: allow-only | SG: no, allow-only. NACL: yes | yes | n/a |
| **Order matters** | no, rules are independent | yes, terms in order | no | SG: no. NACL: yes, lowest number first | yes, sequence id | n/a |
| **Stateful** | not expressed | per-platform option | yes, implicitly | SG: yes. NACL: no | no | n/a |
| **Expiry / review date** | no | **yes**: `expiration` [2] | no | no | no | n/a |
| **Device settings** (SSH v2, HTTP server off) | **no** (#400) | no | no | no | no | **yes, mostly** |

What stands out: no single format does everything. Each covers what its
enforcement point needs. Ours is the only one in the table that is an
**assertion** rather than a configuration. It does not make the network do
anything; it says what the network must and must not do, and a check proves
it. The closest thing to that in industry is Microsoft's SecGuru "contracts"
(see `formal-methods.md`), which is not a public format.

## The gaps, and a recommendation for each

### 1. Device settings: borrow from CIS, partly (#400)

CIS controls like "SSH version 2 only" or "HTTP server disabled" are settings,
not traffic. Our format can't say them. #400 measured that Batfish models only
3 of 12 common CIS IOS lines (logging, NTP and SNMP servers), and the other
nine parse as `PASSED` with zero warnings while being modelled not at all.

**Recommendation:** add one new rule kind for the settings Batfish *does*
model (`nodeProperties`). Don't add rules for the nine it doesn't, because the
check could never verify them, and a rule that can't be checked must not look
like one that passed. The options are already on #400, and the decision there
needs all four of us.

### 2. Names for addresses and services: borrow (Capirca)

Our three-rule example already writes `10.20.0.5` three times and
`10.10.10.0/24` four times.
Capirca keeps addresses in `NETWORK.net` and services in `SERVICES.svc`, and
policies refer to `INTERNAL_SERVER` rather than an address [1]. A renumbered
server is then one edit, not one per rule, and a typo can't make one rule talk about
a different host from the others.

**Recommendation: borrow it.** It's the cheapest gap to close. Names would be
resolved when the file loads, so every check, `policy_conflicts` and
`policy_drift` would still see plain addresses and need no change. A name
that is defined nowhere must be an error, never treated as "any".

### 3. Scope by role, not by device name: borrow the idea, later

Every rule is bound to a device name: `rtr-us5`, through the example's
file-level `device` key. CLAUDE.md §11 records what device names cost: for a
user running our built-in rules, renaming the device halves the detection
(6 findings → 3). Kubernetes avoids
this completely, because a policy selects by label, so a new pod with the
right label is covered the day it starts [3].

**Recommendation: borrow the idea, not the syntax, and not yet.** We have no
source for roles. A config doesn't say "this is a branch router", and
guessing would be the unfounded claim the project avoids. The client's
business-context file (#254) already lets the user tag devices, and is the
natural place for a role. Worth raising once the client's firewall loads
(#78), when there is a second device to share a rule with.

### 4. Expiry and review dates: borrow (Capirca/Aerleon)

Aerleon's `expiration` keyword stops a term from being generated after a date
[2]. Temporary rules ("allow the vendor in until the migration ends") are a
classic source of the stale permits this tool exists to find.

**Recommendation: borrow it, as a warning, not as enforcement.** An expired
rule would still be checked, with a finding saying it is past its date. It
fits beside drift detection (#418) and the never-fires work (#324). It needs
a format change, so it comes to the team as a proposal.

### 5. Order and default action: don't borrow

Capirca, NACLs and OpenConfig rules are ordered because they *are* the filter.
Ours are assertions, and each one is proved independently against the whole
space, so order has no meaning. Kubernetes and security groups avoid
conflicts by being allow-only. We have both prohibitions and requirements, so
a policy can contradict itself. #387 refuses such a policy instead of picking
a winner by order.

**Recommendation: keep it as is.** Order would make a rule's meaning depend on
its neighbours, which is the property that makes real ACLs hard to read.

### 6. Stateful traffic: don't borrow yet

Security groups and Kubernetes allow return traffic implicitly; NACLs need it
written. Our rules check one direction through one stateless filter, and
`searchFilters` can't model state (`formal-methods.md`, limit 3).

**Recommendation: not now.** A format keyword for state would promise
something no check can verify.

## What I'd do, in order

1. Names for addresses and services. Small, loader-only, and it makes every
   other rule easier to get right.
2. Expiry as a warning.
3. The #400 decision on device settings, which is already open.
4. Roles, after #78.

Items 1 and 2 change the format, so they come to the team as one proposal
before any code.

## Sources

1. Google, *Capirca* (multi-platform ACL generation),
   <https://github.com/google/capirca>, and its package page
   <https://pypi.org/project/capirca/>. Definitions files, terms,
   `destination-exclude`, and the `aclcheck` tool.
2. *Aerleon* documentation (a maintained fork of Capirca), common term
   keywords including `expiration`,
   <https://dokk.org/documentation/aerleon/1.0.0/user/generators/common>
3. Kubernetes documentation, "Network Policies",
   <https://kubernetes.io/docs/concepts/services-networking/network-policies/>
4. AWS, "Control traffic to your AWS resources using security groups",
   <https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html>
5. AWS, "Control subnet traffic with network access control lists",
   <https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html>
6. OpenConfig, `openconfig-acl.yang`,
   <https://github.com/openconfig/public/tree/master/release/models/acl>
7. Center for Internet Security, *CIS Cisco IOS Benchmarks*,
   <https://www.cisecurity.org/benchmark/cisco>
8. NIST SP 800-41 Rev. 1, *Guidelines on Firewalls and Firewall Policy*,
   2009. Background on why rule sets drift and need review.
