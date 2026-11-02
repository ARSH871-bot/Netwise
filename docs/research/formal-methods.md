# How Netwise checks a policy, compared with formal verification

**Issue:** #423 · **Author:** Shubham · **Measured:** 30 October 2026, against
`main` at `dc93ccb` and the local `batfish/allinone` container

## The question

`policy_compliance` checks each rule with Batfish's `searchFilters`. We call
that a *proof*: an empty answer means no packet in the space breaks the rule.
How does that compare with what the network-verification literature calls
formal verification, and what can it prove and not prove?

## Short answer

`searchFilters` **is** formal verification, of a narrow thing. It searches
exhaustively and symbolically: Batfish encodes the filter and the header space
as binary decision diagrams (BDDs) and asks whether they intersect [1, 2]. No
packets are sampled. So within its scope, an empty result is a real proof.

The scope is the weak point, and it is narrower than our documents sometimes
suggest. What is proved is: *this filter, as Batfish modelled it, permits (or
denies) nothing in this space.* Three things sit between that and "the device
behaves this way", and none of them is checked by `searchFilters` itself:

1. **Is the filter actually in the traffic's path?** (measured below: no)
2. **Is Batfish's model of the config the same as what the device runs?**
3. **Does anything outside the filter change the answer?** Routing, NAT,
   state, other filters on the path.

## Where our approach sits

| Approach | What it checks | How | Example |
|---|---|---|---|
| Testing / spot checks | one packet at a time | simulate the packet | `testFilters`, `traceroute`, Capirca's `aclcheck` |
| **Data-plane verification, one filter** | **every packet in a space, one filter** | **BDDs / SMT over header space** | **`searchFilters` (ours)**, Microsoft SecGuru [3] |
| Data-plane verification, whole network | every packet, every path, for one computed forwarding state | header-space or BDD reachability | HSA [4], VeriFlow [5], Atomic Predicates [6], Batfish `reachability` |
| Control-plane verification | every forwarding state the configs can produce, e.g. under link failures or any BGP input | SMT encoding of the routing protocols | Minesweeper [7] |
| Language-level equivalence | whether two network programs behave identically | algebra / automata | NetKAT [8] |

Each row down proves something stronger and costs more. We are on the second
row. SecGuru is the closest industrial match: Microsoft has checked Azure ACLs
against "contracts" with an SMT solver since 2013 [3], which is very close to
what a `policy_compliance` rule is.

## What it can prove — measured

A router identical to `rtr-us5-secure` except for one extra line, a hole one
host and one port wide:

```
permit tcp host 10.10.10.77 host 10.20.0.5 eq 8443
```

The rule is "nothing from the LAN reaches the server except TCP/443":

```
searchFilters                    1 flow in 0.14 s
                                 10.10.10.77:49152 -> 10.20.0.5:8443 TCP (SYN)
testFilters, 300 random flows    0 of 300 hit the hole, 48.2 s
```

Each random flow hits the hole with probability 1/254 × 1/65,534, about
6 × 10⁻⁸. Finding it by sampling would take about 16.6 million tests on
average, or around a month at the measured 0.16 s each. Proving it took one
query. This is the case for `searchFilters` over spot checks, and it is
why `policy_compliance` was built on it.

## What it cannot prove — measured

### 1. That the filter is in the path

Same router, with `ip access-group acl_in in` removed, so the ACL exists but
is applied nowhere. Full pipeline:

```
AC-001  found  medium  Filter 'acl_in' is defined but never applied
PC-000  none   low     No issues found by policy compliance
traceroute LAN -> 10.20.0.5 TCP/23    DELIVERED_TO_SUBNET
```

`PC-000` is a green tick. Every prohibition "holds", because the ACL would
deny the traffic **if traffic ever went through it**. Meanwhile telnet from
the LAN reaches the server. The proof is correct about the filter and wrong
about the network.

`access_control`'s AC-001 does report the unapplied filter, so the user is not
left with nothing. But it is a `medium` card about hygiene, sitting beside a
green tick from the check whose job is the policy. Reading the screen, the
policy looks satisfied. Under F-4 that is the wrong answer: the check did not
verify what its tick claims.

### 2. That the model matches the device

Every answer is about Batfish's model. Brown et al. found that most of
Batfish's modelling problems come from the variety of configuration
languages, not from router bugs [2]. We already handle part of this: a
partly parsed file is reported (#217, #317). But #400 measured the other part:
nine of twelve CIS hardening lines parsed as `PASSED` with zero warnings and
were not modelled at all. A clean parse is not a complete model.

### 3. Anything outside one filter

- **Routing.** A permitted packet with no route does not arrive. We check the
  filter, not the path. `differentialReachability` in `change_impact` and
  `traceroute` in `routing` do look at paths, but `policy_compliance` does not.
- **Other filters.** An outbound ACL on the server's interface can deny what
  `acl_in` permits. A prohibition then reports `found` when the network is
  actually safe. That direction is noisy rather than dangerous.
- **State and NAT.** `searchFilters` is stateless. Return traffic, reflexive
  ACLs, zone-based firewalls and NAT are not part of the question.
- **Failures and other inputs.** The answer is for the configs as uploaded.
  Minesweeper-style checking [7] can ask "does this still hold if any one link
  fails?" Nothing in Netwise can, and the client's single firewall makes it a
  low priority.

## What this suggests for Netwise

**One change, and it is in my own check: a rule about a filter that is not
applied anywhere on its device must not report `none`.** Before trusting an
empty `searchFilters` answer, `policy_compliance` should confirm the filter is
some interface's incoming or outgoing filter (`interfaceProperties`). If it is
not, the rule reports **could not check**, naming the filter, not a pass.
That is F-4's own rule applied to the gap above, and it needs no format change
or team decision. Raised as #430 and fixed in its own PR.

Two smaller things:

- **Wording.** `docs/policy-rules.md` §2 says `searchFilters` "cannot be
  fooled in either direction" and that an empty result "means exactly one
  thing: the policy holds". The unapplied filter fools it. The fix PR
  qualifies both sentences in the same commit as the behaviour change, so the
  document never claims more than the code does.
- **Path-level policy.** Checking a prohibition with `reachability` instead of
  `searchFilters` would remove limits 1 and 3 together. `docs/policy-rules.md`
  §2 records why we chose `searchFilters` (it isolates the filter, and
  `reachability` needed routes the fixtures did not have). That trade is still
  right for one-router fixtures, and should be revisited when the client's
  multi-interface firewall can be loaded (#78).

**Not suggested:** control-plane verification. It answers a question about
routing under failures that nobody on this project or at the client is asking,
and Batfish's own authors report that engineers wanted simpler checks more
than broader proofs [2].

## Sources

1. R. E. Bryant, "Graph-Based Algorithms for Boolean Function Manipulation,"
   *IEEE Transactions on Computers*, C-35(8), 1986. The data structure behind
   Batfish's header-space search.
2. M. Brown, A. Fogel, D. Halperin, V. Heorhiadi, R. Mahajan, T. Millstein,
   "Lessons from the evolution of the Batfish configuration analysis tool,"
   *ACM SIGCOMM 2023*. doi:10.1145/3603269.3604866.
   <https://foci.uw.edu/papers/sigcomm23-batfish-lessons.pdf>
3. K. Jayaraman et al., "Validating Datacenters at Scale," *ACM SIGCOMM 2019*.
   <https://www.microsoft.com/en-us/research/publication/validating-datacenters-at-scale/>
4. P. Kazemian, G. Varghese, N. McKeown, "Header Space Analysis: Static
   Checking for Networks," *USENIX NSDI 2012*.
5. A. Khurshid et al., "VeriFlow: Verifying Network-Wide Invariants in Real
   Time," *USENIX NSDI 2013*.
6. H. Yang, S. S. Lam, "Real-time Verification of Network Properties using
   Atomic Predicates," *IEEE ICNP 2013*.
7. R. Beckett, A. Gupta, R. Mahajan, D. Walker, "A General Approach to Network
   Configuration Verification," *ACM SIGCOMM 2017*.
8. C. J. Anderson et al., "NetKAT: Semantic Foundations for Networks,"
   *ACM POPL 2014*.
9. A. Fogel et al., "A General Approach to Network Configuration Analysis,"
   *USENIX NSDI 2015*. The original Batfish paper.

## Reproducing the measurements

Both configs are `tests/fixtures/rtr-us5-secure` with a second interface
(`GigabitEthernet0/1`, `10.20.0.1/24`) so traceroute has somewhere to go:

- **narrow hole:** add `permit tcp host 10.10.10.77 host 10.20.0.5 eq 8443`
  before `deny ip any any`
- **unapplied:** remove `ip access-group acl_in in`

Then run `python -m analysis.pipeline <dir>`, and
`bf.q.searchFilters(headers=HeaderConstraints(srcIps="10.10.10.0/24",
dstIps="10.20.0.5", ipProtocols=["tcp"], dstPorts="0-442,444-65535"),
filters="acl_in", action="permit")`. The random sample used `random.seed(423)`
and one `testFilters` call per flow.
