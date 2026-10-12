"""A policy drafted from the user's own config (#326, US-34).

THREE PARTS, IN THE ORDER THE GUARANTEES MATTER

    1. The loader refuses a draft until a person has made every decision in
       it. This is the "never applied automatically" criterion, and it is
       the one that matters most: a draft describes what the config DOES,
       and a policy that says "the config should do what it does" passes on
       every config ever written, the insecure one included.

    2. The drafter, against a fake session shaped exactly like the tables
       real Batfish returned on 29 September. No Batfish needed.

    3. The same claims against real Batfish, skipped when it is not running.
"""

import copy
import json

import pytest

from analysis.policy import PolicyError, load_policy

#: One drafted rule, as the drafter writes it: the facts filled in, the two
#: judgements left as placeholders.
DRAFTED_RULE = {
    "description": "rtr-us5 acl_in line 1: permit udp 10.10.10.0 0.0.0.255 host 218.8.104.58 eq domain",
    "node": "rtr-us5",
    "filter": "acl_in",
    "kind": "<FILL IN: requirement or prohibition>",
    "queries": [{"srcIps": "10.10.10.0/24", "dstIps": "218.8.104.58",
                 "ipProtocols": ["udp"], "dstPorts": "53"}],
    "violation_severity": "<FILL IN: high, medium or low>",
    "violation_summary": "acl_in on rtr-us5 does not treat this traffic as your policy requires",
}


def _draft(rules=2):
    second = dict(DRAFTED_RULE, description="rtr-us5 acl_in line 2: permit tcp any host 10.20.0.5 eq 443")
    return {
        "draft": {"status": "UNREVIEWED DRAFT"},
        "policy_compliance": [copy.deepcopy(DRAFTED_RULE), copy.deepcopy(second)][:rules],
    }


def _decided(data):
    """What a user does to a draft: make every decision, delete the block."""
    data = copy.deepcopy(data)
    data.pop("draft", None)
    for rule in data["policy_compliance"]:
        rule["kind"] = "requirement"
        rule["violation_severity"] = "medium"
    return data


# --- 1. The loader refuses a draft nobody has reviewed ------------------------


def test_an_unreviewed_draft_is_refused_naming_every_decision_left():
    with pytest.raises(PolicyError) as refused:
        load_policy(_draft())
    message = str(refused.value)
    assert "4 decision(s)" in message
    # BOTH entries named, not just the first: a user fixing a 40-rule draft
    # must not discover the decisions one upload at a time.
    assert "policy_compliance entry 1" in message
    assert "policy_compliance entry 2" in message
    assert "kind" in message and "violation_severity" in message


def test_a_draft_with_every_decision_made_is_refused_until_its_draft_block_is_deleted():
    decided = _decided(_draft())
    decided["draft"] = {"status": "UNREVIEWED DRAFT"}
    with pytest.raises(PolicyError, match="delete the top-level 'draft' block"):
        load_policy(decided)


def test_a_placeholder_left_anywhere_is_refused_even_without_the_draft_block():
    decided = _decided(_draft())
    decided["policy_compliance"][1]["queries"][0]["dstIps"] = "<FILL IN: destination>"
    with pytest.raises(PolicyError) as refused:
        load_policy(decided)
    # Named down to the nested key, because "entry 2 has a placeholder
    # somewhere" is a scavenger hunt.
    assert "policy_compliance entry 2" in str(refused.value)
    assert "queries[0].dstIps" in str(refused.value)


def test_a_reviewed_draft_loads_with_the_rules_the_user_decided():
    loaded = load_policy(_decided(_draft()))
    rules = loaded.entries_for("policy_compliance")
    assert [r["kind"] for r in rules] == ["requirement", "requirement"]
    assert rules[0]["queries"] == DRAFTED_RULE["queries"]


def test_the_refusal_is_the_draft_message_not_a_value_error_for_entry_one():
    """Before #326 the same file was refused by #375's value check, which
    names ONE entry and says nothing about the file being a draft."""
    with pytest.raises(PolicyError) as refused:
        load_policy(_draft())
    assert "not been reviewed" in str(refused.value)
    assert "must be one of" not in str(refused.value)
    assert "unknown section" not in str(refused.value)


def test_a_long_draft_lists_its_first_entries_and_counts_the_rest():
    data = _draft()
    data["policy_compliance"] = [copy.deepcopy(DRAFTED_RULE) for _ in range(30)]
    with pytest.raises(PolicyError) as refused:
        load_policy(data)
    message = str(refused.value)
    assert "60 decision(s)" in message
    assert "policy_compliance entry 10 " in message
    assert "policy_compliance entry 11 " not in message
    assert "and 20 more entries" in message


def test_the_draft_json_round_trips_through_a_file(tmp_path):
    """The web download and the CLI both write JSON; the loader reads it."""
    from analysis.policy import load_policy_file

    path = tmp_path / "draft.json"
    path.write_text(json.dumps(_draft()), encoding="utf-8")
    with pytest.raises(PolicyError, match="not been reviewed"):
        load_policy_file(path)
    path.write_text(json.dumps(_decided(_draft())), encoding="utf-8")
    assert len(load_policy_file(path).entries_for("policy_compliance")) == 2


# --- 2. The drafter, against tables shaped like real Batfish's ----------------
#
# Every shape below was printed from real Batfish on 29 September: the line
# dicts from namedStructures on rtr-us5-secure / rtr-us5-messy / vendor-juniper,
# the Source_Lines from definedStructures, the searchFilters columns and its
# counter-example on rtr-us5-messy.

import pandas as pd  # noqa: E402
from pybatfish.datamodel.primitives import FileLines, Interface  # noqa: E402

from analysis import draft_policy  # noqa: E402
from analysis.checks import policy_compliance  # noqa: E402

CFG = "configs/rtr-us5.cfg"


def _wild(value):
    return {"class": "org.batfish.datamodel.IpWildcardIpSpace", "ipWildcard": value}


def _line(action, text, header_space=None, match_class="MatchHeaderSpace",
          line_class="ExprAclLine", acl="acl_in", filename=CFG, cite=True):
    match = {"class": f"org.batfish.datamodel.acl.{match_class}"}
    if match_class == "MatchHeaderSpace":
        match["headerSpace"] = dict({"negate": False}, **(header_space or {}))
    line = {"class": f"org.batfish.datamodel.{line_class}", "action": action,
            "matchCondition": match, "name": text}
    if cite:
        line["vendorStructureId"] = {
            "filename": filename,
            "structureName": f"{acl}: {text}",
            "structureType": "extended ipv4 access-list line",
        }
    return line


DNS = _line("PERMIT", "permit udp 10.10.10.0 0.0.0.255 host 218.8.104.58 eq domain",
            {"srcIps": _wild("10.10.10.0/24"), "dstIps": _wild("218.8.104.58"),
             "ipProtocols": ["UDP"], "dstPorts": ["53-53"]})
HTTPS = _line("PERMIT", "permit tcp 10.10.10.0 0.0.0.255 host 10.20.0.5 eq 443",
              {"srcIps": _wild("10.10.10.0/24"), "dstIps": _wild("10.20.0.5"),
               "ipProtocols": ["TCP"], "dstPorts": ["443-443"]})
DENY_ALL = _line("DENY", "deny   ip any any",
                 {"srcIps": _wild("0.0.0.0/0"), "dstIps": _wild("0.0.0.0/0")})

#: The counter-example real Batfish gave for rtr-us5-secure's catch-all deny:
#: an earlier line PERMITS some of the traffic `deny ip any any` describes.
DNS_PERMITTED = ("start=rtr-us5 [10.10.10.0:49152->218.8.104.58:53 UDP]", "PERMIT",
                 "permit udp 10.10.10.0 0.0.0.255 host 218.8.104.58 eq domain")


class _Answer:
    def __init__(self, frame):
        self._frame = frame

    def answer(self):
        return self

    def frame(self):
        return self._frame


class _Session:
    """Answers the five questions the drafter asks, and records searchFilters.

    `search` maps (filter, action, headers-as-sorted-items) to the rows
    Batfish would return; anything absent returns no rows, which is what
    real Batfish says when a drafted rule holds.
    """

    def __init__(self, acls, applied=(("rtr-us5", "GigabitEthernet0/0", "acl_in", None),),
                 files=((CFG, "PASSED", ["rtr-us5"]),), search=None, search_raises=False):
        outer = self
        self.searches = []
        defined = []
        for node, name, lines in acls:
            for position, line in enumerate(lines, start=1):
                vid = line.get("vendorStructureId")
                if vid:
                    defined.append((vid["structureType"], vid["structureName"],
                                    FileLines(vid["filename"], [20 + position])))

        class _Q:
            def fileParseStatus(self):
                return _Answer(pd.DataFrame(
                    [(f, s, "CISCO_IOS", n) for f, s, n in files],
                    columns=["File_Name", "Status", "File_Format", "Nodes"]))

            def interfaceProperties(self, properties=None):
                return _Answer(pd.DataFrame(
                    [(Interface(hostname=n, interface=i), inc, out) for n, i, inc, out in applied],
                    columns=["Interface", "Incoming_Filter_Name", "Outgoing_Filter_Name"]))

            def namedStructures(self, structureTypes=None):
                return _Answer(pd.DataFrame(
                    [(n, "IP_ACCESS_LIST", name, {"lines": lines}) for n, name, lines in acls],
                    columns=["Node", "Structure_Type", "Structure_Name", "Structure_Definition"]))

            def definedStructures(self):
                return _Answer(pd.DataFrame(defined, columns=["Structure_Type", "Structure_Name", "Source_Lines"]))

            def searchFilters(self, nodes=None, filters=None, action=None, headers=None):
                asked = {k: v for k, v in headers.dict().items() if v is not None}
                outer.searches.append((nodes, filters, action, asked))
                if search_raises:
                    raise RuntimeError("Batfish could not answer")
                key = (filters, action, tuple(sorted((k, str(v)) for k, v in asked.items())))
                rows = [(nodes, filters, flow, act, content, None)
                        for flow, act, content in (search or {}).get(key, [])]
                return _Answer(pd.DataFrame(
                    rows, columns=["Node", "Filter_Name", "Flow", "Action", "Line_Content", "Trace"]))

        self.q = _Q()


def _secure():
    """rtr-us5-secure: two permits, then a catch-all deny that is NOT the
    whole story -- the permits above it let DNS and HTTPS through."""
    return _Session(
        [("rtr-us5", "acl_in", [DNS, HTTPS, DENY_ALL])],
        search={("acl_in", "permit", (("dstIps", "0.0.0.0/0"), ("srcIps", "0.0.0.0/0"))):
                [DNS_PERMITTED]},
    )


def test_each_permit_line_becomes_one_rule_with_that_lines_traffic():
    rules = draft_policy.draft_policy(_secure())["policy_compliance"]
    assert len(rules) == 2
    assert rules[0]["node"] == "rtr-us5" and rules[0]["filter"] == "acl_in"
    assert rules[0]["queries"] == [{"srcIps": "10.10.10.0/24", "dstIps": "218.8.104.58",
                                    "ipProtocols": ["udp"], "dstPorts": "53"}]
    assert rules[1]["queries"] == [{"srcIps": "10.10.10.0/24", "dstIps": "10.20.0.5",
                                    "ipProtocols": ["tcp"], "dstPorts": "443"}]


def test_every_drafted_rule_cites_the_file_and_line_it_came_from():
    rules = draft_policy.draft_policy(_secure())["policy_compliance"]
    assert "permit udp 10.10.10.0 0.0.0.255 host 218.8.104.58 eq domain" in rules[0]["description"]
    assert "configs/rtr-us5.cfg:[21]" in rules[0]["description"]
    assert "configs/rtr-us5.cfg:[22]" in rules[1]["description"]


def test_a_rule_is_verified_by_asking_batfish_for_the_opposite_decision():
    """A permit line is checked with action=deny: any denied packet in its
    space means some of its traffic is NOT decided by it."""
    session = _secure()
    draft_policy.draft_policy(session)
    actions = [(filters, action) for _, filters, action, _ in session.searches]
    assert actions == [("acl_in", "deny"), ("acl_in", "deny"), ("acl_in", "permit")]


def test_the_judgements_are_placeholders_that_say_what_the_filter_does_today():
    rules = draft_policy.draft_policy(_secure())["policy_compliance"]
    assert rules[0]["kind"].startswith("<FILL IN")
    assert "PERMITS" in rules[0]["kind"]
    assert rules[0]["violation_severity"].startswith("<FILL IN")


def test_a_deny_line_says_it_blocks():
    session = _Session([("rtr-us5", "acl_in", [DENY_ALL])])
    (rule,) = draft_policy.draft_policy(session)["policy_compliance"]
    assert "BLOCKS" in rule["kind"]
    assert rule["queries"] == [{"srcIps": "0.0.0.0/0", "dstIps": "0.0.0.0/0"}]


def test_a_line_an_earlier_line_partly_decides_is_not_drafted_and_says_why():
    """The catch-all deny on rtr-us5-secure: an earlier line permits DNS, so
    'all traffic is blocked' would be false. Named with Batfish's own example."""
    result = draft_policy.draft_policy(_secure())
    (note,) = result["draft"]["not_drafted"]
    assert "deny   ip any any" in note
    assert "configs/rtr-us5.cfg:[23]" in note
    assert "10.10.10.0:49152->218.8.104.58:53 UDP" in note
    assert "permit udp 10.10.10.0 0.0.0.255 host 218.8.104.58 eq domain" in note


def test_the_draft_is_refused_by_the_loader_exactly_as_generated():
    with pytest.raises(PolicyError, match="not been reviewed"):
        load_policy(draft_policy.draft_policy(_secure()))


def test_the_draft_is_plain_json():
    """No pandas or numpy value may leak into it: the web layer and the CLI
    both serialise it, and a numpy int breaks json.dumps. Round-tripped rather
    than only dumped, so a tuple silently becoming a list fails too."""
    draft = draft_policy.draft_policy(_secure())
    assert json.loads(json.dumps(draft)) == draft


@pytest.mark.parametrize("line, reason", [
    (_line("DENY", "block-smb", match_class="AndMatchExpr"), "AndMatchExpr"),
    (_line("PERMIT", "permit tcp any any established",
           {"srcIps": _wild("0.0.0.0/0"), "tcpFlagsMatchConditions": [{"x": 1}]}),
     "tcpFlagsMatchConditions"),
    (_line("PERMIT", "permit ip object-group LAN any",
           {"srcIps": {"class": "org.batfish.datamodel.IpSpaceReference", "name": "LAN"}}),
     "IpSpaceReference"),
    (_line("PERMIT", "permit ip 10.0.0.0 0.255.0.255 any",
           {"srcIps": _wild("10.0.0.0:0.255.0.255")}), "10.0.0.0:0.255.0.255"),
    (_line("PERMIT", "permit ip any any negated", {"negate": True}), "negate"),
    (_line("PERMIT", "permit ip any any", line_class="AclAclLine"), "AclAclLine"),
], ids=["compound-match", "tcp-flags", "object-group", "wildcard", "negated", "nested-acl"])
def test_a_line_that_cannot_be_written_down_exactly_is_refused_not_approximated(line, reason):
    session = _Session([("rtr-us5", "acl_in", [line])])
    result = draft_policy.draft_policy(session)
    assert result["policy_compliance"] == []
    (note,) = result["draft"]["not_drafted"]
    assert reason in note
    assert session.searches == [], "a line we cannot express must not be sent to Batfish at all"


def test_a_line_with_no_config_line_to_cite_is_not_drafted():
    """US-34: every generated rule cites the line it came from. Batfish
    generates some lines itself; those have nothing to cite."""
    session = _Session([("rtr-us5", "acl_in", [dict(DNS, vendorStructureId=None)])])
    result = draft_policy.draft_policy(session)
    assert result["policy_compliance"] == []
    assert "cite" in result["draft"]["not_drafted"][0]


def test_a_filter_applied_to_no_interface_is_named_not_drafted():
    session = _Session([("rtr-us5", "SERVER_IN", [DNS])], applied=())
    result = draft_policy.draft_policy(session)
    assert result["policy_compliance"] == []
    (note,) = result["draft"]["not_drafted"]
    assert "SERVER_IN" in note and "not applied to any interface" in note
    assert session.searches == []


def test_an_outbound_filter_is_drafted_too():
    session = _Session([("rtr-us5", "acl_out", [DNS])],
                       applied=(("rtr-us5", "Gi0/0", None, "acl_out"),))
    assert len(draft_policy.draft_policy(session)["policy_compliance"]) == 1


def test_batfish_generated_filters_are_not_reported_as_unapplied():
    """Names starting '~' are Batfish's own structures, not the user's."""
    session = _Session([("rtr-us5", "~ZONE_ACL~", [DNS])], applied=())
    notes = draft_policy.draft_policy(session)["draft"]["not_drafted"]
    assert not any("~ZONE_ACL~" in note for note in notes)


def test_nothing_is_drafted_from_a_file_batfish_only_partly_read():
    """vendor-asa is PARTIALLY_UNRECOGNIZED. A line Batfish never parsed is
    missing from its model, so a rule 'verified' against that model could
    describe a filter the device does not have."""
    session = _Session([("fw-asa", "OUTSIDE_IN", [DNS])],
                       applied=(("fw-asa", "Gi0/0", "OUTSIDE_IN", None),),
                       files=(("configs/fw-asa.cfg", "PARTIALLY_UNRECOGNIZED", ["fw-asa"]),))
    result = draft_policy.draft_policy(session)
    assert result["policy_compliance"] == []
    (note,) = result["draft"]["not_drafted"]
    assert "configs/fw-asa.cfg" in note and "PARTIALLY_UNRECOGNIZED" in note
    assert session.searches == []


def test_a_config_with_no_applied_filter_says_so_rather_than_nothing():
    """tests/fixtures/routing-faults has no filters. Before this, its draft said
    '0 rule(s) drafted; 0 item(s) not drafted' and never why -- "there was
    nothing to draft from" wearing "we looked and found nothing" (#266)."""
    session = _Session([], applied=())
    (note,) = draft_policy.draft_policy(session)["draft"]["not_drafted"]
    assert "No filter is applied to any interface" in note


def test_a_line_batfish_could_not_check_is_not_drafted():
    session = _Session([("rtr-us5", "acl_in", [DNS])], search_raises=True)
    result = draft_policy.draft_policy(session)
    assert result["policy_compliance"] == []
    assert "could not check" in result["draft"]["not_drafted"][0]


def test_a_match_on_everything_is_drafted_as_an_empty_header_space():
    """Juniper's `allow-all` term: TrueExpr, which matches every packet."""
    line = _line("PERMIT", "allow-all", match_class="TrueExpr")
    (rule,) = draft_policy.draft_policy(_Session([("rtr-us5", "acl_in", [line])]))["policy_compliance"]
    assert rule["queries"] == [{}]


def test_the_draft_stops_at_the_number_of_rules_policy_compliance_can_number():
    """policy_compliance puts rule n's error at PC-(n+50) and reserves 49 and
    50, so a 49th rule would collide. Lines past the limit are counted, and
    are not sent to Batfish."""
    many = [_line("PERMIT", f"permit tcp any host 10.0.0.{i} eq 443",
                  {"dstIps": _wild(f"10.0.0.{i}"), "ipProtocols": ["TCP"], "dstPorts": ["443-443"]})
            for i in range(1, 61)]
    session = _Session([("rtr-us5", "acl_in", many)])
    result = draft_policy.draft_policy(session)
    assert len(result["policy_compliance"]) == policy_compliance.HIGHEST_POLICY_NUMBER == 48
    assert len(session.searches) == 48
    assert any("12 more line(s)" in note for note in result["draft"]["not_drafted"])


def test_rules_come_out_in_device_then_filter_order():
    session = _Session(
        [("rtr-b", "acl_z", [DNS]), ("rtr-a", "acl_y", [HTTPS]), ("rtr-a", "acl_x", [DNS])],
        applied=(("rtr-b", "g0", "acl_z", None), ("rtr-a", "g0", "acl_y", "acl_x")),
        files=((CFG, "PASSED", ["rtr-a", "rtr-b"]),))
    rules = draft_policy.draft_policy(session)["policy_compliance"]
    assert [(r["node"], r["filter"]) for r in rules] == [
        ("rtr-a", "acl_x"), ("rtr-a", "acl_y"), ("rtr-b", "acl_z")]


# --- 3. Against real Batfish --------------------------------------------------

from pathlib import Path  # noqa: E402

from conftest import needs_batfish  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"


def _real_draft(fixture):
    from analysis import pipeline

    bf = pipeline.connect()
    pipeline.load_snapshot(bf, FIXTURES / fixture, "netwise-test-draft", fixture)
    return draft_policy.draft_policy(bf)


def _as_it_is_today(draft):
    """Every decision made as 'keep what the filter does today'."""
    decided = copy.deepcopy(draft)
    decided.pop("draft")
    for rule in decided["policy_compliance"]:
        rule["kind"] = "requirement" if "PERMITS" in rule["kind"] else "prohibition"
        rule["violation_severity"] = "medium"
    return decided


def _policy_compliance(fixture, data):
    from analysis import pipeline

    results = pipeline.analyse(FIXTURES / fixture, check_names=["policy_compliance"],
                               policy=load_policy(data))
    return [(r["id"], r["status"]) for r in results]


@needs_batfish
def test_real_secure_config_drafts_its_two_permits_and_refuses_the_catch_all():
    draft = _real_draft("rtr-us5-secure")
    assert [r["queries"] for r in draft["policy_compliance"]] == [
        [{"srcIps": "10.10.10.0/24", "dstIps": "218.8.104.58", "ipProtocols": ["udp"], "dstPorts": "53"}],
        [{"srcIps": "10.10.10.0/24", "dstIps": "10.20.0.5", "ipProtocols": ["tcp"], "dstPorts": "443"}],
    ]
    (note,) = draft["draft"]["not_drafted"]
    assert "deny   ip any any" in note and "PERMITTED by 'permit" in note


@needs_batfish
def test_real_messy_config_refuses_the_permits_an_earlier_deny_swallows():
    """rtr-us5-messy denies all LAN traffic on line 1, so its DNS and HTTPS
    permits never fire. The draft must say so, not claim they allow anything."""
    draft = _real_draft("rtr-us5-messy")
    kinds = [(r["description"].split(":")[0], "BLOCKS" in r["kind"]) for r in draft["policy_compliance"]]
    assert kinds == [("rtr-us5 acl_in line 1", True), ("rtr-us5 acl_in line 4", True)]
    refused = [n for n in draft["draft"]["not_drafted"] if "acl_in line" in n]
    assert len(refused) == 2
    assert all("DENIED by 'deny   ip 10.10.10.0 0.0.0.255 any'" in n for n in refused)


@needs_batfish
@pytest.mark.parametrize("fixture", ["rtr-us5-secure", "rtr-us5-messy", "rtr-us5-insecure",
                                     "vendor-arista", "vendor-juniper"])
def test_every_real_citation_names_the_line_it_quotes(fixture):
    """Batfish's line number, read back out of the real file. A citation that
    points at the wrong line is worse than none."""
    draft = _real_draft(fixture)
    assert draft["policy_compliance"], f"{fixture} drafted nothing, so this checked nothing"
    for rule in draft["policy_compliance"]:
        quoted = rule["description"].split(": ", 1)[1].rsplit(" (", 1)[0]
        cite = rule["description"].rsplit(" (", 1)[1].rstrip(")")
        filename, lines = cite.split(":[")
        first = int(lines.rstrip("]").split(",")[0])
        text = (FIXTURES / fixture / filename).read_text(encoding="utf-8").splitlines()[first - 1]
        assert quoted.strip() in text, (cite, quoted, text)


@needs_batfish
@pytest.mark.parametrize("fixture", ["rtr-us5-secure", "rtr-us5-messy", "rtr-us5-insecure"])
def test_a_draft_decided_as_it_is_today_passes_the_real_check(fixture):
    """The draft's promise: every rule holds for the config it came from.
    Asked with the same check the user's policy will meet."""
    assert _policy_compliance(fixture, _as_it_is_today(_real_draft(fixture))) == [("PC-000", "none")]


@needs_batfish
def test_flipping_one_decision_produces_a_real_finding():
    """What the draft is FOR: the user marks the DNS rule as traffic that must
    be blocked, and the check reports that the config allows it."""
    decided = _as_it_is_today(_real_draft("rtr-us5-secure"))
    decided["policy_compliance"][0]["kind"] = "prohibition"
    assert ("PC-001", "found") in _policy_compliance("rtr-us5-secure", decided)


@needs_batfish
def test_the_insecure_config_passes_a_draft_accepted_as_it_stands():
    """WHY THE LOADER REFUSES AN UNREVIEWED DRAFT, measured rather than argued.
    rtr-us5-insecure ends in `permit ip any any`; its draft, accepted as is,
    reports it clean. Delete the refusal and this is what a user would see."""
    decided = _as_it_is_today(_real_draft("rtr-us5-insecure"))
    assert any("permit ip any any" in r["description"] for r in decided["policy_compliance"])
    assert _policy_compliance("rtr-us5-insecure", decided) == [("PC-000", "none")]


@needs_batfish
def test_real_partly_read_asa_drafts_nothing():
    draft = _real_draft("vendor-asa")
    assert draft["policy_compliance"] == []
    assert any("PARTIALLY_UNRECOGNIZED" in n for n in draft["draft"]["not_drafted"])


@needs_batfish
def test_real_nxos_filter_applied_nowhere_is_named():
    draft = _real_draft("vendor-nxos")
    assert draft["policy_compliance"] == []
    assert any("SERVER_IN" in n and "not applied" in n for n in draft["draft"]["not_drafted"])


@needs_batfish
def test_real_juniper_compound_term_is_refused_and_match_all_term_drafted():
    draft = _real_draft("vendor-juniper")
    assert [r["queries"] for r in draft["policy_compliance"]] == [[{}]]
    assert any("block-smb" in n and "AndMatchExpr" in n for n in draft["draft"]["not_drafted"])
