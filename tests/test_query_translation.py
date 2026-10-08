"""
Netwise -- tests for ai/query.py, the English-question-to-answer translation
(US-11).

WHY THIS FILE EXISTS
    ai/query.py's module docstring explains the shape: classify a question's
    intent against a closed set of three, resolve any named device/address
    against the real snapshot, and refuse rather than guess the moment
    either step is not confident. These are pure decisions over a string and
    a fake session, no Batfish or Ollama needed, so they are tested directly
    here the same way tests/test_routing_classification.py and
    tests/test_device_scoping.py already test this kind of logic.

RUN
    pytest tests/ -v
"""

import pytest

from ai.query import answer_question


class FakeHop:
    def __init__(self, node: str):
        self.node = node


class FakeTrace:
    def __init__(self, disposition: str, hops=None):
        self.disposition = disposition
        self.hops = hops or [FakeHop("some-node")]


class _FakeAnswer:
    """The real call is bf.q.X().answer().frame() -- three steps, same
    double shape test_device_scoping.py already uses for the same reason."""

    def __init__(self, frame):
        self._frame = frame

    def answer(self):
        return self

    def frame(self):
        return self._frame


class _FakeFrame:
    """Just enough of a pandas frame for the code under test: `.empty`,
    `len()`, `.iloc[0][column]` (traceroute/whole-snapshot results), and
    `.iterrows()` yielding (index, row) with dict-like rows (fileParseStatus,
    same shape tests/test_device_scoping.py already uses for the same
    reason)."""

    def __init__(self, rows):
        self._rows = rows

    @property
    def empty(self):
        return len(self._rows) == 0

    def __len__(self):
        return len(self._rows)

    def iterrows(self):
        return enumerate(self._rows)

    class _Iloc:
        def __init__(self, rows):
            self._rows = rows

        def __getitem__(self, index):
            return self._rows[index]

    @property
    def iloc(self):
        return self._Iloc(self._rows)


class _FakeQuestions:
    """Configurable per-question-name responses, plus an optional raiser.

    `devices=None` means fileParseStatus() itself fails, so
    snapshot.device_names() returns None -- "could not determine", not "no
    devices". `devices={...}` (including the empty set) means it succeeds.
    """

    def __init__(
        self, *, devices=frozenset(), traceroute_frame=None,
        whole_snapshot_frame=None, raises=False,
    ):
        self._devices = devices
        self._traceroute_frame = traceroute_frame
        self._whole_snapshot_frame = whole_snapshot_frame
        self._raises = raises
        # What traceroute() was actually called with, so a test can check
        # what address query.py resolved and handed to Batfish, not just
        # what it printed back -- the #70 fix is entirely about those two
        # no longer being different things.
        self.traceroute_calls = []

    def fileParseStatus(self, **_kwargs):
        if self._devices is None:
            raise RuntimeError("Batfish said no")
        return _FakeAnswer(_FakeFrame([{"Nodes": sorted(self._devices)}]))

    def traceroute(self, **kwargs):
        self.traceroute_calls.append(kwargs)
        if self._raises:
            raise RuntimeError("Batfish said no")
        return _FakeAnswer(self._traceroute_frame)

    def filterLineReachability(self, **_kwargs):
        if self._raises:
            raise RuntimeError("Batfish said no")
        return _FakeAnswer(self._whole_snapshot_frame)

    def undefinedReferences(self, **_kwargs):
        if self._raises:
            raise RuntimeError("Batfish said no")
        return _FakeAnswer(self._whole_snapshot_frame)


class FakeSession:
    def __init__(self, questions):
        self.q = questions


def _session_with_devices(devices, **kwargs):
    return FakeSession(_FakeQuestions(devices=devices, **kwargs))


# --- Empty / unrecognised questions -------------------------------------------


def test_empty_question_is_refused():
    result = answer_question("", FakeSession(_FakeQuestions()))
    assert result["grounded"] is False
    assert result["question_understood"] is None


def test_whitespace_only_question_is_refused():
    result = answer_question("   ", FakeSession(_FakeQuestions()))
    assert result["grounded"] is False


def test_unrecognised_question_is_refused_not_guessed():
    result = answer_question(
        "What's the weather like on the guest network?", FakeSession(_FakeQuestions())
    )
    assert result["grounded"] is False
    assert result["question_understood"] is None
    assert "does not match" in result["answer"]


# --- Reachability: source resolution -------------------------------------------


# --- #108: a node location never crosses an inbound ACL ---------------------


def test_reachability_starts_from_the_entry_point_not_the_bare_device():
    """The bug itself. startLocation=source_device only sees traffic
    ORIGINATING at the device, so an inbound ACL is never traversed --
    measured live, this made a config that blocked the traffic and one that
    permitted everything answer identically, both "grounded: true". Checked
    at the boundary that matters, what was actually sent to Batfish."""
    frame = _FakeFrame([{"Traces": [FakeTrace("ACCEPTED")]}])
    session = _session_with_devices({"rtr-us5"}, traceroute_frame=frame)
    answer_question("Can rtr-us5 reach 10.20.0.5?", session)

    [call] = session.q.traceroute_calls
    assert call["startLocation"] == "@enter(rtr-us5)"


def test_reachability_refuses_when_no_known_device_is_named():
    session = _session_with_devices({"rtr-us5"})
    result = answer_question("Can the guest network reach 10.20.0.5?", session)
    assert result["grounded"] is False
    assert "known device name" in result["answer"]


def test_reachability_refuses_when_devices_could_not_be_determined():
    session = _session_with_devices(None)
    result = answer_question("Can rtr-us5 reach 10.20.0.5?", session)
    assert result["grounded"] is False
    assert "could not be determined" in result["answer"]


def test_device_name_matched_whole_word_not_as_a_substring():
    """"rtr-us5" must not spuriously match inside "rtr-us50" or similar --
    checked directly rather than assumed from the regex."""
    session = _session_with_devices({"rtr-us5"})
    result = answer_question("Can rtr-us50 reach 10.20.0.5?", session)
    assert result["grounded"] is False
    assert "known device name" in result["answer"]


# --- Reachability: destination resolution ---------------------------------------


def test_reachability_refuses_when_destination_is_not_a_valid_address():
    session = _session_with_devices({"rtr-us5"})
    result = answer_question("Can rtr-us5 reach the finance server?", session)
    assert result["grounded"] is False
    assert "IP address or network" in result["answer"]


def test_reachability_refuses_on_an_out_of_range_address():
    """999.1.1.1 matches the digit-dot-digit shape but is not a real IPv4
    address -- must be validated, not just pattern-matched."""
    session = _session_with_devices({"rtr-us5"})
    result = answer_question("Can rtr-us5 reach 999.1.1.1?", session)
    assert result["grounded"] is False


def test_reachability_accepts_a_cidr_destination():
    frame = _FakeFrame([{"Traces": [FakeTrace("ACCEPTED")]}])
    session = _session_with_devices({"rtr-us5"}, traceroute_frame=frame)
    result = answer_question("Can rtr-us5 reach 10.20.0.0/24?", session)
    assert result["grounded"] is True
    assert "10.20.0.0/24" in result["question_understood"]


# --- #70: a network destination is resolved to a real host, not the network
# address, and the substitution is named rather than silent -----------------


def test_cidr_destination_is_resolved_to_a_real_host_before_it_reaches_batfish():
    """The bug #70 found: Batfish resolves a bare CIDR destination to the
    network address, which is never a live host, so a real, reachable
    network reads as unreachable. Fixed by resolving the host ourselves --
    checked here at the boundary that matters, what was actually sent to
    Batfish, not just what the answer says."""
    frame = _FakeFrame([{"Traces": [FakeTrace("ACCEPTED")]}])
    session = _session_with_devices({"rtr-us5"}, traceroute_frame=frame)
    answer_question("Can rtr-us5 reach 10.20.20.0/24?", session)

    [call] = session.q.traceroute_calls
    assert call["headers"].dstIps == "10.20.20.1"


def test_cidr_destination_names_the_resolved_host_in_question_understood():
    frame = _FakeFrame([{"Traces": [FakeTrace("ACCEPTED")]}])
    session = _session_with_devices({"rtr-us5"}, traceroute_frame=frame)
    result = answer_question("Can rtr-us5 reach 10.20.20.0/24?", session)

    assert "10.20.20.0/24" in result["question_understood"]
    assert "10.20.20.1" in result["question_understood"]
    assert "checked" in result["question_understood"]


def test_cidr_destination_names_the_resolved_host_in_the_answer_too():
    """Not just question_understood -- the answer text names the same host,
    so it is never silently more specific than what the reader was told was
    checked."""
    frame = _FakeFrame([{"Traces": [FakeTrace("ACCEPTED")]}])
    session = _session_with_devices({"rtr-us5"}, traceroute_frame=frame)
    result = answer_question("Can rtr-us5 reach 10.20.20.0/24?", session)

    assert "10.20.20.1" in result["answer"]


def test_a_single_host_cidr_behaves_like_a_plain_address():
    """A /32 names exactly one address -- no "checked" phrasing is needed,
    and it must not silently become a different address than the one
    written."""
    frame = _FakeFrame([{"Traces": [FakeTrace("ACCEPTED")]}])
    session = _session_with_devices({"rtr-us5"}, traceroute_frame=frame)
    result = answer_question("Can rtr-us5 reach 10.20.20.5/32?", session)

    assert result["question_understood"] == "Can rtr-us5 reach 10.20.20.5?"
    [call] = session.q.traceroute_calls
    assert call["headers"].dstIps == "10.20.20.5"


def test_the_bug_scenario_from_70_now_answers_yes():
    """Reproduces #70's own repro directly: a network where every host is
    reachable must no longer answer "No" for the network as a whole."""
    frame = _FakeFrame([{"Traces": [FakeTrace("ACCEPTED")]}])
    session = _session_with_devices({"rtr-hq"}, traceroute_frame=frame)
    result = answer_question("Can rtr-hq reach 10.20.20.0/24?", session)

    assert result["answer"].startswith("Yes.")


# --- Reachability: the actual answer, grounded in real trace data --------------


def test_reachability_yes_when_every_trace_succeeds():
    frame = _FakeFrame([{"Traces": [FakeTrace("ACCEPTED"), FakeTrace("DELIVERED_TO_SUBNET")]}])
    session = _session_with_devices({"rtr-us5"}, traceroute_frame=frame)
    result = answer_question("Can rtr-us5 reach 218.8.104.58?", session)
    assert result["grounded"] is True
    assert result["answer"].startswith("Yes.")
    assert "rtr-us5" in result["question_understood"]
    assert "218.8.104.58" in result["question_understood"]


def test_reachability_no_when_every_trace_fails():
    frame = _FakeFrame(
        [{"Traces": [FakeTrace("DENIED_IN", hops=[FakeHop("rtr-us5")])]}]
    )
    session = _session_with_devices({"rtr-us5"}, traceroute_frame=frame)
    result = answer_question("Can rtr-us5 reach 218.8.104.58?", session)
    assert result["grounded"] is True
    assert result["answer"].startswith("No.")
    assert "DENIED_IN" in result["answer"]
    assert "rtr-us5" in result["answer"]


def test_reachability_exits_network_reads_as_failure():
    """Regression coverage for the same trap routing.py's own tests cover:
    EXITS_NETWORK is pybatfish's own idea of success for colouring a
    diagram, but this project measured it also fires for a destination
    that is simply absent from the snapshot -- must not read as "yes"."""
    frame = _FakeFrame([{"Traces": [FakeTrace("EXITS_NETWORK")]}])
    session = _session_with_devices({"rtr-us5"}, traceroute_frame=frame)
    result = answer_question("Can rtr-us5 reach 218.8.104.58?", session)
    assert result["answer"].startswith("No.")


def test_reachability_mixed_result_is_reported_not_picked():
    frame = _FakeFrame(
        [{"Traces": [FakeTrace("ACCEPTED"), FakeTrace("DENIED_IN")]}]
    )
    session = _session_with_devices({"rtr-us5"}, traceroute_frame=frame)
    result = answer_question("Can rtr-us5 reach 218.8.104.58?", session)
    assert result["grounded"] is True
    assert "Mixed result" in result["answer"]
    assert "disagree" in result["answer"]


def test_reachability_empty_frame_is_a_refusal():
    frame = _FakeFrame([])
    session = _session_with_devices({"rtr-us5"}, traceroute_frame=frame)
    result = answer_question("Can rtr-us5 reach 218.8.104.58?", session)
    assert result["grounded"] is False
    assert "no result" in result["answer"]


def test_reachability_batfish_failure_is_a_refusal_not_an_exception():
    session = _session_with_devices({"rtr-us5"}, raises=True)
    result = answer_question("Can rtr-us5 reach 218.8.104.58?", session)
    assert result["grounded"] is False
    assert "could not run this check" in result["answer"]
    # describe_error() is used, not a raw f"...{error}" -- same discipline
    # explain() and pipeline.py already hold, so the reason stays a bounded,
    # safe summary rather than a raw exception dump, confirmed by length
    # rather than assumed.
    assert len(result["answer"]) < 300


def test_reachability_still_returns_question_understood_when_batfish_fails():
    """Shape C must survive a downstream failure -- the caller should still
    see what was ASKED, even if it could not be ANSWERED."""
    session = _session_with_devices({"rtr-us5"}, raises=True)
    result = answer_question("Can rtr-us5 reach 218.8.104.58?", session)
    assert result["question_understood"] == "Can rtr-us5 reach 218.8.104.58?"


# --- Whole-snapshot questions: dead rules ---------------------------------------


def test_dead_rule_question_recognised_by_keyword():
    frame = _FakeFrame([])
    session = FakeSession(_FakeQuestions(whole_snapshot_frame=frame))
    result = answer_question("Are there any dead ACL rules?", session)
    assert result["grounded"] is True
    assert "never take effect" in result["question_understood"]


def test_dead_rule_question_recognised_with_different_phrasing():
    frame = _FakeFrame([])
    session = FakeSession(_FakeQuestions(whole_snapshot_frame=frame))
    result = answer_question("Does any rule never take effect?", session)
    assert result["grounded"] is True


def test_dead_rule_question_empty_result_says_no():
    frame = _FakeFrame([])
    session = FakeSession(_FakeQuestions(whole_snapshot_frame=frame))
    result = answer_question("Are there any dead rules?", session)
    assert result["answer"].startswith("No")


def test_dead_rule_question_nonempty_result_says_yes_with_a_count():
    frame = _FakeFrame([{"x": 1}, {"x": 2}])
    session = FakeSession(_FakeQuestions(whole_snapshot_frame=frame))
    result = answer_question("Are there any dead rules?", session)
    assert result["answer"].startswith("Yes, found 2")


def test_dead_rule_question_batfish_failure_is_a_refusal():
    session = FakeSession(_FakeQuestions(raises=True))
    result = answer_question("Are there any dead rules?", session)
    assert result["grounded"] is False
    assert "could not run this check" in result["answer"]


# --- Whole-snapshot questions: undefined references -----------------------------


def test_undefined_reference_question_recognised():
    frame = _FakeFrame([])
    session = FakeSession(_FakeQuestions(whole_snapshot_frame=frame))
    result = answer_question("Is anything referenced but not defined?", session)
    assert result["grounded"] is True
    assert "never defined" in result["question_understood"].lower()


def test_undefined_reference_question_nonempty_result():
    frame = _FakeFrame([{"x": 1}])
    session = FakeSession(_FakeQuestions(whole_snapshot_frame=frame))
    result = answer_question("Anything undefined in the config?", session)
    assert result["answer"].startswith("Yes, found 1")


# --- Intent classification does not cross-fire ----------------------------------


def test_a_reachability_question_does_not_trip_the_dead_rule_intent():
    frame = _FakeFrame([{"Traces": [FakeTrace("ACCEPTED")]}])
    session = _session_with_devices({"rtr-us5"}, traceroute_frame=frame)
    result = answer_question("Can rtr-us5 reach 218.8.104.58?", session)
    assert "?" in result["question_understood"]
    assert "rule" not in result["question_understood"].lower()


def test_a_dead_rule_question_does_not_trip_reachability(monkeypatch):
    """A question mentioning "reach" incidentally must not be parsed as
    reachability if a dead-rule phrase is also present -- dead-rule
    classification is checked first deliberately."""
    frame = _FakeFrame([])
    session = FakeSession(_FakeQuestions(whole_snapshot_frame=frame))
    result = answer_question(
        "Is there a dead rule that can never be reached?", session
    )
    assert result["grounded"] is True
    assert "never take effect" in result["question_understood"]


# --- Follow-ups: entities carried forward, never intent (#318) ---------------


def _resolved_entities(source_device, destination_ip, destination_display=None):
    return {
        "source_device": source_device,
        "destination_ip": destination_ip,
        "destination_display": destination_display or destination_ip,
    }


def test_a_fresh_reachability_question_populates_resolved_entities():
    """Turn 1 has to seed turn 2 -- follow-ups are not only useful after
    another follow-up."""
    frame = _FakeFrame([{"Traces": [FakeTrace("ACCEPTED")]}])
    session = _session_with_devices({"rtr-us5"}, traceroute_frame=frame)
    result = answer_question("Can rtr-us5 reach 10.20.0.5?", session)
    assert result["resolved_entities"] == _resolved_entities("rtr-us5", "10.20.0.5")


def test_dead_rule_and_undefined_reference_questions_carry_nothing_forward():
    """Neither whole-snapshot intent has a per-question entity to carry --
    resolved_entities must be None, not an empty or partial dict."""
    frame = _FakeFrame([])
    session = FakeSession(_FakeQuestions(whole_snapshot_frame=frame))

    dead_rule = answer_question("Is any ACL rule dead?", session)
    assert dead_rule["resolved_entities"] is None

    undefined = answer_question("Is anything undefined?", session)
    assert undefined["resolved_entities"] is None


def test_refused_question_carries_nothing_forward():
    result = answer_question("", FakeSession(_FakeQuestions()))
    assert result["resolved_entities"] is None


def test_source_side_falls_back_to_the_previous_answer():
    """The follow-up itself: "does it reach ..." resolves nothing on the
    source side, so the previous turn's device is used instead -- and the
    grounding guarantee holds, checked at the boundary that matters (what
    was actually sent to Batfish), not just the returned prose."""
    frame = _FakeFrame([{"Traces": [FakeTrace("ACCEPTED")]}])
    session = _session_with_devices({"rtr-us5", "rtr-branch"}, traceroute_frame=frame)
    previous = _resolved_entities("rtr-us5", "10.20.0.5")

    result = answer_question("Does it reach 10.20.20.5?", session, previous)

    assert result["question_understood"] == "Can rtr-us5 reach 10.20.20.5?"
    [call] = session.q.traceroute_calls
    assert call["startLocation"] == "@enter(rtr-us5)"
    assert call["headers"].dstIps == "10.20.20.5"


def test_destination_side_falls_back_to_the_previous_answer():
    """Symmetric case: a new source is named, the destination is omitted."""
    frame = _FakeFrame([{"Traces": [FakeTrace("ACCEPTED")]}])
    session = _session_with_devices(
        {"rtr-us5", "rtr-branch"}, traceroute_frame=frame
    )
    previous = _resolved_entities("rtr-us5", "10.20.0.5")

    result = answer_question("Can rtr-branch reach it?", session, previous)

    assert result["question_understood"] == "Can rtr-branch reach 10.20.0.5?"
    [call] = session.q.traceroute_calls
    assert call["startLocation"] == "@enter(rtr-branch)"
    assert call["headers"].dstIps == "10.20.0.5"


def test_explicit_text_always_wins_over_the_previous_answer():
    """THE ONE THAT MATTERS. A follow-up naming its own device must never be
    silently overridden by session memory -- the fallback is only ever
    consulted when the current question's own text resolves nothing, and
    this proves that property holds rather than trusting the mechanism."""
    frame = _FakeFrame([{"Traces": [FakeTrace("ACCEPTED")]}])
    session = _session_with_devices(
        {"rtr-us5", "rtr-branch"}, traceroute_frame=frame
    )
    previous = _resolved_entities("rtr-us5", "10.20.0.5")

    result = answer_question("Can rtr-branch reach 10.20.20.5?", session, previous)

    assert result["question_understood"] == "Can rtr-branch reach 10.20.20.5?"
    [call] = session.q.traceroute_calls
    assert call["startLocation"] == "@enter(rtr-branch)"
    assert call["headers"].dstIps == "10.20.20.5"


def test_no_previous_answer_behaves_exactly_as_before():
    """Regression guard: a caller that never passes `previous` (every
    existing caller, until web/main.py is wired) sees unchanged behaviour --
    an unresolvable segment still refuses, it does not error on the missing
    argument or behave differently because the parameter now exists."""
    session = _session_with_devices({"rtr-us5"})
    result = answer_question("Can it reach 10.20.0.5?", session)
    assert result["grounded"] is False
    assert result["question_understood"] is None


def test_a_previous_device_absent_from_this_snapshot_is_not_trusted():
    """A device from an earlier, different upload must not survive into
    this one just because the name is still sitting in session state --
    re-validated against THIS call's snapshot, exactly like a name typed
    directly into the question."""
    session = _session_with_devices({"rtr-branch"})  # rtr-us5 is NOT here
    previous = _resolved_entities("rtr-us5", "10.20.0.5")

    result = answer_question("Does it reach 10.20.0.5?", session, previous)

    assert result["grounded"] is False
    assert result["question_understood"] is None


def test_a_bare_follow_up_with_no_reach_keyword_still_refuses():
    """THE SCOPE BOUNDARY, pinned as a real test rather than left as
    prose (#318 design decision). A previous answer only fills a gap
    INSIDE the reachability path -- it does not widen which questions are
    classified as reachability in the first place. "What about rtr-branch"
    has no reach-style keyword at all, so it is never even split into
    (source, destination); it must refuse exactly as it would with no
    `previous` given."""
    session = _session_with_devices({"rtr-us5", "rtr-branch"})
    previous = _resolved_entities("rtr-us5", "10.20.0.5")

    result = answer_question("What about rtr-branch?", session, previous)

    assert result["grounded"] is False
    assert result["question_understood"] is None
    assert session.q.traceroute_calls == []


# --- The fallback fires on a back-reference, never on failure alone --------
# (found by review, @ARSH871-bot -- the fallback used to fire whenever a
# side failed to resolve, for ANY reason, which did not distinguish "the
# question left this side out" from "the question named something that does
# not resolve". Every case below used to come back grounded=True, silently
# answering with the PREVIOUS turn's entity instead of refusing.)


@pytest.mark.parametrize("question", [
    "Can the guest network reach the finance server?",
    "Can rtr-brnch reach 10.10.10.5?",
    "Can it reach 10.10.10.500?",
    # "IT" the department, not "it" the pronoun -- found by review
    # (@ARSH871-bot, round two). A different failure shape from the three
    # above: not text that failed to resolve, but a real word that
    # case-collided with the back-reference set after lowercasing.
    "Can IT reach 10.10.10.5?",
])
def test_a_named_but_unresolvable_segment_still_refuses_even_with_previous(
        question):
    """THE ONES ARSH'S REVIEW FOUND, across two rounds. Each of these names
    something -- a plain-English name, a typo'd device, a malformed
    address, or a real word that happens to case-collide with a
    back-reference -- and none of them is a genuine reference to the last
    turn. All must refuse exactly as they would with no `previous`, never
    silently answer using the last turn's entity."""
    session = _session_with_devices({"rtr-us5"})
    previous = _resolved_entities("rtr-us5", "10.10.10.5")

    result = answer_question(question, session, previous)

    assert result["grounded"] is False, (
        f"{question!r} was answered using a carried-forward entity instead "
        "of refusing -- exactly the regression this test exists to catch"
    )
    assert result["question_understood"] is None
    assert result["resolved_entities"] is None
    assert session.q.traceroute_calls == []


def test_mutating_the_back_reference_gate_is_caught(monkeypatch):
    """The mutation itself, run as a test rather than only by hand: revert
    to the old "fall back on any failure" behaviour and confirm at least
    one of the three guarded cases above starts (wrongly) succeeding."""
    import ai.query as query_module

    monkeypatch.setattr(query_module, "_is_source_back_reference", lambda _: True)
    monkeypatch.setattr(query_module, "_is_destination_back_reference", lambda _: True)

    frame = _FakeFrame([{"Traces": [FakeTrace("ACCEPTED")]}])
    session = _session_with_devices({"rtr-us5"}, traceroute_frame=frame)
    previous = _resolved_entities("rtr-us5", "10.10.10.5")

    result = answer_question(
        "Can the guest network reach the finance server?", session, previous
    )
    assert result["grounded"] is True, (
        "expected the mutated (unguarded) fallback to wrongly succeed here -- "
        "if it still refuses, this test is not exercising the gate it claims to"
    )


def test_filler_words_are_tolerated_around_a_real_back_reference():
    """"also"/"still"/"too" are filler, not content -- "does it ALSO reach"
    must still be recognised as the same reference "does it reach" is.
    This is the exact phrasing used in this PR's own live verification, so
    it is worth pinning as a test rather than trusting a terminal transcript."""
    frame = _FakeFrame([{"Traces": [FakeTrace("ACCEPTED")]}])
    session = _session_with_devices({"rtr-us5"}, traceroute_frame=frame)
    previous = _resolved_entities("rtr-us5", "10.10.10.5")

    result = answer_question("Does it also reach 8.8.8.8?", session, previous)

    assert result["grounded"] is True
    assert result["question_understood"] == "Can rtr-us5 reach 8.8.8.8?"


def test_a_second_filler_word_is_not_tolerated():
    """Deliberately narrow: one filler word, stripped once from each end.
    "does it also still reach" is unusual enough that refusing it is the
    right call, matching this project's own discipline of refusing the
    unfamiliar rather than parsing harder to accept it."""
    session = _session_with_devices({"rtr-us5"})
    previous = _resolved_entities("rtr-us5", "10.10.10.5")

    result = answer_question(
        "Does it also still reach 8.8.8.8?", session, previous
    )

    assert result["grounded"] is False
