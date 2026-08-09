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
