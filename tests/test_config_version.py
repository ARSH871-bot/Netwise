"""#239 AC-1: extract the software version, or say we could not find one.

`analysis/config_version.py` reads raw config text because Batfish's model
does not carry a version -- measured, not assumed: `nodeProperties` gives
`Configuration_Format = CISCO_IOS` and nothing more precise.

The cases below are grouped by what they are actually protecting:

    1. real IOS version-line formats are found
    2. the things that LOOK like a version line and are not
    3. absence is None, never a guess
    4. contradiction is None, never the first one
"""

import pytest

from analysis.config_version import find_version


# --- 1. real formats ---------------------------------------------------------
#
# A Cisco IOS running-config opens with a comment banner and a `version` line.
# The values below are all real IOS / IOS-XE trains, in the shape the config
# actually writes them: `major.minor`, no build suffix. See the module
# docstring for why the build is not available here.


@pytest.mark.parametrize(
    "version",
    ["15.2", "12.4", "15.1", "16.9", "17.3", "12.2", "15.0"],
)
def test_a_real_ios_version_line_is_found(version):
    config = f"!\nversion {version}\nservice timestamps debug datetime msec\n!\n"
    assert find_version(config) == version


def test_the_version_line_is_found_when_it_is_the_only_line():
    assert find_version("version 15.2") == "15.2"


def test_a_tab_separated_version_line_is_found():
    """Cisco writes a single space; an exported or hand-edited file may not."""
    assert find_version("version\t15.2\n") == "15.2"


def test_trailing_whitespace_does_not_prevent_a_match():
    assert find_version("version 15.2   \n") == "15.2"


def test_a_crlf_file_still_matches():
    """A config exported from a Windows tool carries \\r\\n line endings.

    `\\r` is not in `[ \\t]`, so without handling it the trailing-whitespace
    class would not absorb it and the match would fail on exactly the files
    most likely to arrive from a client.
    """
    assert find_version("!\r\nversion 15.2\r\nhostname r1\r\n") == "15.2"


def test_the_value_is_returned_exactly_as_written():
    """No normalising. "15.2" is a train identifier, not a number.

    Coercing it to a float would make 15.10 and 15.1 the same value, and
    they are different trains.
    """
    assert find_version("version 15.10\n") == "15.10"


# --- 2. the near misses ------------------------------------------------------
#
# Every one of these contains the word "version" and none of them declares
# the software release. A loose search finds all of them, which is why the
# pattern is anchored to the first token of an unindented line.


@pytest.mark.parametrize(
    "line",
    [
        "ip ssh version 2",
        "ntp server 10.0.0.1 version 4",
        " standby 1 version 2",
        "\tstandby 1 version 2",
        " version 15.2",
        "  version 15.2",
        "snmp-server version 3",
        "no version 15.2",
    ],
)
def test_a_line_that_is_not_the_software_version_is_not_matched(line):
    """THE MAIN SAFETY PROPERTY OF THIS MODULE.

    Reporting "this device runs IOS 2" because a config says `ip ssh version
    2` would be a confident, evidenced, wrong answer -- and it would flow
    straight into a CVE lookup. Wrong here is worse than absent.
    """
    config = f"!\nhostname r1\n{line}\n!\n"
    assert find_version(config) is None


def test_an_indented_version_line_is_not_the_software_version():
    """Indentation means "subcommand of the block above", not "top level"."""
    assert find_version("interface Gi0/0\n version 15.2\n") is None


def test_a_commented_out_version_line_is_absent_not_found():
    """A comment is not a declaration.

    Removed BEFORE matching rather than filtered after, so a file whose only
    version-looking line is a comment is indistinguishable from a file with
    no version line -- which is correct, because both say nothing.
    """
    assert find_version("!\n! version 15.2\nhostname r1\n") is None


def test_the_word_version_inside_a_comment_banner_is_ignored():
    """Our own fixtures carry banners; a client's will too."""
    config = (
        "!\n"
        "! Upgraded from version 12.4 in 2019 -- do not roll back\n"
        "!\n"
        "hostname r1\n"
    )
    assert find_version(config) is None


def test_a_bare_version_keyword_with_no_value_is_not_a_version():
    assert find_version("version\n") is None
    assert find_version("version   \n") is None


# --- 3. absence is None ------------------------------------------------------


def test_a_config_with_no_version_line_returns_none():
    config = "!\nhostname rtr-us5\ninterface GigabitEthernet0/0\n"
    assert find_version(config) is None


@pytest.mark.parametrize("value", ["", None, 0, [], {}, b"version 15.2"])
def test_nothing_useful_in_gives_none_out_rather_than_an_exception(value):
    """Never raises. A caller that hands us something odd gets the cautious
    answer, not an exception it then has to decide what to do with."""
    assert find_version(value) is None


# --- 4. contradiction is None ------------------------------------------------


def test_two_different_version_lines_refuse_rather_than_pick_one():
    """A file declaring two versions is most plausibly two files concatenated.

    Picking the first is a guess about which device we are looking at, and
    that guess then becomes a CVE claim. Refusing is the same call
    `pfsense_convert.py` makes on ambiguous rule order.
    """
    config = "!\nversion 15.2\nhostname a\n!\nversion 12.4\nhostname b\n"
    assert find_version(config) is None


def test_two_identical_version_lines_are_not_ambiguous():
    """There is only one answer it could be, so this is accepted.

    The refusal above is about CONTRADICTION, not about repetition -- a
    duplicated line is untidy, not ambiguous, and refusing it would be
    refusing a file we understand perfectly well.
    """
    config = "!\nversion 15.2\nhostname a\n!\nversion 15.2\n"
    assert find_version(config) == "15.2"


# --- 5. against the real fixtures --------------------------------------------


def test_it_runs_against_a_real_fixture_file():
    """The join to actual repository data, not just hand-written strings."""
    from pathlib import Path

    configs = list(Path("tests/fixtures/rtr-us5-insecure/configs").glob("*"))
    assert configs, "the fixture moved -- this test is pinned to a real path"

    text = configs[0].read_text(encoding="utf-8")
    # Asserted as "either a string or None", because step 2 of #239 adds
    # version lines to some fixtures and this test must not care which.
    result = find_version(text)
    assert result is None or isinstance(result, str)
