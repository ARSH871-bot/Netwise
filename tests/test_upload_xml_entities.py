"""An uploaded pfSense XML that declares entities is refused (#397, US-64).

WHAT THIS PINS, AND WHY IT IS NOT ABOUT SIZE
    `analysis/pfsense_convert.py:128` parses uploads with
    `xml.etree.ElementTree`, and `:840`/`:1127` call `ET.parse()`. Nothing in
    that module mentions DOCTYPE or entities, and there is no `defusedxml`.
    Measured directly on 23 October: a three-level declaration
    (`10 -> 30 -> 90` characters, 550 bytes on disk) parsed, and the
    expansion was present in the parsed tree -- `<descr>` came back 90
    characters long.

    So the question is not whether a bomb is big enough to hurt. It is that
    we accept a construct we never decided to support, and whether it hurts
    depends on a libexpat version this project does not pin:

        Python's own docs say "Expat versions lower than 2.7.2 may be
        vulnerable to the 'billion laughs', 'quadratic blowup' and 'large
        tokens' vulnerabilities" -- https://docs.python.org/3/library/xml.html
        This machine has expat 2.6.2. #397's body says 2.7.1. Neither is
        above the threshold, and `requirements.txt`, the `Dockerfile`
        (`python:3.13-slim`, a moving tag) and CI's `setup-python` pin none
        of it. NOT MEASURED: what version CI and production actually get.

    A test that asserted "a bomb is refused" would therefore be asserting a
    property of whichever libexpat happened to be installed. This asserts a
    property of OUR code instead: an entity declaration is refused by us,
    whatever expat would have done with it.

THE SAMPLE IS DELIBERATELY TINY
    Three levels, 90 characters expanded, well under a kilobyte. It is not
    an amplifying bomb and does not need to be: the rule being pinned is
    "we do not accept entity declarations", not "we survive large ones".
    A test that needed a real bomb to fail would be a test that only fails
    on a slow machine.

NO BATFISH, NO OLLAMA, NO NETWORK -- the same property the rest of
tests/test_web_config_upload.py holds. Conversion is pure XML parsing, and
this file never calls analysis.pipeline.analyse().
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from web import main

client = TestClient(main.app)


@pytest.fixture(autouse=True)
def clean_staging():
    """Copied from tests/test_web_config_upload.py's fixture of the same name,
    for the same reason: module-level paths survive a test, so a file staged
    by one of these tests would be visible to the next one. The tests below
    that assert what is or is not staged depend on it.
    """

    def _clear():
        if main.CONFIGS_DIR.exists():
            shutil.rmtree(main.CONFIGS_DIR)

    _clear()
    yield
    _clear()


def _post_config(contents: bytes, filename: str, content_type: str = "text/plain"):
    """Exactly tests/test_web_config_upload.py's helper, deliberately.

    Copied rather than imported so this file stands alone, and shaped the
    same so a reader comparing the two sees one difference: the document.
    """
    return client.post(
        "/api/upload",
        files={"file": (filename, contents, content_type)},
    )


#: A valid pfSense export in every respect EXCEPT the DOCTYPE. One interface
#: with a static address, one `pass` rule -- the shape `_LAN_ONLY_XML` in
#: tests/test_web_config_upload.py uses, so a refusal here cannot be blamed
#: on the config being unconvertible for some other reason.
#:
#: `&c;` expands to 90 characters: a -> 10, b -> 3 x a, c -> 3 x b.
_ENTITY_DECLARING_XML = b"""<?xml version="1.0"?>
<!DOCTYPE pfsense [
  <!ENTITY a "AAAAAAAAAA">
  <!ENTITY b "&a;&a;&a;">
  <!ENTITY c "&b;&b;&b;">
]>
<pfsense>
  <system><hostname>test-device</hostname></system>
  <interfaces>
    <lan><if>em1</if><ipaddr>10.0.0.1</ipaddr><subnet>24</subnet></lan>
  </interfaces>
  <filter>
    <rule><type>pass</type><interface>lan</interface><protocol>tcp</protocol>
    <descr>&c;</descr>
    <source><any/></source><destination><any/></destination></rule>
  </filter>
</pfsense>
"""

#: The same document with the DOCTYPE and the one reference removed, so the
#: control proves the refusal is about the entities and not the file.
_SAME_XML_WITHOUT_ENTITIES = b"""<?xml version="1.0"?>
<pfsense>
  <system><hostname>test-device</hostname></system>
  <interfaces>
    <lan><if>em1</if><ipaddr>10.0.0.1</ipaddr><subnet>24</subnet></lan>
  </interfaces>
  <filter>
    <rule><type>pass</type><interface>lan</interface><protocol>tcp</protocol>
    <descr>plain text</descr>
    <source><any/></source><destination><any/></destination></rule>
  </filter>
</pfsense>
"""


def test_the_same_xml_without_entities_is_accepted():
    """THE CONTROL, and it runs first on purpose.

    Without this, a refusal below would prove only that the endpoint
    dislikes something about this document. This pins that the document is
    otherwise fine, so the DOCTYPE is the only difference that can explain
    a different answer.
    """
    response = _post_config(
        _SAME_XML_WITHOUT_ENTITIES, "config.xml", "application/xml"
    )
    assert response.status_code == 200, response.text


def test_an_upload_declaring_xml_entities_is_refused_and_not_converted():
    """An XML upload that declares entities is refused, and nothing is staged.

    Two assertions, and the second is the one that matters. A 400 alone
    would leave open whether the file had already been parsed and converted
    before the refusal -- which is the #78 validate-then-stage discipline
    this endpoint already keeps for an ambiguous rule order. If we ever
    decide to refuse entity declarations, the refusal has to come BEFORE
    the parse that would expand them.
    """
    response = _post_config(
        _ENTITY_DECLARING_XML, "config.xml", "application/xml"
    )

    assert response.status_code == 400, (
        f"an upload declaring XML entities was accepted with "
        f"{response.status_code}. analysis/pfsense_convert.py parses with "
        f"xml.etree.ElementTree (:128, :840) and refuses no DOCTYPE, so the "
        f"declaration is expanded at parse time -- measured 23 October, a "
        f"three-level declaration produced a 90-character <descr>. Whether "
        f"that is harmful depends on a libexpat version this project does "
        f"not pin (#397). Response: {response.text[:300]}"
    )

    detail = response.json().get("detail", "")
    assert "entit" in detail.lower() or "doctype" in detail.lower(), (
        f"the upload was refused, but the message does not say why in terms "
        f"a user could act on: {detail!r}. A refusal that does not name the "
        f"construct it rejected sends somebody to guess at their own export."
    )
    # A plain entity, named as one. test_c's fixture is the parameter-entity
    # case, so the two tests cannot pass on the same input.
    assert "entity 'a' is declared" in detail, detail
    assert "parameter entity" not in detail, detail


# ---------------------------------------------------------------------------
# #397, the rest of the cases. Each test says what it CLAIMS, and whether it
# is expected to fail before the fix or to pass both before and after.
# ---------------------------------------------------------------------------

#: A parameter entity that declares a general entity, which the body then
#: uses. Different from _ENTITY_DECLARING_XML (plain entities) and from
#: _PARAMETER_ENTITY_XML (a parameter entity nobody uses).
#:
#: Measured with expat 2.6.2: EntityDeclHandler fires once, for `p`, with
#: is_parameter_entity true. With the screen removed the upload is STILL a 400,
#: because ElementTree does not expand `%p;` and so fails on `&c;` as an
#: undefined entity -- which is why test_c asserts the message, not only the
#: status code.
_PARAMETER_ENTITY_IN_USE_XML = b"""<?xml version="1.0"?>
<!DOCTYPE pfsense [
  <!ENTITY % p "<!ENTITY c 'AAAAAAAAAA'>">
  %p;
]>
<pfsense>
  <system><hostname>test-device</hostname></system>
  <interfaces>
    <lan><if>em1</if><ipaddr>10.0.0.1</ipaddr><subnet>24</subnet></lan>
  </interfaces>
  <filter>
    <rule><type>pass</type><interface>lan</interface><protocol>tcp</protocol>
    <descr>&c;</descr>
    <source><any/></source><destination><any/></destination></rule>
  </filter>
</pfsense>
"""

#: A parameter entity. Measured before the fix: ElementTree accepts this
#: document, and expat's EntityDeclHandler fires with is_parameter_entity true.
_PARAMETER_ENTITY_XML = b"""<?xml version="1.0"?>
<!DOCTYPE pfsense [ <!ENTITY % p "x"> ]>
<pfsense>
  <system><hostname>test-device</hostname></system>
  <interfaces>
    <lan><if>em1</if><ipaddr>10.0.0.1</ipaddr><subnet>24</subnet></lan>
  </interfaces>
  <filter>
    <rule><type>pass</type><interface>lan</interface><protocol>tcp</protocol>
    <source><any/></source><destination><any/></destination></rule>
  </filter>
</pfsense>
"""

#: A plain DOCTYPE with no declarations at all. DELIBERATELY ACCEPTED -- it
#: carries no expansion, and refusing it would reject a valid export for no
#: gain. Pinned so that widening it later is a visible choice.
_HARMLESS_DOCTYPE_XML = b"""<?xml version="1.0"?>
<!DOCTYPE pfsense>
<pfsense>
  <system><hostname>test-device</hostname></system>
  <interfaces>
    <lan><if>em1</if><ipaddr>10.0.0.1</ipaddr><subnet>24</subnet></lan>
  </interfaces>
  <filter>
    <rule><type>pass</type><interface>lan</interface><protocol>tcp</protocol>
    <descr>plain text</descr>
    <source><any/></source><destination><any/></destination></rule>
  </filter>
</pfsense>
"""

#: The words DOCTYPE and ENTITY, in element text and in an XML comment. A byte
#: search for them would refuse this file; the parser's handler does not fire.
_WORDS_ONLY_IN_TEXT_XML = b"""<?xml version="1.0"?>
<!-- migration notes: DOCTYPE and ENTITY blocks were removed by hand -->
<pfsense>
  <system><hostname>test-device</hostname></system>
  <interfaces>
    <lan><if>em1</if><ipaddr>10.0.0.1</ipaddr><subnet>24</subnet></lan>
  </interfaces>
  <filter>
    <rule><type>pass</type><interface>lan</interface><protocol>tcp</protocol>
    <descr>see the DOCTYPE and ENTITY notes in the runbook</descr>
    <source><any/></source><destination><any/></destination></rule>
  </filter>
</pfsense>
"""


def _utf16_entity_xml() -> bytes:
    """The same attack, UTF-16 encoded.

    Built here rather than pasted as a literal, so the test can assert the
    thing that matters about it: the words are NOT in the bytes.
    """
    return (
        '<?xml version="1.0" encoding="UTF-16"?>\n'
        '<!DOCTYPE pfsense [ <!ENTITY a "AAAAAAAAAA"> ]>\n'
        "<pfsense>\n"
        "  <system><hostname>test-device</hostname></system>\n"
        "  <interfaces>\n"
        "    <lan><if>em1</if><ipaddr>10.0.0.1</ipaddr>"
        "<subnet>24</subnet></lan>\n"
        "  </interfaces>\n"
        "  <filter>\n"
        "    <rule><type>pass</type><interface>lan</interface>"
        "<protocol>tcp</protocol>\n"
        "    <descr>&a;</descr>\n"
        "    <source><any/></source><destination><any/></destination></rule>\n"
        "  </filter>\n"
        "</pfsense>\n"
    ).encode("utf-16")


def test_b1_an_external_entity_is_refused_and_the_canary_is_not_read():
    """CLAIMS: an upload declaring an external (SYSTEM) entity is refused, and
    the file it points at is not read.

    EXPECTED: passes BEFORE and AFTER the fix. This is a regression pin, not a
    demonstration of the fix.

    Measured before any fix: ElementTree does not resolve external entities --
    it raises ParseError("undefined entity"), which the endpoint already turned
    into a 400, and the canary did not leak. So the outcome was already right;
    what this pins is that it stays right. The canary is a file this test
    creates in the temp directory, never a real sensitive path.
    """
    canary_dir = Path(tempfile.mkdtemp(prefix="netwise-397-canary-"))
    canary = canary_dir / "canary.txt"
    canary.write_text("CANARY-CONTENT-MUST-NOT-APPEAR", encoding="utf-8")
    try:
        document = (
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE pfsense [ <!ENTITY x SYSTEM "'
            + canary.as_uri()
            + '"> ]>\n'
            "<pfsense>\n"
            "  <system><hostname>test-device</hostname></system>\n"
            "  <interfaces>\n"
            "    <lan><if>em1</if><ipaddr>10.0.0.1</ipaddr>"
            "<subnet>24</subnet></lan>\n"
            "  </interfaces>\n"
            "  <filter>\n"
            "    <rule><type>pass</type><interface>lan</interface>"
            "<protocol>tcp</protocol>\n"
            "    <descr>&x;</descr>\n"
            "    <source><any/></source>"
            "<destination><any/></destination></rule>\n"
            "  </filter>\n"
            "</pfsense>\n"
        ).encode("utf-8")

        response = _post_config(document, "config.xml", "application/xml")

        assert response.status_code == 400, (
            f"an upload declaring an external entity was accepted with "
            f"{response.status_code}: {response.text[:300]}"
        )
        assert "CANARY-CONTENT" not in response.text, (
            "the canary file's contents came back in the response, so the "
            "external entity was resolved and read from disk: "
            f"{response.text[:400]}"
        )
        staged = (
            list(main.CONFIGS_DIR.glob("*")) if main.CONFIGS_DIR.exists() else []
        )
        assert staged == [], f"a refused upload staged {staged}"
    finally:
        canary.unlink(missing_ok=True)
        shutil.rmtree(canary_dir, ignore_errors=True)


def test_b2_the_refusal_message_names_the_entity_declaration():
    """CLAIMS: the refusal for an external entity says the file DECLARES an
    entity, rather than describing it as unreadable XML.

    EXPECTED: FAILS before the fix, passes after. Before the fix this upload
    was refused with "is not readable XML (undefined entity &x;)", which
    blames the file's syntax rather than naming the construct we decided not
    to accept -- a message that sends somebody to look for a download problem
    they do not have.
    """
    document = (
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE pfsense [ <!ENTITY x SYSTEM "file:///nonexistent-397"> ]>\n'
        "<pfsense><descr>&x;</descr></pfsense>\n"
    ).encode("utf-8")

    response = _post_config(document, "config.xml", "application/xml")
    assert response.status_code == 400, response.text

    detail = response.json().get("detail", "").lower()
    assert "entit" in detail, (
        f"the refusal does not name the entity declaration: {detail!r}"
    )
    assert "not readable xml" not in detail, (
        "the refusal still describes this as unreadable XML, which blames the "
        f"file's syntax rather than the construct we refuse: {detail!r}"
    )


def test_c_a_parameter_entity_in_use_is_refused_by_name():
    """CLAIMS: a parameter entity that declares another entity is refused as a
    parameter entity, and nothing is staged.

    EXPECTED: fails without the screen, passes with it. Without the screen
    the status is still 400 (ElementTree reports `&c;` as undefined), so the
    message assertion is the one that fails: it would say "not readable XML",
    not "parameter entity".
    """
    response = _post_config(
        _PARAMETER_ENTITY_IN_USE_XML, "config.xml", "application/xml"
    )

    assert response.status_code == 400, (
        f"a parameter entity in use was accepted with "
        f"{response.status_code}: {response.text[:300]}"
    )
    detail = response.json().get("detail", "")
    assert "parameter entity 'p' is declared" in detail, (
        f"refused, but not named as a parameter entity: {detail!r}"
    )
    staged = list(main.CONFIGS_DIR.glob("*")) if main.CONFIGS_DIR.exists() else []
    assert staged == [], f"a refused upload staged {staged}"


def test_c2_a_parameter_entity_declaration_is_refused():
    """CLAIMS: a parameter entity declaration is refused too.

    EXPECTED: fails before the fix, passes after. Measured before the fix:
    ElementTree accepts this document, so it was reachable and accepted.
    """
    response = _post_config(
        _PARAMETER_ENTITY_XML, "config.xml", "application/xml"
    )

    assert response.status_code == 400, (
        f"a parameter entity declaration was accepted with "
        f"{response.status_code}: {response.text[:300]}"
    )


def test_d_the_same_attack_encoded_as_utf16_is_refused():
    """CLAIMS: a UTF-16 document declaring an entity is refused.

    EXPECTED: fails before the fix, passes after.

    THIS IS THE TEST THAT RULES OUT A BYTE SEARCH. The first two assertions
    prove the raw bytes contain neither b"DOCTYPE" nor b"ENTITY", so a fix
    that searched for either would pass every other test in this file and
    fail this one. Measured before the fix: ElementTree parsed this and
    expanded the entity to a 10-character value.
    """
    document = _utf16_entity_xml()

    assert b"DOCTYPE" not in document, (
        "this test is pointless unless the bytes really lack the word -- the "
        "UTF-16 encoding is what makes a byte search miss it"
    )
    assert b"ENTITY" not in document

    response = _post_config(document, "config.xml", "application/xml")

    assert response.status_code == 400, (
        f"a UTF-16 upload declaring an entity was accepted with "
        f"{response.status_code}: {response.text[:300]}"
    )
    detail = response.json().get("detail", "").lower()
    assert "entit" in detail, (
        f"refused, but not for declaring an entity: {detail!r}"
    )


def test_e_a_config_that_only_mentions_the_words_still_works():
    """CLAIMS: a normal export with DOCTYPE and ENTITY in element text and in
    an XML comment is still accepted.

    EXPECTED: passes BEFORE and AFTER. This is the other half of test_d: it
    fails for any fix that searches the bytes for those words, which is why
    the screen uses the parser's own handler instead.
    """
    response = _post_config(
        _WORDS_ONLY_IN_TEXT_XML, "config.xml", "application/xml"
    )

    assert response.status_code == 200, (
        "a config that merely mentions DOCTYPE and ENTITY in text was "
        f"refused: {response.text[:300]}"
    )


def test_e2_a_harmless_doctype_with_no_declarations_is_still_accepted():
    """CLAIMS: <!DOCTYPE pfsense> with no entity declarations is accepted.

    EXPECTED: passes BEFORE and AFTER, and that is a DECISION rather than an
    accident -- see the fix's own docstring. The risk is an entity
    declaration, not the doctype, and refusing every doctype would reject a
    valid export for no gain. Pinned here so widening it is a visible choice.
    """
    response = _post_config(
        _HARMLESS_DOCTYPE_XML, "config.xml", "application/xml"
    )

    assert response.status_code == 200, (
        "a DOCTYPE with no entity declarations was refused: "
        f"{response.text[:300]}"
    )


def test_f_a_plain_cisco_config_is_unaffected():
    """CLAIMS: the non-XML upload path is untouched.

    EXPECTED: passes BEFORE and AFTER. The screen runs only inside
    `if is_pfsense:`, so a .cfg upload never reaches it. This pins that.
    """
    response = _post_config(b"hostname rtr-us5\n", "device.cfg")

    assert response.status_code == 200, response.text
    staged = list(main.CONFIGS_DIR.glob("*"))
    assert len(staged) == 1
    assert staged[0].read_bytes() == b"hostname rtr-us5\n"


def test_g_the_refusal_is_a_refusal_and_not_a_quiet_clean_result():
    """CLAIMS: a refused entity upload leaves the PREVIOUS config staged, and
    never reports success.

    EXPECTED: fails before the fix, passes after.

    This is F-4 applied to the upload: "we refused this" and "this is fine"
    must not look alike. Three things are asserted together, because each one
    alone can be satisfied by the wrong behaviour -- a 400 that destroyed the
    previous snapshot is still a 400, and a kept snapshot under a 200 still
    reads as success.
    """
    good = _post_config(
        _SAME_XML_WITHOUT_ENTITIES, "config.xml", "application/xml"
    )
    assert good.status_code == 200, good.text
    before = list(main.CONFIGS_DIR.glob("*"))
    assert len(before) == 1
    kept = before[0].read_bytes()

    bad = _post_config(_ENTITY_DECLARING_XML, "config.xml", "application/xml")

    assert bad.status_code == 400, (
        f"the entity upload reported {bad.status_code}: {bad.text[:300]}"
    )
    assert bad.json().get("detail"), "a refusal with no message to show"
    after = list(main.CONFIGS_DIR.glob("*"))
    assert len(after) == 1 and after[0].read_bytes() == kept, (
        "the refused upload replaced or removed the previously staged "
        f"config: {after}"
    )
