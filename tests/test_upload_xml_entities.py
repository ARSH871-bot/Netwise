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

from fastapi.testclient import TestClient

from web import main

client = TestClient(main.app)


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
