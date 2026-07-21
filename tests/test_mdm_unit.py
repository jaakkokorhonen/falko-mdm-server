"""Yksikkötestit app/mdm.py -moduulin sisäiselle logiikalle.

Testaa _build_command_plist-funktion payload-muodostusta ilman Flask-kontekstia.
"""
import plistlib
import pytest


@pytest.mark.regression
def test_build_command_plist_basic_structure():
    """_build_command_plist tuottaa oikean Apple MDM plist-rakenteen."""
    from app.mdm import _build_command_plist
    result = _build_command_plist("DeviceInformation", "uuid-001")
    parsed = plistlib.loads(result)
    assert parsed["CommandUUID"] == "uuid-001"
    assert parsed["Command"]["RequestType"] == "DeviceInformation"


@pytest.mark.regression
def test_build_command_plist_with_payload():
    """Payload sulautetaan Command-dictiin tasaisesti (ei alidiktinä)."""
    from app.mdm import _build_command_plist
    result = _build_command_plist("DeviceLock", "uuid-002", {"PIN": "123456"})
    parsed = plistlib.loads(result)
    assert parsed["Command"]["RequestType"] == "DeviceLock"
    assert parsed["Command"]["PIN"] == "123456"
    # PIN ei saa olla alidiktissä
    assert "payload" not in parsed["Command"]


@pytest.mark.regression
def test_build_command_plist_without_payload():
    """Ilman payloadia Command sisältää vain RequestType."""
    from app.mdm import _build_command_plist
    result = _build_command_plist("EraseDevice", "uuid-003")
    parsed = plistlib.loads(result)
    assert list(parsed["Command"].keys()) == ["RequestType"]


@pytest.mark.regression
def test_build_command_plist_empty_payload():
    """Tyhjä payload-dict ei lisää ylimääräisiä avaimia."""
    from app.mdm import _build_command_plist
    result = _build_command_plist("ProfileList", "uuid-004", {})
    parsed = plistlib.loads(result)
    assert list(parsed["Command"].keys()) == ["RequestType"]


@pytest.mark.regression
def test_build_command_plist_returns_bytes():
    """Funktio palauttaa bytes-tyypin (XML plist)."""
    from app.mdm import _build_command_plist
    result = _build_command_plist("DeviceInformation", "uuid-005")
    assert isinstance(result, bytes)
    assert result.startswith(b"<?xml")
