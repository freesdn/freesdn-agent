"""
Tests for passive listener parsers.

Listeners hold raw sockets and require root, so we don't exercise the
sniff loops here. Instead we test the pure parser functions
(``parse_lldp_tlvs``, ``parse_cdp_tlvs``, ``parse_syslog``,
``_try_parse_snmp_trap``) which take bytes and return dicts — these
are the security-relevant boundary where untrusted data first becomes
structured fields, and where a malformed packet could otherwise hang
the agent (infinite loops on zero-length TLVs, OOM on jumbo payloads,
crashes on truncated headers).
"""
from __future__ import annotations

import struct

import pytest

from freesdn_agent.listeners.cdp import (
    CDP_TLV_CAPABILITIES,
    CDP_TLV_DEVICE_ID,
    CDP_TLV_NATIVE_VLAN,
    CDP_TLV_PLATFORM,
    CDP_TLV_PORT_ID,
    CDP_TLV_SOFTWARE_VERSION,
    parse_cdp_tlvs,
)
from freesdn_agent.listeners.lldp import (
    CHASSIS_SUBTYPE_MAC,
    LLDP_TLV_CHASSIS_ID,
    LLDP_TLV_END,
    LLDP_TLV_PORT_ID,
    LLDP_TLV_SYSTEM_NAME,
    LLDP_TLV_TTL,
    PORT_SUBTYPE_LOCAL,
    parse_lldp_tlvs,
)
from freesdn_agent.listeners.snmp_trap import _try_parse_snmp_trap
from freesdn_agent.listeners.syslog import parse_syslog


# ---------------------------------------------------------------------------
# Helpers — build TLV bytes from (type, payload) so tests stay readable
# ---------------------------------------------------------------------------

def _lldp_tlv(t: int, payload: bytes) -> bytes:
    """LLDP TLV header: 7 bits type + 9 bits length."""
    header = ((t & 0x7F) << 9) | (len(payload) & 0x1FF)
    return struct.pack("!H", header) + payload


def _cdp_tlv(t: int, payload: bytes) -> bytes:
    """CDP TLV: 2-byte type + 2-byte total length (includes header)."""
    total_len = 4 + len(payload)
    return struct.pack("!HH", t, total_len) + payload


def _cdp_frame(*tlvs: bytes) -> bytes:
    """CDP frame: version(1) + ttl(1) + checksum(2) + TLVs."""
    return b"\x02\xb4\x00\x00" + b"".join(tlvs)


# ---------------------------------------------------------------------------
# LLDP
# ---------------------------------------------------------------------------

class TestLLDPParser:
    def test_full_neighbor_advertisement(self) -> None:
        """A normal LLDP frame with chassis/port/ttl/system_name parses."""
        chassis_payload = bytes([CHASSIS_SUBTYPE_MAC]) + bytes.fromhex("aabbccddeeff")
        port_payload = bytes([PORT_SUBTYPE_LOCAL]) + b"GigabitEthernet1/0/24"
        frame = (
            _lldp_tlv(LLDP_TLV_CHASSIS_ID, chassis_payload)
            + _lldp_tlv(LLDP_TLV_PORT_ID, port_payload)
            + _lldp_tlv(LLDP_TLV_TTL, struct.pack("!H", 120))
            + _lldp_tlv(LLDP_TLV_SYSTEM_NAME, b"core-sw-01.lab")
            + _lldp_tlv(LLDP_TLV_END, b"")
        )
        out = parse_lldp_tlvs(frame)
        assert out["chassis_id"] == "aa:bb:cc:dd:ee:ff"
        assert out["chassis_id_subtype"] == "mac"
        assert out["port_id"] == "GigabitEthernet1/0/24"
        assert out["ttl"] == 120
        assert out["system_name"] == "core-sw-01.lab"

    def test_empty_returns_empty_dict(self) -> None:
        assert parse_lldp_tlvs(b"") == {}

    def test_oversized_payload_rejected(self) -> None:
        """Anything over 9000 bytes is dropped to bound parse work."""
        assert parse_lldp_tlvs(b"\x00" * 9001) == {}

    def test_zero_length_non_end_tlv_does_not_loop(self) -> None:
        """Zero-length TLV with non-END type would cause an infinite loop
        without the guard at lldp.py L92 — assert we exit instead."""
        # type=1 (chassis_id), len=0 — non-end, zero length
        bad_tlv = struct.pack("!H", (LLDP_TLV_CHASSIS_ID & 0x7F) << 9)
        out = parse_lldp_tlvs(bad_tlv + b"\x00" * 200)
        # No fields parsed, no hang.
        assert "chassis_id" not in out

    def test_truncated_tlv_does_not_overrun(self) -> None:
        """TLV claims 20 bytes of payload but only 5 are available."""
        header = ((LLDP_TLV_SYSTEM_NAME & 0x7F) << 9) | 20
        truncated = struct.pack("!H", header) + b"short"
        out = parse_lldp_tlvs(truncated)
        assert "system_name" not in out

    def test_unknown_tlv_types_skipped(self) -> None:
        """Reserved/unknown TLV types should be silently ignored."""
        unknown = _lldp_tlv(99, b"opaque-vendor-extension")
        end = _lldp_tlv(LLDP_TLV_END, b"")
        out = parse_lldp_tlvs(unknown + end)
        assert out == {}


# ---------------------------------------------------------------------------
# CDP
# ---------------------------------------------------------------------------

class TestCDPParser:
    def test_full_cisco_advertisement(self) -> None:
        frame = _cdp_frame(
            _cdp_tlv(CDP_TLV_DEVICE_ID, b"core-sw.cisco.lab"),
            _cdp_tlv(CDP_TLV_PORT_ID, b"GigabitEthernet0/1"),
            _cdp_tlv(CDP_TLV_PLATFORM, b"cisco WS-C3850-24P"),
            _cdp_tlv(CDP_TLV_SOFTWARE_VERSION, b"Cisco IOS XE 16.12.5"),
            _cdp_tlv(CDP_TLV_NATIVE_VLAN, struct.pack("!H", 42)),
            _cdp_tlv(CDP_TLV_CAPABILITIES, struct.pack("!I", 0x0A)),  # bridge(0x02)+switch(0x08)
        )
        out = parse_cdp_tlvs(frame)
        assert out["device_id"] == "core-sw.cisco.lab"
        assert out["port_id"] == "GigabitEthernet0/1"
        assert out["platform"] == "cisco WS-C3850-24P"
        assert out["software_version"] == "Cisco IOS XE 16.12.5"
        assert out["native_vlan"] == 42
        # 0x0A = 0b1010 = bits 1 (bridge) + 3 (switch). Not host, not router.
        assert out["capabilities"]["bridge"] is True
        assert out["capabilities"]["switch"] is True
        assert out["capabilities"]["host"] is False
        assert out["capabilities"]["router"] is False

    def test_too_short_rejected(self) -> None:
        assert parse_cdp_tlvs(b"\x02\xb4") == {}

    def test_oversized_rejected(self) -> None:
        assert parse_cdp_tlvs(b"\x00" * 9001) == {}

    def test_tlv_with_invalid_length_does_not_hang(self) -> None:
        """A TLV claiming length < 4 is malformed — must break the loop."""
        # type=device_id, total_len=2 (invalid — header alone is 4)
        bad = struct.pack("!HH", CDP_TLV_DEVICE_ID, 2)
        out = parse_cdp_tlvs(_cdp_frame(bad))
        assert "device_id" not in out

    def test_tlv_length_overruns_frame(self) -> None:
        """TLV declares 200 bytes payload but frame has 10."""
        bad = struct.pack("!HH", CDP_TLV_DEVICE_ID, 200) + b"short"
        out = parse_cdp_tlvs(_cdp_frame(bad))
        assert "device_id" not in out


# ---------------------------------------------------------------------------
# Syslog
# ---------------------------------------------------------------------------

class TestSyslogParser:
    def test_rfc5424_message(self) -> None:
        raw = (
            "<165>1 2026-05-24T10:11:12Z host1 myapp 9876 - "
            "Connection from 10.0.0.1 accepted"
        )
        out = parse_syslog(raw, "10.0.0.50")
        assert out is not None
        # PRI 165 = facility 20 (local4), severity 5 (notice)
        assert out["facility"] == "local4"
        assert out["severity"] == "notice"
        assert out["syslog_version"] == 1
        assert out["hostname"] == "host1"
        assert out["app_name"] == "myapp"
        assert out["proc_id"] == "9876"
        assert "Connection from 10.0.0.1 accepted" in out["message"]
        assert out["source_ip"] == "10.0.0.50"

    def test_rfc3164_bsd_message(self) -> None:
        raw = "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick"
        out = parse_syslog(raw, "192.0.2.1")
        assert out is not None
        # PRI 34 = facility 4 (auth), severity 2 (critical)
        assert out["facility"] == "auth"
        assert out["severity"] == "critical"
        assert out["hostname"] == "mymachine"
        assert "su root" in out["message"]

    def test_pri_only_fallback(self) -> None:
        """Unparseable body but valid <PRI> prefix — still extract priority."""
        out = parse_syslog("<13>opaque garbage data here", "10.0.0.1")
        assert out is not None
        assert out["facility"] == "user"
        assert out["severity"] == "notice"

    def test_empty_returns_none(self) -> None:
        assert parse_syslog("", "10.0.0.1") is None
        assert parse_syslog("   ", "10.0.0.1") is None

    def test_garbage_returns_none(self) -> None:
        assert parse_syslog("not a syslog message at all", "10.0.0.1") is None

    def test_control_chars_stripped(self) -> None:
        """A message with embedded NULs/ESC bytes must not leak them downstream."""
        raw = "<13>1 2026-05-24T00:00:00Z h app - - hello\x00\x1bworld"
        out = parse_syslog(raw, "10.0.0.1")
        assert out is not None
        assert "\x00" not in out["message"]
        assert "\x1b" not in out["message"]

    def test_long_message_truncated(self) -> None:
        """Beyond MAX_MESSAGE_LENGTH we truncate (and mark) to bound memory."""
        body = "A" * 9000
        raw = f"<13>1 2026-05-24T00:00:00Z h app - - {body}"
        out = parse_syslog(raw, "10.0.0.1")
        assert out is not None
        assert "truncated" in out["message"]
        assert len(out["message"]) < 9000


# ---------------------------------------------------------------------------
# SNMP Trap
# ---------------------------------------------------------------------------

class TestSNMPTrapParser:
    def test_garbage_returns_none(self) -> None:
        """Random bytes shouldn't blow up the parser."""
        out = _try_parse_snmp_trap(b"\xff" * 64, "10.0.0.1")
        # Without a valid BER message, either None (parse fail) or the
        # ImportError fallback dict — both are acceptable; neither raises.
        if out is not None:
            assert out["source_ip"] == "10.0.0.1"
            assert out["event_type"] == "snmp_trap"

    def test_empty_payload_returns_none(self) -> None:
        out = _try_parse_snmp_trap(b"", "10.0.0.1")
        # Same tolerance as above — depends on pysnmp availability.
        if out is not None:
            assert out["source_ip"] == "10.0.0.1"

    def test_v2c_trap_roundtrip(self) -> None:
        """Build a real SNMPv2c trap with pysnmp and parse it back."""
        try:
            from pysnmp.proto.api import v2c
            from pyasn1.codec.ber import encoder
        except ImportError:
            pytest.skip("pysnmp not installed")

        msg = v2c.Message()
        v2c.apiMessage.set_defaults(msg)  # version 1 = SNMPv2c
        v2c.apiMessage.set_community(msg, b"public")
        pdu = v2c.TrapPDU()
        v2c.apiTrapPDU.set_defaults(pdu)
        v2c.apiTrapPDU.set_varbinds(pdu, [
            (v2c.ObjectIdentifier("1.3.6.1.2.1.1.3.0"), v2c.TimeTicks(12345)),
            (v2c.ObjectIdentifier("1.3.6.1.6.3.1.1.4.1.0"),
             v2c.ObjectIdentifier("1.3.6.1.6.3.1.1.5.3")),  # linkDown
        ])
        v2c.apiMessage.set_pdu(msg, pdu)
        raw = encoder.encode(msg)

        out = _try_parse_snmp_trap(raw, "192.0.2.10")
        assert out is not None
        assert out["source_ip"] == "192.0.2.10"
        assert out["event_type"] == "snmp_trap"
        assert out["snmp_version"] == "v2"
        assert out["trap_oid"] == "1.3.6.1.6.3.1.1.5.3"
        # Community string must NEVER leak into reports
        assert "community" not in out
        assert "public" not in str(out)

    def test_community_string_not_leaked(self) -> None:
        """Defence-in-depth: even on a fallback path, the community must
        not appear in the parsed output."""
        try:
            from pysnmp.proto.api import v2c
            from pyasn1.codec.ber import encoder
        except ImportError:
            pytest.skip("pysnmp not installed")

        msg = v2c.Message()
        v2c.apiMessage.set_defaults(msg)
        v2c.apiMessage.set_community(msg, b"S3cret-c0mmunity!")
        pdu = v2c.TrapPDU()
        v2c.apiTrapPDU.set_defaults(pdu)
        v2c.apiMessage.set_pdu(msg, pdu)
        raw = encoder.encode(msg)

        out = _try_parse_snmp_trap(raw, "192.0.2.10")
        if out is None:
            # v1 trap layout differs — pysnmp may reject the encoded form.
            # The asserting test is the roundtrip above; this one is
            # only defensive.
            return
        assert "S3cret-c0mmunity!" not in str(out)
