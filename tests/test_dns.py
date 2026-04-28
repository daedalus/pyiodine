"""Tests for pyiodine DNS module."""

from __future__ import annotations

import pytest
from pyiodine.dns import (
    build_query,
    parse_response,
    build_response,
    encode_tunnel_data,
    decode_tunnel_data,
    get_txn_id,
    DNSQuery,
    DNSResponse,
    T_TXT,
    T_NULL,
    C_IN,
)


class TestBuildQuery:
    """Tests for build_query function."""

    def test_build_basic_query(self) -> None:
        """Test building a basic DNS query."""
        packet = build_query("test.com")
        assert len(packet) > 0
        # First two bytes are transaction ID
        txn_id = get_txn_id(packet)
        assert 0 <= txn_id <= 65535

    def test_build_query_with_type(self) -> None:
        """Test building query with different types."""
        for qtype in [T_TXT, T_NULL]:
            packet = build_query("test.com", qtype=qtype)
            assert len(packet) > 0

    def test_query_structure(self) -> None:
        """Test query has correct structure."""
        packet = build_query("test.example.com")
        # At least 12 bytes for header
        assert len(packet) >= 12


class TestParseResponse:
    """Tests for parse_response function."""

    def test_parse_empty(self) -> None:
        """Test parsing empty packet."""
        result = parse_response(b"")
        assert result is None

    def test_parse_too_short(self) -> None:
        """Test parsing packet that's too short."""
        result = parse_response(b"\x00\x01")
        assert result is None

    def test_parse_valid_response(self) -> None:
        """Test parsing a valid response."""
        # This is a simplified test - real DNS response would be more complex
        # response = parse_response(valid_dns_response)
        # assert response is not None
        pass  # Placeholder - needs actual DNS response packet


class TestBuildResponse:
    """Tests for build_response function."""

    def test_build_basic_response(self) -> None:
        """Test building a basic DNS response."""
        query = build_query("test.com")
        response = build_response(query, b"hello", "test.com")
        assert len(response) > 0

    def test_response_structure(self) -> None:
        """Test response has correct structure."""
        query = build_query("test.com")
        response = build_response(query, b"data", "test.com")
        # Should have at least header + some data
        assert len(response) >= 12


class TestEncodeTunnelData:
    """Tests for encode_tunnel_data function."""

    def test_encode_simple(self) -> None:
        """Test encoding simple tunnel data."""
        from pyiodine.encoding import encode_base32

        data = b"\x00\x01\x02"
        domain = "test.com"
        result = encode_tunnel_data(data, domain)
        assert domain in result
        assert len(result) > len(domain)

    def test_encode_different_encodings(self) -> None:
        """Test encoding with different encodings."""
        data = b"test"
        domain = "example.com"

        for encoding in ["base32", "base64"]:
            result = encode_tunnel_data(data, domain, encoding=encoding)
            assert domain in result


class TestGetTxnId:
    """Tests for get_txn_id function."""

    def test_get_from_packet(self) -> None:
        """Test extracting transaction ID."""
        import struct

        txn_id = 0x1234
        packet = struct.pack("!H", txn_id) + b"\x00" * 10
        assert get_txn_id(packet) == txn_id

    def test_get_from_short_packet(self) -> None:
        """Test with packet too short."""
        assert get_txn_id(b"\x00") == 0


class TestDNSQuery:
    """Tests for DNSQuery dataclass."""

    def test_create_query(self) -> None:
        """Test creating a DNSQuery."""
        q = DNSQuery(id=1234, name="test.com", type=T_TXT)
        assert q.id == 1234
        assert q.name == "test.com"
        assert q.type == T_TXT


class TestDNSResponse:
    """Tests for DNSResponse dataclass."""

    def test_create_response(self) -> None:
        """Test creating a DNSResponse."""
        r = DNSResponse(id=1234, name="test.com", type=T_TXT, data=b"hello")
        assert r.id == 1234
        assert r.data == b"hello"
        assert r.authoritative is False
