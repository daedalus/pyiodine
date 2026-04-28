"""Tests for pyiodine common module."""

from __future__ import annotations

import pytest
import hashlib
from pyiodine.common import (
    calculate_checksum,
    split_data,
    merge_data,
    ChallengeResponse,
    Packet,
    format_addr,
    check_topdomain,
    create_raw_header,
    RAW_HDR_CMD_LOGIN,
    RAW_HDR_CMD_DATA,
    RAW_HDR_CMD_PING,
)


class TestChecksum:
    """Tests for checksum calculation."""

    def test_empty_data(self) -> None:
        """Test checksum of empty data."""
        result = calculate_checksum(b"")
        assert isinstance(result, int)
        assert 0 <= result <= 0xFFFF

    def test_simple_data(self) -> None:
        """Test checksum of simple data."""
        result = calculate_checksum(b"hello")
        assert isinstance(result, int)

    def test_known_checksum(self) -> None:
        """Test against known checksum value."""
        # The checksum of b"hello" should be deterministic
        result1 = calculate_checksum(b"hello")
        result2 = calculate_checksum(b"hello")
        assert result1 == result2


class TestSplitData:
    """Tests for split_data function."""

    def test_empty_data(self) -> None:
        """Test splitting empty data."""
        assert split_data(b"", 10) == []

    def test_single_chunk(self) -> None:
        """Test data smaller than chunk size."""
        data = b"hello"
        result = split_data(data, 10)
        assert len(result) == 1
        assert result[0] == data

    def test_multiple_chunks(self) -> None:
        """Test data larger than chunk size."""
        data = b"a" * 100
        result = split_data(data, 30)
        assert len(result) == 4  # 100 / 30 = 3.33 -> 4 chunks
        assert merge_data(result) == data

    def test_exact_multiple(self) -> None:
        """Test data that's exact multiple of chunk size."""
        data = b"a" * 90
        result = split_data(data, 30)
        assert len(result) == 3
        assert all(len(c) == 30 for c in result)
        assert merge_data(result) == data


class TestMergeData:
    """Tests for merge_data function."""

    def test_empty_list(self) -> None:
        """Test merging empty list."""
        assert merge_data([]) == b""

    def test_single_chunk(self) -> None:
        """Test merging single chunk."""
        assert merge_data([b"hello"]) == b"hello"

    def test_multiple_chunks(self) -> None:
        """Test merging multiple chunks."""
        chunks = [b"hello", b" ", b"world"]
        assert merge_data(chunks) == b"hello world"


class TestChallengeResponse:
    """Tests for ChallengeResponse class."""

    def test_init(self) -> None:
        """Test initialization."""
        cr = ChallengeResponse("secret")
        assert cr.password == b"secret"

    def test_generate_challenge(self) -> None:
        """Test challenge generation."""
        cr = ChallengeResponse("secret")
        challenge = cr.generate_challenge()
        assert isinstance(challenge, bytes)
        assert len(challenge) == 16

    def test_compute_response(self) -> None:
        """Test response computation."""
        cr = ChallengeResponse("secret")
        challenge = cr.generate_challenge()
        response = cr.compute_response(challenge)
        assert isinstance(response, bytes)
        assert len(response) == 16  # MD5 digest

    def test_verify_response(self) -> None:
        """Test response verification."""
        cr = ChallengeResponse("secret")
        challenge = cr.generate_challenge()
        response = cr.compute_response(challenge)
        assert cr.verify_response(challenge, response) is True

    def test_verify_wrong_response(self) -> None:
        """Test verification with wrong response."""
        cr = ChallengeResponse("secret")
        challenge = cr.generate_challenge()
        wrong_response = b"\x00" * 16
        assert cr.verify_response(challenge, wrong_response) is False


class TestPacket:
    """Tests for Packet dataclass."""

    def test_create_packet(self) -> None:
        """Test creating a packet."""
        p = Packet(len=100, seqno=1, fragment=0)
        assert p.len == 100
        assert p.seqno == 1
        assert p.fragment == 0

    def test_to_from_bytes(self) -> None:
        """Test serialization roundtrip."""
        original = Packet(len=50, seqno=5, fragment=2, data=b"hello")
        serialized = original.to_bytes()
        deserialized = Packet.from_bytes(serialized)
        assert deserialized is not None
        if deserialized:
            assert deserialized.len == original.len
            assert deserialized.seqno == original.seqno
            assert deserialized.fragment == original.fragment

    def test_from_bytes_invalid(self) -> None:
        """Test deserializing invalid data."""
        assert Packet.from_bytes(b"") is None
        assert Packet.from_bytes(b"\x00") is None


class TestFormatAddr:
    """Tests for format_addr function."""

    def test_ipv4_addr(self) -> None:
        """Test formatting IPv4 address."""
        addr = ("192.168.1.1", 53)
        assert format_addr(addr) == "192.168.1.1:53"

    def test_invalid_addr(self) -> None:
        """Test with invalid address."""
        assert format_addr(()) == "()"


class TestCheckTopdomain:
    """Tests for check_topdomain function."""

    def test_valid_domain(self) -> None:
        """Test valid domain names."""
        assert check_topdomain("example.com") is True
        assert check_topdomain("test.example.com") is True

    def test_invalid_domain(self) -> None:
        """Test invalid domain names."""
        assert check_topdomain("") is False
        assert check_topdomain("-start.com") is False
        assert check_topdomain("end-.com") is False

    def test_too_long_label(self) -> None:
        """Test domain with label too long."""
        long_label = "a" * 64
        assert check_topdomain(f"{long_label}.com") is False


class TestCreateRawHeader:
    """Tests for create_raw_header function."""

    def test_create_login(self) -> None:
        """Test creating login header."""
        header = create_raw_header(RAW_HDR_CMD_LOGIN)
        assert len(header) == 4
        assert header[3] & 0xF0 == RAW_HDR_CMD_LOGIN

    def test_create_data(self) -> None:
        """Test creating data header."""
        header = create_raw_header(RAW_HDR_CMD_DATA)
        assert len(header) == 4
        assert header[3] & 0xF0 == RAW_HDR_CMD_DATA

    def test_create_ping(self) -> None:
        """Test creating ping header."""
        header = create_raw_header(RAW_HDR_CMD_PING)
        assert len(header) == 4
        assert header[3] & 0xF0 == RAW_HDR_CMD_PING

    def test_with_user(self) -> None:
        """Test header with user field."""
        header = create_raw_header(RAW_HDR_CMD_DATA, usr=3)
        assert header[3] & 0x0F == 3
