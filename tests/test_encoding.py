"""Tests for pyiodine encoding module."""

from __future__ import annotations

import pytest
from pyiodine.encoding import (
    encode_base32,
    decode_base32,
    encode_base64,
    decode_base64,
    encode_base128,
    decode_base128,
    get_codec,
    get_blksize_raw,
    get_blksize_enc,
)


class TestBase32:
    """Tests for Base32 encoding/decoding."""

    def test_encode_empty(self) -> None:
        """Test encoding empty bytes."""
        assert encode_base32(b"") == ""

    def test_decode_empty(self) -> None:
        """Test decoding empty string."""
        assert decode_base32("") == b""

    def test_encode_simple(self) -> None:
        """Test encoding simple bytes."""
        result = encode_base32(b"\x00\x01\x02\x03\x04")
        assert len(result) > 0
        assert result.isalpha() or result.isalnum()

    def test_encode_decode_roundtrip(self) -> None:
        """Test encode/decode roundtrip."""
        test_data = [
            b"",
            b"\x00",
            b"\xff",
            b"hello world",
            bytes(range(256)),
            b"\x00\x01\x02\x03\x04",
        ]
        for data in test_data:
            encoded = encode_base32(data)
            decoded = decode_base32(encoded)
            assert decoded == data, f"Failed for {data!r}"

    def test_decode_invalid_char(self) -> None:
        """Test decoding with invalid characters."""
        with pytest.raises(ValueError):
            decode_base32("invalid!")

    def test_case_insensitive_decode(self) -> None:
        """Test that decoding accepts both upper and lower case."""
        encoded = encode_base32(b"test")
        # Should work with uppercase
        upper = encoded.upper()
        assert decode_base32(upper) == b"test"

    def test_block_size(self) -> None:
        """Test block size constants."""
        assert get_blksize_raw("base32") == 5
        assert get_blksize_enc("base32") == 8


class TestBase64:
    """Tests for Base64 encoding/decoding."""

    def test_encode_empty(self) -> None:
        """Test encoding empty bytes."""
        assert encode_base64(b"") == ""

    def test_decode_empty(self) -> None:
        """Test decoding empty string."""
        assert decode_base64("") == b""

    def test_encode_decode_roundtrip(self) -> None:
        """Test encode/decode roundtrip."""
        test_data = [
            b"",
            b"\x00",
            b"\xff",
            b"hello world",
            bytes(range(256)),
            b"\x00\x01\x02",
        ]
        for data in test_data:
            encoded = encode_base64(data)
            decoded = decode_base64(encoded)
            assert decoded == data, f"Failed for {data!r}"

    def test_decode_invalid_char(self) -> None:
        """Test decoding with invalid characters."""
        with pytest.raises(ValueError):
            decode_base64("invalid!!!")

    def test_block_size(self) -> None:
        """Test block size constants."""
        assert get_blksize_raw("base64") == 3
        assert get_blksize_enc("base64") == 4


class TestBase128:
    """Tests for Base128 encoding/decoding."""

    def test_encode_empty(self) -> None:
        """Test encoding empty bytes."""
        assert encode_base128(b"") == ""

    def test_decode_empty(self) -> None:
        """Test decoding empty string."""
        assert decode_base128("") == b""

    def test_encode_decode_roundtrip(self) -> None:
        """Test encode/decode roundtrip."""
        test_data = [
            b"",
            b"\x00",
            b"\xff",
            b"hello world",
            bytes(range(127)),  # Base128 sensitive to high bytes
        ]
        for data in test_data:
            encoded = encode_base128(data)
            decoded = decode_base128(encoded)
            assert decoded == data, f"Failed for {data!r}"

    def test_decode_invalid_char(self) -> None:
        """Test decoding with invalid characters."""
        # Characters not in B128_CHARS should fail
        # Use a character that's NOT in B128_CHARS (like a space or punctuation not in the set)
        with pytest.raises(ValueError):
            decode_base128("!!!")  # Contains characters not in B128_CHARS

    def test_block_size(self) -> None:
        """Test block size constants."""
        assert get_blksize_raw("base128") == 7
        assert get_blksize_enc("base128") == 8


class TestGetCodec:
    """Tests for get_codec function."""

    def test_get_base32(self) -> None:
        """Test getting Base32 codec."""
        encoder, decoder = get_codec("base32")
        data = b"test"
        assert decoder(encoder(data)) == data

    def test_get_base64(self) -> None:
        """Test getting Base64 codec."""
        encoder, decoder = get_codec("base64")
        data = b"test"
        assert decoder(encoder(data)) == data

    def test_get_base128(self) -> None:
        """Test getting Base128 codec."""
        encoder, decoder = get_codec("base128")
        data = b"test"
        assert decoder(encoder(data)) == data

    def test_invalid_encoding(self) -> None:
        """Test with invalid encoding name."""
        with pytest.raises(ValueError):
            get_codec("invalid")
