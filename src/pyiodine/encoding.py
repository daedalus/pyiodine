"""Encoding module for pyiodine - Base32, Base64, and Base128 implementations.

This module provides encoding and decoding functions compatible with the C iodine
implementation. The encodings are used to encode binary tunnel data into
DNS-friendly character sets.
"""

from __future__ import annotations

from collections.abc import Callable

# Base32 alphabet (lowercase) - compatible with iodine C implementation
B32_CHARS = "abcdefghijklmnopqrstuvwxyz012345"
B32_CHARS_UCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"

# Base64 alphabet - compatible with iodine C implementation
# Note: uses '-' instead of '/' and preserves case sensitivity
B64_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789+"

# Base128 alphabet - uses extended ASCII (128-255)
# Avoids 254-255 due to possible function overloading in DNS systems
B128_CHARS = (
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    "\xbc\xbd\xbe\xbf"  # 188-191
    "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf"  # 192-207
    "\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"  # 208-223
    "\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef"  # 224-239
    "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd"  # 240-253
)


def encode_base32(data: bytes) -> str:
    """Encode bytes to Base32 string.

    Uses the iodine-compatible Base32 alphabet (a-z, 0-5).
    Each 5 bytes of input becomes 8 characters of output.

    Args:
        data: The raw bytes to encode.

    Returns:
        The Base32-encoded string.

    Example:
        >>> encode_base32(b"\\x00\\x01\\x02\\x03\\x04")
        'abcde'
    """
    if not data:
        return ""

    result = []
    blocks_raw = len(data) // 5
    remainder = len(data) % 5

    # Process complete 5-byte blocks
    for i in range(blocks_raw):
        block = data[i * 5 : (i + 1) * 5]
        # 5 bytes = 40 bits = 8 quintets of 5 bits each
        val = int.from_bytes(block, "big")
        for j in range(8):
            idx = (val >> (35 - j * 5)) & 0x1F
            result.append(B32_CHARS[idx])

    # Process partial block
    if remainder > 0:
        block = bytearray(5)
        block[:remainder] = data[blocks_raw * 5 :]
        val = int.from_bytes(block, "big")
        # Number of complete quintets we can extract
        num_quintets = (remainder * 8 + 4) // 5
        for j in range(num_quintets):
            idx = (val >> (35 - j * 5)) & 0x1F
            result.append(B32_CHARS[idx])

    return "".join(result)


def decode_base32(encoded: str) -> bytes:
    """Decode Base32 string to bytes.

    Accepts both uppercase and lowercase Base32 characters.

    Args:
        encoded: The Base32-encoded string to decode.

    Returns:
        The decoded bytes.

    Raises:
        ValueError: If the input contains invalid Base32 characters.

    Example:
        >>> decode_base32("abcde")
        b'\\x00\\x01\\x02\\x03\\x04'
    """
    if not encoded:
        return b""

    encoded = encoded.lower()
    result = bytearray()
    rev_table = _get_base32_reverse()

    # Process 8-character blocks (produces 5 bytes)
    i = 0
    while i < len(encoded):
        # Collect up to 8 characters
        block_chars = []
        for j in range(min(8, len(encoded) - i)):
            c = encoded[i + j]
            if c not in rev_table:
                raise ValueError(f"Invalid Base32 character: {c}")
            block_chars.append(rev_table[c])

        # Pad to 8 if needed
        while len(block_chars) < 8:
            block_chars.append(0)

        # Combine 8 quintets (5 bits each) into 40 bits
        val = 0
        for j, quintet in enumerate(block_chars):
            val |= quintet << (35 - j * 5)

        # Extract 5 bytes
        result.extend(val.to_bytes(5, "big"))
        i += 8

    # Remove padding based on input length
    # If input wasn't a multiple of 8, we added extra padding
    expected_len = (len(encoded) * 5) // 8
    return bytes(result[:expected_len])


def _get_base32_reverse() -> dict:
    """Build reverse lookup table for Base32 decoding."""
    rev = {}
    for i, c in enumerate(B32_CHARS):
        rev[c] = i
    for i, c in enumerate(B32_CHARS_UCASE):
        rev[c] = i
    return rev


def encode_base64(data: bytes) -> str:
    """Encode bytes to Base64 string.

    Uses the iodine-compatible Base64 alphabet (a-z, A-Z, '-', 0-9, +).
    Each 3 bytes of input becomes 4 characters of output.

    Args:
        data: The raw bytes to encode.

    Returns:
        The Base64-encoded string.

    Example:
        >>> encode_base64(b"\\x00\\x01\\x02")
        'abc'
    """
    if not data:
        return ""

    result = []
    blocks_raw = len(data) // 3
    remainder = len(data) % 3

    # Process complete 3-byte blocks
    for i in range(blocks_raw):
        block = data[i * 3 : (i + 1) * 3]
        val = int.from_bytes(block, "big")
        for j in range(4):
            idx = (val >> (18 - j * 6)) & 0x3F
            result.append(B64_CHARS[idx])

    # Process partial block
    if remainder > 0:
        block = bytearray(3)
        block[:remainder] = data[blocks_raw * 3 :]
        val = int.from_bytes(block, "big")
        num_sextets = remainder + 1  # 1 or 2 bytes -> 2 or 3 chars
        for j in range(num_sextets):
            idx = (val >> (18 - j * 6)) & 0x3F
            result.append(B64_CHARS[idx])

    return "".join(result)


def decode_base64(encoded: str) -> bytes:
    """Decode Base64 string to bytes.

    Args:
        encoded: The Base64-encoded string to decode.

    Returns:
        The decoded bytes.

    Raises:
        ValueError: If the input contains invalid Base64 characters.

    Example:
        >>> decode_base64("abc")
        b'\\x00\\x01\\x02'
    """
    if not encoded:
        return b""

    result = bytearray()
    rev_table = _get_base64_reverse()

    # Process 4-character blocks (produces 3 bytes)
    i = 0
    while i < len(encoded):
        block_chars = []
        for j in range(min(4, len(encoded) - i)):
            c = encoded[i + j]
            if c not in rev_table:
                raise ValueError(f"Invalid Base64 character: {c}")
            block_chars.append(rev_table[c])

        # Pad to 4 if needed
        while len(block_chars) < 4:
            block_chars.append(0)

        # Combine 4 sextets (6 bits each) into 24 bits
        val = 0
        for j, sextet in enumerate(block_chars):
            val |= sextet << (18 - j * 6)

        result.extend(val.to_bytes(3, "big"))
        i += 4

    # Remove padding based on input length
    expected_len = (len(encoded) * 6) // 8
    return bytes(result[:expected_len])


def _get_base64_reverse() -> dict:
    """Build reverse lookup table for Base64 decoding."""
    rev = {}
    for i, c in enumerate(B64_CHARS):
        rev[c] = i
    return rev


def encode_base128(data: bytes) -> str:
    """Encode bytes to Base128 string.

    Uses B128_CHARS lookup table to encode 7 bits per byte.
    Each 7 bytes of input becomes 8 characters of output.

    The encoding scheme:
    - Input: 7 bytes = 56 bits
    - Output: 8 characters, each representing 7 bits of data

    Args:
        data: The raw bytes to encode.

    Returns:
        The Base128-encoded string (may contain non-ASCII characters).

    Example:
        >>> encode_base128(b"\\x00\\x01\\x02\\x03\\x04\\x05\\x06")
        '\\xc0\\xc1\\xc2\\xc3\\xc4\\xc5\\xc6\\xc7'
    """
    if not data:
        return ""

    result = []
    blocks_raw = len(data) // 7
    remainder = len(data) % 7

    # Process complete 7-byte blocks
    for i in range(blocks_raw):
        block = data[i * 7 : (i + 1) * 7]
        # 7 bytes = 56 bits = 8 septets of 7 bits each
        val = int.from_bytes(block, "big")
        for j in range(8):
            # Extract 7 bits starting from the most significant
            septet = (val >> (49 - j * 7)) & 0x7F
            result.append(B128_CHARS[septet])

    # Process partial block
    if remainder > 0:
        block = bytearray(7)
        block[:remainder] = data[blocks_raw * 7 :]
        val = int.from_bytes(block, "big")
        # Number of complete septets we can extract
        num_septets = remainder + 1
        for j in range(num_septets):
            septet = (val >> (49 - j * 7)) & 0x7F
            result.append(B128_CHARS[septet])

    return "".join(result)


def decode_base128(encoded: str) -> bytes:
    """Decode Base128 string to bytes.

    Args:
        encoded: The Base128-encoded string to decode.

    Returns:
        The decoded bytes.

    Raises:
        ValueError: If the input contains invalid Base128 characters.

    Example:
        >>> decode_base128('\\x80\\x81\\x82\\x83\\x84\\x85\\x86\\x87')
        b'\\x00\\x01\\x02\\x03\\x04\\x05\\x06'
    """
    if not encoded:
        return b""

    result = bytearray()
    rev_table = _get_base128_reverse()

    # Process 8-character blocks (produces 7 bytes)
    i = 0
    while i < len(encoded):
        block_chars = []
        for j in range(min(8, len(encoded) - i)):
            c = encoded[i + j]
            idx = rev_table.get(ord(c))
            if idx is None:
                raise ValueError(f"Invalid Base128 character: {repr(c)}")
            block_chars.append(idx)

        # Pad to 8 if needed
        while len(block_chars) < 8:
            block_chars.append(0)

        # Combine 8 septets (7 bits each) into 56 bits
        val = 0
        for j, septet in enumerate(block_chars):
            val |= septet << (49 - j * 7)

        result.extend(val.to_bytes(7, "big"))
        i += 8

    # Remove padding based on input length
    expected_len = (len(encoded) * 7) // 8
    return bytes(result[:expected_len])


def _get_base128_reverse() -> dict:
    """Build reverse lookup table for Base128 decoding."""
    rev = {}
    for i, c in enumerate(B128_CHARS):
        rev[ord(c)] = i
    return rev


def get_codec(name: str) -> tuple[Callable[[bytes], str], Callable[[str], bytes]]:
    """Get encoder/decoder pair by name.

    Args:
        name: The encoding name ('base32', 'base64', or 'base128').

    Returns:
        A tuple of (encoder, decoder) functions.

    Raises:
        ValueError: If the encoding name is not recognized.

    Example:
        >>> encode, decode = get_codec('base32')
        >>> data = b'test'
        >>> decode(encode(data)) == data
        True
    """
    name = name.lower().replace("-", "")
    if name == "base32":
        return encode_base32, decode_base32
    elif name == "base64":
        return encode_base64, decode_base64
    elif name == "base128":
        return encode_base128, decode_base128
    else:
        raise ValueError(f"Unknown encoding: {name}")


# Block size constants (must match C implementation)
BASE32_BLKSIZE_RAW = 5
BASE32_BLKSIZE_ENC = 8
BASE64_BLKSIZE_RAW = 3
BASE64_BLKSIZE_ENC = 4
BASE128_BLKSIZE_RAW = 7
BASE128_BLKSIZE_ENC = 8


def get_blksize_raw(encoding: str) -> int:
    """Get raw block size for an encoding.

    Args:
        encoding: The encoding name.

    Returns:
        The raw block size in bytes.
    """
    encoding = encoding.lower().replace("-", "")
    if encoding == "base32":
        return BASE32_BLKSIZE_RAW
    elif encoding == "base64":
        return BASE64_BLKSIZE_RAW
    elif encoding == "base128":
        return BASE128_BLKSIZE_RAW
    raise ValueError(f"Unknown encoding: {encoding}")


def get_blksize_enc(encoding: str) -> int:
    """Get encoded block size for an encoding.

    Args:
        encoding: The encoding name.

    Returns:
        The encoded block size in characters.
    """
    encoding = encoding.lower().replace("-", "")
    if encoding == "base32":
        return BASE32_BLKSIZE_ENC
    elif encoding == "base64":
        return BASE64_BLKSIZE_ENC
    elif encoding == "base128":
        return BASE128_BLKSIZE_ENC
    raise ValueError(f"Unknown encoding: {encoding}")
