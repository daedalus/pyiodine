"""Common utilities for pyiodine.

This module provides shared functionality used by both client and server,
including checksums, data fragmentation, authentication, and packet handling.
"""

from __future__ import annotations

import hashlib
import os
import socket
import struct
from dataclasses import dataclass

# Protocol constants
RAW_HDR_LEN = 4
RAW_HDR_IDENT_LEN = 3
RAW_HDR_CMD = 3

# Commands
RAW_HDR_CMD_LOGIN = 0x10
RAW_HDR_CMD_DATA = 0x20
RAW_HDR_CMD_PING = 0x30

RAW_HDR_CMD_MASK = 0xF0
RAW_HDR_USR_MASK = 0x0F

# DNS port
DNS_PORT = 53

# Special DNS record types
T_PRIVATE = 65399  # Private use range
T_UNSET = 65432  # Never actually sent

# Fragment constants
MAX_FRAGMENTS = 256
FRAGMENT_SIZE_DEFAULT = 400  # Default max DNS payload size


@dataclass
class Packet:
    """Represents a tunnel packet with fragmentation support."""

    len: int = 0
    sentlen: int = 0
    offset: int = 0
    data: bytes = b""
    seqno: int = 0
    fragment: int = 0

    def to_bytes(self) -> bytes:
        """Serialize packet to bytes.

        Returns:
            The serialized packet.
        """
        # Header: seqno(1) + fragment(1) + len(2) + data
        header = struct.pack("!BBH", self.seqno & 0xFF, self.fragment & 0xFF, len(self.data))
        self.len = len(self.data)
        return header + self.data

    @classmethod
    def from_bytes(cls, raw: bytes) -> Packet | None:
        """Deserialize packet from bytes.

        Args:
            raw: The raw bytes to deserialize.

        Returns:
            Packet object or None if invalid.
        """
        if len(raw) < 4:
            return None

        seqno, fragment, data_len = struct.unpack("!BBH", raw[:4])
        packet = cls()
        packet.seqno = seqno
        packet.fragment = fragment
        packet.len = data_len
        packet.data = raw[4 : 4 + data_len] if data_len > 0 else b""
        return packet


@dataclass
class Query:
    """Represents a DNS query."""

    name: str = ""
    type: int = 0
    rcode: int = 0
    id: int = 0
    id2: int = 0


def calculate_checksum(data: bytes) -> int:
    """Calculate Internet checksum (RFC 1071).

    Args:
        data: The data to checksum.

    Returns:
        The 16-bit checksum value.

    Example:
        >>> calculate_checksum(b"hello")
        3549
    """
    if len(data) % 2 != 0:
        data += b"\x00"

    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + (data[i + 1] if i + 1 < len(data) else 0)
        total += word

    # Fold 32-bit sum to 16 bits
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)

    return ~total & 0xFFFF


def split_data(data: bytes, chunk_size: int) -> list[bytes]:
    """Split data into chunks of specified size.

    Args:
        data: The data to split.
        chunk_size: Maximum size of each chunk.

    Returns:
        List of data chunks.

    Example:
        >>> split_data(b"hello world", 5)
        [b'hello', b' worl', b'd']
    """
    if not data:
        return []

    return [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]


def merge_data(chunks: list[bytes]) -> bytes:
    """Merge data chunks back together.

    Args:
        chunks: List of data chunks.

    Returns:
        The merged data.

    Example:
        >>> merge_data([b'hello', b' ', b'world'])
        b'hello world'
    """
    return b"".join(chunks)


class ChallengeResponse:
    """CHAP-style challenge-response authentication.

    Implements the iodine authentication protocol where the server
    sends a challenge and the client responds with a hash of the
    challenge concatenated with the password.
    """

    def __init__(self, password: str):
        """Initialize with shared password.

        Args:
            password: The shared secret password.
        """
        self.password = password.encode("utf-8")

    def generate_challenge(self) -> bytes:
        """Generate a random challenge.

        Returns:
            Random challenge bytes (16 bytes).
        """
        return os.urandom(16)

    def compute_response(self, challenge: bytes) -> bytes:
        """Compute response to a challenge.

        The response is MD5(challenge + password).

        Args:
            challenge: The challenge bytes from server.

        Returns:
            The response hash.
        """
        md5 = hashlib.md5()
        md5.update(challenge)
        md5.update(self.password)
        return md5.digest()

    def verify_response(self, challenge: bytes, response: bytes) -> bool:
        """Verify a client's response to a challenge.

        Args:
            challenge: The original challenge.
            response: The client's response.

        Returns:
            True if response is valid, False otherwise.
        """
        expected = self.compute_response(challenge)
        return response == expected


def format_addr(sockaddr: tuple[str, int]) -> str:
    """Format a socket address for display.

    Args:
        sockaddr: Socket address tuple (ip, port).

    Returns:
        Formatted address string.
    """
    if len(sockaddr) >= 2:
        return f"{sockaddr[0]}:{sockaddr[1]}"
    return str(sockaddr)


def get_addr(host: str, port: int, family: int = 0, flags: int = 0) -> tuple | None:
    """Resolve a hostname to socket address.

    Args:
        host: Hostname or IP address.
        port: Port number.
        family: Address family (AF_INET, AF_INET6, or 0 for any).
        flags: Additional getaddrinfo flags.

    Returns:
        Socket address tuple or None if resolution fails.
    """
    try:
        results = socket.getaddrinfo(host, port, family, socket.SOCK_DGRAM, 0, flags)
        if results:
            return results[0][4]
    except socket.gaierror:
        pass
    return None


def open_dns_socket(addr: tuple, sockaddr_len: int = 0) -> socket.socket | None:
    """Open a UDP socket for DNS communication.

    Args:
        addr: Socket address to bind to (or None for any).
        sockaddr_len: Unused (kept for compatibility).

    Returns:
        UDP socket or None on failure.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if addr:
            sock.bind(addr)
        return sock
    except OSError:
        return None


def close_dns_socket(sock: socket.socket) -> None:
    """Close a DNS socket.

    Args:
        sock: The socket to close.
    """
    try:
        sock.close()
    except Exception:
        pass


def check_topdomain(domain: str) -> bool:
    """Check if a domain is a valid top-level domain format.

    Args:
        domain: The domain to check.

    Returns:
        True if valid format, False otherwise.
    """
    if not domain or len(domain) > 255:
        return False

    labels = domain.split(".")
    if len(labels) < 2:
        return False

    for label in labels:
        if not label or len(label) > 63:
            return False
        if not all(c.isalnum() or c == "-" for c in label):
            return False
        if label.startswith("-") or label.endswith("-"):
            return False

    return True


def read_password(prompt: str = "Password: ") -> str:
    """Read a password from terminal without echoing.

    Args:
        prompt: The prompt to display.

    Returns:
        The password entered by user.
    """
    import getpass

    return getpass.getpass(prompt)


def recent_seqno(seqno: int, window: list[int]) -> bool:
    """Check if a sequence number is recent (within window).

    Args:
        seqno: The sequence number to check.
        window: List of recent sequence numbers.

    Returns:
        True if seqno is in window, False otherwise.
    """
    return seqno in window


# Raw header functions
def raw_header_get_cmd(header: bytes) -> int:
    """Get command from raw header.

    Args:
        header: The raw header bytes.

    Returns:
        The command byte (masked).
    """
    if len(header) <= RAW_HDR_CMD:
        return 0
    return header[RAW_HDR_CMD] & RAW_HDR_CMD_MASK


def raw_header_get_usr(header: bytes) -> int:
    """Get user field from raw header.

    Args:
        header: The raw header bytes.

    Returns:
        The user field (masked).
    """
    if len(header) <= RAW_HDR_CMD:
        return 0
    return header[RAW_HDR_CMD] & RAW_HDR_USR_MASK


def create_raw_header(cmd: int, usr: int = 0) -> bytes:
    """Create a raw packet header.

    Args:
        cmd: The command (use RAW_HDR_CMD_* constants).
        usr: The user field (4 bits).

    Returns:
        The 4-byte raw header.
    """
    header = bytearray([0x10, 0xD1, 0x9E, 0x00])
    header[RAW_HDR_CMD] = (cmd & RAW_HDR_CMD_MASK) | (usr & RAW_HDR_USR_MASK)
    return bytes(header)
