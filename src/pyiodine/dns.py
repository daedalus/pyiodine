"""DNS packet handling for pyiodine.

This module provides DNS query/response construction and parsing for the
iodine-compatible DNS tunneling protocol. It handles encoding tunnel data
into DNS names and extracting data from DNS responses.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

# DNS record types
T_A = 1
T_NS = 2
T_CNAME = 5
T_NULL = 10
T_TXT = 16
T_MX = 15
T_SRV = 33
T_AAAA = 28

# DNS classes
C_IN = 1

# DNS flags
QR_QUERY = 0
QR_ANSWER = 1


@dataclass
class DNSQuery:
    """Represents a DNS query."""

    id: int
    name: str
    type: int
    raw_data: bytes | None = None


@dataclass
class DNSResponse:
    """Represents a DNS response."""

    id: int
    name: str
    type: int
    data: bytes
    authoritative: bool = False
    ttl: int = 0


def build_query(domain: str, qtype: int = T_TXT, qclass: int = C_IN) -> bytes:
    """Build a DNS query packet.

    Constructs a standard DNS query with the specified domain and type.
    The domain name will contain encoded tunnel data in iodine's format.

    Args:
        domain: The domain name to query (may contain encoded data).
        qtype: DNS record type (default: TXT).
        qclass: DNS class (default: IN).

    Returns:
        The raw DNS query packet bytes.

    Example:
        >>> packet = build_query("test.example.com")
        >>> len(packet) > 0
        True
    """
    # Generate random transaction ID
    import random

    txn_id = random.randint(0, 65535)

    # DNS header: ID(2) + FLAGS(2) + QDCOUNT(2) + ANCOUNT(2) + NSCOUNT(2) + ARCOUNT(2)
    header = struct.pack("!HHHHHH", txn_id, 0x0100, 1, 0, 0, 0)

    # Question section: QNAME + QTYPE(2) + QCLASS(2)
    qname = _encode_domain_name(domain)
    question = struct.pack("!HH", qtype, qclass)

    return header + qname + question


def parse_response(packet: bytes) -> DNSResponse | None:
    """Parse a DNS response packet.

    Extracts the response data from a DNS answer. Handles various
    record types used by iodine (TXT, NULL, CNAME, MX, SRV).

    Args:
        packet: The raw DNS response packet.

    Returns:
        DNSResponse object if successful, None if parsing fails.

    Example:
        >>> response = parse_response(b'\\x00\\x01...')
        >>> response is not None
        False
    """
    if len(packet) < 12:
        return None

    # Parse header
    header = struct.unpack("!HHHHHH", packet[:12])
    txn_id = header[0]
    flags = header[1]
    ancount = header[3]

    if ancount == 0:
        return None

    # Check if this is an answer
    qr = (flags >> 15) & 0x1
    if qr != QR_ANSWER:
        return None

    # Skip header and question section
    offset = 12
    try:
        _, offset = _decode_domain_name(packet, offset)
    except ValueError:
        return None

    # Skip QTYPE and QCLASS
    if offset + 4 > len(packet):
        return None
    offset += 4

    # Parse answer section
    for _ in range(ancount):
        try:
            _, offset = _decode_domain_name(packet, offset)
        except ValueError:
            return None

        if offset + 10 > len(packet):
            return None

        rtype, rclass, ttl, rdlength = struct.unpack(
            "!HHIH", packet[offset : offset + 10]
        )
        offset += 10

        if offset + rdlength > len(packet):
            return None

        rdata = packet[offset : offset + rdlength]
        offset += rdlength

        # Extract data based on record type
        data = _extract_data_from_rdata(rtype, rdata, packet)

        if data is not None:
            return DNSResponse(
                id=txn_id,
                name="",  # Name would need to be extracted from question
                type=rtype,
                data=data,
                authoritative=bool(flags & 0x0400),
                ttl=ttl,
            )

    return None


def build_response(
    query: bytes, data: bytes, domain: str, rtype: int = T_TXT
) -> bytes:
    """Build a DNS response packet with tunnel data.

    Creates a DNS response that contains the encoded tunnel data
    in the appropriate record type.

    Args:
        query: The original DNS query packet.
        data: The tunnel data to include in the response.
        domain: The domain name for the response.
        rtype: The DNS record type to use.

    Returns:
        The raw DNS response packet.

    Example:
        >>> query = build_query("test.com")
        >>> response = build_response(query, b"hello", "test.com")
        >>> len(response) > 0
        True
    """
    if len(query) < 12:
        return b""

    # Parse query header
    header = struct.unpack("!HHHHHH", query[:12])
    txn_id = header[0]

    # Build response header (set QR=1, AA=1)
    resp_header = struct.pack("!HHHHHH", txn_id, 0x8400, 1, 1, 0, 0)

    # Include original question
    # Skip header to find question section
    q_offset = 12
    try:
        qname_encoded, q_offset = _decode_domain_name(query, q_offset)
    except ValueError:
        return b""

    # Re-encode the question
    qname = _encode_domain_name(domain)
    question = struct.pack("!HH", rtype, C_IN)

    # Build answer
    # NAME (pointer to question name)
    answer_name = b"\xc0\x0c"  # Pointer to offset 12 (start of question name)

    # TYPE, CLASS, TTL, RDLENGTH
    ttl = 0  # Authoritative answers use 0 TTL
    if rtype == T_TXT:
        rdlength = len(data) + 1  # +1 for length byte
        answer = struct.pack("!HHIH", rtype, C_IN, ttl, rdlength)
        # TXT record: length byte followed by data
        txt_data = struct.pack("!B", len(data)) + data
        answer += txt_data
    elif rtype == T_NULL:
        rdlength = len(data)
        answer = struct.pack("!HHIH", rtype, C_IN, ttl, rdlength)
        answer += data
    elif rtype == T_CNAME:
        # CNAME points to an encoded domain name
        cname = _encode_domain_name(data.decode("ascii", errors="ignore"))
        rdlength = len(cname)
        answer = struct.pack("!HHIH", rtype, C_IN, ttl, rdlength)
        answer += cname
    else:
        # Default: treat as NULL
        rdlength = len(data)
        answer = struct.pack("!HHIH", rtype, C_IN, ttl, rdlength)
        answer += data

    return resp_header + qname + question + answer_name + answer


def _encode_domain_name(name: str) -> bytes:
    """Encode a domain name into DNS wire format.

    Args:
        name: The domain name to encode (e.g., "www.example.com").

    Returns:
        The DNS wire format bytes.
    """
    result = bytearray()
    labels = name.split(".")
    for label in labels:
        if len(label) > 63:
            raise ValueError(f"Label too long: {label}")
        result.append(len(label))
        result.extend(label.encode("ascii"))
    result.append(0)  # Root label terminator
    return bytes(result)


def _decode_domain_name(
    packet: bytes, offset: int
) -> tuple[str, int]:
    """Decode a domain name from DNS wire format.

    Handles DNS name compression (pointers).

    Args:
        packet: The full DNS packet.
        offset: The offset to start reading from.

    Returns:
        A tuple of (decoded_name, new_offset).

    Raises:
        ValueError: If the name cannot be decoded.
    """
    labels = []
    original_offset = offset

    while True:
        if offset >= len(packet):
            raise ValueError("Unexpected end of packet")

        length_byte = packet[offset]

        # Check for pointer (two high bits set)
        if (length_byte & 0xC0) == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("Incomplete pointer")
            pointer = struct.unpack("!H", packet[offset : offset + 2])[0] & 0x3FFF
            # Recursively decode from pointer location
            pointed_name, _ = _decode_domain_name(packet, pointer)
            labels.append(pointed_name)
            offset += 2
            break

        # Check for root label (end of name)
        if length_byte == 0:
            offset += 1
            break

        # Regular label
        length = length_byte & 0x3F
        if offset + 1 + length > len(packet):
            raise ValueError("Label extends beyond packet")

        label = packet[offset + 1 : offset + 1 + length].decode("ascii", errors="replace")
        labels.append(label)
        offset += 1 + length

    name = ".".join(labels)
    return name, offset


def _extract_data_from_rdata(
    rtype: int, rdata: bytes, packet: bytes
) -> bytes | None:
    """Extract tunnel data from DNS response RDATA.

    Args:
        rtype: The DNS record type.
        rdata: The raw RDATA bytes.
        packet: The full DNS packet (for pointer resolution).

    Returns:
        The extracted data bytes, or None if extraction fails.
    """
    if rtype == T_TXT:
        # TXT record: one or more <length><string> sequences
        if len(rdata) < 1:
            return None
        # First byte is length of first string
        length = rdata[0]
        if length + 1 <= len(rdata):
            return rdata[1 : 1 + length]
        return rdata[1:] if len(rdata) > 1 else b""

    elif rtype == T_NULL:
        # NULL record: data is the raw bytes
        return rdata

    elif rtype == T_CNAME:
        # CNAME: decode the domain name (may contain encoded data)
        try:
            name, _ = _decode_domain_name(packet, 0)  # Would need proper offset
            return name.encode("ascii", errors="replace")
        except Exception:
            return rdata

    elif rtype == T_MX or rtype == T_SRV:
        # MX/SRV: skip priority/weight/port fields, return rest
        # For MX: 2 bytes preference + domain name
        # For SRV: 2 bytes priority + 2 bytes weight + 2 bytes port + domain name
        if len(rdata) < 2:
            return None
        # Skip the initial fields and try to extract domain
        return rdata  # Simplified - return raw data

    return None


def get_txn_id(packet: bytes) -> int:
    """Extract the transaction ID from a DNS packet.

    Args:
        packet: The DNS packet.

    Returns:
        The transaction ID.

    Example:
        >>> get_txn_id(b'\\x12\\x34...')
        0x1234
    """
    if len(packet) < 2:
        return 0
    return struct.unpack("!H", packet[:2])[0]


def set_edns0(packet: bytes, payload_size: int = 4096) -> bytes:
    """Add EDNS0 OPT record to a DNS packet.

    EDNS0 allows larger UDP packet sizes.

    Args:
        packet: The original DNS packet.
        payload_size: The EDNS0 UDP payload size.

    Returns:
        The packet with EDNS0 added.
    """
    if len(packet) < 12:
        return packet

    # Parse header to get ARCOUNT
    header = list(struct.unpack("!HHHHHH", packet[:12]))

    # EDNS0 OPT record:
    # Root name (0), TYPE=OPT(41), CLASS=payload_size, TTL=extended RCODE + flags
    opt_record = b"\x00"  # Root name
    opt_record += struct.pack("!HHI", 41, payload_size, 0)  # TYPE=OPT, CLASS=payload_size, TTL=0
    opt_record += struct.pack("!H", 0)  # RDLENGTH=0

    # Update ARCOUNT
    header[5] += 1
    new_header = struct.pack("!HHHHHH", *header)

    return new_header + packet[12:] + opt_record


# Default record type for tunnel data
DEFAULT_RECORD_TYPE = T_TXT


def encode_tunnel_data(data: bytes, domain: str, encoding: str = "base32") -> str:
    """Encode tunnel data into a domain name for DNS query.

    Args:
        data: The raw tunnel data to encode.
        domain: The base domain (e.g., "t1.example.com").
        encoding: The encoding to use (base32, base64, base128).

    Returns:
        The full domain name with encoded data prepended.

    Example:
        >>> encode_tunnel_data(b"\\x00\\x01", "example.com")
        '...example.com'
    """
    from pyiodine.encoding import get_codec

    encoder, _ = get_codec(encoding)
    encoded = encoder(data)

    # Split encoded data into DNS labels (max 63 chars each)
    labels = []
    for i in range(0, len(encoded), 63):
        labels.append(encoded[i : i + 63])

    # Prepend encoded data labels to domain
    return ".".join(labels + [domain])


def decode_tunnel_data(encoded_domain: str, encoding: str = "base32") -> bytes:
    """Decode tunnel data from a domain name.

    Args:
        encoded_domain: The domain name containing encoded data.
        encoding: The encoding used.

    Returns:
        The decoded tunnel data.
    """
    from pyiodine.encoding import get_codec

    _, decoder = get_codec(encoding)

    # Extract the encoded part (before the base domain)
    # This is simplified - in practice need to know the base domain
    labels = encoded_domain.split(".")
    # Decode all labels except the base domain (last 2-3 labels)
    encoded = "".join(labels[:-2])  # Simplified
    return decoder(encoded)
