# SPEC.md — pyiodine

## Purpose

Pyiondine is a Python translation of the iodine DNS tunneling tool, which allows tunneling IPv4 data through DNS servers. This enables network access in firewalled environments where only DNS queries are allowed. The project translates the core C implementation to Python while maintaining protocol compatibility.

## Scope

**In scope:**
- DNS packet encoding/decoding (query/response)
- Base32, Base64, and Base128 encoding schemes
- Client implementation (iodine equivalent)
- Server implementation (iodined equivalent)
- TUN interface abstraction (where platform-supported)
- DNS message construction and parsing
- Authentication via CHAP-style challenge/response
- Fragmentation and reassembly of tunneled data
- Keepalive and latency measurement

**Out of scope:**
- Windows-specific TUN support (Windows requires external drivers)
- Android-specific implementations
- Systemd/service integration
- Full SELinux support
- Binary compatibility with C iodine (protocol compatibility only)

## Public API / Interface

### Core Modules

#### `pyiodine.encoding`

- `encode_base32(data: bytes) -> str` - Encode bytes to Base32 string
- `decode_base32(encoded: str) -> bytes` - Decode Base32 string to bytes
- `encode_base64(data: bytes) -> str` - Encode bytes to Base64 string
- `decode_base64(encoded: str) -> bytes` - Decode Base64 string to bytes
- `encode_base128(data: bytes) -> str` - Encode bytes to Base128 (custom scheme)
- `decode_base128(encoded: str) -> bytes` - Decode Base128 string to bytes
- `get_codec(name: str) -> tuple[Callable, Callable]` - Get encoder/decoder pair

#### `pyiodine.dns`

- `build_query(domain: str, qtype: int, qclass: int) -> bytes` - Build DNS query packet
- `parse_response(packet: bytes) -> DNSResponse` - Parse DNS response packet
- `build_response(query: bytes, data: bytes, domain: str) - Build DNS response with data
- `DNSTunnelMessage` - Class representing tunneled data in DNS

#### `pyiodine.tunnel`

- `TunnelInterface` - Abstract base class for TUN interface
- `LinuxTunnelInterface` - Linux-specific TUN implementation
- `DummyTunnelInterface` - Dummy interface for testing
- `open_tunnel(ip: str, netmask: str) - Open/create TUN interface

#### `pyiodine.client`

- `IodineClient` - DNS tunneling client
  - `__init__(self, domain: str, nameserver: str, password: str, ...)` - Initialize client
  - `connect(self) -> None` - Establish tunnel connection
  - `disconnect(self) -> None` - Tear down tunnel
  - `send_data(self, data: bytes) -> None` - Send data through tunnel
  - `recv_data(self) -> bytes` - Receive data from tunnel

#### `pyiodine.server`

- `IodineServer` - DNS tunneling server
  - `__init__(self, ip: str, domain: str, password: str, ...)` - Initialize server
  - `start(self) -> None` - Start listening for DNS queries
  - `stop(self) -> None` - Stop server
  - `handle_query(self, data: bytes, addr: tuple) -> None` - Handle incoming DNS query

#### `pyiodine.common`

- `calculate_checksum(data: bytes) -> int` - Calculate checksum for packets
- `split_data(data: bytes, chunk_size: int) - Split data into chunks
- `merge_data(chunks: list[bytes]) -> bytes` - Merge chunks back together
- `ChallengeResponse` - CHAP-style authentication handler

## Data Formats

### DNS Messages
Standard DNS message format as per RFC 1035, with custom encoding of tunnel data in:
- TXT record strings (most common)
- NULL record data
- SRV record priorities/weights

### Tunnel Data Format
```
[version:1][flags:1][seq:2][fragment_id:1][fragment_count:1][data:...]
```

### Encoding Schemes
- Base32: RFC 4648 standard encoding
- Base64: RFC 4648 standard encoding
- Base128: Custom scheme using high ASCII (128-255) to encode 7 bits per byte

## Edge Cases

1. **Empty data**: Encoding/decoding empty bytes should return empty strings/bytes
2. **Large packets**: DNS messages limited to 512 bytes (UDP), fragmentation required
3. **Invalid encoding**: Garbage data passed to decoders should raise `ValueError`
4. **Network timeouts**: DNS queries may timeout, should retry with backoff
5. **Authentication failure**: Wrong password should result in clear error, not hang
6. **TUN interface unavailable**: Should detect and report missing TUN support
7. **Domain validation**: Invalid domain format should be rejected early
8. **Fragment reassembly timeout**: Incomplete fragments should timeout and be discarded

## Performance & Constraints

- Target Python version: 3.11+
- Dependencies: `dnspython` for DNS handling, `pytun` for TUN interface (Linux)
- DNS queries should timeout within 5 seconds by default
- Keep packet overhead minimal (DNS headers + encoding overhead)
- Use asyncio for concurrent client/server operations where appropriate
- Memory usage should be bounded (no unbounded buffers)
- Thread-safe where applicable (TUN read vs DNS send)

## Protocol Compatibility

The implementation must maintain wire protocol compatibility with C iodine:
- Same encoding schemes (base32/base64/base128)
- Same DNS query/response format
- Same authentication handshake (CHAP-style)
- Same fragmentation logic
- Version negotiation (currently version 000005)

## Security Considerations

- Password-based authentication (CHAP challenge/response)
- No encryption by default (tunnel is not encrypted, just encoded)
- Consider adding optional TLS/DTLS in future versions
- Validate all incoming DNS packets to prevent injection
