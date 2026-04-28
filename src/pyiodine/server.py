"""Iodine server implementation for pyiodine.

This module provides the server-side implementation of the iodine DNS tunneling
protocol. It listens for DNS queries and responds with tunneled data.
"""

from __future__ import annotations

import select
import socket
import struct
import threading
import time
from dataclasses import dataclass, field

from pyiodine.common import (
    RAW_HDR_CMD_LOGIN,
    ChallengeResponse,
    close_dns_socket,
)
from pyiodine.dns import (
    DNSQuery,
    build_response,
    encode_tunnel_data,
)
from pyiodine.encoding import get_codec
from pyiodine.tunnel import TunnelInterface, open_tunnel

# Connection modes
CONN_RAW_UDP = 0
CONN_DNS_NULL = 1

# Protocol constants
DNS_PORT = 53
DEFAULT_MTU = 1500


@dataclass
class UserSession:
    """Represents a connected client session."""

    userid: int
    addr: tuple[str, int]
    encoding: str = "base32"
    authenticated: bool = False
    last_seen: float = field(default_factory=time.time)

    # Packet tracking
    last_seqno: int = -1
    fragments: dict[int, list[bytes]] = field(default_factory=dict)

    # Statistics
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0


@dataclass
class ServerState:
    """Server state for tracking all connections."""

    running: bool = True
    topdomain: str = ""
    password: str = ""
    ip: str = "10.0.0.1"
    netmask: str = "255.255.255.0"

    # DNS socket
    dns_socket_v4: socket.socket | None = None
    dns_socket_v6: socket.socket | None = None

    # TUN interface
    tun_interface: TunnelInterface | None = None

    # User sessions
    users: dict[int, UserSession] = field(default_factory=dict)
    next_userid: int = 1

    # Statistics
    total_queries: int = 0
    total_responses: int = 0


class IodineServer:
    """Iodine DNS tunneling server.

    Implements the server-side of the iodine protocol, handling
    DNS queries from clients and managing tunneled data.
    """

    def __init__(
        self,
        ip: str,
        domain: str,
        password: str,
        port: int = DNS_PORT,
        mtu: int = DEFAULT_MTU,
        debug: bool = False,
    ):
        """Initialize the iodine server.

        Args:
            ip: IP address to assign to the TUN interface.
            domain: The top domain for tunneling (e.g., "t1.example.com").
            password: Shared secret for authentication.
            port: DNS port to listen on (default: 53).
            mtu: MTU for the tunnel interface.
            debug: Enable debug output.
        """
        self.domain = domain
        self.password = password
        self.port = port
        self.mtu = mtu
        self.debug = debug

        self.state = ServerState()
        self.state.topdomain = domain
        self.state.ip = ip
        self.state.password = password

        self.challenge_response = ChallengeResponse(password)

        self._lock = threading.Lock()

    def start(self) -> None:
        """Start the server and begin listening for DNS queries.

        Opens DNS sockets and TUN interface, then enters the main loop.
        """
        print(f"Starting iodine server on port {self.port}...")
        print(f"Domain: {self.domain}")
        print(f"Tunnel IP: {self.state.ip}")

        # Open DNS sockets
        if not self._open_dns_sockets():
            print("Failed to open DNS sockets")
            return

        # Open TUN interface
        if not self._open_tun_interface():
            print("Failed to open TUN interface")
            self.stop()
            return

        print(f"TUN interface: {self.state.tun_interface.name}")
        print("Server running. Press Ctrl+C to stop.")

        try:
            self._main_loop()
        except KeyboardInterrupt:
            print("\nInterrupted by user")
        finally:
            self.stop()

    def _open_dns_sockets(self) -> bool:
        """Open DNS sockets for IPv4 and IPv6.

        Returns:
            True if at least one socket opened successfully.
        """
        # IPv4
        try:
            sock_v4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock_v4.bind(("0.0.0.0", self.port))
            self.state.dns_socket_v4 = sock_v4
            print(f"Listening on IPv4:0.0.0.0:{self.port}")
        except OSError as e:
            print(f"Failed to bind IPv4 DNS socket: {e}")

        # IPv6 (optional)
        try:
            sock_v6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sock_v6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock_v6.bind(("::", self.port))
            self.state.dns_socket_v6 = sock_v6
            print(f"Listening on IPv6:[::]:{self.port}")
        except (OSError, AttributeError) as e:
            if self.debug:
                print(f"IPv6 not available: {e}")

        return self.state.dns_socket_v4 is not None or self.state.dns_socket_v6 is not None

    def _open_tun_interface(self) -> bool:
        """Open TUN interface.

        Returns:
            True if successful.
        """
        try:
            self.state.tun_interface = open_tunnel(
                self.state.ip, "255.255.255.0", dummy=False
            )
            return True
        except OSError as e:
            print(f"Failed to open TUN interface: {e}")
            # Try dummy for testing
            self.state.tun_interface = open_tunnel(
                self.state.ip, "255.255.255.0", dummy=True
            )
            print("Using dummy TUN interface for testing")
            return True

    def _main_loop(self) -> None:
        """Main server event loop."""
        sockets = []
        if self.state.dns_socket_v4:
            sockets.append(self.state.dns_socket_v4)
        if self.state.dns_socket_v6:
            sockets.append(self.state.dns_socket_v6)

        tun_fd = -1
        if self.state.tun_interface:
            tun_fd = self.state.tun_interface.fd

        while self.state.running:
            read_fds = list(sockets)
            if tun_fd >= 0:
                read_fds.append(tun_fd)

            try:
                ready, _, _ = select.select(read_fds, [], [], 1.0)
            except OSError:
                continue

            for fd in ready:
                if fd in sockets:
                    self._handle_dns_query(fd)
                elif fd == tun_fd:
                    self._handle_tun_data()

    def _handle_dns_query(self, sock: socket.socket) -> None:
        """Handle incoming DNS query.

        Args:
            sock: The socket that received the query.
        """
        try:
            data, addr = sock.recvfrom(65536)
        except OSError:
            return

        self.state.total_queries += 1

        if self.debug:
            print(f"Query from {addr}: {len(data)} bytes")

        # Parse the query
        query = self._parse_dns_query(data)
        if not query:
            return

        # Route to appropriate handler
        response = self._route_query(query, data, addr)

        if response:
            try:
                sock.sendto(response, addr)
                self.state.total_responses += 1
            except OSError as e:
                if self.debug:
                    print(f"Failed to send response: {e}")

    def _parse_dns_query(self, data: bytes) -> DNSQuery | None:
        """Parse a DNS query packet.

        Args:
            data: Raw DNS packet.

        Returns:
            DNSQuery object or None.
        """
        if len(data) < 12:
            return None

        # Parse header
        header = struct.unpack("!HHHHHH", data[:12])
        txn_id = header[0]
        flags = header[1]
        qdcount = header[2]

        if qdcount == 0:
            return None

        # Check if this is a query (not response)
        qr = (flags >> 15) & 0x1
        if qr != 0:  # Not a query
            return None

        # Parse question section
        offset = 12
        try:
            name, offset = self._decode_domain_name(data, offset)
        except ValueError:
            return None

        if offset + 4 > len(data):
            return None

        qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])

        return DNSQuery(id=txn_id, name=name, type=qtype)

    def _decode_domain_name(self, packet: bytes, offset: int) -> tuple[str, int]:
        """Decode domain name from DNS packet.

        Args:
            packet: Full DNS packet.
            offset: Offset to start reading.

        Returns:
            Tuple of (domain_name, new_offset).
        """
        labels = []
        original_offset = offset

        while True:
            if offset >= len(packet):
                raise ValueError("Unexpected end of packet")

            length_byte = packet[offset]

            # Check for pointer
            if (length_byte & 0xC0) == 0xC0:
                if offset + 1 >= len(packet):
                    raise ValueError("Incomplete pointer")
                pointer = struct.unpack("!H", packet[offset : offset + 2])[0] & 0x3FFF
                pointed_name, _ = self._decode_domain_name(packet, pointer)
                labels.append(pointed_name)
                offset += 2
                break

            if length_byte == 0:
                offset += 1
                break

            length = length_byte & 0x3F
            if offset + 1 + length > len(packet):
                raise ValueError("Label extends beyond packet")

            label = packet[offset + 1 : offset + 1 + length].decode(
                "ascii", errors="replace"
            )
            labels.append(label)
            offset += 1 + length

        return ".".join(labels), offset

    def _route_query(
        self, query: DNSQuery, raw_data: bytes, addr: tuple
    ) -> bytes | None:
        """Route DNS query to appropriate handler.

        Args:
            query: Parsed DNS query.
            raw_data: Raw DNS packet.
            addr: Source address.

        Returns:
            DNS response packet or None.
        """
        # Check if this is a tunnel data query
        if self.domain in query.name:
            return self._handle_tunnel_query(query, raw_data, addr)

        # Otherwise, forward to real DNS if configured
        return None

    def _handle_tunnel_query(
        self, query: DNSQuery, raw_data: bytes, addr: tuple
    ) -> bytes | None:
        """Handle a tunnel data query.

        Args:
            query: Parsed DNS query.
            raw_data: Raw DNS packet.
            addr: Source address.

        Returns:
            DNS response packet.
        """
        # Extract encoded data from domain
        encoded_data = self._extract_encoded_data(query.name)

        if not encoded_data:
            return None

        # Determine encoding from query characteristics
        encoding = self._detect_encoding(encoded_data)

        try:
            decoder, _ = get_codec(encoding)
            raw_data = decoder(encoded_data)
        except (ValueError, KeyError):
            if self.debug:
                print(f"Failed to decode data: {encoded_data[:50]}")
            return None

        # Check if this is a login/authentication packet
        if raw_data and (raw_data[0] & 0xF0) == RAW_HDR_CMD_LOGIN:
            return self._handle_login(query, raw_data, addr, encoding)

        # Handle data packet
        return self._handle_data_packet(query, raw_data, addr, encoding)

    def _extract_encoded_data(self, domain: str) -> str:
        """Extract encoded data from domain name.

        Args:
            domain: Full domain name.

        Returns:
            Encoded data portion (before the top domain).
        """
        # Find where the top domain starts
        if self.domain not in domain:
            return ""

        # Get the part before our domain
        prefix = domain[: -len(self.domain) - 1]

        # Remove any subdomain labels
        parts = prefix.split(".")
        # The encoded data is typically the first label or concatenated labels
        return prefix.replace(".", "")

    def _detect_encoding(self, encoded: str) -> str:
        """Detect encoding from encoded data.

        Args:
            encoded: Encoded data string.

        Returns:
            Encoding name.
        """
        # Simple heuristic - can be expanded
        if all(c in "abcdefghijklmnopqrstuvwxyz012345" for c in encoded.lower()):
            return "base32"
        elif any(c in "+/" for c in encoded):
            return "base64"
        else:
            # Check for non-ASCII chars
            if any(ord(c) > 127 for c in encoded):
                return "base128"
            return "base64"

    def _handle_login(
        self,
        query: DNSQuery,
        data: bytes,
        addr: tuple,
        encoding: str,
    ) -> bytes | None:
        """Handle login/authentication.

        Args:
            query: DNS query.
            data: Decoded data.
            addr: Source address.
            encoding: Encoding used.

        Returns:
            DNS response with challenge or auth result.
        """
        # Create new user session
        with self._lock:
            userid = self.state.next_userid
            self.state.next_userid += 1

            session = UserSession(
                userid=userid,
                addr=addr,
                encoding=encoding,
            )
            self.state.users[userid] = session

        # Generate challenge and send response
        # Simplified - actual protocol involves CHAP-style challenge/response
        response_data = struct.pack("!B", userid) + b"auth_ok"

        return self._build_tunnel_response(query, response_data, encoding)

    def _handle_data_packet(
        self,
        query: DNSQuery,
        data: bytes,
        addr: tuple,
        encoding: str,
    ) -> bytes | None:
        """Handle data packet from client.

        Args:
            query: DNS query.
            data: Decoded tunnel data.
            addr: Source address.
            encoding: Encoding used.

        Returns:
            DNS response.
        """
        # Find user session based on addr
        userid = self._find_user_by_addr(addr)

        if userid is None:
            return None

        session = self.state.users[userid]
        session.last_seen = time.time()
        session.packets_received += 1
        session.bytes_received += len(data)

        # Write data to TUN interface
        if self.state.tun_interface and data:
            try:
                self.state.tun_interface.write(data)
            except OSError as e:
                if self.debug:
                    print(f"Failed to write to TUN: {e}")

        # Build response (may contain data for client)
        response_data = b""  # Would contain downstream data in real impl
        return self._build_tunnel_response(query, response_data, encoding)

    def _find_user_by_addr(self, addr: tuple) -> int | None:
        """Find user ID by address.

        Args:
            addr: Source address.

        Returns:
            User ID or None.
        """
        with self._lock:
            for userid, session in self.state.users.items():
                if session.addr == addr:
                    return userid
        return None

    def _build_tunnel_response(
        self, query: DNSQuery, data: bytes, encoding: str
    ) -> bytes:
        """Build DNS response for tunnel query.

        Args:
            query: Original query.
            data: Response data to encode.
            encoding: Encoding to use.

        Returns:
            DNS response packet.
        """
        # Encode data into domain name or TXT record
        if data:
            encoded = encode_tunnel_data(data, self.domain, encoding)
        else:
            encoded = self.domain

        # Build response with encoded data in TXT record
        response = build_response(
            query=b"",  # Would need original query
            data=data,
            domain=self.domain,
            rtype=query.type if query.type else 16,  # Default to TXT
        )

        return response

    def _handle_tun_data(self) -> None:
        """Handle data from TUN interface (to be sent to clients)."""
        if not self.state.tun_interface:
            return

        try:
            data = self.state.tun_interface.read(4096)
        except OSError:
            return

        if not data:
            return

        # In a real implementation, this would buffer data for each client
        # and include it in responses to their queries
        if self.debug:
            print(f"TUN data: {len(data)} bytes")

    def stop(self) -> None:
        """Stop the server and clean up resources."""
        print("Stopping server...")
        self.state.running = False

        if self.state.dns_socket_v4:
            close_dns_socket(self.state.dns_socket_v4)
            self.state.dns_socket_v4 = None

        if self.state.dns_socket_v6:
            close_dns_socket(self.state.dns_socket_v6)
            self.state.dns_socket_v6 = None

        if self.state.tun_interface:
            self.state.tun_interface.close()
            self.state.tun_interface = None

        print("Server stopped")

    def get_stats(self) -> dict:
        """Get server statistics.

        Returns:
            Dictionary with statistics.
        """
        with self._lock:
            return {
                "total_queries": self.state.total_queries,
                "total_responses": self.state.total_responses,
                "active_users": len(self.state.users),
                "users": {
                    uid: {
                        "addr": str(s.addr),
                        "encoding": s.encoding,
                        "bytes_sent": s.bytes_sent,
                        "bytes_received": s.bytes_received,
                        "packets_sent": s.packets_sent,
                        "packets_received": s.packets_received,
                    }
                    for uid, s in self.state.users.items()
                },
            }
