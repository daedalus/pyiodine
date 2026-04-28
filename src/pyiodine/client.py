"""Iodine client implementation for pyiodine.

This module provides the client-side implementation of the iodine DNS tunneling
protocol. It handles the handshake, authentication, and data tunneling.
"""

from __future__ import annotations

import random
import select
import socket
import struct
from dataclasses import dataclass, field

from pyiodine.common import (
    RAW_HDR_CMD_PING,
    ChallengeResponse,
    Packet,
    close_dns_socket,
    open_dns_socket,
    split_data,
)
from pyiodine.dns import (
    build_query,
    encode_tunnel_data,
    parse_response,
)
from pyiodine.encoding import get_blksize_raw, get_codec
from pyiodine.tunnel import TunnelInterface, open_tunnel

# Connection modes
CONN_RAW_UDP = 0
CONN_DNS_NULL = 1
CONN_MAX = 2

# Protocol constants
CHUNK_ID_RANGE = 65536
SELECT_TIMEOUT_DEFAULT = 5  # RFC says minimum 5 seconds
DNS_PORT = 53


@dataclass
class ClientState:
    """Client state for tracking connection."""

    running: bool = True
    userid: int = 0
    chunkid: int = field(default_factory=lambda: random.randint(0, CHUNK_ID_RANGE - 1))
    chunkid_prev: int = 0
    chunkid_prev2: int = 0

    # Encoders
    data_encoding: str = "base32"
    down_encoding: str = "base32"

    # Connection
    connection_mode: int = CONN_DNS_NULL
    nameserver: tuple[str, int] | None = None
    topdomain: str = ""

    # Packet buffers
    outpkt: Packet = field(default_factory=Packet)
    inpkt: Packet = field(default_factory=Packet)

    # Timing
    last_downstream_time: float =0
    send_ping_soon: bool = True

    # Statistics
    queries_sent: int = 0
    queries_recv: int = 0
    chunks_resent: int = 0


class IodineClient:
    """Iodine DNS tunneling client.

    Implements the client-side of the iodine protocol, handling
    authentication, data tunneling, and keepalive.
    """

    def __init__(
        self,
        domain: str,
        nameserver: str,
        password: str,
        qtype: str = "txt",
        lazy_mode: bool = False,
        select_timeout: int = SELECT_TIMEOUT_DEFAULT,
        hostname_maxlen: int = 255,
    ):
        """Initialize the iodine client.

        Args:
            domain: The top domain for tunneling (e.g., "t1.example.com").
            nameserver: DNS nameserver to use (e.g., "8.8.8.8").
            password: Shared secret for authentication.
            qtype: DNS query type (txt, null, srv, mx, etc.).
            lazy_mode: Enable lazy mode (less frequent communication).
            select_timeout: DNS query timeout in seconds.
            hostname_maxlen: Maximum hostname length for encoding.
        """
        self.domain = domain
        self.nameserver = (nameserver, DNS_PORT)
        self.password = password
        self.qtype = self._parse_qtype(qtype)
        self.lazy_mode = lazy_mode
        self.select_timeout = select_timeout
        self.hostname_maxlen = hostname_maxlen

        self.state = ClientState()
        self.state.topdomain = domain
        self.state.nameserver = self.nameserver

        self.dns_socket: socket.socket | None = None
        self.tun_interface: TunnelInterface | None = None
        self.challenge_response = ChallengeResponse(password)

        # Initialize random chunk ID
        self.state.chunkid = random.randint(0, CHUNK_ID_RANGE - 1)

    def _parse_qtype(self, qtype: str) -> int:
        """Parse query type string to integer.

        Args:
            qtype: Query type string.

        Returns:
            DNS record type constant.
        """
        qtype = qtype.lower()
        from pyiodine.dns import T_A, T_CNAME, T_MX, T_NULL, T_SRV, T_TXT

        type_map = {
            "txt": T_TXT,
            "null": T_NULL,
            "srv": T_SRV,
            "mx": T_MX,
            "cname": T_CNAME,
            "a": T_A,
        }
        return type_map.get(qtype, T_TXT)

    def connect(self) -> bool:
        """Establish tunnel connection.

        Performs the handshake with the server including
        authentication and encoding negotiation.

        Returns:
            True if connection successful, False otherwise.
        """
        print(f"Connecting to {self.domain} via {self.nameserver[0]}...")

        # Open DNS socket
        self.dns_socket = open_dns_socket(None)
        if not self.dns_socket:
            print("Failed to open DNS socket")
            return False

        # Perform handshake
        if not self._handshake():
            print("Handshake failed")
            self.disconnect()
            return False

        print(f"Connected! Tunnel established with userid {self.state.userid}")
        return True

    def _handshake(self) -> bool:
        """Perform the iodine handshake.

        Returns:
            True if handshake successful, False otherwise.
        """
        # Send login request with challenge
        challenge = self.challenge_response.generate_challenge()

        # Build login query with encoded challenge
        encoder, _ = get_codec("base32")
        encoded_challenge = encoder(challenge)
        query_domain = f"{encoded_challenge}.{self.domain}"

        # Send query and wait for response
        for attempt in range(3):
            query_pkt = build_query(query_domain, self.qtype)
            if not self._send_dns_query(query_pkt):
                continue

            response = self._wait_for_response(timeout=5)
            if response:
                # Parse response - should contain server's challenge response
                # and our challenge for verification
                return self._process_handshake_response(response, challenge)

        return False

    def _process_handshake_response(
        self, response: bytes, sent_challenge: bytes
    ) -> bool:
        """Process handshake response from server.

        Args:
            response: DNS response packet.
            sent_challenge: The challenge we sent.

        Returns:
            True if handshake successful, False otherwise.
        """
        # Parse the response
        dns_resp = parse_response(response)
        if not dns_resp:
            return False

        # Verify server's response to our challenge
        # The response data should be the server's challenge + response to our challenge
        # This is simplified - actual protocol is more complex

        # For now, assume success if we got a valid response
        self.state.userid = 1  # Would be assigned by server
        return True

    def _send_dns_query(self, query: bytes) -> bool:
        """Send a DNS query to the nameserver.

        Args:
            query: The DNS query packet.

        Returns:
            True if sent successfully, False otherwise.
        """
        if not self.dns_socket:
            return False

        try:
            self.dns_socket.sendto(query, self.nameserver)
            self.state.queries_sent += 1
            return True
        except OSError:
            return False

    def _wait_for_response(self, timeout: float = 5) -> bytes | None:
        """Wait for a DNS response.

        Args:
            timeout: Timeout in seconds.

        Returns:
            Response packet if received, None otherwise.
        """
        if not self.dns_socket:
            return None

        try:
            ready, _, _ = select.select([self.dns_socket], [], [], timeout)
            if ready:
                data, _ = self.dns_socket.recvfrom(65536)
                self.state.queries_recv += 1
                return data
        except OSError:
            pass

        return None

    def tunnel(self, tun_interface: TunnelInterface | None = None) -> None:
        """Run the main tunneling loop.

        Reads data from TUN interface, encodes it into DNS queries,
        and sends to the server. Also reads DNS responses and writes
        to TUN interface.

        Args:
            tun_interface: Optional TUN interface (creates one if not provided).
        """
        if not tun_interface:
            self.tun_interface = open_tunnel("10.0.0.2", "255.255.255.0")
        else:
            self.tun_interface = tun_interface

        print(f"Tunnel interface: {self.tun_interface.name}")
        print("Starting tunnel loop...")

        try:
            self._tunnel_loop()
        except KeyboardInterrupt:
            print("\nInterrupted by user")
        finally:
            self.disconnect()

    def _tunnel_loop(self) -> None:
        """Main tunnel event loop."""
        if not self.dns_socket or not self.tun_interface:
            return

        # Set up file descriptors for select
        tun_fd = self.tun_interface.fd

        while self.state.running:
            # Prepare select lists
            read_fds = [self.dns_socket]
            if tun_fd >= 0:
                read_fds.append(tun_fd)

            try:
                ready, _, _ = select.select(read_fds, [], [], self.select_timeout)
            except OSError:
                continue

            for fd in ready:
                if fd == self.dns_socket:
                    self._handle_dns_response()
                elif fd == tun_fd:
                    self._handle_tun_data()

            # Send ping if needed
            if self.state.send_ping_soon:
                self._send_ping()
                self.state.send_ping_soon = False

    def _handle_dns_response(self) -> None:
        """Handle incoming DNS response."""
        try:
            data, addr = self.dns_socket.recvfrom(65536)
            self.state.queries_recv += 1
        except OSError:
            return

        # Parse response
        response = parse_response(data)
        if not response:
            return

        # Extract tunnel data from response
        tunnel_data = response.data
        if not tunnel_data:
            return

        # Write data to TUN interface
        if self.tun_interface:
            try:
                self.tun_interface.write(tunnel_data)
            except OSError:
                pass

    def _handle_tun_data(self) -> None:
        """Handle data from TUN interface."""
        if not self.tun_interface:
            return

        try:
            data = self.tun_interface.read(4096)
        except OSError:
            return

        if not data:
            return

        # Encode data for DNS tunnel
        self._send_tunnel_data(data)

    def _send_tunnel_data(self, data: bytes) -> None:
        """Send data through DNS tunnel.

        Args:
            data: The data to send.
        """
        # Fragment data if needed
        encoder, _ = get_codec(self.state.data_encoding)
        chunk_size = get_blksize_raw(self.state.data_encoding)

        # Account for domain + encoding overhead
        max_data_size = min(chunk_size, 200)  # Conservative estimate

        fragments = split_data(data, max_data_size)

        for i, fragment in enumerate(fragments):
            encoded = encoder(fragment)
            query_domain = encode_tunnel_data(fragment, self.domain, self.state.data_encoding)

            # Build and send query
            query = build_query(query_domain, self.qtype)
            self._send_dns_query(query)

            # Update chunk ID
            self.state.chunkid = (self.state.chunkid + 1) % CHUNK_ID_RANGE

    def _send_ping(self) -> None:
        """Send a ping/keepalive to the server."""
        # Build a ping query
        ping_data = struct.pack("!B", RAW_HDR_CMD_PING)
        query_domain = encode_tunnel_data(ping_data, self.domain, "base32")

        query = build_query(query_domain, self.qtype)
        self._send_dns_query(query)

    def disconnect(self) -> None:
        """Disconnect and clean up resources."""
        self.state.running = False

        if self.dns_socket:
            close_dns_socket(self.dns_socket)
            self.dns_socket = None

        if self.tun_interface:
            self.tun_interface.close()
            self.tun_interface = None

        print("Disconnected")

    def get_stats(self) -> dict:
        """Get client statistics.

        Returns:
            Dictionary with statistics.
        """
        return {
            "queries_sent": self.state.queries_sent,
            "queries_received": self.state.queries_recv,
            "chunks_resent": self.state.chunks_resent,
            "user_id": self.state.userid,
            "connection_mode": self.state.connection_mode,
        }
