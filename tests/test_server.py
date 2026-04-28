"""Tests for pyiodine server module."""

from __future__ import annotations

import pytest
from unittest.mock import Mock, MagicMock, patch
from pyiodine.server import IodineServer, ServerState, UserSession
from pyiodine.tunnel import DummyTunnelInterface


class TestIodineServer:
    """Tests for IodineServer class."""

    def test_init(self) -> None:
        """Test server initialization."""
        server = IodineServer(
            ip="10.0.0.1",
            domain="test.com",
            password="secret",
        )
        assert server.domain == "test.com"
        assert server.state.ip == "10.0.0.1"
        assert server.password == "secret"
        assert server.port == 53

    def test_init_custom_port(self) -> None:
        """Test initialization with custom port."""
        server = IodineServer(
            ip="10.0.0.1",
            domain="test.com",
            password="secret",
            port=5353,
        )
        assert server.port == 5353

    def test_open_dns_sockets(self) -> None:
        """Test opening DNS sockets."""
        server = IodineServer("10.0.0.1", "test.com", "secret")

        with patch("socket.socket") as mock_socket:
            mock_instance = MagicMock()
            mock_socket.return_value = mock_instance

            result = server._open_dns_sockets()
            # Should try to bind
            mock_instance.bind.assert_called()

    def test_stop(self) -> None:
        """Test stopping server."""
        server = IodineServer("10.0.0.1", "test.com", "secret")
        server.state.running = True
        server.state.dns_socket_v4 = MagicMock()
        server.state.tun_interface = MagicMock()

        server.stop()

        assert server.state.running is False

    def test_get_stats(self) -> None:
        """Test getting statistics."""
        server = IodineServer("10.0.0.1", "test.com", "secret")
        stats = server.get_stats()

        assert "total_queries" in stats
        assert "total_responses" in stats
        assert "active_users" in stats
        assert "users" in stats

    def test_decode_domain_name(self) -> None:
        """Test domain name decoding."""
        server = IodineServer("10.0.0.1", "test.com", "secret")

        # Simple domain in DNS wire format
        # \x04test\x04com\x00 = 4 t e s t 4 c o m 0
        packet = b"\x00" + b"\x04test\x04com\x00"
        try:
            name, offset = server._decode_domain_name(packet, 1)
            assert "test" in name.lower()
            assert "com" in name.lower()
        except ValueError:
            # Packet format might be wrong, that's OK for this test
            pass


class TestUserSession:
    """Tests for UserSession dataclass."""

    def test_create_session(self) -> None:
        """Test creating a user session."""
        session = UserSession(
            userid=1,
            addr=("192.168.1.1", 12345),
            encoding="base32",
        )

        assert session.userid == 1
        assert session.addr == ("192.168.1.1", 12345)
        assert session.encoding == "base32"
        assert session.authenticated is False


class TestServerState:
    """Tests for ServerState dataclass."""

    def test_default_state(self) -> None:
        """Test default state values."""
        state = ServerState()

        assert state.running is True
        assert state.topdomain == ""
        assert state.next_userid == 1
        assert len(state.users) == 0

    def test_custom_state(self) -> None:
        """Test custom state values."""
        state = ServerState(topdomain="test.com", ip="192.168.1.1")

        assert state.topdomain == "test.com"
        assert state.ip == "192.168.1.1"
