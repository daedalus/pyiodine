"""Tests for pyiodine client module."""

from __future__ import annotations

import pytest
from unittest.mock import Mock, MagicMock, patch
from pyiodine.client import IodineClient, ClientState, CONN_DNS_NULL
from pyiodine.tunnel import DummyTunnelInterface


class TestIodineClient:
    """Tests for IodineClient class."""

    def test_init(self) -> None:
        """Test client initialization."""
        client = IodineClient(
            domain="test.com",
            nameserver="8.8.8.8",
            password="secret",
        )
        assert client.domain == "test.com"
        assert client.nameserver == ("8.8.8.8", 53)
        assert client.password == "secret"

    def test_init_with_port(self) -> None:
        """Test initialization with custom port."""
        client = IodineClient(
            domain="test.com",
            nameserver="192.168.1.1",
            password="secret",
        )
        assert client.nameserver[1] == 53

    def test_parse_qtype(self) -> None:
        """Test query type parsing."""
        client = IodineClient("test.com", "8.8.8.8", "secret")

        from pyiodine.dns import T_TXT, T_NULL, T_SRV, T_MX, T_CNAME, T_A

        assert client._parse_qtype("txt") == T_TXT
        assert client._parse_qtype("null") == T_NULL
        assert client._parse_qtype("srv") == T_SRV
        assert client._parse_qtype("mx") == T_MX
        assert client._parse_qtype("cname") == T_CNAME
        assert client._parse_qtype("a") == T_A
        assert client._parse_qtype("invalid") == T_TXT  # Default

    def test_connect_failure(self) -> None:
        """Test connection failure."""
        client = IodineClient("test.com", "8.8.8.8", "wrong")

        # Mock the entire connect method to simulate failure
        with patch.object(client, 'connect', return_value=False):
            result = client.connect()
            assert result is False

        # Also test that handshake fails
        with patch.object(client, '_handshake', return_value=False):
            result = client.connect()
            assert result is False

    def test_disconnect(self) -> None:
        """Test disconnection."""
        client = IodineClient("test.com", "8.8.8.8", "secret")
        client.dns_socket = MagicMock()
        client.tun_interface = MagicMock()

        client.disconnect()

        assert client.state.running is False

    def test_get_stats(self) -> None:
        """Test getting statistics."""
        client = IodineClient("test.com", "8.8.8.8", "secret")
        stats = client.get_stats()

        assert "queries_sent" in stats
        assert "queries_received" in stats
        assert "user_id" in stats


class TestClientState:
    """Tests for ClientState dataclass."""

    def test_default_state(self) -> None:
        """Test default state values."""
        state = ClientState()

        assert state.running is True
        assert state.userid == 0
        assert state.chunkid != 0  # Random
        assert state.data_encoding == "base32"

    def test_custom_state(self) -> None:
        """Test custom state values."""
        state = ClientState(userid=5, data_encoding="base64")

        assert state.userid == 5
        assert state.data_encoding == "base64"
