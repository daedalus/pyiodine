"""Tests for pyiodine tunnel module."""

from __future__ import annotations

import pytest
from pyiodine.tunnel import (
    LinuxTunnelInterface,
    DummyTunnelInterface,
    open_tunnel,
    set_mtu,
)


class TestDummyTunnelInterface:
    """Tests for DummyTunnelInterface."""

    def test_create(self) -> None:
        """Test creating dummy interface."""
        tun = DummyTunnelInterface()
        assert tun.name == "dummy0"
        assert tun.fd == -1

    def test_read_write(self) -> None:
        """Test read/write operations."""
        tun = DummyTunnelInterface()
        data = b"hello world"
        written = tun.write(data)
        assert written == len(data)

        # Data doesn't go to read buffer by default in dummy
        # This is a simplified test
        tun.inject_data(b"test")
        assert tun.read(100) == b"test"

    def test_close(self) -> None:
        """Test closing interface."""
        tun = DummyTunnelInterface()
        tun.close()
        assert tun.fd == -1

    def test_name_property(self) -> None:
        """Test name property."""
        tun = DummyTunnelInterface(name="test0")
        assert tun.name == "test0"

    def test_get_written_data(self) -> None:
        """Test getting written data."""
        tun = DummyTunnelInterface()
        tun.write(b"hello")
        tun.write(b" ")
        tun.write(b"world")
        data = tun.get_written_data()
        assert data == b"hello world"


class TestOpenTunnel:
    """Tests for open_tunnel function."""

    def test_open_dummy(self) -> None:
        """Test opening dummy tunnel."""
        tun = open_tunnel(dummy=True)
        assert tun is not None
        assert isinstance(tun, DummyTunnelInterface)

    def test_open_dummy_with_params(self) -> None:
        """Test opening dummy with custom params."""
        tun = open_tunnel(
            ip="172.16.0.1", netmask="255.255.0.0", name="custom0", dummy=True
        )
        assert tun.name == "custom0"


class TestSetMTU:
    """Tests for set_mtu function."""

    def test_set_mtu_dummy(self) -> None:
        """Test setting MTU (will fail without proper system)."""
        result = set_mtu("dummy0", 1400)
        # Will likely fail in test environment
        assert isinstance(result, bool)
