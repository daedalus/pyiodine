"""Tunnel (TUN) interface handling for pyiodine.

This module provides TUN interface abstraction for creating and managing
network tunnels. Supports Linux native TUN and a dummy interface for testing.

Note: This implementation currently supports Linux. Windows and macOS
support require platform-specific extensions.
"""

from __future__ import annotations

import fcntl
import os
import struct
import subprocess
from abc import ABC, abstractmethod


class TunnelInterface(ABC):
    """Abstract base class for TUN interface.

    Provides a common interface for reading and writing to a TUN device.
    """

    @abstractmethod
    def read(self, size: int = 4096) -> bytes:
        """Read data from the tunnel.

        Args:
            size: Maximum number of bytes to read.

        Returns:
            The data read from the tunnel.
        """
        pass

    @abstractmethod
    def write(self, data: bytes) -> int:
        """Write data to the tunnel.

        Args:
            data: The data to write.

        Returns:
            Number of bytes written.
        """
        pass

    @abstractmethod
    def close(self) -> None:
        """Close the tunnel interface."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Get the interface name."""
        pass

    @property
    @abstractmethod
    def fd(self) -> int:
        """Get the file descriptor."""
        pass


class LinuxTunnelInterface(TunnelInterface):
    """Linux TUN interface implementation.

    Uses /dev/net/tun to create a virtual network interface.
    """

    # From linux/if_tun.h
    IFF_TUN = 0x0001
    IFF_NO_PI = 0x1000
    TUNSETIFF = 0x400454CA

    def __init__(self, name: str = "", ip: str = "10.0.0.1", netmask: str = "255.255.255.0"):
        """Initialize and open a TUN interface.

        Args:
            name: Desired interface name (empty for auto).
            ip: IP address to assign to the interface.
            netmask: Netmask for the interface.

        Raises:
            OSError: If TUN device cannot be opened or configured.
        """
        self._fd: int | None = None
        self._name: str = ""

        try:
            # Open TUN device
            tun_path = "/dev/net/tun"
            if not os.path.exists(tun_path):
                raise OSError(f"TUN device not found: {tun_path}")

            self._fd = os.open(tun_path, os.O_RDWR)

            # Prepare ifreq structure
            ifreq = struct.pack(
                "16sH",
                name.encode("ascii") if name else b"",
                self.IFF_TUN | self.IFF_NO_PI,
            )

            # Configure TUN device
            fcntl.ioctl(self._fd, self.TUNSETIFF, ifreq)

            # Get assigned interface name
            self._name = ifreq[:16].split(b"\x00")[0].decode("ascii")
            if not self._name:
                self._name = name if name else "tun0"

            # Set IP address and netmask
            self._set_ip(ip, netmask)
            self._set_up()

        except Exception as e:
            if self._fd is not None:
                os.close(self._fd)
            raise OSError(f"Failed to open TUN interface: {e}")

    def _set_ip(self, ip: str, netmask: str) -> None:
        """Set IP address and netmask on the interface.

        Args:
            ip: IP address.
            netmask: Network mask.

        Raises:
            subprocess.CalledProcessError: If ifconfig fails.
        """
        try:
            subprocess.run(
                ["ip", "addr", "add", f"{ip}/{netmask}", "dev", self._name],
                check=True,
                capture_output=True,
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            # Fallback to ifconfig
            subprocess.run(
                ["ifconfig", self._name, ip, "netmask", netmask],
                check=True,
                capture_output=True,
            )

    def _set_up(self) -> None:
        """Bring the interface up.

        Raises:
            subprocess.CalledProcessError: If ifconfig fails.
        """
        try:
            subprocess.run(
                ["ip", "link", "set", "dev", self._name, "up"],
                check=True,
                capture_output=True,
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            subprocess.run(
                ["ifconfig", self._name, "up"], check=True, capture_output=True
            )

    def read(self, size: int = 4096) -> bytes:
        """Read data from the TUN interface.

        Args:
            size: Maximum bytes to read.

        Returns:
            The data read.

        Raises:
            OSError: If read fails.
        """
        if self._fd is None:
            raise OSError("TUN interface not open")
        return os.read(self._fd, size)

    def write(self, data: bytes) -> int:
        """Write data to the TUN interface.

        Args:
            data: The data to write.

        Returns:
            Number of bytes written.

        Raises:
            OSError: If write fails.
        """
        if self._fd is None:
            raise OSError("TUN interface not open")
        return os.write(self._fd, data)

    def close(self) -> None:
        """Close the TUN interface."""
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    @property
    def name(self) -> str:
        """Get the interface name."""
        return self._name

    @property
    def fd(self) -> int:
        """Get the file descriptor."""
        if self._fd is None:
            raise OSError("TUN interface not open")
        return self._fd


class DummyTunnelInterface(TunnelInterface):
    """Dummy TUN interface for testing.

    Simulates a TUN interface using internal buffers.
    Useful for testing without root privileges or TUN support.
    """

    def __init__(self, name: str = "dummy0", ip: str = "10.0.0.1", netmask: str = "255.255.255.0"):
        """Initialize a dummy TUN interface.

        Args:
            name: Interface name for identification.
            ip: IP address (informational).
            netmask: Netmask (informational).
        """
        self._name = name
        self._ip = ip
        self._netmask = netmask
        self._read_buffer = bytearray()
        self._write_buffer = bytearray()
        self._closed = False

    def read(self, size: int = 4096) -> bytes:
        """Read data from the dummy interface.

        Args:
            size: Maximum bytes to read.

        Returns:
            The data read.
        """
        if self._closed:
            raise OSError("Dummy interface closed")

        data = bytes(self._read_buffer[:size])
        self._read_buffer = self._read_buffer[size:]
        return data

    def write(self, data: bytes) -> int:
        """Write data to the dummy interface.

        Args:
            data: The data to write.

        Returns:
            Number of bytes written.
        """
        if self._closed:
            raise OSError("Dummy interface closed")

        self._write_buffer.extend(data)
        return len(data)

    def inject_data(self, data: bytes) -> None:
        """Inject data into the read buffer (for testing).

        Args:
            data: Data to add to read buffer.
        """
        self._read_buffer.extend(data)

    def get_written_data(self) -> bytes:
        """Get and clear written data (for testing).

        Returns:
            Data that was written to the interface.
        """
        data = bytes(self._write_buffer)
        self._write_buffer.clear()
        return data

    def close(self) -> None:
        """Close the dummy interface."""
        self._closed = True

    @property
    def name(self) -> str:
        """Get the interface name."""
        return self._name

    @property
    def fd(self) -> int:
        """Get a dummy file descriptor (-1).

        Returns:
            -1 (invalid fd).
        """
        return -1


def open_tunnel(
    ip: str = "10.0.0.1",
    netmask: str = "255.255.255.0",
    name: str = "",
    dummy: bool = False,
) -> TunnelInterface:
    """Open or create a TUN interface.

    Args:
        ip: IP address to assign.
        netmask: Netmask to use.
        name: Desired interface name (empty for auto).
        dummy: If True, use dummy interface for testing.

    Returns:
        A TunnelInterface instance.

    Raises:
        OSError: If TUN interface cannot be created.
        RuntimeError: If platform is not supported.

    Example:
        >>> tun = open_tunnel("10.0.0.1", "255.255.255.0")
        >>> tun is not None
        True
    """
    if dummy:
        return DummyTunnelInterface(name if name else "dummy0", ip, netmask)

    # Detect platform and create appropriate interface
    import platform

    system = platform.system()

    if system == "Linux":
        return LinuxTunnelInterface(name, ip, netmask)
    else:
        # Fallback to dummy for unsupported platforms
        print(f"Warning: {system} not fully supported, using dummy interface")
        return DummyTunnelInterface(name if name else "dummy0", ip, netmask)


def set_mtu(name: str, mtu: int) -> bool:
    """Set MTU on a network interface.

    Args:
        name: Interface name.
        mtu: MTU value.

    Returns:
        True if successful, False otherwise.
    """
    try:
        subprocess.run(
            ["ip", "link", "set", "dev", name, "mtu", str(mtu)],
            check=True,
            capture_output=True,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        try:
            subprocess.run(
                ["ifconfig", name, "mtu", str(mtu)], check=True, capture_output=True
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
