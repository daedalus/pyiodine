"""Tests for pyiodine - conftest.py.

This file contains shared fixtures for the test suite.
"""

from __future__ import annotations

import pytest


@pytest.fixture
def sample_bytes() -> bytes:
    """Provide sample bytes for testing."""
    return b"hello world test data"


@pytest.fixture
def sample_domain() -> str:
    """Provide a sample domain for testing."""
    return "test.example.com"


@pytest.fixture
def mock_socket():
    """Create a mock socket for testing."""
    from unittest.mock import MagicMock

    return MagicMock()


@pytest.fixture
def client_instance():
    """Create a client instance for testing."""
    from pyiodine.client import IodineClient

    return IodineClient(
        domain="test.com",
        nameserver="8.8.8.8",
        password="test_password",
    )


@pytest.fixture
def server_instance():
    """Create a server instance for testing."""
    from pyiodine.server import IodineServer

    return IodineServer(
        ip="10.0.0.1",
        domain="test.com",
        password="test_password",
    )
