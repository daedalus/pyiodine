**pyiodine** — Python implementation of iodine DNS tunneling tool.

[![Python](https://img.shields.io/pypi/pyversions/pyiodine.svg)](https://pypi.org/project/pyiodine/)

## Description

Pyiondine is a Python translation of the [iodine](http://code.kryo.se/iodine) DNS tunneling tool. It allows tunneling IPv4 data through DNS servers, enabling network access in firewalled environments where only DNS queries are allowed.

This implementation maintains protocol compatibility with the original C version while providing a Pythonic API for integration into Python applications.

## Features

- DNS tunneling client and server implementations
- Multiple encoding schemes (Base32, Base64, Base128)
- TUN interface support (Linux)
- CHAP-style authentication
- Compatible with original iodine protocol
- Pure Python (with optional pytun for TUN support)

## Installation

```bash
pip install pyiodine
```

For TUN interface support on Linux:
```bash
pip install pyiodine[full]  # Includes pytun
```

## Quick Start

### Server Side

```bash
# Start server with tunnel IP and domain
pyiodined -f 10.0.0.1 t1.example.com
```

Enter a password when prompted.

### Client Side

```bash
# Connect to server via DNS
pyiodine -f 8.8.8.8 t1.example.com
```

Enter the same password as on the server.

## Usage Examples

### As a Python Library

```python
from pyiodine import IodineClient, IodineServer

# Create a client
client = IodineClient(
    domain="t1.example.com",
    nameserver="8.8.8.8",
    password="secret"
)

# Connect
client.connect()

# Run tunnel
client.tunnel()
```

### Using Different Encodings

```python
# Client with Base64 encoding
pyiodine -f -T base64 8.8.8.8 t1.example.com

# Server with Base128
pyiodined -f 10.0.0.1 t1.example.com  # Encoding negotiated during handshake
```

## Command Line Options

### Client (pyiodine)

```
pyiodine [options] <nameserver> <domain>
  -f, --foreground    Run in foreground
  -P, --password PASS  Password (not recommended, use prompt)
  -r, --relay         Use raw UDP relay mode
  -T, --type TYPE     DNS record type (txt, null, srv, mx, cname, a)
  -L, --lazy          Enable lazy mode
  -M, --mtu SIZE      Set MTU for tunnel
  -t, --timeout SEC   DNS query timeout
  -v, --verbose       Increase verbosity
```

### Server (pyiodined)

```
pyiodined [options] <ip> <domain>
  -f, --foreground    Run in foreground
  -P, --password PASS  Password (not recommended, use prompt)
  -p, --port PORT     DNS port to listen on
  -u, --user USER     Drop privileges to user
  -t, --mtu MTU       MTU for tunnel interface
  -d, --debug         Enable debug output
  -c, --chroot DIR    Chroot after startup
```

## Architecture

```
+----------------+     DNS Queries      +-----------------+
|  pyiodine      | <------------------> |  pyiodined     |
|  (Client)      |                      |  (Server)      |
|                |     DNS Responses    |                |
|  [TUN] -------| ------------------> | ------ [TUN]    |
+----------------+                      +-----------------+
    10.0.0.2                          10.0.0.1
```

## Protocol

The implementation uses the iodine protocol:
- Authentication: CHAP-style challenge/response
- Encodings: Base32 (default), Base64, Base128
- DNS Record Types: TXT (default), NULL, SRV, MX, CNAME
- Fragmentation: Automatic for large packets

## Development

```bash
git clone https://github.com/daedalus/pyiodine.git
cd pyiodine
pip install -e ".[test]"

# Run tests
pytest

# Format code
ruff format src/ tests/

# Lint
ruff check src/ tests/
prospector src/
semgrep --config=auto --severity=ERROR src/

# Type check
mypy src/
```

## Testing

```bash
# Run all tests with coverage
pytest --cov --cov-report=term-missing

# Run specific tests
pytest tests/test_encoding.py -v
```

## Limitations

- Windows TUN support requires external drivers
- Android not supported (use original C version)
- Systemd integration not included
- SELinux policies not included

## Requirements

- Python 3.11+
- dnspython (DNS handling)
- pytun (TUN interface on Linux, optional)

## License

MIT License - See LICENSE file for details.

## Acknowledgments

This is a Python translation of the original [iodine](http://code.kryo.se/iodine) project by Erik Ekman and Bjorn Andersson. All credit for the protocol design and original implementation goes to them.

## Troubleshooting

### "TUN device not found"
Install the required kernel modules and ensure `/dev/net/tun` exists.

### "Failed to connect"
- Verify the domain is properly delegated to your server
- Check that the server is running and accessible
- Ensure firewalls allow DNS traffic (UDP port 53)

### "Authentication failed"
Ensure you're using the same password on both client and server.
