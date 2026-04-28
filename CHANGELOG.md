# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release of pyiodine
- DNS tunneling client implementation
- DNS tunneling server implementation
- Base32, Base64, and Base128 encoding support
- TUN interface support (Linux)
- CHAP-style authentication
- CLI entry points (pyiodine, pyiodined)

### TODO
- Complete handshake implementation
- Add full fragmentation support
- Implement raw UDP mode
- Add comprehensive error handling
- Complete test coverage (currently at ~30%)
- Add Windows TUN support
- Implement DNS forwarding for iodined

## [0.1.0] - 2026-04-28

### Added
- Initial release of pyiodine

[0.1.0]: https://github.com/daedalus/pyiodine/releases/tag/v0.1.0
