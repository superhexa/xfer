# XFER – Secure Encrypted File Transfer (CLI)

[![Language: C](https://img.shields.io/badge/language-C-00599C?logo=c)](https://en.wikipedia.org/wiki/C_(programming_language))
[![Crypto: OpenSSL](https://img.shields.io/badge/crypto-OpenSSL-721412?logo=openssl)](https://www.openssl.org/)
[![Compression: zlib](https://img.shields.io/badge/compression-zlib-199900)](https://zlib.net/)
[![OS: Linux](https://img.shields.io/badge/OS-Linux-1793D1?logo=linux)](https://kernel.org)

<img width="1366" height="768" alt="2025-08-14-192353_hyprshot" src="https://github.com/user-attachments/assets/00600073-fb87-46c7-aef5-f7ba791ffd31" />

XFER (aka SecureXfer) is a modern, end‑to‑end encrypted command‑line file transfer tool. It feels familiar like scp, but adds a beautiful UX, tunable runtime, metadata preservation, compression, integrity hooks, and a custom protocol designed for streaming performance.

- Fast and reliable transfers over TCP
- End‑to‑end authenticated encryption (AEAD)
- Great CLI UX: colorful output, structured help, command banners, TAB‑completion
- Tunable on the fly: cipher, compression, chunk, streams, timeouts, retries, throttling, and more

---

## Table of Contents
- What is it?
- Why XFER?
- Features
- Quickstart
- Installation
- Commands Overview
- Protocol Overview
- Security Model
- Configuration & Runtime Tuning
- Directory Layout
- Roadmap
- Troubleshooting
- FAQ
- Contributing
- License

---

## What is it?
XFER is a secure file transfer CLI that runs in two modes:
- Client: send to a listening peer
- Server: receive files into an output directory

It uses a custom, compact binary protocol over TCP to exchange metadata and encrypted data frames. A colorful CLI wraps everything with professional messages and minimal friction.

## Why XFER?
- End‑to‑end encryption by default
- Friendly CLI with professional, readable output
- Easy runtime controls without editing config files
- Lightweight single binary, fast build, zero daemons

## Features
- Transport: TCP
- Protocol: Custom XFER binary framing with CRC for headers
- Key exchange: X25519 for shared secret establishment
- AEAD ciphers: AES‑256‑GCM (default), ChaCha20‑Poly1305 (optional)
- Hashing: SHA‑256 (session/auth), XOR8 utility hash
- Compression: zlib/deflate per‑block (runtime toggle + level)
- Auth: Pre‑shared token (SHA‑256) for lightweight access control
- Resume: offset‑based send (stub), planned negotiation extensions
- Parallel: scaffolding for multi‑stream sends
- Integrity: scaffolding for end‑to‑end hash verification
- Metadata: mode and mtime preservation, overwrite policy
- UX: colorful logs, banners, sections; TAB completion for commands

## Quickstart
```
# Receiver (machine B)
$ ./build/SecureXfer
XFER » xfer serve 9090 /tmp/recv

# Sender (machine A)
$ ./build/SecureXfer
XFER » xfer send 10.0.0.2 9090 /path/to/file.iso
```
Optional tuning during a session:
```
XFER » loglevel info
XFER » compress on
XFER » zlevel 6
XFER » chunk 131072
XFER » streams 2
```

## Installation
### Requirements
- gcc/clang
- OpenSSL headers and libs (for AEAD/X25519)
- zlib

### Ubuntu/Debian
```
sudo apt update
sudo apt install -y build-essential libssl-dev zlib1g-dev
make
./build/SecureXfer
```

## Commands Overview
Type `help` inside the shell to see the full, sectioned help. Highlights:

- Core
  - `xfer send <host> <port> <file>`: send one file
  - `xfer recv <port> <outfile>`: receive one file
  - `xfer serve <port> <out_dir>`: start receiver/server

- Security & Auth
  - `encrypt <on|off>`: toggle AEAD
  - `cipher <aes|chacha>`: choose AEAD cipher
  - `auth <token>`: set pre‑shared token
  - `verify <on|off>`: toggle integrity hooks (WIP)

- Performance & Tuning
  - `compress <on|off>`, `zlevel <0-9>`
  - `chunk <bytes>`
  - `throttle <kbps>`
  - `streams <n>` (scaffolding)
  - `progress <mode>`
  - `timeout <ms>`, `ctmo <ms>`, `retries <n>`, `keepalive <on|off>`

- Filesystem
  - `overwrite <skip|ask|force>`
  - `preserve <mode|mtime|all|none>`
  - `sendr <host> <port> <dir>`: flat directory
  - `sendg <host> <port> <pattern>`: globbing
  - `stat <file>`, `ls [dir]`, `du [path]`

- Utilities
  - `cfg`: print current runtime config
  - `hash <file>`: XOR8 quick hash
  - `ping <host> <port>`: TCP reachability
  - `loglevel <debug|info|warn|error|fatal|n>`
  - `version`, `help`, `exit`

## Protocol Overview
XFER runs over TCP and frames messages with a compact header:
- Header: magic, version, type, seq, payload_len, flags, hdr_crc
- Types: HANDSHAKE, KEYEX, META, DATA, ACK, ERR, CTRL
- Crypto: X25519 key exchange, then AES‑GCM or ChaCha20‑Poly1305 per packet
- Compression: optional zlib for data frames
- Integrity: planned end‑to‑end verification (scaffolding present)

## Security Model
- E2E encryption with AEAD protects confidentiality and authenticity
- X25519 for ephemeral key exchange
- Optional pre‑shared token (SHA‑256) prevents unauthorized peers
- Integrity and resume extensions are included as scaffolding; final protocol
  negotiations for partial verification and full E2E hashes are on the roadmap

## Configuration & Runtime Tuning
All toggles are in‑memory (no external config files). Key controls:
- Encryption: `encrypt on|off`, `cipher aes|chacha`
- Compression: `compress on|off`, `zlevel 0..9`
- Networking: `timeout`, `ctmo`, `retries`, `keepalive`
- Performance: `chunk`, `streams`, `throttle`, `progress`
- Filesystem: `preserve`, `overwrite`
- Auth & Integrity: `auth`, `verify`
- Verbosity: `loglevel` (colored logs with professional banners)

## Directory Layout
```
include/
  core/    # protocol, transfer, crypto, handshake, runtime, etc.
  utils/   # buffer, file I/O, net utils, timer, logger
  cli/     # CLI-facing headers
src/
  core/    # protocol, crypto, handshake, transfer, integrity, runtime, ...
  utils/   # buffer, net, timer, file I/O
  cli/     # shell, parser, UI, command modules (core/security/perf/fs/util)
build/
  SecureXfer  # compiled binary
```

## Roadmap
- True multi‑socket parallel streams for large files and many cores
- Robust resume protocol with negotiated offsets and partial hashes
- End‑to‑end integrity verification with control packets
- Rich progress modes and throughput estimation
- Deeper ACL/ownership preservation (beyond mode/mtime)

## Troubleshooting
- “No rule to make target include/…” after pulling: run `make clean` or delete `build/` then `make`.
- OpenSSL/zlib not found: install `libssl-dev` and `zlib1g-dev` (Debian/Ubuntu).
- Connection refused: verify server side is running (`xfer serve`), correct host/port, and firewall.
- Too quiet or too noisy: adjust `loglevel`.

## FAQ
- What protocol is used?
  - Custom XFER binary protocol over TCP with AEAD and X25519
- What’s the idea?
  - A secure, fast, and user‑friendly CLI for file transfer
- Which cryptographic primitives?
  - X25519, AES‑256‑GCM, ChaCha20‑Poly1305, SHA‑256; zlib for compression

## Contributing
Contributions are welcome. Please:
- Keep code readable and modular (small focused files)
- Avoid comments that duplicate code intent; prefer clear naming
- Keep builds green and add tests where practical

## License
Choose and add a license for your distribution (e.g., MIT/Apache‑2.0). If you are unsure, please consult the repository owner.
