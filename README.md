![MSRV](https://img.shields.io/badge/rustc-1.85+-blue.svg)

# SendCipher

**End-to-end encrypted file sharing from the command line.**

Store files in the cloud, generate share links, and download on demand. Your files are encrypted before they ever leave your machine. The server sees only encrypted blobs.

## Quick Start

### Installation
```bash
# (Rust 1.85+ required, `rustup update` if needed)
cargo install sendcipher
```

### To upload a file
```bash

# Set provided token
export SENDCIPHER_TOKEN="your-token-here"

# Upload a file
sendcipher upload --threads 4 confidential.pdf

```

### To download a file

Use the command line:
```bash
# Download using the share ID
sendcipher download --threads 4 <Some Share Id>
```
or visit `https://sendcipher.com/d/<some share ID>`

## Features
- **End-to-end encrypted** - Your files are encrypted before they leave your machine
- **Store in the cloud** - Upload once, files persist until they expire
- **Share links** - Generate links that work anytime, even weeks later
- **Multi-threaded transfers** - Maximize your bandwidth
- **Expiration dates** - Set how long your files live (default 7 days)
- **Web interface** - Download via browser without the CLI

## Architecture
- sendcipher - command line interface
- sendcipher-core - crypto protocol and file chunking
- [sendcipher-common](https://github.com/youcefl/sendcipher-common) - shared types (public API)

## Links
 - [Website](https://sendcipher.com)

