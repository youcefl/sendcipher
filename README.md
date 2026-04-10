# SendCipher

**End-to-end encrypted file sharing from the command line.**

Store files in the cloud, generate share links, and download on demand. Your files are encrypted before they ever leave your machine. The server sees only encrypted blobs.

## Quick Start

### To upload a file
```bash

# Set provided token
export SENDCIPHER_TOKEN="your-token-here"

# Upload a file
sendcipher upload --threads 4 --server https://sendcipher.com --password_file ~/password.txt confidential.pdf

```

### To download a file
```bash
# Download using the share ID
sendcipher download --threads 4 --server https://sendcipher.com --password_file ~/password.txt xYZkQ8w3Nt5R9mF2
```

