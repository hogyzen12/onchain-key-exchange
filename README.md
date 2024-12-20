# Onchain Key Exchange

A secure tool for encrypting and sharing Solana keypairs using X25519 key exchange and AES-GCM encryption.

## Overview

This tool allows you to securely encrypt a Solana keypair file so that only a specific recipient (identified by their public key) can decrypt it. It uses:

- X25519 for key exchange
- AES-GCM for symmetric encryption
- HKDF for key derivation
- Secure memory wiping for sensitive data

## Installation

```bash
# Clone the repository
git clone https://github.com/hogyzen12/onchain-key-exchange
cd onchain-key-exchange

# Install dependencies
go mod tidy
```

## Usage

### Encrypting a Keypair

```bash
go run prod-onchain-key-exchange.go \
  -share /path/to/keypair/to/share.json \
  -recipient RECIPIENT_PUBLIC_KEY
```

Example:
```bash
go run prod-onchain-key-exchange.go \
  -share ~/.config/solana/my-keypair.json \
  -recipient rtrAfh7jLW92d5SqsibLQPRFS7DPEs5UraZR7B4Sd5i
```

The encrypted share will be saved as `encrypted_share.json` by default. You can specify a different output path using the `-output` flag.

### Testing Decryption

You can verify the encryption works correctly using the decryption test:

```bash
go run onchain-decryption-test.go \
  -correct /path/to/recipient/keypair.json \
  -wrong1 /path/to/wrong/keypair1.json \
  -wrong2 /path/to/wrong/keypair2.json
```

This will test that:
1. The correct recipient can decrypt the share
2. Other keypairs cannot decrypt the share

## Security Features

- Uses X25519 for secure key exchange
- Implements HKDF for key derivation
- Uses AES-GCM for authenticated encryption
- Secure memory wiping of sensitive data
- No plaintext keypair data written to disk

## Dependencies

- Go 1.18 or later
- `filippo.io/edwards25519`
- `golang.org/x/crypto`

## License

MIT License - See LICENSE file for details