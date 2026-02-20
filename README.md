# PyKyber

A Python library for Kyber post-quantum key encapsulation, implemented in Rust.

## Installation

```bash
pip install pykyber
```

Or for development:

```bash
pip install maturin
maturin develop
```

## Quick Start

```python
import pykyber

# Generate a keypair
keypair = pykyber.Kyber768KeyPair.generate()

# Encapsulate (create shared secret)
ciphertext, shared_secret = keypair.encapsulate()

# Decapsulate (recover shared secret)
shared_secret2 = keypair.decapsulate(ciphertext)

print(f"Shared secrets match: {shared_secret == shared_secret2}")
```

## API Reference

### Classes

#### Kyber768KeyPair, Kyber512KeyPair, Kyber1024KeyPair

Key pair classes with methods for encapsulation/decapsulation.

```python
# Generate a new keypair
keypair = pykyber.Kyber768KeyPair.generate()

# Or from existing keys
keypair = pykyber.Kyber768KeyPair.from_bytes(public_key, secret_key)

# Encapsulate - returns (ciphertext, shared_secret)
ciphertext, shared_secret = keypair.encapsulate()

# Decapsulate
shared_secret = keypair.decapsulate(ciphertext)
```

#### Kyber, Kyber512, Kyber768, Kyber1024

Module-level functions for each security level.

```python
# Generate keypair
public_key, secret_key = pykyber.Kyber.generate_keypair()

# Or for specific variant
public_key, secret_key = pykyber.Kyber512.generate_keypair()
public_key, secret_key = pykyber.Kyber768.generate_keypair()
public_key, secret_key = pykyber.Kyber1024.generate_keypair()

# Encapsulate
ciphertext, shared_secret = pykyber.Kyber.encapsulate(public_key)

# Decapsulate
shared_secret = pykyber.Kyber.decapsulate(ciphertext, secret_key)
```

### Functions

The raw functions are also available directly:

```python
import pykyber

# Generate keypair (Kyber768 by default)
public_key, secret_key = pykyber.generate_keypair()

# Or specific variants
public_key, secret_key = pykyber.keypair_512()
public_key, secret_key = pykyber.keypair_768()
public_key, secret_key = pykyber.keypair_1024()

# Encapsulate
ciphertext, shared_secret = pykyber.encapsulate(public_key)

# Decapsulate
shared_secret = pykyber.decapsulate(ciphertext, secret_key)
```

### Key Sizes

| Variant  | Public Key | Secret Key | Ciphertext | Shared Secret |
|----------|------------|------------|------------|---------------|
| Kyber-512 | 800 bytes  | 1632 bytes | 768 bytes  | 32 bytes      |
| Kyber-768 | 1184 bytes | 2400 bytes | 1088 bytes | 32 bytes      |
| Kyber-1024 | 1568 bytes | 3168 bytes | 1568 bytes | 32 bytes      |

Note: Currently all variants use Kyber-768 implementation.

## Development

### Build

```bash
# Build Rust extension
cargo build

# Build Python package
maturin develop
```

### Tests

```bash
# Rust tests
cargo test

# Python tests
pytest python/pykyber/test_kyber.py -v
```

## License

MIT
