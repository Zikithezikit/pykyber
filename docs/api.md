# pykyber API Reference

## Classes

### `Kyber512`, `Kyber768`, `Kyber1024`

Each variant has the same interface with variant-specific key sizes.

#### Class constants

| Constant | Kyber512 | Kyber768 | Kyber1024 |
|----------|----------|----------|-----------|
| `PUBLIC_KEY_SIZE` | 800 | 1184 | 1568 |
| `SECRET_KEY_SIZE` | 1632 | 2400 | 3168 |
| `CIPHERTEXT_SIZE` | 768 | 1088 | 1568 |
| `SHARED_SECRET_SIZE` | 32 | 32 | 32 |

#### `__new__(seed: Optional[bytes] = None) -> Keypair`

Generate a new keypair. If `seed` is provided, it must be exactly 64 bytes for deterministic key generation.

```python
keypair = pykyber.Kyber768()
keypair = pykyber.Kyber768(seed=bytes(range(64)))
```

#### `encapsulate(public_key: bytes) -> EncapsulationResult` *(static)*

Encapsulate a shared secret using a public key without creating a keypair instance.

```python
result = pykyber.Kyber768.encapsulate(public_key)
```

#### `decapsulate(ciphertext: bytes, secret_key: bytes) -> bytes` *(static)*

Decapsulate a shared secret using ciphertext and secret key without a keypair instance.

```python
ss = pykyber.Kyber768.decapsulate(ciphertext, secret_key)
```

#### `from_keys(public_key: bytes, secret_key: bytes) -> Keypair` *(classmethod)*

Create a `Keypair` from existing key bytes.

```python
keypair = pykyber.Kyber768.from_keys(pk, sk)
```

---

### `Keypair`

Returned by `Kyber*()` instantiation and `from_keys()`.

#### Properties

- `public_key` — raw public key bytes
- `secret_key` — raw secret key bytes
- `public_key_hex` — hex string
- `secret_key_hex` — hex string
- `public_key_b64` — base64 string
- `secret_key_b64` — base64 string

#### Methods

- `encapsulate() -> EncapsulationResult` — encapsulate using own public key
- `decapsulate(ciphertext: bytes) -> bytes` — decapsulate using own secret key
- `to_dict() -> dict` — `{"public_key": ..., "secret_key": ...}` (hex)

#### Tuple unpacking

```python
public_key, secret_key = keypair  # __iter__ yields (pk, sk)
```

---

### `EncapsulationResult`

Returned by `encapsulate()` and static `Kyber*.encapsulate()`.

#### Properties

- `ciphertext` — raw ciphertext bytes
- `shared_secret` — raw shared secret bytes (32 bytes)
- `ciphertext_hex` — hex string
- `shared_secret_hex` — hex string
- `ciphertext_b64` — base64 string
- `shared_secret_b64` — base64 string

#### Methods

- `to_dict() -> dict` — `{"ciphertext": ..., "shared_secret": ...}` (hex)

#### Tuple unpacking

```python
ciphertext, shared_secret = result  # __iter__ yields (ct, ss)
```

---

## Exceptions

### `KyberError`

Subclass of `Exception`. Raised on:
- Invalid public key size
- Invalid ciphertext size
- Invalid secret key size
- Invalid seed size (not 64 bytes)

```python
try:
    pykyber.Kyber768.encapsulate(b"too_short")
except pykyber.KyberError as e:
    print(e)
```

---

## Low-level functions

These are variant-generic (Kyber-768):

| Function | Returns | Description |
|----------|---------|-------------|
| `_generate_keypair(seed)` | `(pk, sk)` | Kyber-768 keypair |
| `_encapsulate(pk)` | `(ct, ss)` | Kyber-768 encapsulate |
| `_decapsulate(ct, sk)` | `ss` | Kyber-768 decapsulate |

Variant-specific low-level functions:

| Function | Kyber-512 | Kyber-768 | Kyber-1024 |
|----------|-----------|-----------|------------|
| keypair | `_keypair_512(seed)` | `_keypair_768(seed)` | `_keypair_1024(seed)` |
| encapsulate | `_encapsulate_512(pk)` | `_encapsulate_768(pk)` | `_encapsulate_1024(pk)` |
| decapsulate | `_decapsulate_512(ct, sk)` | `_decapsulate_768(ct, sk)` | `_decapsulate_1024(ct, sk)` |
