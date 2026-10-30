# pykyber API Reference

## ML-KEM classes

### `ML_KEM_512`, `ML_KEM_768`, `ML_KEM_1024`

ML-KEM as specified in FIPS 203. Each parameter set has the same interface with its own key sizes. `ML_KEM_768` is the set NIST recommends as the default (FIPS 203, section 8).

#### Class constants

| Constant | ML_KEM_512 | ML_KEM_768 | ML_KEM_1024 |
|----------|------------|------------|-------------|
| `PUBLIC_KEY_SIZE` | 800 | 1184 | 1568 |
| `SECRET_KEY_SIZE` | 1632 | 2400 | 3168 |
| `CIPHERTEXT_SIZE` | 768 | 1088 | 1568 |
| `SHARED_SECRET_SIZE` | 32 | 32 | 32 |
| `SEED_SIZE` | 64 | 64 | 64 |

`ALGORITHM` holds the name (`"ML-KEM-768"`).

#### `__new__(seed: Optional[bytes] = None) -> MlKemKeypair`

Generate a new keypair. Random keys come from the operating system's random generator. If `seed` is provided, it must be exactly 64 bytes, `d || z` in the notation of FIPS 203 (Algorithm 16), and the same seed always gives the same keys. The seed is as sensitive as the secret key.

```python
keypair = pykyber.ML_KEM_768()
keypair = pykyber.ML_KEM_768(seed=bytes(range(64)))
```

#### `encapsulate(public_key: bytes) -> MlKemEncapsulationResult` *(static)*

Encapsulate a shared secret using a public key without creating a keypair instance. The public key must pass the modulus check of FIPS 203 section 7.2.

```python
result = pykyber.ML_KEM_768.encapsulate(public_key)
```

#### `decapsulate(ciphertext: bytes, secret_key: bytes) -> bytes` *(static)*

Decapsulate a shared secret using ciphertext and secret key without a keypair instance. The secret key must pass the hash check of FIPS 203 section 7.3. A well-formed ciphertext that was not made for this key does not raise an error: the result is a different, pseudorandom secret (implicit rejection).

```python
ss = pykyber.ML_KEM_768.decapsulate(ciphertext, secret_key)
```

#### `from_keys(public_key: bytes, secret_key: bytes) -> MlKemKeypair` *(classmethod)*

Create a keypair object from existing key bytes. Only the sizes are checked here; the section 7.2 and 7.3 checks run when the keys are used.

```python
keypair = pykyber.ML_KEM_768.from_keys(pk, sk)
```

---

### `MlKemKeypair`

Returned by `ML_KEM_*()` instantiation and `from_keys()`.

#### Properties

- `algorithm`: name of the parameter set, for example `"ML-KEM-768"`
- `public_key`: raw public key bytes
- `secret_key`: raw secret key bytes
- `seed`: the 64-byte seed `d || z`, or `None` unless the keypair was generated from a seed (secret)
- `public_key_hex`: hex string
- `secret_key_hex`: hex string
- `public_key_b64`: base64 string
- `secret_key_b64`: base64 string

#### Methods

- `encapsulate() -> MlKemEncapsulationResult`: encapsulate using own public key
- `decapsulate(ciphertext: bytes) -> bytes`: decapsulate using own secret key
- `to_dict() -> dict`: `{"public_key": ..., "secret_key": ...}` (hex; the seed is not included)

#### Tuple unpacking

```python
public_key, secret_key = keypair  # __iter__ yields (pk, sk)
```

---

### `MlKemEncapsulationResult`

Returned by `encapsulate()` and static `ML_KEM_*.encapsulate()`.

#### Properties

- `algorithm`: name of the parameter set
- `ciphertext`: raw ciphertext bytes
- `shared_secret`: raw shared secret bytes (32 bytes)
- `ciphertext_hex`: hex string
- `shared_secret_hex`: hex string
- `ciphertext_b64`: base64 string
- `shared_secret_b64`: base64 string

#### Methods

- `to_dict() -> dict`: `{"ciphertext": ..., "shared_secret": ...}` (hex)

#### Tuple unpacking

```python
ciphertext, shared_secret = result  # __iter__ yields (ct, ss)
```

---

## Exceptions

### `KyberError`

Subclass of `Exception`, and the base class of every error pykyber raises on invalid input. The name predates ML-KEM and was kept so that existing `except pykyber.KyberError` blocks keep working.

Subclasses, all raised by the `ML_KEM_*` classes:

| Exception | Raised when |
|-----------|-------------|
| `InvalidInputError` | an argument has the wrong type or length (key, ciphertext, seed) |
| `InvalidEncapsulationKeyError` | the encapsulation key fails the modulus check of FIPS 203 section 7.2 |
| `InvalidDecapsulationKeyError` | the decapsulation key fails the hash check of FIPS 203 section 7.3 |
| `RandomnessError` | the operating system random generator fails |
| `DecapsulationError` | decapsulation fails |
| `AlgorithmMismatchError` | an object of another algorithm or parameter set is passed (also a `TypeError`) |

```python
try:
    pykyber.ML_KEM_768.encapsulate(b"too_short")
except pykyber.KyberError as e:
    print(e)
```

### `KyberDeprecationWarning`

Subclass of `DeprecationWarning`, emitted once per process on the first use of a deprecated `Kyber*` class. See [Kyber (deprecated)](#kyber-deprecated) below.

---

## Kyber (deprecated)

`Kyber512`, `Kyber768` and `Kyber1024` implement round-3 CRYSTALS-Kyber, not ML-KEM. They are deprecated in favor of `ML_KEM_512`, `ML_KEM_768` and `ML_KEM_1024`, and are kept so that existing code and data keep working: their output is byte-identical to pykyber 1.0.5. Nothing has been removed or renamed.

- The shared secrets, ciphertexts and keys of Kyber and ML-KEM are not interchangeable, even though the sizes are identical. Both sides of a connection must switch together.
- The first use of any Kyber entry point (constructor, `from_keys`, static `encapsulate` or `decapsulate`) emits one `KyberDeprecationWarning` per process. Importing pykyber does not warn, and `ML_KEM_*` never warns. Python hides `DeprecationWarning` unless it is attributed to `__main__`; run with `-W default::DeprecationWarning` to see it.
- The interface is the same as for ML-KEM, with `Keypair` and `EncapsulationResult` in place of `MlKemKeypair` and `MlKemEncapsulationResult`, no `seed` property, and an optional 64-byte `seed` argument for deterministic keys.
- The class constants have the same names and values as the ML-KEM table above, apart from `SEED_SIZE`.
- Low-level functions (private, kept for compatibility): `_generate_keypair`, `_encapsulate` and `_decapsulate` for Kyber-768, and `_keypair_{512,768,1024}`, `_encapsulate_{512,768,1024}` and `_decapsulate_{512,768,1024}`.

See the [migration guide](migration.md) for how to switch.
