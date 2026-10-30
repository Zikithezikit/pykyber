# Migrating from Kyber to ML-KEM

pykyber 2.0 adds `ML_KEM_512`, `ML_KEM_768` and `ML_KEM_1024`, which implement ML-KEM as standardized in FIPS 203. `Kyber512`, `Kyber768` and `Kyber1024` implement round-3 CRYSTALS-Kyber, the draft that ML-KEM replaced. The Kyber classes still work and still produce exactly the output of pykyber 1.0.5, but they are deprecated. New code should use ML-KEM; NIST recommends ML-KEM-768 as the default parameter set (FIPS 203, section 8).

The two families look alike but cannot be mixed, and a few details are easy to get wrong.

## What changes

### Not interoperable

The two differ in how keys and secrets are derived: ML-KEM key generation hashes the parameter `k` into the seed, encapsulation does not pre-hash the message, and the shared secret does not depend on a hash of the ciphertext. A Kyber public key, secret key or ciphertext is not a valid input to ML-KEM in any meaningful way, and the other way round. Do not try to convert between them.

### Both sides must switch

A connection where one peer encapsulates with ML-KEM and the other decapsulates with Kyber (or the reverse) does not fail with an error. Decapsulation still returns 32 bytes, but they are not the secret the other peer holds, and whatever you derive from it will not match. Move both peers to the same family, and agree on the parameter set. If you cannot switch both at once, negotiate the algorithm in your protocol.

### The shared secret changes

Even for a fixed seed, ML-KEM and Kyber give different keys, ciphertexts and shared secrets. Anything derived from a Kyber shared secret (session keys, stored wrapped keys, signatures over transcripts) has to be redone, and long-lived Kyber keys have to be replaced with newly generated ML-KEM keys.

### Sizes are identical, so bytes cannot tell the two apart

Public key, secret key and ciphertext sizes are the same for each security level (800/1632/768 for 512, 1184/2400/1088 for 768, 1568/3168/1568 for 1024), and the shared secret is 32 bytes. A stored or transmitted key does not say which family it belongs to. Record the algorithm next to the key (a field name, a file name, a version byte in your protocol); do not guess from the length. Because this is easy to get wrong, pykyber tags its objects: an `ML_KEM_*` method given a `Kyber*` keypair or result raises `AlgorithmMismatchError`, and so does an `ML_KEM_768` method given an `ML_KEM_512` object. Raw `bytes` carry no tag, so this check cannot protect you if you pass bytes.

### The seed is 64 bytes, d || z

`ML_KEM_*(seed=...)` takes a 64-byte seed made of two 32-byte halves, `d` and `z` (FIPS 203, Algorithm 16), and the same seed always gives the same keys. A keypair generated from a seed exposes it as `keypair.seed`; a randomly generated keypair, or one loaded with `from_keys`, has `seed` set to `None`. The seed is as sensitive as the secret key, because it determines it. The Kyber classes also take a 64-byte seed, but a Kyber seed and an ML-KEM seed of the same bytes give unrelated keys.

## Code changes

The classes have the same shape, so most code changes only the class name, plus `keypair.seed` if you use seeds.

```python
import pykyber

# Before (deprecated, round-3 Kyber)
alice = pykyber.Kyber768()
result = pykyber.Kyber768.encapsulate(alice.public_key)
assert alice.decapsulate(result.ciphertext) == result.shared_secret

# After (ML-KEM, FIPS 203)
alice = pykyber.ML_KEM_768()
result = pykyber.ML_KEM_768.encapsulate(alice.public_key)
assert alice.decapsulate(result.ciphertext) == result.shared_secret
```

| Kyber | ML-KEM |
|-------|--------|
| `Kyber512` | `ML_KEM_512` |
| `Kyber768` | `ML_KEM_768` |
| `Kyber1024` | `ML_KEM_1024` |

The constants (`PUBLIC_KEY_SIZE`, `SECRET_KEY_SIZE`, `CIPHERTEXT_SIZE`, `SHARED_SECRET_SIZE`), the static `encapsulate`, `decapsulate` and `from_keys`, the hex, base64 and dict helpers and tuple unpacking all work the same way.

What is different besides the names:

- ML-KEM checks keys when they are used: an encapsulation key that fails the modulus check of FIPS 203 section 7.2 raises `InvalidEncapsulationKeyError`, and a decapsulation key that fails the hash check of section 7.3 raises `InvalidDecapsulationKeyError`. Both are subclasses of `KyberError`, so existing `except pykyber.KyberError` blocks still catch them.
- The new errors `InvalidInputError`, `RandomnessError`, `DecapsulationError` and `AlgorithmMismatchError` are also subclasses of `KyberError`.
- Static `decapsulate` takes `(ciphertext, secret_key)` in both families.

Mixing the families gives an error when the objects are tagged and silent garbage when they are raw bytes:

```python
import pykyber

kyber_keys = pykyber.Kyber768()
ml_kem_keys = pykyber.ML_KEM_768()

# The objects are tagged, so mixing them is caught.
try:
    pykyber.ML_KEM_768.encapsulate(kyber_keys)
except pykyber.AlgorithmMismatchError as e:
    print(type(e).__name__)

# Raw bytes are not tagged: this runs without an error and gives a secret
# that the holder of the Kyber secret key does not have.
result = pykyber.ML_KEM_768.encapsulate(kyber_keys.public_key)
print(kyber_keys.decapsulate(result.ciphertext) == result.shared_secret)  # False
```

## Seeing the deprecation warning

The first use of any Kyber entry point (the constructor, `from_keys`, static `encapsulate` or static `decapsulate`) emits one `KyberDeprecationWarning` per process. It is a subclass of `DeprecationWarning`, and Python hides `DeprecationWarning` by default unless the code that triggers it is in `__main__`. A call made from inside a library or from a test runner is therefore silent unless you ask for it:

```bash
python -W default::DeprecationWarning your_script.py
```

or, inside Python, `warnings.simplefilter("default", pykyber.KyberDeprecationWarning)`. To find every remaining use, make it an error with `warnings.simplefilter("error", pykyber.KyberDeprecationWarning)`. Importing pykyber does not warn, and `ML_KEM_*` never warns.

## Checklist

1. Choose the parameter set (`ML_KEM_768` unless you have a reason to differ).
2. Change both peers, or add algorithm negotiation to your protocol.
3. Generate new ML-KEM keys; do not reuse Kyber keys or seeds.
4. Re-derive everything that was derived from a Kyber shared secret.
5. Store the algorithm name next to every key and ciphertext.
6. Treat `keypair.seed` like the secret key.
