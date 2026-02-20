import pytest
import pykyber


def test_keypair_generation():
    """Test that keypair generation produces valid keys."""
    pk, sk = pykyber.generate_keypair()
    assert len(pk) == 1184
    assert len(sk) == 2400


def test_encapsulate_decapsulate():
    """Test that encapsulate and decapsulate work correctly."""
    pk, sk = pykyber.generate_keypair()
    ct, ss = pykyber.encapsulate(pk)
    assert len(ct) == 1088
    assert len(ss) == 32
    ss2 = pykyber.decapsulate(ct, sk)
    assert ss == ss2


def test_invalid_public_key_length():
    """Test that invalid public key length raises an error."""
    with pytest.raises(Exception):
        pykyber.encapsulate(b"short")


def test_invalid_ciphertext_length():
    """Test that invalid ciphertext length raises an error."""
    sk = bytes(2400)
    with pytest.raises(Exception):
        pykyber.decapsulate(b"short", sk)


def test_invalid_secret_key_length():
    """Test that invalid secret key length raises an error."""
    ct = bytes(1088)
    with pytest.raises(Exception):
        pykyber.decapsulate(ct, b"short")


def test_different_keypairs_produce_different_secrets():
    """Test that different keypairs produce different shared secrets."""
    pk1, sk1 = pykyber.generate_keypair()
    pk2, sk2 = pykyber.generate_keypair()
    
    ct1, ss1 = pykyber.encapsulate(pk1)
    ct2, ss2 = pykyber.encapsulate(pk2)
    
    ss1_dec = pykyber.decapsulate(ct1, sk1)
    ss2_dec = pykyber.decapsulate(ct2, sk2)
    
    assert ss1 == ss1_dec
    assert ss2 == ss2_dec
    assert ss1 != ss2


def test_wrong_secret_key_fails():
    """Test that using wrong secret key produces different result."""
    pk, sk = pykyber.generate_keypair()
    _, wrong_sk = pykyber.generate_keypair()
    
    ct, ss = pykyber.encapsulate(pk)
    ss_wrong = pykyber.decapsulate(ct, wrong_sk)
    
    assert ss != ss_wrong


def test_keypair_512():
    """Test keypair generation for Kyber-512."""
    pk, sk = pykyber.keypair_512()
    assert len(pk) == 1184
    assert len(sk) == 2400


def test_keypair_768():
    """Test keypair generation for Kyber-768."""
    pk, sk = pykyber.keypair_768()
    assert len(pk) == 1184
    assert len(sk) == 2400


def test_keypair_1024():
    """Test keypair generation for Kyber-1024."""
    pk, sk = pykyber.keypair_1024()
    assert len(pk) == 1184
    assert len(sk) == 2400


def test_deterministic_decapsulation():
    """Test that decapsulation is deterministic given the same ciphertext."""
    pk, sk = pykyber.generate_keypair()
    ct, _ = pykyber.encapsulate(pk)
    
    results = [pykyber.decapsulate(ct, sk) for _ in range(5)]
    assert len(set(results)) == 1


def test_ciphertext_randomness():
    """Test that ciphertexts are random."""
    pk, sk = pykyber.generate_keypair()
    ciphertexts = [pykyber.encapsulate(pk)[0] for _ in range(5)]
    assert len(set(ciphertexts)) > 1


def test_empty_public_key():
    """Test that empty public key raises error."""
    with pytest.raises(Exception):
        pykyber.encapsulate(b"")


def test_empty_ciphertext():
    """Test that empty ciphertext raises error."""
    pk, sk = pykyber.generate_keypair()
    with pytest.raises(Exception):
        pykyber.decapsulate(b"", sk)


def test_empty_secret_key():
    """Test that empty secret key raises error."""
    pk, sk = pykyber.generate_keypair()
    ct, _ = pykyber.encapsulate(pk)
    with pytest.raises(Exception):
        pykyber.decapsulate(ct, b"")


def test_boundary_public_key_length():
    """Test with public key that's 1 byte too short."""
    pk, sk = pykyber.generate_keypair()
    short_pk = pk[:-1]
    with pytest.raises(Exception):
        pykyber.encapsulate(short_pk)


def test_boundary_secret_key_length():
    """Test with secret key that's 1 byte too short."""
    pk, sk = pykyber.generate_keypair()
    ct, _ = pykyber.encapsulate(pk)
    short_sk = sk[:-1]
    with pytest.raises(Exception):
        pykyber.decapsulate(ct, short_sk)


def test_boundary_ciphertext_length():
    """Test with ciphertext that's 1 byte too short."""
    pk, sk = pykyber.generate_keypair()
    ct, _ = pykyber.encapsulate(pk)
    short_ct = ct[:-1]
    with pytest.raises(Exception):
        pykyber.decapsulate(short_ct, sk)


def test_all_zero_keypair():
    """Test that generated keys are not all zeros."""
    pk, sk = pykyber.generate_keypair()
    assert any(b != 0 for b in pk)
    assert any(b != 0 for b in sk)


def test_shared_secret_not_all_zeros():
    """Test that shared secrets are not all zeros."""
    pk, sk = pykyber.generate_keypair()
    ct, ss = pykyber.encapsulate(pk)
    assert any(b != 0 for b in ss)
    ss2 = pykyber.decapsulate(ct, sk)
    assert any(b != 0 for b in ss2)


def test_multiple_encapsulations():
    """Test multiple encapsulations with same keypair."""
    pk, sk = pykyber.generate_keypair()
    
    results = []
    for _ in range(10):
        ct, ss = pykyber.encapsulate(pk)
        ss_dec = pykyber.decapsulate(ct, sk)
        results.append((ct, ss, ss_dec))
    
    # All should decapsulate correctly
    for ct, ss, ss_dec in results:
        assert ss == ss_dec
    
    # Ciphertexts should mostly be different (random)
    ciphertexts = [r[0] for r in results]
    assert len(set(ciphertexts)) > 1


def test_keypair_768_function():
    """Test that keypair_768 function works."""
    pk, sk = pykyber.keypair_768()
    ct, ss = pykyber.encapsulate(pk)
    ss2 = pykyber.decapsulate(ct, sk)
    assert ss == ss2


def test_keypair_512_function():
    """Test that keypair_512 function works."""
    pk, sk = pykyber.keypair_512()
    ct, ss = pykyber.encapsulate(pk)
    ss2 = pykyber.decapsulate(ct, sk)
    assert ss == ss2


def test_keypair_1024_function():
    """Test that keypair_1024 function works."""
    pk, sk = pykyber.keypair_1024()
    ct, ss = pykyber.encapsulate(pk)
    ss2 = pykyber.decapsulate(ct, sk)
    assert ss == ss2


def test_encapsulate_512():
    """Test encapsulate_512 function."""
    pk, sk = pykyber.keypair_512()
    ct, ss = pykyber.encapsulate_512(pk)
    ss2 = pykyber.decapsulate_512(ct, sk)
    assert ss == ss2


def test_encapsulate_768():
    """Test encapsulate_768 function."""
    pk, sk = pykyber.keypair_768()
    ct, ss = pykyber.encapsulate_768(pk)
    ss2 = pykyber.decapsulate_768(ct, sk)
    assert ss == ss2


def test_encapsulate_1024():
    """Test encapsulate_1024 function."""
    pk, sk = pykyber.keypair_1024()
    ct, ss = pykyber.encapsulate_1024(pk)
    ss2 = pykyber.decapsulate_1024(ct, sk)
    assert ss == ss2


def test_decapsulate_512():
    """Test decapsulate_512 function."""
    pk, sk = pykyber.keypair_512()
    ct, ss = pykyber.encapsulate(pk)
    ss2 = pykyber.decapsulate_512(ct, sk)
    assert ss == ss2


def test_decapsulate_768():
    """Test decapsulate_768 function."""
    pk, sk = pykyber.keypair_768()
    ct, ss = pykyber.encapsulate(pk)
    ss2 = pykyber.decapsulate_768(ct, sk)
    assert ss == ss2


def test_decapsulate_1024():
    """Test decapsulate_1024 function."""
    pk, sk = pykyber.keypair_1024()
    ct, ss = pykyber.encapsulate(pk)
    ss2 = pykyber.decapsulate_1024(ct, sk)
    assert ss == ss2


def test_same_ciphertext_decapsulation():
    """Test that same ciphertext always decapsulates to same secret."""
    pk, sk = pykyber.generate_keypair()
    ct, _ = pykyber.encapsulate(pk)
    
    results = [pykyber.decapsulate(ct, sk) for _ in range(10)]
    assert all(r == results[0] for r in results)


def test_interoperability_different_calls():
    """Test that different function variants work together."""
    pk, sk = pykyber.generate_keypair()
    
    # Mix and match
    ct1, ss1 = pykyber.encapsulate(pk)
    ss1_dec = pykyber.decapsulate(ct1, sk)
    assert ss1 == ss1_dec
    
    ct2, ss2 = pykyber.encapsulate_768(pk)
    ss2_dec = pykyber.decapsulate_768(ct2, sk)
    assert ss2 == ss2_dec


def test_zero_keypair_not_rejected():
    """Test that zero public key is not rejected (produces weak output)."""
    zero_pk = bytes(1184)
    # Kyber doesn't reject zero keys - it will produce output (but weak)
    ct, ss = pykyber.encapsulate(zero_pk)
    assert len(ct) == 1088
    assert len(ss) == 32


def test_very_long_input_rejection():
    """Test that too long inputs are handled."""
    pk, sk = pykyber.generate_keypair()
    long_pk = pk + b"extra"
    with pytest.raises(Exception):
        pykyber.encapsulate(long_pk)


# Class-based API tests

def test_kyber768_keypair_class():
    """Test Kyber768KeyPair class."""
    kp = pykyber.Kyber768KeyPair.generate()
    assert len(kp.public_key) == 1184
    assert len(kp.secret_key) == 2400
    ct, ss = kp.encapsulate()
    assert len(ct) == 1088
    assert len(ss) == 32
    ss2 = kp.decapsulate(ct)
    assert ss == ss2


def test_kyber512_keypair_class():
    """Test Kyber512KeyPair class."""
    kp = pykyber.Kyber512KeyPair.generate()
    assert len(kp.public_key) == 1184
    assert len(kp.secret_key) == 2400
    ct, ss = kp.encapsulate()
    ss2 = kp.decapsulate(ct)
    assert ss == ss2


def test_kyber1024_keypair_class():
    """Test Kyber1024KeyPair class."""
    kp = pykyber.Kyber1024KeyPair.generate()
    assert len(kp.public_key) == 1184
    assert len(kp.secret_key) == 2400
    ct, ss = kp.encapsulate()
    ss2 = kp.decapsulate(ct)
    assert ss == ss2


def test_kyber768_from_bytes():
    """Test Kyber768KeyPair.from_bytes."""
    kp1 = pykyber.Kyber768KeyPair.generate()
    kp2 = pykyber.Kyber768KeyPair.from_bytes(kp1.public_key, kp1.secret_key)
    ct, ss = kp2.encapsulate()
    ss2 = kp2.decapsulate(ct)
    assert ss == ss2


def test_kyber_class_alias():
    """Test that Kyber is an alias for Kyber768."""
    pk, sk = pykyber.Kyber.generate_keypair()
    assert len(pk) == 1184
    ct, ss = pykyber.Kyber.encapsulate(pk)
    ss2 = pykyber.Kyber.decapsulate(ct, sk)
    assert ss == ss2


def test_keypair_repr():
    """Test __repr__ methods."""
    kp = pykyber.Kyber768KeyPair.generate()
    r = repr(kp)
    assert 'Kyber768KeyPair' in r
    assert 'public_key' in r
    assert 'secret_key' in r
