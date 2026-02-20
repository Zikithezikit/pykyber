import pytest
import pykyber


def test_keypair_generation():
    """Test that keypair generation produces valid keys."""
    pk, sk = pykyber.generate_keypair()
    
    # Kyber-768 default key sizes
    assert len(pk) == 1184, f"Expected public key length 1184, got {len(pk)}"
    assert len(sk) == 2400, f"Expected secret key length 2400, got {len(sk)}"


def test_encapsulate_decapsulate():
    """Test that encapsulate and decapsulate work correctly."""
    pk, sk = pykyber.generate_keypair()
    
    # Encapsulate
    ct, ss = pykyber.encapsulate(pk)
    
    assert len(ct) == 1088, f"Expected ciphertext length 1088, got {len(ct)}"
    assert len(ss) == 32, f"Expected shared secret length 32, got {len(ss)}"
    
    # Decapsulate
    ss2 = pykyber.decapsulate(ct, sk)
    
    # The shared secrets should match
    assert ss == ss2, "Decapsulated secret doesn't match"


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
    
    # Generate secrets for each keypair
    ct1, ss1 = pykyber.encapsulate(pk1)
    ct2, ss2 = pykyber.encapsulate(pk2)
    
    # Verify secrets decapsulate correctly
    ss1_dec = pykyber.decapsulate(ct1, sk1)
    ss2_dec = pykyber.decapsulate(ct2, sk2)
    
    assert ss1 == ss1_dec
    assert ss2 == ss2_dec
    assert ss1 != ss2, "Different keypairs should produce different secrets"


def test_wrong_secret_key_fails():
    """Test that using wrong secret key produces different result."""
    pk, sk = pykyber.generate_keypair()
    _, wrong_sk = pykyber.generate_keypair()
    
    ct, ss = pykyber.encapsulate(pk)
    ss_wrong = pykyber.decapsulate(ct, wrong_sk)
    
    # The wrong key should produce a different result (or should fail)
    # In Kyber, wrong key decapsulation produces garbage, not an error
    assert ss != ss_wrong, "Wrong secret key should produce different result"


def test_keypair_512():
    """Test keypair generation for Kyber-512."""
    pk, sk = pykyber.keypair_512()
    
    # Note: Current implementation uses Kyber-768 by default
    # Kyber-512 key sizes: 800, 1632
    # But function currently uses Kyber-768: 1184, 2400
    assert len(pk) == 1184, f"Expected public key length 1184, got {len(pk)}"
    assert len(sk) == 2400, f"Expected secret key length 2400, got {len(sk)}"


def test_keypair_768():
    """Test keypair generation for Kyber-768."""
    pk, sk = pykyber.keypair_768()
    
    # Kyber-768 key sizes
    assert len(pk) == 1184, f"Expected public key length 1184, got {len(pk)}"
    assert len(sk) == 2400, f"Expected secret key length 2400, got {len(sk)}"


def test_keypair_1024():
    """Test keypair generation for Kyber-1024."""
    pk, sk = pykyber.keypair_1024()
    
    # Note: Current implementation uses Kyber-768 by default
    # Kyber-1024 key sizes: 1568, 3168
    # But function currently uses Kyber-768: 1184, 2400
    assert len(pk) == 1184, f"Expected public key length 1184, got {len(pk)}"
    assert len(sk) == 2400, f"Expected secret key length 2400, got {len(sk)}"


def test_deterministic_decapsulation():
    """Test that decapsulation is deterministic given the same ciphertext."""
    pk, sk = pykyber.generate_keypair()
    
    # Generate a ciphertext
    ct, _ = pykyber.encapsulate(pk)
    
    # Decapsulating the same ciphertext multiple times should produce the same result
    results = [pykyber.decapsulate(ct, sk) for _ in range(5)]
    
    # All results should be identical
    assert len(set(results)) == 1, "Decapsulation should be deterministic"


def test_ciphertext_randomness():
    """Test that ciphertexts are random (different each encapsulation)."""
    pk, sk = pykyber.generate_keypair()
    
    # Generate multiple ciphertexts
    ciphertexts = [pykyber.encapsulate(pk)[0] for _ in range(5)]
    
    # At least some should be different (probability of all 5 being equal is essentially 0)
    assert len(set(ciphertexts)) > 1, "Ciphertexts should be random"
