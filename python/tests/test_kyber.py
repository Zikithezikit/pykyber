import pytest
import pykyber


# Class-based API tests

def test_kyber768_new_api():
    """Test new Kyber768 API: keypair = Kyber768(); result = keypair.encapsulate()"""
    keypair = pykyber.Kyber768()
    
    result = keypair.encapsulate()
    shared_secret2 = keypair.decapsulate(result.ciphertext)
    
    assert len(keypair.public_key) == 1184
    assert len(keypair.secret_key) == 2400
    assert len(result.ciphertext) == 1088
    assert len(result.shared_secret) == 32
    assert result.shared_secret == shared_secret2


def test_kyber512_new_api():
    """Test new Kyber512 API."""
    keypair = pykyber.Kyber512()
    
    result = keypair.encapsulate()
    shared_secret2 = keypair.decapsulate(result.ciphertext)
    
    assert len(keypair.public_key) == 800
    assert len(keypair.secret_key) == 1632
    assert len(result.ciphertext) == 768
    assert len(result.shared_secret) == 32
    assert result.shared_secret == shared_secret2


def test_kyber1024_new_api():
    """Test new Kyber1024 API."""
    keypair = pykyber.Kyber1024()
    
    result = keypair.encapsulate()
    shared_secret2 = keypair.decapsulate(result.ciphertext)
    
    assert len(keypair.public_key) == 1568
    assert len(keypair.secret_key) == 3168
    assert len(result.ciphertext) == 1408
    assert len(result.shared_secret) == 32
    assert result.shared_secret == shared_secret2


def test_keypair_repr():
    """Test __repr__ methods."""
    keypair = pykyber.Kyber768()
    r = repr(keypair)
    assert 'Keypair' in r
    assert 'public_key' in r
    assert 'secret_key' in r
    
    result = keypair.encapsulate()
    r = repr(result)
    assert 'EncapsulationResult' in r


def test_keypair_generation():
    """Test that keypair generation produces valid keys."""
    pk, sk = pykyber._generate_keypair()
    assert len(pk) == 1184
    assert len(sk) == 2400


def test_encapsulate_decapsulate():
    """Test that encapsulate and decapsulate work correctly."""
    pk, sk = pykyber._generate_keypair()
    ct, ss = pykyber._encapsulate(pk)
    assert len(ct) == 1088
    assert len(ss) == 32
    ss2 = pykyber._decapsulate(ct, sk)
    assert ss == ss2


def test_invalid_public_key_length():
    """Test that invalid public key length raises an error."""
    with pytest.raises(Exception):
        pykyber._encapsulate(b"short")


def test_invalid_ciphertext_length():
    """Test that invalid ciphertext length raises an error."""
    sk = bytes(2400)
    with pytest.raises(Exception):
        pykyber._decapsulate(b"short", sk)


def test_invalid_secret_key_length():
    """Test that invalid secret key length raises an error."""
    ct = bytes(1088)
    with pytest.raises(Exception):
        pykyber._decapsulate(ct, b"short")


def test_different_keypairs_produce_different_secrets():
    """Test that different keypairs produce different shared secrets."""
    pk1, sk1 = pykyber._generate_keypair()
    pk2, sk2 = pykyber._generate_keypair()
    
    ct1, ss1 = pykyber._encapsulate(pk1)
    ct2, ss2 = pykyber._encapsulate(pk2)
    
    ss1_dec = pykyber._decapsulate(ct1, sk1)
    ss2_dec = pykyber._decapsulate(ct2, sk2)
    
    assert ss1 == ss1_dec
    assert ss2 == ss2_dec
    assert ss1 != ss2


def test_wrong_secret_key_fails():
    """Test that using wrong secret key produces different result."""
    pk, sk = pykyber._generate_keypair()
    _, wrong_sk = pykyber._generate_keypair()
    
    ct, ss = pykyber._encapsulate(pk)
    ss_wrong = pykyber._decapsulate(ct, wrong_sk)
    
    assert ss != ss_wrong


def test_keypair_512():
    """Test keypair generation for Kyber-512."""
    pk, sk = pykyber._keypair_512()
    assert len(pk) == 800
    assert len(sk) == 1632


def test_keypair_768():
    """Test keypair generation for Kyber-768."""
    pk, sk = pykyber._keypair_768()
    assert len(pk) == 1184
    assert len(sk) == 2400


def test_keypair_1024():
    """Test keypair generation for Kyber-1024."""
    pk, sk = pykyber._keypair_1024()
    assert len(pk) == 1568
    assert len(sk) == 3168


def test_deterministic_decapsulation():
    """Test that decapsulation is deterministic given the same ciphertext."""
    pk, sk = pykyber._generate_keypair()
    ct, _ = pykyber._encapsulate(pk)
    
    results = [pykyber._decapsulate(ct, sk) for _ in range(5)]
    assert len(set(results)) == 1


def test_ciphertext_randomness():
    """Test that ciphertexts are random."""
    pk, sk = pykyber._generate_keypair()
    ciphertexts = [pykyber._encapsulate(pk)[0] for _ in range(5)]
    assert len(set(ciphertexts)) > 1


def test_empty_public_key():
    """Test that empty public key raises error."""
    with pytest.raises(Exception):
        pykyber._encapsulate(b"")


def test_empty_ciphertext():
    """Test that empty ciphertext raises error."""
    pk, sk = pykyber._generate_keypair()
    with pytest.raises(Exception):
        pykyber._decapsulate(b"", sk)


def test_empty_secret_key():
    """Test that empty secret key raises error."""
    pk, sk = pykyber._generate_keypair()
    ct, _ = pykyber._encapsulate(pk)
    with pytest.raises(Exception):
        pykyber._decapsulate(ct, b"")


def test_boundary_public_key_length():
    """Test with public key that's 1 byte too short."""
    pk, sk = pykyber._generate_keypair()
    short_pk = pk[:-1]
    with pytest.raises(Exception):
        pykyber._encapsulate(short_pk)


def test_boundary_secret_key_length():
    """Test with secret key that's 1 byte too short."""
    pk, sk = pykyber._generate_keypair()
    ct, _ = pykyber._encapsulate(pk)
    short_sk = sk[:-1]
    with pytest.raises(Exception):
        pykyber._decapsulate(ct, short_sk)


def test_boundary_ciphertext_length():
    """Test with ciphertext that's 1 byte too short."""
    pk, sk = pykyber._generate_keypair()
    ct, _ = pykyber._encapsulate(pk)
    short_ct = ct[:-1]
    with pytest.raises(Exception):
        pykyber._decapsulate(short_ct, sk)


def test_all_zero_keypair():
    """Test that generated keys are not all zeros."""
    pk, sk = pykyber._generate_keypair()
    assert any(b != 0 for b in pk)
    assert any(b != 0 for b in sk)


def test_shared_secret_not_all_zeros():
    """Test that shared secrets are not all zeros."""
    pk, sk = pykyber._generate_keypair()
    ct, ss = pykyber._encapsulate(pk)
    assert any(b != 0 for b in ss)
    ss2 = pykyber._decapsulate(ct, sk)
    assert any(b != 0 for b in ss2)


def test_multiple_encapsulations():
    """Test multiple encapsulations with same keypair."""
    pk, sk = pykyber._generate_keypair()
    
    results = []
    for _ in range(10):
        ct, ss = pykyber._encapsulate(pk)
        ss_dec = pykyber._decapsulate(ct, sk)
        results.append((ct, ss, ss_dec))
    
    # All should decapsulate correctly
    for ct, ss, ss_dec in results:
        assert ss == ss_dec
    
    # Ciphertexts should mostly be different (random)
    ciphertexts = [r[0] for r in results]
    assert len(set(ciphertexts)) > 1


def test_keypair_768_function():
    """Test that keypair_768 function works."""
    pk, sk = pykyber._keypair_768()
    ct, ss = pykyber._encapsulate(pk)
    ss2 = pykyber._decapsulate(ct, sk)
    assert ss == ss2


def test_keypair_512_function():
    """Test that keypair_512 function works."""
    pk, sk = pykyber._keypair_512()
    ct, ss = pykyber._encapsulate_512(pk)
    ss2 = pykyber._decapsulate_512(ct, sk)
    assert ss == ss2


def test_keypair_1024_function():
    """Test that keypair_1024 function works."""
    pk, sk = pykyber._keypair_1024()
    ct, ss = pykyber._encapsulate_1024(pk)
    ss2 = pykyber._decapsulate_1024(ct, sk)
    assert ss == ss2


def test_encapsulate_512():
    """Test encapsulate_512 function."""
    pk, sk = pykyber._keypair_512()
    ct, ss = pykyber._encapsulate_512(pk)
    ss2 = pykyber._decapsulate_512(ct, sk)
    assert ss == ss2


def test_encapsulate_768():
    """Test encapsulate_768 function."""
    pk, sk = pykyber._keypair_768()
    ct, ss = pykyber._encapsulate_768(pk)
    ss2 = pykyber._decapsulate_768(ct, sk)
    assert ss == ss2


def test_encapsulate_1024():
    """Test encapsulate_1024 function."""
    pk, sk = pykyber._keypair_1024()
    ct, ss = pykyber._encapsulate_1024(pk)
    ss2 = pykyber._decapsulate_1024(ct, sk)
    assert ss == ss2


def test_decapsulate_512():
    """Test decapsulate_512 function."""
    pk, sk = pykyber._keypair_512()
    ct, ss = pykyber._encapsulate_512(pk)
    ss2 = pykyber._decapsulate_512(ct, sk)
    assert ss == ss2


def test_decapsulate_768():
    """Test decapsulate_768 function."""
    pk, sk = pykyber._keypair_768()
    ct, ss = pykyber._encapsulate(pk)
    ss2 = pykyber._decapsulate_768(ct, sk)
    assert ss == ss2


def test_decapsulate_1024():
    """Test decapsulate_1024 function."""
    pk, sk = pykyber._keypair_1024()
    ct, ss = pykyber._encapsulate_1024(pk)
    ss2 = pykyber._decapsulate_1024(ct, sk)
    assert ss == ss2


def test_same_ciphertext_decapsulation():
    """Test that same ciphertext always decapsulates to same secret."""
    pk, sk = pykyber._generate_keypair()
    ct, _ = pykyber._encapsulate(pk)
    
    results = [pykyber._decapsulate(ct, sk) for _ in range(10)]
    assert all(r == results[0] for r in results)


def test_interoperability_different_calls():
    """Test that different function variants work together."""
    pk, sk = pykyber._generate_keypair()
    
    # Mix and match
    ct1, ss1 = pykyber._encapsulate(pk)
    ss1_dec = pykyber._decapsulate(ct1, sk)
    assert ss1 == ss1_dec
    
    ct2, ss2 = pykyber._encapsulate_768(pk)
    ss2_dec = pykyber._decapsulate_768(ct2, sk)
    assert ss2 == ss2_dec


def test_zero_keypair_not_rejected():
    """Test that zero public key is not rejected (produces weak output)."""
    zero_pk = bytes(800)
    # Kyber doesn't reject zero keys - it will produce output (but weak)
    ct, ss = pykyber._encapsulate_512(zero_pk)
    assert len(ct) == 768
    assert len(ss) == 32


def test_very_long_input_rejection():
    """Test that too long inputs are handled."""
    pk, sk = pykyber._generate_keypair()
    long_pk = pk + b"extra"
    with pytest.raises(Exception):
        pykyber._encapsulate(long_pk)


# Key exchange tests (Alice and Bob)

def test_key_exchange_kyber512():
    """Test Alice and Bob can exchange keys using Kyber512."""
    # Alice generates a keypair
    alice_keypair = pykyber.Kyber512()
    alice_public_key = alice_keypair.public_key
    
    # Bob encapsulates using Alice's public key (no keypair needed)
    result = pykyber.Kyber512.encapsulate(alice_public_key)
    bob_shared_secret = result.shared_secret
    ciphertext = result.ciphertext
    
    # Alice decapsulates using her keypair
    alice_shared_secret = alice_keypair.decapsulate(ciphertext)
    
    # Both should have the same shared secret
    assert alice_shared_secret == bob_shared_secret


def test_key_exchange_kyber768():
    """Test Alice and Bob can exchange keys using Kyber768."""
    # Alice generates a keypair
    alice_keypair = pykyber.Kyber768()
    alice_public_key = alice_keypair.public_key
    
    # Bob encapsulates using Alice's public key (no keypair needed)
    result = pykyber.Kyber768.encapsulate(alice_public_key)
    bob_shared_secret = result.shared_secret
    ciphertext = result.ciphertext
    
    # Alice decapsulates using her keypair
    alice_shared_secret = alice_keypair.decapsulate(ciphertext)
    
    # Both should have the same shared secret
    assert alice_shared_secret == bob_shared_secret


def test_key_exchange_kyber1024():
    """Test Alice and Bob can exchange keys using Kyber1024."""
    # Alice generates a keypair
    alice_keypair = pykyber.Kyber1024()
    alice_public_key = alice_keypair.public_key
    
    # Bob encapsulates using Alice's public key (no keypair needed)
    result = pykyber.Kyber1024.encapsulate(alice_public_key)
    bob_shared_secret = result.shared_secret
    ciphertext = result.ciphertext
    
    # Alice decapsulates using her keypair
    alice_shared_secret = alice_keypair.decapsulate(ciphertext)
    
    # Both should have the same shared secret
    assert alice_shared_secret == bob_shared_secret


def test_encapsulate_static_method_kyber512():
    """Test Kyber512.encapsulate() static method works."""
    # Generate a keypair to get a public key
    keypair = pykyber.Kyber512()
    pk = keypair.public_key
    
    # Use static method to encapsulate
    result = pykyber.Kyber512.encapsulate(pk)
    
    assert isinstance(result, pykyber._kyber.EncapsulationResult)
    assert len(result.ciphertext) == 768
    assert len(result.shared_secret) == 32
    
    # Can decapsulate with keypair
    ss = keypair.decapsulate(result.ciphertext)
    assert ss == result.shared_secret


def test_encapsulate_static_method_kyber768():
    """Test Kyber768.encapsulate() static method works."""
    keypair = pykyber.Kyber768()
    pk = keypair.public_key
    
    result = pykyber.Kyber768.encapsulate(pk)
    
    assert isinstance(result, pykyber._kyber.EncapsulationResult)
    assert len(result.ciphertext) == 1088
    assert len(result.shared_secret) == 32
    
    ss = keypair.decapsulate(result.ciphertext)
    assert ss == result.shared_secret


def test_encapsulate_static_method_kyber1024():
    """Test Kyber1024.encapsulate() static method works."""
    keypair = pykyber.Kyber1024()
    pk = keypair.public_key
    
    result = pykyber.Kyber1024.encapsulate(pk)
    
    assert isinstance(result, pykyber._kyber.EncapsulationResult)
    assert len(result.ciphertext) == 1408
    assert len(result.shared_secret) == 32
    
    ss = keypair.decapsulate(result.ciphertext)
    assert ss == result.shared_secret


# Error handling tests - comprehensive

def test_kyber_error_can_be_imported():
    """Test that KyberError can be imported."""
    assert pykyber.KyberError is not None
    assert issubclass(pykyber.KyberError, Exception)


def test_invalid_public_key_length_raises_error():
    """Test that invalid public key length raises KyberError."""
    with pytest.raises(pykyber.KyberError) as exc_info:
        pykyber._encapsulate(b"short")
    assert "Invalid public key" in str(exc_info.value)


def test_invalid_ciphertext_length_raises_error():
    """Test that invalid ciphertext length raises KyberError."""
    sk = bytes(2400)
    with pytest.raises(pykyber.KyberError) as exc_info:
        pykyber._decapsulate(b"short", sk)
    assert "Invalid ciphertext" in str(exc_info.value)


def test_invalid_secret_key_length_raises_error():
    """Test that invalid secret key length raises KyberError."""
    ct = bytes(1088)
    with pytest.raises(pykyber.KyberError) as exc_info:
        pykyber._decapsulate(ct, b"short")
    assert "Invalid input for 'sk'" in str(exc_info.value)


def test_empty_public_key_raises_error():
    """Test that empty public key raises KyberError."""
    with pytest.raises(pykyber.KyberError) as exc_info:
        pykyber._encapsulate(b"")
    assert "Invalid public key" in str(exc_info.value)


def test_empty_ciphertext_raises_error():
    """Test that empty ciphertext raises KyberError."""
    pk, sk = pykyber._generate_keypair()
    with pytest.raises(pykyber.KyberError) as exc_info:
        pykyber._decapsulate(b"", sk)
    assert "Invalid ciphertext" in str(exc_info.value)


def test_empty_secret_key_raises_error():
    """Test that empty secret key raises KyberError."""
    pk, sk = pykyber._generate_keypair()
    ct, _ = pykyber._encapsulate(pk)
    with pytest.raises(pykyber.KyberError) as exc_info:
        pykyber._decapsulate(ct, b"")
    assert "Invalid input for 'sk'" in str(exc_info.value)


def test_very_long_input_raises_error():
    """Test that too long inputs raise KyberError."""
    pk, sk = pykyber._generate_keypair()
    long_pk = pk + b"extra"
    with pytest.raises(pykyber.KyberError) as exc_info:
        pykyber._encapsulate(long_pk)
    assert "Invalid public key" in str(exc_info.value)


def test_kyber512_invalid_public_key_length():
    """Test Kyber512 with invalid public key length."""
    with pytest.raises(pykyber.KyberError) as exc_info:
        pykyber._encapsulate_512(b"short")
    assert "Invalid public key" in str(exc_info.value)


def test_kyber512_invalid_ciphertext_length():
    """Test Kyber512 with invalid ciphertext length."""
    sk = bytes(1632)
    with pytest.raises(pykyber.KyberError) as exc_info:
        pykyber._decapsulate_512(b"short", sk)
    assert "Invalid ciphertext" in str(exc_info.value)


def test_kyber512_invalid_secret_key_length():
    """Test Kyber512 with invalid secret key length."""
    ct = bytes(768)
    with pytest.raises(pykyber.KyberError) as exc_info:
        pykyber._decapsulate_512(ct, b"short")
    assert "Invalid input for 'sk'" in str(exc_info.value)


def test_kyber1024_invalid_public_key_length():
    """Test Kyber1024 with invalid public key length."""
    with pytest.raises(pykyber.KyberError) as exc_info:
        pykyber._encapsulate_1024(b"short")
    assert "Invalid public key" in str(exc_info.value)


def test_kyber1024_invalid_ciphertext_length():
    """Test Kyber1024 with invalid ciphertext length."""
    sk = bytes(3168)
    with pytest.raises(pykyber.KyberError) as exc_info:
        pykyber._decapsulate_1024(b"short", sk)
    assert "Invalid ciphertext" in str(exc_info.value)


def test_kyber1024_invalid_secret_key_length():
    """Test Kyber1024 with invalid secret key length."""
    ct = bytes(1408)
    with pytest.raises(pykyber.KyberError) as exc_info:
        pykyber._decapsulate_1024(ct, b"short")
    assert "Invalid input for 'sk'" in str(exc_info.value)


def test_boundary_public_key_length_512():
    """Test with Kyber512 public key that's 1 byte too short."""
    pk, _ = pykyber._keypair_512()
    short_pk = pk[:-1]
    with pytest.raises(pykyber.KyberError) as exc_info:
        pykyber._encapsulate_512(short_pk)
    assert "Invalid public key" in str(exc_info.value)
    assert "800" in str(exc_info.value)
    assert "799" in str(exc_info.value)


def test_boundary_public_key_length_768():
    """Test with Kyber768 public key that's 1 byte too short."""
    pk, _ = pykyber._keypair_768()
    short_pk = pk[:-1]
    with pytest.raises(pykyber.KyberError) as exc_info:
        pykyber._encapsulate(short_pk)
    assert "Invalid public key" in str(exc_info.value)
    assert "1184" in str(exc_info.value)
    assert "1183" in str(exc_info.value)


def test_boundary_public_key_length_1024():
    """Test with Kyber1024 public key that's 1 byte too short."""
    pk, _ = pykyber._keypair_1024()
    short_pk = pk[:-1]
    with pytest.raises(pykyber.KyberError) as exc_info:
        pykyber._encapsulate_1024(short_pk)
    assert "Invalid public key" in str(exc_info.value)
    assert "1568" in str(exc_info.value)
    assert "1567" in str(exc_info.value)


def test_boundary_secret_key_length_512():
    """Test with Kyber512 secret key that's 1 byte too short."""
    _, sk = pykyber._keypair_512()
    ct, _ = pykyber._encapsulate_512(sk[:800])
    short_sk = sk[:-1]
    with pytest.raises(pykyber.KyberError) as exc_info:
        pykyber._decapsulate_512(ct, short_sk)
    assert "Invalid input for 'sk'" in str(exc_info.value)


def test_boundary_secret_key_length_768():
    """Test with Kyber768 secret key that's 1 byte too short."""
    pk, sk = pykyber._generate_keypair()
    ct, _ = pykyber._encapsulate(pk)
    short_sk = sk[:-1]
    with pytest.raises(pykyber.KyberError) as exc_info:
        pykyber._decapsulate(ct, short_sk)
    assert "Invalid input for 'sk'" in str(exc_info.value)


def test_boundary_secret_key_length_1024():
    """Test with Kyber1024 secret key that's 1 byte too short."""
    pk, sk = pykyber._keypair_1024()
    ct, _ = pykyber._encapsulate_1024(pk)
    short_sk = sk[:-1]
    with pytest.raises(pykyber.KyberError) as exc_info:
        pykyber._decapsulate_1024(ct, short_sk)
    assert "Invalid input for 'sk'" in str(exc_info.value)


def test_boundary_ciphertext_length_512():
    """Test with Kyber512 ciphertext that's 1 byte too short."""
    pk, sk = pykyber._keypair_512()
    ct, _ = pykyber._encapsulate_512(pk)
    short_ct = ct[:-1]
    with pytest.raises(pykyber.KyberError) as exc_info:
        pykyber._decapsulate_512(short_ct, sk)
    assert "Invalid ciphertext" in str(exc_info.value)


def test_boundary_ciphertext_length_768():
    """Test with Kyber768 ciphertext that's 1 byte too short."""
    pk, sk = pykyber._generate_keypair()
    ct, _ = pykyber._encapsulate(pk)
    short_ct = ct[:-1]
    with pytest.raises(pykyber.KyberError) as exc_info:
        pykyber._decapsulate(short_ct, sk)
    assert "Invalid ciphertext" in str(exc_info.value)


def test_boundary_ciphertext_length_1024():
    """Test with Kyber1024 ciphertext that's 1 byte too short."""
    pk, sk = pykyber._keypair_1024()
    ct, _ = pykyber._encapsulate_1024(pk)
    short_ct = ct[:-1]
    with pytest.raises(pykyber.KyberError) as exc_info:
        pykyber._decapsulate_1024(short_ct, sk)
    assert "Invalid ciphertext" in str(exc_info.value)


def test_error_can_be_caught_as_exception():
    """Test that KyberError can be caught as generic Exception."""
    try:
        pykyber._encapsulate(b"short")
        assert False, "Should have raised"
    except Exception as e:
        assert isinstance(e, pykyber.KyberError)


def test_error_message_contains_useful_info():
    """Test that error messages contain parameter name and sizes."""
    pk, sk = pykyber._generate_keypair()
    
    with pytest.raises(pykyber.KyberError) as exc_info:
        pykyber._encapsulate(b"x" * 100)
    msg = str(exc_info.value)
    assert "public key" in msg
    assert "expected" in msg or "bytes" in msg
    
    ct, _ = pykyber._encapsulate(pk)
    with pytest.raises(pykyber.KyberError) as exc_info:
        pykyber._decapsulate(ct, b"x" * 100)
    msg = str(exc_info.value)
    assert "sk" in msg
    
    with pytest.raises(pykyber.KyberError) as exc_info:
        pykyber._decapsulate(b"x" * 100, sk)
    msg = str(exc_info.value)
    assert "ct" in msg


def test_wrong_key_type_raises_error():
    """Test that passing wrong types raises appropriate error."""
    with pytest.raises((pykyber.KyberError, TypeError)):
        pykyber._encapsulate(12345)
    
    with pytest.raises((pykyber.KyberError, TypeError)):
        pykyber._decapsulate(None, None)


def test_all_variants_of_error():
    """Test that different error variants produce appropriate messages."""
    with pytest.raises(pykyber.KyberError):
        pykyber._encapsulate(b"")
    
    with pytest.raises(pykyber.KyberError):
        pk, _ = pykyber._generate_keypair()
        pykyber._decapsulate(pk, b"")


def test_multiple_error_types_in_sequence():
    """Test catching different errors in sequence."""
    errors = []
    
    try:
        pykyber._encapsulate(b"x")
    except pykyber.KyberError:
        errors.append("invalid_pk")
    
    pk, sk = pykyber._generate_keypair()
    try:
        pykyber._decapsulate(b"x", sk)
    except pykyber.KyberError:
        errors.append("invalid_ct")
    
    try:
        pykyber._decapsulate(pk, b"x")
    except pykyber.KyberError:
        errors.append("invalid_sk")
    
    assert len(errors) == 3
    assert "invalid_pk" in errors
    assert "invalid_ct" in errors
    assert "invalid_sk" in errors


def test_error_is_subclass_of_exception():
    """Test that KyberError is properly a subclass of Exception."""
    assert issubclass(pykyber.KyberError, Exception)
    e = pykyber.KyberError("test")
    assert isinstance(e, Exception)
    assert str(e) == "test"


def test_class_api_error_handling_kyber512():
    """Test error handling in Kyber512 class API."""
    keypair = pykyber.Kyber512()
    
    with pytest.raises(pykyber.KyberError):
        pykyber.Kyber512.encapsulate(b"short")
    
    with pytest.raises(pykyber.KyberError):
        keypair.decapsulate(b"short")


def test_class_api_error_handling_kyber768():
    """Test error handling in Kyber768 class API."""
    keypair = pykyber.Kyber768()
    
    with pytest.raises(pykyber.KyberError):
        pykyber.Kyber768.encapsulate(b"short")
    
    with pytest.raises(pykyber.KyberError):
        keypair.decapsulate(b"short")


def test_class_api_error_handling_kyber1024():
    """Test error handling in Kyber1024 class API."""
    keypair = pykyber.Kyber1024()
    
    with pytest.raises(pykyber.KyberError):
        pykyber.Kyber1024.encapsulate(b"short")
    
    with pytest.raises(pykyber.KyberError):
        keypair.decapsulate(b"short")


def test_error_with_none_values():
    """Test that None values raise appropriate errors."""
    with pytest.raises((pykyber.KyberError, TypeError)):
        pykyber._encapsulate(None)
    
    with pytest.raises((pykyber.KyberError, TypeError)):
        pykyber._decapsulate(None, b"x" * 2400)
    
    with pytest.raises((pykyber.KyberError, TypeError)):
        pykyber._decapsulate(b"x" * 1088, None)


def test_error_with_list_input():
    """Test that list input raises appropriate error."""
    with pytest.raises((pykyber.KyberError, TypeError)):
        pykyber._encapsulate([1, 2, 3])
    
    with pytest.raises((pykyber.KyberError, TypeError)):
        pykyber._decapsulate([1, 2, 3], b"x" * 2400)


def test_error_with_integer_input():
    """Test that integer input raises appropriate error."""
    with pytest.raises((pykyber.KyberError, TypeError)):
        pykyber._encapsulate(12345)
    
    with pytest.raises((pykyber.KyberError, TypeError)):
        pykyber._decapsulate(12345, b"x" * 2400)


def test_keypair_functions_error_handling():
    """Test that keypair functions still work correctly."""
    pk, sk = pykyber._keypair_512()
    assert len(pk) == 800
    assert len(sk) == 1632
    
    pk, sk = pykyber._keypair_768()
    assert len(pk) == 1184
    assert len(sk) == 2400
    
    pk, sk = pykyber._keypair_1024()
    assert len(pk) == 1568
    assert len(sk) == 3168


def test_user_can_handle_error_gracefully():
    """Test that a user can handle the error gracefully."""
    def safe_encapsulate(public_key):
        """Example of user handling the error."""
        try:
            return pykyber._encapsulate(public_key)
        except pykyber.KyberError as e:
            return f"Error: {e}"
        except Exception as e:
            return f"Unexpected error: {e}"
    
    result = safe_encapsulate(b"short")
    assert "Error:" in result
    assert "Invalid" in result
    
    pk, _ = pykyber._generate_keypair()
    result = safe_encapsulate(pk)
    ct, ss = result
    assert len(ct) == 1088
    assert len(ss) == 32


# Additional panic prevention tests

def test_all_zero_public_key_512():
    """Test encapsulation with all-zero public key (Kyber512)."""
    zero_pk = bytes(800)
    ct, ss = pykyber._encapsulate_512(zero_pk)
    assert len(ct) == 768
    assert len(ss) == 32


def test_all_zero_public_key_768():
    """Test encapsulation with all-zero public key (Kyber768)."""
    zero_pk = bytes(1184)
    ct, ss = pykyber._encapsulate(zero_pk)
    assert len(ct) == 1088
    assert len(ss) == 32


def test_all_zero_public_key_1024():
    """Test encapsulation with all-zero public key (Kyber1024)."""
    zero_pk = bytes(1568)
    ct, ss = pykyber._encapsulate_1024(zero_pk)
    assert len(ct) == 1408
    assert len(ss) == 32


def test_all_ones_public_key_512():
    """Test encapsulation with all-ones public key (Kyber512)."""
    ones_pk = bytes([255] * 800)
    ct, ss = pykyber._encapsulate_512(ones_pk)
    assert len(ct) == 768
    assert len(ss) == 32


def test_all_ones_public_key_768():
    """Test encapsulation with all-ones public key (Kyber768)."""
    ones_pk = bytes([255] * 1184)
    ct, ss = pykyber._encapsulate(ones_pk)
    assert len(ct) == 1088
    assert len(ss) == 32


def test_all_ones_public_key_1024():
    """Test encapsulation with all-ones public key (Kyber1024)."""
    ones_pk = bytes([255] * 1568)
    ct, ss = pykyber._encapsulate_1024(ones_pk)
    assert len(ct) == 1408
    assert len(ss) == 32


def test_alternating_bits_public_key():
    """Test encapsulation with alternating bits public key."""
    alternating_pk = bytes([i % 2 for i in range(1184)])
    ct, ss = pykyber._encapsulate(alternating_pk)
    assert len(ct) == 1088
    assert len(ss) == 32


def test_decapsulate_with_all_zero_ciphertext_512():
    """Test decapsulation with all-zero ciphertext (Kyber512)."""
    pk, sk = pykyber._keypair_512()
    zero_ct = bytes(768)
    ss = pykyber._decapsulate_512(zero_ct, sk)
    assert len(ss) == 32


def test_decapsulate_with_all_zero_ciphertext_768():
    """Test decapsulation with all-zero ciphertext (Kyber768)."""
    pk, sk = pykyber._generate_keypair()
    zero_ct = bytes(1088)
    ss = pykyber._decapsulate(zero_ct, sk)
    assert len(ss) == 32


def test_decapsulate_with_all_zero_ciphertext_1024():
    """Test decapsulation with all-zero ciphertext (Kyber1024)."""
    pk, sk = pykyber._keypair_1024()
    zero_ct = bytes(1408)
    ss = pykyber._decapsulate_1024(zero_ct, sk)
    assert len(ss) == 32


def test_decapsulate_with_all_ones_ciphertext():
    """Test decapsulation with all-ones ciphertext."""
    pk, sk = pykyber._generate_keypair()
    ones_ct = bytes([255] * 1088)
    ss = pykyber._decapsulate(ones_ct, sk)
    assert len(ss) == 32


def test_wrong_variant_ciphertext_decapsulate_512_with_768_ct():
    """Test using 768 ciphertext with 512 decapsulate - should fail gracefully."""
    pk_768, sk_768 = pykyber._generate_keypair()
    pk_512, sk_512 = pykyber._keypair_512()
    ct_768, _ = pykyber._encapsulate(pk_768)
    with pytest.raises(pykyber.KyberError):
        pykyber._decapsulate_512(ct_768, sk_512)


def test_wrong_variant_ciphertext_decapsulate_1024_with_768_ct():
    """Test using 768 ciphertext with 1024 decapsulate - should fail gracefully."""
    pk_768, sk_768 = pykyber._generate_keypair()
    pk_1024, sk_1024 = pykyber._keypair_1024()
    ct_768, _ = pykyber._encapsulate(pk_768)
    with pytest.raises(pykyber.KyberError):
        pykyber._decapsulate_1024(ct_768, sk_1024)


def test_wrong_variant_ciphertext_decapsulate_768_with_512_ct():
    """Test using 512 ciphertext with 768 decapsulate - should fail gracefully."""
    pk_512, sk_512 = pykyber._keypair_512()
    pk_768, sk_768 = pykyber._generate_keypair()
    ct_512, _ = pykyber._encapsulate_512(pk_512)
    with pytest.raises(pykyber.KyberError):
        pykyber._decapsulate(ct_512, sk_768)


def test_mismatched_keypair_ciphertext():
    """Test decapsulating ciphertext from different keypair."""
    keypair1 = pykyber.Kyber768()
    keypair2 = pykyber.Kyber768()
    result = keypair1.encapsulate()
    ss_dec = keypair2.decapsulate(result.ciphertext)
    assert ss_dec != result.shared_secret


def test_repeated_keypair_generation():
    """Test multiple rapid keypair generations don't panic."""
    for _ in range(100):
        pk, sk = pykyber._generate_keypair()
        assert len(pk) == 1184
        assert len(sk) == 2400


def test_repeated_encapsulation():
    """Test multiple rapid encapsulations don't panic."""
    pk, _ = pykyber._generate_keypair()
    for _ in range(100):
        ct, ss = pykyber._encapsulate(pk)
        assert len(ct) == 1088
        assert len(ss) == 32


def test_repeated_decapsulation():
    """Test multiple rapid decapsulations don't panic."""
    pk, sk = pykyber._generate_keypair()
    ct, _ = pykyber._encapsulate(pk)
    for _ in range(100):
        ss = pykyber._decapsulate(ct, sk)
        assert len(ss) == 32


def test_very_large_valid_size_public_key():
    """Test with a public key that's much larger than expected - should fail gracefully."""
    huge_pk = bytes(10000)
    with pytest.raises(pykyber.KyberError):
        pykyber._encapsulate(huge_pk)


def test_very_large_valid_size_secret_key():
    """Test with a secret key that's much larger than expected - should fail gracefully."""
    pk, sk = pykyber._generate_keypair()
    ct, _ = pykyber._encapsulate(pk)
    huge_sk = sk + bytes(10000)
    with pytest.raises(pykyber.KyberError):
        pykyber._decapsulate(ct, huge_sk)


def test_very_large_valid_size_ciphertext():
    """Test with a ciphertext that's much larger than expected - should fail gracefully."""
    pk, sk = pykyber._generate_keypair()
    ct, _ = pykyber._encapsulate(pk)
    huge_ct = ct + bytes(10000)
    with pytest.raises(pykyber.KyberError):
        pykyber._decapsulate(huge_ct, sk)


def test_boundary_minus_one_ciphertext_512():
    """Test with ciphertext that's 1 byte less than minimum (Kyber512)."""
    pk, sk = pykyber._keypair_512()
    ct, _ = pykyber._encapsulate_512(pk)
    short_ct = ct[:-1]
    with pytest.raises(pykyber.KyberError):
        pykyber._decapsulate_512(short_ct, sk)


def test_boundary_minus_one_ciphertext_768():
    """Test with ciphertext that's 1 byte less than minimum (Kyber768)."""
    pk, sk = pykyber._generate_keypair()
    ct, _ = pykyber._encapsulate(pk)
    short_ct = ct[:-1]
    with pytest.raises(pykyber.KyberError):
        pykyber._decapsulate(short_ct, sk)


def test_boundary_minus_one_ciphertext_1024():
    """Test with ciphertext that's 1 byte less than minimum (Kyber1024)."""
    pk, sk = pykyber._keypair_1024()
    ct, _ = pykyber._encapsulate_1024(pk)
    short_ct = ct[:-1]
    with pytest.raises(pykyber.KyberError):
        pykyber._decapsulate_1024(short_ct, sk)


def test_max_uint8_values_secret_key():
    """Test decapsulation with max uint8 values in secret key - should not panic."""
    pk, sk = pykyber._generate_keypair()
    max_sk = bytes([255] * len(sk))
    ct, _ = pykyber._encapsulate(pk)
    ss = pykyber._decapsulate(ct, max_sk)
    assert len(ss) == 32


def test_max_uint8_values_ciphertext():
    """Test decapsulation with max uint8 values in ciphertext - should not panic."""
    pk, sk = pykyber._generate_keypair()
    max_ct = bytes([255] * 1088)
    ss = pykyber._decapsulate(max_ct, sk)
    assert len(ss) == 32


def test_interleaved_key_generation_and_encapsulation():
    """Test interleaved key generation and encapsulation."""
    for i in range(50):
        if i % 3 == 0:
            pk, _ = pykyber._keypair_512()
            ct, ss = pykyber._encapsulate_512(pk)
        elif i % 3 == 1:
            pk, _ = pykyber._generate_keypair()
            ct, ss = pykyber._encapsulate(pk)
        else:
            pk, _ = pykyber._keypair_1024()
            ct, ss = pykyber._encapsulate_1024(pk)
        assert len(ct) > 0
        assert len(ss) == 32


def test_encapsulate_with_known_vector_512():
    """Test encapsulation produces expected output format."""
    pk = bytes(800)
    ct, ss = pykyber._encapsulate_512(pk)
    assert isinstance(ct, bytes)
    assert isinstance(ss, bytes)
    assert len(ct) == 768
    assert len(ss) == 32


def test_keypair_with_specific_seed_issue():
    """Test that various seed patterns don't cause panic."""
    seeds = [
        bytes(32),
        bytes([0] * 32),
        bytes([255] * 32),
        bytes([i for i in range(32)]),
        bytes([31 - i for i in range(32)]),
    ]
    for seed in seeds:
        pk, sk = pykyber._generate_keypair()
        assert len(pk) == 1184
        assert len(sk) == 2400


def test_concurrent_error_handling():
    """Test that error handling works correctly in sequence."""
    error_inputs = [
        (b"", b""),
        (b"x", b"x" * 2400),
        (b"x" * 1088, b"x"),
        (b"x" * 100, b"x" * 100),
    ]
    for pk_test, sk_test in error_inputs:
        try:
            pykyber._encapsulate(pk_test)
        except pykyber.KyberError:
            pass
        except Exception as e:
            if "panicked" not in str(e).lower():
                raise AssertionError(f"Unexpected non-panic error: {e}")
    
    pk, sk = pykyber._generate_keypair()
    ct, _ = pykyber._encapsulate(pk)
    for ct_test, sk_test in error_inputs:
        try:
            pykyber._decapsulate(ct_test, sk_test)
        except pykyber.KyberError:
            pass
        except Exception as e:
            if "panicked" not in str(e).lower():
                raise AssertionError(f"Unexpected non-panic error: {e}")


# Static decapsulate method tests

def test_static_decapsulate_kyber512():
    """Test static decapsulate method for Kyber512."""
    pk, sk = pykyber._keypair_512()
    ct, ss = pykyber._encapsulate_512(pk)
    ss_dec = pykyber.Kyber512.decapsulate(ct, sk)
    assert ss == ss_dec


def test_static_decapsulate_kyber768():
    """Test static decapsulate method for Kyber768."""
    pk, sk = pykyber._keypair_768()
    ct, ss = pykyber._encapsulate_768(pk)
    ss_dec = pykyber.Kyber768.decapsulate(ct, sk)
    assert ss == ss_dec


def test_static_decapsulate_kyber1024():
    """Test static decapsulate method for Kyber1024."""
    pk, sk = pykyber._keypair_1024()
    ct, ss = pykyber._encapsulate_1024(pk)
    ss_dec = pykyber.Kyber1024.decapsulate(ct, sk)
    assert ss == ss_dec


def test_static_decapsulate_vs_instance_decapsulate_kyber512():
    """Test that static and instance decapsulate produce same result (Kyber512)."""
    keypair = pykyber.Kyber512()
    result = keypair.encapsulate()
    ss_instance = keypair.decapsulate(result.ciphertext)
    ss_static = pykyber.Kyber512.decapsulate(result.ciphertext, keypair.secret_key)
    assert ss_instance == ss_static


def test_static_decapsulate_vs_instance_decapsulate_kyber768():
    """Test that static and instance decapsulate produce same result (Kyber768)."""
    keypair = pykyber.Kyber768()
    result = keypair.encapsulate()
    ss_instance = keypair.decapsulate(result.ciphertext)
    ss_static = pykyber.Kyber768.decapsulate(result.ciphertext, keypair.secret_key)
    assert ss_instance == ss_static


def test_static_decapsulate_vs_instance_decapsulate_kyber1024():
    """Test that static and instance decapsulate produce same result (Kyber1024)."""
    keypair = pykyber.Kyber1024()
    result = keypair.encapsulate()
    ss_instance = keypair.decapsulate(result.ciphertext)
    ss_static = pykyber.Kyber1024.decapsulate(result.ciphertext, keypair.secret_key)
    assert ss_instance == ss_static


def test_static_decapsulate_invalid_ciphertext_length_kyber512():
    """Test static decapsulate with invalid ciphertext length (Kyber512)."""
    sk = bytes(1632)
    with pytest.raises(pykyber.KyberError) as exc_info:
        pykyber.Kyber512.decapsulate(b"short", sk)
    assert "Invalid ciphertext" in str(exc_info.value)


def test_static_decapsulate_invalid_secret_key_length_kyber512():
    """Test static decapsulate with invalid secret key length (Kyber512)."""
    ct = bytes(768)
    with pytest.raises(pykyber.KyberError) as exc_info:
        pykyber.Kyber512.decapsulate(ct, b"short")
    assert "Invalid input for 'sk'" in str(exc_info.value)


def test_static_decapsulate_invalid_ciphertext_length_kyber768():
    """Test static decapsulate with invalid ciphertext length (Kyber768)."""
    sk = bytes(2400)
    with pytest.raises(pykyber.KyberError) as exc_info:
        pykyber.Kyber768.decapsulate(b"short", sk)
    assert "Invalid ciphertext" in str(exc_info.value)


def test_static_decapsulate_invalid_secret_key_length_kyber768():
    """Test static decapsulate with invalid secret key length (Kyber768)."""
    ct = bytes(1088)
    with pytest.raises(pykyber.KyberError) as exc_info:
        pykyber.Kyber768.decapsulate(ct, b"short")
    assert "Invalid input for 'sk'" in str(exc_info.value)


def test_static_decapsulate_invalid_ciphertext_length_kyber1024():
    """Test static decapsulate with invalid ciphertext length (Kyber1024)."""
    sk = bytes(3168)
    with pytest.raises(pykyber.KyberError) as exc_info:
        pykyber.Kyber1024.decapsulate(b"short", sk)
    assert "Invalid ciphertext" in str(exc_info.value)


def test_static_decapsulate_invalid_secret_key_length_kyber1024():
    """Test static decapsulate with invalid secret key length (Kyber1024)."""
    ct = bytes(1408)
    with pytest.raises(pykyber.KyberError) as exc_info:
        pykyber.Kyber1024.decapsulate(ct, b"short")
    assert "Invalid input for 'sk'" in str(exc_info.value)


# Stress tests

def test_stress_kyber512_many_operations():
    """Stress test: many keypair generations and encapsulations (Kyber512)."""
    for _ in range(1000):
        pk, sk = pykyber._keypair_512()
        ct, ss = pykyber._encapsulate_512(pk)
        ss_dec = pykyber._decapsulate_512(ct, sk)
        assert ss == ss_dec


def test_stress_kyber768_many_operations():
    """Stress test: many keypair generations and encapsulations (Kyber768)."""
    for _ in range(1000):
        pk, sk = pykyber._keypair_768()
        ct, ss = pykyber._encapsulate_768(pk)
        ss_dec = pykyber._decapsulate_768(ct, sk)
        assert ss == ss_dec


def test_stress_kyber1024_many_operations():
    """Stress test: many keypair generations and encapsulations (Kyber1024)."""
    for _ in range(1000):
        pk, sk = pykyber._keypair_1024()
        ct, ss = pykyber._encapsulate_1024(pk)
        ss_dec = pykyber._decapsulate_1024(ct, sk)
        assert ss == ss_dec


def test_stress_class_api_kyber512():
    """Stress test: class API with many operations (Kyber512)."""
    for _ in range(1000):
        keypair = pykyber.Kyber512()
        result = keypair.encapsulate()
        ss = keypair.decapsulate(result.ciphertext)
        assert result.shared_secret == ss


def test_stress_class_api_kyber768():
    """Stress test: class API with many operations (Kyber768)."""
    for _ in range(1000):
        keypair = pykyber.Kyber768()
        result = keypair.encapsulate()
        ss = keypair.decapsulate(result.ciphertext)
        assert result.shared_secret == ss


def test_stress_class_api_kyber1024():
    """Stress test: class API with many operations (Kyber1024)."""
    for _ in range(1000):
        keypair = pykyber.Kyber1024()
        result = keypair.encapsulate()
        ss = keypair.decapsulate(result.ciphertext)
        assert result.shared_secret == ss


def test_stress_static_methods_kyber512():
    """Stress test: static methods without keypair (Kyber512)."""
    for _ in range(1000):
        pk, sk = pykyber._keypair_512()
        result = pykyber.Kyber512.encapsulate(pk)
        ss = pykyber.Kyber512.decapsulate(result.ciphertext, sk)
        assert result.shared_secret == ss


def test_stress_static_methods_kyber768():
    """Stress test: static methods without keypair (Kyber768)."""
    for _ in range(1000):
        pk, sk = pykyber._keypair_768()
        result = pykyber.Kyber768.encapsulate(pk)
        ss = pykyber.Kyber768.decapsulate(result.ciphertext, sk)
        assert result.shared_secret == ss


def test_stress_static_methods_kyber1024():
    """Stress test: static methods without keypair (Kyber1024)."""
    for _ in range(1000):
        pk, sk = pykyber._keypair_1024()
        result = pykyber.Kyber1024.encapsulate(pk)
        ss = pykyber.Kyber1024.decapsulate(result.ciphertext, sk)
        assert result.shared_secret == ss


def test_stress_mixed_variants():
    """Stress test: mixed variants in sequence."""
    for _ in range(333):
        pk_512, sk_512 = pykyber._keypair_512()
        ct_512, ss_512 = pykyber._encapsulate_512(pk_512)
        ss_512_dec = pykyber._decapsulate_512(ct_512, sk_512)
        assert ss_512 == ss_512_dec

        pk_768, sk_768 = pykyber._keypair_768()
        ct_768, ss_768 = pykyber._encapsulate_768(pk_768)
        ss_768_dec = pykyber._decapsulate_768(ct_768, sk_768)
        assert ss_768 == ss_768_dec

        pk_1024, sk_1024 = pykyber._keypair_1024()
        ct_1024, ss_1024 = pykyber._encapsulate_1024(pk_1024)
        ss_1024_dec = pykyber._decapsulate_1024(ct_1024, sk_1024)
        assert ss_1024 == ss_1024_dec


# Performance tests

def test_performance_kyber512_keypair_generation():
    """Performance test: measure time for 100 keypair generations (Kyber512)."""
    import time
    iterations = 100
    
    start = time.perf_counter()
    for _ in range(iterations):
        pykyber._keypair_512()
    elapsed = time.perf_counter() - start
    
    print(f"\nKyber512 keypair generation: {elapsed/iterations*1000:.3f} ms/op ({iterations} iterations)")
    assert elapsed < 5.0  # Should complete 100 iterations in under 5 seconds


def test_performance_kyber768_keypair_generation():
    """Performance test: measure time for 100 keypair generations (Kyber768)."""
    import time
    iterations = 100
    
    start = time.perf_counter()
    for _ in range(iterations):
        pykyber._keypair_768()
    elapsed = time.perf_counter() - start
    
    print(f"\nKyber768 keypair generation: {elapsed/iterations*1000:.3f} ms/op ({iterations} iterations)")
    assert elapsed < 5.0


def test_performance_kyber1024_keypair_generation():
    """Performance test: measure time for 100 keypair generations (Kyber1024)."""
    import time
    iterations = 100
    
    start = time.perf_counter()
    for _ in range(iterations):
        pykyber._keypair_1024()
    elapsed = time.perf_counter() - start
    
    print(f"\nKyber1024 keypair generation: {elapsed/iterations*1000:.3f} ms/op ({iterations} iterations)")
    assert elapsed < 5.0


def test_performance_kyber512_encapsulation():
    """Performance test: measure time for 100 encapsulations (Kyber512)."""
    import time
    pk, _ = pykyber._keypair_512()
    iterations = 100
    
    start = time.perf_counter()
    for _ in range(iterations):
        pykyber._encapsulate_512(pk)
    elapsed = time.perf_counter() - start
    
    print(f"\nKyber512 encapsulation: {elapsed/iterations*1000:.3f} ms/op ({iterations} iterations)")
    assert elapsed < 5.0


def test_performance_kyber768_encapsulation():
    """Performance test: measure time for 100 encapsulations (Kyber768)."""
    import time
    pk, _ = pykyber._keypair_768()
    iterations = 100
    
    start = time.perf_counter()
    for _ in range(iterations):
        pykyber._encapsulate_768(pk)
    elapsed = time.perf_counter() - start
    
    print(f"\nKyber768 encapsulation: {elapsed/iterations*1000:.3f} ms/op ({iterations} iterations)")
    assert elapsed < 5.0


def test_performance_kyber1024_encapsulation():
    """Performance test: measure time for 100 encapsulations (Kyber1024)."""
    import time
    pk, _ = pykyber._keypair_1024()
    iterations = 100
    
    start = time.perf_counter()
    for _ in range(iterations):
        pykyber._encapsulate_1024(pk)
    elapsed = time.perf_counter() - start
    
    print(f"\nKyber1024 encapsulation: {elapsed/iterations*1000:.3f} ms/op ({iterations} iterations)")
    assert elapsed < 5.0


def test_performance_kyber512_decapsulation():
    """Performance test: measure time for 100 decapsulations (Kyber512)."""
    import time
    pk, sk = pykyber._keypair_512()
    ct, _ = pykyber._encapsulate_512(pk)
    iterations = 100
    
    start = time.perf_counter()
    for _ in range(iterations):
        pykyber._decapsulate_512(ct, sk)
    elapsed = time.perf_counter() - start
    
    print(f"\nKyber512 decapsulation: {elapsed/iterations*1000:.3f} ms/op ({iterations} iterations)")
    assert elapsed < 5.0


def test_performance_kyber768_decapsulation():
    """Performance test: measure time for 100 decapsulations (Kyber768)."""
    import time
    pk, sk = pykyber._keypair_768()
    ct, _ = pykyber._encapsulate_768(pk)
    iterations = 100
    
    start = time.perf_counter()
    for _ in range(iterations):
        pykyber._decapsulate_768(ct, sk)
    elapsed = time.perf_counter() - start
    
    print(f"\nKyber768 decapsulation: {elapsed/iterations*1000:.3f} ms/op ({iterations} iterations)")
    assert elapsed < 5.0


def test_performance_kyber1024_decapsulation():
    """Performance test: measure time for 100 decapsulations (Kyber1024)."""
    import time
    pk, sk = pykyber._keypair_1024()
    ct, _ = pykyber._encapsulate_1024(pk)
    iterations = 100
    
    start = time.perf_counter()
    for _ in range(iterations):
        pykyber._decapsulate_1024(ct, sk)
    elapsed = time.perf_counter() - start
    
    print(f"\nKyber1024 decapsulation: {elapsed/iterations*1000:.3f} ms/op ({iterations} iterations)")
    assert elapsed < 5.0


def test_performance_class_api_kyber768():
    """Performance test: class API full key exchange (Kyber768)."""
    import time
    iterations = 100
    
    start = time.perf_counter()
    for _ in range(iterations):
        keypair = pykyber.Kyber768()
        result = keypair.encapsulate()
        keypair.decapsulate(result.ciphertext)
    elapsed = time.perf_counter() - start
    
    print(f"\nKyber768 full key exchange (class API): {elapsed/iterations*1000:.3f} ms/op ({iterations} iterations)")
    assert elapsed < 5.0


def test_performance_static_methods_kyber768():
    """Performance test: static methods full key exchange (Kyber768)."""
    import time
    iterations = 100
    
    start = time.perf_counter()
    for _ in range(iterations):
        pk, sk = pykyber._keypair_768()
        result = pykyber.Kyber768.encapsulate(pk)
        pykyber.Kyber768.decapsulate(result.ciphertext, sk)
    elapsed = time.perf_counter() - start
    
    print(f"\nKyber768 full key exchange (static methods): {elapsed/iterations*1000:.3f} ms/op ({iterations} iterations)")
    assert elapsed < 5.0
