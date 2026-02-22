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
    assert "Invalid input for 'pk'" in str(exc_info.value)


def test_invalid_ciphertext_length_raises_error():
    """Test that invalid ciphertext length raises KyberError."""
    sk = bytes(2400)
    with pytest.raises(pykyber.KyberError) as exc_info:
        pykyber._decapsulate(b"short", sk)
    assert "Invalid input for 'ct'" in str(exc_info.value)


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
    assert "Invalid input for 'pk'" in str(exc_info.value)


def test_empty_ciphertext_raises_error():
    """Test that empty ciphertext raises KyberError."""
    pk, sk = pykyber._generate_keypair()
    with pytest.raises(pykyber.KyberError) as exc_info:
        pykyber._decapsulate(b"", sk)
    assert "Invalid input for 'ct'" in str(exc_info.value)


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
    assert "Invalid input for 'pk'" in str(exc_info.value)


def test_kyber512_invalid_public_key_length():
    """Test Kyber512 with invalid public key length."""
    with pytest.raises(pykyber.KyberError) as exc_info:
        pykyber._encapsulate_512(b"short")
    assert "Invalid input for 'pk'" in str(exc_info.value)


def test_kyber512_invalid_ciphertext_length():
    """Test Kyber512 with invalid ciphertext length."""
    sk = bytes(1632)
    with pytest.raises(pykyber.KyberError) as exc_info:
        pykyber._decapsulate_512(b"short", sk)
    assert "Invalid input for 'ct'" in str(exc_info.value)


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
    assert "Invalid input for 'pk'" in str(exc_info.value)


def test_kyber1024_invalid_ciphertext_length():
    """Test Kyber1024 with invalid ciphertext length."""
    sk = bytes(3168)
    with pytest.raises(pykyber.KyberError) as exc_info:
        pykyber._decapsulate_1024(b"short", sk)
    assert "Invalid input for 'ct'" in str(exc_info.value)


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
    assert "Invalid input for 'pk'" in str(exc_info.value)
    assert "800" in str(exc_info.value)
    assert "799" in str(exc_info.value)


def test_boundary_public_key_length_768():
    """Test with Kyber768 public key that's 1 byte too short."""
    pk, _ = pykyber._keypair_768()
    short_pk = pk[:-1]
    with pytest.raises(pykyber.KyberError) as exc_info:
        pykyber._encapsulate(short_pk)
    assert "Invalid input for 'pk'" in str(exc_info.value)
    assert "1184" in str(exc_info.value)
    assert "1183" in str(exc_info.value)


def test_boundary_public_key_length_1024():
    """Test with Kyber1024 public key that's 1 byte too short."""
    pk, _ = pykyber._keypair_1024()
    short_pk = pk[:-1]
    with pytest.raises(pykyber.KyberError) as exc_info:
        pykyber._encapsulate_1024(short_pk)
    assert "Invalid input for 'pk'" in str(exc_info.value)
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
    assert "Invalid input for 'ct'" in str(exc_info.value)


def test_boundary_ciphertext_length_768():
    """Test with Kyber768 ciphertext that's 1 byte too short."""
    pk, sk = pykyber._generate_keypair()
    ct, _ = pykyber._encapsulate(pk)
    short_ct = ct[:-1]
    with pytest.raises(pykyber.KyberError) as exc_info:
        pykyber._decapsulate(short_ct, sk)
    assert "Invalid input for 'ct'" in str(exc_info.value)


def test_boundary_ciphertext_length_1024():
    """Test with Kyber1024 ciphertext that's 1 byte too short."""
    pk, sk = pykyber._keypair_1024()
    ct, _ = pykyber._encapsulate_1024(pk)
    short_ct = ct[:-1]
    with pytest.raises(pykyber.KyberError) as exc_info:
        pykyber._decapsulate_1024(short_ct, sk)
    assert "Invalid input for 'ct'" in str(exc_info.value)


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
    assert "pk" in msg
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
    assert "Invalid input" in result
    
    pk, _ = pykyber._generate_keypair()
    result = safe_encapsulate(pk)
    ct, ss = result
    assert len(ct) == 1088
    assert len(ss) == 32
