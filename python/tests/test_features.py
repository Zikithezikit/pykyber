import pykyber
import pytest
import base64


def test_deterministic_keypair():
    """Test that the same seed produces the same keypair."""
    seed = bytes(range(64))
    
    # Kyber-512
    k512_1 = pykyber.Kyber512(seed=seed)
    k512_2 = pykyber.Kyber512(seed=seed)
    assert k512_1.public_key == k512_2.public_key
    assert k512_1.secret_key == k512_2.secret_key
    
    # Kyber-768
    k768_1 = pykyber.Kyber768(seed=seed)
    k768_2 = pykyber.Kyber768(seed=seed)
    assert k768_1.public_key == k768_2.public_key
    assert k768_1.secret_key == k768_2.secret_key
    
    # Kyber-1024
    k1024_1 = pykyber.Kyber1024(seed=seed)
    k1024_2 = pykyber.Kyber1024(seed=seed)
    assert k1024_1.public_key == k1024_2.public_key
    assert k1024_1.secret_key == k1024_2.secret_key


def test_invalid_seed_size():
    """Test that invalid seed size raises KyberError."""
    seed = b"too short"
    with pytest.raises(pykyber.KyberError, match="Invalid seed size"):
        pykyber.Kyber768(seed=seed)


def test_serialization_utilities():
    """Test the hex, base64 and dict serialization properties."""
    k768 = pykyber.Kyber768()
    
    # Keypair serialization
    assert k768.public_key_hex == k768.public_key.hex()
    assert k768.secret_key_hex == k768.secret_key.hex()
    assert k768.public_key_b64 == base64.b64encode(k768.public_key).decode("utf-8")
    assert k768.secret_key_b64 == base64.b64encode(k768.secret_key).decode("utf-8")
    
    d = k768.to_dict()
    assert d["public_key"] == k768.public_key_hex
    assert d["secret_key"] == k768.secret_key_hex
    
    # EncapsulationResult serialization
    res = k768.encapsulate()
    assert res.ciphertext_hex == res.ciphertext.hex()
    assert res.shared_secret_hex == res.shared_secret.hex()
    assert res.ciphertext_b64 == base64.b64encode(res.ciphertext).decode("utf-8")
    assert res.shared_secret_b64 == base64.b64encode(res.shared_secret).decode("utf-8")
    
    rd = res.to_dict()
    assert rd["ciphertext"] == res.ciphertext_hex
    assert rd["shared_secret"] == res.shared_secret_hex


def test_from_keys():
    """Test creating a Keypair from existing keys."""
    k768 = pykyber.Kyber768()
    pk = k768.public_key
    sk = k768.secret_key
    
    k768_new = pykyber.Kyber768.from_keys(pk, sk)
    assert k768_new.public_key == pk
    assert k768_new.secret_key == sk
    
    # Verify it can still decapsulate
    res = k768.encapsulate()
    ss1 = k768.decapsulate(res.ciphertext)
    ss2 = k768_new.decapsulate(res.ciphertext)
    assert ss1 == ss2
