import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from valigetta.utils import der_public_key_to_pem


@pytest.fixture
def rsa_public_key_der():
    """Generate a sample RSA public key in DER format."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def test_der_public_key_to_pem_success(rsa_public_key_der):
    """Valid DER should be converted to PEM format."""
    pem_str = der_public_key_to_pem(rsa_public_key_der)

    assert pem_str.startswith("-----BEGIN PUBLIC KEY-----\n")
    assert pem_str.endswith("-----END PUBLIC KEY-----\n") or pem_str.endswith(
        "-----END PUBLIC KEY-----\n\n"
    )
    assert "-----END PUBLIC KEY-----" in pem_str
    assert isinstance(pem_str, str)
    assert "\n" in pem_str
    assert len(pem_str) > 100


def test_invalid_der():
    """Invalid DER should raise a ValueError."""
    with pytest.raises(ValueError):
        der_public_key_to_pem(b"this-is-not-der")
