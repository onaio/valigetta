from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_der_public_key


def der_public_key_to_pem(der_bytes: bytes) -> str:
    """Convert a DER-encoded X.509 public key to PEM format.

    :param der_bytes: bytes
    :return: PEM-formatted public key
    """
    try:
        public_key = load_der_public_key(der_bytes)
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pem.decode("utf-8")

    except (ValueError, UnsupportedAlgorithm) as e:
        raise ValueError("Invalid DER-encoded public key") from e
