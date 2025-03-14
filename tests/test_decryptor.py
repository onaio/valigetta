import base64
from io import StringIO
from unittest.mock import MagicMock

import pytest
from Crypto.Cipher import AES

from valigetta.decryptor import _get_submission_iv, decrypt_submission


@pytest.fixture
def fake_submission_xml():
    """Fake submission XML with an encrypted key and signature."""
    encrypted_key = base64.b64encode(b"fake-encrypted-key").decode("utf-8")
    encrypted_signature = base64.b64encode(b"fake-encrypted-signature").decode("utf-8")
    xml_content = f"""<?xml version="1.0"?>
    <data encrypted="yes" id="test_valigetta" version="202502131337"
          instanceID="uuid:a10ead67-7415-47da-b823-0947ab8a8ef0"
          submissionDate="2025-02-13T13:46:07.458944+00:00"
          xmlns="http://opendatakit.org/submissions">
        <base64EncryptedKey>{encrypted_key}</base64EncryptedKey>
        <meta xmlns="http://openrosa.org/xforms">
            <instanceID>uuid:a10ead67-7415-47da-b823-0947ab8a8ef0</instanceID>
        </meta>
        <media>
            <file>kingfisher.jpeg.enc</file>
        </media>
        <encryptedXmlFile>submission.xml.enc</encryptedXmlFile>
        <base64EncryptedElementSignature>{encrypted_signature}</base64EncryptedElementSignature>
    </data>
    """.strip()
    return StringIO(xml_content)


@pytest.fixture
def fake_aes_key(boto3_kms_client, kms_key):
    """Encrypt a fake AES key with AWS KMS and return it."""
    plaintext_key = b"0123456789abcdef0123456789abcdef"
    response = boto3_kms_client.encrypt(KeyId=kms_key, Plaintext=plaintext_key)
    encrypted_key = response["CiphertextBlob"]
    return plaintext_key, encrypted_key


def test_decrypt_submission(kms_client, kms_key, fake_submission_xml, fake_aes_key):
    """Test decryption of an ODK submission."""
    plaintext_aes_key, _ = fake_aes_key

    kms_client.decrypt_aes_key = MagicMock()
    kms_client.decrypt_aes_key.return_value = plaintext_aes_key

    # Generate IV using fake AES key, instanceID, and index 0
    iv = _get_submission_iv(
        "uuid:a10ead67-7415-47da-b823-0947ab8a8ef0", plaintext_aes_key, index=0
    )

    # Encrypt sample data using fake AES key
    cipher_aes = AES.new(plaintext_aes_key, AES.MODE_CFB, iv=iv, segment_size=128)
    original_data = b"<data>test submission</data>"
    encrypted_data = cipher_aes.encrypt(original_data)

    decrypted_data = decrypt_submission(
        kms_client,
        key_id=kms_key,
        submission_xml=fake_submission_xml,
        encrypted_files=[encrypted_data],
    )

    assert decrypted_data[0] == original_data
