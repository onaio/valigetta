import base64
from io import BytesIO
from unittest.mock import ANY, MagicMock

import pytest
from Crypto.Cipher import AES

from valigetta.decryptor import _get_submission_iv, decrypt_submission
from valigetta.exceptions import InvalidSubmission


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

    return BytesIO(xml_content.encode("utf-8"))


@pytest.fixture
def fake_aes_key(boto3_kms_client, kms_key):
    """Encrypt a fake AES key with AWS KMS and return it."""
    plaintext_key = b"0123456789abcdef0123456789abcdef"
    response = boto3_kms_client.encrypt(KeyId=kms_key, Plaintext=plaintext_key)
    encrypted_key = response["CiphertextBlob"]
    return plaintext_key, encrypted_key


@pytest.fixture
def encrypt_submission(fake_aes_key):
    def _encrypt(original_data, index):
        plaintext_aes_key, _ = fake_aes_key
        iv = _get_submission_iv(
            "uuid:a10ead67-7415-47da-b823-0947ab8a8ef0", plaintext_aes_key, index=index
        )
        cipher_aes = AES.new(plaintext_aes_key, AES.MODE_CFB, iv=iv, segment_size=128)
        return cipher_aes.encrypt(original_data)

    return _encrypt


def test_decrypt_submission(
    kms_client, kms_key, fake_submission_xml, fake_aes_key, encrypt_submission
):
    """Test decryption of an ODK submission."""
    plaintext_aes_key, _ = fake_aes_key
    kms_client.decrypt_aes_key = MagicMock(return_value=plaintext_aes_key)
    original_data = b"<data>test submission</data>"
    encrypted_data = encrypt_submission(original_data, 0)
    decrypted_data = decrypt_submission(
        kms_client,
        key_id=kms_key,
        submission_xml=fake_submission_xml.read(),
        encrypted_data=[encrypted_data],
    )

    assert list(decrypted_data)[0] == original_data


def test_decrypt_submission_multiple_files(
    kms_client, kms_key, fake_submission_xml, fake_aes_key, encrypt_submission
):
    """KMS decryption is only called once when decrypting multiple files."""
    plaintext_aes_key, _ = fake_aes_key
    kms_client.decrypt_aes_key = MagicMock(return_value=plaintext_aes_key)

    original_files = [b"<data>file1</data>", b"<data>file2</data>"]

    def encrypted_files_generator():
        for index, original_data in enumerate(original_files):
            yield encrypt_submission(original_data, index)

    decrypted_data = list(
        decrypt_submission(
            kms_client,
            key_id=kms_key,
            submission_xml=fake_submission_xml.read(),
            encrypted_data=encrypted_files_generator(),
        )
    )

    assert decrypted_data == original_files

    kms_client.decrypt_aes_key.assert_called_once_with(kms_key, ANY)


def test_decrypt_invalid_xml(kms_client, kms_key, fake_aes_key, encrypt_submission):
    """Invalid XML structure raises an exception"""
    plaintext_aes_key, _ = fake_aes_key
    kms_client.decrypt_aes_key = MagicMock(return_value=plaintext_aes_key)

    original_data = b"<data>test submission</data>"
    encrypted_data = encrypt_submission(original_data, 0)

    invalid_xml = BytesIO(b"invalid xml")

    with pytest.raises(InvalidSubmission) as exc_info:
        list(
            decrypt_submission(
                kms_client,
                key_id=kms_key,
                submission_xml=invalid_xml.read(),
                encrypted_data=[encrypted_data],
            )
        )

    assert (
        str(exc_info.value) == "Invalid XML structure: syntax error: line 1, column 0"
    )

    # instanceID missing
    encrypted_key = base64.b64encode(b"fake-encrypted-key").decode("utf-8")
    encrypted_signature = base64.b64encode(b"fake-encrypted-signature").decode("utf-8")
    xml_content = f"""<?xml version="1.0"?>
    <data encrypted="yes" id="test_valigetta" version="202502131337"
          submissionDate="2025-02-13T13:46:07.458944+00:00"
          xmlns="http://opendatakit.org/submissions">
        <base64EncryptedKey>{encrypted_key}</base64EncryptedKey>
        <media>
            <file>kingfisher.jpeg.enc</file>
        </media>
        <encryptedXmlFile>submission.xml.enc</encryptedXmlFile>
        <base64EncryptedElementSignature>{encrypted_signature}</base64EncryptedElementSignature>
    </data>""".strip()

    with pytest.raises(InvalidSubmission) as exc_info:
        list(
            decrypt_submission(
                kms_client,
                key_id=kms_key,
                submission_xml=BytesIO(xml_content.encode("utf-8")).read(),
                encrypted_data=[encrypted_data],
            )
        )

    assert str(exc_info.value) == "instanceID not found in submission.xml"

    # base64EncryptedKey
    xml_content = f"""<?xml version="1.0"?>
    <data encrypted="yes" id="test_valigetta" version="202502131337"
          instanceID="uuid:a10ead67-7415-47da-b823-0947ab8a8ef0"
          submissionDate="2025-02-13T13:46:07.458944+00:00"
          xmlns="http://opendatakit.org/submissions">
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

    with pytest.raises(InvalidSubmission) as exc_info:
        list(
            decrypt_submission(
                kms_client,
                key_id=kms_key,
                submission_xml=BytesIO(xml_content.encode("utf-8")).read(),
                encrypted_data=[encrypted_data],
            )
        )

    assert (
        str(exc_info.value) == "base64EncryptedKey element not found in submission.xml"
    )
