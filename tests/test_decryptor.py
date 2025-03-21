import base64
from collections import defaultdict
from io import BytesIO
from unittest.mock import MagicMock

import pytest
from Crypto.Cipher import AES

from valigetta.decryptor import _get_submission_iv, decrypt_submission
from valigetta.exceptions import InvalidSubmission


@pytest.fixture
def fake_aes_key(boto3_kms_client, aws_kms_key):
    """Encrypt a fake AES key with AWS KMS and return it."""
    plaintext_key = b"0123456789abcdef0123456789abcdef"
    response = boto3_kms_client.encrypt(KeyId=aws_kms_key, Plaintext=plaintext_key)
    encrypted_key = response["CiphertextBlob"]
    return plaintext_key, encrypted_key


@pytest.fixture
def fake_submission_xml(fake_aes_key):
    """Fake submission XML with an encrypted key and signature."""
    _, fake_encrypted_key = fake_aes_key
    encrypted_key = base64.b64encode(fake_encrypted_key).decode("utf-8")
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
def encrypt_submission(fake_aes_key):
    def _encrypt(original_data, index):
        plaintext_aes_key, _ = fake_aes_key
        iv = _get_submission_iv(
            "uuid:a10ead67-7415-47da-b823-0947ab8a8ef0", plaintext_aes_key, index=index
        )
        cipher_aes = AES.new(plaintext_aes_key, AES.MODE_CFB, iv=iv, segment_size=128)
        return BytesIO(cipher_aes.encrypt(original_data))

    return _encrypt


def test_decrypt_submission(
    aws_kms_client, aws_kms_key, fake_submission_xml, fake_aes_key, encrypt_submission
):
    """Test decryption of an ODK submission."""
    plaintext_aes_key, fake_encrypted_key = fake_aes_key
    aws_kms_client.decrypt_aes_key = MagicMock(return_value=plaintext_aes_key)
    original_data = b"<data>test submission</data>"
    file_index = 0
    encrypted_file = encrypt_submission(original_data, file_index)
    aws_kms_client.key_id = aws_kms_key
    decrypted_files = defaultdict(bytearray)

    for index, chunk in decrypt_submission(
        aws_kms_client,
        submission_xml=fake_submission_xml,
        encrypted_files=[(file_index, encrypted_file)],
    ):
        decrypted_files[index].extend(chunk)

    assert decrypted_files[0] == original_data

    aws_kms_client.decrypt_aes_key.assert_called_once_with(fake_encrypted_key)


def test_decrypt_submission_multiple_files(
    aws_kms_client, aws_kms_key, fake_submission_xml, fake_aes_key, encrypt_submission
):
    """KMS decryption is only called once when decrypting multiple files."""
    plaintext_aes_key, fake_encrypted_key = fake_aes_key
    aws_kms_client.decrypt_aes_key = MagicMock(return_value=plaintext_aes_key)

    original_data = [b"<data>file1</data>", b"<data>file2</data>"]

    def encrypted_files_generator():
        for index, datum in enumerate(original_data):
            yield index, encrypt_submission(datum, index)

    aws_kms_client.key_id = aws_kms_key

    decrypted_files = defaultdict(bytearray)

    for index, chunk in decrypt_submission(
        aws_kms_client,
        submission_xml=fake_submission_xml,
        encrypted_files=encrypted_files_generator(),
    ):
        decrypted_files[index].extend(chunk)

    assert decrypted_files[0] == original_data[0]
    assert decrypted_files[1] == original_data[1]

    aws_kms_client.decrypt_aes_key.assert_called_once_with(fake_encrypted_key)


def test_decrypt_invalid_xml(
    aws_kms_client, aws_kms_key, fake_aes_key, encrypt_submission
):
    """Invalid XML structure raises an exception"""
    plaintext_aes_key, _ = fake_aes_key
    aws_kms_client.key_id = aws_kms_key
    aws_kms_client.decrypt_aes_key = MagicMock(return_value=plaintext_aes_key)

    original_data = b"<data>test submission</data>"
    encrypted_file = encrypt_submission(original_data, 0)
    encrypted_files = [(0, encrypted_file)]

    with pytest.raises(InvalidSubmission) as exc_info:
        list(
            decrypt_submission(
                aws_kms_client,
                submission_xml=BytesIO(b"invalid xml"),
                encrypted_files=encrypted_files,
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
                aws_kms_client,
                submission_xml=BytesIO(xml_content.encode("utf-8")),
                encrypted_files=[encrypted_file],
            )
        )

    assert str(exc_info.value) == "instanceID not found in submission.xml"

    # base64EncryptedKey missing
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
                aws_kms_client,
                submission_xml=BytesIO(xml_content.encode("utf-8")),
                encrypted_files=[encrypted_file],
            )
        )

    assert (
        str(exc_info.value) == "base64EncryptedKey element not found in submission.xml"
    )


def test_decrypt_large_file(
    aws_kms_client, aws_kms_key, fake_submission_xml, fake_aes_key, encrypt_submission
):
    """A file larger than 4KB is decrypted correctly."""
    plaintext_aes_key, fake_encrypted_key = fake_aes_key
    aws_kms_client.key_id = aws_kms_key
    aws_kms_client.decrypt_aes_key = MagicMock(return_value=plaintext_aes_key)

    # 10KB, 1MB of data files
    original_data = [b"A" * 10 * 1024, b"B" * 1024 * 1024]

    def encrypted_files_generator():
        for index, datum in enumerate(original_data):
            yield index, encrypt_submission(datum, index)

    decrypted_files = defaultdict(bytearray)

    for index, chunk in decrypt_submission(
        aws_kms_client,
        submission_xml=fake_submission_xml,
        encrypted_files=encrypted_files_generator(),
    ):
        decrypted_files[index].extend(chunk)

    # Verify that the entire file was decrypted correctly
    assert decrypted_files[0] == original_data[0]
    assert decrypted_files[1] == original_data[1]

    aws_kms_client.decrypt_aes_key.assert_called_once_with(fake_encrypted_key)
