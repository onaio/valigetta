import base64
import hashlib
import xml.etree.ElementTree as ET
from io import BytesIO
from unittest.mock import MagicMock, call

import pytest
from Crypto.Cipher import AES

from valigetta.decryptor import (
    _get_submission_iv,
    decrypt_file,
    decrypt_submission,
    extract_encrypted_aes_key,
    extract_encrypted_media_file_names,
    extract_encrypted_signature,
    extract_encrypted_submission_file_name,
    extract_form_id,
    extract_instance_id,
    extract_version,
    is_submission_valid,
)
from valigetta.exceptions import InvalidSubmission


@pytest.fixture
def fake_aes_key(boto3_kms_client, aws_kms_key):
    """Encrypt a fake AES key with AWS KMS and return it."""
    plaintext_key = b"0123456789abcdef0123456789abcdef"
    response = boto3_kms_client.encrypt(KeyId=aws_kms_key, Plaintext=plaintext_key)
    encrypted_key = response["CiphertextBlob"]
    return plaintext_key, encrypted_key


@pytest.fixture
def fake_decrypted_media():
    """Fake decrypted media files for submission."""
    return {
        "sunset.png": BytesIO(b"Fake PNG image data"),
        "forest.mp4": BytesIO(b"Fake MP4 video data"),
    }


@pytest.fixture
def fake_decrypted_submission():
    """Fake decrypted XML content for the submission."""
    xml_content = """<?xml version="1.0"?>
    <data id="test_valigetta" version="202502131337"
          instanceID="uuid:a10ead67-7415-47da-b823-0947ab8a8ef0"
          xmlns="http://opendatakit.org/submissions">
        <meta xmlns="http://openrosa.org/xforms">
            <instanceID>uuid:a10ead67-7415-47da-b823-0947ab8a8ef0</instanceID>
        </meta>
        <media>
            <file>sunset.png</file>
            <file>forest.mp4</file>
        </media>
    </data>
    """.strip()

    return BytesIO(xml_content.encode("utf-8"))


@pytest.fixture
def fake_signature(
    boto3_kms_client,
    aws_kms_key,
    fake_aes_key,
    fake_decrypted_submission,
    fake_decrypted_media,
):
    """Generate an encrypted signature using AWS KMS."""

    def get_md5_hash_from_file(file: BytesIO) -> str:
        """Computes the MD5 hash of a file's content."""
        file.seek(0)
        return hashlib.md5(file.read()).hexdigest().zfill(32)

    def compute_digest(message: str) -> bytes:
        """Computes the MD5 digest of the given message (UTF-8 encoded)."""
        return hashlib.md5(message.encode("utf-8")).digest()

    _, fake_encrypted_key = fake_aes_key

    signature_parts = [
        "test_valigetta",
        "202502131337",
        base64.b64encode(fake_encrypted_key).decode("utf-8"),
        "uuid:a10ead67-7415-47da-b823-0947ab8a8ef0",
    ]

    # Add media files
    for media_name, media_file in fake_decrypted_media.items():
        submission_md5_hash = get_md5_hash_from_file(media_file)
        signature_parts.append(f"{media_name}::{submission_md5_hash}")

    # Add submission file
    submission_md5_hash = get_md5_hash_from_file(fake_decrypted_submission)
    signature_parts.append(f"submission.xml::{submission_md5_hash}")
    # Construct final signature string
    signature_data = "\n".join(signature_parts) + "\n"
    # Compute MD5 digest before encrypting
    signature_md5_digest = compute_digest(signature_data)
    # Encrypt MD5 digest
    response = boto3_kms_client.encrypt(
        KeyId=aws_kms_key, Plaintext=signature_md5_digest
    )

    return response["CiphertextBlob"]


@pytest.fixture
def fake_submission_xml(fake_aes_key, fake_signature):
    """Fake submission XML with an encrypted key and signature."""
    _, fake_encrypted_key = fake_aes_key
    encrypted_key_b64 = base64.b64encode(fake_encrypted_key).decode("utf-8")
    encrypted_signature_b64 = base64.b64encode(fake_signature).decode("utf-8")

    xml_content = f"""<?xml version="1.0"?>
    <data encrypted="yes" id="test_valigetta" version="202502131337"
          instanceID="uuid:a10ead67-7415-47da-b823-0947ab8a8ef0"
          submissionDate="2025-02-13T13:46:07.458944+00:00"
          xmlns="http://opendatakit.org/submissions">
        <base64EncryptedKey>{encrypted_key_b64}</base64EncryptedKey>
        <meta xmlns="http://openrosa.org/xforms">
            <instanceID>uuid:a10ead67-7415-47da-b823-0947ab8a8ef0</instanceID>
        </meta>
        <media>
            <file>sunset.png.enc</file>
            <file>forest.mp4.enc</file>
        </media>
        <encryptedXmlFile>submission.xml.enc</encryptedXmlFile>
        <base64EncryptedElementSignature>{encrypted_signature_b64}</base64EncryptedElementSignature>
    </data>
    """.strip()

    return BytesIO(xml_content.encode("utf-8"))


@pytest.fixture
def encrypt_submission(fake_aes_key):
    def _encrypt(original_data, iv_counter):
        plaintext_aes_key, _ = fake_aes_key
        iv = _get_submission_iv(
            "uuid:a10ead67-7415-47da-b823-0947ab8a8ef0",
            plaintext_aes_key,
            iv_counter=iv_counter,
        )
        cipher_aes = AES.new(plaintext_aes_key, AES.MODE_CFB, iv=iv, segment_size=128)
        return BytesIO(cipher_aes.encrypt(original_data))

    return _encrypt


@pytest.fixture
def fake_decrypted_files(fake_decrypted_submission, fake_decrypted_media):
    return {"submission.xml": fake_decrypted_submission, **fake_decrypted_media}


@pytest.fixture
def fake_submission_tree(fake_submission_xml):
    fake_submission_xml.seek(0)
    return ET.fromstring(fake_submission_xml.read())


@pytest.fixture
def fake_encrypted_files(
    encrypt_submission, fake_decrypted_submission, fake_decrypted_media
):
    return {
        "forest.mp4.enc": encrypt_submission(
            fake_decrypted_media["forest.mp4"].getvalue(), 2
        ),
        "sunset.png.enc": encrypt_submission(
            fake_decrypted_media["sunset.png"].getvalue(), 1
        ),
        "submission.xml.enc": encrypt_submission(
            fake_decrypted_submission.getvalue(), 3
        ),
    }


def test_decrypt_submission(
    aws_kms_client,
    aws_kms_key,
    fake_submission_xml,
    fake_decrypted_files,
    fake_encrypted_files,
):
    """Decryption of an ODK submission."""
    for dec_file_name, dec_file in decrypt_submission(
        kms_client=aws_kms_client,
        key_id=aws_kms_key,
        submission_xml=fake_submission_xml,
        enc_files=fake_encrypted_files,
    ):
        assert dec_file.getvalue() == fake_decrypted_files[dec_file_name].getvalue()


def test_corrupted_submission(
    aws_kms_client,
    aws_kms_key,
    fake_submission_xml,
    fake_decrypted_submission,
    fake_decrypted_media,
    encrypt_submission,
):
    """Corrupt data is handled."""
    # All have an initialization vector of 0
    enc_files = {
        "submission.xml.enc": encrypt_submission(
            fake_decrypted_submission.getvalue(), 0
        ),
        "sunset.png.enc": encrypt_submission(
            fake_decrypted_media["sunset.png"].getvalue(), 0
        ),
        "forest.mp4.enc": encrypt_submission(
            fake_decrypted_media["forest.mp4"].getvalue(), 0
        ),
    }

    with pytest.raises(InvalidSubmission) as exc_info:
        list(
            decrypt_submission(
                kms_client=aws_kms_client,
                key_id=aws_kms_key,
                submission_xml=fake_submission_xml,
                enc_files=enc_files,
            )
        )

    assert str(exc_info.value) == (
        "Submission validation failed for instance ID "
        "uuid:a10ead67-7415-47da-b823-0947ab8a8ef0. "
        "Corrupted data or incorrect signature"
    )


def test_kms_decrypt_called_twice(
    aws_kms_client,
    aws_kms_key,
    fake_submission_xml,
    fake_aes_key,
    fake_encrypted_files,
    fake_signature,
):
    """KMSClient decrypt call is called twice

    1st call decrypts AES key
    2nd call decrypts signature
    """
    key_id = aws_kms_key
    plaintext_key, fake_encrypted_key = fake_aes_key
    aws_kms_client.decrypt = MagicMock(return_value=plaintext_key)

    try:
        list(
            decrypt_submission(
                kms_client=aws_kms_client,
                key_id=key_id,
                submission_xml=fake_submission_xml,
                enc_files=fake_encrypted_files,
            )
        )

    except InvalidSubmission:
        pass

    calls = [
        call(key_id=key_id, ciphertext=fake_encrypted_key),
        call(key_id=key_id, ciphertext=fake_signature),
    ]
    aws_kms_client.decrypt.assert_has_calls(calls)


def test_extract_instance_id(fake_submission_tree):
    """Extract of instanceID from submission XML is successful."""
    instance_id = extract_instance_id(fake_submission_tree)

    assert instance_id == "uuid:a10ead67-7415-47da-b823-0947ab8a8ef0"

    # Missing instanceID
    with pytest.raises(InvalidSubmission) as exc_info:
        extract_instance_id(ET.fromstring(b"<data>hello</data>"))

    assert str(exc_info.value) == "instanceID not found in submission.xml"


def test_extract_encrypted_aes_key(fake_submission_tree, fake_aes_key):
    """Extraction of encrypted AES key from submission XML is successful."""
    _, fake_encrypted_key = fake_aes_key
    enc_aes_key = extract_encrypted_aes_key(fake_submission_tree)

    assert enc_aes_key == base64.b64encode(fake_encrypted_key).decode("utf-8")

    # Missing encrypted AES key
    with pytest.raises(InvalidSubmission) as exc_info:
        extract_encrypted_aes_key(ET.fromstring(b"<data>hello</data>"))

    assert (
        str(exc_info.value) == "base64EncryptedKey element not found in submission.xml"
    )


def test_decrypt_file(fake_aes_key, encrypt_submission):
    """Decrypting a single file works."""
    plaintext_aes_key, _ = fake_aes_key
    original_data = b"A" * 10 * 1024  # 10KB of 'A' characters
    enc_file = encrypt_submission(original_data, 1)
    dec_file = decrypt_file(
        enc_file, plaintext_aes_key, "uuid:a10ead67-7415-47da-b823-0947ab8a8ef0", 1
    )

    assert dec_file == original_data


def test_extract_encrypted_signature(fake_submission_tree, fake_signature):
    """Extraction of encrypted signature is successful."""
    enc_signature = extract_encrypted_signature(fake_submission_tree)

    assert enc_signature == base64.b64encode(fake_signature).decode("utf-8")

    # Missing signature
    with pytest.raises(InvalidSubmission) as exc_info:
        extract_encrypted_signature(ET.fromstring(b"<data>hello</data>"))

    assert (
        str(exc_info.value)
        == "base64EncryptedElementSignature element not found in submission.xml"
    )


def test_extract_encrypted_xml_file_name(fake_submission_tree):
    """Extraction of encrypted xml file name is successful."""
    enc_xml_file_name = extract_encrypted_submission_file_name(fake_submission_tree)

    assert enc_xml_file_name == "submission.xml.enc"

    # Missing xml file name
    with pytest.raises(InvalidSubmission) as exc_info:
        extract_encrypted_submission_file_name(ET.fromstring(b"<data>hello</data>"))

    assert str(exc_info.value) == "encryptedXmlFile element not found in submission.xml"


def test_extract_form_id(fake_submission_tree):
    """Extraction of submission's form id is successful."""
    form_id = extract_form_id(fake_submission_tree)

    assert form_id == "test_valigetta"

    # Missing form id
    with pytest.raises(InvalidSubmission) as exc_info:
        extract_form_id(ET.fromstring(b"<data>hello</data>"))

    assert str(exc_info.value) == "Form ID not found in submission.xml"


def test_extract_version(fake_submission_tree):
    """Extraction of submission's version is successful."""
    version = extract_version(fake_submission_tree)

    assert version == "202502131337"

    # Missing version
    with pytest.raises(InvalidSubmission) as exc_info:
        extract_version(ET.fromstring(b"<data>hello</data>"))

    assert str(exc_info.value) == "version not found in submission.xml"


def test_extract_media_file_names(fake_submission_tree):
    """Extraction of media file names is successful."""
    media_file_names = extract_encrypted_media_file_names(fake_submission_tree)

    assert media_file_names == ["sunset.png.enc", "forest.mp4.enc"]

    # Missing media
    media_file_names = extract_encrypted_media_file_names(
        ET.fromstring(b"<data>hello</data>")
    )

    assert len(media_file_names) == 0


def test_is_submssion_valid(
    aws_kms_client,
    fake_submission_tree,
    fake_decrypted_files,
    aws_kms_key,
    fake_aes_key,
):
    """Is valid check for decrypted submission contents works."""
    key_id = aws_kms_key

    assert is_submission_valid(
        kms_client=aws_kms_client,
        key_id=key_id,
        tree=fake_submission_tree,
        dec_files=list(fake_decrypted_files.items()),
    )

    # Corrupted file
    assert not is_submission_valid(
        kms_client=aws_kms_client,
        key_id=key_id,
        tree=fake_submission_tree,
        dec_files=list(
            {**fake_decrypted_files, "sunset.png": BytesIO(b"corrupted sunset")}.items()
        ),
    )

    # Signature mismatch
    _, fake_encrypted_key = fake_aes_key
    enc_key_b64 = base64.b64encode(fake_encrypted_key).decode("utf-8")
    enc_signature_b64 = base64.b64encode(b"different-signature").decode("utf-8")
    submission_xml = f"""<?xml version="1.0"?>
    <data encrypted="yes" id="test_valigetta" version="202502131337"
          instanceID="uuid:a10ead67-7415-47da-b823-0947ab8a8ef0"
          submissionDate="2025-02-13T13:46:07.458944+00:00"
          xmlns="http://opendatakit.org/submissions">
        <base64EncryptedKey>{enc_key_b64}</base64EncryptedKey>
        <meta xmlns="http://openrosa.org/xforms">
            <instanceID>uuid:a10ead67-7415-47da-b823-0947ab8a8ef0</instanceID>
        </meta>
        <media>
            <file>sunset.png.enc</file>
            <file>forest.mp4.enc</file>
        </media>
        <encryptedXmlFile>submission.xml.enc</encryptedXmlFile>
        <base64EncryptedElementSignature>{enc_signature_b64}</base64EncryptedElementSignature>
    </data>
    """.strip()

    dec_files = list(fake_decrypted_files.items())
    dec_files[0] = ("submission.xml", BytesIO(submission_xml.encode("utf-8")))

    assert not is_submission_valid(
        kms_client=aws_kms_client,
        key_id=key_id,
        tree=fake_submission_tree,
        dec_files=dec_files,
    )


def test_decrypt_submission_with_missing_media_file(
    aws_kms_client, aws_kms_key, fake_submission_xml, fake_encrypted_files
):
    """Decrypt submission with missing files raises an error."""
    fake_encrypted_files.pop("forest.mp4.enc")

    with pytest.raises(InvalidSubmission) as exc_info:
        list(
            decrypt_submission(
                aws_kms_client, aws_kms_key, fake_submission_xml, fake_encrypted_files
            )
        )

    assert str(exc_info.value) == (
        "Failed to validate submission: Media file forest.mp4.enc "
        "not found in provided files."
    )


def test_decrypt_submission_with_missing_submission_file(
    aws_kms_client, aws_kms_key, fake_submission_xml, fake_encrypted_files
):
    """Decrypt submission with missing submission file raises an error."""
    fake_encrypted_files.pop("submission.xml.enc")

    with pytest.raises(InvalidSubmission) as exc_info:
        list(
            decrypt_submission(
                aws_kms_client, aws_kms_key, fake_submission_xml, fake_encrypted_files
            )
        )

    assert str(exc_info.value) == (
        "Failed to validate submission: Submission file submission.xml.enc "
        "not found in provided files."
    )
