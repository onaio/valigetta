import pytest


def test_aws_create_key(aws_kms_client):
    """AWS client create_key successfully returns metadata."""
    response = aws_kms_client.create_key(description="Test KMS key")

    assert "KeyId" in response
    assert "Arn" in response
    assert response["Description"] == "Test KMS key"


def test_aws_decrypt_aes_key(aws_kms_key, aws_kms_client, boto3_kms_client):
    """AWS client decrypt_aes_key decrypts symmetric key."""
    # Generate a new KMS key
    key_id = aws_kms_key
    aws_kms_client.key_id = key_id  # Set key_id

    # Encrypt a test AES key with KMS key
    plaintext_key = b"test-aes-key-1234"
    encrypted_response = boto3_kms_client.encrypt(KeyId=key_id, Plaintext=plaintext_key)
    encrypted_aes_key = encrypted_response["CiphertextBlob"]

    # Decrypt AES key with KSM key
    decrypted_key = aws_kms_client.decrypt_aes_key(encrypted_aes_key)

    assert decrypted_key == plaintext_key


def test_aws_decrypt_key_required(aws_kms_key, aws_kms_client, boto3_kms_client):
    """AWS client decrypt_aes_key requires key_id"""
    # Encrypt a test AES key with KMS key
    plaintext_key = b"test-aes-key-1234"
    encrypted_response = boto3_kms_client.encrypt(
        KeyId=aws_kms_key, Plaintext=plaintext_key
    )
    encrypted_aes_key = encrypted_response["CiphertextBlob"]

    with pytest.raises(ValueError) as exc_info:
        aws_kms_client.decrypt_aes_key(encrypted_aes_key)

    assert str(exc_info.value) == "A key_id must be provided for decryption."
