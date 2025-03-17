def test_aws_create_key(aws_kms_client):
    """AWS KMS client create_key successfully returns metadata."""
    response = aws_kms_client.create_key(description="Test KMS key")

    assert "KeyId" in response
    assert "Arn" in response
    assert response["Description"] == "Test KMS key"


def test_aws_decrypt_aes_key(aws_kms_key, aws_kms_client, boto3_kms_client):
    """AWS KMS client decrypt_aes_key decrypts symmetric key."""
    # Generate a new KMS key
    key_id = aws_kms_key

    # Encrypt a test AES key with KMS key
    plaintext_key = b"test-aes-key-1234"
    encrypted_response = boto3_kms_client.encrypt(KeyId=key_id, Plaintext=plaintext_key)
    encrypted_aes_key = encrypted_response["CiphertextBlob"]

    # Decrypt AES key with KSM key
    decrypted_key = aws_kms_client.decrypt_aes_key(key_id, encrypted_aes_key)

    assert decrypted_key == plaintext_key
