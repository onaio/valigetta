def test_create_key(kms_client):
    """Test that create_key successfully returns metadata."""
    response = kms_client.create_key(description="Test KMS key")

    assert "KeyId" in response
    assert "Arn" in response
    assert response["Description"] == "Test KMS key"


def test_decrypt_aes_key(kms_key, kms_client, boto3_kms_client):
    """Test decrypt_aes_key by encrypting a key and decrypting it back."""
    # Generate a new KMS key
    key_id = kms_key

    # Encrypt a test AES key with KMS key
    plaintext_key = b"test-aes-key-1234"
    encrypted_response = boto3_kms_client.encrypt(KeyId=key_id, Plaintext=plaintext_key)
    encrypted_aes_key = encrypted_response["CiphertextBlob"]

    # Decrypt AES key with KSM key
    decrypted_key = kms_client.decrypt_aes_key(key_id, encrypted_aes_key)

    assert decrypted_key == plaintext_key
