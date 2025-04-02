from unittest.mock import Mock


def test_aws_create_key(aws_kms_client):
    """AWSKMSClient create_key successfully returns metadata."""
    response = aws_kms_client.create_key(description="Test KMS key")

    assert "KeyId" in response
    assert "Arn" in response
    assert response["Description"] == "Test KMS key"


def test_aws_decrypt(aws_kms_key, aws_kms_client, boto3_kms_client):
    """AWSKMSClient decrypt decrypts symmetric key."""
    # Generate a new KMS key
    key_id = aws_kms_key

    # Encrypt a test AES key with KMS key
    plaintext_key = b"test-aes-key-1234"
    encrypted_response = boto3_kms_client.encrypt(KeyId=key_id, Plaintext=plaintext_key)
    encrypted_aes_key = encrypted_response["CiphertextBlob"]

    # Decrypt AES key with KSM key
    decrypted_key = aws_kms_client.decrypt(key_id=key_id, ciphertext=encrypted_aes_key)

    assert decrypted_key == plaintext_key


def test_aws_get_public_key(aws_kms_client, aws_kms_key):
    """AWSKMSClient get_public_key returns public key"""
    aws_kms_client.boto3_client.get_public_key = Mock(
        return_value={"PublicKey": b"fake-public-key"}
    )
    response = aws_kms_client.get_public_key(key_id=aws_kms_key)

    assert response == b"fake-public-key"


def test_aws_describe_key(aws_kms_client, aws_kms_key):
    """AWSKMSClient describe_key returns key metadata."""
    response = aws_kms_client.describe_key(key_id=aws_kms_key)

    assert "KeyId" in response
    assert "AWSAccountId" in response


def test_aws_update_key_description(aws_kms_client, aws_kms_key):
    """AWSKMSClient update_key_description updates KMS key description."""
    key_id = aws_kms_key
    aws_kms_client.boto3_client.update_key_description = Mock()
    aws_kms_client.update_key_description(key_id=key_id, description="New description")

    aws_kms_client.boto3_client.update_key_description.assert_called_once_with(
        KeyId=key_id, Description="New description"
    )


def test_aws_disable_key(aws_kms_client, aws_kms_key):
    """AWSKMSClient disable_key disables KMS key."""
    key_id = aws_kms_key
    aws_kms_client.boto3_client.disable_key = Mock()
    aws_kms_client.disable_key(key_id)

    aws_kms_client.boto3_client.disable_key.assert_called_once_with(KeyId=key_id)
