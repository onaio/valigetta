import base64
from datetime import datetime
from unittest.mock import Mock, call, patch

import pytest
import requests
from botocore.exceptions import BotoCoreError, ClientError

from valigetta.exceptions import (
    KMSCreateAliasError,
    KMSDecryptionError,
    KMSDeleteAliasError,
    KMSDescribeKeyError,
    KMSDisableKeyError,
    KMSGetPublicKeyError,
    KMSInvalidAPIURLsError,
    KMSKeyCreationError,
    KMSUpdateKeyDescriptionError,
)
from valigetta.kms import APIKMSClient


def test_aws_create_key(aws_kms_client):
    """AWSKMSClient create_key successfully returns metadata."""
    response = aws_kms_client.create_key(description="Test KMS key")

    assert "key_id" in response
    assert response["description"] == "Test KMS key"
    assert "creation_date" in response
    parsed_date = datetime.fromisoformat(response["creation_date"])
    assert parsed_date.tzinfo is not None

    # ClientError is handled
    with pytest.raises(KMSKeyCreationError) as exc_info:
        aws_kms_client.boto3_client.create_key = Mock()
        aws_kms_client.boto3_client.create_key.side_effect = ClientError(
            {"Error": {"Code": "test-error"}}, "test-error"
        )
        aws_kms_client.create_key(description="Test KMS key")

    assert "Failed to create key" in str(exc_info.value)

    # BotoCoreError is handled
    with pytest.raises(KMSKeyCreationError) as exc_info:
        aws_kms_client.boto3_client.create_key = Mock()
        aws_kms_client.boto3_client.create_key.side_effect = BotoCoreError()
        aws_kms_client.create_key(description="Test KMS key")

    assert "Failed to create key" in str(exc_info.value)


def test_aws_decrypt(aws_kms_key, aws_kms_client, boto3_kms_client):
    """AWSKMSClient decrypt decrypts encrypted data."""
    # Generate a new KMS key
    key_id = aws_kms_key

    # Encrypt a test AES key with KMS key
    plaintext_key = b"test-aes-key-1234"
    encrypted_response = boto3_kms_client.encrypt(KeyId=key_id, Plaintext=plaintext_key)
    encrypted_aes_key = encrypted_response["CiphertextBlob"]

    # Decrypt AES key with KSM key
    decrypted_key = aws_kms_client.decrypt(key_id=key_id, ciphertext=encrypted_aes_key)

    assert decrypted_key == plaintext_key

    # ClientError is handled
    with pytest.raises(KMSDecryptionError) as exc_info:
        aws_kms_client.boto3_client.decrypt = Mock()
        aws_kms_client.boto3_client.decrypt.side_effect = ClientError(
            {"Error": {"Code": "test-error"}}, "test-error"
        )
        aws_kms_client.decrypt(key_id=key_id, ciphertext=encrypted_aes_key)

    assert "Failed to decrypt" in str(exc_info.value)

    # BotoCoreError is handled
    with pytest.raises(KMSDecryptionError) as exc_info:
        aws_kms_client.boto3_client.decrypt = Mock()
        aws_kms_client.boto3_client.decrypt.side_effect = BotoCoreError()
        aws_kms_client.decrypt(key_id=key_id, ciphertext=encrypted_aes_key)

    assert "Failed to decrypt" in str(exc_info.value)


def test_aws_get_public_key(aws_kms_client, aws_kms_key):
    """AWSKMSClient get_public_key returns PEM-formatted public key."""
    pem_str = aws_kms_client.get_public_key(key_id=aws_kms_key)

    assert isinstance(pem_str, str)
    assert pem_str.startswith("-----BEGIN PUBLIC KEY-----\n")
    assert pem_str.endswith("-----END PUBLIC KEY-----\n") or pem_str.endswith(
        "-----END PUBLIC KEY-----\n\n"
    )

    # ClientError is handled
    with pytest.raises(KMSGetPublicKeyError) as exc_info:
        aws_kms_client.boto3_client.get_public_key = Mock()
        aws_kms_client.boto3_client.get_public_key.side_effect = ClientError(
            {"Error": {"Code": "test-error"}}, "test-error"
        )
        aws_kms_client.get_public_key(key_id=aws_kms_key)

    assert "Failed to get public key" in str(exc_info.value)

    # BotoCoreError is handled
    with pytest.raises(KMSGetPublicKeyError) as exc_info:
        aws_kms_client.boto3_client.get_public_key = Mock()
        aws_kms_client.boto3_client.get_public_key.side_effect = BotoCoreError()
        aws_kms_client.get_public_key(key_id=aws_kms_key)

    assert "Failed to get public key" in str(exc_info.value)


def test_aws_describe_key(aws_kms_client, aws_kms_key):
    """AWSKMSClient describe_key returns key metadata."""
    response = aws_kms_client.describe_key(key_id=aws_kms_key)

    assert "key_id" in response
    assert "description" in response
    assert "creation_date" in response
    assert "enabled" in response

    # ClientError is handled
    with pytest.raises(KMSDescribeKeyError) as exc_info:
        aws_kms_client.boto3_client.describe_key = Mock()
        aws_kms_client.boto3_client.describe_key.side_effect = ClientError(
            {"Error": {"Code": "test-error"}}, "test-error"
        )
        aws_kms_client.describe_key(key_id=aws_kms_key)

    assert "Failed to describe key" in str(exc_info.value)

    # BotoCoreError is handled
    with pytest.raises(KMSDescribeKeyError) as exc_info:
        aws_kms_client.boto3_client.describe_key = Mock()
        aws_kms_client.boto3_client.describe_key.side_effect = BotoCoreError()
        aws_kms_client.describe_key(key_id=aws_kms_key)

    assert "Failed to describe key" in str(exc_info.value)


def test_aws_update_key_description(aws_kms_client, aws_kms_key):
    """AWSKMSClient update_key_description updates KMS key description."""
    key_id = aws_kms_key
    aws_kms_client.boto3_client.update_key_description = Mock()
    aws_kms_client.update_key_description(key_id=key_id, description="New description")

    aws_kms_client.boto3_client.update_key_description.assert_called_once_with(
        KeyId=key_id, Description="New description"
    )

    # ClientError is handled
    with pytest.raises(KMSUpdateKeyDescriptionError) as exc_info:
        aws_kms_client.boto3_client.update_key_description.side_effect = ClientError(
            {"Error": {"Code": "test-error"}}, "test-error"
        )
        aws_kms_client.update_key_description(
            key_id=key_id, description="New description"
        )

    assert "Failed to update key description" in str(exc_info.value)

    # BotoCoreError is handled
    with pytest.raises(KMSUpdateKeyDescriptionError) as exc_info:
        aws_kms_client.boto3_client.update_key_description.side_effect = BotoCoreError()
        aws_kms_client.update_key_description(
            key_id=key_id, description="New description"
        )

    assert "Failed to update key description" in str(exc_info.value)


def test_aws_disable_key(aws_kms_client, aws_kms_key):
    """AWSKMSClient disable_key disables KMS key."""
    key_id = aws_kms_key
    aws_kms_client.boto3_client.disable_key = Mock()
    aws_kms_client.disable_key(key_id)

    aws_kms_client.boto3_client.disable_key.assert_called_once_with(KeyId=key_id)

    # ClientError is handled
    with pytest.raises(KMSDisableKeyError) as exc_info:
        aws_kms_client.boto3_client.disable_key.side_effect = ClientError(
            {"Error": {"Code": "test-error"}}, "test-error"
        )
        aws_kms_client.disable_key(key_id)

    assert "Failed to disable key" in str(exc_info.value)

    # BotoCoreError is handled
    with pytest.raises(KMSDisableKeyError) as exc_info:
        aws_kms_client.boto3_client.disable_key.side_effect = BotoCoreError()
        aws_kms_client.disable_key(key_id)

    assert "Failed to disable key" in str(exc_info.value)


def test_aws_create_alias(aws_kms_client, aws_kms_key):
    """AWSKMSClient create_alias creates an alias for a KMS key."""
    alias_name = "test-alias"
    aws_kms_client.boto3_client.create_alias = Mock()
    aws_kms_client.create_alias(alias_name=alias_name, key_id=aws_kms_key)

    aws_kms_client.boto3_client.create_alias.assert_called_once_with(
        AliasName=alias_name, TargetKeyId=aws_kms_key
    )

    # ClientError is handled
    with pytest.raises(KMSCreateAliasError) as exc_info:
        aws_kms_client.boto3_client.create_alias.side_effect = ClientError(
            {"Error": {"Code": "test-error"}}, "test-error"
        )
        aws_kms_client.create_alias(alias_name=alias_name, key_id=aws_kms_key)

    assert "Failed to create alias" in str(exc_info.value)

    # BotoCoreError is handled
    with pytest.raises(KMSCreateAliasError) as exc_info:
        aws_kms_client.boto3_client.create_alias.side_effect = BotoCoreError()
        aws_kms_client.create_alias(alias_name=alias_name, key_id=aws_kms_key)

    assert "Failed to create alias" in str(exc_info.value)


def test_aws_delete_alias(aws_kms_client, aws_kms_key):
    """AWSKMSClient delete_alias deletes an alias for a KMS key."""
    alias_name = "test-alias"
    aws_kms_client.boto3_client.delete_alias = Mock()
    aws_kms_client.delete_alias(alias_name=alias_name)

    aws_kms_client.boto3_client.delete_alias.assert_called_once_with(
        AliasName=alias_name
    )

    # ClientError is handled
    with pytest.raises(KMSDeleteAliasError) as exc_info:
        aws_kms_client.boto3_client.delete_alias.side_effect = ClientError(
            {"Error": {"Code": "test-error"}}, "test-error"
        )
        aws_kms_client.delete_alias(alias_name=alias_name)

    assert "Failed to delete alias" in str(exc_info.value)

    # BotoCoreError is handled
    with pytest.raises(KMSDeleteAliasError) as exc_info:
        aws_kms_client.boto3_client.delete_alias.side_effect = BotoCoreError()
        aws_kms_client.delete_alias(alias_name=alias_name)

    assert "Failed to delete alias" in str(exc_info.value)


def test_api_create_key(api_kms_client):
    """APIKMSClient create_key successfully returns metadata."""
    with patch("requests.request") as mock_request:
        mock_request.return_value.json.return_value = {
            "key_id": "test-key-id",
            "description": "Test KMS key",
        }
        response = api_kms_client.create_key(description="Test KMS key")

        assert "key_id" in response
        assert "description" in response

        mock_request.assert_called_once_with(
            "POST",
            "http://localhost:8000/keys",
            json={"description": "Test KMS key"},
            headers={"Authorization": "Bearer test-token"},
        )

    # HTTP error is handled
    mock_response = Mock()
    mock_response.status_code = 500
    mock_response.raise_for_status.side_effect = requests.HTTPError(
        response=Mock(status_code=500)
    )

    with patch("requests.request", return_value=mock_response) as mock_request:
        with pytest.raises(KMSKeyCreationError) as exc_info:
            api_kms_client.create_key(description="Test KMS key")

        assert "Failed to create key" in str(exc_info.value)


def test_api_decrypt(api_kms_client):
    """APIKMSClient decrypts encrypted data."""

    ciphertext = b"test-ciphertext"
    plaintext = b"test-plaintext"
    ciphertext_base64 = base64.b64encode(ciphertext).decode("utf-8")
    plaintext_base64 = base64.b64encode(plaintext).decode("utf-8")

    with patch("requests.request") as mock_request:
        mock_request.return_value.json.return_value = {"plaintext": plaintext_base64}
        response = api_kms_client.decrypt(key_id="test-key-id", ciphertext=ciphertext)

        assert response == plaintext
        mock_request.assert_called_once_with(
            "POST",
            "http://localhost:8000/keys/test-key-id/decrypt",
            json={"ciphertext": ciphertext_base64},
            headers={"Authorization": "Bearer test-token"},
        )

    # HTTP error is handled
    mock_response = Mock()
    mock_response.status_code = 500
    mock_response.raise_for_status.side_effect = requests.HTTPError(
        response=Mock(status_code=500)
    )

    with patch("requests.request", return_value=mock_response) as mock_request:
        with pytest.raises(KMSDecryptionError) as exc_info:
            api_kms_client.decrypt(key_id="test-key-id", ciphertext=ciphertext)

        assert "Failed to decrypt" in str(exc_info.value)


def test_api_get_public_key(api_kms_client):
    """APIKMSClient get_public_key returns public key."""
    with patch("requests.request") as mock_request:
        mock_request.return_value.json.return_value = {"public_key": "fake-public-key"}
        response = api_kms_client.get_public_key(key_id="test-key-id")

        assert response == "fake-public-key"
        mock_request.assert_called_once_with(
            "GET",
            "http://localhost:8000/keys/test-key-id",
            headers={"Authorization": "Bearer test-token"},
        )

    # HTTP error is handled
    mock_response = Mock()
    mock_response.status_code = 500
    mock_response.raise_for_status.side_effect = requests.HTTPError(
        response=Mock(status_code=500)
    )

    with patch("requests.request", return_value=mock_response) as mock_request:
        with pytest.raises(KMSGetPublicKeyError) as exc_info:
            api_kms_client.get_public_key(key_id="test-key-id")

        assert "Failed to get public key" in str(exc_info.value)


def test_api_describe_key(api_kms_client):
    """APIKMSClient describe_key returns key metadata."""
    with patch("requests.request") as mock_request:
        mock_request.return_value.json.return_value = {
            "KeyId": "test-key-id",
            "Arn": "test-arn",
            "Description": "Test KMS key",
        }
        response = api_kms_client.describe_key(key_id="test-key-id")

        assert response["KeyId"] == "test-key-id"
        assert response["Arn"] == "test-arn"
        assert response["Description"] == "Test KMS key"
        mock_request.assert_called_once_with(
            "GET",
            "http://localhost:8000/keys/test-key-id",
            headers={"Authorization": "Bearer test-token"},
        )

    # HTTP error is handled
    mock_response = Mock()
    mock_response.status_code = 500
    mock_response.raise_for_status.side_effect = requests.HTTPError(
        response=Mock(status_code=500)
    )

    with patch("requests.request", return_value=mock_response) as mock_request:
        with pytest.raises(KMSDescribeKeyError) as exc_info:
            api_kms_client.describe_key(key_id="test-key-id")

        assert "Failed to describe key" in str(exc_info.value)


def test_api_update_key_description(api_kms_client):
    """APIKMSClient update_key_description updates KMS key description."""
    with patch("requests.request") as mock_request:
        api_kms_client.update_key_description(
            key_id="test-key-id", description="New description"
        )

        mock_request.assert_called_once_with(
            "PATCH",
            "http://localhost:8000/keys/test-key-id",
            json={"description": "New description"},
            headers={"Authorization": "Bearer test-token"},
        )

    # HTTP error is handled
    mock_response = Mock()
    mock_response.status_code = 500
    mock_response.raise_for_status.side_effect = requests.HTTPError(
        response=Mock(status_code=500)
    )

    with patch("requests.request", return_value=mock_response) as mock_request:
        with pytest.raises(KMSUpdateKeyDescriptionError) as exc_info:
            api_kms_client.update_key_description(
                key_id="test-key-id", description="New description"
            )

        assert "Failed to update key description" in str(exc_info.value)


def test_api_disable_key(api_kms_client):
    """APIKMSClient disable_key disables KMS key."""
    with patch("requests.request") as mock_request:
        api_kms_client.disable_key(key_id="test-key-id")

        mock_request.assert_called_once_with(
            "POST",
            "http://localhost:8000/keys/test-key-id/disable",
            headers={"Authorization": "Bearer test-token"},
        )

    # HTTP error is handled
    mock_response = Mock()
    mock_response.status_code = 500
    mock_response.raise_for_status.side_effect = requests.HTTPError(
        response=Mock(status_code=500)
    )

    with patch("requests.request", return_value=mock_response) as mock_request:
        with pytest.raises(KMSDisableKeyError) as exc_info:
            api_kms_client.disable_key(key_id="test-key-id")

        assert "Failed to disable key" in str(exc_info.value)


def test_api_create_alias(api_kms_client):
    """APIKMSClient create_alias creates an alias for a KMS key."""
    with patch("requests.request") as mock_request:
        api_kms_client.create_alias(alias_name="test-alias", key_id="test-key-id")

        mock_request.assert_called_once_with(
            "PATCH",
            "http://localhost:8000/keys/test-key-id",
            json={"alias": "test-alias"},
            headers={"Authorization": "Bearer test-token"},
        )

    # HTTP error is handled
    mock_response = Mock()
    mock_response.status_code = 500
    mock_response.raise_for_status.side_effect = requests.HTTPError(
        response=Mock(status_code=500)
    )

    with patch("requests.request", return_value=mock_response) as mock_request:
        with pytest.raises(KMSCreateAliasError) as exc_info:
            api_kms_client.create_alias(alias_name="test-alias", key_id="test-key-id")

        assert "Failed to create alias" in str(exc_info.value)


def test_api_get_token(api_kms_client_urls):
    """Token is set on initialization."""
    with patch("requests.post") as mock_post:
        mock_post.return_value.json.return_value = {
            "access": "test-token",
            "refresh": "test-refresh-token",
        }
        client = APIKMSClient(
            client_id="test-client-id",
            client_secret="test-client-secret",
            urls=api_kms_client_urls,
        )

    assert client._access_token == "test-token"
    assert client._refresh_token == "test-refresh-token"

    mock_post.assert_called_once_with(
        "http://localhost:8000/token",
        data={"client_id": "test-client-id", "client_secret": "test-client-secret"},
    )


def test_api_refresh_token(api_kms_client):
    """Token is refreshed when expired."""
    with patch("requests.post") as mock_post, patch("requests.request") as mock_request:
        # Mock the /token/refresh call to return a new access token
        mock_post.return_value.json.return_value = {"access": "new-token"}

        # Mock the /keys/test-key-id
        # First one returns 401
        mock_401 = Mock()
        mock_401.status_code = 401
        mock_401.raise_for_status.side_effect = requests.HTTPError(response=mock_401)
        # Second one returns 200
        mock_200 = Mock()
        mock_200.status_code = 200
        mock_200.json.return_value = {"public_key": "fake-public-key"}
        mock_200.raise_for_status.return_value = None
        # Apply side effect
        mock_request.side_effect = [mock_401, mock_200]

        # Trigger the refresh
        api_kms_client.get_public_key(key_id="test-key-id")

        mock_post.assert_called_once_with(
            "http://localhost:8000/token/refresh",
            data={"refresh": "test-refresh-token"},
        )

        # Get public key is called twice: once before the refresh, once after
        calls = [
            call(
                "GET",
                "http://localhost:8000/keys/test-key-id",
                headers={"Authorization": "Bearer test-token"},
            ),
            call(
                "GET",
                "http://localhost:8000/keys/test-key-id",
                headers={"Authorization": "Bearer new-token"},
            ),
        ]
        mock_request.assert_has_calls(calls)

    assert api_kms_client._access_token == "new-token"


def test_api_refresh_token_failure(api_kms_client):
    """New token is requested if refresh token fails."""
    with patch("requests.post") as mock_post, patch(
        "requests.request"
    ) as mock_request, patch("valigetta.kms.APIKMSClient._get_token") as mock_get_token:
        mock_post.side_effect = requests.HTTPError(response=Mock(status_code=401))
        mock_get_token.return_value = {
            "access": "new-token",
            "refresh": "new-refresh-token",
        }
        # Mock the /keys/test-key-id
        # First one returns 401
        mock_401 = Mock()
        mock_401.status_code = 401
        mock_401.raise_for_status.side_effect = requests.HTTPError(response=mock_401)
        # Second one returns 200
        mock_200 = Mock()
        mock_200.status_code = 200
        mock_200.json.return_value = {"public_key": "fake-public-key"}
        mock_200.raise_for_status.return_value = None
        # Apply side effect
        mock_request.side_effect = [mock_401, mock_200]

        api_kms_client.get_public_key(key_id="test-key-id")

        mock_post.assert_called_once_with(
            "http://localhost:8000/token/refresh",
            data={"refresh": "test-refresh-token"},
        )

        # Get public key is called twice: once before get token, once after
        calls = [
            call(
                "GET",
                "http://localhost:8000/keys/test-key-id",
                headers={"Authorization": "Bearer test-token"},
            ),
            call(
                "GET",
                "http://localhost:8000/keys/test-key-id",
                headers={"Authorization": "Bearer new-token"},
            ),
        ]
        mock_request.assert_has_calls(calls)

    assert api_kms_client._access_token == "new-token"
    assert api_kms_client._refresh_token == "new-refresh-token"


def test_api_invalid_urls():
    """APIKMSClient raises an error if invalid URLs are provided."""
    with pytest.raises(KMSInvalidAPIURLsError) as exc_info:
        APIKMSClient(
            client_id="test-client-id",
            client_secret="test-client-secret",
            urls={
                "token": "invalid-url",
                "token_refresh": "invalid-url",
                "create_key": "invalid-url",
                "decrypt": "invalid-url",
                "get_public_key": "invalid-url",
                "describe_key": "invalid-url",
                "update_key_description": "invalid-url",
                "disable_key": "invalid-url",
                "create_alias": "invalid-url",
            },
        )

    errors = exc_info.value.args[0]
    assert isinstance(errors, dict)
    assert errors["token"] == "Invalid value 'invalid-url'"
    assert errors["token_refresh"] == "Invalid value 'invalid-url'"
    assert errors["create_key"] == "Invalid value 'invalid-url'"
    assert errors["decrypt"] == "Invalid value 'invalid-url'"
    assert errors["get_public_key"] == "Invalid value 'invalid-url'"
    assert errors["describe_key"] == "Invalid value 'invalid-url'"
    assert errors["update_key_description"] == "Invalid value 'invalid-url'"
    assert errors["disable_key"] == "Invalid value 'invalid-url'"
    assert errors["create_alias"] == "Invalid value 'invalid-url'"


def test_api_missing_urls():
    """APIKMSClient raises an error if required URLs are missing."""
    with pytest.raises(KMSInvalidAPIURLsError) as exc_info:
        APIKMSClient(
            client_id="test-client-id", client_secret="test-client-secret", urls={}
        )

    errors = exc_info.value.args[0]
    assert isinstance(errors, dict)
    assert errors["token"] == "URL is required"
    assert errors["token_refresh"] == "URL is required"
    assert errors["create_key"] == "URL is required"
    assert errors["decrypt"] == "URL is required"
    assert errors["get_public_key"] == "URL is required"
    assert errors["describe_key"] == "URL is required"
    assert errors["update_key_description"] == "URL is required"
    assert errors["disable_key"] == "URL is required"
    assert errors["create_alias"] == "URL is required"
