from unittest.mock import Mock, call, patch

import requests

from valigetta.kms import APIKMSClient


def test_aws_create_key(aws_kms_client):
    """AWSKMSClient create_key successfully returns metadata."""
    response = aws_kms_client.create_key(description="Test KMS key")

    assert "KeyId" in response
    assert "Arn" in response
    assert response["Description"] == "Test KMS key"


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


def test_api_create_key(api_kms_client):
    """APIKMSClient create_key successfully returns metadata."""
    with patch("requests.request") as mock_request:
        mock_request.return_value.json.return_value = {
            "KeyId": "test-key-id",
            "Arn": "test-arn",
            "Description": "Test KMS key",
        }
        response = api_kms_client.create_key(description="Test KMS key")

    assert "KeyId" in response
    assert "Arn" in response
    assert response["Description"] == "Test KMS key"

    mock_request.assert_called_once_with(
        "POST",
        "http://localhost:8000/keys",
        json={"description": "Test KMS key"},
        headers={"Authorization": "Bearer test-token"},
    )


def test_api_decrypt(api_kms_client):
    """APIKMSClient decrypts encrypted data."""
    with patch("requests.request") as mock_request:
        mock_request.return_value.json.return_value = {"Plaintext": b"test-plaintext"}
        response = api_kms_client.decrypt(
            key_id="test-key-id", ciphertext=b"test-ciphertext"
        )

    assert response["Plaintext"] == b"test-plaintext"

    mock_request.assert_called_once_with(
        "POST",
        "http://localhost:8000/keys/test-key-id/decrypt",
        json={"ciphertext": b"test-ciphertext"},
        headers={"Authorization": "Bearer test-token"},
    )


def test_api_get_public_key(api_kms_client):
    """APIKMSClient get_public_key returns public key."""
    with patch("requests.request") as mock_request:
        mock_request.return_value.json.return_value = {"PublicKey": b"test-public-key"}
        response = api_kms_client.get_public_key(key_id="test-key-id")

    assert response["PublicKey"] == b"test-public-key"

    mock_request.assert_called_once_with(
        "GET",
        "http://localhost:8000/keys/test-key-id/public",
        headers={"Authorization": "Bearer test-token"},
    )


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


def test_api_update_key_description(api_kms_client):
    """APIKMSClient update_key_description updates KMS key description."""
    with patch("requests.request") as mock_request:
        mock_request.return_value.json.return_value = {
            "KeyId": "test-key-id",
            "Arn": "test-arn",
            "Description": "New description",
        }
        response = api_kms_client.update_key_description(
            key_id="test-key-id", description="New description"
        )

    assert response["KeyId"] == "test-key-id"
    assert response["Arn"] == "test-arn"
    assert response["Description"] == "New description"

    mock_request.assert_called_once_with(
        "PUT",
        "http://localhost:8000/keys/test-key-id",
        json={"description": "New description"},
        headers={"Authorization": "Bearer test-token"},
    )


def test_api_disable_key(api_kms_client):
    """APIKMSClient disable_key disables KMS key."""
    with patch("requests.request") as mock_request:
        mock_request.return_value.json.return_value = {
            "KeyId": "test-key-id",
            "Arn": "test-arn",
            "Description": "New description",
        }
        response = api_kms_client.disable_key(key_id="test-key-id")

    assert response["KeyId"] == "test-key-id"
    assert response["Arn"] == "test-arn"
    assert response["Description"] == "New description"

    mock_request.assert_called_once_with(
        "POST",
        "http://localhost:8000/keys/test-key-id/disable",
        headers={"Authorization": "Bearer test-token"},
    )


def test_api_get_token():
    """Token is set on initialization."""
    with patch("requests.post") as mock_post:
        mock_post.return_value.json.return_value = {
            "access": "test-token",
            "refresh": "test-refresh-token",
        }
        client = APIKMSClient(
            base_url="http://localhost:8000",
            client_id="test-client-id",
            client_secret="test-client-secret",
        )

    assert client.access_token == "test-token"
    assert client.refresh_token == "test-refresh-token"

    mock_post.assert_called_once_with(
        "http://localhost:8000/token",
        data={"client_id": "test-client-id", "client_secret": "test-client-secret"},
    )


def test_api_refresh_token(api_kms_client):
    """Token is refreshed when expired."""
    with patch("requests.post") as mock_post, patch("requests.request") as mock_request:
        # Mock the /token/refresh call to return a new access token
        mock_post.return_value.json.return_value = {"access": "new-token"}

        # Mock the /keys/test-key-id/public
        # First one returns 401
        mock_401 = Mock()
        mock_401.status_code = 401
        mock_401.raise_for_status.side_effect = requests.HTTPError(response=mock_401)
        # Second one returns 200
        mock_200 = Mock()
        mock_200.status_code = 200
        mock_200.json.return_value = {b"fake-public-key"}
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
                "http://localhost:8000/keys/test-key-id/public",
                headers={"Authorization": "Bearer test-token"},
            ),
            call(
                "GET",
                "http://localhost:8000/keys/test-key-id/public",
                headers={"Authorization": "Bearer new-token"},
            ),
        ]
        mock_request.assert_has_calls(calls)

    assert api_kms_client.access_token == "new-token"


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
        # Mock the /keys/test-key-id/public
        # First one returns 401
        mock_401 = Mock()
        mock_401.status_code = 401
        mock_401.raise_for_status.side_effect = requests.HTTPError(response=mock_401)
        # Second one returns 200
        mock_200 = Mock()
        mock_200.status_code = 200
        mock_200.json.return_value = {b"fake-public-key"}
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
                "http://localhost:8000/keys/test-key-id/public",
                headers={"Authorization": "Bearer test-token"},
            ),
            call(
                "GET",
                "http://localhost:8000/keys/test-key-id/public",
                headers={"Authorization": "Bearer new-token"},
            ),
        ]
        mock_request.assert_has_calls(calls)

    assert api_kms_client.access_token == "new-token"
    assert api_kms_client.refresh_token == "new-refresh-token"
