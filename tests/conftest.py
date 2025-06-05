from unittest.mock import patch

import boto3
import pytest
from moto import mock_aws

from valigetta.kms import APIKMSClient, AWSKMSClient


@pytest.fixture
def aws_kms_client():
    """Fixture to provide a KMSClient instance with mocked credentials."""
    with mock_aws():
        yield AWSKMSClient(region_name="us-east-1")


@pytest.fixture
def boto3_kms_client():
    """Fixture to provide a boto3 KMS client with a mocked KMS backend."""
    with mock_aws():
        yield boto3.client("kms", region_name="us-east-1")


@pytest.fixture
def aws_kms_key(aws_kms_client):
    """Creates a mocked AWS KMS key."""
    response = aws_kms_client.create_key(description="Test key")

    return response["key_id"]


@pytest.fixture
def api_kms_client_urls():
    """Fixture to provide a KMSClient instance with mocked credentials."""
    return {
        "token": "http://localhost:8000/token",
        "token_refresh": "http://localhost:8000/token/refresh",
        "create_key": "http://localhost:8000/keys",
        "decrypt": "http://localhost:8000/keys/{key_id}/decrypt",
        "get_public_key": "http://localhost:8000/keys/{key_id}",
        "describe_key": "http://localhost:8000/keys/{key_id}",
        "update_key_description": "http://localhost:8000/keys/{key_id}",
        "disable_key": "http://localhost:8000/keys/{key_id}/disable",
        "create_alias": "http://localhost:8000/keys/{key_id}",
    }


@pytest.fixture
def api_kms_client(api_kms_client_urls):
    """Fixture to provide a KMSClient instance with mocked credentials."""
    # Mock the _get_token method
    with patch("valigetta.kms.APIKMSClient._get_token") as mock_get_token:
        mock_get_token.return_value = {
            "access": "test-token",
            "refresh": "test-refresh-token",
        }

        yield APIKMSClient(
            client_id="test-client-id",
            client_secret="test-client-secret",
            urls=api_kms_client_urls,
        )
