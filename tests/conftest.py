import boto3
import pytest
from moto import mock_aws

from valigetta.kms import KMSClient


@pytest.fixture
def kms_client():
    """Fixture to provide a KMSClient instance with mocked credentials."""
    with mock_aws():
        yield KMSClient(region_name="us-east-1")


@pytest.fixture
def boto3_kms_client():
    """Fixture to provide a boto3 KMS client with a mocked KMS backend."""
    with mock_aws():
        yield boto3.client("kms", region_name="us-east-1")


@pytest.fixture
def kms_key(kms_client):
    """Creates a mocked AWS KMS key."""
    response = kms_client.create_key(description="Test key")

    return response["KeyId"]
