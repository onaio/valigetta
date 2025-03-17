import logging
from abc import ABC, abstractmethod
from typing import Optional

import boto3

logger = logging.getLogger(__name__)


class KMSClient(ABC):
    """Abstract Base Class for KMS Clients."""

    @abstractmethod
    def create_key(self, description: Optional[str] = None) -> dict:
        """Create an encryption key."""
        raise NotImplementedError("Subclasses must implement create_key method.")

    @abstractmethod
    def decrypt_aes_key(self, key_id: str, encrypted_aes_key: bytes) -> bytes:
        """Decrypt AES symmetric key."""
        raise NotImplementedError("Subclasses must implement decrypt_aes_key method.")


class AWSKMSClient(KMSClient):
    """AWS KMS Client Implementation."""

    def __init__(
        self,
        key_id: Optional[str] = None,
        aws_access_key_id: Optional[str] = None,
        aws_secret_access_key: Optional[str] = None,
        region_name: Optional[str] = None,
    ):
        self.kms_client = boto3.client(
            "kms",
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name=region_name,
        )
        self.key_id = key_id

    def create_key(self, description: Optional[str] = None) -> dict:
        """Create RSA 2048-bit key pair for encryption/decryption.

        :param description: A description of the KMS key. Do not include
                            sensitive material.
        :return: Metadata of the created key.
        """
        response = self.kms_client.create_key(
            KeyUsage="ENCRYPT_DECRYPT",
            KeySpec="RSA_2048",
            Description=description if description else "",
        )
        return response["KeyMetadata"]

    def decrypt_aes_key(self, encrypted_aes_key: bytes) -> bytes:
        """Decrypt AES symmetric key using AWS KMS.

        :param encrypted_aes_key: Encrypted symmetric key.
        :return: Decrypted AES key in plaintext.
        """
        if not self.key_id:
            raise ValueError("A key_id must be provided for decryption.")

        response = self.kms_client.decrypt(
            CiphertextBlob=encrypted_aes_key,
            KeyId=self.key_id,
            EncryptionAlgorithm="RSAES_OAEP_SHA_256",
        )
        return response["Plaintext"]
