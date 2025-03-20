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
    def decrypt_aes_key(self, encrypted_aes_key: bytes) -> bytes:
        """Decrypt AES symmetric key."""
        raise NotImplementedError("Subclasses must implement decrypt_aes_key method.")

    @abstractmethod
    def get_public_key(self) -> bytes:
        """Returns the public key of an asymmetric key"""
        raise NotImplementedError("Subclasses must implement get_public_key method.")


class AWSKMSClient(KMSClient):
    """AWS KMS Client Implementation."""

    def __init__(
        self,
        key_id: Optional[str] = None,
        aws_access_key_id: Optional[str] = None,
        aws_secret_access_key: Optional[str] = None,
        region_name: Optional[str] = None,
    ):
        self.boto3_client = boto3.client(
            "kms",
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name=region_name,
        )
        self.key_id = key_id

    def _ensure_key_id(self) -> str:
        """Ensure key_id is set before performing KMS operations."""
        if not self.key_id:
            raise ValueError("A key_id must be provided.")
        return self.key_id

    def create_key(self, description: Optional[str] = None) -> dict:
        """Create RSA 2048-bit key pair for encryption/decryption.

        :param description: A description of the KMS key. Do not include
                            sensitive material.
        :return: Metadata of the created key.
        """
        response = self.boto3_client.create_key(
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
        response = self.boto3_client.decrypt(
            CiphertextBlob=encrypted_aes_key,
            KeyId=self._ensure_key_id(),
            EncryptionAlgorithm="RSAES_OAEP_SHA_256",
        )
        return response["Plaintext"]

    def get_public_key(self) -> bytes:
        """Get AWS KMS key's public key

        :return: Public key
        """
        response = self.boto3_client.get_public_key(KeyId=self._ensure_key_id())
        return response["PublicKey"]

    def describe_key(self) -> dict:
        """Returns detailed information about a KMS key.

        :return: Key detailed information
        """
        response = self.boto3_client.describe_key(KeyId=self._ensure_key_id())
        return response["KeyMetadata"]

    def update_key_description(self, description: str) -> None:
        """Updates the description of a KMS key.

        :param description: New description of the KMS key
        """
        self.boto3_client.update_key_description(
            KeyId=self._ensure_key_id(), Description=description
        )

    def disable_key(self):
        """Sets the state of a KMS key to disabled

        Prevents use of the KMS key.
        """
        self.boto3_client.disable_key(KeyId=self._ensure_key_id())
