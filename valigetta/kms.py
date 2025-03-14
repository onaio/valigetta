import logging
from typing import Optional

import boto3

logger = logging.getLogger(__name__)


class KMSClient:
    def __init__(
        self, aws_access_key_id=None, aws_secret_access_key=None, region_name=None
    ):
        self.kms_client = boto3.client(
            "kms",
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name=region_name,
        )

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

    def decrypt_aes_key(self, key_id: str, encrypted_aes_key: bytes) -> bytes:
        """Decrypt AES symmetric key using AWS KMS.

        :param key_id: AWS KMS key used for decryption.
        :param encrypted_aes_key: Encrypted symmetric key.
        :return: Decrypted AES key in plaintext.
        """
        response = self.kms_client.decrypt(
            CiphertextBlob=encrypted_aes_key,
            KeyId=key_id,
            EncryptionAlgorithm="RSAES_OAEP_SHA_256",
        )
        return response["Plaintext"]
