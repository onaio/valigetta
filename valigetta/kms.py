import logging
from abc import ABC, abstractmethod
from typing import Optional

import boto3
import requests

logger = logging.getLogger(__name__)


class KMSClient(ABC):
    """Abstract Base Class for KMS Clients."""

    @abstractmethod
    def create_key(self, description: Optional[str] = None) -> dict:
        """Create an encryption key."""
        raise NotImplementedError("Subclasses must implement create_key method.")

    @abstractmethod
    def decrypt(self, key_id: str, ciphertext: bytes) -> bytes:
        """Decrypts ciphertext that was encrypted by a KMS key"""
        raise NotImplementedError("Subclasses must implement decrypt method.")

    @abstractmethod
    def get_public_key(self, key_id: str) -> bytes:
        """Returns the public key of an asymmetric key"""
        raise NotImplementedError("Subclasses must implement get_public_key method.")

    @abstractmethod
    def describe_key(self, key_id: str) -> dict:
        """Returns detailed information about a KMS key"""
        raise NotImplementedError("Subclasses must implement describe_key method.")

    @abstractmethod
    def update_key_description(self, key_id: str, description: str) -> None:
        """Updates the description of a KMS key"""
        raise NotImplementedError(
            "Subclasses must implement update_key_description method."
        )

    @abstractmethod
    def disable_key(self, key_id: str) -> None:
        """Disables a KMS key"""
        raise NotImplementedError("Subclasses must implement disable_key method.")


class AWSKMSClient(KMSClient):
    """AWS KMS Client Implementation."""

    def __init__(
        self,
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

    def decrypt(self, key_id: str, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext that was encrypted using AWS KMS key.

        :param key_id: Identifier for the KMS key
        :param ciphertext: Encrypted data.
        :return: Decrypted plaintext data.
        """
        response = self.boto3_client.decrypt(
            CiphertextBlob=ciphertext,
            KeyId=key_id,
            EncryptionAlgorithm="RSAES_OAEP_SHA_256",
        )
        return response["Plaintext"]

    def get_public_key(self, key_id: str) -> bytes:
        """Get AWS KMS key's public key

        :param key_id: Identifier for the KMS key
        :return: Public key
        """
        response = self.boto3_client.get_public_key(KeyId=key_id)
        return response["PublicKey"]

    def describe_key(self, key_id: str) -> dict:
        """Returns detailed information about a KMS key.

        :param key_id: Identifier for the KMS key
        :return: Key detailed information
        """
        response = self.boto3_client.describe_key(KeyId=key_id)
        return response["KeyMetadata"]

    def update_key_description(self, key_id: str, description: str) -> None:
        """Updates the description of a KMS key.

        :param key_id: Identifier for the KMS key
        :param description: New description of the KMS key
        """
        self.boto3_client.update_key_description(KeyId=key_id, Description=description)

    def disable_key(self, key_id: str) -> None:
        """Sets the state of a KMS key to disabled

        Prevents use of the KMS key.

        :param key_id: Identifier for the KMS key
        """
        self.boto3_client.disable_key(KeyId=key_id)


class APIKMSClient(KMSClient):
    """Generic API client implementation"""

    def __init__(self, base_url: str, client_id: str, client_secret: str):
        self.base_url = base_url
        self.client_id = client_id
        self.client_secret = client_secret

        data = self._get_token()
        self.access_token = data["access"]
        self.refresh_token = data["refresh"]

    def _get_token(self) -> dict:
        """Get a token for the API client"""
        response = requests.post(
            f"{self.base_url}/token",
            data={"client_id": self.client_id, "client_secret": self.client_secret},
        )
        response.raise_for_status()
        return response.json()

    def _refresh_access_token(self) -> dict:
        """Refresh the token for the API client"""
        response = requests.post(
            f"{self.base_url}/token/refresh",
            data={"refresh": self.refresh_token},
        )
        response.raise_for_status()
        return response.json()

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        url = f"{self.base_url}{path}"
        headers = kwargs.pop("headers", {}).copy()
        headers["Authorization"] = f"Bearer {self.access_token}"
        kwargs["headers"] = headers

        response = requests.request(method, url, **kwargs)

        # Handle 401 Unauthorized: try refresh token, then retry once
        if response.status_code == 401:
            try:
                data = self._refresh_access_token()
                self.access_token = data["access"]
            except requests.HTTPError as e:
                if e.response.status_code == 401:
                    data = self._get_token()
                    self.access_token = data["access"]
                    self.refresh_token = data["refresh"]
                else:
                    raise e

            # Retry the request once after token refresh
            headers = kwargs.get("headers", {}).copy()
            headers["Authorization"] = f"Bearer {self.access_token}"
            kwargs["headers"] = headers

            response = requests.request(method, url, **kwargs)

        response.raise_for_status()
        return response

    def create_key(self, description: Optional[str] = None) -> dict:
        """Create a new key.

        :param description: A description of the KMS key. Do not include
                            sensitive material.
        :return: Metadata of the created key.
        """
        response = self._request("POST", "/keys", json={"description": description})
        return response.json()

    def decrypt(self, key_id: str, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext that was encrypted using AWS KMS key.

        :param key_id: Identifier for the KMS key
        :param ciphertext: Encrypted data.
        :return: Decrypted plaintext data.
        """
        response = self._request(
            "POST", f"/keys/{key_id}/decrypt", json={"ciphertext": ciphertext}
        )
        return response.json()

    def get_public_key(self, key_id: str) -> bytes:
        """Get the public key of a key.

        :param key_id: Identifier for the KMS key
        :return: Public key
        """
        response = self._request("GET", f"/keys/{key_id}/public")
        return response.json()

    def describe_key(self, key_id: str) -> dict:
        """Get the description of a key.

        :param key_id: Identifier for the KMS key
        :return: Key detailed information
        """
        response = self._request("GET", f"/keys/{key_id}")
        return response.json()

    def update_key_description(self, key_id: str, description: str) -> None:
        """Update the description of a key.

        :param key_id: Identifier for the KMS key
        :param description: New description of the KMS key
        """
        response = self._request(
            "PUT", f"/keys/{key_id}", json={"description": description}
        )
        return response.json()

    def disable_key(self, key_id: str) -> None:
        """Disable a key.

        :param key_id: Identifier for the KMS key
        """
        response = self._request("POST", f"/keys/{key_id}/disable")
        return response.json()
