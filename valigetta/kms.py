import base64
import logging
from abc import ABC, abstractmethod
from typing import Optional
from urllib.parse import urlparse

import boto3
import requests
from botocore.exceptions import BotoCoreError, ClientError

from valigetta.exceptions import (
    KMSClientError,
    KMSCreateAliasError,
    KMSDecryptionError,
    KMSDeleteAliasError,
    KMSDescribeKeyError,
    KMSDisableKeyError,
    KMSGetPublicKeyError,
    KMSKeyCreationError,
    KMSTokenError,
    KMSUnauthorizedError,
    KMSUpdateKeyDescriptionError,
)
from valigetta.utils import der_public_key_to_pem

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
    def get_public_key(self, key_id: str) -> str:
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

    @abstractmethod
    def create_alias(self, alias_name: str, key_id: str) -> None:
        """Creates an alias for a KMS key"""
        raise NotImplementedError("Subclasses must implement create_alias method.")


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
        try:
            response = self.boto3_client.create_key(
                KeyUsage="ENCRYPT_DECRYPT",
                KeySpec="RSA_2048",
                Description=description if description else "",
            )
        except (BotoCoreError, ClientError) as exc:
            raise KMSKeyCreationError("Failed to create key") from exc

        return {
            "key_id": response["KeyMetadata"]["KeyId"],
            "description": response["KeyMetadata"]["Description"],
            "creation_date": response["KeyMetadata"]["CreationDate"].isoformat(),
        }

    def decrypt(self, key_id: str, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext that was encrypted using AWS KMS key.

        :param key_id: Identifier for the KMS key
        :param ciphertext: Encrypted data.
        :return: Decrypted plaintext data.
        """
        try:
            response = self.boto3_client.decrypt(
                CiphertextBlob=ciphertext,
                KeyId=key_id,
                EncryptionAlgorithm="RSAES_OAEP_SHA_256",
            )
        except (BotoCoreError, ClientError) as exc:
            raise KMSDecryptionError("Failed to decrypt ciphertext") from exc

        return response["Plaintext"]

    def get_public_key(self, key_id: str) -> str:
        """Get AWS KMS key's public key

        :param key_id: Identifier for the KMS key
        :return: PEM-formatted public key
        """
        try:
            response = self.boto3_client.get_public_key(KeyId=key_id)
        except (BotoCoreError, ClientError) as exc:
            raise KMSGetPublicKeyError("Failed to get public key") from exc

        return der_public_key_to_pem(response["PublicKey"])

    def describe_key(self, key_id: str) -> dict:
        """Returns detailed information about a KMS key.

        :param key_id: Identifier for the KMS key
        :return: Key detailed information
        """
        try:
            response = self.boto3_client.describe_key(KeyId=key_id)
        except (BotoCoreError, ClientError) as exc:
            raise KMSDescribeKeyError("Failed to describe key") from exc

        return {
            "key_id": response["KeyMetadata"]["KeyId"],
            "description": response["KeyMetadata"]["Description"],
            "creation_date": response["KeyMetadata"]["CreationDate"].isoformat(),
            "enabled": response["KeyMetadata"]["Enabled"],
        }

    def update_key_description(self, key_id: str, description: str) -> None:
        """Updates the description of a KMS key.

        :param key_id: Identifier for the KMS key
        :param description: New description of the KMS key
        """
        try:
            self.boto3_client.update_key_description(
                KeyId=key_id, Description=description
            )
        except (BotoCoreError, ClientError) as exc:
            raise KMSUpdateKeyDescriptionError(
                "Failed to update key description"
            ) from exc

    def disable_key(self, key_id: str) -> None:
        """Sets the state of a KMS key to disabled

        Prevents use of the KMS key.

        :param key_id: Identifier for the KMS key
        """
        try:
            self.boto3_client.disable_key(KeyId=key_id)
        except (BotoCoreError, ClientError) as exc:
            raise KMSDisableKeyError("Failed to disable key") from exc

    def create_alias(self, alias_name: str, key_id: str) -> None:
        """Creates an alias for a KMS key.

        :param alias_name: Name of the alias
        :param key_id: Identifier for the KMS key
        """
        try:
            self.boto3_client.create_alias(AliasName=alias_name, TargetKeyId=key_id)
        except (BotoCoreError, ClientError) as exc:
            raise KMSCreateAliasError("Failed to create alias") from exc

    def delete_alias(self, alias_name: str) -> None:
        """Deletes an alias for a KMS key.

        :param alias_name: Name of the alias
        """
        try:
            self.boto3_client.delete_alias(AliasName=alias_name)
        except (BotoCoreError, ClientError) as exc:
            raise KMSDeleteAliasError("Failed to delete alias") from exc


class APIKMSClient(KMSClient):
    """Generic API client implementation"""

    URL_TOKEN_KEY = "token"
    URL_TOKEN_REFRESH_KEY = "token_refresh"
    URL_CREATE_KEY = "create_key"
    URL_DECRYPT_KEY = "decrypt"
    URL_GET_PUBLIC_KEY = "get_public_key"
    URL_DESCRIBE_KEY = "describe_key"
    URL_UPDATE_KEY_DESCRIPTION_KEY = "update_key_description"
    URL_DISABLE_KEY = "disable_key"
    URL_CREATE_ALIAS_KEY = "create_alias"
    URL_KEYS = frozenset(
        [
            URL_TOKEN_KEY,
            URL_TOKEN_REFRESH_KEY,
            URL_CREATE_KEY,
            URL_DECRYPT_KEY,
            URL_GET_PUBLIC_KEY,
            URL_DESCRIBE_KEY,
            URL_UPDATE_KEY_DESCRIPTION_KEY,
            URL_DISABLE_KEY,
            URL_CREATE_ALIAS_KEY,
        ]
    )

    def __init__(self, client_id: str, client_secret: str, urls: dict[str, str]):
        self.client_id = client_id
        self.client_secret = client_secret
        self.urls = urls

        self._validate_urls()
        data = self._get_token()

        self._access_token = data["access"]
        self._refresh_token = data["refresh"]

    def _is_valid_url(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            return all([parsed.scheme, parsed.netloc])
        except Exception:
            return False

    def _validate_urls(self):
        """Validate the URLs for the API client"""
        errors = {}

        for url_key in self.URL_KEYS:
            if url_key not in self.urls:
                errors[url_key] = "URL is required"

            elif not self._is_valid_url(self.urls[url_key]):
                errors[url_key] = f"Invalid value '{self.urls[url_key]}'"

        if errors:
            raise KMSClientError(errors)

    def _get_token(self) -> dict:
        """Get a token for the API client"""
        try:
            response = requests.post(
                self.urls[self.__class__.URL_TOKEN_KEY],
                data={"client_id": self.client_id, "client_secret": self.client_secret},
            )
            response.raise_for_status()
            return response.json()

        except requests.RequestException as exc:
            raise KMSTokenError("Failed to get token") from exc

    def _refresh_access_token(self) -> dict:
        """Refresh the token for the API client"""
        try:
            response = requests.post(
                self.urls[self.__class__.URL_TOKEN_REFRESH_KEY],
                data={"refresh": self._refresh_token},
            )
            response.raise_for_status()
            return response.json()

        except requests.RequestException as exc:
            raise KMSTokenError("Failed to refresh token") from exc

    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        headers = kwargs.pop("headers", {}).copy()
        headers["Authorization"] = f"Bearer {self._access_token}"
        kwargs["headers"] = headers

        response = requests.request(method, url, **kwargs)

        # Handle 401 Unauthorized: try refresh token, then retry once
        if response.status_code == 401:
            try:
                data = self._refresh_access_token()
                self._access_token = data["access"]
            except KMSTokenError:
                # If refresh token fails, try to get a new token
                try:
                    data = self._get_token()
                    self._access_token = data["access"]
                    self._refresh_token = data["refresh"]
                except KMSTokenError as exc:
                    raise KMSUnauthorizedError("Re-authentication failed") from exc

            # Retry the request once after token refresh
            headers = kwargs.get("headers", {}).copy()
            headers["Authorization"] = f"Bearer {self._access_token}"
            kwargs["headers"] = headers

            response = requests.request(method, url, **kwargs)

        try:
            response.raise_for_status()
        except requests.RequestException as exc:
            raise KMSClientError(f"Request to {url} failed") from exc

        return response

    def create_key(self, description: Optional[str] = None) -> dict:
        """Create a new key.

        :param description: A description of the KMS key. Do not include
                            sensitive material.
        :return: Metadata of the created key.
        """
        try:
            response = self._request(
                "POST",
                self.urls[self.__class__.URL_CREATE_KEY],
                json={"description": description},
            )
        except KMSClientError as exc:
            raise KMSKeyCreationError("Failed to create key") from exc

        return response.json()

    def decrypt(self, key_id: str, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext that was encrypted using AWS KMS key.

        :param key_id: Identifier for the KMS key
        :param ciphertext: Ciphertext in bytes.
        :return: Decrypted plaintext in bytes.
        """
        ciphertext_base64 = base64.b64encode(ciphertext).decode("utf-8")

        try:
            response = self._request(
                "POST",
                self.urls[self.__class__.URL_DECRYPT_KEY].format(key_id=key_id),
                json={"ciphertext": ciphertext_base64},
            )
        except KMSClientError as exc:
            raise KMSDecryptionError("Failed to decrypt ciphertext") from exc

        plaintext_base64 = response.json()["plaintext"]

        return base64.b64decode(plaintext_base64)

    def get_public_key(self, key_id: str) -> str:
        """Get the public key of a key.

        :param key_id: Identifier for the KMS key
        :return: PEM-formatted public key
        """
        try:
            response = self._request(
                "GET",
                self.urls[self.__class__.URL_GET_PUBLIC_KEY].format(key_id=key_id),
            )
        except KMSClientError as exc:
            raise KMSGetPublicKeyError("Failed to get public key") from exc

        return response.json()["public_key"]

    def describe_key(self, key_id: str) -> dict:
        """Get the description of a key.

        :param key_id: Identifier for the KMS key
        :return: Key detailed information
        """
        try:
            response = self._request(
                "GET",
                self.urls[self.__class__.URL_DESCRIBE_KEY].format(key_id=key_id),
            )
        except KMSClientError as exc:
            raise KMSDescribeKeyError("Failed to describe key") from exc

        return response.json()

    def update_key_description(self, key_id: str, description: str) -> None:
        """Update the description of a key.

        :param key_id: Identifier for the KMS key
        :param description: New description of the KMS key
        """
        try:
            response = self._request(
                "PATCH",
                self.urls[self.__class__.URL_UPDATE_KEY_DESCRIPTION_KEY].format(
                    key_id=key_id
                ),
                json={"description": description},
            )
        except KMSClientError as exc:
            raise KMSUpdateKeyDescriptionError(
                "Failed to update key description"
            ) from exc

        return response.json()

    def disable_key(self, key_id: str) -> None:
        """Disable a key.

        :param key_id: Identifier for the KMS key
        """
        try:
            response = self._request(
                "POST",
                self.urls[self.__class__.URL_DISABLE_KEY].format(key_id=key_id),
            )
        except KMSClientError as exc:
            raise KMSDisableKeyError("Failed to disable key") from exc

        return response.json()

    def create_alias(self, alias_name: str, key_id: str) -> None:
        """Create an alias for a key.

        :param alias_name: Name of the alias
        :param key_id: Identifier for the KMS key
        """
        try:
            response = self._request(
                "PATCH",
                self.urls[self.__class__.URL_CREATE_ALIAS_KEY].format(key_id=key_id),
                json={"alias": alias_name},
            )
        except KMSClientError as exc:
            raise KMSCreateAliasError("Failed to create alias") from exc

        return response.json()
