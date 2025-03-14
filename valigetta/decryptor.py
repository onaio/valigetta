"""
Submission decryption
"""

import base64
import hashlib
import logging
import xml.etree.ElementTree as ET
from typing import TextIO

from Crypto.Cipher import AES

from valigetta.exceptions import InvalidSubmission
from valigetta.kms import KMSClient

logger = logging.getLogger(__name__)


def _extract_encrypted_aes_key(submission_xml: TextIO) -> str:
    """Extract encrypted AES key from submission.xml

    :param submission_xml: Submission XML file
    :return: value from the tag base64EncryptedKey
    """
    try:
        tree = ET.parse(submission_xml)
        root = tree.getroot()
        namespace = {"n": "http://opendatakit.org/submissions"}
        encrypted_key_elem = root.find("n:base64EncryptedKey", namespace)

        if encrypted_key_elem is None:
            raise InvalidSubmission(
                "base64EncryptedKey element not found in submission.xml"
            )

        return encrypted_key_elem.text.strip().replace("\n", "")
    except ET.ParseError as exc:
        raise InvalidSubmission(f"Invalid XML structure: {exc}")

    except Exception as exc:
        logger.error(f"Error extracting symmetric key: {exc}")

        raise


def _get_instance_id(submission_xml: TextIO) -> str:
    """Extract instanceID from submission XML"""

    try:
        submission_xml.seek(0)  # Reset file pointer
        tree = ET.parse(submission_xml)
        root = tree.getroot()
        instance_id = root.attrib.get("instanceID")

        if instance_id is None:
            meta_elem = root.find(".//{http://openrosa.org/xforms}meta")

            if meta_elem is not None:
                instance_id_elem = meta_elem.find(
                    "{http://openrosa.org/xforms}instanceID"
                )
                if instance_id_elem is not None and instance_id_elem.text:
                    instance_id = instance_id_elem.text.strip()

        if not instance_id:
            raise InvalidSubmission("instanceID not found in submission.xml")

        return instance_id
    except ET.ParseError as exc:
        raise InvalidSubmission(f"Invalid XML structure: {exc}")

    except Exception as exc:
        logging.error(f"Error extracting instance ID: {exc}")

        raise


def _get_submission_iv(instance_id: str, aes_key: bytes, index: int) -> bytes:
    """Generates a 16-byte initialization vector (IV) for AES encryption.

    The IV is created by hashing the instance ID and AES key, then mutating
    the hash based on the index.

    :param instance_id: Unique instance ID from submission.xml
    :param aes_key: Symmetric key used for encryption
    :param index: Counter used for mutating the IV
    :return: A 16-byte initialization vector (IV)
    """
    md5_hash = hashlib.md5()
    md5_hash.update(instance_id.encode("utf-8"))
    md5_hash.update(aes_key)

    iv_seed_array = bytearray(md5_hash.digest())

    # Mutate IV based on index
    for i in range(index):
        iv_seed_array[i % 16] = (iv_seed_array[i % 16] + 1) % 256

    return bytes(iv_seed_array)


def decrypt_submission(
    kms_client: KMSClient,
    key_id: str,
    submission_xml: TextIO,
    encrypted_data: bytes,
    index: int,
) -> bytes:
    """Decrypt submission using AWS KMS

    :param kms_client KMSClient instance
    :param key_id: AWS KMS key used for decryption
    :param submission_xml: Submission XML file
    :param encrypted_file: Encrypted file contents
    :param index: Index used for mutating IV
    :return: Decrypted submission
    """
    logger.debug("Extracting encrypted AES key from submission XML.")
    encrypted_aes_key_b64 = _extract_encrypted_aes_key(submission_xml)
    encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)

    logger.debug("Decrypting AES key using AWS KMS.")
    aes_key = kms_client.decrypt_aes_key(key_id, encrypted_aes_key)

    logger.debug("Generating IV for AES decryption.")
    instance_id = _get_instance_id(submission_xml)
    iv = _get_submission_iv(instance_id, aes_key, index)

    logger.debug("Performing AES decryption on submission data.")
    cipher_aes = AES.new(aes_key, AES.MODE_CFB, iv=iv, segment_size=128)

    logger.debug("Decryption successful")
    return cipher_aes.decrypt(encrypted_data)
