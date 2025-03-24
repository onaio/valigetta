"""
Submission decryption
"""

import base64
import hashlib
import logging
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from io import BytesIO
from typing import Iterable, Iterator, Tuple

from Crypto.Cipher import AES

from valigetta.exceptions import InvalidSubmission
from valigetta.kms import KMSClient

logger = logging.getLogger(__name__)


def extract_encrypted_aes_key(submission_xml: BytesIO) -> str:
    """Extract encrypted AES key from submission XML

    :param submission_xml: Submission XML file
    :return: value from the tag base64EncryptedKey
    """
    try:
        submission_xml.seek(0)  # Reset file pointer
        tree = ET.fromstring(submission_xml.read())
        namespace = {"n": "http://opendatakit.org/submissions"}
        encrypted_key_elem = tree.find("n:base64EncryptedKey", namespace)

        if encrypted_key_elem is None or not encrypted_key_elem.text:
            raise InvalidSubmission(
                "base64EncryptedKey element not found in submission.xml"
            )

        return encrypted_key_elem.text.strip().replace("\n", "")
    except ET.ParseError as exc:
        raise InvalidSubmission(f"Invalid XML structure: {exc}")

    except Exception as exc:
        logger.error(f"Error extracting symmetric key: {exc}")

        raise


def extract_instance_id(submission_xml: BytesIO) -> str:
    """Extract instanceID from submission XML

    :param submission_xml: Submission XML file
    """
    try:
        submission_xml.seek(0)  # Reset file pointer
        tree = ET.fromstring(submission_xml.read())
        instance_id = tree.attrib.get("instanceID")

        if instance_id is None:
            meta_elem = tree.find(".//{http://openrosa.org/xforms}meta")

            if meta_elem is not None:
                instance_id_elem = meta_elem.find(
                    "{http://openrosa.org/xforms}instanceID"
                )
                if instance_id_elem is not None and instance_id_elem.text:
                    instance_id = instance_id_elem.text.strip().replace("\n", "")

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


def decrypt_file(
    file: BytesIO, aes_key: bytes, instance_id: str, index: int
) -> Iterator[bytes]:
    """Decrypt a single file.

    :param file: File to be decrypted
    :param aes_key: Symmetric key used during encryption
    :param instance_id: instanceID of the submission
    :param index: Counter used for mutating the IV
    :return: Decrypted file in bytes
    """
    logger.debug("Generating IV for index %d", index)
    iv = _get_submission_iv(instance_id, aes_key, index)
    cipher_aes = AES.new(aes_key, AES.MODE_CFB, iv=iv, segment_size=128)

    while chunk := file.read(4096):  # Read chunks of 4KB
        yield cipher_aes.decrypt(chunk)


def extract_dec_aes_key(kms_client: KMSClient, submission_xml: BytesIO) -> bytes:
    """Extract encrypted AES key from submission XML and decrypt it

    :param kms_client: KMSClient instance
    :param submission_xml: Submission XML file
    :return Decrypted AES key
    """
    logger.debug("Extracting encrypted AES key from submission XML.")
    encrypted_aes_key_b64 = extract_encrypted_aes_key(submission_xml)
    encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)

    logger.debug("Decrypting AES key using AWS KMS.")
    return kms_client.decrypt_aes_key(encrypted_aes_key)


def decrypt_submission(
    kms_client: KMSClient,
    submission_xml: BytesIO,
    encrypted_files: Iterable[Tuple[int, BytesIO]],
) -> Iterator[Tuple[int, bytes]]:
    """Decrypt submission and media files using AWS KMS.

    :param kms_client: KMSClient instance
    :param submission_xml: Submission XML file contents
    :param encrypted_files: An iterable yielding encrypted file contents
    :return: A generator yielding decrypted data chunks
    """
    aes_key = extract_dec_aes_key(kms_client, submission_xml)
    instance_id = extract_instance_id(submission_xml)

    with ThreadPoolExecutor() as executor:
        futures = {
            executor.submit(decrypt_file, file, aes_key, instance_id, index): index
            for index, file in enumerate(encrypted_files)
        }

        for future in as_completed(futures):
            index = futures[future]

            for chunk in future.result():  # Process each chunk as it's available
                logger.debug("Decrypted chunk for index %d", index)

                yield index, chunk
