"""
Submission decryption
"""

import base64
import hashlib
import logging
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from io import BytesIO
from typing import Iterable, Iterator, List, Tuple

from Crypto.Cipher import AES

from valigetta.exceptions import InvalidSubmission
from valigetta.kms import KMSClient

logger = logging.getLogger(__name__)


def extract_encrypted_aes_key(submission_xml: BytesIO) -> str:
    """Extract submission's encrypted AES key.

    :param submission_xml: Submission XML file
    :return: value from the tag base64EncryptedKey
    """
    try:
        submission_xml.seek(0)  # Reset file pointer
        tree = ET.fromstring(submission_xml.read())
        namespace = {"n": "http://opendatakit.org/submissions"}
        enc_key_elem = tree.find("n:base64EncryptedKey", namespace)

        if enc_key_elem is None or not enc_key_elem.text:
            raise InvalidSubmission(
                "base64EncryptedKey element not found in submission.xml"
            )

        return enc_key_elem.text.strip().replace("\n", "")
    except ET.ParseError as exc:
        raise InvalidSubmission(f"Invalid XML structure: {exc}")

    except Exception as exc:
        logger.error(f"Error extracting base64EncryptedKey: {exc}")

        raise


def extract_instance_id(submission_xml: BytesIO) -> str:
    """Extract submissions's instanceID.

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
        logging.error(f"Error extracting instanceID: {exc}")

        raise


def extract_encrypted_signature(submission_xml: BytesIO) -> str:
    """Extract submission's encrypted signature.

    :param submission_xml: Submission XML file
    :return: value from the tag base64EncryptedElementSignature
    """
    try:
        submission_xml.seek(0)  # Reset file pointer
        tree = ET.fromstring(submission_xml.read())
        namespace = {"n": "http://opendatakit.org/submissions"}
        enc_sig_elem = tree.find("n:base64EncryptedElementSignature", namespace)

        if enc_sig_elem is None or not enc_sig_elem.text:
            raise InvalidSubmission(
                "base64EncryptedElementSignature element not found in submission.xml"
            )

        return enc_sig_elem.text.strip().replace("\n", "")
    except ET.ParseError as exc:
        raise InvalidSubmission(f"Invalid XML structure: {exc}")

    except Exception as exc:
        logger.error(f"Error extracting base64EncryptedElementSignature: {exc}")

        raise


def extract_encrypted_submission_file_name(submission_xml: BytesIO) -> str:
    """Extract the file name of the encrypted submission file.

    :param submission_xml: Submission XML file
    :return: value from the tag encryptedXmlFile
    """
    try:
        submission_xml.seek(0)  # Reset file pointer
        tree = ET.fromstring(submission_xml.read())
        namespace = {"n": "http://opendatakit.org/submissions"}
        enc_xml_file_elem = tree.find("n:encryptedXmlFile", namespace)

        if enc_xml_file_elem is None or not enc_xml_file_elem.text:
            raise InvalidSubmission(
                "encryptedXmlFile element not found in submission.xml"
            )

        return enc_xml_file_elem.text.strip().replace("\n", "")
    except ET.ParseError as exc:
        raise InvalidSubmission(f"Invalid XML structure: {exc}")

    except Exception as exc:
        logger.error(f"Error extracting encryptedXmlFile: {exc}")

        raise


def extract_form_id(submission_xml: BytesIO) -> str:
    """Extract the submission's form ID.

    :param submission_xml: Submission XML file
    :return: Value of the root node's "id"
    """
    try:
        submission_xml.seek(0)  # Reset file pointer
        tree = ET.fromstring(submission_xml.read())
        form_id = tree.attrib.get("id")

        if not form_id:
            raise InvalidSubmission("form id not found in submission.xml")

        return form_id
    except ET.ParseError as exc:
        raise InvalidSubmission(f"Invalid XML structure: {exc}")

    except Exception as exc:
        logging.error(f"Error extracting form id: {exc}")

        raise


def extract_version(submission_xml: BytesIO) -> str:
    """Extra the submission's version.

    :param submission_xml: Submission XML file
    :return: Value of the root node's "version"
    """
    try:
        submission_xml.seek(0)  # Reset file pointer
        tree = ET.fromstring(submission_xml.read())
        version = tree.attrib.get("version")

        if not version:
            raise InvalidSubmission("version not found in submission.xml")

        return version
    except ET.ParseError as exc:
        raise InvalidSubmission(f"Invalid XML structure: {exc}")

    except Exception as exc:
        logging.error(f"Error extracting version: {exc}")

        raise


def extract_media_file_names(submission_xml: BytesIO) -> List[str]:
    """Extract all the submission's media file names.

    :param submission_xml: Submission XML file
    :return: List of media file names
    """
    try:
        submission_xml.seek(0)  # Reset file pointer
        tree = ET.fromstring(submission_xml.read())
        namespace = {"n": "http://opendatakit.org/submissions"}

        media_files = tree.findall("n:media/n:file", namespace)
        file_names = [
            file_elem.text.strip() for file_elem in media_files if file_elem.text
        ]

        return file_names
    except ET.ParseError as exc:
        raise InvalidSubmission(f"Invalid XML structure: {exc}")
    except Exception as exc:
        logging.error(f"Error extracting media file names: {exc}")
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


def extract_n_decrypt_aes_key(kms_client: KMSClient, submission_xml: BytesIO) -> bytes:
    """Extract encrypted AES key from submission XML and decrypt it

    :param kms_client: KMSClient instance
    :param submission_xml: Submission XML file
    :return Decrypted AES key
    """
    logger.debug("Extracting encrypted AES key from submission XML.")
    encrypted_aes_key_b64 = extract_encrypted_aes_key(submission_xml)
    encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)

    logger.debug("Decrypting AES key using AWS KMS.")
    return kms_client.decrypt(encrypted_aes_key)


def decrypt_submission(
    kms_client: KMSClient,
    submission_xml: BytesIO,
    encrypted_files: Iterable[Tuple[int, BytesIO]],
) -> Iterator[Tuple[int, bytes]]:
    """Decrypt submission and media files using AWS KMS.

    :param kms_client: KMSClient instance
    :param submission_xml: Submission XML file
    :param encrypted_files: An iterable yielding encrypted file contents
    :return: A generator yielding decrypted data chunks
    """
    aes_key = extract_n_decrypt_aes_key(kms_client, submission_xml)
    instance_id = extract_instance_id(submission_xml)

    with ThreadPoolExecutor() as executor:
        futures = {
            executor.submit(decrypt_file, file, aes_key, instance_id, index): index
            for index, file in encrypted_files
        }

        for future in as_completed(futures):
            index = futures[future]

            for chunk in future.result():  # Process each chunk as it's available
                logger.debug("Decrypted chunk for index %d", index)

                yield index, chunk


def _build_signature(
    submission_xml: BytesIO,
    decrypted_submission: BytesIO,
    decrypted_media: dict[str, BytesIO],
) -> str:
    """Build a signature from a decrypted submission's content

    The signature is computed by concatenating:
    - Form ID
    - Version
    - Encrypted AES key
    - Instance ID
    - Media file names with their MD5 hashes
    - Submission file name with its MD5 hash

    :param submission_xml: Submission XML file
    :param decrypted_submission: Decrypted submission file
    :param decrypted_media: A dictionary of original media file names
                            mapped to the decrypted file
    :return Plain text signature string
    """

    def get_md5_hash_from_file(file: BytesIO) -> str:
        """Computes the MD5 hash of a file."""
        file.seek(0)
        md5 = hashlib.md5()

        while chunk := file.read(256):  # Read chunks of 256 bytes
            md5.update(chunk)

        return md5.hexdigest().zfill(32)  # Ensure 32-character padding

    def strip_enc_extension(encrypted_file_name: str) -> str:
        """Strip .enc extension from encrypted file name."""
        return encrypted_file_name.rsplit(".", 1)[0]

    signature_parts = []
    signature_parts.append(extract_form_id(submission_xml))
    signature_parts.append(extract_version(submission_xml))
    signature_parts.append(extract_encrypted_aes_key(submission_xml))
    signature_parts.append(extract_instance_id(submission_xml))

    for encrypted_media_name in extract_media_file_names(submission_xml):
        original_media_name = strip_enc_extension(encrypted_media_name)

        if original_media_name in decrypted_media:
            original_media_file = decrypted_media[original_media_name]
            original_media_md5_hash = get_md5_hash_from_file(original_media_file)
            signature_parts.append(f"{original_media_name}::{original_media_md5_hash}")

    encrypted_submission_name = extract_encrypted_submission_file_name(submission_xml)
    original_submission_name = strip_enc_extension(encrypted_submission_name)
    original_submission_md5_hash = get_md5_hash_from_file(decrypted_submission)
    signature_parts.append(
        f"{original_submission_name}::{original_submission_md5_hash}"
    )

    return "\n".join(signature_parts) + "\n"


def is_submission_valid(
    kms_client: KMSClient,
    submission_xml: BytesIO,
    decrypted_submission: BytesIO,
    decrypted_media: dict[str, BytesIO],
) -> bool:
    """Check if decryted submission is valid

    :param kms_client: KMSClient instance
    :param submission_xml: Submission XML file
    :param decrypted_submission: Decrypted submission file
    :param decrypted_media: A dictionary of original media file names
                            mapped to the decrypted file
    :return True if submission is valid, False otherwise
    """

    def compute_digest(message: str) -> bytes:
        """Computes the MD5 digest of the given message (UTF-8 encoded)."""
        return hashlib.md5(message.encode("utf-8")).digest()

    decrypted_signature = _build_signature(
        submission_xml, decrypted_submission, decrypted_media
    )
    decrypted_signature_md5_digest = compute_digest(decrypted_signature)
    encrypted_b64_signature = extract_encrypted_signature(submission_xml)
    encrypted_signature = base64.b64decode(encrypted_b64_signature)
    expected_signature = kms_client.decrypt(encrypted_signature)

    return expected_signature == decrypted_signature_md5_digest
