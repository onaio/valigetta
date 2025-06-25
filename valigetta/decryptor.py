"""
Submission decryption
"""

import base64
import hashlib
import hmac
import logging
import xml.etree.ElementTree as ET
from io import BytesIO
from typing import Iterable, Iterator, List, Optional, Tuple

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from valigetta.exceptions import InvalidSubmissionException
from valigetta.kms import KMSClient

logger = logging.getLogger(__name__)


def _get_namespaces(tree: ET.Element) -> dict:
    root_ns = tree.tag.split("}")[0].strip("{")

    return {
        "n": root_ns,
        "meta": "http://openrosa.org/xforms",
    }


def _parse_submission_xml(submission_xml: BytesIO) -> ET.Element:
    """Parses the XML file."""
    try:
        submission_xml.seek(0)
        return ET.fromstring(submission_xml.read())
    except ET.ParseError as exc:
        raise InvalidSubmissionException(f"Invalid XML structure: {exc}")


def _extract_xml_value(tree: ET.Element, xpath: str) -> Optional[str]:
    """Generic function to extract an XML element's text value."""
    namespaces = _get_namespaces(tree)
    element = tree.find(xpath, namespaces)

    if element is None or not element.text:
        return None

    return element.text.strip()


def extract_encrypted_aes_key(tree: ET.Element) -> str:
    """Extract submission's encrypted AES key.

    :param tree: Parsed XML tree
    :return: Value from the tag base64EncryptedKey
    """
    enc_aes_key = _extract_xml_value(tree, "n:base64EncryptedKey")

    if enc_aes_key:
        return enc_aes_key

    raise InvalidSubmissionException(
        "base64EncryptedKey element not found in submission.xml"
    )


def extract_instance_id(tree: ET.Element) -> str:
    """Extract submissions's instanceID.

    :param tree: Parsed XML tree
    :return: Value of the root node's "instanceID"
    """

    instance_id = tree.attrib.get("instanceID")

    if instance_id:
        return instance_id

    # Fallback to searching inside meta tag
    meta_elem = tree.find(".//{http://openrosa.org/xforms}meta")

    if meta_elem is not None:
        instance_id_elem = meta_elem.find("{http://openrosa.org/xforms}instanceID")
        if instance_id_elem is not None and instance_id_elem.text:
            return instance_id_elem.text.strip()

    raise InvalidSubmissionException("instanceID not found in submission.xml")


def extract_encrypted_signature(tree: ET.Element) -> str:
    """Extract submission's encrypted signature.

    :param tree: Parsed XML tree
    :return: Value from the tag base64EncryptedElementSignature
    """
    enc_signature = _extract_xml_value(tree, "n:base64EncryptedElementSignature")

    if enc_signature:
        return enc_signature

    raise InvalidSubmissionException(
        "base64EncryptedElementSignature element not found in submission.xml"
    )


def extract_encrypted_submission_file_name(tree: ET.Element) -> str:
    """Extract the file name of the encrypted submission file.

    :param tree: Parsed XML tree
    :return: Value from the tag encryptedXmlFile
    """
    enc_submisson_name = _extract_xml_value(tree, "n:encryptedXmlFile")

    if enc_submisson_name:
        return enc_submisson_name

    raise InvalidSubmissionException(
        "encryptedXmlFile element not found in submission.xml"
    )


def extract_form_id(tree: ET.Element) -> str:
    """Extract the submission's form ID.

    :param tree: Parsed XML tree
    :return: Value of the root node's "id"
    """
    form_id = tree.attrib.get("id")

    if form_id:
        return form_id

    raise InvalidSubmissionException("Form ID not found in submission.xml")


def extract_version(tree: ET.Element) -> str:
    """Extra the submission's version.

    :param tree: Parsed XML tree
    :return: Value of the root node's "version"
    """
    version = tree.attrib.get("version")

    if version:
        return version

    raise InvalidSubmissionException("version not found in submission.xml")


def extract_encrypted_media_file_names(tree: ET.Element) -> List[str]:
    """Extract all the encrypted submission's media file names.

    :param tree: Parsed XML tree
    :return: List of media file names
    """
    namespaces = _get_namespaces(tree)
    return [
        elem.text.strip()
        for elem in tree.findall("n:media/n:file", namespaces)
        if elem.text
    ]


def _get_submission_iv(instance_id: str, aes_key: bytes, iv_counter: int) -> bytes:
    """Generates a 16-byte initialization vector (IV) for AES encryption.

    The IV is created by hashing the instance ID and AES key, then mutating
    the hash based on the iv_counter.

    :param instance_id: Unique instance ID from submission.xml
    :param aes_key: Symmetric key used for encryption
    :param iv_counter: Counter used for mutating the IV
    :return: A 16-byte initialization vector (IV)
    """
    md5_hash = hashlib.md5()
    md5_hash.update(instance_id.encode("utf-8"))
    md5_hash.update(aes_key)

    iv_seed_array = bytearray(md5_hash.digest())

    # Mutate IV based on iv_counter
    for i in range(iv_counter):
        iv_seed_array[i % 16] = (iv_seed_array[i % 16] + 1) % 256

    return bytes(iv_seed_array)


def decrypt_file(
    file: BytesIO, aes_key: bytes, instance_id: str, iv_counter: int
) -> bytes:
    """Decrypt a single file.

    :param file: File to be decrypted
    :param aes_key: Symmetric key used during encryption
    :param instance_id: instanceID of the submission
    :param iv_counter: Counter used for mutating the IV
    :return: Decrypted file in bytes
    """
    file.seek(0)
    logger.debug("Generating IV for iv_counter %d", iv_counter)
    iv = _get_submission_iv(instance_id, aes_key, iv_counter)
    cipher_aes = AES.new(aes_key, AES.MODE_CFB, iv=iv, segment_size=128)
    decrypted = cipher_aes.decrypt(file.read())
    # Strip any PKCS5/PKCS7 padding
    return unpad(decrypted, AES.block_size)


def decrypt_submission(
    kms_client: KMSClient,
    key_id: str,
    submission_xml: BytesIO,
    enc_files: dict[str, BytesIO],
) -> Iterator[Tuple[str, BytesIO]]:
    """Decrypt submission's encrypted files.

    :param kms_client: KMSClient instance
    :param key_id: Identifier for the KMS key
    :param submission_xml: Submission XML file
    :param enc_files: Encrypted files
    :return: A generator yielding decrypted files
    """
    tree = _parse_submission_xml(submission_xml)

    logger.debug("Extracting encrypted AES key from submission XML.")
    enc_aes_key_b64 = extract_encrypted_aes_key(tree)
    enc_aes_key = base64.b64decode(enc_aes_key_b64)

    logger.debug("Decrypting AES key using AWS KMS.")
    aes_key = kms_client.decrypt(key_id=key_id, ciphertext=enc_aes_key)

    instance_id = extract_instance_id(tree)
    enc_submission_name = extract_encrypted_submission_file_name(tree)
    enc_media_names = extract_encrypted_media_file_names(tree)

    def decrypt_files():
        # Process media files in order they appear in submission.xml
        for i, enc_file_name in enumerate(enc_media_names, start=1):
            if enc_file_name not in enc_files:
                raise InvalidSubmissionException(
                    f"Media file {enc_file_name} not found in provided files."
                )

            enc_file = enc_files[enc_file_name]
            dec_data = decrypt_file(enc_file, aes_key, instance_id, i)
            yield _strip_enc_extension(enc_file_name), BytesIO(dec_data)

        # Process submission file last with index = number of media files + 1
        if enc_submission_name not in enc_files:
            raise InvalidSubmissionException(
                f"Submission file {enc_submission_name} not found in provided files."
            )

        dec_data = decrypt_file(
            enc_files[enc_submission_name],
            aes_key,
            instance_id,
            len(enc_media_names) + 1,
        )
        yield _strip_enc_extension(enc_submission_name), BytesIO(dec_data)

    if not is_submission_valid(
        kms_client=kms_client,
        key_id=key_id,
        tree=tree,
        dec_files=decrypt_files(),
    ):
        raise InvalidSubmissionException(
            (
                f"Submission validation failed for instance ID {instance_id}. "
                "Corrupted data or incorrect signature"
            )
        )

    yield from decrypt_files()


def _strip_enc_extension(encrypted_file_name: str) -> str:
    """Strip .enc extension from encrypted file name."""
    return encrypted_file_name.rsplit(".", 1)[0]


def _build_signature(
    tree: ET.Element,
    dec_files: Iterable[Tuple[str, BytesIO]],
) -> str:
    """Build a signature from a decrypted submission's content

    The signature is computed by concatenating:
    - Form ID
    - Version (if present)
    - Encrypted AES key
    - Instance ID
    - Media file names with their MD5 hashes
    - Submission file name with its MD5 hash

    :param tree: Parsed XML tree
    :param dec_files: Decrypted files
    :return Plain text signature string
    """

    def get_md5_hash_from_file(file: BytesIO) -> str:
        """Computes the MD5 hash of a file."""
        file.seek(0)
        md5 = hashlib.md5()

        while chunk := file.read(256):  # Read chunks of 256 bytes
            md5.update(chunk)

        return md5.hexdigest().zfill(32)  # Ensure 32-character padding

    # Start with form ID
    signature_parts = [extract_form_id(tree)]

    # Only add version if present
    version = extract_version(tree)

    if version:
        signature_parts.append(version)

    # Add encrypted key
    signature_parts.append(extract_encrypted_aes_key(tree))
    # Add instance ID
    signature_parts.append(extract_instance_id(tree))

    enc_submission_name = extract_encrypted_submission_file_name(tree)
    dec_submission_name = _strip_enc_extension(enc_submission_name)
    enc_media_names = extract_encrypted_media_file_names(tree)
    dec_submission_parts = []
    dec_media_parts = [_strip_enc_extension(name) for name in enc_media_names]

    # Media files in the same order as they appear in submission.xml
    for dec_file_name, dec_file in dec_files:
        if dec_file_name == dec_submission_name:
            # Submission file
            dec_file_md5_hash = get_md5_hash_from_file(dec_file)
            dec_submission_parts.append(f"{dec_submission_name}::{dec_file_md5_hash}")
        else:
            # Media file. We concatenate media hashes in the same order
            # the files appear in submission.xml
            index = dec_media_parts.index(dec_file_name)
            dec_file_md5_hash = get_md5_hash_from_file(dec_file)
            dec_media_parts[index] = f"{dec_file_name}::{dec_file_md5_hash}"

    signature_parts.extend(dec_media_parts)

    # Submission file last
    signature_parts.extend(dec_submission_parts)

    signature = "\n".join(signature_parts) + "\n"
    logger.debug("Built signature:\n%s", signature)
    return signature


def is_submission_valid(
    kms_client: KMSClient,
    key_id: str,
    tree: ET.Element,
    dec_files: Iterable[Tuple[str, BytesIO]],
) -> bool:
    """Check if decryted submission is valid

    :param kms_client: KMSClient instance
    :param key_id: Identifier for the KMS key
    :param tree: Parsed XML tree
    :param dec_files: Decrypted files
    :return True if submission is valid, False otherwise
    """

    def compute_digest(message: str) -> bytes:
        """Computes the MD5 digest of the given message"""
        return hashlib.md5(message.encode("utf-8")).digest()

    computed_signature = _build_signature(tree, dec_files)
    computed_signature_digest = compute_digest(computed_signature)
    encrypted_b64_signature = extract_encrypted_signature(tree)
    encrypted_signature = base64.b64decode(encrypted_b64_signature)
    expected_signature_digest = kms_client.decrypt(
        key_id=key_id, ciphertext=encrypted_signature
    )

    logger.debug("Computed signature digest: %r", computed_signature_digest)
    logger.debug("Expected signature digest: %r", expected_signature_digest)

    return hmac.compare_digest(expected_signature_digest, computed_signature_digest)
