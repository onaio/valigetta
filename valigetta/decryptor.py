"""
Submission decryption
"""

import base64
import hashlib
import hmac
import logging
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from io import BytesIO
from typing import Iterable, Iterator, List, Optional, Tuple

from Crypto.Cipher import AES

from valigetta.exceptions import InvalidSubmission
from valigetta.kms import KMSClient

logger = logging.getLogger(__name__)

NAMESPACE = {
    "n": "http://opendatakit.org/submissions",
    "meta": "http://openrosa.org/xforms",
}


def _parse_submission_xml(submission_xml: BytesIO) -> ET.Element:
    """Parses the XML file."""
    try:
        submission_xml.seek(0)
        return ET.fromstring(submission_xml.read())
    except ET.ParseError as exc:
        raise InvalidSubmission(f"Invalid XML structure: {exc}")


def _extract_xml_value(
    tree: ET.Element, xpath: str, namespace: dict = NAMESPACE
) -> Optional[str]:
    """Generic function to extract an XML element's text value."""
    element = tree.find(xpath, namespace)

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

    raise InvalidSubmission("base64EncryptedKey element not found in submission.xml")


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

    raise InvalidSubmission("instanceID not found in submission.xml")


def extract_encrypted_signature(tree: ET.Element) -> str:
    """Extract submission's encrypted signature.

    :param tree: Parsed XML tree
    :return: Value from the tag base64EncryptedElementSignature
    """
    enc_signature = _extract_xml_value(tree, "n:base64EncryptedElementSignature")

    if enc_signature:
        return enc_signature

    raise InvalidSubmission(
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

    raise InvalidSubmission("encryptedXmlFile element not found in submission.xml")


def extract_form_id(tree: ET.Element) -> str:
    """Extract the submission's form ID.

    :param tree: Parsed XML tree
    :return: Value of the root node's "id"
    """
    form_id = tree.attrib.get("id")

    if form_id:
        return form_id

    raise InvalidSubmission("Form ID not found in submission.xml")


def extract_version(tree: ET.Element) -> str:
    """Extra the submission's version.

    :param tree: Parsed XML tree
    :return: Value of the root node's "version"
    """
    version = tree.attrib.get("version")

    if version:
        return version

    raise InvalidSubmission("version not found in submission.xml")


def extract_encrypted_media_file_names(tree: ET.Element) -> List[str]:
    """Extract all the encrypted submission's media file names.

    :param tree: Parsed XML tree
    :return: List of media file names
    """
    return [
        elem.text.strip()
        for elem in tree.findall("n:media/n:file", NAMESPACE)
        if elem.text
    ]


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
    file.seek(0)
    logger.debug("Generating IV for index %d", index)
    iv = _get_submission_iv(instance_id, aes_key, index)
    cipher_aes = AES.new(aes_key, AES.MODE_CFB, iv=iv, segment_size=128)

    while chunk := file.read(4096):  # Read chunks of 4KB
        yield cipher_aes.decrypt(chunk)


def decrypt_submission(
    kms_client: KMSClient,
    submission_xml: BytesIO,
    enc_files: Iterable[Tuple[str, BytesIO]],
) -> Iterator[Tuple[str, BytesIO]]:
    """Decrypt submission and media files using AWS KMS.

    :param kms_client: KMSClient instance
    :param submission_xml: Submission XML file
    :param enc_files: An iterable yielding encrypted files
    :return: A generator yielding decrypted files
    """
    dec_files: dict[str, BytesIO] = {}
    tree = _parse_submission_xml(submission_xml)

    logger.debug("Extracting encrypted AES key from submission XML.")
    enc_aes_key_b64 = extract_encrypted_aes_key(tree)
    enc_aes_key = base64.b64decode(enc_aes_key_b64)

    logger.debug("Decrypting AES key using AWS KMS.")
    aes_key = kms_client.decrypt(enc_aes_key)

    instance_id = extract_instance_id(tree)
    enc_submission_name = extract_encrypted_submission_file_name(tree)
    enc_media_names = extract_encrypted_media_file_names(tree)

    def decrypt_task(enc_file_name: str, enc_file: BytesIO):
        """Helper function to decrypt a single file and store it in BytesIO."""
        if enc_file_name == enc_submission_name:
            index = 0  # Submission files use index 0
        else:
            try:
                index = enc_media_names.index(enc_file_name) + 1
            except ValueError:
                raise InvalidSubmission(
                    f"Media {enc_file_name} not found in submission.xml"
                )

        dec_file_name = _strip_enc_extension(enc_file_name)
        dec_stream = BytesIO()

        for chunk in decrypt_file(enc_file, aes_key, instance_id, index):
            dec_stream.write(chunk)

        dec_stream.seek(0)  # Reset stream position for reading
        dec_files[dec_file_name] = dec_stream

    # Use a thread pool to decrypt files in parallel
    with ThreadPoolExecutor() as executor:
        futures = [
            executor.submit(decrypt_task, name, file) for name, file in enc_files
        ]

        # Ensure all decryption tasks complete
        for future in as_completed(futures):
            future.result()

    dec_submission_name = _strip_enc_extension(enc_submission_name)
    dec_submission = dec_files[dec_submission_name]
    dec_media = {k: v for k, v in dec_files.items() if k != dec_submission_name}

    if not is_submission_valid(
        kms_client=kms_client,
        tree=tree,
        dec_submission=dec_submission,
        dec_media=dec_media,
    ):
        raise InvalidSubmission(
            (
                f"Submission validation failed for instance ID {instance_id}. "
                "Corrupted data or incorrect signature"
            )
        )

    for dec_file_name, dec_file in dec_files.items():
        yield dec_file_name, dec_file


def _strip_enc_extension(encrypted_file_name: str) -> str:
    """Strip .enc extension from encrypted file name."""
    return encrypted_file_name.rsplit(".", 1)[0]


def _build_signature(
    tree: ET.Element,
    dec_submission: BytesIO,
    dec_media: dict[str, BytesIO],
) -> str:
    """Build a signature from a decrypted submission's content

    The signature is computed by concatenating:
    - Form ID
    - Version
    - Encrypted AES key
    - Instance ID
    - Media file names with their MD5 hashes
    - Submission file name with its MD5 hash

    :param tree: Parsed XML tree
    :param dec_submission: Decrypted submission file
    :param dec_media: A dictionary of original media file names
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

    signature_parts = []
    signature_parts.append(extract_form_id(tree))
    signature_parts.append(extract_version(tree))
    signature_parts.append(extract_encrypted_aes_key(tree))
    signature_parts.append(extract_instance_id(tree))

    for enc_media_name in extract_encrypted_media_file_names(tree):
        dec_media_name = _strip_enc_extension(enc_media_name)

        if dec_media_name in dec_media:
            dec_media_file = dec_media[dec_media_name]
            dec_media_md5_hash = get_md5_hash_from_file(dec_media_file)
            signature_parts.append(f"{dec_media_name}::{dec_media_md5_hash}")

    enc_submission_name = extract_encrypted_submission_file_name(tree)
    dec_submission_name = _strip_enc_extension(enc_submission_name)
    dec_submission_md5_hash = get_md5_hash_from_file(dec_submission)
    signature_parts.append(f"{dec_submission_name}::{dec_submission_md5_hash}")

    return "\n".join(signature_parts) + "\n"


def is_submission_valid(
    kms_client: KMSClient,
    tree: ET.Element,
    dec_submission: BytesIO,
    dec_media: Optional[dict[str, BytesIO]] = None,
) -> bool:
    """Check if decryted submission is valid

    :param kms_client: KMSClient instance
    :param tree: Parsed XML tree
    :param dec_submission: Decrypted submission file
    :param dec_media: A dictionary of original media file names
                            mapped to the decrypted file
    :return True if submission is valid, False otherwise
    """

    def compute_digest(message: str) -> bytes:
        """Computes the MD5 digest of the given message (UTF-8 encoded)."""
        return hashlib.md5(message.encode("utf-8")).digest()

    if dec_media is None:
        dec_media = {}

    try:
        decrypted_signature = _build_signature(tree, dec_submission, dec_media)
        computed_signature_digest = compute_digest(decrypted_signature)
        encrypted_b64_signature = extract_encrypted_signature(tree)
        encrypted_signature = base64.b64decode(encrypted_b64_signature)
        expected_signature_digest = kms_client.decrypt(encrypted_signature)

        logger.debug("Comparing submission signatures")

        return hmac.compare_digest(expected_signature_digest, computed_signature_digest)

    except Exception as exc:
        logger.error(f"Error validating submission: {exc}")

        raise InvalidSubmission(f"Failed to validate submission: {exc}")
