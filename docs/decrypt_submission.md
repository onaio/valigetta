# decrypt_submission

`valigetta.submission.decrypt_submission(**kwargs)`

Decrypts an encrypted ODK submission, including the submission XML and any associated media files.

All encrypted files referenced in the submission manifest must be provided. If any required file is missing, an `valigetta.exceptions.InvalidSubmissionException.InvalidSubmissionException` will be raised.

## Request

```python
from valigetta import KMSClient
from io import BytesIO
from typing import Iterator

def decrypt_submission(
    kms_client: KMSClient,
    key_id: str,
    submission_xml: BytesIO,
    enc_files: dict[str, BytesIO],
) -> Iterator[tuple[str, BytesIO]]:
```

## PARAMETERS

- **kms_client**

An instance of a `KMSClient` implementation (e.g., `AWSKMSClient`, `APIKMSClient`).

- **key_id**

The identifier of the KMS key used to encrypt the submission.

- **submission_xml**

A `io.BytesIO` object of the [submission manifest](https://getodk.github.io/xforms-spec/encryption.html#submission-manifest).

This file provides the metadata required for decryption (e.g., instance ID, encrypted AES key, media file names).

- **enc_files**

A dictionary mapping encrypted file names to `io.BytesIO` objects of the submission’s encrypted files.

All encrypted file names listed in the `<encryptedXmlFile>` and `<media><file>` tags of the [submission manifest](https://getodk.github.io/xforms-spec/encryption.html#submission-manifest) **must** be included as keys in this dictionary. These files are:

- The encrypted submission file (e.g., `submission.xml.enc`)
- Any encrypted media files (e.g., `myimage.jpg.enc`, `myaudio.mp3.enc`)

If any of these files are missing in `enc_files`, `InvalidSubmissionException` will be raised.

## Response

**RETURN TYPE**: `Iterator[tuple[str, BytesIO]]`

A generator that yields a tuple for each decrypted file. Each tuple contains:

- The original file name (e.g., `submission.xml`).
- A `io.BytesIO` object with the decrypted content.

## Exceptions

- `valigetta.exceptions.InvalidSubmissionException`: Raised if the submission is invalid, corrupted, or validation fails.
- `valigetta.exceptions.ConnectionException`: Raised on connection errors with the KMS.
- `valigetta.exceptions.DecryptException`: Raised if decryption fails in the KMS.

## Examples

The following example decrypts an ODK submission package.

```python
from valigetta import AWSKMSClient
from valigetta.submission import decrypt_submission
from io import BytesIO

# Initialize the KMS client
kms = AWSKMSClient(
    aws_access_key_id="your-access-key",
    aws_secret_access_key="your-secret-key",
    region_name="us-east-1"
)

# Decrypt the submission
with open("submission.xml", "rb") as submission_xml, \
     open("submission.xml.enc", "rb") as enc_submission_xml, \
     open("sunset.png.enc", "rb") as enc_media1, \
     open("forest.mp4.enc", "rb") as enc_media2:

    for original_name, decrypted_file in decrypt_submission(
        kms_client=kms,
        key_id="your-key-id",
        submission_xml=BytesIO(submission_xml.read()),
        enc_files={
            "submission.xml.enc": BytesIO(enc_submission_xml.read()),
            "sunset.png.enc": BytesIO(enc_media1.read()),
            "forest.mp4.enc": BytesIO(enc_media2.read()),
        }
    ):
        with open(original_name, "wb") as out_file:
            out_file.write(decrypted_file.read())
```
