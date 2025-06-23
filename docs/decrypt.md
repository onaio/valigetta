# decrypt

`KMSClient.decrypt(**kwargs)`

Decrypts ciphertext that was encrypted by a KMS key.

## Request

```python
response = client.decrypt(
    key_id='string',
    ciphertext=b'bytes'
)
```

## PARAMETERS

- **key_id**

The identifier of the KMS key to use for decryption.

- **ciphertext**

The ciphertext to decrypt.

## Response

**RETURN TYPE**: bytes

The decrypted plaintext data.

## Exceptions

- `valigetta.exceptions.ConnectionException`
- `valigetta.exceptions.DecryptException`

## Examples

The following example decrypts a ciphertext.

```python
plaintext = client.decrypt(
    key_id="8eb847a3-9eb0-4bd9-9758-f7d14a575985",
    ciphertext=b'Ci...'
)
print(plaintext)
```

**Example Output**

```python
b'decrypted data'
```

## See Also

- **`AWSKMSClient` users**:
  [AWS KMS Decrypt API Reference](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html)
  **Required IAM Permission**: `kms:Decrypt`
- **`APIKMSClient` users**:
  This client sends a `POST` request to the `decrypt` URL.
  Example:

  ```
  POST https://kms.example.com/keys/8eb847a3-9eb0-4bd9-9758-f7d14a575985/decrypt/
  Content-Type: application/json

  {
    "ciphertext": "Q2k..."
  }
  ```
