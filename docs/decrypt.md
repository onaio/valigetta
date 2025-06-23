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

**RETURN TYPE**: dict

```python
{
    "key_id": "string",
    "plaintext": "bytes"
}
```

- **key_id**

The identifier of the KMS key used to decrypt the ciphertext.

- **plaintext**

The decrypted plaintext data.

## Exceptions

- `valigetta.exceptions.ConnectionException`
- `valigetta.exceptions.DecryptException`

## Examples

The following example decrypts a ciphertext.

```python
response = client.decrypt(
    key_id="8eb847a3-9eb0-4bd9-9758-f7d14a575985",
    ciphertext=b'Ci...'
)
print(response)
```

**Example Output**

```python
{
  "key_id": "8eb847a3-9eb0-4bd9-9758-f7d14a575985",
  "plaintext": "b'decrypted data'"
}
```

## See Also

- **`AWSKMSClient` users**:
  [AWS KMS Decrypt API Reference](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html)
  **Required IAM Permission**: `kms:Decrypt`
