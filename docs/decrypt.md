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
