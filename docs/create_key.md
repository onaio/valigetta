# create_key

`KMSClient.create_key(**kwargs)`

Creates a unique managed key in your key management service provider.

The key created is an RSA 2048-bit key pair.

## Request

```python

response = client.create_key(description='string')
```

**PARAMETERS**

- **description**

A description of the KMS key. The default value is an empty string.

> **WARNING**
>
> Do not include confidential or sensitive information in this field. This field may be displayed in plaintext in CloudTrail logs and other output.

## Response

**RETURN TYPE**: dict

```python
{
    "key_id": "string",
    "description": "string",
    "creation_date": "string"
}
```

- **key_id**

The unique identifier of the KMS key.

- **description**

The description of the KMS key.

- **creation_date**

The date and time when the KMS key was created.

## Exceptions

- `valigetta.exceptions.ConnectionException`
- `valigetta.exceptions.CreateKeyException`

## Examples

The following example creates a new key with the description "My test key".

```python
response = client.create_key(description="My test key")
print(response)
```

**Example Output**

```python
{
  "key_id": "8eb847a3-9eb0-4bd9-9758-f7d14a575985",
  "description": "My test key",
  "creation_date": "2023-04-01T12:00:00Z"
}
```

## See Also

- **`AWSKMSClient` users**:
  [AWS KMS CreateKey API Reference](https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateKey.html)
  **Required IAM Permission**: `kms:CreateKey`
- **`APIKMSClient` users**:
  Makes a `POST` request to the `create_key` URL.
  Example:

  ```
  POST https://kms.example.com/keys/
  Content-Type: application/json

  {
    "description": "My first key"
  }
  ```
