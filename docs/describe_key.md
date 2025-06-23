# describe_key

`KMSClient.describe_key(**kwargs)`

Returns detailed information about a KMS key.

## Request

```python
response = client.describe_key(key_id='string')
```

## PARAMETERS

- **key_id**

The identifier of the KMS key.

## Response

**RETURN TYPE**: dict

```python
{
    "key_id": "string",
    "description": "string",
    "creation_date": "string",
    "enabled": "boolean"
}
```

- **key_id**

The unique identifier of the KMS key.

- **description**

The description of the KMS key.

- **creation_date**

The date and time when the KMS key was created.

- **enabled**

Whether the KMS key is enabled.

## Exceptions

- `valigetta.exceptions.ConnectionException`: Raised when a connection to the KMS server fails.
- `valigetta.exceptions.DescribeKeyException`: Raised when describing a KMS key fails.

## Examples

The following example gets detailed information about a KMS key.

```python
response = client.describe_key(key_id="8eb847a3-9eb0-4bd9-9758-f7d14a575985")
print(response)
```

**Example Output**

```python
{
    "key_id": "8eb847a3-9eb0-4bd9-9758-f7d14a575985",
    "description": "My test key",
    "creation_date": "2023-04-01T12:00:00Z",
    "enabled": true
}
```

## See Also

- **`AWSKMSClient` users**:
  [AWS KMS DescribeKey API Reference](https://docs.aws.amazon.com/kms/latest/APIReference/API_DescribeKey.html)
  **Required IAM Permission**: `kms:DescribeKey`
- **`APIKMSClient` users**:
  This client sends a `GET` request to the `describe_key` URL.
  Example:

  ```
  GET https://kms.example.com/keys/8eb847a3-9eb0-4bd9-9758-f7d14a575985/
  ```
