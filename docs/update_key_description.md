# update_key_description

`KMSClient.update_key_description(**kwargs)`

Updates the description of a KMS key.

## Request

```python
client.update_key_description(
    key_id='string',
    description='string'
)
```

## PARAMETERS

- **key_id**

The identifier of the KMS key.

- **description**

The new description of the KMS key.

> **WARNING**
>
> Do not include confidential or sensitive information in this field. This field may be displayed in plaintext in CloudTrail logs and other output.

## Response

**RETURN TYPE**: None

This method does not return any value.

## Exceptions

- `valigetta.exceptions.ConnectionException`: Raised when a connection to the KMS server fails.
- `valigetta.exceptions.UpdateKeyDescriptionException`: Raised when updating the description of a KMS key fails.

## Examples

The following example updates the description of a KMS key.

```python
client.update_key_description(
    key_id="8eb847a3-9eb0-4bd9-9758-f7d14a575985",
    description="Updated key description"
)
```

## See Also

- **`AWSKMSClient` users**:
  [AWS KMS UpdateKeyDescription API Reference](https://docs.aws.amazon.com/kms/latest/APIReference/API_UpdateKeyDescription.html)
  **Required IAM Permission**: `kms:UpdateKeyDescription`
- **`APIKMSClient` users**:
  This client sends a `PATCH` request to the `update_key_description` URL.
  Example:

  ```
  PATCH https://kms.example.com/keys/8eb847a3-9eb0-4bd9-9758-f7d14a575985/
  Content-Type: application/json

  {
      "description": "Updated key description"
  }
  ```
