# disable_key

`KMSClient.disable_key(**kwargs)`

Disables a KMS key.

## Request

```python
client.disable_key(key_id='string')
```

## PARAMETERS

- **key_id**

The identifier of the KMS key to disable.

## Response

**RETURN TYPE**: None

This method does not return any value.

## Exceptions

- `valigetta.exceptions.ConnectionException`: Raised when a connection to the KMS server fails.
- `valigetta.exceptions.DisableKeyException`: Raised when disabling a KMS key fails.

## Examples

The following example disables a KMS key.

```python
client.disable_key(key_id="8eb847a3-9eb0-4bd9-9758-f7d14a575985")
```

## See Also

- **`AWSKMSClient` users**:
  [AWS KMS DisableKey API Reference](https://docs.aws.amazon.com/kms/latest/APIReference/API_DisableKey.html)
  **Required IAM Permission**: `kms:DisableKey`
- **`APIKMSClient` users**:
  This client sends a `POST` request to the `disable_key` URL.
  Example:

  ```
  POST https://kms.example.com/keys/8eb847a3-9eb0-4bd9-9758-f7d14a575985/disable/
  ```
