# create_alias

`KMSClient.create_alias(**kwargs)`

Creates an alias for a KMS key.

## Request

```python
client.create_alias(
    alias_name='string',
    key_id='string'
)
```

## PARAMETERS

- **alias_name**

The name of the alias to create.

- **key_id**

The identifier of the KMS key to associate with the alias.

## Response

**RETURN TYPE**: None

This method does not return any value.

## Exceptions

- `valigetta.exceptions.ConnectionException`
- `valigetta.exceptions.CreateAliasException`
- `valigetta.exceptions.AliasAlreadyExistsException`

## Examples

The following example creates an alias for a KMS key.

```python
client.create_alias(
    alias_name="alias/my-key-alias",
    key_id="8eb847a3-9eb0-4bd9-9758-f7d14a575985"
)
```

## See Also

- **`AWSKMSClient` users**:
  [AWS KMS CreateAlias API Reference](https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateAlias.html)
  **Required IAM Permission**: `kms:CreateAlias`
- **`APIKMSClient` users**:
  This client sends a `PATCH` request to the `create_alias` URL.
  Example:

  ```
  PATCH https://kms.example.com/keys/8eb847a3-9eb0-4bd9-9758-f7d14a575985
  Content-Type: application/json

  {
      "alias": "alias/my-key-alias"
  }
  ```
