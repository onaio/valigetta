# delete_alias

`KMSClient.delete_alias(**kwargs)`

Deletes an alias for a KMS key.

## Request

```python
client.delete_alias(alias_name='string')
```

## PARAMETERS

- **alias_name**

The name of the alias to delete.

## Response

**RETURN TYPE**: None

This method does not return any value.

## Exceptions

- `valigetta.exceptions.ConnectionException`: Raised when a connection to the KMS server fails.
- `valigetta.exceptions.DeleteAliasException`: Raised when deleting an alias for a KMS key fails.

## Examples

The following example deletes an alias for a KMS key.

```python
client.delete_alias(alias_name="alias/my-key-alias")
```

## See Also

- **`AWSKMSClient` users**:
  [AWS KMS DeleteAlias API Reference](https://docs.aws.amazon.com/kms/latest/APIReference/API_DeleteAlias.html)
  **Required IAM Permission**: `kms:DeleteAlias`
- **`APIKMSClient` users**:
  This method is not supported by the `APIKMSClient`.
