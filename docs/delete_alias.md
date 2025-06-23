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

- `valigetta.exceptions.ConnectionException`
- `valigetta.exceptions.DeleteAliasException`

## Examples

The following example deletes an alias for a KMS key.

```python
client.delete_alias(alias_name="alias/my-key-alias")
```
