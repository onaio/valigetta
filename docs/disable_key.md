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

- `valigetta.exceptions.ConnectionException`
- `valigetta.exceptions.DisableKeyException`

## Examples

The following example disables a KMS key.

```python
client.disable_key(key_id="8eb847a3-9eb0-4bd9-9758-f7d14a575985")
```
