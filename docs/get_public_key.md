# get_public_key

`KMSClient.get_public_key(**kwargs)`

Gets the public key of a KMS key.

## Request

```python
response = client.get_public_key(key_id='string')
```

## PARAMETERS

- **key_id**

The identifier of the KMS key.

## Response

**RETURN TYPE**: string

The public key of the KMS key.

## Exceptions

- `valigetta.exceptions.ConnectionException`
- `valigetta.exceptions.GetPublicKeyException`

## Examples

The following example gets the public key of a KMS key.

```python
response = client.get_public_key(key_id="8eb847a3-9eb0-4bd9-9758-f7d14a575985")
print(response)
```

**Example Output**

```text
"-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
```
