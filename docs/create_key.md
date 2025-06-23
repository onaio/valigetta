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
