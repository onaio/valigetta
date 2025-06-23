# Valigetta

![Coverage](https://onaio.github.io/valigetta/coverage/coverage.svg)

A Python Software Development Kit (SDK) for managing keys and decrypting submissions from ODK servers.

## Usage

Valigetta supports multiple key management service (KMS) backends. Choose a client class depending on the KMS provider you use.

### AWSKMSClient (Amazon Web Services)

Use this client if you manage your keys using [AWS KMS](https://aws.amazon.com/kms/).

```python
from valigetta import AWSKMSClient

client = AWSKMSClient(
    aws_access_key_id="your-access-key",
    aws_secret_access_key="your-secret-key",
    region="us-east-1"
)

key = client.create_key(description="My first key")
```

### APIKMSClient (Custom HTTP API)

Use this client if your organization provides a KMS-compatible HTTP API.

```python
from valigetta import APIKMSClient

client = APIKMSClient(
    client_id="your-client-id",
    client_secret="your-client-secret",
    urls={
        "token": "https://kms.example.com/auth/token/",
        "token_refresh": "https://kms.example.com/auth/refresh/",
        "create_key": "https://kms.example.com/keys/",
        "decrypt": "https://kms.example.com/keys/{key_id}/decrypt/",
        "get_public_key": "https://kms.example.com/keys/{key_id}/",
        "describe_key": "https://kms.example.com/keys/{key_id}/",
        "update_key_description": "https://kms.example.com/keys/{key_id}/",
        "disable_key": "https://kms.example.com/keys/{key_id}/disable/",
        "create_alias": "https://kms.example.com/keys/{key_id}",
    }
)

key = client.create_key(description="My first key")
```

All clients support the same interface:

- [KMSClient.create_key](docs/create_key.md)
- [KMSClient.decrypt](docs/decrypt.md)
- [KMSClient.get_public_key](docs/get_public_key.md)
- [KMSClient.describe_key](docs/describe_key.md)
- [KMSClient.update_key_description](docs/update_key_description.md)
- [KMSClient.disable_key](docs/disable_key.md)
- [KMSClient.create_alias](docs/create_alias.md)
- [KMSClient.delete_alias](docs/delete_alias.md)

## Development

### Prerequisites

Python >= 3.11.2

An active Python virtual environment.

### Setting up the development environment

Change directory into the root of the project

Install the pre-commit hooks by running in the terminal:

```sh
pre-commit install
```

Install the development requirements in your local virtual environment by executing in the terminal:

```sh
pip install -r requirements/dev.txt
```

### Installing packages

Package installation is via `pip-compile` provided by the [pip-tools](https://pypi.org/project/pip-tools/) package. Install this package in your environment.

To add a new package, update the corresponding `requirements/<environment>.in` depending on the package's purpose.

Compile `requirements/dev.txt` by running the command

```sh
pip-compile --output-file=requirements/dev.txt requirements/dev.in
```

Re-install the development requirements in your local virtual environment by executing in the terminal:

```sh
pip install -r requirements/dev.txt
```

### Running tests

To run all tests

```sh
pytest -s -vv
```

To run tests with coverage

```sh
coverage run -m pytest -s -vv
```

## License

[GNU GENERAL PUBLIC LICENSE](https://github.com/onaio/valigetta/blob/main/LICENSE)
