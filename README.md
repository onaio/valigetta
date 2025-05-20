# Valigetta

![Coverage](https://onaio.github.io/valigetta/coverage/coverage.svg)

A Python Software Development Kit (SDK) for managing keys and decrypting submissions from ODK servers.

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
