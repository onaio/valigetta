class InvalidSubmissionException(Exception):
    """Raised when a submission is invalid."""

    pass


class KMSClientException(Exception):
    """Base exception for all KMS client errors."""

    pass


class CreateKeyException(KMSClientException):
    """Raised when KMS key creation fails."""

    pass


class DecryptException(KMSClientException):
    """Raised when decryption with KMS fails."""

    pass


class GetPublicKeyException(KMSClientException):
    """Raised when getting the public key from KMS fails."""

    pass


class DescribeKeyException(KMSClientException):
    """Raised when describing a KMS key fails."""

    pass


class UpdateKeyDescriptionException(KMSClientException):
    """Raised when updating the description of a KMS key fails."""

    pass


class DisableKeyException(KMSClientException):
    """Raised when disabling a KMS key fails."""

    pass


class CreateAliasException(KMSClientException):
    """Raised when creating an alias for a KMS key fails."""

    pass


class AliasAlreadyExistsException(CreateAliasException):
    """Raised when an alias already exists."""

    pass


class DeleteAliasException(KMSClientException):
    """Raised when deleting an alias for a KMS key fails."""

    pass


class AuthenticationException(KMSClientException):
    """Raised when authentication fails."""

    pass


class InvalidAPIURLException(KMSClientException):
    """Raised when invalid API URLs are provided."""

    pass
