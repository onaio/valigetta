class InvalidSubmission(Exception):
    pass


class KMSClientError(Exception):
    """Base exception for all KMS client errors."""

    pass


class KMSKeyCreationError(KMSClientError):
    """Raised when KMS key creation fails."""

    pass


class KMSDecryptionError(KMSClientError):
    """Raised when decryption with KMS fails."""

    pass


class KMSGetPublicKeyError(KMSClientError):
    """Raised when getting the public key from KMS fails."""

    pass


class KMSDescribeKeyError(KMSClientError):
    """Raised when describing a KMS key fails."""

    pass


class KMSUpdateKeyDescriptionError(KMSClientError):
    """Raised when updating the description of a KMS key fails."""

    pass


class KMSDisableKeyError(KMSClientError):
    """Raised when disabling a KMS key fails."""

    pass


class KMSCreateAliasError(KMSClientError):
    """Raised when creating an alias for a KMS key fails."""

    pass


class KMSDeleteAliasError(KMSClientError):
    """Raised when deleting an alias for a KMS key fails."""

    pass


class KMSTokenError(KMSClientError):
    """Raised when token acquisition or refresh fails."""

    pass


class KMSUnauthorizedError(KMSClientError):
    """Raised when authentication fails permanently (e.g., bad credentials)."""

    pass


class KMSInvalidAPIURLsError(KMSClientError):
    """Raised when invalid API URLs are provided."""

    pass
