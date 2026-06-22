class FcoinError(Exception):
    """Base exception for expected FCOIN failures."""


class ValidationError(FcoinError):
    """Input data failed structural validation."""


class DependencyError(FcoinError):
    """A required external tool is unavailable."""


class AcquisitionError(FcoinError):
    """A card acquisition operation failed."""


class PlanError(FcoinError):
    """A proposed change is unsafe or inconsistent."""


class ProfileError(FcoinError):
    """A card profile is invalid or does not authorize an operation."""


class VerificationError(FcoinError):
    """Post-operation verification failed."""
