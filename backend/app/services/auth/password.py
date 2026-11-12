from passlib.context import CryptContext

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
)

# bcrypt's hard limit. We refuse passwords above this rather than silently
# truncating — silent truncation lets two distinct passwords sharing a
# 72-byte prefix authenticate against the same hash.
BCRYPT_MAX_BYTES = 72


class PasswordTooLongError(ValueError):
    """Raised when a password exceeds bcrypt's 72-byte ceiling."""


def _check_length(password: str) -> None:
    if password is None or len(password.encode("utf-8")) > BCRYPT_MAX_BYTES:
        raise PasswordTooLongError("password_too_long")


def hash_password(password: str) -> str:
    _check_length(password)
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    # An over-length input cannot have produced this hash via hash_password,
    # so reject up-front rather than silently truncating during verify.
    if password is None or len(password.encode("utf-8")) > BCRYPT_MAX_BYTES:
        return False
    if not hashed:
        return False
    try:
        return pwd_context.verify(password, hashed)
    except Exception:
        return False
