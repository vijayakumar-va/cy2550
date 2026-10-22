import bcrypt


def hash_password(password: str) -> str:
    """Return a secure hash of password suitable for database storage."""
    password_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode("utf-8")


def verify_password(password: str, stored_hash: str) -> bool:
    """Return True if password matches stored_hash, False otherwise."""
    password_bytes = password.encode("utf-8")
    stored_hash_bytes = stored_hash.encode("utf-8")
    return bcrypt.checkpw(password_bytes, stored_hash_bytes)
