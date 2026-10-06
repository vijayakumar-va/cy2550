"""Password-based file encryption with AES-256-GCM (hardened version of ai_crypto.py).

Requires:  sudo apt install python3-cryptography   (or: pip install cryptography)

File layout:  MAGIC (5) | salt (16) | nonce (12) | ciphertext | GCM tag (16)

Changes from ai_crypto.py:
  1. Output and temp files are created with O_EXCL and mode 0600, so another
     user cannot read the plaintext or plant a symlink at the temp path.
  2. Existing output files are never silently overwritten.
  3. Encryption refuses passwords shorter than MIN_PASSWORD_LEN characters.

Usage:
    python3 fixed_crypto.py encrypt message.txt
    python3 fixed_crypto.py decrypt message.txt.enc -o roundtrip.txt
"""

import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"AESF1"
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
HEADER_LEN = len(MAGIC) + SALT_LEN + NONCE_LEN
CHUNK_SIZE = 1024 * 1024
MAX_PLAINTEXT_BYTES = 2**36 - 32
MIN_PASSWORD_LEN = 12


def _derive_key(password: str, salt: bytes) -> bytes:
    """Stretch a password into a 256-bit key with scrypt (memory-hard, deliberately slow)."""
    kdf = Scrypt(salt=salt, length=32, n=2**17, r=8, p=1)
    return kdf.derive(password.encode("utf-8"))


def _open_private(path: Path):
    """Create a brand-new file readable only by its owner.

    O_EXCL fails if anything (including a symlink) already exists at `path`,
    and 0o600 keeps other users on the machine from reading it.
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    return os.fdopen(fd, "wb")


def _check_dst(dst: Path):
    if dst.exists():
        raise FileExistsError(f"{dst} already exists; refusing to overwrite it")


def encrypt_file(src, password: str, dst=None) -> Path:
    src = Path(src)
    dst = Path(dst) if dst else src.with_name(src.name + ".enc")
    if len(password) < MIN_PASSWORD_LEN:
        raise ValueError(f"password must be at least {MIN_PASSWORD_LEN} characters")
    if src.stat().st_size > MAX_PLAINTEXT_BYTES:
        raise ValueError("file is too large for a single AES-GCM stream (limit ~64 GiB)")
    _check_dst(dst)

    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    header = MAGIC + salt + nonce

    encryptor = Cipher(algorithms.AES(_derive_key(password, salt)), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(header)

    tmp = dst.with_name(dst.name + ".tmp")
    created = False
    try:
        with open(src, "rb") as fin, _open_private(tmp) as fout:
            created = True
            fout.write(header)
            while chunk := fin.read(CHUNK_SIZE):
                fout.write(encryptor.update(chunk))
            fout.write(encryptor.finalize())
            fout.write(encryptor.tag)
        _check_dst(dst)
        os.replace(tmp, dst)
    finally:
        if created:
            tmp.unlink(missing_ok=True)
    return dst


def decrypt_file(src, password: str, dst=None) -> Path:
    src = Path(src)
    if dst:
        dst = Path(dst)
    elif src.suffix == ".enc":
        dst = src.with_suffix("")
    else:
        dst = src.with_name(src.name + ".dec")
    _check_dst(dst)

    ciphertext_len = src.stat().st_size - HEADER_LEN - TAG_LEN
    if ciphertext_len < 0:
        raise ValueError("file is too short to be a valid encrypted file")

    tmp = dst.with_name(dst.name + ".tmp")
    created = False
    try:
        with open(src, "rb") as fin:
            header = fin.read(HEADER_LEN)
            if header[: len(MAGIC)] != MAGIC:
                raise ValueError("not a file created by encrypt_file")
            salt = header[len(MAGIC): len(MAGIC) + SALT_LEN]
            nonce = header[len(MAGIC) + SALT_LEN:]

            fin.seek(-TAG_LEN, os.SEEK_END)
            tag = fin.read(TAG_LEN)
            fin.seek(HEADER_LEN)

            decryptor = Cipher(
                algorithms.AES(_derive_key(password, salt)), modes.GCM(nonce, tag)
            ).decryptor()
            decryptor.authenticate_additional_data(header)

            # Unverified plaintext only ever lands in an owner-only temp file,
            # which is deleted unless the GCM tag checks out.
            with _open_private(tmp) as fout:
                created = True
                remaining = ciphertext_len
                while remaining:
                    chunk = fin.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        raise ValueError("file is truncated")
                    remaining -= len(chunk)
                    fout.write(decryptor.update(chunk))
                try:
                    fout.write(decryptor.finalize())
                except InvalidTag:
                    raise ValueError("wrong password, or the file is corrupted or tampered with") from None
        _check_dst(dst)
        os.replace(tmp, dst)
    finally:
        if created:
            tmp.unlink(missing_ok=True)
    return dst


if __name__ == "__main__":
    import argparse
    import getpass

    parser = argparse.ArgumentParser(description="Encrypt or decrypt a file with AES-256-GCM.")
    parser.add_argument("mode", choices=["encrypt", "decrypt"])
    parser.add_argument("path")
    parser.add_argument("-o", "--output", help="output path (optional)")
    args = parser.parse_args()

    pw = getpass.getpass("Password: ")
    try:
        if args.mode == "encrypt":
            if pw != getpass.getpass("Confirm password: "):
                raise SystemExit("Passwords do not match.")
            print("Wrote", encrypt_file(args.path, pw, args.output))
        else:
            print("Wrote", decrypt_file(args.path, pw, args.output))
    except (ValueError, FileExistsError) as exc:
        raise SystemExit(f"Error: {exc}")
