"""Password-based file encryption with AES-256-GCM.

Requires:  pip install cryptography

File layout:  MAGIC (5) | salt (16) | nonce (12) | ciphertext | GCM tag (16)

Usage as a library:
    from aes_file import encrypt_file, decrypt_file
    encrypt_file("report.pdf", "correct horse battery staple")   # -> report.pdf.enc
    decrypt_file("report.pdf.enc", "correct horse battery staple")  # -> report.pdf

Usage from the command line:
    python aes_file.py encrypt report.pdf
    python aes_file.py decrypt report.pdf.enc
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
CHUNK_SIZE = 1024 * 1024  # 1 MiB; files are streamed, never loaded whole

# AES-GCM is only safe up to ~64 GiB of data under a single nonce.
MAX_PLAINTEXT_BYTES = 2**36 - 32


def _derive_key(password: str, salt: bytes) -> bytes:
    """Stretch a password into a 256-bit key with scrypt (~128 MB RAM, deliberately slow)."""
    kdf = Scrypt(salt=salt, length=32, n=2**17, r=8, p=1)
    return kdf.derive(password.encode("utf-8"))


def encrypt_file(src, password: str, dst=None) -> Path:
    """Encrypt `src` with AES-256-GCM and return the path of the encrypted file.

    A fresh random salt and nonce are generated on every call, so encrypting
    the same file twice produces different output. The original file is left
    untouched. `dst` defaults to `src` with ".enc" appended.
    """
    src = Path(src)
    dst = Path(dst) if dst else src.with_name(src.name + ".enc")
    if not password:
        raise ValueError("password must not be empty")
    if src.stat().st_size > MAX_PLAINTEXT_BYTES:
        raise ValueError("file is too large for a single AES-GCM stream (limit ~64 GiB)")

    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    header = MAGIC + salt + nonce

    encryptor = Cipher(algorithms.AES(_derive_key(password, salt)), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(header)  # header tampering is detected too

    tmp = dst.with_name(dst.name + ".tmp")
    try:
        with open(src, "rb") as fin, open(tmp, "wb") as fout:
            fout.write(header)
            while chunk := fin.read(CHUNK_SIZE):
                fout.write(encryptor.update(chunk))
            fout.write(encryptor.finalize())
            fout.write(encryptor.tag)
        os.replace(tmp, dst)  # atomic: never leaves a half-written output file
    finally:
        tmp.unlink(missing_ok=True)
    return dst


def decrypt_file(src, password: str, dst=None) -> Path:
    """Decrypt a file produced by `encrypt_file` and return the output path.

    Raises ValueError if the password is wrong or the file has been modified.
    `dst` defaults to `src` without its ".enc" suffix (or with ".dec" appended).
    """
    src = Path(src)
    if dst:
        dst = Path(dst)
    elif src.suffix == ".enc":
        dst = src.with_suffix("")
    else:
        dst = src.with_name(src.name + ".dec")

    ciphertext_len = src.stat().st_size - HEADER_LEN - TAG_LEN
    if ciphertext_len < 0:
        raise ValueError("file is too short to be a valid encrypted file")

    tmp = dst.with_name(dst.name + ".tmp")
    try:
        with open(src, "rb") as fin:
            header = fin.read(HEADER_LEN)
            if header[: len(MAGIC)] != MAGIC:
                raise ValueError("not a file created by encrypt_file")
            salt = header[len(MAGIC) : len(MAGIC) + SALT_LEN]
            nonce = header[len(MAGIC) + SALT_LEN :]

            fin.seek(-TAG_LEN, os.SEEK_END)
            tag = fin.read(TAG_LEN)
            fin.seek(HEADER_LEN)

            decryptor = Cipher(
                algorithms.AES(_derive_key(password, salt)), modes.GCM(nonce, tag)
            ).decryptor()
            decryptor.authenticate_additional_data(header)

            with open(tmp, "wb") as fout:
                remaining = ciphertext_len
                while remaining:
                    chunk = fin.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        raise ValueError("file is truncated")
                    remaining -= len(chunk)
                    fout.write(decryptor.update(chunk))
                try:
                    fout.write(decryptor.finalize())  # verifies the tag
                except InvalidTag:
                    raise ValueError("wrong password, or the file is corrupted or tampered with") from None
        os.replace(tmp, dst)  # only reached once the data is authenticated
    finally:
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
    if args.mode == "encrypt":
        if pw != getpass.getpass("Confirm password: "):
            raise SystemExit("Passwords do not match.")
        print("Wrote", encrypt_file(args.path, pw, args.output))
    else:
        try:
            print("Wrote", decrypt_file(args.path, pw, args.output))
        except ValueError as exc:
            raise SystemExit(f"Error: {exc}")