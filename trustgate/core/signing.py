"""Machine keys: every ledger entry signed by the machine that wrote it.

A hash chain needs no secret, so anyone who can append to the file can
append a valid-looking line (the outside review's exp3-5). A signature needs
the machine's private key, which in the guard room lives in a folder only the
daemon's OS user can read. So a line the daemon did not write fails
verification, however carefully it was hashed.

The signature is Ed25519 over the ASCII bytes of the entry's `entry_hash`.
The hash already commits to every other field and to the previous entry, so
signing it signs everything.

Needs the `cryptography` package (`pip install trustgate[guardroom]`). Only
the daemon and the verifier import it; the core engine still has no
dependency beyond pydantic and PyYAML.
"""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path


def _crypto():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ImportError as exc:  # pragma: no cover - depends on the install
        raise RuntimeError(
            "signing needs the cryptography package: pip install 'trustgate[guardroom]'"
        ) from exc
    return serialization, Ed25519PrivateKey, Ed25519PublicKey


def key_id_for(public_raw: bytes) -> str:
    """Short, stable name for a public key: `ed25519:<first 16 hex of sha256>`."""
    return "ed25519:" + hashlib.sha256(public_raw).hexdigest()[:16]


class Signer:
    """Holds a private key and signs entry hashes."""

    def __init__(self, private_key) -> None:
        serialization, _, _ = _crypto()
        self._key = private_key
        self.public_raw = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.key_id = key_id_for(self.public_raw)

    @classmethod
    def from_seed(cls, seed: bytes) -> Signer:
        """Deterministic key from 32 bytes. For test vectors only."""
        _, private_cls, _ = _crypto()
        return cls(private_cls.from_private_bytes(seed))

    @classmethod
    def load_or_create(cls, path: str | Path) -> Signer:
        """Load the key at `path`, or make one there with mode 0600."""
        serialization, private_cls, _ = _crypto()
        path = Path(path)
        if path.exists():
            key = serialization.load_pem_private_key(path.read_bytes(), password=None)
            return cls(key)
        key = private_cls.generate()
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(pem)
        return cls(key)

    @property
    def public_b64(self) -> str:
        return base64.b64encode(self.public_raw).decode("ascii")

    def sign(self, entry_hash: str) -> str:
        return base64.b64encode(self._key.sign(entry_hash.encode("ascii"))).decode("ascii")


def check_signature(public_b64: str, entry_hash: str, sig_b64: str) -> bool:
    """Whether `sig_b64` is the key's signature over `entry_hash`."""
    _, _, public_cls = _crypto()
    from cryptography.exceptions import InvalidSignature

    try:
        key = public_cls.from_public_bytes(base64.b64decode(public_b64))
        key.verify(base64.b64decode(sig_b64), entry_hash.encode("ascii"))
        return True
    except (InvalidSignature, ValueError):
        return False
