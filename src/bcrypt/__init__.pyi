from __future__ import annotations

def gensalt(rounds: int = 12, prefix: bytes = b"2b") -> bytes: ...
def hashpw(
    password: bytes, salt: bytes, *, prehash: bool = False
) -> bytes: ...
def checkpw(
    password: bytes,
    hashed_password: bytes,
    *,
    prehash: bool | None = None,
    legacy_truncate: bool = True,
) -> bool: ...
def prehash_password(password: bytes) -> bytes: ...
def needs_update(
    hashed_password: bytes,
    *,
    rounds: int | None = 12,
    prefix: bytes = b"2b",
) -> bool: ...

needs_rehash = needs_update

def checkpw_and_upgrade(
    password: bytes,
    hashed_password: bytes,
    *,
    rounds: int = 12,
    prefix: bytes = b"2b",
    prehash: bool = True,
    legacy_truncate: bool = True,
) -> tuple[bool, bytes | None]: ...

verify_and_upgrade = checkpw_and_upgrade

def upgrade_hash(
    password: bytes,
    hashed_password: bytes,
    *,
    rounds: int = 12,
    prefix: bytes = b"2b",
    prehash: bool = True,
    legacy_truncate: bool = True,
) -> bytes | None: ...
def migrate_hash(
    password: bytes,
    hashed_password: bytes,
    *,
    rounds: int = 12,
    prefix: bytes = b"2b",
    prehash: bool = True,
    legacy_truncate: bool = True,
) -> bytes | None: ...
def kdf(
    password: bytes,
    salt: bytes,
    desired_key_bytes: int,
    rounds: int,
    ignore_few_rounds: bool = False,
) -> bytes: ...
