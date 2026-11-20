# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

import base64
import hashlib

from . import _bcrypt
from ._bcrypt import (
    __author__,
    __copyright__,
    __email__,
    __license__,
    __summary__,
    __title__,
    __uri__,
    gensalt,
    kdf,
)
from ._bcrypt import (
    __version_ex__ as __version__,
)

_MAX_PASSWORD_LENGTH = 72
_SUPPORTED_PREFIXES = (b"2a", b"2b")
_SUPPORTED_VERSIONS = (b"2a", b"2b", b"2x", b"2y")


def prehash_password(password: bytes) -> bytes:
    """Pre-hash a password so it fits within bcrypt's 72-byte input limit.

    The password is hashed with SHA-256 and the digest is encoded with standard
    Base64 (44 bytes). This is the same construction described in the README
    for long passwords.
    """
    if not isinstance(password, (bytes, bytearray, memoryview)):
        raise TypeError("password must be a bytes-like object")

    digest = hashlib.sha256(bytes(password)).digest()
    return base64.b64encode(digest)


def _normalize_hash(hashed_password: bytes) -> bytes:
    if not isinstance(hashed_password, (bytes, bytearray, memoryview)):
        raise TypeError("hashed_password must be a bytes-like object")
    return bytes(hashed_password)


def _parse_hash(hashed_password: bytes) -> tuple[bytes, int]:
    hashed_password = _normalize_hash(hashed_password)
    parts = hashed_password.split(b"$")
    if len(parts) != 4 or parts[0] != b"":
        raise ValueError("Invalid salt")

    version = parts[1]
    if version not in _SUPPORTED_VERSIONS:
        raise ValueError("Invalid salt")

    raw_cost = parts[2]
    if len(raw_cost) != 2 or not raw_cost.isdigit():
        raise ValueError("Invalid salt")

    cost = int(raw_cost)
    if not 4 <= cost <= 31 or len(parts[3]) < 22:
        raise ValueError("Invalid salt")

    return version, cost


def _validate_prefix(prefix: bytes) -> None:
    if prefix not in _SUPPORTED_PREFIXES:
        raise ValueError("Supported prefixes are b'2a' or b'2b'")


def _verification_candidates(
    password: bytes,
    prehash: bool | None,
    legacy_truncate: bool,
) -> tuple[tuple[bytes, bool], ...]:
    if len(password) <= _MAX_PASSWORD_LENGTH:
        return ((password, False),)

    candidates = []
    if prehash is not False:
        candidates.append((prehash_password(password), False))
    if legacy_truncate:
        candidates.append((password[:_MAX_PASSWORD_LENGTH], True))
    return tuple(candidates)


def hashpw(password: bytes, salt: bytes, *, prehash: bool = False) -> bytes:
    """Hash a password with bcrypt.

    Passwords longer than 72 bytes raise ``ValueError`` by default. Set
    ``prehash=True`` to hash long passwords with SHA-256 and Base64 before
    passing them to bcrypt.
    """
    if prehash and len(password) > _MAX_PASSWORD_LENGTH:
        password = prehash_password(password)
    return _bcrypt.hashpw(password, salt)


def checkpw(
    password: bytes,
    hashed_password: bytes,
    *,
    prehash: bool | None = None,
    legacy_truncate: bool = True,
) -> bool:
    """Check a password against a bcrypt hash.

    ``$2a$``, ``$2b$``, ``$2x$``, and ``$2y$`` hashes are supported. For
    passwords longer than 72 bytes, ``prehash=None`` tries both the SHA-256
    pre-hash and the legacy bcrypt truncation behavior. Set ``prehash=False``
    to disable pre-hashing, or ``legacy_truncate=False`` to reject truncated
    matches.
    """
    candidates = _verification_candidates(password, prehash, legacy_truncate)

    if not candidates:
        return _bcrypt.checkpw(password, hashed_password)

    for candidate, _ in candidates:
        if _bcrypt.checkpw(candidate, hashed_password):
            return True
    return False


def needs_update(
    hashed_password: bytes,
    *,
    rounds: int | None = 12,
    prefix: bytes = b"2b",
) -> bool:
    """Return whether a hash should be upgraded to the target parameters.

    The cost in an existing hash is preserved during upgrades. ``rounds`` is a
    minimum target cost, not a maximum.
    """
    _validate_prefix(prefix)
    if rounds is not None and not 4 <= rounds <= 31:
        raise ValueError("Invalid rounds")

    version, cost = _parse_hash(hashed_password)
    return version != prefix or (rounds is not None and cost < rounds)


def checkpw_and_upgrade(
    password: bytes,
    hashed_password: bytes,
    *,
    rounds: int = 12,
    prefix: bytes = b"2b",
    prehash: bool = True,
    legacy_truncate: bool = True,
) -> tuple[bool, bytes | None]:
    """Verify a password and generate an upgraded hash when necessary.

    Returns ``(False, None)`` for an invalid password, ``(True, None)`` when
    the stored hash already matches the target parameters, and
    ``(True, new_hash)`` when an upgrade was generated.

    Long passwords are pre-hashed by default. If ``prehash=False``, an existing
    legacy truncated hash is re-hashed with the same truncation behavior.
    """
    _validate_prefix(prefix)
    if not 4 <= rounds <= 31:
        raise ValueError("Invalid rounds")

    hashed_password = _normalize_hash(hashed_password)
    version, cost = _parse_hash(hashed_password)

    candidates = _verification_candidates(password, prehash, legacy_truncate)
    if not candidates:
        # Preserve the strict error for an unsupported long-password policy.
        _bcrypt.checkpw(password, hashed_password)

    verified = False
    matched_truncation = False
    for candidate, truncated in candidates:
        if _bcrypt.checkpw(candidate, hashed_password):
            verified = True
            matched_truncation = truncated
            break

    if not verified:
        return False, None

    effective_rounds = max(cost, rounds)
    if version == prefix and cost >= rounds and not matched_truncation:
        return True, None

    salt = gensalt(effective_rounds, prefix)
    if len(password) > _MAX_PASSWORD_LENGTH and prehash:
        password = prehash_password(password)
    elif len(password) > _MAX_PASSWORD_LENGTH:
        password = password[:_MAX_PASSWORD_LENGTH]

    return True, _bcrypt.hashpw(password, salt)


def upgrade_hash(
    password: bytes,
    hashed_password: bytes,
    *,
    rounds: int = 12,
    prefix: bytes = b"2b",
    prehash: bool = True,
    legacy_truncate: bool = True,
) -> bytes | None:
    """Return an upgraded hash, the original hash, or ``None`` if invalid."""
    verified, new_hash = checkpw_and_upgrade(
        password,
        hashed_password,
        rounds=rounds,
        prefix=prefix,
        prehash=prehash,
        legacy_truncate=legacy_truncate,
    )
    if not verified:
        return None
    if new_hash is not None:
        return new_hash
    return _normalize_hash(hashed_password)


def migrate_hash(
    password: bytes,
    hashed_password: bytes,
    *,
    rounds: int = 12,
    prefix: bytes = b"2b",
    prehash: bool = True,
    legacy_truncate: bool = True,
) -> bytes | None:
    """Alias for :func:`upgrade_hash` used by the migration tool."""
    return upgrade_hash(
        password,
        hashed_password,
        rounds=rounds,
        prefix=prefix,
        prehash=prehash,
        legacy_truncate=legacy_truncate,
    )


verify_and_upgrade = checkpw_and_upgrade
needs_rehash = needs_update

__all__ = [
    "__author__",
    "__copyright__",
    "__email__",
    "__license__",
    "__summary__",
    "__title__",
    "__uri__",
    "__version__",
    "checkpw",
    "checkpw_and_upgrade",
    "gensalt",
    "hashpw",
    "kdf",
    "migrate_hash",
    "needs_rehash",
    "needs_update",
    "prehash_password",
    "upgrade_hash",
    "verify_and_upgrade",
]
