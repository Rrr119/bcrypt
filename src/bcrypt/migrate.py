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

"""Migrate bcrypt hashes from legacy formats and parameters.

The tool reads newline-delimited JSON records. Each record must contain a
``hash`` and exactly one of ``password`` (UTF-8 text) or ``password_b64``
(Base64 encoded bytes)::

    {"id": "alice", "password": "correct horse", "hash": "$2a$04$..."}

Successful upgrades are written as newline-delimited JSON. Password fields are
removed from the output; other record metadata is retained.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import IO, Any

from . import checkpw_and_upgrade


def _password_from_record(record: Mapping[str, Any]) -> bytes:
    has_password = "password" in record
    has_password_b64 = "password_b64" in record
    if has_password == has_password_b64:
        raise ValueError("record must contain password or password_b64")

    if has_password:
        password = record["password"]
        if isinstance(password, str):
            return password.encode("utf-8")
        if isinstance(password, (bytes, bytearray, memoryview)):
            return bytes(password)
        raise TypeError("password must be text or bytes")

    encoded = record["password_b64"]
    if not isinstance(encoded, str):
        raise TypeError("password_b64 must be text")
    try:
        return base64.b64decode(encoded.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise ValueError("password_b64 is not valid Base64") from exc


def _hash_from_record(record: Mapping[str, Any]) -> bytes:
    hashed_password = record.get("hash")
    if isinstance(hashed_password, str):
        try:
            return hashed_password.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ValueError("hash must be ASCII") from exc
    if isinstance(hashed_password, (bytes, bytearray, memoryview)):
        return bytes(hashed_password)
    raise TypeError("hash must be text or bytes")


def _hash_to_text(hashed_password: Any) -> str:
    if isinstance(hashed_password, (bytes, bytearray, memoryview)):
        return bytes(hashed_password).decode("ascii", "replace")
    if isinstance(hashed_password, str):
        return hashed_password
    return ""


def migrate_record(
    record: Mapping[str, Any],
    *,
    rounds: int = 12,
    prefix: bytes = b"2b",
    prehash: bool = True,
    legacy_truncate: bool = True,
) -> dict[str, Any]:
    """Migrate one record and return a JSON-serializable result.

    The ``status`` field is ``upgraded``, ``unchanged``, or ``invalid``.
    Password fields are never included in the returned mapping.
    """
    if not isinstance(record, Mapping):
        raise TypeError("record must be a mapping")
    if prefix not in (b"2a", b"2b"):
        raise ValueError("Supported prefixes are b'2a' or b'2b'")
    if not 4 <= rounds <= 31:
        raise ValueError("Invalid rounds")

    result = {
        key: value
        for key, value in record.items()
        if key not in {"password", "password_b64", "hash"}
    }

    try:
        hashed_password = _hash_from_record(record)
        password = _password_from_record(record)
        verified, new_hash = checkpw_and_upgrade(
            password,
            hashed_password,
            rounds=rounds,
            prefix=prefix,
            prehash=prehash,
            legacy_truncate=legacy_truncate,
        )
    except (TypeError, ValueError) as exc:
        result["status"] = "invalid"
        result["hash"] = _hash_to_text(record.get("hash", b""))
        result["error"] = str(exc)
        return result

    result["hash"] = _hash_to_text(
        hashed_password if new_hash is None else new_hash
    )
    if new_hash is not None:
        result["status"] = "upgraded"
        result["previous_hash"] = _hash_to_text(hashed_password)
    elif verified:
        result["status"] = "unchanged"
    else:
        result["status"] = "invalid"
    return result


def _read_records(stream: IO[str]) -> Mapping[str, Any]:
    for line_number, line in enumerate(stream, 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"line {line_number}: invalid JSON: {exc.msg}"
            ) from exc
        if not isinstance(record, dict):
            raise ValueError(f"line {line_number}: record must be an object")
        yield record


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m bcrypt.migrate",
        description="Upgrade legacy bcrypt hashes from JSONL records.",
    )
    parser.add_argument(
        "input",
        nargs="?",
        type=Path,
        help="input JSONL file (default: stdin)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="output JSONL file (default: stdout)",
    )
    parser.add_argument(
        "--rounds",
        type=int,
        default=12,
        help="minimum bcrypt cost for upgraded hashes (default: 12)",
    )
    parser.add_argument(
        "--prefix",
        choices=("2a", "2b"),
        default="2b",
        help="target bcrypt version (default: 2b)",
    )
    parser.add_argument(
        "--no-prehash",
        action="store_false",
        dest="prehash",
        help="disable SHA-256 pre-hashing for passwords over 72 bytes",
    )
    parser.add_argument(
        "--strict-truncation",
        action="store_false",
        dest="legacy_truncate",
        help="do not verify legacy hashes with truncated long passwords",
    )
    parser.add_argument(
        "--fail-on-invalid",
        action="store_true",
        help="exit with status 1 if any record is invalid",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    input_stream: IO[str]
    output_stream: IO[str]
    close_input = False
    close_output = False
    try:
        if args.input is None:
            input_stream = sys.stdin
        else:
            input_stream = args.input.open("r", encoding="utf-8")
            close_input = True

        if args.output is None:
            output_stream = sys.stdout
        else:
            output_stream = args.output.open("w", encoding="utf-8")
            close_output = True

        invalid = 0
        for record in _read_records(input_stream):
            result = migrate_record(
                record,
                rounds=args.rounds,
                prefix=args.prefix.encode("ascii"),
                prehash=args.prehash,
                legacy_truncate=args.legacy_truncate,
            )
            if result["status"] == "invalid":
                invalid += 1
            output_stream.write(json.dumps(result, ensure_ascii=False))
            output_stream.write("\n")
    except (OSError, ValueError) as exc:
        print(f"bcrypt migration failed: {exc}", file=sys.stderr)
        return 2
    finally:
        if close_input:
            input_stream.close()
        if close_output:
            output_stream.close()

    if args.fail_on_invalid and invalid:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
