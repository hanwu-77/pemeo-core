"""Versioned strict JSON/JCS boundary for I1; not a change to Protocol v0.1."""
from __future__ import annotations

from decimal import Decimal
import hashlib
import json
import math

import rfc8785

MAX_BYTES = 1024 * 1024
MAX_RECORDS = 32
PROFILE = 'pemeo-jcs-v1'


class InputRejected(ValueError):
    pass


def canonical(value) -> bytes:
    try:
        result = rfc8785.dumps(value)
    except (rfc8785.CanonicalizationError, UnicodeError, RecursionError, TypeError) as exc:
        raise InputRejected('Unsupported JSON value') from exc
    if len(result) > MAX_BYTES:
        raise InputRejected('Input exceeds 1 MiB')
    return result


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputRejected('Duplicate JSON key')
        result[key] = value
    return result


def _float(token):
    result = float(token)
    if not math.isfinite(result) or abs(result) > 9007199254740991:
        raise InputRejected('Number outside supported range')
    # Reject precision loss before a Python float discards the original digits.
    if Decimal(token) != Decimal(rfc8785.dumps(result).decode()):
        raise InputRejected('Number would lose decimal precision')
    return result


def _constant(_token):
    raise InputRejected('Non-finite number')


def parse(raw: bytes):
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        raise InputRejected('Expected UTF-8 bytes within 1 MiB')
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs,
                           parse_float=_float, parse_constant=_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, InputRejected):
            raise
        raise InputRejected('Invalid JSON') from exc
    canonical(value)
    return value


def records(raw: bytes) -> list[dict]:
    value = parse(raw)
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_RECORDS or any(not isinstance(r, dict) for r in value):
        raise InputRejected('Expected 1 to 32 record objects')
    return value


def digest(domain: str, value) -> str:
    return hashlib.sha256((PROFILE + ':' + domain + '\0').encode() + canonical(value)).hexdigest()
