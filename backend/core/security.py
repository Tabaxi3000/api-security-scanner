"""
Security utilities for password hashing and JWT token management.
"""

import math
import re
from datetime import (
    datetime,
    timedelta,
)
from typing import Any

import bcrypt
from jose import JWTError, jwt

from config import settings


# A small starter set of the most-breached passwords. In production this
# would be backed by a full list (e.g. rockyou.txt top 10k) loaded from disk.
COMMON_PASSWORDS: frozenset[str] = frozenset(
    {
        "password", "123456", "123456789", "12345678", "12345",
        "qwerty", "abc123", "password1", "111111", "1234567",
        "letmein", "welcome", "admin", "iloveyou", "monkey",
        "dragon", "sunshine", "princess", "football", "password123",
        "qwerty123", "1q2w3e4r", "000000", "qwertyuiop", "superman",
    }
)

# Keyboard-walk sequences used to flag low-effort passwords.
_KEYBOARD_WALKS: tuple[str, ...] = (
    "qwerty", "asdfgh", "zxcvbn", "qwertyuiop", "asdfghjkl", "1234567890",
)

STRENGTH_WEAK = "weak"
STRENGTH_MEDIUM = "medium"
STRENGTH_STRONG = "strong"


def _character_space(password: str) -> int:
    """
    Estimate the size of the character pool the password draws from.
    """
    space = 0
    if re.search(r"[a-z]", password):
        space += 26
    if re.search(r"[A-Z]", password):
        space += 26
    if re.search(r"[0-9]", password):
        space += 10
    if re.search(r"[^A-Za-z0-9]", password):
        space += 32
    return space


def password_entropy(password: str) -> float:
    """
    Estimate password entropy in bits: length * log2(character space).
    """
    if not password:
        return 0.0
    space = _character_space(password)
    if space == 0:
        return 0.0
    return round(len(password) * math.log2(space), 1)


def check_password_strength(password: str) -> dict[str, Any]:
    """
    Score a password and return actionable feedback.

    Returns a dict with ``strength`` (weak/medium/strong), a numeric
    ``score``, the estimated ``entropy`` in bits, and a list of
    ``feedback`` messages. A password found in the common-password list
    is always rated weak regardless of its composition.
    """
    score = 0
    feedback: list[str] = []

    if len(password) >= 16:
        score += 3
    elif len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Use at least 12 characters")

    if re.search(r"[A-Z]", password):
        score += 1
    if re.search(r"[a-z]", password):
        score += 1
    if re.search(r"[0-9]", password):
        score += 1
    if re.search(r"[^A-Za-z0-9]", password):
        score += 1
    else:
        feedback.append("Add a symbol")

    lowered = password.lower()

    if re.search(r"(.)\1{2,}", password):
        score -= 1
        feedback.append("Avoid repeated characters")

    if any(walk in lowered for walk in _KEYBOARD_WALKS):
        score -= 1
        feedback.append("Avoid keyboard sequences like 'qwerty'")

    is_common = lowered in COMMON_PASSWORDS
    if is_common:
        score = 0
        feedback = ["This is a commonly used password"]

    score = max(score, 0)
    entropy = password_entropy(password)

    # A password below the minimum length is weak no matter how varied its
    # characters are - variety cannot compensate for a tiny keyspace.
    too_short = len(password) < 8

    if is_common or too_short or score < 3:
        strength = STRENGTH_WEAK
    elif score < 5:
        strength = STRENGTH_MEDIUM
    else:
        strength = STRENGTH_STRONG

    return {
        "strength": strength,
        "score": score,
        "entropy": entropy,
        "is_common": is_common,
        "feedback": feedback,
    }


def hash_password(password: str) -> str:
    """
    Hash a plain text password using bcrypt
    """
    password_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode("utf-8")


def verify_password(
    plain_password: str,
    hashed_password: str
) -> bool:
    """
    Verify a plain text password against a hashed password
    """
    password_bytes = plain_password.encode("utf-8")
    hashed_bytes = hashed_password.encode("utf-8")
    return bcrypt.checkpw(password_bytes, hashed_bytes)


def create_access_token(
    data: dict[str,
               str],
    expires_delta: timedelta | None = None
) -> str:
    """
    Create a JWT access token
    """
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(
            minutes = settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        to_encode,
        settings.SECRET_KEY,
        algorithm = settings.ALGORITHM
    )
    return encoded_jwt


def decode_token(token: str) -> dict[str, str]:
    """
    Decode and verify a JWT token
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms = [settings.ALGORITHM]
        )
        return payload
    except JWTError as e:
        raise ValueError(f"Invalid token: {str(e)}") from e
