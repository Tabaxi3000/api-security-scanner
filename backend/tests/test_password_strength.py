"""
Tests for password strength scoring and the registration validator.
"""

import pytest
from pydantic import ValidationError

from core.security import (
    check_password_strength,
    password_entropy,
    STRENGTH_STRONG,
    STRENGTH_WEAK,
)
from schemas.user_schemas import UserCreate


class TestCheckPasswordStrength:
    def test_common_password_is_weak(self):
        result = check_password_strength("password")
        assert result["is_common"] is True
        assert result["strength"] == STRENGTH_WEAK
        assert result["score"] == 0

    def test_common_password_case_insensitive(self):
        assert check_password_strength("PASSWORD")["is_common"] is True

    def test_long_random_password_is_strong(self):
        result = check_password_strength("Tr0ub4dour&3xtra-Long!")
        assert result["strength"] == STRENGTH_STRONG
        assert result["is_common"] is False

    def test_short_password_gets_length_feedback(self):
        result = check_password_strength("Ab1!")
        assert any("12 characters" in f for f in result["feedback"])
        assert result["strength"] == STRENGTH_WEAK

    def test_keyboard_walk_penalized(self):
        walk = check_password_strength("Qwerty123!aa")
        assert any("keyboard" in f.lower() for f in walk["feedback"])

    def test_repeated_chars_penalized(self):
        assert any(
            "repeated" in f.lower()
            for f in check_password_strength("Aaaa1111!!!!")["feedback"]
        )


class TestPasswordEntropy:
    def test_empty_is_zero(self):
        assert password_entropy("") == 0.0

    def test_longer_and_wider_pool_has_more_entropy(self):
        low = password_entropy("aaaaaaaa")          # 8 lowercase
        high = password_entropy("aA1!aA1!aA1!")      # 12, all classes
        assert high > low


class TestRegistrationValidator:
    def test_common_password_rejected(self):
        with pytest.raises(ValidationError) as exc:
            UserCreate(email="user@example.com", password="Password1")
        # "password1" is in the common list
        assert "too common" in str(exc.value).lower()

    def test_strong_password_accepted(self):
        user = UserCreate(
            email="user@example.com",
            password="Zx9-quiet-River-42",
        )
        assert user.email == "user@example.com"

    def test_missing_number_rejected(self):
        with pytest.raises(ValidationError):
            UserCreate(email="user@example.com", password="NoNumbersHere")
