from __future__ import annotations

from django.contrib.auth.tokens import PasswordResetTokenGenerator, default_token_generator
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str


class EmailVerificationTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return f"{user.pk}{user.email}{user.is_email_verified}{timestamp}"


email_verification_token_generator = EmailVerificationTokenGenerator()


def encode_uid(pk: int) -> str:
    return urlsafe_base64_encode(force_bytes(pk))


def decode_uid(uid: str) -> str | None:
    try:
        return force_str(urlsafe_base64_decode(uid))
    except (TypeError, ValueError, OverflowError):
        return None


__all__ = [
    "default_token_generator",
    "email_verification_token_generator",
    "encode_uid",
    "decode_uid",
]
